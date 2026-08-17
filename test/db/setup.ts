import pg from "pg";
import { Database } from "../../src/db/client.ts";

/**
 * Database test harness.
 *
 * Schema creation lives in test/global-setup.ts, which runs once before any
 * worker starts. This module only hands out connections and fixtures.
 *
 * Tests connect as a login role that is a *member* of driftless_app, which is
 * how production connects. Running these tests as a superuser would silently
 * bypass row-level security and turn every isolation assertion into a
 * tautology — the exact failure this suite exists to catch.
 */

export const ADMIN_URL =
  process.env["DATABASE_URL"] ??
  "postgresql://postgres@localhost:5433/driftless_test?host=/tmp/pgrun";

/**
 * Returns `connectionString` with its user swapped and any password dropped.
 *
 * Parsed rather than string-replaced. The previous version did
 * `ADMIN_URL.replace("postgres@", "driftless_app_login@")`, which is correct
 * only for a passwordless URL. Given CI's
 * `postgresql://postgres:postgres@host/db`, the literal `postgres@` matches at
 * the *password* position instead, yielding
 * `postgresql://postgres:driftless_app_login@host/db` — user still `postgres`,
 * password now a role name. Every connection then failed with "password
 * authentication failed for user postgres", and CI had never once been green.
 *
 * The password is cleared deliberately: `driftless_app_login` and
 * `driftless_worker_login` are created without one, so they authenticate only
 * where the server trusts the connection. Carrying the admin password over
 * would be a silent lie about who is connecting.
 */
export function withUser(connectionString: string, user: string): string {
  const url = new URL(connectionString);
  url.username = user;
  url.password = "";
  return url.toString();
}

export const APP_URL = withUser(ADMIN_URL, "driftless_app_login");
export const PLATFORM_URL = withUser(ADMIN_URL, "driftless_worker_login");

/**
 * Retained so test files read declaratively. Schema preparation already
 * happened in global setup; this only asserts that it did, so a
 * misconfiguration fails with a clear message rather than a cascade of
 * confusing RLS errors.
 */
export async function prepareDatabase(): Promise<void> {
  const client = new pg.Client({ connectionString: ADMIN_URL });
  await client.connect();
  try {
    const { rowCount } = await client.query(
      "SELECT 1 FROM information_schema.tables WHERE table_name = 'provider'",
    );
    if (!rowCount) {
      throw new Error(
        "Schema is missing. test/global-setup.ts should have run — check vitest.config.ts.",
      );
    }
  } finally {
    await client.end();
  }
}

/** Tenant-scoped access only. No platform connection — most code needs none. */
export function appDatabase(): Database {
  return new Database({ connectionString: APP_URL });
}

/** A worker: tenant access plus the platform connection used to dequeue. */
export function workerDatabase(): Database {
  return new Database({
    connectionString: APP_URL,
    platformConnectionString: PLATFORM_URL,
  });
}

export async function adminClient(): Promise<pg.Client> {
  const client = new pg.Client({ connectionString: ADMIN_URL });
  await client.connect();
  return client;
}

export interface Fixture {
  /** Seed slug. Forge coordinates derive from it: owner is `<slug>-consumer`. */
  slug: string;
  providerId: string;
  consumerId: string;
  installationId: string;
  repositoryId: string;
  changeId: string;
}

/**
 * Seeds a provider and its dependents.
 *
 * Uses the admin connection deliberately: seeding through the app role would
 * require tenant context to already exist, which is circular. Everything the
 * tests then *assert* runs through the app role.
 */
export async function seedProvider(slug: string): Promise<Fixture> {
  const client = await adminClient();
  try {
    const provider = await client.query<{ id: string }>(
      "INSERT INTO provider (slug, display_name) VALUES ($1, $2) RETURNING id",
      [slug, `${slug} Inc`],
    );
    const providerId = provider.rows[0]!.id;

    const consumer = await client.query<{ id: string }>(
      "INSERT INTO consumer (provider_id, forge_owner) VALUES ($1, $2) RETURNING id",
      [providerId, `${slug}-consumer`],
    );
    const consumerId = consumer.rows[0]!.id;

    const installation = await client.query<{ id: string }>(
      `INSERT INTO installation (provider_id, consumer_id, forge_installation_id, granted_permissions)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [
        providerId,
        consumerId,
        BigInt(Math.floor(Math.random() * 1e12)).toString(),
        JSON.stringify({ contents: "write", pull_requests: "write" }),
      ],
    );
    const installationId = installation.rows[0]!.id;

    const repository = await client.query<{ id: string }>(
      `INSERT INTO repository (provider_id, installation_id, forge_owner, forge_name)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [providerId, installationId, `${slug}-consumer`, "widgets"],
    );
    const repositoryId = repository.rows[0]!.id;

    const change = await client.query<{ id: string }>(
      `INSERT INTO upstream_change (provider_id, change_key, ecosystem, package_name, summary)
       VALUES ($1, $2, 'npm', 'acme-sdk', 'v3 removes callback API') RETURNING id`,
      [providerId, `${slug}-change-1`],
    );

    return {
      slug,
      providerId,
      consumerId,
      installationId,
      repositoryId,
      changeId: change.rows[0]!.id,
    };
  } finally {
    await client.end();
  }
}

export const SHA_A = "a".repeat(40);
export const SHA_B = "b".repeat(40);
