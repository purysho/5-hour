import { beforeAll, afterAll, describe, expect, it } from "vitest";
import pg from "pg";
import { PLATFORM_URL, prepareDatabase, workerDatabase, adminClient } from "./setup.ts";
import type { Database } from "../../src/db/client.ts";
import { applyForgeEvent, type ApplyDeps } from "../../src/http/webhook-apply.ts";
import { handleSetup, type SetupDeps, type PendingInstallation } from "../../src/http/setup.ts";
import { hashToken } from "../../src/outbound/suppression.ts";
import { recordEnrolment } from "../../src/http/webhook-apply.ts";
import { createBillingStore, type BillingStore } from "../../src/billing/provisioning.ts";
import { BILLING_URL } from "./setup.ts";
import { PLANS } from "../../src/billing/plans.ts";
import { Secret } from "../../src/config.ts";

/**
 * Paying and being connected are two different things, and the gap between
 * them was total: an installation resolved to no tenant and was dropped, so a
 * customer could pay and be connected to nothing — permanently, with a log
 * line as the only symptom.
 *
 * These tests run against the real login roles. That is not incidental: the
 * privilege bug that made parking fail in production was invisible to any test
 * using a superuser, and invisible to a test that issued a plain INSERT rather
 * than the upsert the code actually runs.
 */

let db: Database;
let store: BillingStore;

beforeAll(async () => {
  await prepareDatabase();
  db = workerDatabase();
  store = createBillingStore(new Secret(BILLING_URL, "BILLING_DATABASE_URL"));
});

afterAll(async () => {
  await db?.close();
  await store?.close();
});

function grant(owner: string, names: readonly string[]) {
  return names.map((name, index) => ({
    owner,
    name,
    forgeRepositoryId: Math.abs(hashCode(`${owner}/${name}`)) + index,
    isPrivate: false,
  }));
}

function hashCode(value: string): number {
  let hash = 2_166_136_261;
  for (const character of value) {
    hash ^= character.charCodeAt(0);
    hash = Math.imul(hash, 16_777_619) >>> 0;
  }
  return hash | 0;
}

/** The wiring the server uses, so the tests exercise the real statements. */
function applyDeps(parked: { called: boolean }): ApplyDeps {
  return {
    withTenant: (id, fn) => db.withTenant(id, fn),
    providerForInstallation: async (forgeInstallationId) => {
      const rows = await db.withPlatformContext("installation lookup", (client) =>
        client
          .query<{ provider_id: string | null }>(
            "SELECT provider_for_installation($1) AS provider_id",
            [forgeInstallationId],
          )
          .then((r) => r.rows),
      );
      return rows[0]?.provider_id ?? null;
    },
    parkInstallation: async (forgeInstallationId, account, repositories) => {
      parked.called = true;
      await db.withPlatformContext("park installation", (client) =>
        client.query(
          `INSERT INTO pending_installation (forge_installation_id, account, repositories)
                VALUES ($1, $2, $3::jsonb)
           ON CONFLICT (forge_installation_id) DO UPDATE
              SET account = EXCLUDED.account,
                  repositories = EXCLUDED.repositories,
                  received_at = now()`,
          [forgeInstallationId, account, JSON.stringify(repositories)],
        ),
      );
    },
  };
}

function setupDeps(): SetupDeps {
  return {
    log: () => {},
    providerForEnrolmentRef: async (refHash) => {
      const rows = await db.withPlatformContext("enrolment ref lookup", (client) =>
        client
          .query<{ provider_id: string | null }>(
            "SELECT provider_id_for_enrolment_ref($1) AS provider_id",
            [refHash],
          )
          .then((r) => r.rows),
      );
      return rows[0]?.provider_id ?? null;
    },
    takePendingInstallation: async (forgeInstallationId) => {
      const rows = await db.withPlatformContext("drain parked installation", (client) =>
        client
          .query<{ account: string; repositories: unknown }>(
            `DELETE FROM pending_installation WHERE forge_installation_id = $1
               RETURNING account, repositories`,
            [forgeInstallationId],
          )
          .then((r) => r.rows),
      );
      const row = rows[0];
      if (!row) return null;
      return {
        account: row.account,
        repositories: Array.isArray(row.repositories)
          ? (row.repositories as PendingInstallation["repositories"])
          : [],
      };
    },
    enrol: async (providerId, forgeInstallationId, pending) => {
      await db.withTenant(providerId, (client) =>
        recordEnrolment(
          client,
          providerId,
          pending?.account ?? `installation-${forgeInstallationId}`,
          forgeInstallationId,
          pending?.repositories ?? [],
        ),
      );
    },
    consumeEnrolmentRef: async (providerId) => {
      await db.withTenant(providerId, (client) =>
        client.query("UPDATE provider SET enrolment_ref_hash = NULL WHERE id = $1", [providerId]),
      );
    },
  };
}

async function payFor(slug: string, reference: string): Promise<string> {
  const { providerId } = await store.provision({
    slug,
    displayName: `${slug}@example.com`,
    stripeCustomerId: `cus_${slug}`,
    stripeSubscriptionId: `sub_${slug}`,
    status: "active",
    plan: PLANS.team,
    currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    cancelAtPeriodEnd: false,
    enrolmentRefHash: hashToken(reference),
  });
  return providerId;
}

describe("the parked-installation writer", () => {
  it("can run the upsert the server actually issues", async () => {
    // The bug this test exists for: the grant was SELECT, INSERT, DELETE. A
    // plain INSERT passed, and the ON CONFLICT DO UPDATE the code runs failed
    // with "permission denied" on every call — Postgres checks the UPDATE
    // privilege at plan time whether or not a conflict occurs. Nothing caught
    // it until the server was run for real.
    const client = new pg.Client({ connectionString: PLATFORM_URL });
    await client.connect();
    try {
      const id = Math.floor(Math.random() * 1e9);
      const upsert = `INSERT INTO pending_installation (forge_installation_id, account, repositories)
                           VALUES ($1, $2, '[]'::jsonb)
                      ON CONFLICT (forge_installation_id) DO UPDATE
                         SET account = EXCLUDED.account, received_at = now()`;
      await expect(client.query(upsert, [id, "first"])).resolves.toBeTruthy();
      // And again, so the conflict branch itself is exercised.
      await expect(client.query(upsert, [id, "second"])).resolves.toBeTruthy();

      const { rows } = await client.query<{ account: string }>(
        "SELECT account FROM pending_installation WHERE forge_installation_id = $1",
        [id],
      );
      expect(rows[0]?.account).toBe("second");
      await client.query("DELETE FROM pending_installation WHERE forge_installation_id = $1", [id]);
    } finally {
      await client.end();
    }
  });
});

describe("a customer who pays and then installs", () => {
  it("is connected, with the repository selection they chose", async () => {
    const reference = `ref-${Date.now()}-a`;
    const providerId = await payFor(`ss-happy-${Date.now()}`, reference);
    const installationId = Math.floor(Math.random() * 1e9);
    const parked = { called: false };

    // GitHub's webhook arrives first, which is the common order.
    const applied = await applyForgeEvent(
      {
        type: "installation.created",
        installationId,
        account: "funnelcorp",
        repositories: grant("funnelcorp", ["api", "web"]),
      },
      applyDeps(parked),
    );
    expect(parked.called).toBe(true);
    expect(applied.applied).toBe(true);
    expect(applied.auditAction).toBe("installation.parked");

    // Then the browser reaches the setup URL.
    const outcome = await handleSetup(
      { installationId: String(installationId), state: reference },
      setupDeps(),
    );
    expect(outcome).toMatchObject({ kind: "enrolled", providerId });

    const repositories = await db.withTenant(providerId, async (client) => {
      const { rows } = await client.query<{ forge_name: string }>(
        "SELECT forge_name FROM repository WHERE archived_at IS NULL ORDER BY forge_name",
      );
      return rows.map((row) => row.forge_name);
    });
    // The selection survived the race. Before parking existed this was empty,
    // and nothing ever asked the customer again.
    expect(repositories).toEqual(["api", "web"]);
  });

  it("is connected even when the browser arrives before the webhook", async () => {
    const reference = `ref-${Date.now()}-b`;
    const providerId = await payFor(`ss-race-${Date.now()}`, reference);
    const installationId = Math.floor(Math.random() * 1e9);

    const outcome = await handleSetup(
      { installationId: String(installationId), state: reference },
      setupDeps(),
    );
    expect(outcome.kind).toBe("enrolled");

    // The installation exists, so the webhook that follows resolves to this
    // tenant rather than being parked.
    const found = await db.withPlatformContext("lookup", (client) =>
      client
        .query<{ provider_id: string | null }>(
          "SELECT provider_for_installation($1) AS provider_id",
          [installationId],
        )
        .then((r) => r.rows),
    );
    expect(found[0]?.provider_id).toBe(providerId);
  });
});

describe("the enrolment reference", () => {
  it("cannot be used twice", async () => {
    const reference = `ref-${Date.now()}-c`;
    await payFor(`ss-once-${Date.now()}`, reference);

    const first = await handleSetup(
      { installationId: String(Math.floor(Math.random() * 1e9)), state: reference },
      setupDeps(),
    );
    expect(first.kind).toBe("enrolled");

    // A reference is a bearer credential: whoever holds one could otherwise
    // bind their own installation to somebody else's paid tenant.
    const second = await handleSetup(
      { installationId: String(Math.floor(Math.random() * 1e9)), state: reference },
      setupDeps(),
    );
    expect(second).toEqual({ kind: "rejected", reason: "unknown-reference" });
  });

  it("refuses a reference nobody minted", async () => {
    const outcome = await handleSetup(
      { installationId: "12345", state: "not-a-real-reference" },
      setupDeps(),
    );
    expect(outcome).toEqual({ kind: "rejected", reason: "unknown-reference" });
  });

  it("refuses a callback with no state rather than falling back to a default", async () => {
    // The default IS the bug: with DEFAULT_PROVIDER_SLUG set, every customer's
    // installation enrolled into one tenant.
    const outcome = await handleSetup({ installationId: "12345", state: null }, setupDeps());
    expect(outcome).toEqual({ kind: "rejected", reason: "missing-state" });
  });

  for (const installationId of [null, "", "0", "-1", "not-a-number", "1e999"]) {
    it(`refuses installation_id ${JSON.stringify(installationId)}`, async () => {
      const outcome = await handleSetup({ installationId, state: "anything" }, setupDeps());
      expect(outcome.kind).toBe("rejected");
    });
  }

  it("is stored hashed, so the database never holds a usable reference", async () => {
    const reference = `ref-${Date.now()}-d`;
    const providerId = await payFor(`ss-hash-${Date.now()}`, reference);

    const admin = await adminClient();
    try {
      const { rows } = await admin.query<{ enrolment_ref_hash: string | null }>(
        "SELECT enrolment_ref_hash FROM provider WHERE id = $1",
        [providerId],
      );
      expect(rows[0]?.enrolment_ref_hash).toBe(hashToken(reference));
      expect(rows[0]?.enrolment_ref_hash).not.toBe(reference);
    } finally {
      await admin.end();
    }
  });
});
