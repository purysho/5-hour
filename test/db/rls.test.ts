import { beforeAll, afterAll, describe, expect, it } from "vitest";
import type pg from "pg";
import {
  adminClient,
  appDatabase,
  prepareDatabase,
  seedProvider,
  type Fixture,
} from "./setup.ts";
import type { Database } from "../../src/db/client.ts";

/**
 * Cross-tenant isolation probes (ADR-0005 §4).
 *
 * Providers are frequently competitors, and we hold their consumer lists and
 * version-fragmentation data simultaneously. A leak here ends the business,
 * so the isolation claim is tested rather than asserted.
 *
 * Every one of these probes runs through the application role with legitimate
 * tenant context. None of them attempt anything exotic — they do exactly what
 * a bug in a WHERE clause would do.
 */

let db: Database;
let acme: Fixture;
let globex: Fixture;

beforeAll(async () => {
  await prepareDatabase();
  db = appDatabase();
  acme = await seedProvider("acme");
  globex = await seedProvider("globex");
});

afterAll(async () => {
  await db?.close();
});

describe("tenant isolation", () => {
  it("sees only its own provider row", async () => {
    const rows = await db.withTenant(acme.providerId, async (client) => {
      const result = await client.query("SELECT id, slug FROM provider");
      return result.rows;
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ id: acme.providerId, slug: "acme" });
  });

  it("cannot read another tenant's repositories even when naming them directly", async () => {
    const rows = await db.withTenant(acme.providerId, async (client) => {
      const result = await client.query("SELECT id FROM repository WHERE id = $1", [
        globex.repositoryId,
      ]);
      return result.rows;
    });
    // Not an error — an empty result. RLS filters rather than raising, which
    // is what makes a forgotten predicate harmless instead of catastrophic.
    expect(rows).toHaveLength(0);
  });

  it("cannot read another tenant's consumers", async () => {
    const rows = await db.withTenant(globex.providerId, async (client) => {
      const result = await client.query("SELECT id, forge_owner FROM consumer");
      return result.rows;
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.["forge_owner"]).toBe("globex-consumer");
  });

  it("cannot write a row attributed to another tenant", async () => {
    // WITH CHECK, not just USING. A policy with only USING lets a tenant
    // insert rows belonging to someone else, which is the more damaging half.
    await expect(
      db.withTenant(acme.providerId, async (client) => {
        await client.query(
          "INSERT INTO consumer (provider_id, forge_owner) VALUES ($1, $2)",
          [globex.providerId, "smuggled"],
        );
      }),
    ).rejects.toThrow(/row-level security/i);
  });

  it("cannot update another tenant's rows", async () => {
    const updated = await db.withTenant(acme.providerId, async (client) => {
      const result = await client.query(
        "UPDATE repository SET default_branch = 'hijacked' WHERE id = $1",
        [globex.repositoryId],
      );
      return result.rowCount;
    });
    expect(updated).toBe(0);

    const stillIntact = await db.withTenant(globex.providerId, async (client) => {
      const result = await client.query<{ default_branch: string }>(
        "SELECT default_branch FROM repository WHERE id = $1",
        [globex.repositoryId],
      );
      return result.rows[0]?.default_branch;
    });
    expect(stillIntact).toBe("main");
  });

  it("cannot delete another tenant's rows", async () => {
    const deleted = await db.withTenant(acme.providerId, async (client) => {
      const result = await client.query("DELETE FROM repository WHERE id = $1", [
        globex.repositoryId,
      ]);
      return result.rowCount;
    });
    expect(deleted).toBe(0);
  });

  it("returns nothing when tenant context is missing", async () => {
    // The fail-closed property. current_provider_id() is NULL, every policy
    // compares `= NULL` which is NULL rather than TRUE, so no row matches.
    const client = await adminClient();
    try {
      await client.query("SET ROLE driftless_app");
      const result = await client.query("SELECT id FROM provider");
      expect(result.rows).toHaveLength(0);
    } finally {
      await client.end();
    }
  });

  it("does not leak tenant context between pooled connections", async () => {
    // set_config is transaction-local, so a connection returned to the pool
    // cannot carry one tenant's context into the next borrower's query.
    await db.withTenant(acme.providerId, async (client) => {
      await client.query("SELECT 1 FROM provider");
    });
    for (let i = 0; i < 5; i++) {
      const rows = await db.withTenant(globex.providerId, async (client) => {
        const result = await client.query<{ slug: string }>("SELECT slug FROM provider");
        return result.rows;
      });
      expect(rows).toHaveLength(1);
      expect(rows[0]?.slug).toBe("globex");
    }
  });

  it("rejects a malformed tenant identifier loudly", async () => {
    await expect(
      db.withTenant("not-a-uuid", async (client) => client.query("SELECT 1")),
    ).rejects.toThrow(/must be a UUID/);
  });
});

describe("RLS coverage", () => {
  /**
   * ADR-0005 §5: a migration that adds a tenant-scoped table without RLS must
   * fail the build. This is where that discipline realistically decays, so it
   * is automated rather than left to review.
   */
  it("enables and forces RLS on every table with a provider_id column", async () => {
    const client = await adminClient();
    try {
      const { rows } = await client.query<{
        tablename: string;
        rowsecurity: boolean;
        forced: boolean;
        policies: number;
      }>(`
        SELECT c.relname AS tablename,
               c.relrowsecurity  AS rowsecurity,
               c.relforcerowsecurity AS forced,
               (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid)::int AS policies
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind = 'r'
          AND EXISTS (
            SELECT 1 FROM information_schema.columns col
            WHERE col.table_name = c.relname
              AND col.table_schema = 'public'
              AND col.column_name IN ('provider_id')
          )
      `);

      expect(rows.length).toBeGreaterThan(0);
      const offenders = rows.filter(
        (r) => !r.rowsecurity || !r.forced || r.policies === 0,
      );
      expect(
        offenders,
        `tables with provider_id lacking enabled+forced RLS and a policy: ${offenders
          .map((o) => o.tablename)
          .join(", ")}`,
      ).toEqual([]);
    } finally {
      await client.end();
    }
  });

  it("grants the application role no BYPASSRLS", async () => {
    const client = await adminClient();
    try {
      const { rows } = await client.query<{ rolname: string; rolbypassrls: boolean }>(
        "SELECT rolname, rolbypassrls FROM pg_roles WHERE rolname LIKE 'driftless%'",
      );
      expect(rows.length).toBeGreaterThan(0);
      for (const role of rows) {
        expect(role.rolbypassrls, `${role.rolname} must not bypass RLS`).toBe(false);
      }
    } finally {
      await client.end();
    }
  });

  it("gives every policy a WITH CHECK clause, not only USING", async () => {
    const client = await adminClient();
    try {
      const { rows } = await client.query<{ polname: string; withcheck: string | null }>(`
        SELECT polname, pg_get_expr(polwithcheck, polrelid) AS withcheck
        FROM pg_policy
        WHERE polcmd = '*'
      `);
      expect(rows.length).toBeGreaterThan(0);
      const missing = rows.filter((r) => r.withcheck === null).map((r) => r.polname);
      expect(missing, `policies without WITH CHECK: ${missing.join(", ")}`).toEqual([]);
    } finally {
      await client.end();
    }
  });
});
