import { beforeAll, afterAll, describe, expect, it } from "vitest";
import {
  appDatabase,
  prepareDatabase,
  seedProvider,
  SHA_A,
  SHA_B,
  type Fixture,
} from "./setup.ts";
import type { Database } from "../../src/db/client.ts";

/**
 * Exactly-once outbound writes (ADR-0004).
 *
 * Threat-model §5.6 rates a duplicate-PR incident as more probable than any
 * attack in this system, and unrecoverable in the way that matters: forty pull
 * requests in a customer's repository costs their trust permanently.
 *
 * So the guarantee is tested the way it will actually be attacked in
 * production — by concurrency and by crashes, not by calling the function
 * twice in sequence.
 */

interface ClaimResult {
  write_id: string;
  is_owner: boolean;
  status: string;
  pr_number: number | null;
  pr_url: string | null;
  attempts: number;
}

let db: Database;
let tenant: Fixture;

beforeAll(async () => {
  await prepareDatabase();
  db = appDatabase();
  tenant = await seedProvider("idem");
});

afterAll(async () => {
  await db?.close();
});

function claim(
  fixture: Fixture,
  baseSha: string,
  ttl = "10 minutes",
): Promise<ClaimResult> {
  return db.withTenant(fixture.providerId, async (client) => {
    const result = await client.query<ClaimResult>(
      "SELECT * FROM claim_outbound_write($1, $2, $3, $4, $5, $6::interval)",
      [
        fixture.providerId,
        fixture.installationId,
        fixture.repositoryId,
        fixture.changeId,
        baseSha,
        ttl,
      ],
    );
    return result.rows[0]!;
  });
}

function resolve(
  fixture: Fixture,
  writeId: string,
  status: string,
  prNumber?: number,
): Promise<void> {
  return db.withTenant(fixture.providerId, async (client) => {
    await client.query(
      "SELECT resolve_outbound_write($1, $2::outbound_write_status, $3, $4, NULL)",
      [writeId, status, prNumber ?? null, prNumber ? `https://example/pr/${prNumber}` : null],
    );
  });
}

describe("exactly-once outbound writes", () => {
  it("grants ownership to the first caller only", async () => {
    const first = await claim(tenant, SHA_A);
    expect(first.is_owner).toBe(true);

    const second = await claim(tenant, SHA_A);
    expect(second.is_owner).toBe(false);
    expect(second.write_id).toBe(first.write_id);
  });

  it("returns the prior result to a late caller instead of writing again", async () => {
    const fixture = await seedProvider("idem-prior-result");
    const owner = await claim(fixture, SHA_A);
    await resolve(fixture, owner.write_id, "succeeded", 42);

    const late = await claim(fixture, SHA_A);
    expect(late.is_owner).toBe(false);
    expect(late.status).toBe("succeeded");
    expect(late.pr_number).toBe(42);
    expect(late.pr_url).toBe("https://example/pr/42");
  });

  it("treats a different base_sha as a different migration", async () => {
    // The repository moved on, so this genuinely needs a new pull request.
    // Keying on (repository, change) alone would silently skip it — a failure
    // that is invisible, which is worse than a duplicate.
    const moved = await claim(tenant, SHA_B);
    expect(moved.is_owner).toBe(true);
    await resolve(tenant, moved.write_id, "succeeded", 43);
  });

  it("grants ownership to exactly one of many concurrent callers", async () => {
    const concurrent = await seedProvider("idem-concurrent");
    const attempts = 25;

    const results = await Promise.all(
      Array.from({ length: attempts }, () => claim(concurrent, SHA_A)),
    );

    const owners = results.filter((r) => r.is_owner);
    expect(owners).toHaveLength(1);

    const ids = new Set(results.map((r) => r.write_id));
    expect(ids.size).toBe(1);
  });

  it("keeps exactly one row under concurrent load", async () => {
    const concurrent = await seedProvider("idem-rowcount");
    await Promise.all(Array.from({ length: 20 }, () => claim(concurrent, SHA_A)));

    const count = await db.withTenant(concurrent.providerId, async (client) => {
      const result = await client.query<{ count: string }>(
        "SELECT count(*) FROM outbound_write",
      );
      return Number(result.rows[0]!.count);
    });
    expect(count).toBe(1);
  });

  it("reclaims an expired claim without creating a second row", async () => {
    // Simulates a worker that died after claiming and before writing. The row
    // is reused, so the guarantee survives the crash.
    const crashed = await seedProvider("idem-crash");
    const first = await claim(crashed, SHA_A, "0 seconds");
    expect(first.is_owner).toBe(true);

    const reclaimed = await claim(crashed, SHA_A);
    expect(reclaimed.is_owner).toBe(true);
    expect(reclaimed.write_id).toBe(first.write_id);
    expect(reclaimed.attempts).toBe(2);

    const count = await db.withTenant(crashed.providerId, async (client) => {
      const result = await client.query<{ count: string }>(
        "SELECT count(*) FROM outbound_write",
      );
      return Number(result.rows[0]!.count);
    });
    expect(count).toBe(1);
  });

  it("does not reclaim a live claim", async () => {
    const live = await seedProvider("idem-live");
    const first = await claim(live, SHA_A, "1 hour");
    expect(first.is_owner).toBe(true);

    const second = await claim(live, SHA_A);
    expect(second.is_owner).toBe(false);
    expect(second.attempts).toBe(1);
  });

  it("refuses to resolve the same write twice", async () => {
    // Resolving an already-resolved row would overwrite the recorded result of
    // a side effect that actually happened.
    const once = await seedProvider("idem-resolve-once");
    const claimed = await claim(once, SHA_A);
    await resolve(once, claimed.write_id, "succeeded", 7);
    await expect(resolve(once, claimed.write_id, "failed")).rejects.toThrow(
      /not in claimed state/,
    );
  });

  it("rejects a claim attributed to another tenant", async () => {
    const other = await seedProvider("idem-other");
    await expect(
      db.withTenant(tenant.providerId, async (client) => {
        await client.query(
          "SELECT * FROM claim_outbound_write($1, $2, $3, $4, $5)",
          [
            other.providerId,
            other.installationId,
            other.repositoryId,
            other.changeId,
            SHA_A,
          ],
        );
      }),
    ).rejects.toThrow(/row-level security/i);
  });

  it("rejects a malformed base_sha at the database", async () => {
    const bad = await seedProvider("idem-badsha");
    await expect(claim(bad, "not-a-sha")).rejects.toThrow(/base_sha_is_sha/);
  });
});

describe("the idempotency index", () => {
  it("exists, is unique, and is not partial", async () => {
    // A partial index — excluding failed rows so they can be "retried
    // cleanly" — reintroduces the duplicate the index exists to prevent: a
    // write that failed to report success may still have succeeded remotely.
    // Guarding it in a test because the change looks harmless in review.
    const client = await (await import("./setup.ts")).adminClient();
    try {
      const { rows } = await client.query<{
        indexdef: string;
        indisunique: boolean;
      }>(`
        SELECT pg_get_indexdef(i.indexrelid) AS indexdef, i.indisunique
        FROM pg_index i
        JOIN pg_class c ON c.oid = i.indexrelid
        WHERE c.relname = 'outbound_write_idempotency_key'
      `);
      expect(rows).toHaveLength(1);
      expect(rows[0]!.indisunique).toBe(true);
      expect(rows[0]!.indexdef).not.toMatch(/WHERE/i);
      expect(rows[0]!.indexdef).toMatch(/installation_id/);
      expect(rows[0]!.indexdef).toMatch(/repository_id/);
      expect(rows[0]!.indexdef).toMatch(/change_id/);
      expect(rows[0]!.indexdef).toMatch(/base_sha/);
    } finally {
      await client.end();
    }
  });
});
