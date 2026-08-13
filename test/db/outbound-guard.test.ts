import { beforeAll, afterAll, describe, expect, it } from "vitest";
import {
  adminClient,
  appDatabase,
  prepareDatabase,
  seedProvider,
  SHA_A,
  SHA_B,
  type Fixture,
} from "./setup.ts";
import type { Database } from "../../src/db/client.ts";
import {
  authoriseOutboundWrite,
  recordOutboundResult,
} from "../../src/outbound/guard.ts";

/**
 * The last gate before anything reaches a customer repository (ADR-0004).
 *
 * Three brakes, checked in increasing order of cost: the global kill switch,
 * per-installation ceilings, then the idempotency claim. The ordering is
 * itself under test — a halted system must not consume claims, or resuming
 * after an incident would find every write already claimed and silently skip
 * the work it was halted to protect.
 */

let db: Database;

beforeAll(async () => {
  await prepareDatabase();
  db = appDatabase();
});

afterAll(async () => {
  await db?.close();
  await setHalted(false, "test cleanup");
});

async function setHalted(halted: boolean, reason: string): Promise<void> {
  const client = await adminClient();
  try {
    await client.query(
      "UPDATE outbound_kill_switch SET halted = $1, reason = $2, halted_by = 'test'",
      [halted, reason],
    );
  } finally {
    await client.end();
  }
}

function request(fixture: Fixture, baseSha = SHA_A) {
  return {
    providerId: fixture.providerId,
    installationId: fixture.installationId,
    repositoryId: fixture.repositoryId,
    changeId: fixture.changeId,
    baseSha,
  };
}

describe("the happy path", () => {
  it("authorises a first write and records its result", async () => {
    const tenant = await seedProvider("guard-happy");
    const decision = await db.withTenant(tenant.providerId, (client) =>
      authoriseOutboundWrite(client, request(tenant)),
    );

    expect(decision.allowed).toBe(true);
    if (!decision.allowed) return;

    await db.withTenant(tenant.providerId, (client) =>
      recordOutboundResult(client, decision.writeId, {
        status: "succeeded",
        prNumber: 5,
        prUrl: "https://github.com/acme/widgets/pull/5",
      }),
    );

    const second = await db.withTenant(tenant.providerId, (client) =>
      authoriseOutboundWrite(client, request(tenant)),
    );
    expect(second.allowed).toBe(false);
    if (second.allowed) return;
    expect(second.reason).toBe("already-written");
    if (second.reason !== "already-written") return;
    expect(second.prNumber).toBe(5);
  });

  it("records a failure without losing the claim", async () => {
    // A failed write keeps its row. The write may have succeeded remotely
    // without reporting, so releasing the claim would risk a duplicate.
    const tenant = await seedProvider("guard-failure");
    const decision = await db.withTenant(tenant.providerId, (client) =>
      authoriseOutboundWrite(client, request(tenant)),
    );
    expect(decision.allowed).toBe(true);
    if (!decision.allowed) return;

    await db.withTenant(tenant.providerId, (client) =>
      recordOutboundResult(client, decision.writeId, {
        status: "failed",
        error: "github returned 502",
      }),
    );

    const retry = await db.withTenant(tenant.providerId, (client) =>
      authoriseOutboundWrite(client, request(tenant)),
    );
    expect(retry.allowed).toBe(false);
  });
});

describe("the kill switch", () => {
  it("blocks writes when halted", async () => {
    const tenant = await seedProvider("guard-halt");
    await setHalted(true, "incident 2026-08-13");
    try {
      const decision = await db.withTenant(tenant.providerId, (client) =>
        authoriseOutboundWrite(client, request(tenant)),
      );
      expect(decision.allowed).toBe(false);
      if (decision.allowed) return;
      expect(decision.reason).toBe("kill-switch");
      if (decision.reason !== "kill-switch") return;
      expect(decision.detail).toContain("incident");
    } finally {
      await setHalted(false, "resumed");
    }
  });

  it("consumes no claim while halted, so nothing is skipped on resume", async () => {
    // The ordering guarantee. If the halt check ran after the claim, resuming
    // would find every write already claimed and silently skip the work.
    const tenant = await seedProvider("guard-halt-noclaim");
    await setHalted(true, "halted");
    try {
      await db.withTenant(tenant.providerId, (client) =>
        authoriseOutboundWrite(client, request(tenant)),
      );
      const claims = await db.withTenant(tenant.providerId, async (client) => {
        const { rows } = await client.query("SELECT id FROM outbound_write");
        return rows;
      });
      expect(claims).toHaveLength(0);
    } finally {
      await setHalted(false, "resumed");
    }

    const afterResume = await db.withTenant(tenant.providerId, (client) =>
      authoriseOutboundWrite(client, request(tenant)),
    );
    expect(afterResume.allowed).toBe(true);
  });

  it("is not tenant-scoped — one flip halts everyone", async () => {
    const a = await seedProvider("guard-halt-a");
    const b = await seedProvider("guard-halt-b");
    await setHalted(true, "global");
    try {
      for (const tenant of [a, b]) {
        const decision = await db.withTenant(tenant.providerId, (client) =>
          authoriseOutboundWrite(client, request(tenant)),
        );
        expect(decision.allowed).toBe(false);
      }
    } finally {
      await setHalted(false, "resumed");
    }
  });
});

describe("rate ceilings", () => {
  it("blocks once the hourly write ceiling is reached", async () => {
    const tenant = await seedProvider("guard-rate");
    const client = await adminClient();
    try {
      await client.query(
        `INSERT INTO outbound_rate_limit (installation_id, provider_id, max_writes_per_hour)
         VALUES ($1, $2, 2)`,
        [tenant.installationId, tenant.providerId],
      );
    } finally {
      await client.end();
    }

    const shas = [SHA_A, SHA_B, "c".repeat(40)];
    const decisions = [];
    for (const sha of shas) {
      decisions.push(
        await db.withTenant(tenant.providerId, (c) =>
          authoriseOutboundWrite(c, request(tenant, sha)),
        ),
      );
    }

    expect(decisions[0]!.allowed).toBe(true);
    expect(decisions[1]!.allowed).toBe(true);
    expect(decisions[2]!.allowed).toBe(false);
    const blocked = decisions[2]!;
    if (blocked.allowed) return;
    expect(blocked.reason).toBe("rate-limit");
    if (blocked.reason !== "rate-limit") return;
    expect(blocked.detail).toContain("ceiling is 2");
  });

  it("blocks once the open pull request ceiling is reached", async () => {
    const tenant = await seedProvider("guard-open-prs");
    const client = await adminClient();
    try {
      await client.query(
        `INSERT INTO outbound_rate_limit (installation_id, provider_id, max_open_prs)
         VALUES ($1, $2, 1)`,
        [tenant.installationId, tenant.providerId],
      );
    } finally {
      await client.end();
    }

    const first = await db.withTenant(tenant.providerId, (c) =>
      authoriseOutboundWrite(c, request(tenant, SHA_A)),
    );
    expect(first.allowed).toBe(true);
    if (!first.allowed) return;
    await db.withTenant(tenant.providerId, (c) =>
      recordOutboundResult(c, first.writeId, {
        status: "succeeded",
        prNumber: 1,
        prUrl: "https://example/1",
      }),
    );

    const second = await db.withTenant(tenant.providerId, (c) =>
      authoriseOutboundWrite(c, request(tenant, SHA_B)),
    );
    expect(second.allowed).toBe(false);
    if (second.allowed) return;
    expect(second.reason).toBe("rate-limit");
  });

  it("applies a default ceiling to an installation with no explicit limit", async () => {
    const tenant = await seedProvider("guard-default-limit");
    const decision = await db.withTenant(tenant.providerId, (c) =>
      authoriseOutboundWrite(c, request(tenant)),
    );
    expect(decision.allowed).toBe(true);
  });
});

describe("input validation", () => {
  it("rejects a malformed base sha before touching the database", async () => {
    const tenant = await seedProvider("guard-badsha");
    await expect(
      db.withTenant(tenant.providerId, (c) =>
        authoriseOutboundWrite(c, request(tenant, "HEAD")),
      ),
    ).rejects.toThrow(/40-character lowercase hex/);
  });
});
