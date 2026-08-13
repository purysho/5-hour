import { beforeAll, afterAll, describe, expect, it } from "vitest";
import {
  adminClient,
  appDatabase,
  prepareDatabase,
  seedProvider,
  type Fixture,
} from "./setup.ts";
import type { Database } from "../../src/db/client.ts";
import {
  GENESIS_HASH,
  verifyChain,
  type ExportedEntry,
} from "../../src/audit/verify.ts";

/**
 * Tamper-evident audit chain (ADR-0007).
 *
 * The claim being tested is specific: a customer can detect that we altered
 * the record of what we did in their repositories, without trusting us. So the
 * tests actually tamper — as a superuser, bypassing the application entirely,
 * which is the position an attacker with control-plane access would be in.
 */

let db: Database;
let tenant: Fixture;

beforeAll(async () => {
  await prepareDatabase();
  db = appDatabase();
  tenant = await seedProvider("audit");
});

afterAll(async () => {
  await db?.close();
});

async function append(
  fixture: Fixture,
  action: string,
  subject: string,
  metadata: Record<string, unknown> = {},
): Promise<string> {
  return db.withTenant(fixture.providerId, async (client) => {
    const result = await client.query<{ id: string }>(
      `INSERT INTO audit_entry (provider_id, action, subject, metadata)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [fixture.providerId, action, subject, JSON.stringify(metadata)],
    );
    return result.rows[0]!.id;
  });
}

async function exportChain(fixture: Fixture): Promise<ExportedEntry[]> {
  return db.withTenant(fixture.providerId, async (client) => {
    const result = await client.query<ExportedEntry>("SELECT * FROM audit_export($1)", [
      fixture.providerId,
    ]);
    return result.rows;
  });
}

describe("chain construction", () => {
  it("starts from the genesis hash and increments sequence", async () => {
    const fixture = await seedProvider("audit-genesis");
    await append(fixture, "token.mint", "github:acme/widgets");
    await append(fixture, "pr.open", "github:acme/widgets");

    const entries = await exportChain(fixture);
    expect(entries).toHaveLength(2);
    expect(Number(entries[0]!.seq)).toBe(1);
    expect(entries[0]!.prev_hash).toBe(GENESIS_HASH);
    expect(Number(entries[1]!.seq)).toBe(2);
    expect(entries[1]!.prev_hash).toBe(entries[0]!.entry_hash);
  });

  it("verifies a well-formed chain", async () => {
    const fixture = await seedProvider("audit-valid");
    for (let i = 0; i < 10; i++) {
      await append(fixture, "pr.open", `github:acme/repo-${i}`, { pr_number: i });
    }
    const result = verifyChain(await exportChain(fixture));
    expect(result.valid).toBe(true);
    expect(result.entriesChecked).toBe(10);
    expect(result.failures).toEqual([]);
  });

  it("keeps each tenant's chain independent", async () => {
    const a = await seedProvider("audit-tenant-a");
    const b = await seedProvider("audit-tenant-b");
    await append(a, "pr.open", "github:a/one");
    await append(b, "pr.open", "github:b/one");
    await append(a, "pr.open", "github:a/two");

    const chainA = await exportChain(a);
    const chainB = await exportChain(b);
    expect(chainA.map((e) => Number(e.seq))).toEqual([1, 2]);
    expect(chainB.map((e) => Number(e.seq))).toEqual([1]);
    expect(verifyChain(chainA).valid).toBe(true);
    expect(verifyChain(chainB).valid).toBe(true);
  });

  it("assigns unique sequence numbers under concurrent appends", async () => {
    // Serialisation comes from the FOR UPDATE lock on the chain head. Two
    // writers claiming the same sequence would break the chain silently.
    const fixture = await seedProvider("audit-concurrent");
    await Promise.all(
      Array.from({ length: 20 }, (_, i) => append(fixture, "pr.open", `github:x/r${i}`)),
    );
    const entries = await exportChain(fixture);
    expect(entries).toHaveLength(20);
    expect(new Set(entries.map((e) => Number(e.seq))).size).toBe(20);
    expect(verifyChain(entries).valid).toBe(true);
  });
});

describe("write-ahead intent and outcome", () => {
  it("records the outcome as a separate entry referencing the intent", async () => {
    // A log with an UPDATE in it is not append-only. The outcome is a new
    // entry, so the intent record survives verbatim.
    const fixture = await seedProvider("audit-writeahead");
    const intentId = await append(fixture, "pr.open.intent", "github:acme/widgets", {
      base_sha: "a".repeat(40),
    });

    await db.withTenant(fixture.providerId, async (client) => {
      await client.query(
        `INSERT INTO audit_entry (provider_id, action, subject, intent_id, metadata)
         VALUES ($1, 'pr.open.outcome', 'github:acme/widgets', $2, $3)`,
        [fixture.providerId, intentId, JSON.stringify({ pr_number: 12 })],
      );
    });

    const entries = await exportChain(fixture);
    expect(entries).toHaveLength(2);
    expect(verifyChain(entries).valid).toBe(true);
  });
});

describe("append-only enforcement", () => {
  it("refuses updates to audit entries", async () => {
    await append(tenant, "pr.open", "github:acme/widgets");
    await expect(
      db.withTenant(tenant.providerId, async (client) => {
        await client.query("UPDATE audit_entry SET action = 'tampered'");
      }),
    ).rejects.toThrow();
  });

  it("refuses deletes of audit entries", async () => {
    await expect(
      db.withTenant(tenant.providerId, async (client) => {
        await client.query("DELETE FROM audit_entry");
      }),
    ).rejects.toThrow();
  });

  it("grants the application no UPDATE or DELETE privilege on audit_entry", async () => {
    const client = await adminClient();
    try {
      const { rows } = await client.query<{ privilege_type: string }>(
        `SELECT privilege_type FROM information_schema.role_table_grants
         WHERE table_name = 'audit_entry' AND grantee = 'driftless_app'`,
      );
      const granted = rows.map((r) => r.privilege_type).sort();
      expect(granted).toEqual(["INSERT", "SELECT"]);
    } finally {
      await client.end();
    }
  });
});

describe("tamper detection", () => {
  /**
   * These bypass the application and the triggers, using a superuser — the
   * position an attacker with control-plane access holds. If tampering were
   * only detectable when performed through our own API, the control would be
   * worthless in the scenario it exists for (threat-model §5.4).
   */

  it("detects an altered entry", async () => {
    const fixture = await seedProvider("audit-tamper-alter");
    await append(fixture, "pr.open", "github:acme/widgets", { pr_number: 1 });
    await append(fixture, "pr.open", "github:acme/gadgets", { pr_number: 2 });

    const client = await adminClient();
    try {
      await client.query("ALTER TABLE audit_entry DISABLE TRIGGER audit_entry_no_update");
      await client.query(
        "UPDATE audit_entry SET subject = 'github:attacker/evil' WHERE seq = 1 AND provider_id = $1",
        [fixture.providerId],
      );
      await client.query("ALTER TABLE audit_entry ENABLE TRIGGER audit_entry_no_update");
    } finally {
      await client.end();
    }

    const result = verifyChain(await exportChain(fixture));
    expect(result.valid).toBe(false);
    expect(result.failures.some((f) => f.kind === "hash_mismatch")).toBe(true);
  });

  it("detects a removed entry", async () => {
    const fixture = await seedProvider("audit-tamper-delete");
    for (let i = 0; i < 4; i++) {
      await append(fixture, "pr.open", `github:acme/r${i}`);
    }

    const client = await adminClient();
    try {
      await client.query("ALTER TABLE audit_entry DISABLE TRIGGER audit_entry_no_update");
      await client.query("DELETE FROM audit_entry WHERE seq = 2 AND provider_id = $1", [
        fixture.providerId,
      ]);
      await client.query("ALTER TABLE audit_entry ENABLE TRIGGER audit_entry_no_update");
    } finally {
      await client.end();
    }

    const result = verifyChain(await exportChain(fixture));
    expect(result.valid).toBe(false);
    expect(
      result.failures.some((f) => f.kind === "sequence_gap" || f.kind === "broken_link"),
    ).toBe(true);
  });

  it("detects history rewritten after a published checkpoint", async () => {
    // The property that matters most. Chaining alone only proves internal
    // consistency — an attacker with write access can recompute a fully
    // consistent chain. Anchoring to a checkpoint the customer already holds
    // is what makes the rewrite detectable.
    const fixture = await seedProvider("audit-checkpoint");
    await append(fixture, "pr.open", "github:acme/widgets");
    await append(fixture, "pr.open", "github:acme/gadgets");

    const original = await exportChain(fixture);
    const customerHeldCheckpoint = {
      seq: 2,
      head_hash: original[1]!.entry_hash,
    };

    const client = await adminClient();
    try {
      await client.query("ALTER TABLE audit_entry DISABLE TRIGGER audit_entry_no_update");
      // A thorough attacker recomputes the chain so it verifies internally.
      await client.query(
        `UPDATE audit_entry SET subject = 'github:acme/innocuous',
           entry_hash = encode(sha256(convert_to(
             audit_canonical_payload(seq, prev_hash, provider_id, action,
               'github:acme/innocuous', intent_id, metadata, occurred_at), 'UTF8')), 'hex')
         WHERE seq = 2 AND provider_id = $1`,
        [fixture.providerId],
      );
      await client.query("ALTER TABLE audit_entry ENABLE TRIGGER audit_entry_no_update");
    } finally {
      await client.end();
    }

    const rewritten = await exportChain(fixture);

    // Internally consistent — the rewrite was competent.
    expect(verifyChain(rewritten).valid).toBe(true);

    // Against the checkpoint the customer already had, it fails.
    const checked = verifyChain(rewritten, [customerHeldCheckpoint]);
    expect(checked.valid).toBe(false);
    expect(checked.failures.some((f) => f.kind === "checkpoint_mismatch")).toBe(true);
  });
});
