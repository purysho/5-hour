import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { appDatabase, prepareDatabase, seedProvider, type Fixture } from "../db/setup.ts";
import { MINT_INTENT, MINT_OUTCOME, postgresAuditSink } from "../../src/audit/sink.ts";
import type { Database } from "../../src/db/client.ts";

/**
 * The audit sink, against the real chain.
 *
 * Tested with a database rather than a stub because the guarantees being
 * checked are the database's: the trigger assigns the sequence and the hash,
 * the grant makes the table append-only, and RLS decides whose chain a row
 * lands in. A mock would assert that this module calls SQL, which is not the
 * property that matters.
 */

let db: Database;
let tenant: Fixture;

beforeAll(async () => {
  await prepareDatabase();
  db = appDatabase();
  tenant = await seedProvider(`audit-sink-${Date.now()}`);
});

afterAll(async () => {
  await db.close();
});

interface Entry {
  seq: string;
  action: string;
  subject: string;
  intent_id: string | null;
  metadata: Record<string, unknown>;
}

async function entries(): Promise<Entry[]> {
  return db.withTenant(tenant.providerId, async (client) => {
    const { rows } = await client.query<Entry>(
      `SELECT seq, action, subject, intent_id, metadata
         FROM audit_entry ORDER BY seq`,
    );
    return rows;
  });
}

function sink() {
  return postgresAuditSink({ withTenant: (id, fn) => db.withTenant(id, fn) }, tenant.providerId);
}

const INTENT = {
  tokenId: "token-1",
  installationId: "install-1",
  repositoryId: "repo-1",
  permissions: { contents: "write", pull_requests: "write" },
  ttlSeconds: 600,
};

describe("recording a mint", () => {
  it("writes the intent before the token exists, and links the outcome to it", async () => {
    // ADR-0007 §2. A token with no preceding intent entry is evidence of
    // compromise; that inference only works if the intent is always first and
    // the outcome always points back at it.
    const audit = sink();

    await audit.recordMintIntent({ ...INTENT, tokenId: `t-${Date.now()}` });
    const afterIntent = await entries();
    const intent = afterIntent[afterIntent.length - 1]!;

    expect(intent.action).toBe(MINT_INTENT);

    await audit.recordMintOutcome({
      tokenId: intent.metadata["tokenId"] as string,
      succeeded: true,
      expiresAt: new Date().toISOString(),
    });

    const all = await entries();
    const outcome = all[all.length - 1]!;
    expect(outcome.action).toBe(MINT_OUTCOME);
    expect(outcome.intent_id).toBeTruthy();
    expect(Number(outcome.seq)).toBe(Number(intent.seq) + 1);
  });

  it("records which repository the grant was for", async () => {
    const audit = sink();
    const tokenId = `t-subject-${Date.now()}`;

    await audit.recordMintIntent({ ...INTENT, tokenId, repositoryId: "repo-42" });

    const all = await entries();
    expect(all[all.length - 1]!.subject).toBe("repository:repo-42");
  });

  it("records a failed mint rather than only the successful ones", async () => {
    // The failures are the interesting half: a burst of them is what a stolen
    // app key looks like from inside.
    const audit = sink();
    const tokenId = `t-fail-${Date.now()}`;

    await audit.recordMintIntent({ ...INTENT, tokenId });
    await audit.recordMintOutcome({ tokenId, succeeded: false, error: "401 Bad credentials" });

    const all = await entries();
    const outcome = all[all.length - 1]!;
    expect(outcome.metadata["succeeded"]).toBe(false);
    expect(outcome.metadata["error"]).toBe("401 Bad credentials");
  });

  it("never writes the token itself", async () => {
    // ADR-0007 §6. The log records the shape of the grant, not the grant.
    const audit = sink();
    const tokenId = `t-secret-${Date.now()}`;

    await audit.recordMintIntent({ ...INTENT, tokenId });
    await audit.recordMintOutcome({ tokenId, succeeded: true, expiresAt: "2026-01-01T00:00:00Z" });

    const serialised = JSON.stringify(await entries());
    expect(serialised).not.toContain("ghs_");
    expect(serialised).not.toContain("ghp_");
  });

  it("truncates an error the forge could otherwise make arbitrarily long", async () => {
    const audit = sink();
    const tokenId = `t-long-${Date.now()}`;

    await audit.recordMintIntent({ ...INTENT, tokenId });
    await audit.recordMintOutcome({ tokenId, succeeded: false, error: "x".repeat(5_000) });

    const all = await entries();
    expect((all[all.length - 1]!.metadata["error"] as string).length).toBe(500);
  });
});

describe("append-only", () => {
  it("refuses to let a recorded mint be edited afterwards", async () => {
    // Not this module's doing — the grant refuses UPDATE before the trigger
    // ever runs (migration 003 calls the grant the real control and the
    // trigger defence in depth, and this is what that looks like from the
    // application role). Asserted here because the sink's value depends on it:
    // a log that can be rewritten proves nothing.
    const audit = sink();
    const tokenId = `t-immutable-${Date.now()}`;
    await audit.recordMintIntent({ ...INTENT, tokenId });

    await expect(
      db.withTenant(tenant.providerId, (client) =>
        client.query("UPDATE audit_entry SET action = 'tampered' WHERE action = $1", [MINT_INTENT]),
      ),
    ).rejects.toThrow(/permission denied|append-only/);
  });
});
