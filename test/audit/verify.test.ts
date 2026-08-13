import { describe, expect, it } from "vitest";
import {
  describeFailure,
  GENESIS_HASH,
  hashPayload,
  verifyChain,
  type ExportedEntry,
} from "../../src/audit/verify.ts";

/**
 * Unit tests for the verifier a customer runs (ADR-0007 §4).
 *
 * This is the one piece of Driftless that runs on someone else's machine, in
 * an adversarial frame of mind, to check up on us. If it reports "valid" on a
 * tampered chain, every other control in ADR-0007 is decorative — so the
 * failure paths matter more here than the happy path.
 */

function entry(seq: number, prevHash: string, body: string): ExportedEntry {
  const canonical = `${seq}\n${prevHash}\n${body}`;
  return {
    seq,
    prev_hash: prevHash,
    entry_hash: hashPayload(canonical),
    canonical_payload: canonical,
  };
}

function chain(length: number): ExportedEntry[] {
  const entries: ExportedEntry[] = [];
  let prev = GENESIS_HASH;
  for (let i = 1; i <= length; i++) {
    const e = entry(i, prev, `action-${i}`);
    entries.push(e);
    prev = e.entry_hash;
  }
  return entries;
}

describe("verifyChain", () => {
  it("accepts a well-formed chain", () => {
    const result = verifyChain(chain(5));
    expect(result.valid).toBe(true);
    expect(result.entriesChecked).toBe(5);
    expect(result.headHash).toBe(chain(5).at(-1)?.entry_hash);
  });

  it("treats an empty export as valid only when no checkpoints are claimed", () => {
    expect(verifyChain([]).valid).toBe(true);
    expect(verifyChain([], [{ seq: 1, head_hash: "x" }]).valid).toBe(false);
  });

  it("detects altered content", () => {
    const entries = chain(3);
    entries[1] = { ...entries[1]!, canonical_payload: "2\n" + entries[1]!.prev_hash + "\ntampered" };
    const result = verifyChain(entries);
    expect(result.valid).toBe(false);
    expect(result.failures.some((f) => f.kind === "hash_mismatch")).toBe(true);
  });

  it("detects a broken link", () => {
    const entries = chain(3);
    entries[2] = { ...entries[2]!, prev_hash: "f".repeat(64) };
    const result = verifyChain(entries);
    expect(result.failures.some((f) => f.kind === "broken_link")).toBe(true);
  });

  it("detects a sequence gap", () => {
    const entries = chain(4);
    entries.splice(1, 1);
    const result = verifyChain(entries);
    expect(result.failures.some((f) => f.kind === "sequence_gap")).toBe(true);
  });

  it("detects a replaced chain head", () => {
    const entries = chain(3);
    entries[0] = entry(1, "9".repeat(64), "action-1");
    const result = verifyChain(entries);
    expect(result.failures.some((f) => f.kind === "bad_genesis")).toBe(true);
  });

  it("accepts a partial export that legitimately starts mid-chain", () => {
    // Customers may export a window rather than the whole history, so a first
    // entry above sequence 1 is not itself evidence of tampering.
    const full = chain(6);
    const window = full.slice(3);
    const result = verifyChain(window);
    expect(result.valid).toBe(true);
    expect(result.entriesChecked).toBe(3);
  });

  it("flags a checkpoint with no corresponding entry", () => {
    const result = verifyChain(chain(3), [{ seq: 99, head_hash: "a".repeat(64) }]);
    expect(result.failures.some((f) => f.kind === "checkpoint_missing")).toBe(true);
  });

  it("flags a checkpoint that disagrees with the export", () => {
    const result = verifyChain(chain(3), [{ seq: 2, head_hash: "b".repeat(64) }]);
    expect(result.failures.some((f) => f.kind === "checkpoint_mismatch")).toBe(true);
  });

  it("accepts a checkpoint that agrees", () => {
    const entries = chain(3);
    const result = verifyChain(entries, [
      { seq: 2, head_hash: entries[1]!.entry_hash },
    ]);
    expect(result.valid).toBe(true);
  });
});

describe("describeFailure", () => {
  it("explains every failure kind in terms a customer can act on", () => {
    const failures = [
      { kind: "hash_mismatch", seq: 1, expected: "a", actual: "b" },
      { kind: "broken_link", seq: 2, expected: "a", actual: "b" },
      { kind: "sequence_gap", expected: 3, actual: 5 },
      { kind: "bad_genesis", actual: "x" },
      { kind: "checkpoint_mismatch", seq: 4, expected: "a", actual: "b" },
      { kind: "checkpoint_missing", seq: 6 },
    ] as const;

    for (const failure of failures) {
      const message = describeFailure(failure);
      expect(message.length).toBeGreaterThan(20);
      // Says what happened, not just which invariant broke.
      expect(message).toMatch(/altered|inserted|missing|replaced|rewritten|export/i);
    }
  });
});
