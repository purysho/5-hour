import { createHash } from "node:crypto";

/**
 * Independent verification of the audit chain (ADR-0007 §4).
 *
 * This deliberately takes exported rows and nothing else. It opens no database
 * connection and calls no Driftless service, so the same function can be handed
 * to a customer and run against an export we have no involvement in. A verifier
 * that has to ask us anything at verification time verifies nothing.
 */

export const GENESIS_HASH = "0".repeat(64);

export interface ExportedEntry {
  readonly seq: number | string;
  readonly prev_hash: string;
  readonly entry_hash: string;
  /**
   * The exact bytes that were hashed, produced by `audit_canonical_payload` in
   * migration 003. Exported rather than reconstructed so that verification
   * cannot drift from what was signed.
   */
  readonly canonical_payload: string;
}

export interface Checkpoint {
  readonly seq: number;
  readonly head_hash: string;
}

export type VerificationFailure =
  | { kind: "hash_mismatch"; seq: number; expected: string; actual: string }
  | { kind: "broken_link"; seq: number; expected: string; actual: string }
  | { kind: "sequence_gap"; expected: number; actual: number }
  | { kind: "bad_genesis"; actual: string }
  | { kind: "checkpoint_mismatch"; seq: number; expected: string; actual: string }
  | { kind: "checkpoint_missing"; seq: number };

export interface VerificationResult {
  readonly valid: boolean;
  readonly entriesChecked: number;
  readonly headHash: string | null;
  readonly failures: readonly VerificationFailure[];
}

export function hashPayload(canonicalPayload: string): string {
  return createHash("sha256").update(canonicalPayload, "utf8").digest("hex");
}

/**
 * Walks a chain and, optionally, checks it against checkpoints the customer
 * already holds.
 *
 * The checkpoint comparison is the part that makes the chain meaningful.
 * Chaining alone only proves internal consistency — an attacker with write
 * access could recompute an entire consistent chain. Anchoring to a checkpoint
 * captured earlier, elsewhere, is what makes rewriting history detectable.
 */
export function verifyChain(
  entries: readonly ExportedEntry[],
  checkpoints: readonly Checkpoint[] = [],
): VerificationResult {
  const failures: VerificationFailure[] = [];

  if (entries.length === 0) {
    return { valid: checkpoints.length === 0, entriesChecked: 0, headHash: null, failures };
  }

  let expectedPrev = GENESIS_HASH;
  let expectedSeq = Number(entries[0]?.seq ?? 1);

  if (expectedSeq === 1 && entries[0]?.prev_hash !== GENESIS_HASH) {
    failures.push({ kind: "bad_genesis", actual: entries[0]?.prev_hash ?? "" });
  }
  // A partial export legitimately starts mid-chain, so the first link is only
  // anchored to genesis when the export starts at sequence 1.
  if (expectedSeq !== 1) {
    expectedPrev = entries[0]?.prev_hash ?? GENESIS_HASH;
  }

  let headHash: string | null = null;

  for (const entry of entries) {
    const seq = Number(entry.seq);

    if (seq !== expectedSeq) {
      failures.push({ kind: "sequence_gap", expected: expectedSeq, actual: seq });
      expectedSeq = seq;
    }

    if (entry.prev_hash !== expectedPrev) {
      failures.push({
        kind: "broken_link",
        seq,
        expected: expectedPrev,
        actual: entry.prev_hash,
      });
    }

    const computed = hashPayload(entry.canonical_payload);
    if (computed !== entry.entry_hash) {
      failures.push({
        kind: "hash_mismatch",
        seq,
        expected: computed,
        actual: entry.entry_hash,
      });
    }

    expectedPrev = entry.entry_hash;
    expectedSeq = seq + 1;
    headHash = entry.entry_hash;
  }

  const bySeq = new Map(entries.map((e) => [Number(e.seq), e.entry_hash]));
  for (const checkpoint of checkpoints) {
    const actual = bySeq.get(checkpoint.seq);
    if (actual === undefined) {
      failures.push({ kind: "checkpoint_missing", seq: checkpoint.seq });
      continue;
    }
    if (actual !== checkpoint.head_hash) {
      failures.push({
        kind: "checkpoint_mismatch",
        seq: checkpoint.seq,
        expected: checkpoint.head_hash,
        actual,
      });
    }
  }

  return {
    valid: failures.length === 0,
    entriesChecked: entries.length,
    headHash,
    failures,
  };
}

export function describeFailure(failure: VerificationFailure): string {
  switch (failure.kind) {
    case "hash_mismatch":
      return `Entry ${failure.seq}: content does not match its recorded hash. The entry was altered after it was written.`;
    case "broken_link":
      return `Entry ${failure.seq}: previous-hash does not match the preceding entry. An entry was inserted, removed, or reordered.`;
    case "sequence_gap":
      return `Expected sequence ${failure.expected}, found ${failure.actual}. Entries are missing from the export.`;
    case "bad_genesis":
      return `Chain does not start from the genesis hash (found ${failure.actual}). The beginning of the chain is missing or was replaced.`;
    case "checkpoint_mismatch":
      return `Entry ${failure.seq} does not match the published checkpoint. History was rewritten after that checkpoint was published.`;
    case "checkpoint_missing":
      return `Checkpoint at sequence ${failure.seq} has no corresponding entry in this export.`;
  }
}
