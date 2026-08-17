/**
 * The approval trigger.
 *
 * The link between a human deciding and the system acting. `detect-changes`
 * records a change and stops; `plan-rollout` refuses to do anything until
 * `approved_at` is set. Nothing joined the two, so approval was a column
 * nobody read and the fan-out workflow could never be reached.
 *
 * ── Why a poll rather than an event ──────────────────────────────────────────
 *
 * Approval is a human writing a timestamp — today with SQL, later through an
 * interface. Requiring whoever does that to also enqueue a job means the gate
 * can be walked through incorrectly: approve and forget, or approve twice and
 * fan out twice. Polling makes the column the whole interface. Anything that
 * can set `approved_at` gets correct behaviour for free, and nothing that sets
 * it can produce a second rollout.
 *
 * ── Why it does not need to claim ────────────────────────────────────────────
 *
 * The sweep scheduler claims, because a sweep recurs and two schedulers must
 * not both decide the same package is due. A rollout does not recur: one
 * approved change earns exactly one rollout, ever, and the unbucketed dedupe
 * key `rollout:<change id>` is what enforces that — unique across every job
 * status, so a duplicate is refused whether the first rollout is queued,
 * running, finished, or dead.
 *
 * That is deliberately the *opposite* of the sweep scheduler's bucketed key.
 * There, an unbucketed key would make the first sweep of a package the last
 * one forever. Here, that is precisely the property we want.
 *
 * ── Which way it fails ───────────────────────────────────────────────────────
 *
 * Toward doing nothing. A tick that dies mid-batch leaves the remaining
 * approvals unenqueued and the next tick finds them again, because the query
 * is "approved and not yet rolled out" rather than a cursor. A rollout that is
 * late is a delay; a rollout that happens twice is two waves of pull requests
 * into other people's repositories.
 */

import type { Database } from "../db/client.ts";

export interface ApprovedChange {
  readonly providerId: string;
  readonly changeId: string;
}

/** Finds approved changes with no rollout job. Never claims or mutates. */
export interface ApprovalStore {
  awaitingRollout(limit: number): Promise<readonly ApprovedChange[]>;
}

/** The slice of `Queue` this needs. Narrow so a test double is type-checked. */
export interface ApprovalQueue {
  enqueue(
    providerId: string,
    workflow: string,
    input: Record<string, unknown>,
    options?: { dedupeKey?: string; priority?: number },
  ): Promise<{ jobId: string; created: boolean }>;
}

export interface ApprovalTriggerOptions {
  readonly store: ApprovalStore;
  readonly queue: ApprovalQueue;
  /** Approvals handled per tick. Bounds the burst after a batch approval. */
  readonly batchSize?: number;
  readonly log?: (event: string, detail: Record<string, unknown>) => void;
}

export interface ApprovalTickResult {
  readonly found: number;
  readonly enqueued: number;
  /** Already queued by a previous tick. Not an error (ADR-0004). */
  readonly duplicate: number;
  readonly failed: number;
}

const DEFAULT_BATCH_SIZE = 25;

export function rolloutDedupeKey(changeId: string): string {
  return `rollout:${changeId}`;
}

export class ApprovalTrigger {
  readonly #store: ApprovalStore;
  readonly #queue: ApprovalQueue;
  readonly #batchSize: number;
  readonly #log: (event: string, detail: Record<string, unknown>) => void;
  #timer: ReturnType<typeof setInterval> | null = null;
  #running = false;

  constructor(options: ApprovalTriggerOptions) {
    this.#store = options.store;
    this.#queue = options.queue;
    this.#batchSize = options.batchSize ?? DEFAULT_BATCH_SIZE;
    this.#log = options.log ?? (() => {});
  }

  async tick(): Promise<ApprovalTickResult> {
    const approved = await this.#store.awaitingRollout(this.#batchSize);
    let enqueued = 0;
    let duplicate = 0;
    let failed = 0;

    for (const change of approved) {
      try {
        const result = await this.#queue.enqueue(
          change.providerId,
          "plan-rollout",
          { changeId: change.changeId },
          { dedupeKey: rolloutDedupeKey(change.changeId) },
        );
        if (result.created) {
          enqueued += 1;
          this.#log("approval.rollout_enqueued", { changeId: change.changeId });
        } else {
          duplicate += 1;
        }
      } catch (error) {
        // One tenant's failure must not cost every other tenant their
        // rollout. The change stays unenqueued and the next tick finds it
        // again, because the query is a predicate rather than a cursor.
        failed += 1;
        this.#log("approval.enqueue_failed", {
          changeId: change.changeId,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    return { found: approved.length, enqueued, duplicate, failed };
  }

  start(intervalMs: number): this {
    if (this.#timer) return this;
    this.#timer = setInterval(() => {
      // Overlap guard. A tick that runs long must not have a second one
      // started underneath it — the dedupe key would refuse the duplicates,
      // but only after both ticks have done the work of discovering them.
      if (this.#running) return;
      this.#running = true;
      void this.tick()
        .catch((error: unknown) => {
          this.#log("approval.tick_failed", {
            error: error instanceof Error ? error.message : String(error),
          });
        })
        .finally(() => {
          this.#running = false;
        });
    }, intervalMs);
    this.#timer.unref?.();
    return this;
  }

  async stop(): Promise<void> {
    if (this.#timer) {
      clearInterval(this.#timer);
      this.#timer = null;
    }
    // Let an in-flight tick finish its enqueues rather than losing them.
    while (this.#running) await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

export class PostgresApprovalStore implements ApprovalStore {
  readonly #db: Database;

  constructor(db: Database) {
    this.#db = db;
  }

  async awaitingRollout(limit: number): Promise<readonly ApprovedChange[]> {
    return this.#db.withPlatformContext("trigger scanning approved changes", async (client) => {
      const { rows } = await client.query<{ provider_id: string; change_id: string }>(
        "SELECT * FROM approved_changes_awaiting_rollout($1)",
        [limit],
      );
      return rows.map((row) => ({ providerId: row.provider_id, changeId: row.change_id }));
    });
  }
}
