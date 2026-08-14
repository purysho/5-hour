/**
 * The detection scheduler.
 *
 * Turns "packages we watch" into `detect-changes` jobs on a clock. Detection
 * that runs when someone remembers is not detection — a breaking change
 * noticed three weeks late has already stranded everyone it was going to
 * strand.
 *
 * ── Where the decision lives ─────────────────────────────────────────────────
 *
 * In the database, not in this process. `claim_due_sweeps` selects the due
 * rows `FOR UPDATE SKIP LOCKED` and advances their clock in the same
 * statement, so two schedulers — or one scheduler either side of a deploy —
 * cannot both conclude that the same package is due. An in-process timer with
 * an in-process "last run" would produce a duplicate sweep on every restart.
 *
 * The job dedupe key is a second defence rather than the only one. It is
 * bucketed by time, because `job_dedupe_key_idx` is unique across all statuses
 * — an unbucketed key would make the first sweep of a package the last one
 * forever.
 *
 * ── Which way this fails ─────────────────────────────────────────────────────
 *
 * Claim-then-enqueue means a crash between the two silently skips a sweep,
 * recovered on the next interval. Enqueue-then-claim would instead risk
 * duplicate sweeps, which cost registry calls and can race on the
 * `upstream_change` upsert.
 *
 * A late sweep is a delay. A duplicated one is a correctness problem. So the
 * order here is deliberate, and the cost of it is bounded by the interval.
 */

import type { Database } from "../db/client.ts";

export interface DueSweep {
  readonly providerId: string;
  readonly ecosystem: "npm";
  readonly packageName: string;
  readonly baselineVersion: string;
}

/** Claims packages due for a sweep. Advances their clock as it returns them. */
export interface SweepStore {
  claimDue(limit: number, now: Date): Promise<readonly DueSweep[]>;
}

/** The slice of `Queue` this needs. Narrow so a test double is type-checked. */
export interface SweepQueue {
  enqueue(
    providerId: string,
    workflow: string,
    input: Record<string, unknown>,
    options?: { dedupeKey?: string; priority?: number },
  ): Promise<{ jobId: string; created: boolean }>;
}

export interface SchedulerOptions {
  readonly store: SweepStore;
  readonly queue: SweepQueue;
  /** Packages claimed per tick. Bounds the burst a long outage produces. */
  readonly batchSize?: number;
  /**
   * Dedupe bucket width. Two ticks inside one bucket enqueue one job for a
   * given package, whatever else has gone wrong.
   */
  readonly dedupeBucketMs?: number;
  readonly log?: (event: string, detail: Record<string, unknown>) => void;
}

export interface TickResult {
  readonly claimed: number;
  readonly enqueued: number;
  /** Claimed but already queued for this bucket. */
  readonly duplicate: number;
  readonly failed: number;
}

const DEFAULT_BATCH_SIZE = 50;
const DEFAULT_BUCKET_MS = 3_600_000;

export class SweepScheduler {
  readonly #store: SweepStore;
  readonly #queue: SweepQueue;
  readonly #batchSize: number;
  readonly #bucketMs: number;
  readonly #log: (event: string, detail: Record<string, unknown>) => void;

  constructor(options: SchedulerOptions) {
    this.#store = options.store;
    this.#queue = options.queue;
    this.#batchSize = options.batchSize ?? DEFAULT_BATCH_SIZE;
    this.#bucketMs = options.dedupeBucketMs ?? DEFAULT_BUCKET_MS;
    this.#log = options.log ?? (() => {});
  }

  async tick(now: Date = new Date()): Promise<TickResult> {
    const due = await this.#store.claimDue(this.#batchSize, now);
    if (due.length === 0) return { claimed: 0, enqueued: 0, duplicate: 0, failed: 0 };

    const bucket = Math.floor(now.getTime() / this.#bucketMs);
    let enqueued = 0;
    let duplicate = 0;
    let failed = 0;

    for (const sweep of due) {
      try {
        const result = await this.#queue.enqueue(
          sweep.providerId,
          "detect-changes",
          {
            packageName: sweep.packageName,
            currentVersion: sweep.baselineVersion,
            ecosystem: sweep.ecosystem,
          },
          {
            dedupeKey: `sweep:${sweep.ecosystem}:${sweep.packageName}:${sweep.baselineVersion}:${bucket}`,
          },
        );
        if (result.created) enqueued++;
        else duplicate++;
      } catch (error) {
        // One provider's bad row must not stop every other provider's sweep.
        // The clock has already advanced for this package, so the failure
        // costs one interval rather than being retried forever.
        failed++;
        this.#log("scheduler.enqueue_failed", {
          providerId: sweep.providerId,
          ecosystem: sweep.ecosystem,
          packageName: sweep.packageName,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    this.#log("scheduler.tick", { claimed: due.length, enqueued, duplicate, failed });
    return { claimed: due.length, enqueued, duplicate, failed };
  }

  /**
   * Runs `tick` on an interval until stopped.
   *
   * Ticks do not overlap: a slow tick delays the next one rather than running
   * beside it. Overlapping ticks would be safe — the claim is exclusive — but
   * they would pile up under a slow database, which is exactly when adding
   * concurrency is least helpful.
   */
  start(intervalMs: number): { stop: () => Promise<void> } {
    let stopped = false;
    // Resolved by `stop` so a shutdown does not have to wait out the interval.
    // Without this, stopping a scheduler on an hourly tick takes up to an hour,
    // which in practice means the process gets killed instead of drained.
    let wake: () => void = () => {};

    const loop = async (): Promise<void> => {
      while (!stopped) {
        try {
          await this.tick();
        } catch (error) {
          // A failing tick must not end the loop. The next one may well
          // succeed, and a scheduler that quietly stopped scheduling is the
          // failure nobody notices.
          this.#log("scheduler.tick_failed", {
            error: error instanceof Error ? error.message : String(error),
          });
        }
        if (stopped) break;
        await new Promise<void>((resolve) => {
          wake = resolve;
          const timer = setTimeout(resolve, intervalMs);
          timer.unref?.();
        });
      }
    };

    const finished = loop();

    return {
      stop: async () => {
        stopped = true;
        wake();
        await finished.catch(() => {});
      },
    };
  }
}

/**
 * The production store.
 *
 * Platform-scoped by necessity: the scheduler must see every provider's
 * packages, and there is no tenant context to run in until a row tells it
 * which tenant to enqueue into. `claim_due_sweeps` is shaped to disclose only
 * that — see migration 007.
 */
export class PostgresSweepStore implements SweepStore {
  readonly #db: Database;

  constructor(db: Database) {
    this.#db = db;
  }

  async claimDue(limit: number, now: Date): Promise<readonly DueSweep[]> {
    return this.#db.withPlatformContext("scheduler claiming due sweeps", async (client) => {
      const { rows } = await client.query<{
        provider_id: string;
        ecosystem: string;
        package_name: string;
        baseline_version: string;
      }>("SELECT * FROM claim_due_sweeps($1, $2)", [limit, now]);

      return rows.map((row) => ({
        providerId: row.provider_id,
        ecosystem: row.ecosystem as "npm",
        packageName: row.package_name,
        baselineVersion: row.baseline_version,
      }));
    });
  }
}
