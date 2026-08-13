/**
 * The worker process.
 *
 * Dequeues jobs, runs them, and — the part that matters — shuts down without
 * abandoning work.
 *
 * ── Why shutdown gets this much attention ────────────────────────────────────
 *
 * Deploys, autoscaling, and preemption kill workers constantly. That is
 * ordinary, and ADR-0009's lease expiry means nothing is lost when it happens
 * abruptly: the job returns to the queue and another worker resumes it from
 * its last completed step.
 *
 * But "nothing is lost" is not the same as "nothing is wasted". A worker
 * killed mid-job leaves that job invisible until its lease expires — minutes
 * of latency for a job that was seconds from finishing, and a step's worth of
 * model inference thrown away. Multiply by every pod in a rolling deploy and a
 * routine release becomes a latency spike.
 *
 * So on SIGTERM the worker stops *accepting* work immediately and finishes
 * what it already holds. Only if that overruns the grace period does it fall
 * back to the lease-expiry path, which is correct but slow.
 *
 * The second signal is not a courtesy. A process that ignores repeated SIGTERM
 * gets SIGKILL from the orchestrator anyway, so an operator who needs it gone
 * now should be able to say so and have it obeyed.
 */

import type { Queue } from "../workflow/queue.ts";
import type { JobRecord } from "../workflow/types.ts";

/**
 * The slice of the queue this worker uses.
 *
 * Derived from `Queue` with `Pick`, so it cannot drift from the real
 * signatures — but narrow enough that a test double can satisfy it without
 * casting past private fields. Depending on the concrete class would force
 * every test to `as unknown as Queue`, which compiles against any shape at
 * all and is exactly how a worker calling methods that do not exist passed
 * its tests.
 */
export type WorkerQueue = Pick<Queue, "dequeue" | "runJob">;

export interface WorkerOptions {
  readonly concurrency: number;
  readonly pollIntervalMs: number;
  readonly shutdownGraceMs: number;
  readonly log: (message: string, fields?: Record<string, unknown>) => void;
}

export interface WorkerHandle {
  /** Resolves when the run loop has stopped and in-flight jobs are done. */
  readonly finished: Promise<void>;
  /** Begin graceful shutdown. Idempotent. */
  stop(reason: string): void;
  /** True while accepting new work. Drives the health check. */
  readonly accepting: boolean;
  readonly inFlight: number;
}

export function startWorker(queue: WorkerQueue, options: WorkerOptions): WorkerHandle {
  let accepting = true;
  let stopping = false;
  let inFlight = 0;
  let wake: (() => void) | null = null;

  const handle = {
    get accepting() {
      return accepting;
    },
    get inFlight() {
      return inFlight;
    },
    stop(reason: string) {
      if (stopping) return;
      stopping = true;
      accepting = false;
      options.log("worker draining", { reason });
      // Break out of the poll sleep immediately rather than waiting up to a
      // full interval to notice we are shutting down.
      wake?.();
    },
    finished: Promise.resolve(),
  };

  handle.finished = (async () => {
    while (accepting) {
      let claimed = 0;
      try {
        // The queue owns its own batch size (Queue options), so capacity is
        // enforced here by simply not dequeuing while saturated rather than by
        // asking for a smaller batch.
        if (inFlight < options.concurrency) {
          const jobs: JobRecord[] = await queue.dequeue();
          claimed = jobs.length;

          for (const job of jobs) {
            inFlight += 1;
            void queue
              .runJob(job, {
                // RuntimeHooks.log takes a structured entry; the worker's log
                // takes a message and fields. Adapt rather than widen either.
                log: (entry) =>
                  options.log(entry.message, {
                    jobId: entry.jobId,
                    workflow: entry.workflow,
                    attempt: entry.attempt,
                    ...entry.fields,
                  }),
              })
              .catch((error) => {
                // runJob records failure itself; reaching here means the queue
                // machinery failed, which must not kill the run loop.
                options.log("job execution error", {
                  jobId: job.id,
                  error: String(error),
                });
              })
              .finally(() => {
                inFlight -= 1;
              });
          }
        }
      } catch (error) {
        options.log("dequeue failed", { error: String(error) });
      }

      // Only idle when there was nothing to take. A busy queue should not be
      // polled at the idle interval.
      if (claimed === 0 && accepting) {
        await sleep(options.pollIntervalMs, (resolve) => {
          wake = resolve;
        });
        wake = null;
      }
    }

    await drain(options, () => inFlight);
    options.log("worker stopped", { inFlight });
  })();

  return handle;
}

async function drain(
  options: WorkerOptions,
  inFlight: () => number,
): Promise<void> {
  const deadline = Date.now() + options.shutdownGraceMs;

  while (inFlight() > 0 && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 50));
  }

  if (inFlight() > 0) {
    // Correct but slow: these jobs stay invisible until their leases expire,
    // then another worker resumes them from their last completed step. Logged
    // loudly because a grace period that is routinely too short is a
    // configuration problem worth seeing.
    options.log("shutdown grace expired with jobs in flight", {
      inFlight: inFlight(),
      graceMs: options.shutdownGraceMs,
    });
  }
}

function sleep(ms: number, register: (resolve: () => void) => void): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    register(() => {
      clearTimeout(timer);
      resolve();
    });
  });
}

/**
 * Wires process signals to a worker handle.
 *
 * Kept separate so the worker itself is testable without touching global
 * process state.
 */
export function installSignalHandlers(handle: WorkerHandle, log: WorkerOptions["log"]): void {
  let signalled = false;

  for (const signal of ["SIGTERM", "SIGINT"] as const) {
    process.on(signal, () => {
      if (signalled) {
        // An operator asking twice means they want it gone now. Obeying is
        // better than being SIGKILLed a moment later having pretended not to
        // hear.
        log("second signal — exiting immediately", { signal });
        process.exit(130);
      }
      signalled = true;
      handle.stop(signal);
    });
  }
}
