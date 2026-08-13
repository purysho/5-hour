import { describe, expect, it, vi } from "vitest";
import {
  startWorker,
  type WorkerOptions,
  type WorkerQueue,
} from "../../src/main/worker.ts";
import type { JobRecord, JobStatus } from "../../src/workflow/types.ts";

/**
 * Worker lifecycle.
 *
 * Deploys and preemption kill workers constantly, and ADR-0009's lease expiry
 * means nothing is lost when that happens. But "nothing lost" is not "nothing
 * wasted": a worker killed mid-job leaves it invisible until the lease
 * expires — minutes of latency for a job that was seconds from done, times
 * every pod in a rolling deploy.
 *
 * So these tests are about draining rather than about throughput.
 */

function options(overrides: Partial<WorkerOptions> = {}): WorkerOptions {
  return {
    concurrency: 4,
    pollIntervalMs: 10,
    shutdownGraceMs: 1000,
    log: () => {},
    ...overrides,
  };
}

/**
 * Minimal queue double.
 *
 * Typed as `Pick<Queue, "dequeue" | "runJob">` rather than cast wholesale to
 * `Queue`. An `as unknown as Queue` cast compiles against any shape at all,
 * which is how the first version of this file passed while the worker called
 * `dequeue(capacity)` and passed a logger the real `runJob` does not accept —
 * green tests over a worker that could not have run. Narrowing the type is
 * what makes the double track the real interface.
 */
type QueueDouble = WorkerQueue;

function fakeQueue(
  behaviour: {
    batches?: JobRecord[][];
    runJob?: (job: JobRecord) => Promise<JobStatus>;
    onDequeue?: () => void;
  } = {},
): QueueDouble & { dequeued: number; ran: string[] } {
  const batches = [...(behaviour.batches ?? [])];
  const ran: string[] = [];
  let dequeued = 0;

  return {
    get dequeued() {
      return dequeued;
    },
    ran,
    async dequeue(): Promise<JobRecord[]> {
      dequeued += 1;
      behaviour.onDequeue?.();
      return batches.shift() ?? [];
    },
    async runJob(job: JobRecord): Promise<JobStatus> {
      const result = behaviour.runJob ? await behaviour.runJob(job) : "succeeded";
      ran.push(job.id);
      return result;
    },
  };
}

/** Only the fields the worker touches; the rest are filler. */
function job(id: string): JobRecord {
  return {
    id,
    provider_id: "11111111-1111-4111-8111-111111111111",
    workflow: "migrate-repository",
    input: {},
    status: "running",
    attempts: 1,
    max_attempts: 3,
    last_error: null,
  };
}

const settle = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 40));

describe("running work", () => {
  it("runs dequeued jobs", async () => {
    const queue = fakeQueue({ batches: [[job("a"), job("b")]] });
    const worker = startWorker(queue, options());

    await settle();
    worker.stop("test");
    await worker.finished;

    expect(queue.ran.sort()).toEqual(["a", "b"]);
  });

  it("keeps running after a job throws", async () => {
    // runJob records its own failures; reaching the catch means the queue
    // machinery broke, and that must not take the run loop with it.
    const queue = fakeQueue({
      batches: [[job("boom")], [job("fine")]],
      runJob: async (job) => {
        if (job.id === "boom") throw new Error("queue exploded");
        return "succeeded";
      },
    });
    const worker = startWorker(queue, options());

    await settle();
    worker.stop("test");
    await worker.finished;

    expect(queue.ran).toContain("fine");
  });

  it("survives a failing dequeue", async () => {
    let calls = 0;
    const queue = {
      async dequeue() {
        calls += 1;
        if (calls === 1) throw new Error("database unavailable");
        return [];
      },
      async runJob() {
        return "succeeded";
      },
    } satisfies QueueDouble;

    const worker = startWorker(queue, options());
    await settle();
    worker.stop("test");
    await worker.finished;

    expect(calls).toBeGreaterThan(1);
  });

  it("does not exceed its concurrency", async () => {
    let concurrent = 0;
    let peak = 0;
    const queue = fakeQueue({
      batches: [[job("1"), job("2")]],
      runJob: async () => {
        concurrent += 1;
        peak = Math.max(peak, concurrent);
        await new Promise((r) => setTimeout(r, 20));
        concurrent -= 1;
        return "succeeded";
      },
    });

    const worker = startWorker(queue, options({ concurrency: 2 }));
    await settle();
    worker.stop("test");
    await worker.finished;

    expect(peak).toBeLessThanOrEqual(2);
  });
});

describe("draining", () => {
  it("stops accepting immediately on stop", async () => {
    const queue = fakeQueue();
    const worker = startWorker(queue, options());

    expect(worker.accepting).toBe(true);
    worker.stop("SIGTERM");
    expect(worker.accepting).toBe(false);

    await worker.finished;
  });

  it("finishes in-flight work rather than abandoning it", async () => {
    // The whole point. Abandoning a job that was seconds from done costs a
    // lease-expiry wait and a step's worth of model inference.
    let finished = false;
    const queue = fakeQueue({
      batches: [[job("slow")]],
      runJob: async () => {
        await new Promise((r) => setTimeout(r, 120));
        finished = true;
        return "succeeded";
      },
    });

    const worker = startWorker(queue, options());
    await new Promise((r) => setTimeout(r, 20));
    worker.stop("SIGTERM");
    await worker.finished;

    expect(finished, "in-flight job must complete before shutdown returns").toBe(true);
  });

  it("wakes out of the poll interval instead of waiting it out", async () => {
    // A 30-second poll interval would otherwise mean a 30-second shutdown.
    const queue = fakeQueue();
    const worker = startWorker(queue, options({ pollIntervalMs: 30_000 }));

    await new Promise((r) => setTimeout(r, 20));
    const started = Date.now();
    worker.stop("SIGTERM");
    await worker.finished;

    expect(Date.now() - started).toBeLessThan(1000);
  });

  it("gives up after the grace period and logs loudly", async () => {
    // Correct but slow: the lease-expiry path takes over. A grace period that
    // is routinely too short is a configuration problem worth seeing.
    const log = vi.fn();
    const queue = fakeQueue({
      batches: [[job("stuck")]],
      runJob: () => new Promise(() => {}),
    });

    const worker = startWorker(queue, options({ shutdownGraceMs: 1000, log }));
    await new Promise((r) => setTimeout(r, 20));
    worker.stop("SIGTERM");
    await worker.finished;

    expect(log).toHaveBeenCalledWith(
      "shutdown grace expired with jobs in flight",
      expect.objectContaining({ inFlight: 1 }),
    );
  });

  it("is idempotent — a second stop is not an error", async () => {
    const queue = fakeQueue();
    const worker = startWorker(queue, options());
    worker.stop("SIGTERM");
    worker.stop("SIGTERM");
    await worker.finished;
    expect(worker.accepting).toBe(false);
  });

  it("reports in-flight count for the health check", async () => {
    const queue = fakeQueue({
      batches: [[job("a")]],
      runJob: async () => {
        await new Promise((r) => setTimeout(r, 60));
        return "succeeded";
      },
    });
    const worker = startWorker(queue, options());

    await new Promise((r) => setTimeout(r, 20));
    expect(worker.inFlight).toBe(1);

    worker.stop("test");
    await worker.finished;
    expect(worker.inFlight).toBe(0);
  });
});

describe("polling", () => {
  it("does not idle while the queue is busy", async () => {
    // A busy queue must not be polled at the idle interval.
    const queue = fakeQueue({
      batches: [[job("1")], [job("2")], [job("3")]],
    });
    const worker = startWorker(queue, options({ pollIntervalMs: 5000 }));

    await new Promise((r) => setTimeout(r, 30));
    worker.stop("test");
    await worker.finished;

    // Three non-empty batches consumed back to back despite a 5s idle
    // interval, which is only possible if it skipped sleeping between them.
    expect(queue.ran.sort()).toEqual(["1", "2", "3"]);
  });
});
