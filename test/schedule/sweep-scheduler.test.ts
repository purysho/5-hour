import { describe, expect, it } from "vitest";
import {
  SweepScheduler,
  type DueSweep,
  type SweepQueue,
  type SweepStore,
} from "../../src/schedule/sweep-scheduler.ts";

/**
 * The detection scheduler.
 *
 * Detection that runs when someone remembers is not detection. These tests are
 * about the two ways an automatic sweep goes wrong: not running, and running
 * twice.
 */

interface Enqueued {
  providerId: string;
  workflow: string;
  input: Record<string, unknown>;
  dedupeKey: string | undefined;
}

function recordingQueue(): SweepQueue & { calls: Enqueued[] } {
  const calls: Enqueued[] = [];
  const seen = new Set<string>();
  return {
    calls,
    async enqueue(providerId, workflow, input, options) {
      calls.push({ providerId, workflow, input, dedupeKey: options?.dedupeKey });
      // Mirrors `enqueue_job`: the dedupe key is unique across all statuses,
      // so a repeat returns the existing job rather than creating one.
      const key = `${providerId}:${workflow}:${options?.dedupeKey ?? Math.random()}`;
      const created = !seen.has(key);
      seen.add(key);
      return { jobId: key, created };
    },
  };
}

function storeReturning(...batches: readonly (readonly DueSweep[])[]): SweepStore & {
  claims: { limit: number; now: Date }[];
} {
  const claims: { limit: number; now: Date }[] = [];
  let index = 0;
  return {
    claims,
    async claimDue(limit, now) {
      claims.push({ limit, now });
      return batches[index++] ?? [];
    },
  };
}

const PACKAGE: DueSweep = {
  providerId: "11111111-1111-1111-1111-111111111111",
  ecosystem: "npm",
  packageName: "acme-sdk",
  baselineVersion: "1.4.2",
};

describe("tick", () => {
  it("enqueues a detect-changes job for each due package", async () => {
    const queue = recordingQueue();
    const scheduler = new SweepScheduler({ store: storeReturning([PACKAGE]), queue });

    const result = await scheduler.tick(new Date("2026-08-14T10:00:00Z"));

    expect(result).toMatchObject({ claimed: 1, enqueued: 1, duplicate: 0, failed: 0 });
    expect(queue.calls[0]).toMatchObject({
      providerId: PACKAGE.providerId,
      workflow: "detect-changes",
      input: { packageName: "acme-sdk", currentVersion: "1.4.2", ecosystem: "npm" },
    });
  });

  it("does nothing when nothing is due", async () => {
    const queue = recordingQueue();
    const result = await new SweepScheduler({ store: storeReturning([]), queue }).tick();
    expect(result.claimed).toBe(0);
    expect(queue.calls).toHaveLength(0);
  });

  it("buckets the dedupe key by time", async () => {
    // `job_dedupe_key_idx` is unique across every status, so an unbucketed key
    // would make the first sweep of a package the last one, permanently.
    const queue = recordingQueue();
    const store = storeReturning([PACKAGE], [PACKAGE]);
    const scheduler = new SweepScheduler({ store, queue, dedupeBucketMs: 3_600_000 });

    await scheduler.tick(new Date("2026-08-14T10:00:00Z"));
    await scheduler.tick(new Date("2026-08-14T11:00:00Z"));

    expect(queue.calls[0]?.dedupeKey).not.toBe(queue.calls[1]?.dedupeKey);
    expect(queue.calls.every((c) => c.dedupeKey?.startsWith("sweep:npm:acme-sdk:1.4.2:"))).toBe(
      true,
    );
  });

  it("does not suppress a sweep at the shortest interval the database allows", async () => {
    // The default bucket was an hour, which capped every package at one sweep
    // per hour however it was configured. A package on the minimum 60s
    // interval was claimed every minute — `last_swept_at` moved, so it looked
    // swept — while 59 of every 60 enqueues hit an existing key and did
    // nothing. Defaults, deliberately: this pins the shipped behaviour, not a
    // value a test chose.
    const queue = recordingQueue();
    const store = storeReturning([PACKAGE], [PACKAGE]);
    const scheduler = new SweepScheduler({ store, queue });

    await scheduler.tick(new Date("2026-08-14T10:00:00Z"));
    const second = await scheduler.tick(new Date("2026-08-14T10:01:00Z"));

    expect(second).toMatchObject({ claimed: 1, enqueued: 1, duplicate: 0 });
    expect(queue.calls[0]?.dedupeKey).not.toBe(queue.calls[1]?.dedupeKey);
  });

  it("reports a duplicate rather than counting it as work", async () => {
    // Two ticks inside one bucket. The database claim should already have
    // prevented this; the dedupe key is the second line, and the count is how
    // an operator finds out the first one is misbehaving.
    const queue = recordingQueue();
    const store = storeReturning([PACKAGE], [PACKAGE]);
    const scheduler = new SweepScheduler({ store, queue, dedupeBucketMs: 3_600_000 });

    await scheduler.tick(new Date("2026-08-14T10:00:00Z"));
    const second = await scheduler.tick(new Date("2026-08-14T10:30:00Z"));

    expect(second).toMatchObject({ claimed: 1, enqueued: 0, duplicate: 1 });
  });

  it("keeps going when one package fails to enqueue", async () => {
    // One provider's bad row must not stop every other provider's sweep.
    const other = { ...PACKAGE, providerId: "22222222-2222-2222-2222-222222222222" };
    const logged: string[] = [];
    const queue: SweepQueue = {
      async enqueue(providerId) {
        if (providerId === PACKAGE.providerId) throw new Error("provider is gone");
        return { jobId: "j", created: true };
      },
    };

    const result = await new SweepScheduler({
      store: storeReturning([PACKAGE, other]),
      queue,
      log: (event) => logged.push(event),
    }).tick();

    expect(result).toMatchObject({ claimed: 2, enqueued: 1, failed: 1 });
    expect(logged).toContain("scheduler.enqueue_failed");
  });

  it("bounds the burst after an outage", async () => {
    const store = storeReturning([]);
    await new SweepScheduler({ store, queue: recordingQueue(), batchSize: 7 }).tick();
    expect(store.claims[0]?.limit).toBe(7);
  });

  it("claims against the caller's clock, not the database's", async () => {
    // So a test can assert on due-ness without waiting an hour, and so an
    // operator can reason about a backfill.
    const store = storeReturning([]);
    const now = new Date("2026-08-14T10:00:00Z");
    await new SweepScheduler({ store, queue: recordingQueue() }).tick(now);
    expect(store.claims[0]?.now).toEqual(now);
  });
});

describe("start and stop", () => {
  it("ticks repeatedly until stopped", async () => {
    const store = storeReturning([PACKAGE], [PACKAGE], [PACKAGE], []);
    const queue = recordingQueue();
    const scheduler = new SweepScheduler({ store, queue });

    const handle = scheduler.start(1);
    await new Promise((resolve) => setTimeout(resolve, 30));
    await handle.stop();

    expect(store.claims.length).toBeGreaterThan(1);
  });

  it("stops without waiting out the interval", async () => {
    // A scheduler on an hourly tick that takes an hour to drain gets killed
    // instead of stopped, and its in-flight enqueues are lost.
    const scheduler = new SweepScheduler({
      store: storeReturning([]),
      queue: recordingQueue(),
    });

    const handle = scheduler.start(3_600_000);
    const started = Date.now();
    await handle.stop();
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  it("survives a failing tick rather than silently stopping", async () => {
    // A scheduler that quietly stopped scheduling is the failure nobody
    // notices until a customer asks why nothing has been detected all week.
    let calls = 0;
    const logged: string[] = [];
    const store: SweepStore = {
      async claimDue() {
        calls++;
        if (calls === 1) throw new Error("database is down");
        return [];
      },
    };

    const handle = new SweepScheduler({
      store,
      queue: recordingQueue(),
      log: (event) => logged.push(event),
    }).start(1);
    await new Promise((resolve) => setTimeout(resolve, 30));
    await handle.stop();

    expect(calls).toBeGreaterThan(1);
    expect(logged).toContain("scheduler.tick_failed");
  });
});
