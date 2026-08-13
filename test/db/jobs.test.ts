import { beforeAll, afterAll, describe, expect, it, vi } from "vitest";
import {
  adminClient,
  prepareDatabase,
  seedProvider,
  workerDatabase,
} from "./setup.ts";
import type { Database } from "../../src/db/client.ts";
import { Queue } from "../../src/workflow/queue.ts";
import { PermanentFailure } from "../../src/workflow/types.ts";

/**
 * Durable execution against a real database (ADR-0009).
 *
 * The unit tests in test/workflow/runtime.test.ts pin the step semantics. This
 * file tests the parts that only exist in Postgres: leasing, reclaim after
 * worker death, SKIP LOCKED under concurrency, backoff, and the dead-letter
 * ceiling.
 */

let db: Database;

beforeAll(async () => {
  await prepareDatabase();
  db = workerDatabase();
});

afterAll(async () => {
  await db?.close();
});

function queue(workerId: string, leaseSeconds = 300): Queue {
  return new Queue(db, { workerId, leaseSeconds, batchSize: 5 });
}

async function jobRow(jobId: string): Promise<{
  status: string;
  attempts: number;
  last_error: string | null;
  leased_by: string | null;
}> {
  const client = await adminClient();
  try {
    const { rows } = await client.query(
      "SELECT status, attempts, last_error, leased_by FROM job WHERE id = $1",
      [jobId],
    );
    return rows[0] as never;
  } finally {
    await client.end();
  }
}

describe("enqueue", () => {
  it("enqueues and runs a job to success", async () => {
    const tenant = await seedProvider("jobs-basic");
    const effect = vi.fn(async () => ({ ok: true }));
    const q = queue("worker-1").register({
      name: "basic",
      handler: async (ctx) => ctx.step("do-it", effect),
    });

    const { jobId, created } = await q.enqueue(tenant.providerId, "basic", { n: 1 });
    expect(created).toBe(true);

    const jobs = await q.dequeue();
    const mine = jobs.find((j) => j.id === jobId);
    expect(mine).toBeDefined();

    const status = await q.runJob(mine!, { log: () => {} });
    expect(status).toBe("succeeded");
    expect(effect).toHaveBeenCalledOnce();
    expect((await jobRow(jobId)).status).toBe("succeeded");
  });

  it("deduplicates on dedupe_key", async () => {
    // Two webhook deliveries for one upstream change must not create two jobs.
    // Distinct from the outbound idempotency key, which stops two jobs
    // creating two pull requests — both are needed.
    const tenant = await seedProvider("jobs-dedupe");
    const q = queue("worker-1").register({ name: "dedupe", handler: async () => null });

    const first = await q.enqueue(tenant.providerId, "dedupe", {}, { dedupeKey: "change-1" });
    const second = await q.enqueue(tenant.providerId, "dedupe", {}, { dedupeKey: "change-1" });

    expect(first.created).toBe(true);
    expect(second.created).toBe(false);
    expect(second.jobId).toBe(first.jobId);
  });

  it("refuses to enqueue an unregistered workflow", async () => {
    const tenant = await seedProvider("jobs-unregistered");
    const q = queue("worker-1");
    await expect(q.enqueue(tenant.providerId, "nope")).rejects.toThrow(/not registered/);
  });

  it("refuses to register the same workflow twice", () => {
    const q = queue("worker-1").register({ name: "dup", handler: async () => null });
    expect(() => q.register({ name: "dup", handler: async () => null })).toThrow(
      /already registered/,
    );
  });
});

describe("leasing", () => {
  it("gives a job to exactly one of several competing workers", async () => {
    // SKIP LOCKED is what lets workers poll the same queue without
    // serialising on the head of it.
    const tenant = await seedProvider("jobs-compete");
    const workers = Array.from({ length: 5 }, (_, i) =>
      queue(`worker-${i}`).register({ name: "compete", handler: async () => null }),
    );
    await workers[0]!.enqueue(tenant.providerId, "compete");

    const claimed = await Promise.all(workers.map((w) => w.dequeue()));
    const all = claimed.flat().filter((j) => j.provider_id === tenant.providerId);
    expect(all).toHaveLength(1);
  });

  it("returns a dead worker's job to the queue when its lease expires", async () => {
    // The failure this exists for: a worker takes a job and vanishes. Nothing
    // sweeps; the job simply becomes runnable again.
    const tenant = await seedProvider("jobs-lease");
    const dead = queue("worker-dead", 0).register({
      name: "lease",
      handler: async () => null,
    });
    const alive = queue("worker-alive").register({
      name: "lease",
      handler: async () => null,
    });

    await dead.enqueue(tenant.providerId, "lease");
    const takenByDead = (await dead.dequeue()).filter(
      (j) => j.provider_id === tenant.providerId,
    );
    expect(takenByDead).toHaveLength(1);

    const reclaimed = (await alive.dequeue()).filter(
      (j) => j.provider_id === tenant.providerId,
    );
    expect(reclaimed).toHaveLength(1);
    expect(reclaimed[0]!.id).toBe(takenByDead[0]!.id);
    expect(reclaimed[0]!.attempts).toBe(2);
  });

  it("does not reclaim a job whose lease is live", async () => {
    const tenant = await seedProvider("jobs-live-lease");
    const holder = queue("worker-holder", 600).register({
      name: "live",
      handler: async () => null,
    });
    const other = queue("worker-other").register({
      name: "live",
      handler: async () => null,
    });

    await holder.enqueue(tenant.providerId, "live");
    expect(
      (await holder.dequeue()).filter((j) => j.provider_id === tenant.providerId),
    ).toHaveLength(1);
    expect(
      (await other.dequeue()).filter((j) => j.provider_id === tenant.providerId),
    ).toHaveLength(0);
  });

  it("refuses an outcome from a worker that no longer holds the lease", async () => {
    // A slow worker returning from the dead must not overwrite the result of
    // the worker that actually finished the job.
    const tenant = await seedProvider("jobs-stale-owner");
    const first = queue("worker-first", 0).register({
      name: "stale",
      handler: async () => null,
    });
    const second = queue("worker-second").register({
      name: "stale",
      handler: async () => "second wins",
    });

    const { jobId } = await first.enqueue(tenant.providerId, "stale");
    await first.dequeue();
    const reclaimed = (await second.dequeue()).find((j) => j.id === jobId)!;
    await second.runJob(reclaimed, { log: () => {} });

    // The first worker now reports success for a job it no longer owns.
    await first.runJob({ ...reclaimed, id: jobId } as never, { log: () => {} });

    const row = await jobRow(jobId);
    expect(row.status).toBe("succeeded");
    expect(row.leased_by).toBeNull();
  });
});

describe("retry and dead-lettering", () => {
  it("schedules a retry with backoff after a transient failure", async () => {
    const tenant = await seedProvider("jobs-retry");
    const q = queue("worker-1").register({
      name: "flaky",
      handler: async () => {
        throw new Error("registry timed out");
      },
    });

    const { jobId } = await q.enqueue(tenant.providerId, "flaky", {}, { maxAttempts: 3 });
    const claimed = (await q.dequeue()).find((j) => j.id === jobId)!;
    const status = await q.runJob(claimed, { log: () => {} });

    expect(status).toBe("failed");
    const row = await jobRow(jobId);
    expect(row.status).toBe("failed");
    expect(row.attempts).toBe(1);
    expect(row.last_error).toBe("registry timed out");

    // Backoff means it is not immediately runnable again.
    const immediate = (await q.dequeue()).filter((j) => j.id === jobId);
    expect(immediate).toHaveLength(0);
  });

  it("dead-letters once the attempt ceiling is reached", async () => {
    // A job retrying forever turns a transient outage into a rate-limit ban.
    const tenant = await seedProvider("jobs-dead");
    const q = queue("worker-1").register({
      name: "doomed",
      handler: async () => {
        throw new Error("always fails");
      },
    });

    const { jobId } = await q.enqueue(tenant.providerId, "doomed", {}, { maxAttempts: 1 });
    const claimed = (await q.dequeue()).find((j) => j.id === jobId)!;
    await q.runJob(claimed, { log: () => {} });

    const row = await jobRow(jobId);
    expect(row.status).toBe("dead");
  });

  it("dead-letters a PermanentFailure without consuming the retry budget", async () => {
    const tenant = await seedProvider("jobs-permanent");
    const q = queue("worker-1").register({
      name: "revoked",
      handler: async () => {
        throw new PermanentFailure("installation was revoked");
      },
    });

    const { jobId } = await q.enqueue(tenant.providerId, "revoked", {}, { maxAttempts: 10 });
    const claimed = (await q.dequeue()).find((j) => j.id === jobId)!;
    const status = await q.runJob(claimed, { log: () => {} });

    expect(status).toBe("dead");
    const row = await jobRow(jobId);
    expect(row.status).toBe("dead");
    expect(row.attempts).toBe(1);
    expect(row.last_error).toBe("installation was revoked");
  });
});

describe("step memoisation through Postgres", () => {
  it("does not repeat a completed side effect across attempts", async () => {
    // The end-to-end version of ADR-0004's guarantee: a job that crashes after
    // its side effect resumes without repeating it.
    const tenant = await seedProvider("jobs-memo");
    const sideEffect = vi.fn(async () => ({ prNumber: 101 }));
    let shouldCrash = true;

    const q = queue("worker-1").register({
      name: "memo",
      handler: async (ctx) => {
        const pr = await ctx.step("open-pr", sideEffect);
        if (shouldCrash) {
          shouldCrash = false;
          throw new Error("crashed after opening the PR");
        }
        return pr;
      },
    });

    const { jobId } = await q.enqueue(tenant.providerId, "memo", {}, { maxAttempts: 5 });

    const first = (await q.dequeue()).find((j) => j.id === jobId)!;
    expect(await q.runJob(first, { log: () => {} })).toBe("failed");
    expect(sideEffect).toHaveBeenCalledTimes(1);

    // Clear the backoff so the retry is claimable now.
    const client = await adminClient();
    try {
      await client.query("UPDATE job SET run_at = now() WHERE id = $1", [jobId]);
    } finally {
      await client.end();
    }

    const second = (await q.dequeue()).find((j) => j.id === jobId)!;
    expect(await q.runJob(second, { log: () => {} })).toBe("succeeded");

    // The pull request was opened once, across two attempts.
    expect(sideEffect).toHaveBeenCalledTimes(1);

    const row = await jobRow(jobId);
    expect(row.status).toBe("succeeded");
  });

  it("scopes steps to the tenant that owns the job", async () => {
    const a = await seedProvider("jobs-step-tenant-a");
    const q = queue("worker-1").register({
      name: "scoped",
      handler: async (ctx) => ctx.step("s", async () => "value"),
    });
    const { jobId } = await q.enqueue(a.providerId, "scoped");
    const claimed = (await q.dequeue()).find((j) => j.id === jobId)!;
    await q.runJob(claimed, { log: () => {} });

    const steps = await db.withTenant(a.providerId, async (client) => {
      const { rows } = await client.query("SELECT step_key FROM job_step WHERE job_id = $1", [
        jobId,
      ]);
      return rows;
    });
    expect(steps).toHaveLength(1);

    const b = await seedProvider("jobs-step-tenant-b");
    const leaked = await db.withTenant(b.providerId, async (client) => {
      const { rows } = await client.query("SELECT step_key FROM job_step WHERE job_id = $1", [
        jobId,
      ]);
      return rows;
    });
    expect(leaked).toHaveLength(0);
  });
});
