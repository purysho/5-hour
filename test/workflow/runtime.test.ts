import { describe, expect, it, vi } from "vitest";
import {
  DuplicateStepKeyError,
  executeJob,
  MemoryStepRecorder,
  type RuntimeHooks,
} from "../../src/workflow/runtime.ts";
import { PermanentFailure, type JobRecord } from "../../src/workflow/types.ts";

/**
 * Step memoisation (ADR-0009).
 *
 * The claim under test: a completed side effect is never executed twice,
 * however many times the job is retried. Everything else in the durable
 * execution layer is scheduling; this is the part that delivers ADR-0004's
 * guarantee.
 *
 * These run against an in-memory recorder so the semantics are pinned
 * independently of Postgres. The database-backed equivalents live in
 * test/db/jobs.test.ts.
 */

function job(overrides: Partial<JobRecord> = {}): JobRecord {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    provider_id: "22222222-2222-4222-8222-222222222222",
    workflow: "test",
    input: {},
    status: "running",
    attempts: 1,
    max_attempts: 5,
    last_error: null,
    ...overrides,
  };
}

const hooks: RuntimeHooks = { heartbeat: async () => {}, log: () => {} };

describe("step memoisation", () => {
  it("runs a step once and returns its result", async () => {
    const recorder = new MemoryStepRecorder();
    const sideEffect = vi.fn(async () => ({ prNumber: 7 }));

    const result = await executeJob(
      job(),
      { name: "test", handler: async (ctx) => ctx.step("open-pr", sideEffect) },
      recorder,
      hooks,
    );

    expect(result.outcome).toBe("succeeded");
    expect(result.result).toEqual({ prNumber: 7 });
    expect(sideEffect).toHaveBeenCalledTimes(1);
  });

  it("does not re-execute a completed step on retry", async () => {
    // The core guarantee. A job that crashed after opening a pull request must
    // not open a second one when it resumes.
    const recorder = new MemoryStepRecorder();
    const openPr = vi.fn(async () => ({ prNumber: 7 }));

    const handler = async (ctx: {
      step: <T>(k: string, f: () => Promise<T>) => Promise<T>;
    }): Promise<unknown> => {
      const pr = await ctx.step("open-pr", openPr);
      await ctx.step("record-result", async () => ({ recorded: true }));
      return pr;
    };

    // Attempt 1 crashes after the first step.
    const crashing = {
      name: "test",
      handler: async (ctx: Parameters<typeof handler>[0]) => {
        await ctx.step("open-pr", openPr);
        throw new Error("worker died");
      },
    };
    const first = await executeJob(job({ attempts: 1 }), crashing, recorder, hooks);
    expect(first.outcome).toBe("failed");
    expect(openPr).toHaveBeenCalledTimes(1);

    // Attempt 2 resumes. The pull request is not opened again.
    const second = await executeJob(
      job({ attempts: 2 }),
      { name: "test", handler: handler as never },
      recorder,
      hooks,
    );
    expect(second.outcome).toBe("succeeded");
    expect(openPr).toHaveBeenCalledTimes(1);
    expect(second.result).toEqual({ prNumber: 7 });
  });

  it("replays the recorded result, not a fresh one", async () => {
    const recorder = new MemoryStepRecorder();
    let counter = 0;
    const definition = {
      name: "test",
      handler: async (ctx: { step: <T>(k: string, f: () => Promise<T>) => Promise<T> }) =>
        ctx.step("increment", async () => ++counter),
    };

    const first = await executeJob(job({ attempts: 1 }), definition, recorder, hooks);
    const second = await executeJob(job({ attempts: 2 }), definition, recorder, hooks);

    expect(first.result).toBe(1);
    expect(second.result).toBe(1);
    expect(counter).toBe(1);
  });

  it("returns the deserialised form on replay, matching production", async () => {
    // Results round-trip through JSON when persisted. A test that returned the
    // original object would hide the difference until it surfaced in
    // production as a Date that had become a string.
    const recorder = new MemoryStepRecorder();
    const definition = {
      name: "test",
      handler: async (ctx: { step: <T>(k: string, f: () => Promise<T>) => Promise<T> }) =>
        ctx.step("dated", async () => ({ at: new Date("2026-01-01T00:00:00Z") })),
    };

    const first = await executeJob(job({ attempts: 1 }), definition, recorder, hooks);
    const second = await executeJob(job({ attempts: 2 }), definition, recorder, hooks);

    expect((first.result as { at: unknown }).at).toBe("2026-01-01T00:00:00.000Z");
    expect(second.result).toEqual(first.result);
  });

  it("keeps steps independent across jobs", async () => {
    const recorder = new MemoryStepRecorder();
    const effect = vi.fn(async () => "done");
    const definition = {
      name: "test",
      handler: async (ctx: { step: <T>(k: string, f: () => Promise<T>) => Promise<T> }) =>
        ctx.step("same-key", effect),
    };

    await executeJob(job({ id: "aaaaaaaa-1111-4111-8111-111111111111" }), definition, recorder, hooks);
    await executeJob(job({ id: "bbbbbbbb-1111-4111-8111-111111111111" }), definition, recorder, hooks);

    expect(effect).toHaveBeenCalledTimes(2);
  });

  it("rejects a duplicate step key within one job", async () => {
    // Two steps sharing a key would memoise to each other's results — a
    // corruption that reads like a caching bug and is miserable to diagnose.
    const recorder = new MemoryStepRecorder();
    const result = await executeJob(
      job(),
      {
        name: "test",
        handler: async (ctx: {
          step: <T>(k: string, f: () => Promise<T>) => Promise<T>;
        }) => {
          await ctx.step("dup", async () => 1);
          await ctx.step("dup", async () => 2);
        },
      },
      recorder,
      hooks,
    );

    expect(result.outcome).toBe("permanent-failure");
    expect(result.error).toMatch(/used more than once/);
  });

  it("surfaces DuplicateStepKeyError as permanent, not retryable", async () => {
    // A programming error. Retrying cannot help and burns the retry budget.
    const recorder = new MemoryStepRecorder();
    const result = await executeJob(
      job(),
      {
        name: "test",
        handler: async (ctx: {
          step: <T>(k: string, f: () => Promise<T>) => Promise<T>;
        }) => {
          await ctx.step("x", async () => 1);
          await ctx.step("x", async () => 2);
        },
      },
      recorder,
      hooks,
    );
    expect(result.outcome).toBe("permanent-failure");
    expect(new DuplicateStepKeyError("x").name).toBe("DuplicateStepKeyError");
  });

  it("yields to a result recorded concurrently", async () => {
    // Two workers can briefly overlap when a lease expires while the original
    // is still alive. The recorded result wins, because it corresponds to the
    // side effect that was actually observed.
    const recorder = new MemoryStepRecorder();
    await recorder.record("job-x", "prov", "open-pr", { prNumber: 99 }, 1);

    const result = await executeJob(
      job({ id: "job-x" }),
      {
        name: "test",
        handler: async (ctx: {
          step: <T>(k: string, f: () => Promise<T>) => Promise<T>;
        }) => ctx.step("open-pr", async () => ({ prNumber: 1 })),
      },
      recorder,
      hooks,
    );

    expect(result.result).toEqual({ prNumber: 99 });
  });
});

describe("failure classification", () => {
  it("treats an ordinary error as retryable", async () => {
    const result = await executeJob(
      job(),
      {
        name: "test",
        handler: async () => {
          throw new Error("registry timed out");
        },
      },
      new MemoryStepRecorder(),
      hooks,
    );
    expect(result.outcome).toBe("failed");
    expect(result.error).toBe("registry timed out");
  });

  it("treats PermanentFailure as terminal", async () => {
    // A revoked installation or a policy rejection will never succeed on
    // retry. Retrying burns rate limit that legitimate work needs.
    const result = await executeJob(
      job(),
      {
        name: "test",
        handler: async () => {
          throw new PermanentFailure("installation was revoked");
        },
      },
      new MemoryStepRecorder(),
      hooks,
    );
    expect(result.outcome).toBe("permanent-failure");
    expect(result.error).toBe("installation was revoked");
  });

  it("handles a thrown non-Error", async () => {
    const result = await executeJob(
      job(),
      {
        name: "test",
        // eslint-disable-next-line @typescript-eslint/only-throw-error
        handler: async () => Promise.reject("just a string"),
      },
      new MemoryStepRecorder(),
      hooks,
    );
    expect(result.outcome).toBe("failed");
    expect(result.error).toBe("just a string");
  });
});

describe("context", () => {
  it("exposes job identity and attempt to the workflow", async () => {
    const seen: Record<string, unknown> = {};
    await executeJob(
      job({ attempts: 3 }),
      {
        name: "test",
        handler: async (ctx) => {
          seen["jobId"] = ctx.jobId;
          seen["providerId"] = ctx.providerId;
          seen["attempt"] = ctx.attempt;
        },
      },
      new MemoryStepRecorder(),
      hooks,
    );
    expect(seen["attempt"]).toBe(3);
    expect(seen["jobId"]).toBe("11111111-1111-4111-8111-111111111111");
  });

  it("passes heartbeat and log through to the hooks", async () => {
    const heartbeat = vi.fn(async () => {});
    const log = vi.fn();
    await executeJob(
      job(),
      {
        name: "test",
        handler: async (ctx) => {
          await ctx.heartbeat();
          ctx.log("halfway", { files: 3 });
        },
      },
      new MemoryStepRecorder(),
      { heartbeat, log },
    );
    expect(heartbeat).toHaveBeenCalledOnce();
    expect(log).toHaveBeenCalledWith(
      expect.objectContaining({ message: "halfway", fields: { files: 3 } }),
    );
  });
});
