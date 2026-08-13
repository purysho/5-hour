import type { TenantClient } from "../db/client.ts";
import {
  PermanentFailure,
  type JobRecord,
  type WorkflowContext,
  type WorkflowDefinition,
} from "./types.ts";

/**
 * Durable workflow execution over Postgres (ADR-0009).
 *
 * The whole design rests on one idea: a completed step is never re-executed.
 * Retry therefore resumes rather than restarts, and a crash between "the pull
 * request was opened" and "we recorded that it was opened" cannot produce a
 * second pull request.
 */

export interface StepRecorder {
  /** Returns the recorded result if the step already completed, else null. */
  lookup(jobId: string, stepKey: string): Promise<{ result: unknown } | null>;
  record(
    jobId: string,
    providerId: string,
    stepKey: string,
    result: unknown,
    attempt: number,
  ): Promise<{ recorded: boolean; result: unknown }>;
}

export class PostgresStepRecorder implements StepRecorder {
  constructor(private readonly client: TenantClient) {}

  async lookup(jobId: string, stepKey: string): Promise<{ result: unknown } | null> {
    const { rows } = await this.client.query<{ result: unknown }>(
      "SELECT result FROM job_step WHERE job_id = $1 AND step_key = $2",
      [jobId, stepKey],
    );
    return rows.length > 0 ? { result: rows[0]!.result } : null;
  }

  async record(
    jobId: string,
    providerId: string,
    stepKey: string,
    result: unknown,
    attempt: number,
  ): Promise<{ recorded: boolean; result: unknown }> {
    const { rows } = await this.client.query<{ recorded: boolean; result: unknown }>(
      "SELECT * FROM record_job_step($1, $2, $3, $4, $5)",
      [jobId, providerId, stepKey, JSON.stringify(result ?? null), attempt],
    );
    return rows[0] ?? { recorded: false, result: null };
  }
}

export interface RuntimeHooks {
  heartbeat(jobId: string): Promise<void>;
  log(entry: {
    jobId: string;
    providerId: string;
    workflow: string;
    attempt: number;
    message: string;
    fields?: Record<string, unknown>;
  }): void;
}

export interface ExecutionResult {
  readonly outcome: "succeeded" | "failed" | "permanent-failure";
  readonly result?: unknown;
  readonly error?: string;
}

export class DuplicateStepKeyError extends Error {
  override readonly name = "DuplicateStepKeyError";
}

/**
 * Executes one attempt of one job.
 *
 * Does not touch job status — leasing and completion belong to the queue.
 * Keeping those apart means this function can be unit-tested against an
 * in-memory recorder, which is how the step semantics are verified without a
 * database.
 */
export async function executeJob(
  job: JobRecord,
  definition: WorkflowDefinition,
  recorder: StepRecorder,
  hooks: RuntimeHooks,
): Promise<ExecutionResult> {
  const usedKeys = new Set<string>();

  const ctx: WorkflowContext = {
    jobId: job.id,
    providerId: job.provider_id,
    attempt: job.attempts,

    async step<T>(key: string, fn: () => Promise<T>): Promise<T> {
      if (usedKeys.has(key)) {
        // Two steps sharing a key would silently memoise to each other's
        // results — a corruption that looks like a caching bug and is
        // extremely hard to diagnose in production. Fail at the point of the
        // mistake instead.
        throw new DuplicateStepKeyError(
          `Step key "${key}" used more than once in job ${job.id}. ` +
            `Step keys must be unique within a workflow.`,
        );
      }
      usedKeys.add(key);

      const existing = await recorder.lookup(job.id, key);
      if (existing !== null) {
        hooks.log({
          jobId: job.id,
          providerId: job.provider_id,
          workflow: job.workflow,
          attempt: job.attempts,
          message: "step.replayed",
          fields: { step: key },
        });
        return existing.result as T;
      }

      const result = await fn();

      // A concurrent attempt may have recorded this step between the lookup
      // and here — two workers can briefly overlap when a lease expires while
      // the original worker is still alive. The recorded result wins, because
      // it corresponds to the side effect that was actually observed.
      const recorded = await recorder.record(
        job.id,
        job.provider_id,
        key,
        result,
        job.attempts,
      );
      return recorded.result as T;
    },

    async heartbeat(): Promise<void> {
      await hooks.heartbeat(job.id);
    },

    log(message: string, fields?: Record<string, unknown>): void {
      hooks.log({
        jobId: job.id,
        providerId: job.provider_id,
        workflow: job.workflow,
        attempt: job.attempts,
        message,
        ...(fields === undefined ? {} : { fields }),
      });
    },
  };

  try {
    const result = await definition.handler(ctx, job.input);
    return { outcome: "succeeded", result };
  } catch (error) {
    if (error instanceof PermanentFailure) {
      return { outcome: "permanent-failure", error: error.message };
    }
    if (error instanceof DuplicateStepKeyError) {
      // A programming error. Retrying cannot help and would burn the budget.
      return { outcome: "permanent-failure", error: error.message };
    }
    return {
      outcome: "failed",
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/** In-memory recorder for tests and local development. */
export class MemoryStepRecorder implements StepRecorder {
  readonly steps = new Map<string, unknown>();

  lookup(jobId: string, stepKey: string): Promise<{ result: unknown } | null> {
    const key = `${jobId}:${stepKey}`;
    return Promise.resolve(
      this.steps.has(key) ? { result: this.steps.get(key) } : null,
    );
  }

  record(
    jobId: string,
    _providerId: string,
    stepKey: string,
    result: unknown,
    _attempt?: number,
  ): Promise<{ recorded: boolean; result: unknown }> {
    const key = `${jobId}:${stepKey}`;
    if (this.steps.has(key)) {
      return Promise.resolve({ recorded: false, result: this.steps.get(key) });
    }
    // Round-trips through JSON so tests observe what production observes:
    // a replayed step returns the deserialised form, not the original object.
    const stored = JSON.parse(JSON.stringify(result ?? null)) as unknown;
    this.steps.set(key, stored);
    return Promise.resolve({ recorded: true, result: stored });
  }
}
