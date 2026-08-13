export interface JobRecord {
  readonly id: string;
  readonly provider_id: string;
  readonly workflow: string;
  readonly input: Record<string, unknown>;
  readonly status: JobStatus;
  readonly attempts: number;
  readonly max_attempts: number;
  readonly last_error: string | null;
}

export type JobStatus =
  | "pending"
  | "running"
  | "succeeded"
  | "failed"
  | "dead"
  | "cancelled";

/**
 * The interface a workflow sees.
 *
 * Deliberately minimal, and deliberately free of anything Postgres-specific.
 * ADR-0009 commits to keeping the migration path to Temporal open, and that
 * only holds if workflow code never learns what it is running on. If a
 * Postgres concept appears in this interface, that promise is already broken.
 */
export interface WorkflowContext {
  readonly jobId: string;
  readonly providerId: string;
  readonly attempt: number;

  /**
   * Run a side effect exactly once across all attempts of this job.
   *
   * On the first attempt the function runs and its result is recorded. On any
   * later attempt the recorded result is returned and the function is NOT
   * called. This is what makes retry safe rather than merely possible.
   *
   * Everything with an external side effect must be inside a step. Anything
   * outside one will be re-executed on every attempt.
   *
   * The result must be JSON-serialisable: it is persisted, and on replay the
   * caller receives the deserialised form rather than the original object.
   */
  step<T>(key: string, fn: () => Promise<T>): Promise<T>;

  /** Extend the lease during a long step. */
  heartbeat(): Promise<void>;

  /** Structured log scoped to this job. Never receives untrusted content. */
  log(message: string, fields?: Record<string, unknown>): void;
}

export type WorkflowHandler = (
  ctx: WorkflowContext,
  input: Record<string, unknown>,
) => Promise<unknown>;

export interface WorkflowDefinition {
  readonly name: string;
  readonly handler: WorkflowHandler;
  /** Overrides the queue default when this workflow warrants fewer retries. */
  readonly maxAttempts?: number;
}

/**
 * Thrown by a workflow to fail a job immediately without consuming the
 * remaining retry budget.
 *
 * For failures that will never succeed on retry — a repository that no longer
 * exists, a revoked installation, a migration the policy engine rejected.
 * Retrying those wastes a rate-limit budget that legitimate work needs.
 */
export class PermanentFailure extends Error {
  override readonly name = "PermanentFailure";
}
