import type { Database } from "../db/client.ts";
import { executeJob, PostgresStepRecorder, type RuntimeHooks } from "./runtime.ts";
import type { JobRecord, JobStatus, WorkflowDefinition } from "./types.ts";

/**
 * The worker loop (ADR-0009).
 *
 * Shape, and the reason for it:
 *
 *   withPlatformContext → dequeue. A worker polls a shared queue and cannot
 *                         know whose job it will get, so it cannot have tenant
 *                         context set beforehand.
 *   withTenant(job)     → execute. Everything that touches untrusted input or
 *                         claims an outbound write runs under RLS.
 *
 * Only the act of taking a job off the queue is cross-tenant. That is the
 * narrowest surface this can be reduced to (ADR-0005 §6).
 */

export interface QueueOptions {
  readonly workerId: string;
  readonly leaseSeconds?: number;
  readonly batchSize?: number;
  readonly pollIntervalMs?: number;
}

export interface EnqueueOptions {
  readonly dedupeKey?: string;
  readonly runAt?: Date;
  readonly maxAttempts?: number;
  readonly priority?: number;
}

export class Queue {
  readonly #db: Database;
  readonly #workflows = new Map<string, WorkflowDefinition>();
  readonly #options: Required<Omit<QueueOptions, "workerId">> & { workerId: string };
  #running = false;

  constructor(db: Database, options: QueueOptions) {
    this.#db = db;
    this.#options = {
      workerId: options.workerId,
      leaseSeconds: options.leaseSeconds ?? 300,
      batchSize: options.batchSize ?? 5,
      pollIntervalMs: options.pollIntervalMs ?? 1000,
    };
  }

  register(definition: WorkflowDefinition): this {
    if (this.#workflows.has(definition.name)) {
      throw new Error(`Workflow "${definition.name}" is already registered`);
    }
    this.#workflows.set(definition.name, definition);
    return this;
  }

  async enqueue(
    providerId: string,
    workflow: string,
    input: Record<string, unknown> = {},
    options: EnqueueOptions = {},
  ): Promise<{ jobId: string; created: boolean }> {
    if (!this.#workflows.has(workflow)) {
      // Enqueuing a workflow no worker can run produces a job that sits until
      // its lease logic gives up. Fail at the call site instead.
      throw new Error(`Workflow "${workflow}" is not registered`);
    }
    return this.#db.withTenant(providerId, async (client) => {
      const { rows } = await client.query<{ job_id: string; created: boolean }>(
        "SELECT * FROM enqueue_job($1, $2, $3, $4, $5, $6, $7)",
        [
          providerId,
          workflow,
          JSON.stringify(input),
          options.dedupeKey ?? null,
          options.runAt ?? new Date(),
          options.maxAttempts ?? this.#workflows.get(workflow)?.maxAttempts ?? 5,
          options.priority ?? 100,
        ],
      );
      const row = rows[0]!;
      return { jobId: row.job_id, created: row.created };
    });
  }

  /** Claims up to `batchSize` jobs. Platform-scoped; see the class comment. */
  async dequeue(): Promise<JobRecord[]> {
    const names = [...this.#workflows.keys()];
    if (names.length === 0) return [];

    return this.#db.withPlatformContext("worker dequeue", async (client) => {
      const { rows } = await client.query<JobRecord>(
        "SELECT * FROM dequeue_jobs($1, $2, $3, make_interval(secs => $4))",
        [this.#options.workerId, names, this.#options.batchSize, this.#options.leaseSeconds],
      );
      return rows;
    });
  }

  /**
   * Runs one job to completion, then reports the outcome.
   *
   * Execution and reporting are separate transactions on purpose. Holding a
   * transaction open across model inference and network calls would pin a
   * connection for minutes and produce lock contention under fan-out.
   */
  async runJob(job: JobRecord, hooks?: Partial<RuntimeHooks>): Promise<JobStatus> {
    const definition = this.#workflows.get(job.workflow);
    if (!definition) {
      await this.#fail(job, `No handler registered for workflow "${job.workflow}"`);
      return "failed";
    }

    const runtimeHooks: RuntimeHooks = {
      heartbeat: hooks?.heartbeat ?? ((jobId) => this.heartbeat(jobId)),
      log: hooks?.log ?? defaultLog,
    };

    const execution = await this.#db.withTenant(job.provider_id, async (client) => {
      const recorder = new PostgresStepRecorder(client);
      return executeJob(job, definition, recorder, runtimeHooks);
    });

    switch (execution.outcome) {
      case "succeeded":
        await this.#complete(job, execution.result);
        return "succeeded";
      case "permanent-failure":
        // Skips the remaining retry budget. Retrying a revoked installation or
        // a policy rejection burns rate limit that legitimate work needs.
        await this.#kill(job, execution.error ?? "permanent failure");
        return "dead";
      case "failed":
        return (await this.#fail(job, execution.error ?? "unknown error")) ?? "failed";
    }
  }

  async heartbeat(jobId: string): Promise<void> {
    await this.#db.withPlatformContext("job heartbeat", async (client) => {
      await client.query(
        "SELECT heartbeat_job($1, $2, make_interval(secs => $3))",
        [jobId, this.#options.workerId, this.#options.leaseSeconds],
      );
    });
  }

  async #complete(job: JobRecord, result: unknown): Promise<void> {
    await this.#db.withPlatformContext("job completion", async (client) => {
      await client.query("SELECT complete_job($1, $2, $3)", [
        job.id,
        this.#options.workerId,
        JSON.stringify(result ?? null),
      ]);
    });
  }

  async #fail(job: JobRecord, error: string): Promise<JobStatus | null> {
    return this.#db.withPlatformContext("job failure", async (client) => {
      const { rows } = await client.query<{ fail_job: JobStatus | null }>(
        "SELECT fail_job($1, $2, $3)",
        [job.id, this.#options.workerId, truncateError(error)],
      );
      return rows[0]?.fail_job ?? null;
    });
  }

  /** Terminal failure that bypasses the retry budget. */
  async #kill(job: JobRecord, error: string): Promise<void> {
    await this.#db.withPlatformContext("job permanent failure", async (client) => {
      await client.query(
        `UPDATE job
            SET status = 'dead', last_error = $3, finished_at = now(),
                leased_by = NULL, lease_expires_at = NULL, updated_at = now()
          WHERE id = $1 AND leased_by = $2 AND status = 'running'`,
        [job.id, this.#options.workerId, truncateError(error)],
      );
    });
  }

  /** Poll loop. Returns when `stop()` is called and the in-flight batch drains. */
  async start(): Promise<void> {
    if (this.#running) throw new Error("Queue is already running");
    this.#running = true;

    while (this.#running) {
      const jobs = await this.dequeue();
      if (jobs.length === 0) {
        await sleep(this.#options.pollIntervalMs);
        continue;
      }
      // Sequential within a batch. Concurrency comes from running more
      // workers, which is also how it scales across machines — and it keeps
      // one slow job from starving the connection pool.
      for (const job of jobs) {
        if (!this.#running) break;
        await this.runJob(job);
      }
    }
  }

  stop(): void {
    this.#running = false;
  }
}

function truncateError(error: string, limit = 2000): string {
  return error.length <= limit ? error : `${error.slice(0, limit)}…`;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const defaultLog: RuntimeHooks["log"] = (entry) => {
  // Structured, and carrying no repository content by construction: workflows
  // pass field values explicitly, and UntrustedContent throws if serialised
  // (ADR-0003).
  console.log(JSON.stringify({ level: "info", ...entry }));
};
