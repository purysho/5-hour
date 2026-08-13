import pg from "pg";

/**
 * Database access with mandatory tenant context.
 *
 * ADR-0005 puts tenant isolation in the database via row-level security, which
 * only works if the tenant context is actually set on the connection running
 * the query. The whole point of RLS here is to fail closed, so this module is
 * built so that the natural way to run a query is also the correct one.
 *
 * Two hazards this guards against:
 *
 *   Pooling. `set_config(..., is_local => true)` scopes the setting to the
 *   surrounding transaction, so a connection returned to the pool cannot carry
 *   one tenant's context into another tenant's query. Session-level SET is
 *   never used.
 *
 *   Escape hatches. There is deliberately no exported "run a query without
 *   tenant context" helper. Cross-tenant work uses `withPlatformContext`,
 *   which is a separate, narrow, audited path (ADR-0005 §6).
 */

export type ProviderId = string;

export interface TenantClient {
  query<R extends pg.QueryResultRow = pg.QueryResultRow>(
    text: string,
    values?: readonly unknown[],
  ): Promise<pg.QueryResult<R>>;
}

export interface PoolConfig {
  /**
   * Connects as a role granted `driftless_app` and NOTHING ELSE.
   *
   * This is load-bearing and not obvious. Postgres applies every policy
   * attached to any role the current user is a member of, OR'd together. A
   * login role holding both `driftless_app` and `driftless_admin` therefore
   * picks up the platform policy on `job` and `job_step` — and every
   * tenant-scoped query silently gains cross-tenant visibility, with no error
   * and no failing query to notice.
   *
   * Role membership is the isolation boundary, so the two must never be
   * combined on one login role. A test asserts this.
   */
  connectionString: string;
  /**
   * Connects as a role granted `driftless_admin` only. Used exclusively for
   * taking jobs off the shared queue (ADR-0009). Omit it and
   * `withPlatformContext` is unavailable, which is the right default for any
   * process that is not a worker.
   */
  platformConnectionString?: string;
  /** Neither role may be a superuser, and neither may have BYPASSRLS. */
  max?: number;
  statementTimeoutMs?: number;
}

export class Database {
  readonly #pool: pg.Pool;
  readonly #platformPool: pg.Pool | null;
  readonly #statementTimeoutMs: number;

  constructor(config: PoolConfig) {
    this.#pool = new pg.Pool({
      connectionString: config.connectionString,
      max: config.max ?? 10,
    });
    this.#platformPool = config.platformConnectionString
      ? new pg.Pool({
          connectionString: config.platformConnectionString,
          // Deliberately small. The only platform operation is dequeue, and a
          // large pool here would make an accidental cross-tenant query path
          // cheap to run at volume.
          max: 4,
        })
      : null;
    this.#statementTimeoutMs = config.statementTimeoutMs ?? 30_000;
  }

  /**
   * Run `fn` inside a transaction scoped to one provider.
   *
   * Every query issued through the supplied client is subject to the RLS
   * policies in migration 001. A query for another tenant's rows returns
   * nothing; an insert attributed to another tenant raises.
   */
  async withTenant<T>(
    providerId: ProviderId,
    fn: (client: TenantClient) => Promise<T>,
  ): Promise<T> {
    assertUuid(providerId, "providerId");
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(`SET LOCAL statement_timeout = ${this.#statementTimeoutMs}`);
      // is_local => true. Scoped to this transaction, discarded on COMMIT or
      // ROLLBACK, so it cannot leak to the next borrower of this connection.
      await client.query("SELECT set_config('app.current_provider_id', $1, true)", [
        providerId,
      ]);
      const result = await fn(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {
        // A failed rollback means the connection is unusable; releasing it
        // with an error below removes it from the pool rather than returning
        // a poisoned connection.
      });
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Cross-tenant access for platform operations (billing aggregates, support).
   *
   * Deliberately awkward: it demands a written reason, and every use is
   * expected to produce an audit entry. If this is being reached for on a
   * request-serving path, that path is wrong.
   */
  async withPlatformContext<T>(
    reason: string,
    fn: (client: TenantClient) => Promise<T>,
  ): Promise<T> {
    if (!reason.trim()) {
      throw new Error("withPlatformContext requires a reason for the audit trail");
    }
    if (!this.#platformPool) {
      throw new Error(
        "No platform connection configured. Cross-tenant access requires a " +
          "separate login role granted driftless_admin only — see PoolConfig.",
      );
    }
    // A separate pool, not SET ROLE on the app pool. The platform role's
    // reach is decided by which credentials the process holds, so a bug in
    // application code cannot escalate into it.
    const client = await this.#platformPool.connect();
    try {
      await client.query("BEGIN");
      await client.query(`SET LOCAL statement_timeout = ${this.#statementTimeoutMs}`);
      const result = await fn(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    await Promise.all([this.#pool.end(), this.#platformPool?.end()]);
  }
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Tenant identifiers are interpolated into a `set_config` parameter rather
 * than concatenated into SQL, so this is not the injection boundary — but a
 * malformed identifier silently yielding NULL tenant context (and therefore an
 * empty result set) is a confusing failure. Reject it loudly instead.
 */
export function assertUuid(value: string, label: string): void {
  if (!UUID_RE.test(value)) {
    throw new Error(`${label} must be a UUID`);
  }
}
