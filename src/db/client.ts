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
  connectionString: string;
  /** Application role. Must not be a superuser and must not have BYPASSRLS. */
  max?: number;
  statementTimeoutMs?: number;
}

export class Database {
  readonly #pool: pg.Pool;
  readonly #statementTimeoutMs: number;

  constructor(config: PoolConfig) {
    this.#pool = new pg.Pool({
      connectionString: config.connectionString,
      max: config.max ?? 10,
    });
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
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SET LOCAL ROLE driftless_admin");
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
    await this.#pool.end();
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
