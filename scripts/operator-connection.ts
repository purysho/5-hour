/**
 * The connection the operator scripts run on, and why it is not the app's.
 *
 * These scripts read and write tables that RLS confines to a tenant:
 * `provider`, `watched_package`, `upstream_change`. The application role
 * reaches those rows only with `app.current_provider_id()` set, which is
 * established per request from a server-derived identity — something a CLI
 * has no way to supply, and should not.
 *
 * `driftless_admin` does not help either. Its cross-tenant policies cover
 * `job` and `job_step` and nothing else (migrations 001 and 004), so on the
 * rest RLS denies by default.
 *
 * So these run on the migration connection, the same one `db:migrate` and
 * `db:provider` already documented themselves as needing. That is a
 * deliberate boundary rather than an oversight: deciding which packages a
 * tenant watches, and who authorised a rollout, are operator acts, and the
 * roles that serve traffic are not supposed to be able to perform them.
 *
 * ── The failure this exists to prevent ──────────────────────────────────────
 *
 * RLS does not raise. It filters. A script pointed at the app role does not
 * fail — it reports an empty system: no watched packages, no changes, nothing
 * awaiting approval. Indistinguishable from a correctly configured deployment
 * that has nothing to do, and the reading an operator is most likely to
 * accept. So the connection is resolved explicitly and the ambiguity is
 * reported rather than left to be discovered.
 */

import pg from "pg";

export const OPERATOR_URL_VAR = "ADMIN_DATABASE_URL";

/**
 * The connection string for an operator script.
 *
 * `ADMIN_DATABASE_URL` first, falling back to `DATABASE_URL` — which is
 * correct in development, where both are the same superuser, and wrong in a
 * production that has separated its roles. `describeVisibility` below is what
 * tells the difference.
 */
export function operatorConnectionString(
  env: NodeJS.ProcessEnv = process.env,
): string | undefined {
  return env[OPERATOR_URL_VAR]?.trim() || env["DATABASE_URL"]?.trim() || undefined;
}

export interface Visibility {
  readonly role: string;
  /** True when this role can see across tenants: superuser, or table owner. */
  readonly unfiltered: boolean;
  /** Non-null when rows may be silently hidden. Ready to print. */
  readonly warning: string | null;
}

/**
 * Whether this connection can actually see the rows it is about to report on.
 *
 * A superuser bypasses RLS; so does the owner of a table, unless the table
 * sets FORCE (migration 001 sets FORCE on every tenant-scoped table, so
 * ownership alone is not enough there). Anything else is filtered, and the
 * filtering is invisible.
 */
export async function describeVisibility(client: pg.Client): Promise<Visibility> {
  const { rows } = await client.query<{
    role: string;
    is_super: boolean;
    can_see_providers: boolean;
  }>(
    `SELECT current_user AS role,
            (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS is_super,
            EXISTS (SELECT 1 FROM provider) AS can_see_providers`,
  );
  const row = rows[0];
  if (!row) {
    return { role: "unknown", unfiltered: false, warning: "could not determine the current role" };
  }

  // A superuser is definitive. Otherwise the question is empirical: if no
  // provider is visible, either there are none or RLS is hiding them, and
  // those two states are worth distinguishing out loud.
  if (row.is_super) {
    return { role: row.role, unfiltered: true, warning: null };
  }
  if (row.can_see_providers) {
    return { role: row.role, unfiltered: true, warning: null };
  }
  return {
    role: row.role,
    unfiltered: false,
    warning:
      `Connected as ${row.role}, which cannot see any provider. Either none ` +
      `exists, or row-level security is filtering them — RLS hides rows ` +
      `rather than raising, so an empty result here is not evidence of an ` +
      `empty system. Operator scripts need the migration connection: set ` +
      `${OPERATOR_URL_VAR} to it.`,
  };
}
