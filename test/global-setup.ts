import pg from "pg";
import { migrate } from "../scripts/migrate.ts";

/**
 * Runs once per `vitest run`, before any worker starts.
 *
 * Schema reset must not live in per-file setup: test files run in separate
 * worker threads, so each would reset the schema underneath the others. That
 * failure is racy and file-order dependent, which is the worst kind to debug.
 */

export const ADMIN_URL =
  process.env["DATABASE_URL"] ??
  "postgresql://postgres@localhost:5433/driftless_test?host=/tmp/pgrun";

export default async function setup(): Promise<void> {
  const bootstrapUrl = ADMIN_URL.replace(/\/driftless_test/, "/postgres");
  const bootstrap = new pg.Client({ connectionString: bootstrapUrl });
  await bootstrap.connect();
  try {
    const { rowCount } = await bootstrap.query(
      "SELECT 1 FROM pg_database WHERE datname = 'driftless_test'",
    );
    if (!rowCount) await bootstrap.query("CREATE DATABASE driftless_test");
  } finally {
    await bootstrap.end();
  }

  await migrate(ADMIN_URL, { reset: true });

  const admin = new pg.Client({ connectionString: ADMIN_URL });
  await admin.connect();
  try {
    // A login role that is a member of driftless_app, mirroring how
    // production connects. Tests must not run as a superuser: RLS would be
    // bypassed and every isolation assertion would pass vacuously.
    // TWO login roles, never one holding both grants.
    //
    // Postgres applies every policy attached to any role the current user is a
    // member of, OR'd together. A login role granted both driftless_app and
    // driftless_admin therefore picks up the platform policy on job/job_step,
    // and every tenant-scoped query silently gains cross-tenant visibility —
    // no error, no failing query, nothing to notice. Role membership is the
    // isolation boundary here, so the split is mandatory, not tidiness.
    for (const [login, grant] of [
      ["driftless_app_login", "driftless_app"],
      ["driftless_worker_login", "driftless_admin"],
    ] as const) {
      await admin.query(`
        DO $$ BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${login}') THEN
            CREATE ROLE ${login} LOGIN INHERIT NOBYPASSRLS;
          END IF;
        END $$;
      `);
      await admin.query(`GRANT ${grant} TO ${login}`);
      await admin.query(`GRANT CONNECT ON DATABASE driftless_test TO ${login}`);
    }
  } finally {
    await admin.end();
  }
}
