/**
 * Migration runner.
 *
 * Applies numbered SQL files in order, once each, tracked in
 * schema_migration. Intentionally minimal — no down migrations, since a
 * forward-only history is easier to reason about and a rollback of a
 * destructive migration is a restore, not a script.
 *
 * ADR-0005 §5 requires that a migration adding a tenant-scoped table without
 * RLS fails the build. That check lives in the test suite
 * (test/db/rls.test.ts) so it runs on every CI run rather than only when a
 * migration happens to be applied.
 */

import { readdir, readFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "migrations");

export async function migrate(
  connectionString: string,
  options: { reset?: boolean } = {},
): Promise<string[]> {
  const client = new pg.Client({ connectionString });
  await client.connect();
  const applied: string[] = [];

  try {
    if (options.reset) {
      // Roles are cluster-scoped and survive a schema drop, so they are
      // dropped explicitly. Order matters: owned objects first.
      await client.query("DROP SCHEMA IF EXISTS public CASCADE");
      await client.query("DROP SCHEMA IF EXISTS app CASCADE");
      await client.query("CREATE SCHEMA public");
      for (const role of ["driftless_app", "driftless_admin"]) {
        await client.query(
          `DO $$ BEGIN
             IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${role}') THEN
               EXECUTE 'DROP OWNED BY ${role}';
               EXECUTE 'DROP ROLE ${role}';
             END IF;
           END $$;`,
        );
      }
    }

    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migration (
        name       text PRIMARY KEY,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `);

    const files = (await readdir(MIGRATIONS_DIR))
      .filter((f) => f.endsWith(".sql"))
      .sort();

    for (const file of files) {
      const { rowCount } = await client.query(
        "SELECT 1 FROM schema_migration WHERE name = $1",
        [file],
      );
      if (rowCount && rowCount > 0) continue;

      const sql = await readFile(join(MIGRATIONS_DIR, file), "utf8");
      // Each migration is one transaction: a partially applied migration is
      // far worse than a failed one.
      await client.query("BEGIN");
      try {
        await client.query(sql);
        await client.query("INSERT INTO schema_migration (name) VALUES ($1)", [file]);
        await client.query("COMMIT");
        applied.push(file);
      } catch (error) {
        await client.query("ROLLBACK");
        throw new Error(`Migration ${file} failed: ${(error as Error).message}`, {
          cause: error,
        });
      }
    }
  } finally {
    await client.end();
  }

  return applied;
}

const isEntrypoint =
  process.argv[1] !== undefined &&
  import.meta.url === `file://${process.argv[1]}`;

if (isEntrypoint) {
  const connectionString = process.env["DATABASE_URL"];
  if (!connectionString) {
    console.error("DATABASE_URL is required");
    process.exit(1);
  }
  const applied = await migrate(connectionString, {
    reset: process.argv.includes("--reset"),
  });
  console.log(
    applied.length ? `Applied: ${applied.join(", ")}` : "No migrations to apply",
  );
}
