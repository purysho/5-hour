/**
 * Lets one approved change be planned again.
 *
 * One approval earns exactly one rollout, ever. That is not a convention —
 * `job_dedupe_key_idx` makes `rollout:<change id>` unique across every job
 * status, so the approval trigger enqueues nothing once a rollout exists,
 * however many times it ticks (migration 010). It is the property that keeps
 * "how many rollouts can one approval cause" answerable by reading one index.
 *
 * That guard defends against a scheduler bug, not against an operator who has
 * fixed something and wants the same change reassessed. Those are different
 * acts, and only the second one is this script:
 *
 *   pnpm db:replan react@19.2.8
 *   pnpm db:replan react@19.2.8 --retry-migrations
 *
 * A rollout's migrations are deduplicated on
 * `migrate:<change>:<repository>:<sha>`, and a job holds that key in every
 * status including the terminal ones. So a repository whose migration died is
 * never attempted again at that commit, even after the thing that killed it is
 * fixed — the next rollout finds the key and reports a duplicate.
 *
 * `--retry-migrations` clears the dead and cancelled ones. It is off by
 * default because a rollout re-planned after a reporting fix should reach the
 * same repositories and skip the same ones; clearing migrations is right only
 * when what was fixed is the thing that failed them. Pending and running jobs
 * are never touched — they are live work — and neither are succeeded ones,
 * which already opened a pull request that re-running would duplicate.
 *
 * It removes the rollout job for one named change and nothing else. No bulk
 * form and no "all pending" flag, deliberately: the guard exists so that a
 * mistake costs one repository rather than every repository at once, and a
 * command that clears it for everything at once reintroduces exactly the
 * failure the index was added to prevent.
 *
 * Re-planning is not re-approving. `approved_at` and `approved_by` are left
 * alone — the human who authorised the change still authorised it, and
 * rewriting that to make a rollout run again would falsify the one record
 * anyone will want afterwards.
 *
 * A change that already produced migrations will produce them again. Those
 * are separately deduplicated on their own idempotency key (ADR-0004), so a
 * repository that already has a pull request does not get a second one — but
 * a repository that was skipped last time and is readable now will get its
 * first, which is usually the point of running this at all.
 */

import pg from "pg";
import { operatorConnectionString, OPERATOR_URL_VAR } from "./operator-connection.ts";
import { resolveChange } from "./resolve-change.ts";

export interface ReplanResult {
  readonly changeKey: string;
  readonly removed: number;
  /** Terminal migration jobs cleared by --retry-migrations. */
  readonly migrationsCleared: number;
  readonly approvedBy: string | null;
}

export async function replan(
  connectionString: string,
  changeKey: string,
  providerSlug?: string,
  options: { retryMigrations?: boolean } = {},
): Promise<ReplanResult> {
  const client = new pg.Client({ connectionString });
  await client.connect();
  try {
    // Resolved rather than matched: a change key belongs to a provider, and
    // two tenants watching the same package hold the same key. See
    // resolve-change.ts for why ambiguity is refused instead of resolved.
    const change = await resolveChange(client, changeKey, providerSlug);

    if (change.approvedAt === null) {
      // Nothing to clear, and clearing nothing would look like it worked.
      // An unapproved change is waiting on a human, not on a stale job row.
      throw new Error(
        `${changeKey} has not been approved; there is no rollout to replan. ` +
          `Approve it with \`pnpm db:approve ${changeKey} --by <your name>\`.`,
      );
    }

    // Scoped to this change's own dedupe key. A DELETE on workflow alone would
    // take every rollout in the deployment with it.
    const { rowCount } = await client.query(
      "DELETE FROM job WHERE workflow = 'plan-rollout' AND dedupe_key = $1",
      [`rollout:${change.id}`],
    );

    // Off by default, because a rollout re-planned after a *reporting* fix
    // should reach the same repositories and skip the same ones. Clearing
    // migrations makes the next rollout re-open work that already ran, which
    // is the right move only when what was fixed is the thing that failed
    // them.
    //
    // Terminal states only. A pending or running migration is live work and
    // deleting it would strand a repository mid-flight; a succeeded one
    // already produced its pull request, and re-running would open a second.
    //
    // The keys are `migrate:<change>:<repository>:<sha>`, so this is bounded
    // to this change and cannot reach another's.
    let migrationsCleared = 0;
    if (options.retryMigrations) {
      const cleared = await client.query(
        `DELETE FROM job
          WHERE workflow = 'migrate-repository'
            AND status IN ('dead', 'cancelled')
            AND dedupe_key LIKE $1`,
        [`migrate:${change.id}:%`],
      );
      migrationsCleared = cleared.rowCount ?? 0;
    }

    return {
      changeKey,
      removed: rowCount ?? 0,
      migrationsCleared,
      approvedBy: change.approvedBy,
    };
  } finally {
    await client.end();
  }
}

const isEntrypoint =
  process.argv[1] !== undefined && import.meta.url === `file://${process.argv[1]}`;

function flag(argv: readonly string[], name: string): string | undefined {
  const index = argv.indexOf(`--${name}`);
  return index === -1 ? undefined : argv[index + 1];
}

if (isEntrypoint) {
  const argv = process.argv.slice(2);
  const connectionString = operatorConnectionString();
  const changeKey = argv[0]?.startsWith("--") ? undefined : argv[0];
  const providerSlug = flag(argv, "provider");
  const retryMigrations = argv.includes("--retry-migrations");

  if (!connectionString) {
    console.error(`${OPERATOR_URL_VAR} or DATABASE_URL is required`);
    process.exit(1);
  }
  if (!changeKey) {
    console.error(
      "usage: pnpm db:replan <change-key> [--provider slug] [--retry-migrations]\n" +
        "Removes one approved change's rollout job so it is planned again.\n" +
        "`pnpm db:status` lists the change keys.",
    );
    process.exit(1);
  }

  try {
    const result = await replan(connectionString, changeKey, providerSlug, {
      retryMigrations,
    });
    if (result.removed === 0) {
      console.log(
        `${result.changeKey} has no rollout job; the approval trigger will ` +
          `enqueue one on its next tick.`,
      );
    } else {
      const migrations =
        result.migrationsCleared > 0
          ? `\n${result.migrationsCleared} terminal migration job(s) cleared; ` +
            `those repositories will be attempted again.`
          : retryMigrations
            ? "\nNo terminal migration jobs to clear."
            : "";
      console.log(
        `Removed the rollout job for ${result.changeKey}.\n` +
          `Still approved by ${result.approvedBy ?? "?"} — the trigger re-plans ` +
          `it on its next tick.${migrations}`,
      );
    }
  } catch (error) {
    console.error((error as Error).message);
    process.exit(1);
  }
}
