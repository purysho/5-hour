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
import { resolveChange } from "./resolve-change.ts";

export interface ReplanResult {
  readonly changeKey: string;
  readonly removed: number;
  readonly approvedBy: string | null;
}

export async function replan(
  connectionString: string,
  changeKey: string,
  providerSlug?: string,
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

    return {
      changeKey,
      removed: rowCount ?? 0,
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
  const connectionString = process.env["DATABASE_URL"];
  const changeKey = argv[0]?.startsWith("--") ? undefined : argv[0];
  const providerSlug = flag(argv, "provider");

  if (!connectionString) {
    console.error("DATABASE_URL is required");
    process.exit(1);
  }
  if (!changeKey) {
    console.error(
      "usage: pnpm db:replan <change-key> [--provider slug]\n" +
        "Removes one approved change's rollout job so it is planned again.\n" +
        "`pnpm db:status` lists the change keys.",
    );
    process.exit(1);
  }

  try {
    const result = await replan(connectionString, changeKey, providerSlug);
    if (result.removed === 0) {
      console.log(
        `${result.changeKey} has no rollout job; the approval trigger will ` +
          `enqueue one on its next tick.`,
      );
    } else {
      console.log(
        `Removed the rollout job for ${result.changeKey}.\n` +
          `Still approved by ${result.approvedBy ?? "?"} — the trigger re-plans ` +
          `it on its next tick.`,
      );
    }
  } catch (error) {
    console.error((error as Error).message);
    process.exit(1);
  }
}
