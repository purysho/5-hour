import { beforeAll, describe, expect, it } from "vitest";
import { ADMIN_URL, adminClient, prepareDatabase, seedProvider } from "../db/setup.ts";
import { replan } from "../../scripts/replan.ts";

/**
 * Re-planning an approved change.
 *
 * The dedupe key makes one approval earn exactly one rollout, which is the
 * property that bounds the blast radius of a scheduler bug. This script
 * deliberately clears it for one named change, so what these cover is the
 * narrowness: that it removes that change's rollout and no other, and that it
 * does not touch the approval while doing so.
 */

beforeAll(async () => {
  await prepareDatabase();
});

async function seedApproved(
  slug: string,
  changeKey: string,
  options: { approved?: boolean; withJob?: boolean } = {},
): Promise<{ providerId: string; changeId: string }> {
  const approved = options.approved ?? true;
  const fixture = await seedProvider(slug);
  const client = await adminClient();
  try {
    const { rows } = await client.query<{ id: string }>(
      `INSERT INTO upstream_change
              (provider_id, change_key, ecosystem, package_name,
               from_version, to_version, summary, corroborations,
               impacted_symbols, approved_at, approved_by)
            VALUES ($1, $2, 'npm', 'react', '18.2.0', '19.2.8', 'summary',
                    '[]'::jsonb, ARRAY['createRoot'], $3, $4)
         RETURNING id`,
      [fixture.providerId, changeKey, approved ? new Date() : null, approved ? "oliver" : null],
    );
    const changeId = rows[0]!.id;
    if (options.withJob ?? true) {
      await client.query(
        `INSERT INTO job (provider_id, workflow, status, dedupe_key, finished_at)
              VALUES ($1, 'plan-rollout', 'succeeded', $2, now())`,
        [fixture.providerId, `rollout:${changeId}`],
      );
    }
    return { providerId: fixture.providerId, changeId };
  } finally {
    await client.end();
  }
}

async function seedMigration(
  providerId: string,
  changeId: string,
  repo: string,
  status: string,
): Promise<void> {
  const client = await adminClient();
  try {
    // Matching the table's own CHECKs rather than approximating them:
    // job_terminal_finished wants finished_at on succeeded/dead/cancelled, and
    // job_lease_coherent wants a lease on running.
    const terminal = ["dead", "succeeded", "cancelled"].includes(status);
    const running = status === "running";
    await client.query(
      `INSERT INTO job
         (provider_id, workflow, status, dedupe_key, finished_at,
          leased_by, lease_expires_at)
       VALUES ($1, 'migrate-repository', $2::job_status, $3, $4, $5, $6)`,
      [
        providerId,
        status,
        `migrate:${changeId}:${repo}:abc123`,
        terminal ? new Date() : null,
        running ? "worker-test" : null,
        running ? new Date(Date.now() + 60_000) : null,
      ],
    );
  } finally {
    await client.end();
  }
}

async function migrationStatuses(changeId: string): Promise<string[]> {
  const client = await adminClient();
  try {
    const { rows } = await client.query<{ status: string }>(
      `SELECT status::text AS status FROM job
        WHERE workflow = 'migrate-repository' AND dedupe_key LIKE $1
        ORDER BY dedupe_key`,
      [`migrate:${changeId}:%`],
    );
    return rows.map((r) => r.status);
  } finally {
    await client.end();
  }
}

async function rolloutJobCount(changeId: string): Promise<number> {
  const client = await adminClient();
  try {
    const { rows } = await client.query<{ count: string }>(
      "SELECT count(*) FROM job WHERE dedupe_key = $1",
      [`rollout:${changeId}`],
    );
    return Number(rows[0]!.count);
  } finally {
    await client.end();
  }
}

describe("replanning a rollout", () => {
  it("removes the rollout job so the trigger can enqueue again", async () => {
    const { changeId } = await seedApproved("replan-basic", "react@19.2.8");
    expect(await rolloutJobCount(changeId)).toBe(1);

    // Named, because other providers in this database hold the same key —
    // which is the situation resolve-change.ts exists to refuse to guess at.
    const result = await replan(ADMIN_URL, "react@19.2.8", "replan-basic");

    expect(result.removed).toBe(1);
    expect(await rolloutJobCount(changeId)).toBe(0);
  });

  it("leaves the approval and its attribution alone", async () => {
    // Re-planning is not re-approving. Rewriting who authorised a rollout to
    // make it run again falsifies the one record anyone asks for afterwards.
    await seedApproved("replan-keeps-approval", "vue@4.0.0");

    const result = await replan(ADMIN_URL, "vue@4.0.0");

    expect(result.approvedBy).toBe("oliver");
    const client = await adminClient();
    try {
      const { rows } = await client.query<{ approved_at: Date | null; approved_by: string }>(
        "SELECT approved_at, approved_by FROM upstream_change WHERE change_key = $1",
        ["vue@4.0.0"],
      );
      expect(rows[0]?.approved_at).not.toBeNull();
      expect(rows[0]?.approved_by).toBe("oliver");
    } finally {
      await client.end();
    }
  });

  it("takes only the named change's rollout, never another's", async () => {
    // The guard bounds one approval to one rollout. A replan that reached
    // further would reintroduce exactly the fan-out this index prevents.
    const mine = await seedApproved("replan-scoped-a", "react@19.9.9");
    const theirs = await seedApproved("replan-scoped-b", "svelte@6.0.0");

    await replan(ADMIN_URL, "react@19.9.9");

    expect(await rolloutJobCount(mine.changeId)).toBe(0);
    expect(await rolloutJobCount(theirs.changeId)).toBe(1);
  });

  it("refuses a change nobody approved", async () => {
    // Clearing nothing would report success and leave the operator waiting on
    // a rollout that is waiting on them.
    await seedApproved("replan-unapproved", "ember@5.0.0", {
      approved: false,
      withJob: false,
    });

    await expect(replan(ADMIN_URL, "ember@5.0.0")).rejects.toThrow(/has not been approved/);
  });

  it("refuses a key two providers share rather than guessing which", async () => {
    // Same defect class as db:approve. Here it would delete the wrong
    // tenant's rollout guard and re-fan-out their repositories.
    await seedApproved("replan-ambiguous-a", "shared@9.0.0");
    const other = await seedApproved("replan-ambiguous-b", "shared@9.0.0");

    await expect(replan(ADMIN_URL, "shared@9.0.0")).rejects.toThrow(/matches 2 providers/);
    expect(await rolloutJobCount(other.changeId)).toBe(1);
  });

  it("leaves terminal migrations alone unless asked", async () => {
    // The default is a re-plan after a reporting fix, which should reach the
    // same repositories and skip the same ones. Clearing migrations would make
    // it re-open work that already ran.
    const { providerId, changeId } = await seedApproved("replan-keeps-migrations", "keep@1.0.0");
    await seedMigration(providerId, changeId, "repo-a", "dead");

    await replan(ADMIN_URL, "keep@1.0.0", "replan-keeps-migrations");

    expect(await migrationStatuses(changeId)).toEqual(["dead"]);
  });

  it("clears dead migrations with --retry-migrations, and only those", async () => {
    // A job holds its dedupe key in every status, so a repository whose
    // migration died is never attempted again at that commit — the next
    // rollout finds the key and reports a duplicate.
    //
    // Pending and running are live work; deleting either strands a repository
    // mid-flight. Succeeded already opened a pull request, and re-running
    // would open a second one.
    const { providerId, changeId } = await seedApproved("replan-retry", "retry@1.0.0");
    await seedMigration(providerId, changeId, "a-dead", "dead");
    await seedMigration(providerId, changeId, "b-succeeded", "succeeded");
    await seedMigration(providerId, changeId, "c-pending", "pending");
    await seedMigration(providerId, changeId, "d-running", "running");

    const result = await replan(ADMIN_URL, "retry@1.0.0", "replan-retry", {
      retryMigrations: true,
    });

    expect(result.migrationsCleared).toBe(1);
    expect(await migrationStatuses(changeId)).toEqual(["succeeded", "pending", "running"]);
  });

  it("does not reach another change's migrations", async () => {
    // Bounded by the dedupe key prefix, which carries the change id.
    const mine = await seedApproved("replan-scope-mine", "mine@1.0.0");
    const theirs = await seedApproved("replan-scope-theirs", "theirs@1.0.0");
    await seedMigration(mine.providerId, mine.changeId, "r", "dead");
    await seedMigration(theirs.providerId, theirs.changeId, "r", "dead");

    await replan(ADMIN_URL, "mine@1.0.0", "replan-scope-mine", { retryMigrations: true });

    expect(await migrationStatuses(mine.changeId)).toEqual([]);
    expect(await migrationStatuses(theirs.changeId)).toEqual(["dead"]);
  });

  it("refuses a change key that does not exist", async () => {
    await expect(replan(ADMIN_URL, "nope@1.0.0")).rejects.toThrow(/no change with key/);
  });
});
