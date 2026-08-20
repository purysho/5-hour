import { beforeAll, describe, expect, it } from "vitest";
import { ADMIN_URL, adminClient, prepareDatabase, seedProvider } from "../db/setup.ts";
import { readStatus, render } from "../../scripts/status.ts";

/**
 * The read-only view of the pipeline.
 *
 * It exists because approving a change removes it from `pnpm db:approve` —
 * correct for a to-do list, and it left nothing to watch a rollout with. The
 * behaviour worth pinning is that an approved change stays visible, and that
 * "approved" and "rollout queued" are reported as the separate facts they are:
 * the gap between them is exactly where a stalled scheduler shows up.
 */

beforeAll(async () => {
  await prepareDatabase();
});

async function seed(
  slug: string,
  options: { approved?: boolean; withRolloutJob?: boolean } = {},
): Promise<string> {
  const fixture = await seedProvider(slug);
  const client = await adminClient();
  try {
    await client.query(
      `INSERT INTO watched_package
              (provider_id, ecosystem, package_name, baseline_version, sweep_interval_seconds)
            VALUES ($1, 'npm', 'react', '18.2.0', 60)`,
      [fixture.providerId],
    );
    const { rows } = await client.query<{ id: string }>(
      `INSERT INTO upstream_change
              (provider_id, change_key, ecosystem, package_name,
               from_version, to_version, summary, corroborations,
               impacted_symbols, approved_at, approved_by)
            VALUES ($1, 'react@19.2.8', 'npm', 'react', '18.2.0', '19.2.8',
                    'react 18.2.0 → 19.2.8: affects createRoot',
                    '[{"source":"registry"},{"source":"artifact"}]'::jsonb,
                    ARRAY['createRoot'], $2, $3)
         RETURNING id`,
      [fixture.providerId, options.approved ? new Date() : null, options.approved ? "oliver" : null],
    );
    if (options.withRolloutJob) {
      await client.query(
        `INSERT INTO job (provider_id, workflow, dedupe_key)
              VALUES ($1, 'plan-rollout', $2)`,
        [fixture.providerId, `rollout:${rows[0]!.id}`],
      );
    }
  } finally {
    await client.end();
  }
  return fixture.providerId;
}

describe("pipeline status", () => {
  it("keeps an approved change visible after db:approve stops listing it", async () => {
    // The whole reason this script exists. `listPending` filters on
    // approved_at IS NULL, so approving is the moment the console goes quiet.
    await seed("status-approved", { approved: true });
    const status = await readStatus(ADMIN_URL);

    const change = status.changes.find((c) => c.changeKey === "react@19.2.8");
    expect(change).toBeDefined();
    expect(change?.approvedBy).toBe("oliver");
    expect(change?.impactedSymbols).toBe(1);
  });

  it("reports approved and rollout-queued as separate facts", async () => {
    // An approval with no rollout job is the scheduler not having ticked yet.
    // Collapsing the two would hide precisely that state.
    await seed("status-not-queued", { approved: true });
    const before = await readStatus(ADMIN_URL);
    expect(before.changes.some((c) => c.approvedAt !== null && !c.rolloutQueued)).toBe(true);

    await seed("status-queued", { approved: true, withRolloutJob: true });
    const after = await readStatus(ADMIN_URL);
    expect(after.changes.some((c) => c.rolloutQueued)).toBe(true);
  });

  it("shows a watched package that has never been swept", async () => {
    // Distinct from one swept recently that found nothing — the two look
    // identical in a change count and have different fixes.
    await seed("status-unswept");
    const status = await readStatus(ADMIN_URL);
    const watched = status.watched.find((w) => w.packageName === "react");
    expect(watched?.lastSweptAt).toBeNull();
    expect(render(status)).toContain("last swept never");
  });

  it("names the enrolment gap when a rollout targeted nothing", async () => {
    // The state this pipeline lands in most often, and the least legible:
    // plan-rollout succeeds, no pull request exists, and the count of
    // migrate-repository jobs is zero rather than wrong. `targeted 0` with
    // nothing skipped means there were no repositories to begin with.
    const providerId = await seed("status-empty-rollout");
    const client = await adminClient();
    try {
      await client.query(
        `INSERT INTO job (provider_id, workflow, status, result, finished_at)
              VALUES ($1, 'plan-rollout', 'succeeded',
                      '{"kind":"planned","targeted":0,"enqueued":0,"skipped":[]}'::jsonb,
                      now())`,
        [providerId],
      );
    } finally {
      await client.end();
    }

    const output = render(await readStatus(ADMIN_URL));
    expect(output).toContain("no candidate repositories");
  });

  it("points at enrolment when there are no repositories at all", async () => {
    // Rendered from a constructed status rather than the database: the counts
    // are deployment-wide, and a shared test database always has rows from
    // somewhere else. What matters is that zero repositories names the cause —
    // `installation.created` fires only at install time, so an App installed
    // before DEFAULT_PROVIDER_SLUG was set never enrolled and never will
    // without a reinstall.
    const output = render({
      enrolment: {
        consumers: 0,
        installations: 0,
        suspendedInstallations: 0,
        repositories: 0,
        archivedRepositories: 0,
      },
      watched: [],
      changes: [],
      jobs: [],
      rollouts: [],
      failures: [],
    });
    expect(output).toContain("no repositories");
    expect(output).toContain("installation.created");
    expect(output).toContain("DEFAULT_PROVIDER_SLUG");
  });

  it("prints each skipped repository's reason", async () => {
    // Repositories that exist and were filtered is a different problem from
    // no repositories, and the reason is only ever in the job result.
    const providerId = await seed("status-skipped-rollout");
    const client = await adminClient();
    try {
      await client.query(
        `INSERT INTO job (provider_id, workflow, status, result, finished_at)
              VALUES ($1, 'plan-rollout', 'succeeded',
                      '{"kind":"planned","targeted":0,"enqueued":0,"skipped":[
                         {"owner":"acme","name":"web","reason":"manifest could not be read"}
                       ]}'::jsonb, now())`,
        [providerId],
      );
    } finally {
      await client.end();
    }

    const output = render(await readStatus(ADMIN_URL));
    expect(output).toContain("skipped acme/web: manifest could not be read");
  });

  it("surfaces a dead job, not only a retrying one", async () => {
    // 'failed' will be retried; 'dead' has exhausted its attempts and is
    // terminal. Querying only 'failed' hid the jobs that had stopped for good
    // and would never report themselves again.
    const providerId = await seed("status-dead-job");
    const client = await adminClient();
    try {
      await client.query(
        `INSERT INTO job (provider_id, workflow, status, attempts, last_error, finished_at)
              VALUES ($1, 'migrate-repository', 'dead', 3, 'agent refused: no usable source files', now())`,
        [providerId],
      );
    } finally {
      await client.end();
    }

    const status = await readStatus(ADMIN_URL);
    expect(status.failures.some((f) => f.status === "dead")).toBe(true);

    const output = render(status);
    expect(output).toContain("agent refused: no usable source files");
    expect(output).toContain("DEAD, no further attempts");
  });

  it("says when a rollout enqueued nothing because it was already queued", async () => {
    // "targeted 4, enqueued 0" reads as a rollout that did nothing. It is a
    // re-plan finding every migration already present on its dedupe key, which
    // is ADR-0004 working rather than failing.
    const providerId = await seed("status-dupe-rollout");
    const client = await adminClient();
    try {
      await client.query(
        `INSERT INTO job (provider_id, workflow, status, result, finished_at)
              VALUES ($1, 'plan-rollout', 'succeeded',
                      '{"kind":"planned","targeted":4,"enqueued":0,"duplicates":4,"skipped":[]}'::jsonb,
                      now())`,
        [providerId],
      );
    } finally {
      await client.end();
    }

    expect(render(await readStatus(ADMIN_URL))).toContain("4 already queued");
  });

  it("prints why a failed job failed, not just that it did", async () => {
    // A failed job is neither pending nor running, so it is invisible in a
    // status count; 'failed 1' tells nobody what to do next.
    const providerId = await seed("status-failed");
    const client = await adminClient();
    try {
      await client.query(
        `INSERT INTO job (provider_id, workflow, status, attempts, last_error, finished_at)
              VALUES ($1, 'migrate-repository', 'failed', 5, 'ANTHROPIC_API_KEY missing', now())`,
        [providerId],
      );
    } finally {
      await client.end();
    }

    const status = await readStatus(ADMIN_URL);
    expect(render(status)).toContain("ANTHROPIC_API_KEY missing");
  });
});
