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
