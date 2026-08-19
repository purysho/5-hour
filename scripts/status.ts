/**
 * What the pipeline is actually doing.
 *
 * Every other operator script writes; this one only reads. It exists because
 * the moment a change is approved it disappears from `pnpm db:approve` —
 * `listPending` filters on `approved_at IS NULL`, which is correct for a
 * to-do list and leaves nothing to watch a rollout with. The first time
 * anyone approved a real change, the console went quiet and the only way to
 * see whether anything had happened was to open psql against production.
 *
 *   pnpm db:status
 *
 * The four sections are the four places this pipeline stalls, in the order it
 * runs: nothing watched, nothing detected, nothing approved, nothing dequeued.
 * Reading it top to bottom is meant to answer "which of those is it" without
 * needing a query.
 *
 * `last swept` is the field that catches the most common confusion. A sweep
 * never advances its own baseline, so a package that shows a recent sweep and
 * no change means detection ran and found nothing to report — which is a very
 * different problem from a package that has never been swept at all.
 *
 * Failures print their `last_error` because a job that has exhausted its
 * attempts is invisible in a status count: it is neither pending nor running,
 * and 'failed' next to a number tells nobody why.
 */

import pg from "pg";

export interface WatchedRow {
  readonly ecosystem: string;
  readonly packageName: string;
  readonly baselineVersion: string;
  readonly enabled: boolean;
  readonly sweepIntervalSeconds: number;
  readonly lastSweptAt: Date | null;
}

export interface ChangeRow {
  readonly changeKey: string;
  readonly summary: string;
  readonly impactedSymbols: number;
  readonly corroborations: number;
  readonly approvedAt: Date | null;
  readonly approvedBy: string | null;
  readonly rolloutQueued: boolean;
}

export interface JobCount {
  readonly workflow: string;
  readonly status: string;
  readonly count: number;
}

export interface JobFailure {
  readonly workflow: string;
  readonly attempts: number;
  readonly lastError: string | null;
  readonly finishedAt: Date | null;
}

export interface PipelineStatus {
  readonly watched: readonly WatchedRow[];
  readonly changes: readonly ChangeRow[];
  readonly jobs: readonly JobCount[];
  readonly failures: readonly JobFailure[];
}

export async function readStatus(connectionString: string): Promise<PipelineStatus> {
  const client = new pg.Client({ connectionString });
  await client.connect();
  try {
    const watched = await client.query(
      `SELECT ecosystem, package_name, baseline_version, enabled,
              sweep_interval_seconds, last_swept_at
         FROM watched_package
        ORDER BY package_name`,
    );

    // `rollout_queued` is derived from the job table rather than a column,
    // because that is where the truth is: one approval earns exactly one
    // rollout, enforced by the unique dedupe key `rollout:<change id>`. An
    // approved change with no such job has not been picked up yet; one with a
    // job will never get a second, however many times it is re-approved.
    const changes = await client.query(
      `SELECT c.change_key, c.summary,
              coalesce(array_length(c.impacted_symbols, 1), 0) AS impacted_symbols,
              jsonb_array_length(c.corroborations) AS corroborations,
              c.approved_at, c.approved_by,
              EXISTS (
                SELECT 1 FROM job j
                 WHERE j.workflow = 'plan-rollout'
                   AND j.dedupe_key = 'rollout:' || c.id::text
              ) AS rollout_queued
         FROM upstream_change c
        ORDER BY c.created_at DESC
        LIMIT 20`,
    );

    const jobs = await client.query(
      `SELECT workflow, status::text AS status, count(*)::int AS count
         FROM job
        GROUP BY workflow, status
        ORDER BY workflow, status`,
    );

    const failures = await client.query(
      `SELECT workflow, attempts, last_error, finished_at
         FROM job
        WHERE status = 'failed'
        ORDER BY finished_at DESC NULLS LAST
        LIMIT 10`,
    );

    return {
      watched: watched.rows.map((r) => ({
        ecosystem: r.ecosystem,
        packageName: r.package_name,
        baselineVersion: r.baseline_version,
        enabled: r.enabled,
        sweepIntervalSeconds: r.sweep_interval_seconds,
        lastSweptAt: r.last_swept_at,
      })),
      changes: changes.rows.map((r) => ({
        changeKey: r.change_key,
        summary: r.summary,
        impactedSymbols: Number(r.impacted_symbols),
        corroborations: Number(r.corroborations),
        approvedAt: r.approved_at,
        approvedBy: r.approved_by,
        rolloutQueued: r.rollout_queued,
      })),
      jobs: jobs.rows.map((r) => ({
        workflow: r.workflow,
        status: r.status,
        count: Number(r.count),
      })),
      failures: failures.rows.map((r) => ({
        workflow: r.workflow,
        attempts: r.attempts,
        lastError: r.last_error,
        finishedAt: r.finished_at,
      })),
    };
  } finally {
    await client.end();
  }
}

function ago(at: Date | null): string {
  if (!at) return "never";
  const seconds = Math.round((Date.now() - at.getTime()) / 1000);
  if (seconds < 90) return `${seconds}s ago`;
  if (seconds < 5400) return `${Math.round(seconds / 60)}m ago`;
  return `${Math.round(seconds / 3600)}h ago`;
}

export function render(status: PipelineStatus): string {
  const out: string[] = [];

  out.push("Watched packages");
  if (status.watched.length === 0) {
    out.push("  (none — nothing to detect; see `pnpm db:watch`)");
  }
  for (const w of status.watched) {
    const paused = w.enabled ? "" : "  [paused]";
    out.push(
      `  ${w.ecosystem}:${w.packageName} baseline ${w.baselineVersion}` +
        `  every ${w.sweepIntervalSeconds}s  last swept ${ago(w.lastSweptAt)}${paused}`,
    );
  }

  out.push("", "Changes");
  if (status.changes.length === 0) {
    out.push("  (none — no sweep has reported one yet)");
  }
  for (const c of status.changes) {
    const gate = c.approvedAt
      ? `approved by ${c.approvedBy ?? "?"} ${ago(c.approvedAt)}` +
        (c.rolloutQueued ? ", rollout queued" : ", rollout not queued yet")
      : "awaiting approval";
    out.push(`  ${c.changeKey}  [${gate}]`);
    out.push(`    ${c.summary}`);
    out.push(
      `    ${c.corroborations} corroboration(s), ${c.impactedSymbols} impacted symbol(s)`,
    );
  }

  out.push("", "Jobs");
  if (status.jobs.length === 0) {
    out.push("  (none queued)");
  }
  for (const j of status.jobs) {
    out.push(`  ${j.workflow.padEnd(20)} ${j.status.padEnd(10)} ${j.count}`);
  }

  if (status.failures.length > 0) {
    out.push("", "Recent failures");
    for (const f of status.failures) {
      out.push(`  ${f.workflow} (attempt ${f.attempts}, ${ago(f.finishedAt)})`);
      out.push(`    ${f.lastError ?? "no error recorded"}`);
    }
  }

  return out.join("\n");
}

const isEntrypoint =
  process.argv[1] !== undefined && import.meta.url === `file://${process.argv[1]}`;

if (isEntrypoint) {
  const connectionString = process.env["DATABASE_URL"];
  if (!connectionString) {
    console.error("DATABASE_URL is required");
    process.exit(1);
  }
  console.log(render(await readStatus(connectionString)));
}
