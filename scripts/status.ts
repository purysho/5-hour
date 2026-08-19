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

export interface EnrolmentCounts {
  readonly consumers: number;
  readonly installations: number;
  readonly suspendedInstallations: number;
  readonly repositories: number;
  readonly archivedRepositories: number;
}

export interface RolloutResult {
  readonly finishedAt: Date | null;
  readonly kind: string;
  readonly targeted: number | null;
  readonly enqueued: number | null;
  readonly skipped: readonly { owner: string; name: string; reason: string }[];
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
  readonly enrolment: EnrolmentCounts;
  readonly watched: readonly WatchedRow[];
  readonly changes: readonly ChangeRow[];
  readonly jobs: readonly JobCount[];
  readonly rollouts: readonly RolloutResult[];
  readonly failures: readonly JobFailure[];
}

export async function readStatus(connectionString: string): Promise<PipelineStatus> {
  const client = new pg.Client({ connectionString });
  await client.connect();
  try {
    // Counted rather than listed. "Is anything enrolled" is the question a
    // rollout that targeted nothing raises, and the answer is a number — while
    // listing customer repositories into a terminal is a disclosure nobody
    // asked this command for.
    const enrolment = await client.query(
      `SELECT
         (SELECT count(*) FROM consumer)::int AS consumers,
         (SELECT count(*) FROM installation)::int AS installations,
         (SELECT count(*) FROM installation WHERE suspended_at IS NOT NULL)::int
           AS suspended_installations,
         (SELECT count(*) FROM repository)::int AS repositories,
         (SELECT count(*) FROM repository WHERE archived_at IS NOT NULL)::int
           AS archived_repositories`,
    );

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

    // A succeeded plan-rollout that enqueued nothing is the single most
    // confusing state this pipeline produces: the job worked, and no pull
    // request exists. The reason is in `result` and nowhere else, so it is
    // read back rather than left for whoever thinks to look in the jsonb.
    const rollouts = await client.query(
      `SELECT finished_at, result
         FROM job
        WHERE workflow = 'plan-rollout' AND result IS NOT NULL
        ORDER BY finished_at DESC NULLS LAST
        LIMIT 3`,
    );

    const failures = await client.query(
      `SELECT workflow, attempts, last_error, finished_at
         FROM job
        WHERE status = 'failed'
        ORDER BY finished_at DESC NULLS LAST
        LIMIT 10`,
    );

    const enrolmentRow = enrolment.rows[0];

    return {
      enrolment: {
        consumers: Number(enrolmentRow?.consumers ?? 0),
        installations: Number(enrolmentRow?.installations ?? 0),
        suspendedInstallations: Number(enrolmentRow?.suspended_installations ?? 0),
        repositories: Number(enrolmentRow?.repositories ?? 0),
        archivedRepositories: Number(enrolmentRow?.archived_repositories ?? 0),
      },
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
      rollouts: rollouts.rows.map((r) => ({
        finishedAt: r.finished_at,
        kind: typeof r.result?.kind === "string" ? r.result.kind : "unknown",
        targeted: typeof r.result?.targeted === "number" ? r.result.targeted : null,
        enqueued: typeof r.result?.enqueued === "number" ? r.result.enqueued : null,
        skipped: Array.isArray(r.result?.skipped) ? r.result.skipped : [],
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

  const e = status.enrolment;
  out.push("Enrolment");
  if (e.repositories === 0) {
    // The state a rollout targeting nothing almost always turns out to be.
    // Enrolment rides on `installation.created`, which GitHub sends only at
    // install time — so an App installed before DEFAULT_PROVIDER_SLUG was set
    // never enrolled, and reinstalling is the only way to get that event again.
    out.push(
      "  no repositories — nothing to roll out to.",
      "  Enrolment happens on installation.created, which GitHub sends only at",
      "  install time. If the App was installed before DEFAULT_PROVIDER_SLUG was",
      "  set, reinstall it.",
    );
  } else {
    const suspended =
      e.suspendedInstallations > 0 ? `, ${e.suspendedInstallations} suspended` : "";
    const archived = e.archivedRepositories > 0 ? `, ${e.archivedRepositories} archived` : "";
    out.push(
      `  ${e.consumers} consumer(s), ${e.installations} installation(s)${suspended}, ` +
        `${e.repositories} repository(ies)${archived}`,
    );
  }

  out.push("", "Watched packages");
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

  if (status.rollouts.length > 0) {
    out.push("", "Rollouts");
    for (const r of status.rollouts) {
      const counts =
        r.targeted === null
          ? ""
          : `  targeted ${r.targeted}, enqueued ${r.enqueued ?? 0}`;
      out.push(`  ${r.kind}${counts}  (${ago(r.finishedAt)})`);
      if (r.kind === "planned" && r.targeted === 0 && r.skipped.length === 0) {
        // Distinguishes "no repositories at all" from "repositories, all
        // filtered". They read identically in a count and have different fixes.
        out.push("    no candidate repositories — see Enrolment above");
      }
      for (const skip of r.skipped.slice(0, 10)) {
        out.push(`    skipped ${skip.owner}/${skip.name}: ${skip.reason}`);
      }
      if (r.skipped.length > 10) {
        out.push(`    … and ${r.skipped.length - 10} more skipped`);
      }
    }
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
