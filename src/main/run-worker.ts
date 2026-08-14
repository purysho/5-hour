/**
 * Worker entry point.
 *
 * Registers the workflows that have production implementations and refuses to
 * start otherwise.
 *
 * ── On refusing to start ─────────────────────────────────────────────────────
 *
 * `migrate-repository` composes a model that proposes migrations and a forge
 * client that opens pull requests. The first now has a production
 * implementation (`ClaudeMigrationAgent`, ADR-0013); the second does not, and
 * neither does the sandbox that would make running a repository's test suite
 * safe (see docs/HANDOFF.md). The tempting shape is to register the workflow
 * with stubs so the process boots and "works" until it reaches one — which
 * means a worker that dequeues real jobs, burns their retry budget, and fails
 * them for reasons that have nothing to do with the job.
 *
 * Refusing to register an incomplete workflow means those jobs stay queued
 * until a worker that can actually run them exists. Queued is a recoverable
 * state; failed-and-retried-to-death is not.
 */

import { loadConfig, Secret } from "../config.ts";
import { Database } from "../db/client.ts";
import { Queue } from "../workflow/queue.ts";
import { installSignalHandlers, startWorker } from "./worker.ts";
import { detectChangesWorkflow } from "../workflows/detect-changes.ts";
import { NpmCollector } from "../detect/npm.ts";
import { NpmSurfaceSource } from "../detect/npm-surface-source.ts";
import { PostgresSweepStore, SweepScheduler } from "../schedule/sweep-scheduler.ts";

const config = loadConfig();

function log(message: string, fields: Record<string, unknown> = {}): void {
  console.log(JSON.stringify({ level: "info", message, ...fields }));
}

const db = new Database({
  connectionString: Secret.reveal(config.databaseUrl),
  platformConnectionString: Secret.reveal(config.platformDatabaseUrl),
});

const workerId = `${process.env["HOSTNAME"] ?? "worker"}-${process.pid}`;

const queue = new Queue(db, { workerId });

// ── detect-changes ──────────────────────────────────────────────────────────
//
// Fully implemented. Its only external dependencies are HTTP fetches of public
// registry data and a surface source; there is no model and no write path, so
// it is safe to run today.

queue.register({
  name: "detect-changes",
  handler: detectChangesWorkflow({
    collector: new NpmCollector({
      async get(url, headers) {
        const response = await fetch(url, { headers });
        return { status: response.status, body: await response.text() };
      },
    }),
    // The third corroboration source, and the only one that speaks to whether
    // consumers will actually break. It fails to null on every error, which
    // costs a corroboration rather than failing the sweep — one publisher's
    // malformed tarball must not become an outage of ours.
    surfaces: new NpmSurfaceSource(
      new NpmCollector({
        async get(url, headers) {
          const response = await fetch(url, { headers });
          return { status: response.status, body: await response.text() };
        },
      }),
      {
        async get(url, headers) {
          const response = await fetch(url, { headers });
          return { status: response.status, body: Buffer.from(await response.arrayBuffer()) };
        },
      },
      { log },
    ),
    recorder: {
      // `impacted_symbols` is not optional detail. The migration blast radius
      // is derived from it before any inference runs (ADR-0013), so dropping
      // it here would make every downstream migration refuse itself for a
      // reason that reads like "nothing references this package".
      //
      // `approved_at` is preserved on conflict rather than overwritten: a
      // re-sweep must not silently revoke a human's approval, and must not
      // grant one either.
      record: async (input) =>
        db.withTenant(input.providerId, async (client) => {
          const { rows } = await client.query<{ id: string }>(
            `INSERT INTO upstream_change
               (provider_id, change_key, ecosystem, package_name,
                from_version, to_version, summary, corroborations,
                impacted_symbols, approved_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (provider_id, change_key) DO UPDATE
               SET corroborations = EXCLUDED.corroborations,
                   summary = EXCLUDED.summary,
                   impacted_symbols = EXCLUDED.impacted_symbols
             RETURNING id`,
            [
              input.providerId,
              input.changeKey,
              input.ecosystem,
              input.packageName,
              input.fromVersion,
              input.toVersion,
              input.summary,
              JSON.stringify(input.corroborations),
              input.impactedSymbols,
              input.approvedAt,
            ],
          );
          return rows[0]!.id;
        }),
    },
    downstreamCount: async () => 0,
  }) as never,
  maxAttempts: 3,
});

// ── migrate-repository ──────────────────────────────────────────────────────
//
// Deliberately NOT registered. See the file comment: registering it with stubs
// would mean dequeuing real jobs and failing them for reasons unrelated to the
// job itself.
//
// The blockers are logged individually rather than as one flag, so an operator
// can see which of them they have cleared.

const migrationBlockers = [
  ...(config.anthropic.apiKey ? [] : ["ANTHROPIC_API_KEY is not set"]),
  "no ForgeClient implementation",
  "no sandbox for test verification (ADR-0006)",
];

log("worker starting", {
  workerId,
  env: config.env,
  workflows: ["detect-changes"],
  unregistered: [`migrate-repository (${migrationBlockers.join("; ")})`],
});

const worker = startWorker(queue, {
  concurrency: config.worker.concurrency,
  pollIntervalMs: config.worker.pollIntervalMs,
  shutdownGraceMs: config.worker.shutdownGraceMs,
  log,
});

// ── Scheduler ───────────────────────────────────────────────────────────────
//
// Enqueues `detect-changes` for packages whose sweep is due. Safe to run in
// every worker: the claim happens in the database, so N schedulers produce one
// sweep per package per interval rather than N (migration 007).
const scheduler = new SweepScheduler({
  store: new PostgresSweepStore(db),
  queue,
  log: (event, detail) => log(event, detail),
}).start(config.worker.schedulerIntervalMs);

installSignalHandlers(worker, log);

await worker.finished;
// After the worker, so a tick in flight when SIGTERM arrived finishes its
// enqueues rather than losing them.
await scheduler.stop();
await db.close();
log("worker exited");
