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
    // No production extractor yet. Returning null costs a corroboration source
    // rather than inventing one — the gate then requires registry and artifact
    // to agree, at moderate confidence instead of high.
    surfaces: { surfaceFor: async () => null },
    recorder: {
      record: async (input) =>
        db.withTenant(input.providerId, async (client) => {
          const { rows } = await client.query<{ id: string }>(
            `INSERT INTO upstream_change
               (provider_id, change_key, ecosystem, package_name,
                from_version, to_version, summary, corroborations)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (provider_id, change_key) DO UPDATE
               SET corroborations = EXCLUDED.corroborations,
                   summary = EXCLUDED.summary
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

installSignalHandlers(worker, log);

await worker.finished;
await db.close();
log("worker exited");
