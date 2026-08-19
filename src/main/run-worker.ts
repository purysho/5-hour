/**
 * Worker entry point.
 *
 * Registers the workflows that have production implementations and refuses to
 * start the ones that do not.
 *
 * ── On refusing to register ──────────────────────────────────────────────────
 *
 * The tempting shape is to register everything with stubs so the process boots
 * and "works" until it reaches one — which means a worker that dequeues real
 * jobs, burns their retry budget, and fails them for reasons that have nothing
 * to do with the job. Queued is a recoverable state; failed-and-retried-to-death
 * is not.
 *
 * `migrate-repository` is registered now that a forge client, a content reader
 * and an audit sink exist. It still runs without verification, and that is not
 * a stub: the verifier reports `tests: not-run`, the pull request body says so
 * in as many words, and the policy engine judges the diff either way. A
 * migration presented as verified when it is not would be the dishonest
 * version; saying we did not run them is the honest one.
 *
 * Verification is implemented (src/sandbox/) but not provisioned here: it needs
 * `runsc` and a rootfs on the host, and a checkout source to clone with. The
 * verifier is constructed without them deliberately, so it reports which are
 * missing per migration rather than this process claiming a capability the
 * host does not have. See docs/SANDBOX_SETUP.md.
 *
 * The one thing it will not run without is a model. Without `ANTHROPIC_API_KEY`
 * there is nothing to generate a migration with, so the workflow stays
 * unregistered and its jobs stay queued for a worker that has one.
 */

import Anthropic from "@anthropic-ai/sdk";
import { loadConfig, Secret } from "../config.ts";
import { Database } from "../db/client.ts";
import { Queue } from "../workflow/queue.ts";
import { installSignalHandlers, startWorker } from "./worker.ts";
import { detectChangesWorkflow } from "../workflows/detect-changes.ts";
import { migrateRepositoryWorkflow } from "../workflows/migrate-repository.ts";
import { planRolloutWorkflow } from "../workflows/plan-rollout.ts";
import { NpmCollector } from "../detect/npm.ts";
import { NpmSurfaceSource } from "../detect/npm-surface-source.ts";
import { PostgresSweepStore, SweepScheduler } from "../schedule/sweep-scheduler.ts";
import { ApprovalTrigger, PostgresApprovalStore } from "../schedule/approval-trigger.ts";
import { GitHubApp } from "../github/app.ts";
import { FileSigner, KmsSigner, type KmsClient } from "../github/signer.ts";
import { AwsKmsClient } from "../github/kms-signer.ts";
import { GitHubForgeClient, type ForgeHttpClient } from "../forge/github-forge.ts";
import { GitHubContentClient } from "../forge/github-contents.ts";
import {
  AnthropicModelClient,
  ClaudeMigrationAgent,
} from "../agent/claude-migration-agent.ts";
import { GVisorVerifier } from "../sandbox/gvisor-verifier.ts";
import { auditFor, createMigrationDeps, createRolloutDeps, installedRepositoryCount } from "./wiring.ts";

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

// ── HTTP ────────────────────────────────────────────────────────────────────
//
// One client shape for every GitHub call, injected rather than imported by the
// modules that use it. Credential-handling code does not inherit an SDK's
// error messages, which are a common route for a token to reach a log.

const forgeHttp: ForgeHttpClient = {
  async request(method, url, body, headers) {
    const response = await fetch(url, {
      method,
      headers: { ...headers, ...(body !== undefined && { "content-type": "application/json" }) },
      ...(body !== undefined && { body: JSON.stringify(body) }),
    });
    return { status: response.status, body: await response.text() };
  },
};

// ── detect-changes ──────────────────────────────────────────────────────────
//
// Fully implemented. Its only external dependencies are HTTP fetches of public
// registry data and a surface source; there is no model and no write path, so
// it is safe to run today.

const registryCollector = () =>
  new NpmCollector({
    async get(url, headers) {
      const response = await fetch(url, { headers });
      return { status: response.status, body: await response.text() };
    },
  });

queue.register({
  name: "detect-changes",
  handler: detectChangesWorkflow({
    collector: registryCollector(),
    // The third corroboration source, and the only one that speaks to whether
    // consumers will actually break. It fails to null on every error, which
    // costs a corroboration rather than failing the sweep — one publisher's
    // malformed tarball must not become an outage of ours.
    surfaces: new NpmSurfaceSource(
      registryCollector(),
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
    // Was a hardcoded 0, which made the reported canary size fiction. It is
    // now the tenant's live repository count — an upper bound on how many
    // repositories a change could reach, and used only where an upper bound is
    // safe (see the note in wiring.ts).
    downstreamCount: installedRepositoryCount(db),
  }) as never,
  maxAttempts: 3,
});

// ── GitHub App ──────────────────────────────────────────────────────────────

const signer =
  config.github.signing.kind === "kms"
    ? new KmsSigner(kmsClient(), config.github.signing.keyId)
    : new FileSigner(config.github.signing.path);

const app = new GitHubApp({
  appId: config.github.appId,
  signer,
  http: {
    async post(url, body, headers) {
      return forgeHttp.request("POST", url, body, headers);
    },
  },
});

const contents = new GitHubContentClient({ http: forgeHttp, log });
const forge = new GitHubForgeClient({ http: forgeHttp });

// ── plan-rollout ────────────────────────────────────────────────────────────
//
// The fan-out gate. Safe to register without a model: it reads manifests and
// enqueues, and it will not enqueue anything for a change no human approved.

queue.register({
  name: "plan-rollout",
  handler: planRolloutWorkflow(createRolloutDeps({ db, app, contents, log })) as never,
  // Deliberately fewer attempts than the default. A rollout that keeps failing
  // is not a transient problem worth grinding at — it is planning a wave of
  // writes into other people's repositories, and the right response to
  // repeated failure there is to stop and be looked at.
  maxAttempts: 3,
});

// ── migrate-repository ──────────────────────────────────────────────────────

const workflows = ["detect-changes", "plan-rollout"];

if (config.anthropic.apiKey) {
  const agent = new ClaudeMigrationAgent({
    model: new AnthropicModelClient({
      client: new Anthropic({ apiKey: Secret.reveal(config.anthropic.apiKey) }),
    }),
    verifier: new GVisorVerifier({ log }),
    log,
  });

  queue.register({
    name: "migrate-repository",
    // Dependencies are built per job rather than once at startup, because the
    // audit sink is bound to a tenant's hash chain and the tenant is only
    // known here. A sink constructed at startup would have to be handed a
    // provider id from somewhere, and the somewhere would eventually be wrong.
    handler: (ctx, input) =>
      migrateRepositoryWorkflow(
        createMigrationDeps({
          db,
          app,
          contents,
          agent,
          forge,
          log,
          audit: auditFor(db, ctx.providerId),
          optOutUrl: (token) => `${config.http.publicOrigin}/opt-out/${token}`,
        }),
      )(ctx, input),
    maxAttempts: 3,
  });

  workflows.push("migrate-repository");
}

log("worker starting", {
  workerId,
  env: config.env,
  workflows,
  ...(config.anthropic.apiKey
    ? {}
    : { unregistered: ["migrate-repository (ANTHROPIC_API_KEY is not set)"] }),
  // Stated on every boot rather than buried in a document. Anyone reading the
  // logs of a running worker should know that the pull requests it opens were
  // not test-verified (ADR-0006).
  verification:
    "sandbox implemented but not provisioned on this host (needs runsc, a " +
    "rootfs and a checkout source); migrations report tests as not-run",
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

// ── Approval trigger ────────────────────────────────────────────────────────
//
// Watches `approved_at` and enqueues `plan-rollout`. Without it, approval is a
// column nobody reads: a human approves a change and nothing happens, because
// nothing else in the system enqueues that workflow.
//
// Safe in every worker for the same reason as the scheduler, by a different
// mechanism: the dedupe key `rollout:<change id>` is unique across every job
// status, so N triggers produce one rollout per approval rather than N.
const approvals = new ApprovalTrigger({
  store: new PostgresApprovalStore(db),
  queue,
  log: (event, detail) => log(event, detail),
}).start(config.worker.schedulerIntervalMs);

installSignalHandlers(worker, log);

await worker.finished;
// After the worker, so a tick in flight when SIGTERM arrived finishes its
// enqueues rather than losing them.
await scheduler.stop();
await approvals.stop();
await db.close();
log("worker exited");

/**
 * The KMS client.
 *
 * Uses AWS KMS to sign GitHub App JWTs. The private key never enters the
 * application process; only the ability to request signatures is granted
 * (ADR-0002 §2). Credentials are loaded from the default AWS SDK chain:
 * environment variables, ~/.aws/credentials, or EC2 IAM instance role.
 *
 * IAM policy required:
 *   {
 *     "Effect": "Allow",
 *     "Action": ["kms:Sign"],
 *     "Resource": "arn:aws:kms:region:account:key/key-id"
 *   }
 */
function kmsClient(): KmsClient {
  return new AwsKmsClient();
}
