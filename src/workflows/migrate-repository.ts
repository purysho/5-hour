import type { TenantClient } from "../db/client.ts";
import type { AuditSink, GitHubApp } from "../github/app.ts";
import { ScopedToken } from "../github/token.ts";
import {
  authoriseOutboundWrite,
  recordOutboundResult,
} from "../outbound/guard.ts";
import { evaluateDiff, type PolicyContext, type PolicyDecision } from "../policy/diff-policy.ts";
import { PermanentFailure, type WorkflowContext } from "../workflow/types.ts";
import {
  composePullRequest,
  type ChangeSummary,
  type TestOutcome,
} from "../forge/pull-request.ts";
import { parseUnifiedDiff } from "../policy/diff.ts";
import { issueOptOutToken, recordOptOutToken } from "../outbound/suppression.ts";
import type { Impact } from "../discover/affected.ts";
import type { UntrustedContent } from "../agent/untrusted.ts";

/**
 * The migration workflow — the pipeline every other component exists to serve.
 *
 * ── One constraint worth stating loudly ─────────────────────────────────────
 *
 * **Neither a credential nor repository content may be a step result.**
 *
 * Step results are persisted so they can be replayed (ADR-0009), and both of
 * these are things we have promised not to persist:
 *
 *   A token in `job_step` is a live credential sitting in our database —
 *   precisely the standing privilege ADR-0002 exists to eliminate. Replaying
 *   one would also hand back a token that expired minutes ago.
 *
 *   Repository content in `job_step` breaks threat-model §7: source code is
 *   processed, never durably stored. Worse, it would come back from the
 *   database as a plain string with its untrusted marking gone — turning the
 *   replay path into an injection vector that layer 1 no longer guards.
 *
 * So both are acquired *inside* the step that consumes them, and each step
 * returns only its non-secret, non-untrusted outcome. On replay the step does
 * not run at all; on a genuine retry, a fresh token is minted and the sources
 * are re-read.
 *
 * Both types enforce this at runtime rather than trusting the convention:
 * `ScopedToken.toJSON` redacts and `UntrustedContent.toJSON` throws, so
 * returning either from a step fails immediately and loudly. That is how this
 * constraint was found — the type refused to be persisted before anyone
 * noticed the design was wrong.
 */

export interface MigrationInput extends Record<string, unknown> {
  readonly repositoryId: string;
  readonly installationId: string;
  readonly changeId: string;
  readonly baseSha: string;
}

export interface RepositoryContext {
  readonly forgeOwner: string;
  readonly forgeName: string;
  readonly forgeRepositoryId: number;
  readonly forgeInstallationId: number;
  readonly defaultBranch: string;
  readonly knownHosts: readonly string[];
}

/** Produces a migration diff. Injected so the workflow is testable and so the
 *  model provider is not baked into the pipeline. */
export interface MigrationAgent {
  generate(request: {
    repository: RepositoryContext;
    /** Repository content, already wrapped. Never interpolated (ADR-0003). */
    sources: readonly { path: string; content: UntrustedContent }[];
    changeSummary: string;
    /**
     * Symbols the upstream change impacted. The agent derives the blast radius
     * from these, deterministically and before any inference — which is what
     * keeps the radius it returns from being a description of its own
     * footprint (ADR-0013).
     */
    impactedSymbols: readonly string[];
  }): Promise<{
    diff: string;
    /**
     * The files the migration was permitted to touch. Computed from the
     * upstream change before generation, never from the generated diff.
     */
    blastRadius: readonly string[];
    summary: string;
    /**
     * How the migration was validated. The agent runs the repository's own
     * suite inside the sandbox, so it is the only component that knows.
     *
     * Reported honestly, including failure — a migration presented as verified
     * when it is not destroys the only thing that makes these pull requests
     * worth opening.
     */
    verification: {
      tests: TestOutcome;
      command: string | null;
      durationSeconds?: number;
    };
  }>;
}

export interface ForgeClient {
  openPullRequest(request: {
    token: ScopedToken;
    owner: string;
    name: string;
    baseSha: string;
    branch: string;
    title: string;
    body: string;
    diff: string;
  }): Promise<{ number: number; url: string }>;
}

export interface MigrationDeps {
  readonly app: GitHubApp;
  readonly agent: MigrationAgent;
  readonly forge: ForgeClient;
  readonly audit: AuditSink;
  /**
   * Loads tenant-scoped metadata. Runs under RLS.
   *
   * Returns nothing secret and nothing untrusted, because its result is
   * persisted as a step result. Repository content is loaded separately by
   * `loadSources`, inside the step that consumes it.
   */
  readonly loadContext: (
    client: TenantClient,
    input: MigrationInput,
  ) => Promise<{
    repository: RepositoryContext;
    changeSummary: string;
    /** Structured change facts for the pull request body. */
    change: ChangeSummary;
    changeKey: string;
    impact: Impact;
    /** Release link. Allowlisted by host before it reaches the body. */
    upstreamUrl?: string;
  }>;
  /**
   * Reads repository content. Called inside the generation step and never
   * across a step boundary — see the note at the top of this file.
   */
  readonly loadSources: (
    input: MigrationInput,
    repository: RepositoryContext,
  ) => Promise<readonly { path: string; content: UntrustedContent }[]>;
  /** Tenant-scoped client factory for steps that touch the database. */
  readonly withTenant: <T>(
    providerId: string,
    fn: (client: TenantClient) => Promise<T>,
  ) => Promise<T>;
  /** Builds the public opt-out URL from a minted token. From config. */
  readonly optOutUrl: (token: string) => string;
}

export type MigrationOutcome =
  | { status: "opened"; prNumber: number; prUrl: string }
  | { status: "skipped"; reason: string }
  | { status: "escalated"; findings: PolicyDecision["findings"] };

export function migrateRepositoryWorkflow(deps: MigrationDeps) {
  return async function migrateRepository(
    ctx: WorkflowContext,
    rawInput: Record<string, unknown>,
  ): Promise<MigrationOutcome> {
    const input = rawInput as unknown as MigrationInput;

    // ── 1. Load tenant context ──────────────────────────────────────────────
    //
    // Before authorisation, because the suppression check needs the forge
    // coordinates to consult the opt-out list. This is a single tenant-scoped
    // read; the expensive thing this workflow guards against spending is model
    // inference, which still happens after the claim.
    const loaded = await ctx.step("load-context", async () =>
      deps.withTenant(ctx.providerId, (client) => deps.loadContext(client, input)),
    );

    // ── 2. Authorise before doing any real work ─────────────────────────────
    // Kill switch, suppression, rate ceilings, then the idempotency claim
    // (ADR-0004). Deliberately ahead of generation: spending model inference
    // on a write that will not happen is waste, and claiming the write before
    // generating means a crash mid-generation still holds the claim, so a
    // retry resumes rather than duplicating.
    const authorisation = await ctx.step("authorise-write", async () =>
      deps.withTenant(ctx.providerId, async (client) => {
        const decision = await authoriseOutboundWrite(client, {
          providerId: ctx.providerId,
          installationId: input.installationId,
          repositoryId: input.repositoryId,
          changeId: input.changeId,
          baseSha: input.baseSha,
          target: {
            forge: "github",
            owner: loaded.repository.forgeOwner,
            name: loaded.repository.forgeName,
          },
        });
        return decision;
      }),
    );

    if (!authorisation.allowed) {
      if (authorisation.reason === "already-written") {
        // Not a failure. Another attempt, or a previous run, already did this.
        return {
          status: "skipped",
          reason: `already written as PR ${authorisation.prNumber ?? "(pending)"}`,
        };
      }
      if (authorisation.reason === "suppressed") {
        // Someone told us to stop. That is not a transient condition and
        // retrying it would burn the retry budget re-deciding a settled
        // question — and, worse, treat an explicit refusal as a temporary
        // obstacle.
        return { status: "skipped", reason: authorisation.detail };
      }
      // Kill switch and rate limits are transient by nature — the job should
      // come back, so this is a retryable error rather than a permanent one.
      throw new Error(`outbound write refused: ${authorisation.detail}`);
    }

    const writeId = authorisation.writeId;

    // ── 3. Generate the migration ───────────────────────────────────────────
    //
    // Sources are read INSIDE this step and never cross its boundary. The
    // agent sees them only through wrapped data channels; the step returns
    // the diff, which is Driftless-derived output rather than raw repository
    // content.
    const generated = await ctx.step("generate-migration", async () => {
      const sources = await deps.loadSources(input, loaded.repository);
      return deps.agent.generate({
        repository: loaded.repository,
        sources,
        changeSummary: loaded.changeSummary,
        // From our own change record, not from the agent. The blast radius the
        // policy engine enforces below is derived from these, so letting the
        // agent supply them would let a generated migration choose the bound
        // it is then judged against.
        impactedSymbols: loaded.change.impactedSymbols,
      });
    });

    // ── 4. Policy ───────────────────────────────────────────────────────────
    // Deterministic, no inference. Runs on every diff regardless of how
    // confident the generator was (ADR-0003 layer 3).
    const policyContext: PolicyContext = {
      blastRadius: generated.blastRadius,
      knownHosts: loaded.repository.knownHosts,
    };
    const decision = await ctx.step("evaluate-policy", async () =>
      evaluateDiff(generated.diff, policyContext),
    );

    if (decision.verdict === "reject") {
      await ctx.step("record-rejection", async () =>
        deps.withTenant(ctx.providerId, (client) =>
          recordOutboundResult(client, writeId, {
            status: "failed",
            error: `policy rejected: ${decision.findings.map((f) => f.rule).join(", ")}`,
          }),
        ),
      );
      // Terminal. A rejected diff will be rejected identically on retry, and
      // retrying burns rate limit that legitimate work needs.
      throw new PermanentFailure(
        `Diff rejected by policy: ${decision.findings.map((f) => f.detail).join("; ")}`,
      );
    }

    if (decision.verdict === "escalate") {
      await ctx.step("record-escalation", async () =>
        deps.withTenant(ctx.providerId, (client) =>
          recordOutboundResult(client, writeId, {
            status: "failed",
            error: `escalated for human review: ${decision.findings.map((f) => f.rule).join(", ")}`,
          }),
        ),
      );
      return { status: "escalated", findings: decision.findings };
    }

    // ── 5. Mint the opt-out token ───────────────────────────────────────────
    //
    // BEFORE the pull request, not after. The body contains the link, so a
    // token recorded afterwards would leave a window in which we published a
    // link that does not work — and the maintainer most likely to click it is
    // the one who clicks immediately.
    //
    // The token IS a step result, which looks like a violation of the rule
    // that credentials must not cross a step boundary. It is not: this value
    // is about to be printed in a public pull request body, its only
    // capability is to stop us contacting that repository, and it must survive
    // replay so the link in an already-opened pull request keeps working. A
    // fresh token per attempt would silently break the link in the body.
    const optOutToken = await ctx.step("mint-opt-out-token", async () => {
      const issued = issueOptOutToken();
      await deps.withTenant(ctx.providerId, (client) =>
        recordOptOutToken(client, ctx.providerId, issued.hash, {
          forge: "github",
          owner: loaded.repository.forgeOwner,
          name: loaded.repository.forgeName,
        }),
      );
      return issued.token;
    });

    // ── 6. Open the pull request ────────────────────────────────────────────
    //
    // The token is minted INSIDE this step and never leaves it. See the note
    // at the top of this file: a credential must never be a step result.
    const opened = await ctx.step("open-pr", async () => {
      const token = await deps.app.mintInstallationToken(
        {
          installationId: input.installationId,
          forgeInstallationId: loaded.repository.forgeInstallationId,
          repositoryId: input.repositoryId,
          forgeRepositoryId: loaded.repository.forgeRepositoryId,
        },
        deps.audit,
      );

      // Composed from structured facts only. There is no parameter a
      // changelog could travel through, so upstream prose cannot be laundered
      // through a body a maintainer trusts (see src/forge/pull-request.ts).
      const composed = composePullRequest({
        change: loaded.change,
        impact: loaded.impact,
        verification: {
          tests: generated.verification.tests,
          command: generated.verification.command,
          ...(generated.verification.durationSeconds !== undefined && {
            durationSeconds: generated.verification.durationSeconds,
          }),
          policyVerdict: decision.verdict,
        },
        filesChanged: parseUnifiedDiff(generated.diff).files.length,
        changeKey: loaded.changeKey,
        optOutUrl: deps.optOutUrl(optOutToken),
        ...(loaded.upstreamUrl !== undefined && { upstreamUrl: loaded.upstreamUrl }),
      });

      const result = await deps.forge.openPullRequest({
        token,
        owner: loaded.repository.forgeOwner,
        name: loaded.repository.forgeName,
        baseSha: input.baseSha,
        branch: `driftless/${input.changeId.slice(0, 8)}`,
        title: composed.title,
        body: composed.body,
        diff: generated.diff,
      });

      // Only the non-secret outcome crosses the step boundary.
      return { number: result.number, url: result.url };
    });

    // ── 7. Record the result ────────────────────────────────────────────────
    await ctx.step("record-result", async () =>
      deps.withTenant(ctx.providerId, (client) =>
        recordOutboundResult(client, writeId, {
          status: "succeeded",
          prNumber: opened.number,
          prUrl: opened.url,
        }),
      ),
    );

    ctx.log("migration.opened", { prNumber: opened.number });
    return { status: "opened", prNumber: opened.number, prUrl: opened.url };
  };
}

/**
 * Pull request body.
 *
 * Both inputs are Driftless-authored — the agent's summary and our own change
 * record. Repository content is never echoed here: a body assembled from
 * untrusted text would carry an injection straight to a human reviewer, which
 * is the one place in the pipeline where persuasion still works.
 */
