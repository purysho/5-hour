/**
 * Fan-out planning.
 *
 * The missing middle of the pipeline. `detect-changes` produces a corroborated
 * `upstream_change` and deliberately stops; `migrate-repository` acts on one
 * repository and expects to be told which. Nothing decided who to contact —
 * which is why `assessRepository`, `decideTarget` and `prioritise` were fully
 * implemented, fully tested, and imported by nothing.
 *
 * This is the workflow that turns one detected change into a bounded set of
 * migration jobs, and it is the most dangerous one in the system. Every other
 * workflow is scoped to a single repository and can fail alone. A bug here
 * multiplies: the whole point of this step is fan-out, so a mistake is not one
 * bad pull request but hundreds, opened simultaneously, under our name, on
 * repositories that never asked for them. That is unrecoverable reputationally
 * long before it is unrecoverable technically.
 *
 * So the shape is: refuse, narrow, order, then take a small prefix.
 *
 * ── The approval gate ────────────────────────────────────────────────────────
 *
 * `detect-changes` says it in its own header: detecting and acting in one step
 * would mean a detection bug becomes a fan-out incident with no gate between
 * them. This is that gate, and `approved_at` is the thing it reads.
 *
 * A change that no human has approved does not fan out — not "fans out to a
 * smaller canary", not "fans out with a warning". Approval is the only reason
 * this step is safe to automate at all, so it is checked before anything else
 * and its absence is a clean, non-retrying stop.
 *
 * ── Why eligibility is recomputed rather than trusted ────────────────────────
 *
 * The corroborations are re-read from the stored row and re-assessed here.
 * That looks redundant — `detect-changes` already found the change eligible or
 * it would not have been recorded. It is not redundant: the corroboration
 * policy is a tuning parameter, the row may have been written weeks earlier by
 * a different version of that policy, and this is the step that spends the
 * budget. Re-assessing means a tightened policy takes effect on the next
 * rollout rather than only on newly detected changes.
 *
 * ── Why a repository that cannot be read is skipped, not guessed at ─────────
 *
 * A manifest we cannot fetch, cannot parse, or that does not name the package
 * produces a skip with a recorded reason. The alternative — assuming the
 * dependency is present because the repository is in our table — opens a pull
 * request against a repository that does not use the package at all, which is
 * the single most credibility-destroying thing this system can do.
 */

import { PermanentFailure, type WorkflowContext } from "../workflow/types.ts";
import {
  assessEligibility,
  canarySize,
  type Corroboration,
  type Eligibility,
} from "../detect/corroborate.ts";
import {
  decideTarget,
  prioritise,
  type EligibilityRules,
  type Impact,
  type RepositoryCandidate,
  type TargetDecision,
} from "../discover/affected.ts";
import { lockedVersion, parseManifest } from "../discover/manifest.ts";
import type { TenantClient } from "../db/client.ts";

export interface RolloutInput extends Record<string, unknown> {
  readonly changeId: string;
}

/** The change, as stored by the detection sweep. */
export interface StoredChange {
  readonly changeKey: string;
  readonly ecosystem: string;
  readonly packageName: string;
  readonly fromVersion: string | null;
  readonly toVersion: string | null;
  readonly corroborations: readonly Corroboration[];
  /** Null until a human approves. The gate this workflow exists to enforce. */
  readonly approvedAt: string | null;
}

/**
 * A repository we may contact, before we know whether it uses the package.
 *
 * Membership in this list means only that the App is installed and we have a
 * row for it. Everything that decides whether it is a *target* comes from
 * reading its manifest.
 */
export interface CandidateRepository {
  readonly repositoryId: string;
  readonly installationId: string;
  /**
   * GitHub's numeric ids. Not used by the planning logic at all — carried
   * because `readManifest` has to mint a token to read anything, and ADR-0002
   * scopes a token by numeric repository id rather than by coordinates.
   */
  readonly forgeRepositoryId: number;
  readonly forgeInstallationId: number;
  readonly forgeOwner: string;
  readonly forgeName: string;
  readonly defaultBranch: string;
  readonly archived: boolean;
  readonly fork: boolean;
  readonly stars?: number;
}

/** What a repository declares, read at the commit we would migrate from. */
export interface RepositoryManifest {
  /** Head of the default branch. Becomes the migration's `baseSha`. */
  readonly headSha: string;
  readonly manifest: string;
  readonly lockfile?: { readonly filename: string; readonly content: string };
}

export interface RolloutDeps {
  readonly loadChange: (client: TenantClient, changeId: string) => Promise<StoredChange | null>;
  readonly candidates: (
    client: TenantClient,
    change: StoredChange,
  ) => Promise<readonly CandidateRepository[]>;
  /**
   * Reads a repository's manifest and lockfile.
   *
   * Returns why on failure rather than a bare null. Not reading a repository
   * costs it a candidacy; a fabricated manifest would cost a maintainer's
   * trust — but the two reasons a read fails are not the same fact. A
   * repository with no `package.json` is not an npm package and was never
   * going to be targeted, while one we could not authenticate to is a
   * misconfiguration on our side. Collapsing them reported an entire fleet as
   * unreadable when most of it was simply written in another language.
   */
  readonly readManifest: (
    repository: CandidateRepository,
    providerId: string,
  ) => Promise<RepositoryManifest | { readonly unreadable: string }>;
  /**
   * Enqueues one migration. Must be idempotent on the dedupe key — this
   * workflow's step boundary can replay, and a duplicate here is a duplicate
   * pull request.
   */
  readonly enqueueMigration: (input: {
    providerId: string;
    repositoryId: string;
    installationId: string;
    changeId: string;
    baseSha: string;
    /**
     * How this repository is affected, as classified here against the manifest
     * at `baseSha`.
     *
     * Carried into the job rather than recomputed by the migration, and that
     * is deliberate. It is the sentence the pull request opens with — "your
     * declared range excludes this version" versus "your next install will
     * pick it up" — so two independent derivations of it are two chances to
     * tell a maintainer something untrue about their own repository. This one
     * was computed from the manifest at the commit the migration is pinned to,
     * which is the only reading that matches the diff.
     */
    impact: Impact;
    dedupeKey: string;
  }) => Promise<{ created: boolean }>;
  readonly withTenant: <T>(
    providerId: string,
    fn: (client: TenantClient) => Promise<T>,
  ) => Promise<T>;
  readonly rules?: EligibilityRules;
  /** Ceiling on repositories inspected in one rollout. */
  readonly maxCandidates?: number;
}

export interface SkippedRepository {
  readonly owner: string;
  readonly name: string;
  readonly reason: string;
}

export type RolloutOutcome =
  | { readonly kind: "not-approved"; readonly changeKey: string }
  | { readonly kind: "not-eligible"; readonly reason: string; readonly detail: string }
  | {
      readonly kind: "planned";
      readonly changeKey: string;
      readonly confidence: "high" | "moderate";
      /** Repositories that declare the package and pass the eligibility rules. */
      readonly targeted: number;
      readonly canarySize: number;
      readonly enqueued: number;
      /** Already queued by a previous run. Not an error (ADR-0004). */
      readonly duplicates: number;
      readonly skipped: readonly SkippedRepository[];
    };

const DEFAULT_MAX_CANDIDATES = 500;

export function planRolloutWorkflow(deps: RolloutDeps) {
  return async function planRollout(
    ctx: WorkflowContext,
    rawInput: Record<string, unknown>,
  ): Promise<RolloutOutcome> {
    const input = rawInput as RolloutInput;
    const maxCandidates = deps.maxCandidates ?? DEFAULT_MAX_CANDIDATES;

    // ── 1. The change, and the two gates on it ──────────────────────────────
    const change = await ctx.step("load-change", async () =>
      deps.withTenant(ctx.providerId, (client) => deps.loadChange(client, input.changeId)),
    );

    if (!change) {
      // A rollout for a change that does not exist is a bug in whoever
      // enqueued it, and no amount of retrying will conjure the row.
      throw new PermanentFailure(`Change ${input.changeId} not found`);
    }

    if (change.approvedAt === null) {
      // The gate. Not retryable and not an error: it is the system working.
      // A human will approve it or they will not, and either way the answer
      // does not arrive by trying again.
      ctx.log("rollout.not_approved", { changeKey: change.changeKey });
      return { kind: "not-approved", changeKey: change.changeKey };
    }

    // Re-assessed rather than trusted — see the header. The stored row may
    // predate the current corroboration policy.
    const eligibility: Eligibility = assessEligibility({
      changeKey: change.changeKey,
      ecosystem: change.ecosystem,
      packageName: change.packageName,
      fromVersion: change.fromVersion,
      toVersion: change.toVersion,
      corroborations: change.corroborations,
    });

    if (!eligibility.eligible) {
      ctx.log("rollout.not_eligible", { changeKey: change.changeKey, reason: eligibility.reason });
      return { kind: "not-eligible", reason: eligibility.reason, detail: eligibility.detail };
    }

    // Versions are needed to assess a declared range against the change. A
    // change recorded without them cannot be assessed at all, and guessing
    // would produce a confident wrong impact for every repository at once.
    if (!change.fromVersion || !change.toVersion) {
      throw new PermanentFailure(
        `Change ${change.changeKey} has no version pair; cannot assess downstream impact`,
      );
    }

    // ── 2. Candidates ───────────────────────────────────────────────────────
    const candidates = await ctx.step("list-candidates", async () =>
      deps.withTenant(ctx.providerId, (client) => deps.candidates(client, change)),
    );

    if (candidates.length > maxCandidates) {
      // A ceiling rather than a slice: silently rolling out to the first 500
      // of 5000 looks like success and is not. Whoever widened the candidate
      // set should decide what to do about it.
      throw new PermanentFailure(
        `${candidates.length} candidate repositories exceeds the ${maxCandidates} ceiling ` +
          `for a single rollout`,
      );
    }

    // ── 3. Assess each ──────────────────────────────────────────────────────
    //
    // One step for the whole assessment rather than one per repository: these
    // are reads, they are individually cheap, and a step per repository would
    // write hundreds of step rows for a single rollout.
    const assessed = await ctx.step("assess-candidates", async () => {
      const targets: { decision: TargetDecision; repository: CandidateRepository; baseSha: string }[] =
        [];
      const skipped: SkippedRepository[] = [];

      for (const repository of candidates) {
        const manifest = await deps.readManifest(repository, ctx.providerId);
        if ("unreadable" in manifest) {
          skipped.push({
            owner: repository.forgeOwner,
            name: repository.forgeName,
            reason: manifest.unreadable,
          });
          continue;
        }

        let parsed;
        try {
          parsed = parseManifest(manifest.manifest);
        } catch (error) {
          // Attacker-authored input (threat-model §5.1). One repository's
          // malformed manifest must not end the rollout for everyone else.
          skipped.push({
            owner: repository.forgeOwner,
            name: repository.forgeName,
            reason: `manifest unparseable: ${(error as Error).message}`,
          });
          continue;
        }

        const resolved = manifest.lockfile
          ? lockedVersion(manifest.lockfile, change.packageName)
          : null;

        const candidate: RepositoryCandidate = {
          forge: "github",
          owner: repository.forgeOwner,
          name: repository.forgeName,
          defaultBranch: repository.defaultBranch,
          dependencies: parsed.dependencies,
          archived: repository.archived,
          fork: repository.fork,
          ...(resolved !== null && { lockedVersion: resolved }),
          ...(repository.stars !== undefined && { stars: repository.stars }),
        };

        const decision = decideTarget(
          candidate,
          {
            packageName: change.packageName,
            fromVersion: change.fromVersion as string,
            toVersion: change.toVersion as string,
          },
          deps.rules ?? {},
        );

        if (!decision.targeted) {
          skipped.push({
            owner: repository.forgeOwner,
            name: repository.forgeName,
            reason: decision.skipReason ?? "not targeted",
          });
          continue;
        }

        targets.push({ decision, repository, baseSha: manifest.headSha });
      }

      return { targets, skipped };
    });

    // ── 4. Order, then take the canary ──────────────────────────────────────
    //
    // `prioritise` puts exposed repositories first and, within a class, the
    // smallest first: the canary should carry the cheapest failures. Sending
    // the first wave to the most-watched repositories in the ecosystem is
    // exactly backwards.
    const ordered = prioritise(assessed.targets.map((entry) => entry.decision));
    const bySlug = new Map(
      assessed.targets.map((entry) => [
        `${entry.repository.forgeOwner}/${entry.repository.forgeName}`,
        entry,
      ]),
    );

    const size = canarySize(eligibility, ordered.length);
    const wave = ordered
      .slice(0, size)
      .map((decision) => bySlug.get(`${decision.repository.owner}/${decision.repository.name}`))
      .filter((entry): entry is NonNullable<typeof entry> => entry !== undefined);

    // ── 5. Enqueue ──────────────────────────────────────────────────────────
    //
    // The dedupe key pins a migration to (change, repository, base). Replaying
    // this step — or re-running the rollout after an approval is re-confirmed
    // — must not produce a second pull request for work already queued.
    const enqueued = await ctx.step("enqueue-migrations", async () => {
      let created = 0;
      let duplicates = 0;
      for (const entry of wave) {
        const result = await deps.enqueueMigration({
          providerId: ctx.providerId,
          repositoryId: entry.repository.repositoryId,
          installationId: entry.repository.installationId,
          changeId: input.changeId,
          baseSha: entry.baseSha,
          impact: entry.decision.assessment.impact,
          dedupeKey: `migrate:${input.changeId}:${entry.repository.repositoryId}:${entry.baseSha}`,
        });
        if (result.created) created += 1;
        else duplicates += 1;
      }
      return { created, duplicates };
    });

    ctx.log("rollout.planned", {
      changeKey: change.changeKey,
      targeted: ordered.length,
      canarySize: size,
      enqueued: enqueued.created,
      skipped: assessed.skipped.length,
    });

    return {
      kind: "planned",
      changeKey: change.changeKey,
      confidence: eligibility.confidence,
      targeted: ordered.length,
      canarySize: size,
      enqueued: enqueued.created,
      duplicates: enqueued.duplicates,
      skipped: assessed.skipped,
    };
  };
}
