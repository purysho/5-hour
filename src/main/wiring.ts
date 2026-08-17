/**
 * Production dependencies for the workflows.
 *
 * Every workflow in this system takes its collaborators as parameters, which
 * is what makes them testable without a network or a model. The consequence is
 * that something has to supply the real ones, and this is that something: the
 * seam between "logic that has been tested" and "the database, GitHub, and a
 * model that costs money".
 *
 * It is deliberately the least clever file in the repository. The rules it
 * follows are worth stating, because each one is a mistake this file is the
 * natural place to make:
 *
 *   **Nothing untrusted crosses a step boundary.** `loadContext` returns
 *   metadata and a classification; `loadSources` returns wrapped content and
 *   is called *inside* the generation step. Neither ever hands repository text
 *   back to the workflow runtime, which would persist it as a step result and
 *   strip its untrusted marking on the way back out (see the header of
 *   `migrate-repository.ts`).
 *
 *   **Nothing is invented to make a job runnable.** A repository with no
 *   numeric forge id cannot have a token minted for it, and a job with no
 *   impact classification would have its pull request opened with a sentence
 *   nothing computed. Both fail permanently rather than defaulting, because
 *   the default would be a claim about somebody's repository that we made up.
 *
 *   **Reads are bounded before they are convenient.** A downstream repository
 *   is attacker-authored and can be any size, so the source read is capped by
 *   file count, per-file bytes, and total bytes, and the caps are visible here
 *   rather than buried in a client.
 */

import type { Database, TenantClient } from "../db/client.ts";
import type { AuditSink, GitHubApp } from "../github/app.ts";
import { postgresAuditSink } from "../audit/sink.ts";
import { PermanentFailure } from "../workflow/types.ts";
import { untrusted, type UntrustedContent } from "../agent/untrusted.ts";
import {
  GitHubContentClient,
  selectSourcePaths,
  type RepositoryDescription,
} from "../forge/github-contents.ts";
import type { Impact } from "../discover/affected.ts";
import type { Corroboration } from "../detect/corroborate.ts";
import type {
  MigrationDeps,
  MigrationInput,
  RepositoryContext,
} from "../workflows/migrate-repository.ts";
import type {
  CandidateRepository,
  RolloutDeps,
  StoredChange,
} from "../workflows/plan-rollout.ts";
import type { ChangeSummary } from "../forge/pull-request.ts";

/**
 * Hosts a migration diff may reference without being escalated for review.
 *
 * Not a general allowlist: the policy engine uses it to decide whether a URL
 * appearing in generated code is ordinary. Registry and forge hosts are
 * ordinary in a dependency migration; anything else in a diff we generated is
 * worth a human looking at it.
 */
export const KNOWN_HOSTS: readonly string[] = Object.freeze([
  "registry.npmjs.org",
  "npmjs.com",
  "www.npmjs.com",
  "github.com",
  "api.github.com",
  "raw.githubusercontent.com",
]);

/** Caps on a single repository read. See the header. */
export interface SourceLimits {
  readonly maxFiles?: number;
  readonly maxFileBytes?: number;
  readonly maxTotalBytes?: number;
}

const DEFAULT_SOURCE_LIMITS = {
  maxFiles: 300,
  maxFileBytes: 256 * 1024,
  maxTotalBytes: 4 * 1024 * 1024,
} as const;

export interface WiringDeps {
  readonly db: Database;
  readonly app: GitHubApp;
  readonly contents: GitHubContentClient;
  readonly log?: (event: string, detail: Record<string, unknown>) => void;
  readonly sourceLimits?: SourceLimits;
}

/** Tenant-bound audit sink. Bound per job, never shared across providers. */
export function auditFor(db: Database, providerId: string): AuditSink {
  return postgresAuditSink({ withTenant: (id, fn) => db.withTenant(id, fn) }, providerId);
}

// ── migrate-repository ──────────────────────────────────────────────────────

interface ContextRow {
  forge_owner: string;
  forge_name: string;
  forge_repository_id: string | null;
  forge_installation_id: string;
  default_branch: string;
  archived_at: Date | null;
  suspended_at: Date | null;
  change_key: string;
  ecosystem: string;
  package_name: string;
  from_version: string | null;
  to_version: string | null;
  summary: string;
  corroborations: unknown;
  impacted_symbols: string[] | null;
}

/**
 * One query, joined rather than three round trips.
 *
 * It also reads `suspended_at` and `archived_at`, which are not needed to
 * build the context and are the entire reason the join includes those tables.
 * A revoked installation means the customer told us to stop; discovering that
 * at token-mint time is too late, because by then we have already decided to
 * act.
 */
const CONTEXT_SQL = `
  SELECT r.forge_owner, r.forge_name, r.forge_repository_id, r.default_branch,
         r.archived_at,
         i.forge_installation_id, i.suspended_at,
         c.change_key, c.ecosystem, c.package_name, c.from_version,
         c.to_version, c.summary, c.corroborations, c.impacted_symbols
    FROM repository r
    JOIN installation i ON i.id = r.installation_id
    JOIN upstream_change c ON c.id = $2
   WHERE r.id = $1
`;

export function createMigrationDeps(
  deps: WiringDeps & {
    readonly agent: MigrationDeps["agent"];
    readonly forge: MigrationDeps["forge"];
    readonly optOutUrl: (token: string) => string;
    /** Bound per job by the caller: the audit sink is tenant-scoped. */
    readonly audit: AuditSink;
  },
): MigrationDeps {
  const limits = { ...DEFAULT_SOURCE_LIMITS, ...deps.sourceLimits };
  const log = deps.log ?? (() => {});

  return {
    app: deps.app,
    agent: deps.agent,
    forge: deps.forge,
    audit: deps.audit,
    withTenant: (providerId, fn) => deps.db.withTenant(providerId, fn),
    optOutUrl: deps.optOutUrl,

    async loadContext(client: TenantClient, input: MigrationInput) {
      const { rows } = await client.query<ContextRow>(CONTEXT_SQL, [
        input.repositoryId,
        input.changeId,
      ]);
      const row = rows[0];

      // RLS makes "no row" and "another tenant's row" indistinguishable, which
      // is the point. Either way there is nothing here to act on and no retry
      // will produce one.
      if (!row) {
        throw new PermanentFailure(
          `Repository ${input.repositoryId} or change ${input.changeId} is not visible to this tenant`,
        );
      }
      if (row.archived_at !== null) {
        throw new PermanentFailure("Repository is archived; a pull request would reach nobody");
      }
      if (row.suspended_at !== null) {
        throw new PermanentFailure("Installation is suspended or revoked; refusing to act");
      }
      if (row.forge_repository_id === null) {
        // ADR-0002 scopes a token to a numeric repository id. Without one the
        // only way to proceed is a token scoped to the whole installation,
        // which is the standing privilege the ADR exists to eliminate.
        throw new PermanentFailure(
          "Repository has no forge id; a token cannot be scoped to it (migration 008)",
        );
      }

      const repository: RepositoryContext = {
        forgeOwner: row.forge_owner,
        forgeName: row.forge_name,
        forgeRepositoryId: Number(row.forge_repository_id),
        forgeInstallationId: Number(row.forge_installation_id),
        defaultBranch: row.default_branch,
        knownHosts: KNOWN_HOSTS,
      };

      const change: ChangeSummary = {
        packageName: row.package_name,
        fromVersion: row.from_version ?? "",
        toVersion: row.to_version ?? "",
        ecosystem: row.ecosystem,
        // Kinds only. `composePullRequest` rejects anything else, and the free
        // text of a corroboration is upstream prose — the exact thing that must
        // not reach a body a maintainer trusts.
        corroboratedBy: corroborationKinds(row.corroborations),
        impactedSymbols: row.impacted_symbols ?? [],
      };

      return {
        repository,
        changeSummary: row.summary,
        change,
        changeKey: row.change_key,
        impact: requireImpact(input.impact),
      };
    },

    async loadSources(
      input: MigrationInput,
      repository: RepositoryContext,
    ): Promise<readonly { path: string; content: UntrustedContent }[]> {
      // The token is minted here, inside the generation step, and is not
      // returned. Nothing in this function may outlive the call.
      const token = await deps.app.mintInstallationToken(
        {
          installationId: input.installationId,
          forgeInstallationId: repository.forgeInstallationId,
          repositoryId: input.repositoryId,
          forgeRepositoryId: repository.forgeRepositoryId,
        },
        deps.audit,
      );

      const coord = { owner: repository.forgeOwner, name: repository.forgeName };
      // Read at the pinned commit, never at the branch head. The head may have
      // moved since the rollout planned this job, and migrating content the
      // policy engine did not inspect is the failure the base sha exists to
      // prevent.
      const snapshot = await deps.contents.snapshot(token, coord, input.baseSha);
      if (!snapshot) {
        throw new PermanentFailure(`Base commit ${input.baseSha} is not readable`);
      }

      const selected = selectSourcePaths(snapshot.entries, {
        maxFiles: limits.maxFiles,
        maxFileBytes: limits.maxFileBytes,
      });
      const files = await deps.contents.readFiles(token, coord, selected, {
        maxTotalBytes: limits.maxTotalBytes,
      });

      log("sources.read", {
        repository: `${coord.owner}/${coord.name}`,
        inTree: snapshot.entries.length,
        selected: selected.length,
        read: files.length,
        truncated: snapshot.truncated,
      });

      // The wrapping point. Everything past here is `UntrustedContent`, which
      // throws rather than serialising and cannot be interpolated into a
      // prompt (ADR-0003 layer 1).
      return files.map((file) => ({
        path: file.path,
        content: untrusted(file.content, "repository_file", file.path),
      }));
    },
  };
}

/**
 * The impact classification, or a refusal.
 *
 * `plan-rollout` computed this against the manifest at the base commit. A job
 * without it was not planned by that workflow, and the honest response is to
 * refuse rather than to guess: this value becomes the first sentence of a pull
 * request in somebody else's repository.
 */
function requireImpact(value: unknown): Impact {
  const permitted: readonly Impact[] = ["stranded", "exposed", "current", "unrelated", "unknown"];
  if (typeof value === "string" && (permitted as readonly string[]).includes(value)) {
    return value as Impact;
  }
  throw new PermanentFailure(
    "Migration job carries no impact classification; it was not produced by plan-rollout",
  );
}

/**
 * Corroboration *kinds*, defensively.
 *
 * The column is jsonb and was written by the detection sweep, but this is the
 * path to a pull request body, so the shape is checked rather than asserted.
 */
function corroborationKinds(value: unknown): readonly string[] {
  if (!Array.isArray(value)) return [];
  const kinds = new Set<string>();
  for (const entry of value) {
    const kind = (entry as Partial<Corroboration> | null)?.kind;
    if (typeof kind === "string") kinds.add(kind);
  }
  return [...kinds];
}

// ── plan-rollout ────────────────────────────────────────────────────────────

interface ChangeRow {
  change_key: string;
  ecosystem: string;
  package_name: string;
  from_version: string | null;
  to_version: string | null;
  corroborations: unknown;
  approved_at: Date | null;
}

interface CandidateRow {
  id: string;
  installation_id: string;
  forge_repository_id: string | null;
  forge_installation_id: string;
  forge_owner: string;
  forge_name: string;
  default_branch: string;
  archived_at: Date | null;
  stars: number | null;
  is_fork: boolean;
}

/** Manifest filenames, in the order a repository is asked for them. */
const MANIFEST_PATH = "package.json";
const LOCKFILE_PATHS = ["pnpm-lock.yaml", "package-lock.json", "yarn.lock"] as const;

/** `parseManifest`'s own ceiling. Reading past it would only be discarded. */
const MANIFEST_MAX_BYTES = 2 * 1024 * 1024;
/** Lockfiles are routinely far larger than any source file. */
const LOCKFILE_MAX_BYTES = 8 * 1024 * 1024;

export function createRolloutDeps(deps: WiringDeps): RolloutDeps {
  const log = deps.log ?? (() => {});

  return {
    withTenant: (providerId, fn) => deps.db.withTenant(providerId, fn),

    async loadChange(client, changeId): Promise<StoredChange | null> {
      const { rows } = await client.query<ChangeRow>(
        `SELECT change_key, ecosystem, package_name, from_version, to_version,
                corroborations, approved_at
           FROM upstream_change WHERE id = $1`,
        [changeId],
      );
      const row = rows[0];
      if (!row) return null;

      return {
        changeKey: row.change_key,
        ecosystem: row.ecosystem,
        packageName: row.package_name,
        fromVersion: row.from_version,
        toVersion: row.to_version,
        corroborations: Array.isArray(row.corroborations)
          ? (row.corroborations as Corroboration[])
          : [],
        approvedAt: row.approved_at ? row.approved_at.toISOString() : null,
      };
    },

    async candidates(client): Promise<readonly CandidateRepository[]> {
      // Every live repository under a non-suspended installation. Which of
      // them actually declares the package is decided by reading manifests,
      // not by this query — a repository being in our table is not evidence
      // that it uses anything.
      const { rows } = await client.query<CandidateRow>(
        `SELECT r.id, r.installation_id, r.forge_repository_id, r.forge_owner,
                r.forge_name, r.default_branch, r.archived_at, r.stars, r.is_fork,
                i.forge_installation_id
           FROM repository r
           JOIN installation i ON i.id = r.installation_id
          WHERE r.archived_at IS NULL
            AND i.suspended_at IS NULL
            AND r.forge_repository_id IS NOT NULL
          ORDER BY r.created_at`,
      );

      return rows.map((row) => ({
        repositoryId: row.id,
        installationId: row.installation_id,
        forgeRepositoryId: Number(row.forge_repository_id),
        forgeInstallationId: Number(row.forge_installation_id),
        forgeOwner: row.forge_owner,
        forgeName: row.forge_name,
        defaultBranch: row.default_branch,
        archived: false,
        // From the forge, refreshed on each rollout that reads this
        // repository (migration 009). Until then it is the default, which is
        // why `readManifest` re-checks it against a live description before
        // spending a tree read.
        fork: row.is_fork,
        ...(row.stars !== null && { stars: row.stars }),
      }));
    },

    /**
     * Reads one candidate's manifest at the head of its default branch.
     *
     * Every failure returns null rather than throwing, and that asymmetry is
     * the point: a rollout inspects hundreds of repositories, and one of them
     * having a revoked installation, an empty default branch, or no manifest
     * at all must cost that repository its migration and nothing else. The
     * reason is logged so a skip is visible rather than silent.
     */
    async readManifest(repository, providerId) {
      const coord = { owner: repository.forgeOwner, name: repository.forgeName };
      try {
        const token = await deps.app.mintInstallationToken(
          {
            installationId: repository.installationId,
            forgeInstallationId: repository.forgeInstallationId,
            repositoryId: repository.repositoryId,
            forgeRepositoryId: repository.forgeRepositoryId,
          },
          auditFor(deps.db, providerId),
        );

        // Ask the forge what this repository actually looks like before
        // reading it. The webhook never said which branch is the default, and
        // reading the wrong one produces a repository that looks like it has
        // no manifest — a skip nobody investigates.
        const described = await deps.contents.describe(token, coord);
        if (!described) return null;
        await refreshRepositoryShape(deps.db, providerId, repository.repositoryId, described);

        if (described.archived || described.fork) {
          // Both are `decideTarget`'s decision, but it works from the row, and
          // the row was stale until a moment ago. Stopping here saves a tree
          // read on a repository that was never going to be targeted.
          log("rollout.repository_skipped", {
            repository: `${coord.owner}/${coord.name}`,
            reason: described.archived ? "archived" : "fork",
          });
          return null;
        }

        const snapshot = await deps.contents.snapshot(token, coord, described.defaultBranch);
        if (!snapshot) return null;

        const manifest = await deps.contents.readPath(
          token,
          coord,
          snapshot,
          MANIFEST_PATH,
          MANIFEST_MAX_BYTES,
        );
        // No manifest is not a failure to read — it is a repository that is
        // not an npm package. `plan-rollout` records it as a skip either way.
        if (manifest === null) return null;

        // A lockfile only sharpens the assessment; its absence costs evidence,
        // not correctness. Lockfiles are also routinely megabytes, so they get
        // their own ceiling rather than the source-file one.
        let lockfile: { filename: string; content: string } | undefined;
        for (const filename of LOCKFILE_PATHS) {
          const content = await deps.contents.readPath(
            token,
            coord,
            snapshot,
            filename,
            LOCKFILE_MAX_BYTES,
          );
          if (content !== null) {
            lockfile = { filename, content };
            break;
          }
        }

        return {
          headSha: snapshot.commitSha,
          manifest,
          ...(lockfile !== undefined && { lockfile }),
        };
      } catch (error) {
        log("rollout.manifest_unreadable", {
          repository: `${coord.owner}/${coord.name}`,
          // The message is already redacted at the ForgeError boundary; a
          // token cannot reach a log through here.
          error: error instanceof Error ? error.message : String(error),
        });
        return null;
      }
    },

    async enqueueMigration(input) {
      return deps.db.withTenant(input.providerId, async (client) => {
        const { rows } = await client.query<{ created: boolean }>(
          `SELECT created FROM enqueue_job($1, $2, $3::jsonb, $4)`,
          [
            input.providerId,
            "migrate-repository",
            JSON.stringify({
              repositoryId: input.repositoryId,
              installationId: input.installationId,
              changeId: input.changeId,
              baseSha: input.baseSha,
              impact: input.impact,
            }),
            input.dedupeKey,
          ],
        );
        const created = rows[0]?.created === true;
        log("rollout.enqueued", { repositoryId: input.repositoryId, created });
        return { created };
      });
    },
  };
}

/**
 * Caches what the forge said about a repository.
 *
 * Best-effort on purpose: a failure to write the cache must not cost the
 * rollout the manifest it just successfully read. The values are a performance
 * and ordering concern, and the authoritative copy was in hand a line ago.
 */
async function refreshRepositoryShape(
  db: Database,
  providerId: string,
  repositoryId: string,
  described: RepositoryDescription,
): Promise<void> {
  try {
    await db.withTenant(providerId, (client) =>
      client.query(
        `UPDATE repository
            SET default_branch = $2, stars = $3, is_fork = $4,
                archived_at = CASE WHEN $5 THEN COALESCE(archived_at, now()) ELSE archived_at END,
                described_at = now()
          WHERE id = $1`,
        [repositoryId, described.defaultBranch, described.stars, described.fork, described.archived],
      ),
    );
  } catch {
    // Deliberately swallowed. See above.
  }
}

// ── detect-changes ──────────────────────────────────────────────────────────

/**
 * How many repositories a change could reach, for canary sizing.
 *
 * This counts repositories we are installed on for the tenant — not
 * repositories known to declare the package, because nothing stores that. It
 * is therefore an upper bound, and it is used only where an upper bound is
 * safe: `canarySize` scales the first wave by it, and `plan-rollout` recomputes
 * the wave against the repositories that actually declared the package before
 * anything is enqueued.
 *
 * Stated plainly because the previous value was a hardcoded 0, which made
 * every canary the minimum size and made the number in the sweep's output
 * fiction. An honest upper bound is worth more than a confident zero.
 */
export function installedRepositoryCount(db: Database) {
  return async (_packageName: string, providerId: string): Promise<number> => {
    return db.withTenant(providerId, async (client) => {
      const { rows } = await client.query<{ count: string }>(
        `SELECT count(*)::text AS count
           FROM repository r
           JOIN installation i ON i.id = r.installation_id
          WHERE r.archived_at IS NULL AND i.suspended_at IS NULL`,
      );
      return Number(rows[0]?.count ?? 0);
    });
  };
}
