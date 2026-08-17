/**
 * Reading a downstream repository.
 *
 * The counterpart to `github-forge.ts`: that module writes a commit, this one
 * reads the bytes a migration is generated from. Both go through the Git Data
 * API for the same reason — no clone, no working tree, no temporary directory
 * holding somebody else's source next to a credential.
 *
 * ── Everything this returns is attacker-authored ─────────────────────────────
 *
 * A repository's files are threat-model §5.1 input. This module deliberately
 * returns plain strings rather than `UntrustedContent`, and that is not an
 * oversight: wrapping happens in `loadSources`, the one function whose output
 * reaches a prompt. The manifest path never wraps, because it never goes near
 * one — it is parsed deterministically by `parseManifest`. Wrapping here would
 * force a third `unsafeReveal` call site to exist purely to unwrap content that
 * was never in danger, and the value of that invariant is that it stays small
 * enough to audit by grep.
 *
 * ── Why selection is a pure function ─────────────────────────────────────────
 *
 * A repository can hold a hundred thousand files, and the agent's prompt budget
 * is a few hundred kilobytes. Something must choose. `selectSourcePaths` is
 * that something, and it is pure and exported so its refusals — vendored
 * directories, minified bundles, files above the size cap — are testable
 * without a network. The blast radius then narrows this set again, from the
 * upstream change rather than from anything a repository said (ADR-0013); this
 * is only a coarse pre-filter, and it is bounded rather than clever.
 */

import { ForgeError, type ForgeHttpClient } from "./github-forge.ts";
import { ScopedToken } from "../github/token.ts";

export interface RepositoryCoordinate {
  readonly owner: string;
  readonly name: string;
}

/** One blob in the tree. `size` is GitHub's, in bytes, before decoding. */
export interface TreeEntry {
  readonly path: string;
  readonly sha: string;
  readonly size: number;
}

export interface RepositorySnapshot {
  readonly commitSha: string;
  readonly treeSha: string;
  readonly entries: readonly TreeEntry[];
  /**
   * GitHub truncates very large trees. A truncated snapshot is a partial view,
   * so a file's absence from it proves nothing — callers must treat "not found"
   * as "not found here" rather than "does not exist".
   */
  readonly truncated: boolean;
}

export interface RepositoryFile {
  readonly path: string;
  readonly content: string;
}

export interface ContentClientOptions {
  readonly http: ForgeHttpClient;
  readonly baseUrl?: string;
  readonly userAgent?: string;
  /** Per-file ceiling. A file above it is not read at all. */
  readonly maxFileBytes?: number;
  readonly log?: (event: string, detail: Record<string, unknown>) => void;
}

const DEFAULT_BASE_URL = "https://api.github.com";
const DEFAULT_MAX_FILE_BYTES = 256 * 1024;

export class GitHubContentClient {
  readonly #http: ForgeHttpClient;
  readonly #baseUrl: string;
  readonly #userAgent: string;
  readonly #maxFileBytes: number;
  readonly #log: (event: string, detail: Record<string, unknown>) => void;

  constructor(options: ContentClientOptions) {
    this.#http = options.http;
    this.#baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.#userAgent = options.userAgent ?? "driftless";
    this.#maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
    this.#log = options.log ?? (() => {});
  }

  /**
   * The commit a migration will be generated against, and everything in it.
   *
   * One recursive read rather than a walk: the alternative is a request per
   * directory, which on a repository of any size is both slower and a far
   * larger share of the installation's rate limit.
   */
  async snapshot(
    token: ScopedToken,
    coord: RepositoryCoordinate,
    ref: string,
  ): Promise<RepositorySnapshot | null> {
    assertCoordinate(coord);
    assertRef(ref);
    const auth = ScopedToken.revealForAuthorisedUse(token, "github-api-request");
    const repo = this.#repoUrl(coord);

    const head = await this.#send("GET", `${repo}/commits/${encodeURIComponent(ref)}`, auth);
    if (head.status === 404 || head.status === 409) {
      // 409 is GitHub's answer for an empty repository. Both mean there is
      // nothing here to migrate, which is ordinary rather than an error.
      return null;
    }
    if (head.status !== 200) {
      throw new ForgeError(
        `Resolving ${ref} returned ${head.status}: ${head.body}`,
        head.status,
      );
    }

    const commit = parse<{ sha?: string; commit?: { tree?: { sha?: string } } }>(head.body);
    const commitSha = commit.sha;
    const treeSha = commit.commit?.tree?.sha;
    if (!commitSha || !treeSha) throw new ForgeError(`Commit ${ref} has no tree`);

    const tree = await this.#send("GET", `${repo}/git/trees/${treeSha}?recursive=1`, auth);
    if (tree.status !== 200) {
      throw new ForgeError(
        `Reading tree ${treeSha} returned ${tree.status}: ${tree.body}`,
        tree.status,
      );
    }

    const parsed = parse<{
      truncated?: boolean;
      tree?: { path?: string; sha?: string; type?: string; size?: number }[];
    }>(tree.body);

    const entries: TreeEntry[] = [];
    for (const entry of parsed.tree ?? []) {
      if (entry.type !== "blob" || !entry.path || !entry.sha) continue;
      entries.push({ path: entry.path, sha: entry.sha, size: entry.size ?? 0 });
    }

    if (parsed.truncated) {
      this.#log("contents.tree_truncated", {
        repository: `${coord.owner}/${coord.name}`,
        entries: entries.length,
      });
    }

    return { commitSha, treeSha, entries, truncated: parsed.truncated === true };
  }

  /**
   * Reads one blob as text.
   *
   * Returns null for anything that is not usable as source: above the size
   * cap, or holding a NUL byte. A NUL means the file is binary, and handing
   * binary to a text pipeline produces mojibake that the model would then
   * cheerfully propose edits to.
   */
  async readBlob(
    token: ScopedToken,
    coord: RepositoryCoordinate,
    sha: string,
    maxBytes = this.#maxFileBytes,
  ): Promise<string | null> {
    assertCoordinate(coord);
    assertBlobSha(sha);
    const auth = ScopedToken.revealForAuthorisedUse(token, "github-api-request");

    const response = await this.#send("GET", `${this.#repoUrl(coord)}/git/blobs/${sha}`, auth);
    if (response.status === 404) return null;
    if (response.status !== 200) {
      throw new ForgeError(
        `Reading blob ${sha} returned ${response.status}: ${response.body}`,
        response.status,
      );
    }

    const blob = parse<{ content?: string; encoding?: string; size?: number }>(response.body);
    if (blob.encoding !== "base64" || typeof blob.content !== "string") return null;
    if ((blob.size ?? 0) > maxBytes) return null;

    const bytes = Buffer.from(blob.content, "base64");
    if (bytes.byteLength > maxBytes) return null;
    if (bytes.includes(0)) return null;

    return bytes.toString("utf8");
  }

  /** Convenience: the blob at a path in a snapshot, or null if absent. */
  async readPath(
    token: ScopedToken,
    coord: RepositoryCoordinate,
    snapshot: RepositorySnapshot,
    path: string,
    maxBytes?: number,
  ): Promise<string | null> {
    const entry = snapshot.entries.find((candidate) => candidate.path === path);
    if (!entry) return null;
    return this.readBlob(token, coord, entry.sha, maxBytes);
  }

  /**
   * Reads the selected files, in order, stopping at the total byte budget.
   *
   * Sequential rather than parallel. These reads run against one installation's
   * rate limit on somebody else's repository, and a burst of parallel requests
   * buys latency we do not need at the cost of being the noisiest client they
   * have that day.
   */
  async readFiles(
    token: ScopedToken,
    coord: RepositoryCoordinate,
    entries: readonly TreeEntry[],
    limits: { maxTotalBytes: number },
  ): Promise<readonly RepositoryFile[]> {
    const files: RepositoryFile[] = [];
    let used = 0;

    for (const entry of entries) {
      if (used + entry.size > limits.maxTotalBytes) continue;
      const content = await this.readBlob(token, coord, entry.sha);
      if (content === null) continue;
      files.push({ path: entry.path, content });
      used += Buffer.byteLength(content, "utf8");
    }

    return files;
  }

  #repoUrl(coord: RepositoryCoordinate): string {
    return `${this.#baseUrl}/repos/${coord.owner}/${coord.name}`;
  }

  async #send(
    method: "GET",
    url: string,
    auth: string,
  ): Promise<{ status: number; body: string }> {
    try {
      return await this.#http.request(method, url, undefined, {
        authorization: `Bearer ${auth}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        "user-agent": this.#userAgent,
      });
    } catch (error) {
      throw new ForgeError(
        `${method} failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
}

// ── Selection ───────────────────────────────────────────────────────────────

export interface SelectionLimits {
  readonly maxFiles?: number;
  readonly maxFileBytes?: number;
}

const SOURCE_EXTENSIONS = Object.freeze([
  ".ts",
  ".tsx",
  ".mts",
  ".cts",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
]);

/**
 * Directories whose contents are not the repository's own source.
 *
 * Editing a vendored copy of a dependency produces a pull request that changes
 * code the maintainer did not write and will not review, and `dist` is worse:
 * a generated file that the next build overwrites, so the migration looks
 * applied and silently is not.
 */
const EXCLUDED_SEGMENTS = new Set([
  ".git",
  "node_modules",
  "vendor",
  "third_party",
  "dist",
  "build",
  "out",
  "coverage",
  ".next",
  ".nuxt",
  ".output",
  "__snapshots__",
  "fixtures",
]);

const DEFAULT_MAX_SELECTED_FILES = 300;

/**
 * Chooses which files are worth showing the agent.
 *
 * Pure, so every refusal below is provable without a network. The order is
 * deliberate: `src/` first, then shallowest, then alphabetical. Shallow files
 * in `src` are where a package's call sites live; the ordering only matters
 * because the cap truncates, and truncating alphabetically would spend the
 * whole budget in `app/` on a repository that keeps its code in `src/`.
 */
export function selectSourcePaths(
  entries: readonly TreeEntry[],
  limits: SelectionLimits = {},
): readonly TreeEntry[] {
  const maxFiles = limits.maxFiles ?? DEFAULT_MAX_SELECTED_FILES;
  const maxFileBytes = limits.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;

  const eligible = entries.filter((entry) => isSelectableSource(entry, maxFileBytes));

  eligible.sort((a, b) => {
    const aSrc = a.path.startsWith("src/") ? 0 : 1;
    const bSrc = b.path.startsWith("src/") ? 0 : 1;
    if (aSrc !== bSrc) return aSrc - bSrc;
    const depth = a.path.split("/").length - b.path.split("/").length;
    if (depth !== 0) return depth;
    return a.path < b.path ? -1 : a.path > b.path ? 1 : 0;
  });

  return eligible.slice(0, maxFiles);
}

function isSelectableSource(entry: TreeEntry, maxFileBytes: number): boolean {
  const path = entry.path;
  if (path.length === 0 || path.length > 400) return false;
  if (entry.size > maxFileBytes) return false;

  const segments = path.split("/");
  if (segments.some((segment) => EXCLUDED_SEGMENTS.has(segment))) return false;
  // A hidden directory is tooling, not source. A hidden *file* at the root
  // (`.eslintrc.js`) is configuration, which migrations are forbidden to touch
  // by policy anyway — excluding both here saves the budget for real code.
  if (segments.some((segment) => segment.startsWith("."))) return false;

  const name = segments[segments.length - 1] ?? "";
  // Minified and generated output. A single 200KB line is worthless to a model
  // and would consume the whole prompt budget proving it.
  if (name.includes(".min.")) return false;
  if (name.endsWith(".d.ts")) return false;

  return SOURCE_EXTENSIONS.some((extension) => name.endsWith(extension));
}

// ── Validation ──────────────────────────────────────────────────────────────

const COORDINATE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

function assertCoordinate(coord: RepositoryCoordinate): void {
  for (const [value, label] of [
    [coord.owner, "owner"],
    [coord.name, "repository name"],
  ] as const) {
    if (!COORDINATE.test(value) || value.length > 100) {
      throw new ForgeError(`Invalid ${label}: ${JSON.stringify(value)}`);
    }
  }
}

/**
 * A ref reaches a URL path, so it is validated on shape before it gets there
 * rather than trusted to the encoder. Accepts a branch name or a commit sha —
 * both are legitimate things to snapshot.
 */
function assertRef(ref: string): void {
  const invalid =
    ref.length === 0 ||
    ref.length > 200 ||
    ref.startsWith("-") ||
    ref.startsWith("/") ||
    ref.endsWith("/") ||
    ref.includes("..") ||
    ref.includes("//") ||
    ref.includes("@{") ||
    /[\s~^:?*[\\\x00-\x1f\x7f]/.test(ref);
  if (invalid) throw new ForgeError(`Invalid ref: ${JSON.stringify(ref)}`);
}

function assertBlobSha(sha: string): void {
  if (!/^[0-9a-f]{40}$/.test(sha)) {
    throw new ForgeError(`Invalid blob sha: ${JSON.stringify(sha)}`);
  }
}

function parse<T>(body: string): T {
  try {
    return JSON.parse(body) as T;
  } catch {
    throw new ForgeError("GitHub returned a response that is not JSON");
  }
}
