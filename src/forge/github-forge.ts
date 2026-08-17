/**
 * Opening the pull request on GitHub.
 *
 * The last step of the pipeline, and the first one that writes to somebody
 * else's repository. Everything before it is analysis that can be thrown away;
 * this leaves a permanent artifact under a maintainer's name.
 *
 * ── Why this takes file contents and not a diff ──────────────────────────────
 *
 * The obvious signature is `openPullRequest({ diff })`, and it is wrong.
 *
 * `unified-diff.ts` explains the reasoning at length: the model never writes
 * diff syntax, because a diff that is both *the artifact the policy engine
 * inspects* and *the instruction git executes* has two readers who are not
 * guaranteed to agree. `git apply --3way` relocates hunks whose line numbers
 * are wrong; a hunk header that lies about its length is tolerated by some
 * appliers and rejected by others. Any gap between what the policy engine
 * parsed and what lands in the branch is a gap an injection can be aimed at.
 *
 * Driftless already holds the answer. `applyEditPlan` applies the model's
 * anchored replacements to content we fetched ourselves and produces the exact
 * post-migration bytes; the diff is rendered *from* those bytes, as a
 * description of a transformation already performed. So this client writes the
 * bytes. Re-deriving them by applying the diff here would reintroduce the
 * second reader the whole design exists to remove.
 *
 * ── Why the Git Data API rather than a clone ─────────────────────────────────
 *
 * No working tree, no `git` subprocess, no temporary directory holding another
 * repository's source next to a credential. Blobs, a tree, a commit, a ref —
 * four writes, and the commit is atomic across every changed file. It is also
 * the only approach that keeps this module honest about the filesystem, the
 * same way `api-surface.ts` runs the compiler over a map-backed host and
 * `tarball.ts` reads an archive without unpacking it to disk.
 *
 * ── Why it never force-pushes ────────────────────────────────────────────────
 *
 * This workflow retries, so it will meet its own half-finished work: a branch
 * that exists because a previous attempt died between creating the ref and
 * opening the pull request. Force-updating the ref makes that case trivial —
 * and silently destroys a maintainer's commit in the case where they pushed a
 * fixup onto our branch, which is the single most valuable thing that can
 * happen to one of these pull requests. So a branch that already exists is
 * never overwritten. See `#reconcileExistingBranch`.
 */

import { ScopedToken, redactSecrets } from "../github/token.ts";
import type { FileChange } from "../agent/unified-diff.ts";

export interface ForgeHttpResponse {
  readonly status: number;
  readonly body: string;
}

/**
 * Injected for the reasons `GitHubApp` states: tests exercise the real request
 * sequence without network, and code that handles a credential does not
 * inherit the behaviour of an SDK we do not control — particularly its error
 * messages, which are a common route for a token to reach a log.
 */
export interface ForgeHttpClient {
  request(
    method: "GET" | "POST" | "PATCH",
    url: string,
    body: unknown | undefined,
    headers: Readonly<Record<string, string>>,
  ): Promise<ForgeHttpResponse>;
}

export class ForgeError extends Error {
  override readonly name = "ForgeError";
  readonly status: number;

  constructor(message: string, status = 0) {
    // Redacts rather than trusting the caller. This message is built from
    // response bodies, and a 401 body has been known to echo the credential
    // that produced it.
    super(redactSecrets(message));
    this.status = status;
  }
}

export interface GitHubForgeOptions {
  readonly http: ForgeHttpClient;
  readonly baseUrl?: string;
  readonly userAgent?: string;
  /** Refuse absurd blobs rather than streaming them into a commit. */
  readonly maxFileBytes?: number;
  readonly maxFiles?: number;
}

export interface OpenPullRequestRequest {
  readonly token: ScopedToken;
  readonly owner: string;
  readonly name: string;
  /** The commit the migration was generated against. The commit's parent. */
  readonly baseSha: string;
  readonly branch: string;
  /** Branch the pull request targets. */
  readonly baseBranch: string;
  readonly title: string;
  readonly body: string;
  /**
   * Post-migration contents. `after` is written verbatim; `before` is carried
   * only so this client can verify the file it is replacing is the one the
   * migration was generated against.
   */
  readonly files: readonly FileChange[];
  readonly commitMessage: string;
}

export interface OpenedPullRequest {
  readonly number: number;
  readonly url: string;
  /** True when a previous attempt had already opened it (ADR-0004). */
  readonly alreadyOpen: boolean;
}

const DEFAULT_MAX_FILE_BYTES = 1024 * 1024;
const DEFAULT_MAX_FILES = 50;
const DEFAULT_BASE_URL = "https://api.github.com";

/** Regular files only. A migration has no business creating a symlink. */
const BLOB_MODE_FILE = "100644";
const BLOB_MODE_EXECUTABLE = "100755";

export class GitHubForgeClient {
  readonly #http: ForgeHttpClient;
  readonly #baseUrl: string;
  readonly #userAgent: string;
  readonly #maxFileBytes: number;
  readonly #maxFiles: number;

  constructor(options: GitHubForgeOptions) {
    this.#http = options.http;
    this.#baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.#userAgent = options.userAgent ?? "driftless";
    this.#maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
    this.#maxFiles = options.maxFiles ?? DEFAULT_MAX_FILES;
  }

  async openPullRequest(request: OpenPullRequestRequest): Promise<OpenedPullRequest> {
    assertRepositoryCoordinate(request.owner, "owner");
    assertRepositoryCoordinate(request.name, "repository name");
    assertBranchName(request.branch);
    assertBranchName(request.baseBranch);
    assertCommitSha(request.baseSha);
    this.#assertFiles(request.files);

    // Read once, at the boundary, and hold it in a local. Every helper takes
    // it as a parameter so there is no field on this object that holds a
    // credential for longer than the call.
    const auth = ScopedToken.revealForAuthorisedUse(request.token, "github-api-request");
    const repo = `${this.#baseUrl}/repos/${request.owner}/${request.name}`;

    // An existing branch means a previous attempt got at least this far. Deal
    // with that before spending four writes reproducing work that is already
    // on the remote.
    const existing = await this.#getRef(repo, request.branch, auth);
    if (existing !== null) {
      return this.#reconcileExistingBranch(repo, request, auth);
    }

    const baseTreeSha = await this.#treeShaOf(repo, request.baseSha, auth);
    const modes = await this.#resolveModes(repo, baseTreeSha, request.files, auth);

    const entries: TreeEntry[] = [];
    for (const file of request.files) {
      const sha = await this.#createBlob(repo, file.after, auth);
      entries.push({
        path: file.path,
        mode: modes.get(file.path) ?? BLOB_MODE_FILE,
        type: "blob",
        sha,
      });
    }

    const treeSha = await this.#createTree(repo, baseTreeSha, entries, auth);
    const commitSha = await this.#createCommit(
      repo,
      { message: request.commitMessage, treeSha, parentSha: request.baseSha },
      auth,
    );
    await this.#createRef(repo, request.branch, commitSha, auth);

    return this.#createPullRequest(repo, request, auth);
  }

  // ── Reconciliation ────────────────────────────────────────────────────────

  /**
   * The branch is already there. Decide what that means without destroying
   * anything.
   *
   * If a pull request is open for it, the previous attempt succeeded and we
   * simply did not get to record it — that is ADR-0004's idempotency case, and
   * returning the existing pull request is the correct, non-duplicating
   * outcome.
   *
   * If there is no pull request, the branch is ambiguous: it may be our own
   * dead attempt, or it may be somebody else's. Distinguishing the two costs
   * more certainty than it buys, and the wrong guess either force-pushes over
   * a maintainer's work or opens a second pull request against a stale branch.
   * Both are worse than stopping, so it stops.
   */
  async #reconcileExistingBranch(
    repo: string,
    request: OpenPullRequestRequest,
    auth: string,
  ): Promise<OpenedPullRequest> {
    const open = await this.#findPullRequest(repo, request.owner, request.branch, auth);
    if (open) return { ...open, alreadyOpen: true };

    throw new ForgeError(
      `Branch ${request.branch} already exists on ${request.owner}/${request.name} ` +
        `but has no open pull request. Refusing to force-update it: the branch may ` +
        `carry a maintainer's commits. Delete it to retry.`,
    );
  }

  // ── Git data ──────────────────────────────────────────────────────────────

  async #getRef(repo: string, branch: string, auth: string): Promise<string | null> {
    const response = await this.#send(
      "GET",
      `${repo}/git/ref/heads/${encodeURIComponent(branch)}`,
      undefined,
      auth,
    );
    if (response.status === 404) return null;
    if (response.status !== 200) {
      throw new ForgeError(
        `Reading ref ${branch} returned ${response.status}: ${response.body}`,
        response.status,
      );
    }
    return parse<{ object?: { sha?: string } }>(response.body).object?.sha ?? null;
  }

  async #treeShaOf(repo: string, commitSha: string, auth: string): Promise<string> {
    const response = await this.#send("GET", `${repo}/git/commits/${commitSha}`, undefined, auth);
    if (response.status !== 200) {
      throw new ForgeError(
        `Reading base commit ${commitSha} returned ${response.status}: ${response.body}`,
        response.status,
      );
    }
    const sha = parse<{ tree?: { sha?: string } }>(response.body).tree?.sha;
    if (!sha) throw new ForgeError(`Base commit ${commitSha} has no tree`);
    return sha;
  }

  /**
   * File modes for the paths being rewritten.
   *
   * Not incidental. `applyEditPlan` can only edit a file it was shown, so
   * every path here already exists at the base commit — and writing it back at
   * 100644 when it was 100755 silently clears the executable bit on a script
   * the repository's own tooling runs. That is a broken build with no line in
   * the diff to explain it, which is exactly the class of damage that makes a
   * maintainer distrust the whole system.
   *
   * One recursive read covers it. Very large repositories truncate that
   * response, so the changed paths are walked individually as a fallback —
   * bounded by the blast radius, so it stays small.
   */
  async #resolveModes(
    repo: string,
    baseTreeSha: string,
    files: readonly FileChange[],
    auth: string,
  ): Promise<Map<string, string>> {
    const modes = new Map<string, string>();
    const response = await this.#send(
      "GET",
      `${repo}/git/trees/${baseTreeSha}?recursive=1`,
      undefined,
      auth,
    );
    if (response.status !== 200) {
      throw new ForgeError(
        `Reading base tree returned ${response.status}: ${response.body}`,
        response.status,
      );
    }

    const tree = parse<{
      truncated?: boolean;
      tree?: { path?: string; mode?: string; type?: string }[];
    }>(response.body);

    const wanted = new Set(files.map((file) => file.path));
    for (const entry of tree.tree ?? []) {
      if (entry.type !== "blob" || !entry.path || !entry.mode) continue;
      if (wanted.has(entry.path)) modes.set(entry.path, normaliseMode(entry.mode));
    }

    if (tree.truncated) {
      for (const file of files) {
        if (modes.has(file.path)) continue;
        const mode = await this.#walkForMode(repo, baseTreeSha, file.path, auth);
        if (mode) modes.set(file.path, mode);
      }
    }

    // A path the migration edited that is absent from the base tree means the
    // base moved under us between generation and write. Guessing a mode would
    // paper over a genuinely wrong write.
    for (const file of files) {
      if (!modes.has(file.path)) {
        throw new ForgeError(
          `${file.path} is not present at the base commit. The base moved ` +
            `between generation and write; regenerate against the current head.`,
        );
      }
    }

    return modes;
  }

  /** Descends one path segment at a time. Used only when a tree truncates. */
  async #walkForMode(
    repo: string,
    rootTreeSha: string,
    path: string,
    auth: string,
  ): Promise<string | null> {
    const segments = path.split("/");
    let treeSha = rootTreeSha;

    for (const [index, segment] of segments.entries()) {
      const response = await this.#send("GET", `${repo}/git/trees/${treeSha}`, undefined, auth);
      if (response.status !== 200) return null;
      const entries =
        parse<{ tree?: { path?: string; mode?: string; type?: string; sha?: string }[] }>(
          response.body,
        ).tree ?? [];
      const match = entries.find((entry) => entry.path === segment);
      if (!match?.sha || !match.mode) return null;

      if (index === segments.length - 1) {
        return match.type === "blob" ? normaliseMode(match.mode) : null;
      }
      if (match.type !== "tree") return null;
      treeSha = match.sha;
    }
    return null;
  }

  async #createBlob(repo: string, content: string, auth: string): Promise<string> {
    // base64 rather than utf-8: the API's utf-8 mode is lossy for content
    // containing lone surrogates or a NUL, and a migration that silently
    // rewrites bytes it did not intend to rewrite is the failure this whole
    // module is arranged to prevent.
    const response = await this.#send(
      "POST",
      `${repo}/git/blobs`,
      { content: Buffer.from(content, "utf8").toString("base64"), encoding: "base64" },
      auth,
    );
    if (response.status !== 201) {
      throw new ForgeError(
        `Creating blob returned ${response.status}: ${response.body}`,
        response.status,
      );
    }
    const sha = parse<{ sha?: string }>(response.body).sha;
    if (!sha) throw new ForgeError("Blob creation returned no sha");
    return sha;
  }

  async #createTree(
    repo: string,
    baseTreeSha: string,
    entries: readonly TreeEntry[],
    auth: string,
  ): Promise<string> {
    const response = await this.#send(
      "POST",
      `${repo}/git/trees`,
      { base_tree: baseTreeSha, tree: entries },
      auth,
    );
    if (response.status !== 201) {
      throw new ForgeError(
        `Creating tree returned ${response.status}: ${response.body}`,
        response.status,
      );
    }
    const sha = parse<{ sha?: string }>(response.body).sha;
    if (!sha) throw new ForgeError("Tree creation returned no sha");
    return sha;
  }

  async #createCommit(
    repo: string,
    commit: { message: string; treeSha: string; parentSha: string },
    auth: string,
  ): Promise<string> {
    const response = await this.#send(
      "POST",
      `${repo}/git/commits`,
      { message: commit.message, tree: commit.treeSha, parents: [commit.parentSha] },
      auth,
    );
    if (response.status !== 201) {
      throw new ForgeError(
        `Creating commit returned ${response.status}: ${response.body}`,
        response.status,
      );
    }
    const sha = parse<{ sha?: string }>(response.body).sha;
    if (!sha) throw new ForgeError("Commit creation returned no sha");
    return sha;
  }

  async #createRef(repo: string, branch: string, sha: string, auth: string): Promise<void> {
    const response = await this.#send(
      "POST",
      `${repo}/git/refs`,
      { ref: `refs/heads/${branch}`, sha },
      auth,
    );
    if (response.status !== 201) {
      throw new ForgeError(
        `Creating ref ${branch} returned ${response.status}: ${response.body}`,
        response.status,
      );
    }
  }

  // ── Pull request ──────────────────────────────────────────────────────────

  async #createPullRequest(
    repo: string,
    request: OpenPullRequestRequest,
    auth: string,
  ): Promise<OpenedPullRequest> {
    const response = await this.#send(
      "POST",
      `${repo}/pulls`,
      {
        title: request.title,
        body: request.body,
        head: request.branch,
        base: request.baseBranch,
        // Nobody has asked us to open this. Letting a bot @-mention every
        // recent committer on a repository it was not invited to is how the
        // whole motion gets blocked.
        maintainer_can_modify: true,
      },
      auth,
    );

    if (response.status === 201) {
      const created = parse<{ number?: number; html_url?: string }>(response.body);
      if (typeof created.number !== "number" || !created.html_url) {
        throw new ForgeError("Pull request creation returned an unusable response");
      }
      return { number: created.number, url: created.html_url, alreadyOpen: false };
    }

    // GitHub answers a duplicate with 422. That is this workflow meeting its
    // own previous attempt, not an error — resolve it to the existing pull
    // request rather than failing a job that already did its work.
    if (response.status === 422) {
      const open = await this.#findPullRequest(repo, request.owner, request.branch, auth);
      if (open) return { ...open, alreadyOpen: true };
    }

    throw new ForgeError(
      `Opening pull request returned ${response.status}: ${response.body}`,
      response.status,
    );
  }

  async #findPullRequest(
    repo: string,
    owner: string,
    branch: string,
    auth: string,
  ): Promise<{ number: number; url: string } | null> {
    const head = encodeURIComponent(`${owner}:${branch}`);
    const response = await this.#send(
      "GET",
      `${repo}/pulls?head=${head}&state=open&per_page=1`,
      undefined,
      auth,
    );
    if (response.status !== 200) return null;
    const [first] = parse<{ number?: number; html_url?: string }[]>(response.body);
    if (!first || typeof first.number !== "number" || !first.html_url) return null;
    return { number: first.number, url: first.html_url };
  }

  // ── Transport ─────────────────────────────────────────────────────────────

  async #send(
    method: "GET" | "POST" | "PATCH",
    url: string,
    body: unknown | undefined,
    auth: string,
  ): Promise<ForgeHttpResponse> {
    try {
      return await this.#http.request(method, url, body, {
        authorization: `Bearer ${auth}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        "user-agent": this.#userAgent,
      });
    } catch (error) {
      // The thrown value came from a transport we do not control and may quote
      // the request headers back at us.
      throw new ForgeError(
        `${method} failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  #assertFiles(files: readonly FileChange[]): void {
    if (files.length === 0) throw new ForgeError("Refusing to open a pull request with no changes");
    if (files.length > this.#maxFiles) {
      throw new ForgeError(`Migration touches ${files.length} files, above the ${this.#maxFiles} ceiling`);
    }

    const seen = new Set<string>();
    for (const file of files) {
      assertRepositoryPath(file.path);
      if (seen.has(file.path)) {
        throw new ForgeError(`${file.path} appears twice; refusing to guess which write wins`);
      }
      seen.add(file.path);

      const bytes = Buffer.byteLength(file.after, "utf8");
      if (bytes > this.#maxFileBytes) {
        throw new ForgeError(`${file.path} is ${bytes} bytes, above the ${this.#maxFileBytes} ceiling`);
      }
      if (file.before === file.after) {
        throw new ForgeError(`${file.path} is unchanged; it does not belong in the commit`);
      }
    }
  }
}

interface TreeEntry {
  readonly path: string;
  readonly mode: string;
  readonly type: "blob";
  readonly sha: string;
}

/**
 * Only two modes are writable.
 *
 * Git also has 120000 (symlink) and 160000 (submodule). A migration that
 * turned a source file into a symlink, or pinned a submodule, would be a
 * content change the diff does not describe — so an unexpected mode is
 * narrowed to a regular file rather than carried through.
 */
function normaliseMode(mode: string): string {
  return mode === BLOB_MODE_EXECUTABLE ? BLOB_MODE_EXECUTABLE : BLOB_MODE_FILE;
}

function parse<T>(body: string): T {
  try {
    return JSON.parse(body) as T;
  } catch {
    throw new ForgeError("GitHub returned a response that is not JSON");
  }
}

const COORDINATE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

function assertRepositoryCoordinate(value: string, label: string): void {
  if (!COORDINATE.test(value) || value.length > 100) {
    throw new ForgeError(`Invalid ${label}: ${JSON.stringify(value)}`);
  }
}

/**
 * git's own ref rules, enforced before the value reaches a URL.
 *
 * These characters are refused by `git check-ref-format`, so a name containing
 * one cannot have come from a branch that exists. Validating here keeps a
 * crafted name out of the request path rather than trusting the encoder.
 */
function assertBranchName(branch: string): void {
  const invalid =
    branch.length === 0 ||
    branch.length > 200 ||
    branch.startsWith("-") ||
    branch.startsWith("/") ||
    branch.endsWith("/") ||
    branch.endsWith(".") ||
    branch.endsWith(".lock") ||
    branch.includes("..") ||
    branch.includes("//") ||
    branch.includes("@{") ||
    /[\s~^:?*[\\\x00-\x1f\x7f]/.test(branch);
  if (invalid) throw new ForgeError(`Invalid branch name: ${JSON.stringify(branch)}`);
}

function assertCommitSha(sha: string): void {
  if (!/^[0-9a-f]{40}$/.test(sha)) {
    throw new ForgeError(`Invalid base commit sha: ${JSON.stringify(sha)}`);
  }
}

/**
 * The last check before a path becomes a tree entry.
 *
 * The blast radius has already refused anything outside the permitted write
 * set, and the diff policy has inspected the paths again. This is the third
 * reading, and it is here because the first two answer "may we write this
 * file?" while this one answers "is this a file path at all?" — `.git/config`
 * and `../../etc` are refused on their shape, whatever the radius said.
 */
function assertRepositoryPath(path: string): void {
  const segments = path.split("/");
  const invalid =
    path.length === 0 ||
    path.length > 400 ||
    path.startsWith("/") ||
    path.includes("\\") ||
    path.includes("\0") ||
    segments.some((segment) => segment === "" || segment === "." || segment === "..") ||
    segments[0] === ".git";
  if (invalid) throw new ForgeError(`Refusing to write path: ${JSON.stringify(path)}`);
}
