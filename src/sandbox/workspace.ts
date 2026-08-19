/**
 * A working tree for verification.
 *
 * The blocker named in `gvisor-verifier.ts`: running a repository's test suite
 * needs a real directory with the migration applied, and nothing upstream had
 * one to give. `migrate-repository` reads the blast-radius files through the
 * forge API and never materialises anything, so verification could not be
 * written at all — not because the sandbox was missing, but because there was
 * nothing to mount into it.
 *
 * ── Why this clones rather than writing out what the agent had ───────────────
 *
 * The agent is shown the blast radius, not the repository. A tree built from
 * those files alone is missing every module they import, every fixture the
 * suite reads and the lockfile the install needs, so the suite fails for
 * reasons that have nothing to do with the migration — which is worse than not
 * running it, because it looks like a verdict.
 *
 * So the checkout is real, and the migration is overlaid onto it.
 *
 * ── Overlaid from bytes, never by applying the diff ──────────────────────────
 *
 * `AppliedPlan.files` carries the post-migration contents, and `edit-plan.ts`
 * explains why they are carried rather than discarded: re-deriving content by
 * applying the diff would make git's reading and the policy engine's reading
 * two separate interpretations of the same text, and any gap between them is a
 * gap an injection can be aimed at. That reasoning applies here unchanged —
 * the tree that gets tested must be the same bytes the policy engine
 * inspected, so this module never parses a diff.
 *
 * ── The token is never written to disk ───────────────────────────────────────
 *
 * A clone needs a credential and the obvious places to put one — the remote
 * URL, a .git-credentials file — both persist it inside a tree that untrusted
 * code is about to run in. It goes in a header on the command line for the
 * clone only, and the remote is rewritten to a URL carrying no credential
 * before anything else touches the directory.
 */

import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, normalize, resolve, sep } from "node:path";

export class WorkspaceError extends Error {
  override readonly name = "WorkspaceError";
}

export interface WorkspaceFile {
  readonly path: string;
  readonly content: string;
}

/** Runs a command. Injected so the clone is testable without a network. */
export interface CommandRunner {
  run(
    command: string,
    args: readonly string[],
    options: { cwd: string; timeoutMs: number },
  ): Promise<{ code: number; stdout: string; stderr: string }>;
}

export interface CheckoutRequest {
  /** https URL of the repository. Never carries a credential. */
  readonly url: string;
  /** Branch or commit to verify against. */
  readonly ref: string;
  /**
   * Installation token, used for exactly one command and never persisted.
   * Optional: a public repository needs none, and asking for one anyway would
   * mint a credential we do not need (ADR-0002 mints per job).
   */
  readonly token?: string | undefined;
}

export interface MaterialiseOptions {
  readonly checkout: CheckoutRequest;
  /** Post-migration contents. Overlaid onto the checkout. */
  readonly overlay: readonly WorkspaceFile[];
  readonly runner: CommandRunner;
  readonly timeoutMs?: number;
  /** Parent directory for the temporary tree. Defaults to the system temp. */
  readonly root?: string;
}

export interface Workspace {
  /** Absolute path to the tree. */
  readonly path: string;
  /** Removes the tree. Safe to call twice. */
  dispose(): Promise<void>;
}

const DEFAULT_TIMEOUT_MS = 120_000;

/**
 * Rejects a path that would write outside the workspace.
 *
 * The paths come from a model proposal. `applyEditPlan` already refuses edits
 * outside the blast radius, so this is the second of two checks rather than
 * the only one — but it is the one standing between a traversal and the
 * filesystem, and defence that only exists one layer up is defence that a
 * refactor can delete without a test failing.
 */
export function assertWithinWorkspace(workspacePath: string, filePath: string): string {
  if (isAbsolute(filePath)) {
    throw new WorkspaceError(`refusing absolute path in overlay: ${filePath}`);
  }
  if (filePath.includes("\0")) {
    throw new WorkspaceError("refusing path containing a null byte");
  }

  const target = resolve(workspacePath, normalize(filePath));
  const boundary = resolve(workspacePath) + sep;
  if (!target.startsWith(boundary)) {
    throw new WorkspaceError(`refusing path outside the workspace: ${filePath}`);
  }
  // `.git` is the one in-tree directory where a write changes what the *host*
  // does with this checkout rather than what the suite does — hooks run on
  // ordinary git commands, and config can redirect a remote.
  const relative = target.slice(boundary.length);
  if (relative === ".git" || relative.startsWith(`.git${sep}`)) {
    throw new WorkspaceError(`refusing to overlay onto .git: ${filePath}`);
  }
  return target;
}

export async function materialiseWorkspace(options: MaterialiseOptions): Promise<Workspace> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const parent = options.root ?? tmpdir();
  const path = await mkdtemp(join(parent, "driftless-verify-"));

  const dispose = async () => {
    await rm(path, { recursive: true, force: true }).catch(() => {
      // Best effort. A workspace that outlives its job is a disk-space
      // problem; throwing here would turn it into a failed migration.
    });
  };

  try {
    // --depth 1 against an explicit ref: history is not what a test suite
    // reads, and a shallow clone of a large repository is the difference
    // between verification being affordable and being skipped.
    const args = [
      "-c",
      // Submodules would fetch and then execute code from repositories the
      // customer did not grant us, so they are never initialised.
      "protocol.file.allow=never",
      ...(options.checkout.token
        ? [
            "-c",
            `http.extraheader=Authorization: Bearer ${options.checkout.token}`,
          ]
        : []),
      "clone",
      "--depth",
      "1",
      "--no-tags",
      "--single-branch",
      "--branch",
      options.checkout.ref,
      options.checkout.url,
      ".",
    ];

    const clone = await options.runner.run("git", args, { cwd: path, timeoutMs });
    if (clone.code !== 0) {
      // The token can appear in git's own error output. Reported without it.
      throw new WorkspaceError(
        `clone failed (exit ${clone.code}): ${redact(clone.stderr, options.checkout.token)}`,
      );
    }

    for (const file of options.overlay) {
      const target = assertWithinWorkspace(path, file.path);
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, file.content, "utf8");
    }

    return { path, dispose };
  } catch (error) {
    await dispose();
    throw error;
  }
}

function redact(text: string, token: string | undefined): string {
  if (!token) return text;
  return text.split(token).join("[REDACTED]");
}
