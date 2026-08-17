/**
 * Test verification inside a gVisor sandbox.
 *
 * ── What this does today ─────────────────────────────────────────────────────
 *
 * It reports `not-run`, and it names the prerequisite it is missing when it
 * does. It does not execute a test suite, and it does not invoke gVisor. That
 * is stated here, in the boot log, and in the pull request body, because a
 * migration presented as verified when it is not is the one failure mode that
 * makes every pull request this system opens worthless (ADR-0006).
 *
 * This file previously carried a `runInGVisor` function and a
 * `detectTestCommand` that returned `null` unconditionally, neither of which
 * was reachable from anywhere. Scaffolding that reads like an implementation is
 * worse than an honest gap: it invites the reader to believe verification is
 * one wiring change away, when in fact the interface cannot express it (below).
 *
 * ── Why it cannot simply be finished ─────────────────────────────────────────
 *
 * `Verifier.verify` receives `{ repository, diff, changedPaths }`. Running a
 * test suite needs a checkout — a real directory, with the diff applied and
 * dependencies installed. None of those are reachable from this signature, and
 * no caller has one to give: `migrate-repository` works on content fetched
 * through the forge API, never a working tree.
 *
 * So real verification needs, in order:
 *
 *   1. A workspace. Something that materialises a checkout, applies the diff,
 *      and hands over a path. This is the actual blocker, and it is a change
 *      to the workflow, not to this file.
 *   2. `runsc` on the worker host, plus a rootfs (docs/SANDBOX_SETUP.md).
 *   3. An egress-proxied network namespace — `DEFAULT_EGRESS_ALLOWLIST` in
 *      ./environment.ts is the policy it should enforce.
 *
 * The two pieces that do not need a workspace are implemented and tested here:
 * test-command detection, and the sandbox availability probe. They are the
 * parts that would otherwise be written in a hurry on the day the workspace
 * lands.
 */

import { access, constants } from "node:fs/promises";
import { delimiter, join } from "node:path";
import type { Verifier, VerificationResult } from "../agent/claude-migration-agent.ts";
import type { RepositoryContext } from "../workflows/migrate-repository.ts";

/** Five minutes. A suite slower than this is not one we can gate a PR on. */
export const DEFAULT_TIMEOUT_MS = 300_000;

/**
 * `npm init` writes this. Treating it as a test suite would guarantee a
 * `failed` verdict on every repository that never replaced it — which reads,
 * in a pull request body, as "your tests broke" rather than "you have none".
 */
const NPM_PLACEHOLDER_TEST = /no test specified/i;

/**
 * The test command declared by a `package.json`, or null if it has none worth
 * running.
 *
 * Takes the manifest source rather than a `RepositoryContext`, because the
 * context does not carry file contents — the previous signature could not have
 * been implemented, which is why it never was.
 */
export function detectTestCommand(manifestSource: string): string | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(manifestSource);
  } catch {
    // A manifest we cannot parse is not a verification failure. The migration
    // is judged by policy either way, and `no-suite` is the honest report.
    return null;
  }

  if (typeof parsed !== "object" || parsed === null) return null;
  const scripts = (parsed as { scripts?: unknown }).scripts;
  if (typeof scripts !== "object" || scripts === null) return null;

  const test = (scripts as { test?: unknown }).test;
  if (typeof test !== "string") return null;

  const trimmed = test.trim();
  if (trimmed.length === 0) return null;
  if (NPM_PLACEHOLDER_TEST.test(trimmed)) return null;

  return trimmed;
}

/**
 * Whether `runsc` — the gVisor runtime — is on this host.
 *
 * Checked rather than assumed, so a worker deployed without it says so per
 * migration instead of failing test runs for a reason that has nothing to do
 * with the migration.
 */
export async function isSandboxAvailable(
  options: {
    path?: string | undefined;
    canExecute?: (candidate: string) => Promise<boolean>;
  } = {},
): Promise<boolean> {
  const path = options.path ?? process.env["PATH"] ?? "";
  const canExecute =
    options.canExecute ??
    (async (candidate: string) => {
      try {
        await access(candidate, constants.X_OK);
        return true;
      } catch {
        return false;
      }
    });

  for (const directory of path.split(delimiter)) {
    if (directory.length === 0) continue;
    if (await canExecute(join(directory, "runsc"))) return true;
  }
  return false;
}

export interface GVisorVerifierOptions {
  /**
   * Test command to run once a workspace exists. Recorded and reported; it is
   * not executed today.
   */
  readonly testCommand?: string | undefined;
  /** Timeout in milliseconds. Default five minutes. */
  readonly timeoutMs?: number | undefined;
  readonly log?: ((event: string, detail: Record<string, unknown>) => void) | undefined;
  /** Overridden in tests. Defaults to probing PATH for `runsc`. */
  readonly sandboxAvailable?: (() => Promise<boolean>) | undefined;
}

/**
 * Reports `not-run`, and logs which prerequisite is missing.
 *
 * Deliberately still a distinct type from `UNVERIFIED` rather than a copy of
 * it: this one says *why* per migration, which is what turns "verification is
 * off" from a fact buried in a boot log into something visible in the record
 * of an individual pull request.
 */
export class GVisorVerifier implements Verifier {
  readonly #timeoutMs: number;
  readonly #testCommand: string | undefined;
  readonly #log: (event: string, detail: Record<string, unknown>) => void;
  readonly #sandboxAvailable: () => Promise<boolean>;

  constructor(options: GVisorVerifierOptions = {}) {
    this.#testCommand = options.testCommand;
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.#log = options.log ?? (() => {});
    this.#sandboxAvailable = options.sandboxAvailable ?? (() => isSandboxAvailable());
  }

  async verify(input: {
    repository: RepositoryContext;
    diff: string;
    changedPaths: readonly string[];
  }): Promise<VerificationResult> {
    // The probe is the only thing here that can throw, and an infrastructure
    // problem must not burn a migration's retry budget — so a failure to
    // determine availability is reported as unavailable, not raised.
    const sandboxReady = await this.#sandboxAvailable().catch((error: unknown) => {
      this.#log("sandbox.probe_failed", {
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    });

    this.#log("sandbox.not_run", {
      // Both are reported, because they are independent and a deployment can
      // fix one without the other. `workspace` is the blocker that outlives
      // any host provisioning.
      missing: sandboxReady ? ["workspace"] : ["workspace", "runsc"],
      repository: `${input.repository.forgeOwner}/${input.repository.forgeName}`,
      changedPaths: input.changedPaths.length,
      configuredTimeoutMs: this.#timeoutMs,
      configuredTestCommand: this.#testCommand ?? null,
    });

    // `command: null`, not the configured command. The field means "the
    // command we ran", and it is rendered as such in the pull request body;
    // naming a command beside `not-run` would imply an attempt that did not
    // happen.
    return { tests: "not-run", command: null };
  }
}
