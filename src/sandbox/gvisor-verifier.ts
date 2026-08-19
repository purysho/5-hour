/**
 * Test verification inside a gVisor sandbox.
 *
 * ── What this does today ─────────────────────────────────────────────────────
 *
 * Given a sandbox and somewhere to clone from, it materialises the repository,
 * overlays the migration, and runs the repository's own suite inside gVisor.
 * Given either of those missing, it reports `not-run` and names what was
 * missing — per migration, not once in a boot log.
 *
 * It never falls back to running the suite outside the sandbox. That would be
 * executing attacker-authored code beside the control plane, and a `passed`
 * obtained that way is worth less than no verification at all (ADR-0006).
 *
 * ── What is verified where ───────────────────────────────────────────────────
 *
 * The three prerequisites named by the previous version of this file were:
 *
 *   1. A workspace — a real directory with the migration applied. Built now,
 *      in ./workspace.ts, by cloning and overlaying the post-migration bytes.
 *   2. `runsc` on the host, plus a rootfs (docs/SANDBOX_SETUP.md).
 *   3. An egress-proxied network namespace for the dependency install —
 *      `DEFAULT_EGRESS_ALLOWLIST` in ./environment.ts is the policy it should
 *      enforce.
 *
 * (1) is done. (2) and (3) are host provisioning, and this file cannot assert
 * them: the bundle it builds is deny-by-default (./oci.ts) and the process
 * that runs it is injected, so both are covered by tests with a fake runner —
 * but neither the escape properties of gVisor nor the egress policy have been
 * exercised against a real sandboxed host from here. The sandbox is probed
 * rather than assumed for exactly that reason, and a host without it gets
 * `not-run` rather than a guess.
 *
 * Because (3) is unproven, the install step runs with the network the caller
 * configures and defaults to none — so on an unprovisioned host a repository
 * with dependencies reports `not-run` from a failed install rather than
 * `failed`, which would read as the migration's fault.
 */

import { access, constants, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import type { Verifier, VerificationResult } from "../agent/claude-migration-agent.ts";
import type { FileChange } from "../agent/unified-diff.ts";
import type { RepositoryContext } from "../workflows/migrate-repository.ts";
import { buildOciConfig } from "./oci.ts";
import { buildSandboxEnvironment } from "./environment.ts";
import {
  materialiseWorkspace,
  type CheckoutRequest,
  type CommandRunner,
} from "./workspace.ts";

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
   * Overrides the repository's own `scripts.test`.
   *
   * Rarely wanted: the point is to run what the repository runs. Present for
   * a deployment that pins a command for every tenant.
   */
  readonly testCommand?: string | undefined;
  /** Timeout in milliseconds. Default five minutes. */
  readonly timeoutMs?: number | undefined;
  readonly log?: ((event: string, detail: Record<string, unknown>) => void) | undefined;
  /** Overridden in tests. Defaults to probing PATH for `runsc`. */
  readonly sandboxAvailable?: (() => Promise<boolean>) | undefined;
  /**
   * Where to clone the repository from, and with what credential.
   *
   * Injected rather than derived here because the credential is minted per job
   * (ADR-0002) and this module must not be the thing that decides when to mint
   * one. Absent, there is no workspace and the result is `not-run`.
   */
  readonly checkoutFor?:
    | ((repository: RepositoryContext) => Promise<CheckoutRequest | null>)
    | undefined;
  /** Runs a process. Injected so the bundle and argv are testable. */
  readonly runner?: CommandRunner | undefined;
  /** Absolute path to the rootfs the suite runs against (SANDBOX_SETUP.md). */
  readonly rootfsPath?: string | undefined;
  /**
   * Command that installs dependencies, run inside the sandbox before the
   * suite. Inside, because an install executes lifecycle scripts — running it
   * on the host would be the exact arbitrary execution the sandbox exists to
   * contain.
   */
  readonly installCommand?: string | undefined;
  /**
   * Whether the install step gets a network. Defaults to none, which is safe
   * and means a repository with dependencies cannot install. See the header:
   * the egress-proxied namespace is the missing piece.
   */
  readonly installNetwork?: "none" | "host" | undefined;
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
  readonly #checkoutFor:
    | ((repository: RepositoryContext) => Promise<CheckoutRequest | null>)
    | undefined;
  readonly #runner: CommandRunner | undefined;
  readonly #rootfsPath: string | undefined;
  readonly #installCommand: string | undefined;
  readonly #installNetwork: "none" | "host";

  constructor(options: GVisorVerifierOptions = {}) {
    this.#testCommand = options.testCommand;
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.#log = options.log ?? (() => {});
    this.#sandboxAvailable = options.sandboxAvailable ?? (() => isSandboxAvailable());
    this.#checkoutFor = options.checkoutFor;
    this.#runner = options.runner;
    this.#rootfsPath = options.rootfsPath;
    this.#installCommand = options.installCommand;
    this.#installNetwork = options.installNetwork ?? "none";
  }

  async verify(input: {
    repository: RepositoryContext;
    diff: string;
    changedPaths: readonly string[];
    files: readonly FileChange[];
  }): Promise<VerificationResult> {
    const repository = `${input.repository.forgeOwner}/${input.repository.forgeName}`;

    // The probe is infrastructure, and an infrastructure problem must not burn
    // a migration's retry budget — so a failure to determine availability is
    // reported as unavailable, not raised.
    const sandboxReady = await this.#sandboxAvailable().catch((error: unknown) => {
      this.#log("sandbox.probe_failed", {
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    });

    const missing: string[] = [];
    if (!sandboxReady) missing.push("runsc");
    if (!this.#rootfsPath) missing.push("rootfs");
    if (!this.#runner) missing.push("runner");
    if (!this.#checkoutFor) missing.push("checkout");

    if (missing.length > 0) {
      return this.#notRun(repository, missing, input.changedPaths.length);
    }

    const checkout = await this.#checkoutFor!(input.repository).catch((error: unknown) => {
      this.#log("sandbox.checkout_unavailable", {
        repository,
        error: error instanceof Error ? error.message : String(error),
      });
      return null;
    });
    if (!checkout) return this.#notRun(repository, ["checkout"], input.changedPaths.length);

    let workspace;
    try {
      workspace = await materialiseWorkspace({
        checkout,
        // The bytes, never the diff. See the header of ./workspace.ts.
        overlay: input.files.map((file) => ({ path: file.path, content: file.after })),
        runner: this.#runner!,
        timeoutMs: this.#timeoutMs,
      });
    } catch (error) {
      // A tree we could not build is not a failing suite. Reporting `failed`
      // here would blame the migration for our own infrastructure.
      this.#log("sandbox.workspace_failed", {
        repository,
        error: error instanceof Error ? error.message : String(error),
      });
      return { tests: "not-run", command: null };
    }

    try {
      const manifest = await readFile(join(workspace.path, "package.json"), "utf8").catch(
        () => null,
      );
      const command = this.#testCommand ?? (manifest ? detectTestCommand(manifest) : null);
      if (!command) {
        // A repository with no suite is not an unverified one. `no-suite` is a
        // different fact from `not-run`, and the pull request body says so.
        this.#log("sandbox.no_suite", { repository });
        return { tests: "no-suite", command: null };
      }

      if (this.#installCommand) {
        const install = await this.#runSandboxed(workspace.path, this.#installCommand, {
          network: this.#installNetwork,
        });
        if (install.code !== 0) {
          // An install that could not reach a registry is our missing egress
          // policy, not the migration's fault.
          this.#log("sandbox.install_failed", {
            repository,
            code: install.code,
            network: this.#installNetwork,
          });
          return { tests: "not-run", command: null };
        }
      }

      const result = await this.#runSandboxed(workspace.path, command, { network: "none" });
      this.#log("sandbox.tests_ran", { repository, command, code: result.code });

      // Only an exit code decides this. Parsing a suite's output to guess
      // whether it "really" passed is how a `passed` gets reported for a run
      // that did not.
      return { tests: result.code === 0 ? "passed" : "failed", command };
    } finally {
      await workspace.dispose();
    }
  }

  #notRun(
    repository: string,
    missing: readonly string[],
    changedPaths: number,
  ): VerificationResult {
    this.#log("sandbox.not_run", {
      missing: [...missing],
      repository,
      changedPaths,
      configuredTimeoutMs: this.#timeoutMs,
      configuredTestCommand: this.#testCommand ?? null,
    });
    // `command: null`, not the configured command. The field means "the
    // command we ran", and it is rendered as such in the pull request body;
    // naming a command beside `not-run` would imply an attempt that did not
    // happen.
    return { tests: "not-run", command: null };
  }

  /** Writes an OCI bundle for one command and runs it under `runsc`. */
  async #runSandboxed(
    workspacePath: string,
    command: string,
    options: { network: "none" | "host" },
  ): Promise<{ code: number; stdout: string; stderr: string }> {
    const bundle = await mkdtemp(join(tmpdir(), "driftless-bundle-"));
    try {
      const config = buildOciConfig({
        workspacePath,
        rootfsPath: this.#rootfsPath!,
        // `sh -c` because a package.json test script is a shell string, not an
        // argv. It is the repository's own command either way.
        command: ["/bin/sh", "-c", command],
        env: buildSandboxEnvironment({ jobId: "verify", workspace: "/work" }),
        network: options.network,
      });
      await writeFile(join(bundle, "config.json"), JSON.stringify(config, null, 2), "utf8");

      return await this.#runner!.run(
        "runsc",
        ["--bundle", bundle, "run", `driftless-${Date.now()}`],
        { cwd: bundle, timeoutMs: this.#timeoutMs },
      );
    } finally {
      await rm(bundle, { recursive: true, force: true }).catch(() => {});
    }
  }
}
