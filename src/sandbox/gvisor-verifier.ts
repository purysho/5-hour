/**
 * Test verification inside gVisor sandbox.
 *
 * Runs the repository's test suite against the migration diff inside a gVisor
 * sandbox, which provides OS-level isolation from the control plane. The result
 * is reported honestly: passed, failed, or timed out.
 *
 * ── Why gVisor ──────────────────────────────────────────────────────────────
 *
 * gVisor (open source, CNCF) is a sandbox runtime that intercepts syscalls and
 * runs them in userspace. It provides strong isolation (prevents container
 * breakout, limits resource access) without requiring kernel hypervisor
 * features (KVM, nested virt). Proven at scale by Google Cloud Run, Fly.io,
 * and others. Trade-off: ~20% slower than native execution.
 *
 * Alternative would have been Firecracker (faster) but requires host KVM
 * support and is harder to bootstrap a rootfs for. Managed runners are free
 * of infrastructure burden but cost real money per run.
 */

import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Verifier, VerificationResult } from "../agent/claude-migration-agent.ts";
import type { RepositoryContext } from "../workflows/migrate-repository.ts";

const DEFAULT_TIMEOUT_MS = 300_000; // 5 minutes

/**
 * Detects the test command for the repository by looking for common indicators.
 * Returns null if no test script is found (in which case verification is "not-run").
 *
 * Tries to find test commands in this order:
 * 1. package.json "test" script
 * 2. Makefile `test` target
 * 3. shell scripts (test.sh, runtests.sh, etc.)
 */
export function detectTestCommand(repository: RepositoryContext): string | null {
  // The repository is loaded but we don't have the file contents here.
  // In practice, this would be called with the loaded manifest.
  // For now, return null and let callers pass it explicitly.
  return null;
}

/**
 * Runs a test command inside a gVisor sandbox.
 *
 * Spawns a gVisor container with a minimal rootfs, copies the migrated
 * repository into it, installs dependencies, and runs the test command.
 *
 * Returns the result: passed/failed/not-run along with the command used
 * and duration.
 *
 * Not yet implemented: this requires gVisor to be installed on the host,
 * which is a prerequisite for the worker environment. For now, returns
 * "not-run" to maintain honest reporting (ADR-0006).
 */
export class GVisorVerifier implements Verifier {
  readonly #timeoutMs: number;
  readonly #testCommand: string | undefined;
  readonly #log: (event: string, detail: Record<string, unknown>) => void;

  constructor(options?: {
    /**
     * Optional test command to run. If not provided, detectTestCommand is used
     * and verification returns "not-run" if no standard script is found.
     */
    testCommand?: string;
    /** Timeout in milliseconds. Default 5 minutes. */
    timeoutMs?: number;
    log?: (event: string, detail: Record<string, unknown>) => void;
  }) {
    this.#testCommand = options?.testCommand;
    this.#timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.#log = options?.log ?? (() => {});
  }

  async verify(input: {
    repository: RepositoryContext;
    diff: string;
    changedPaths: readonly string[];
  }): Promise<VerificationResult> {
    const startTime = Date.now();

    try {
      // TODO(P3): Implement gVisor sandbox setup
      // For now, return "not-run" to match current behavior while placeholder is built
      // This ensures migrations report honestly that tests were not run
      this.#log("sandbox.not_implemented", {
        reason: "gVisor sandbox infrastructure not yet deployed",
        repository: input.repository.forgeOwner,
        changedPaths: input.changedPaths,
        configuredTimeout: this.#timeoutMs,
      });

      // When implemented, would call runInGVisor here:
      // const result = await runInGVisor({
      //   rootfs: "/opt/driftless/rootfs",
      //   repository: createTemporaryClone(input),
      //   command: this.#testCommand ?? detectTestCommand(...),
      //   timeoutMs: this.#timeoutMs,
      // });

      return {
        tests: "not-run",
        command: this.#testCommand ?? null,
      };
    } catch (error) {
      this.#log("sandbox.verification_error", {
        error: error instanceof Error ? error.message : String(error),
      });
      // On error, report not-run rather than failing the migration.
      // An infrastructure problem should not burn retry budget.
      return {
        tests: "not-run",
        command: this.#testCommand ?? null,
      };
    }
  }
}

/**
 * Spawns a gVisor container with the given rootfs, mounts the repository,
 * and runs the test command.
 *
 * @returns Exit code (0 = passed, non-zero = failed), stdout, stderr
 */
async function runInGVisor(input: {
  rootfs: string;
  repository: string;
  command: string;
  timeoutMs: number;
}): Promise<{
  exitCode: number;
  stdout: string;
  stderr: string;
  durationSeconds: number;
}> {
  // Placeholder: would use runsc or crun-gvisor here
  // Actual implementation would:
  // 1. Create a bundle directory for gVisor (OCI image format)
  // 2. Run: runsc run --rootfs=<rootfs> --bundle=<bundle> <container-id>
  // 3. Execute test command inside
  // 4. Capture output and exit code
  // 5. Clean up

  const startTime = Date.now();
  const tempDir = await mkdtemp(join(tmpdir(), "gvisor-"));

  try {
    // Temporary stub: just return not-run result
    // This is the honest position while the infrastructure is being set up
    const durationSeconds = (Date.now() - startTime) / 1000;

    return {
      exitCode: 0,
      stdout: "",
      stderr: "gVisor sandbox implementation pending",
      durationSeconds,
    };
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}
