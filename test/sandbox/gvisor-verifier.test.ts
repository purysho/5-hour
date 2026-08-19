import { describe, expect, it } from "vitest";
import {
  DEFAULT_TIMEOUT_MS,
  GVisorVerifier,
  detectTestCommand,
  isSandboxAvailable,
} from "../../src/sandbox/gvisor-verifier.ts";
import type { RepositoryContext } from "../../src/workflows/migrate-repository.ts";

const repository: RepositoryContext = {
  forgeOwner: "owner",
  forgeName: "repo",
  forgeRepositoryId: 123,
  forgeInstallationId: 456,
  defaultBranch: "main",
  knownHosts: [],
};

const input = {
  repository,
  diff: "--- a/src/index.ts\n+++ b/src/index.ts\n@@ -1 +1 @@\n-old\n+new\n",
  changedPaths: ["src/index.ts"] as const,
  files: [] as const,
};

describe("detectTestCommand", () => {
  it("finds the declared test script", () => {
    expect(detectTestCommand(JSON.stringify({ scripts: { test: "vitest run" } }))).toBe(
      "vitest run",
    );
  });

  it("trims surrounding whitespace", () => {
    expect(detectTestCommand(JSON.stringify({ scripts: { test: "  pnpm test  " } }))).toBe(
      "pnpm test",
    );
  });

  it("ignores the placeholder npm init writes", () => {
    // Running this would exit 1 by design, and the pull request would say the
    // repository's tests broke. They do not exist.
    const manifest = JSON.stringify({
      scripts: { test: 'echo "Error: no test specified" && exit 1' },
    });
    expect(detectTestCommand(manifest)).toBeNull();
  });

  it("returns null when there is no test script", () => {
    expect(detectTestCommand(JSON.stringify({ scripts: { build: "tsc" } }))).toBeNull();
  });

  it("returns null when there are no scripts at all", () => {
    expect(detectTestCommand(JSON.stringify({ name: "widgets" }))).toBeNull();
  });

  it("returns null for an empty test script", () => {
    expect(detectTestCommand(JSON.stringify({ scripts: { test: "   " } }))).toBeNull();
  });

  it("returns null rather than throwing on unparseable input", () => {
    expect(detectTestCommand("{ not json")).toBeNull();
  });

  it("survives a manifest that is valid JSON but not an object", () => {
    for (const source of ["null", "[]", '"a string"', "42"]) {
      expect(detectTestCommand(source), source).toBeNull();
    }
  });

  it("survives non-string and non-object script fields", () => {
    expect(detectTestCommand(JSON.stringify({ scripts: "vitest" }))).toBeNull();
    expect(detectTestCommand(JSON.stringify({ scripts: { test: 42 } }))).toBeNull();
    expect(detectTestCommand(JSON.stringify({ scripts: null }))).toBeNull();
  });
});

describe("isSandboxAvailable", () => {
  it("finds runsc on the path", async () => {
    const checked: string[] = [];
    const available = await isSandboxAvailable({
      path: "/usr/bin:/opt/gvisor/bin",
      canExecute: async (candidate) => {
        checked.push(candidate);
        return candidate === "/opt/gvisor/bin/runsc";
      },
    });

    expect(available).toBe(true);
    expect(checked).toContain("/usr/bin/runsc");
  });

  it("reports unavailable when runsc is absent", async () => {
    expect(
      await isSandboxAvailable({ path: "/usr/bin:/bin", canExecute: async () => false }),
    ).toBe(false);
  });

  it("handles an empty path", async () => {
    expect(await isSandboxAvailable({ path: "", canExecute: async () => true })).toBe(false);
  });

  it("skips empty path segments", async () => {
    const checked: string[] = [];
    await isSandboxAvailable({
      path: "/usr/bin::/bin",
      canExecute: async (candidate) => {
        checked.push(candidate);
        return false;
      },
    });

    expect(checked).toEqual(["/usr/bin/runsc", "/bin/runsc"]);
  });

  it("does not find runsc on this host", async () => {
    // The real probe, against the real PATH. gVisor is not installed in the
    // test environment; if this ever starts passing, the verifier's reported
    // prerequisites change and the assertion below should be revisited.
    expect(await isSandboxAvailable()).toBe(false);
  });
});

describe("GVisorVerifier", () => {
  const unavailable = { sandboxAvailable: async () => false };

  it("implements the Verifier interface", async () => {
    const result = await new GVisorVerifier(unavailable).verify(input);

    expect(result).toHaveProperty("tests");
    expect(result).toHaveProperty("command");
    // The four outcomes the shared TestOutcome type actually has. The previous
    // version of this test also listed "error", which is not one of them, so
    // it would have accepted a value the type forbids.
    expect(["passed", "failed", "not-run", "no-suite"]).toContain(result.tests);
  });

  it("reports not-run when the host cannot sandbox", async () => {
    // Never a fallback to running the suite on the host: that is executing
    // attacker-authored code beside the control plane, and a `passed` obtained
    // that way is worth less than no verification (ADR-0006).
    const result = await new GVisorVerifier(unavailable).verify(input);
    expect(result.tests).toBe("not-run");
  });

  it("reports no command, even when one is configured", async () => {
    // `command` means "the command we ran". Naming one beside `not-run` would
    // imply an attempt that never happened.
    const result = await new GVisorVerifier({ ...unavailable, testCommand: "pnpm test" }).verify(
      input,
    );

    expect(result.command).toBeNull();
  });

  it("names every missing prerequisite when nothing is provisioned", async () => {
    const logs: Array<[string, Record<string, unknown>]> = [];
    await new GVisorVerifier({
      sandboxAvailable: async () => false,
      log: (event, detail) => logs.push([event, detail]),
    }).verify(input);

    const entry = logs.find(([event]) => event === "sandbox.not_run");
    expect(entry).toBeDefined();
    // Each is independently fixable, and a deployment should be told which
    // one it is missing rather than "verification is off".
    expect(entry![1]["missing"]).toEqual(["runsc", "rootfs", "runner", "checkout"]);
    expect(entry![1]["repository"]).toBe("owner/repo");
  });

  it("stops naming runsc once it is present", async () => {
    const logs: Array<[string, Record<string, unknown>]> = [];
    await new GVisorVerifier({
      sandboxAvailable: async () => true,
      log: (event, detail) => logs.push([event, detail]),
    }).verify(input);

    // A worker with gVisor installed but nothing else configured should be
    // told what remains, rather than being blamed for the part it fixed.
    expect(logs.find(([event]) => event === "sandbox.not_run")![1]["missing"]).toEqual([
      "rootfs",
      "runner",
      "checkout",
    ]);
  });

  it("treats a probe failure as unavailable rather than raising", async () => {
    // An infrastructure fault must not burn the migration's retry budget.
    const logs: Array<[string, Record<string, unknown>]> = [];
    const result = await new GVisorVerifier({
      sandboxAvailable: async () => {
        throw new Error("permission denied reading PATH");
      },
      log: (event, detail) => logs.push([event, detail]),
    }).verify(input);

    expect(result.tests).toBe("not-run");
    expect(logs.some(([event]) => event === "sandbox.probe_failed")).toBe(true);
    expect(logs.find(([event]) => event === "sandbox.not_run")![1]["missing"]).toContain("runsc");
  });

  it("reports a non-Error probe failure without crashing", async () => {
    const logs: Array<[string, Record<string, unknown>]> = [];
    await new GVisorVerifier({
      sandboxAvailable: async () => {
        throw "nope";
      },
      log: (event, detail) => logs.push([event, detail]),
    }).verify(input);

    expect(logs.find(([event]) => event === "sandbox.probe_failed")![1]["error"]).toBe("nope");
  });

  it("logs the configured timeout and command", async () => {
    const logs: Array<[string, Record<string, unknown>]> = [];
    await new GVisorVerifier({
      ...unavailable,
      timeoutMs: 60_000,
      testCommand: "make test",
      log: (event, detail) => logs.push([event, detail]),
    }).verify(input);

    const detail = logs.find(([event]) => event === "sandbox.not_run")![1];
    expect(detail["configuredTimeoutMs"]).toBe(60_000);
    expect(detail["configuredTestCommand"]).toBe("make test");
  });

  it("defaults the timeout to five minutes", async () => {
    const logs: Array<[string, Record<string, unknown>]> = [];
    await new GVisorVerifier({ ...unavailable, log: (e, d) => logs.push([e, d]) }).verify(input);

    expect(logs.find(([event]) => event === "sandbox.not_run")![1]["configuredTimeoutMs"]).toBe(
      DEFAULT_TIMEOUT_MS,
    );
    expect(DEFAULT_TIMEOUT_MS).toBe(300_000);
  });

  it("constructs with no options at all", async () => {
    // The default probe touches the real filesystem; it must not throw.
    const result = await new GVisorVerifier().verify(input);
    expect(result.tests).toBe("not-run");
  });
});

/**
 * Running a suite.
 *
 * The paths that only exist now that there is a workspace to mount. gVisor
 * itself is not exercised here — there is no runsc in CI — so the runner is
 * injected and what is asserted is the decision-making around it: that a
 * verdict comes from an exit code, that our own infrastructure failing is
 * never reported as the migration failing, and that the bytes tested are the
 * bytes the policy engine inspected.
 */
describe("running the repository's suite", () => {
  const CHECKOUT = { url: "https://github.com/owner/repo.git", ref: "main" };

  /** Clones a repo with a package.json, and records every command run. */
  function harness(
    options: {
      manifest?: string;
      testExit?: number;
      installExit?: number;
      cloneExit?: number;
    } = {},
  ) {
    const commands: Array<{ command: string; args: readonly string[] }> = [];
    const written: Record<string, string> = {};
    const runner = {
      async run(command: string, args: readonly string[], opts: { cwd: string }) {
        commands.push({ command, args });
        if (command === "git") {
          if (options.cloneExit && options.cloneExit !== 0) {
            return { code: options.cloneExit, stdout: "", stderr: "fatal" };
          }
          const { mkdir, writeFile } = await import("node:fs/promises");
          const { join: j } = await import("node:path");
          await mkdir(j(opts.cwd, ".git"), { recursive: true });
          const manifest = options.manifest ?? JSON.stringify({ scripts: { test: "vitest run" } });
          await writeFile(j(opts.cwd, "package.json"), manifest, "utf8");
          // Record what the overlay lands on top of.
          await writeFile(j(opts.cwd, "src.txt"), "original", "utf8");
          return { code: 0, stdout: "", stderr: "" };
        }
        // runsc. Reads the bundle so the config can be asserted.
        const { readFile: rf } = await import("node:fs/promises");
        const { join: j } = await import("node:path");
        const bundleIndex = args.indexOf("--bundle");
        written["config"] = await rf(j(args[bundleIndex + 1]!, "config.json"), "utf8");
        const isInstall = written["config"]!.includes("npm ci");
        const code = isInstall ? (options.installExit ?? 0) : (options.testExit ?? 0);
        return { code, stdout: "", stderr: "" };
      },
    };
    return { commands, written, runner };
  }

  function verifier(h: ReturnType<typeof harness>, extra: Record<string, unknown> = {}) {
    return new GVisorVerifier({
      sandboxAvailable: async () => true,
      checkoutFor: async () => CHECKOUT,
      runner: h.runner,
      rootfsPath: "/opt/rootfs",
      ...extra,
    });
  }

  const withFiles = {
    ...input,
    files: [{ path: "src.txt", before: "original", after: "migrated" }] as const,
  };

  it("passes when the suite exits zero", async () => {
    const h = harness({ testExit: 0 });
    const result = await verifier(h).verify(withFiles);

    expect(result).toEqual({ tests: "passed", command: "vitest run" });
  });

  it("fails when the suite exits non-zero", async () => {
    const h = harness({ testExit: 1 });
    const result = await verifier(h).verify(withFiles);

    expect(result).toEqual({ tests: "failed", command: "vitest run" });
  });

  it("reports no-suite rather than passed when there is nothing to run", async () => {
    // A repository with no tests is a different fact from a verified one.
    const h = harness({ manifest: JSON.stringify({ scripts: {} }) });
    const result = await verifier(h).verify(withFiles);

    expect(result).toEqual({ tests: "no-suite", command: null });
  });

  it("reports not-run, not failed, when the clone fails", async () => {
    // Our infrastructure failing must never be rendered as the migration
    // breaking the customer's tests.
    const h = harness({ cloneExit: 128 });
    const result = await verifier(h).verify(withFiles);

    expect(result.tests).toBe("not-run");
  });

  it("reports not-run, not failed, when the install fails", async () => {
    // Most likely cause is the egress policy we have not built, which is our
    // problem and not the diff's.
    const h = harness({ installExit: 1 });
    const result = await verifier(h, { installCommand: "npm ci" }).verify(withFiles);

    expect(result.tests).toBe("not-run");
  });

  it("runs the install inside the sandbox, never on the host", async () => {
    // An install executes lifecycle scripts — arbitrary code from the
    // dependency tree.
    const h = harness({});
    await verifier(h, { installCommand: "npm ci" }).verify(withFiles);

    const hostCommands = h.commands.filter((c) => c.command !== "runsc" && c.command !== "git");
    expect(hostCommands).toEqual([]);
    expect(h.commands.filter((c) => c.command === "runsc")).toHaveLength(2);
  });

  it("gives the test run no network", async () => {
    const h = harness({});
    await verifier(h).verify(withFiles);

    const config = JSON.parse(h.written["config"]!);
    expect(config.linux.namespaces).toContainEqual({ type: "network" });
  });

  it("does not clone without a checkout, and says so", async () => {
    const h = harness({});
    const result = await verifier(h, { checkoutFor: async () => null }).verify(withFiles);

    expect(result.tests).toBe("not-run");
    expect(h.commands).toEqual([]);
  });
});
