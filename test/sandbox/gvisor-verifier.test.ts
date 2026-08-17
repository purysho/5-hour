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

  it("reports not-run, because no suite is executed", async () => {
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

  it("names both missing prerequisites when runsc is absent", async () => {
    const logs: Array<[string, Record<string, unknown>]> = [];
    await new GVisorVerifier({
      sandboxAvailable: async () => false,
      log: (event, detail) => logs.push([event, detail]),
    }).verify(input);

    const entry = logs.find(([event]) => event === "sandbox.not_run");
    expect(entry).toBeDefined();
    expect(entry![1]["missing"]).toEqual(["workspace", "runsc"]);
    expect(entry![1]["repository"]).toBe("owner/repo");
  });

  it("names only the workspace when runsc is present", async () => {
    const logs: Array<[string, Record<string, unknown>]> = [];
    await new GVisorVerifier({
      sandboxAvailable: async () => true,
      log: (event, detail) => logs.push([event, detail]),
    }).verify(input);

    // The blocker that survives host provisioning. A worker with gVisor
    // installed still cannot verify, and the log should say which half is
    // missing rather than implying the deployment is at fault.
    expect(logs.find(([event]) => event === "sandbox.not_run")![1]["missing"]).toEqual([
      "workspace",
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
    expect(logs.find(([event]) => event === "sandbox.not_run")![1]["missing"]).toEqual([
      "workspace",
      "runsc",
    ]);
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
