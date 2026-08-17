import { describe, expect, it } from "vitest";
import { GVisorVerifier } from "../../src/sandbox/gvisor-verifier.ts";
import type { RepositoryContext } from "../../src/workflows/migrate-repository.ts";

describe("GVisorVerifier", () => {
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

  it("implements the Verifier interface", async () => {
    const verifier = new GVisorVerifier();
    const result = await verifier.verify(input);

    expect(result).toHaveProperty("tests");
    expect(result).toHaveProperty("command");
    expect(["passed", "failed", "not-run", "error"]).toContain(result.tests);
  });

  it("returns not-run when sandbox is not implemented", async () => {
    const verifier = new GVisorVerifier();
    const result = await verifier.verify(input);

    expect(result.tests).toBe("not-run");
    expect(result.command).toBeNull();
  });

  it("reports duration when available", async () => {
    const verifier = new GVisorVerifier();
    const result = await verifier.verify(input);

    if (result.durationSeconds !== undefined) {
      expect(typeof result.durationSeconds).toBe("number");
      expect(result.durationSeconds).toBeGreaterThanOrEqual(0);
    }
  });

  it("accepts optional test command", () => {
    const verifier = new GVisorVerifier({ testCommand: "pnpm test" });
    expect(verifier).toBeDefined();
  });

  it("accepts optional timeout", () => {
    const verifier = new GVisorVerifier({ timeoutMs: 60_000 });
    expect(verifier).toBeDefined();
  });

  it("accepts optional logger", async () => {
    const logs: Array<[string, Record<string, unknown>]> = [];
    const verifier = new GVisorVerifier({
      log: (event, detail) => logs.push([event, detail]),
    });

    await verifier.verify(input);

    expect(logs.length).toBeGreaterThan(0);
    expect(logs.some(([event]) => event.includes("sandbox"))).toBe(true);
  });
});
