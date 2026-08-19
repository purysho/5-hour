import { describe, expect, it, vi } from "vitest";
import {
  detectChangesWorkflow,
  type DetectDeps,
  type DetectInput,
  type DetectOutcome,
  type RecordedChange,
  type SurfaceSource,
} from "../../src/workflows/detect-changes.ts";
import { NpmCollector, type HttpClient, type HttpResponse } from "../../src/detect/npm.ts";
import type { ApiSurface, ExportedSymbol } from "../../src/detect/api-surface.ts";
import { PermanentFailure, type WorkflowContext } from "../../src/workflow/types.ts";

/**
 * The detection sweep.
 *
 * The front of the pipeline, and the cheapest place to stop a bad change. Its
 * most important behaviour is negative: it must produce nothing when the
 * evidence does not support acting, and it must never approve its own output.
 */

const REGISTRY = "https://registry.npmjs.org";

/** Minimal in-memory workflow context. Steps run once and memoise, as in production. */
function testContext(): WorkflowContext & { stepKeys: string[] } {
  const results = new Map<string, unknown>();
  const stepKeys: string[] = [];
  return {
    jobId: "job-1",
    providerId: "11111111-1111-4111-8111-111111111111",
    attempt: 1,
    stepKeys,
    async step<T>(key: string, fn: () => Promise<T>): Promise<T> {
      if (results.has(key)) return results.get(key) as T;
      stepKeys.push(key);
      const value = await fn();
      results.set(key, value);
      return value;
    },
    async heartbeat() {},
    log() {},
  };
}

function stubHttp(body: unknown): HttpClient {
  return {
    async get(url: string): Promise<HttpResponse> {
      if (url === `${REGISTRY}/acme-sdk`) {
        return { status: 200, body: JSON.stringify(body) };
      }
      return { status: 404, body: "{}" };
    },
  };
}

function versionEntry(version: string) {
  return {
    version,
    dist: {
      tarball: `${REGISTRY}/acme-sdk/-/acme-sdk-${version}.tgz`,
      integrity: `sha512-${"x".repeat(64)}`,
    },
  };
}

function symbol(name: string, overrides: Partial<ExportedSymbol> = {}): ExportedSymbol {
  return { name, kind: "function", signature: "(): void", ...overrides };
}

function surfaceSource(
  surfaces: Record<string, ExportedSymbol[] | null>,
): SurfaceSource {
  return {
    async surfaceFor(packageName, version): Promise<ApiSurface | null> {
      const symbols = surfaces[version];
      if (symbols === undefined || symbols === null) return null;
      return { packageName, version, symbols };
    },
  };
}

function deps(
  overrides: Partial<DetectDeps> = {},
  recorded: RecordedChange[] = [],
): DetectDeps {
  return {
    collector: new NpmCollector(
      stubHttp({
        name: "acme-sdk",
        versions: { "2.9.1": versionEntry("2.9.1"), "3.0.0": versionEntry("3.0.0") },
      }),
    ),
    // Signature change, not a removal: breaking, but mechanically migratable.
    // A removal would correctly be held for human guidance (tested below), so
    // it is the wrong default for exercising the eligible path.
    surfaces: surfaceSource({
      "2.9.1": [symbol("createClient", { signature: "(url: string): Client" })],
      "3.0.0": [symbol("createClient", { signature: "(options: Options): Client" })],
    }),
    recorder: {
      async record(input) {
        recorded.push(input);
        return `change-${recorded.length}`;
      },
    },
    downstreamCount: async () => 400,
    ...overrides,
  };
}

const INPUT: DetectInput = {
  packageName: "acme-sdk",
  currentVersion: "2.9.1",
  ecosystem: "npm",
};

async function run(
  d: DetectDeps,
  input: DetectInput = INPUT,
  ctx = testContext(),
): Promise<DetectOutcome> {
  return (await detectChangesWorkflow(d)(ctx, input)) as DetectOutcome;
}

describe("a well-corroborated change", () => {
  it("is recorded and reported eligible", async () => {
    const recorded: RecordedChange[] = [];
    const outcome = await run(deps({}, recorded));

    expect(outcome.kind).toBe("eligible");
    if (outcome.kind !== "eligible") return;
    expect(outcome.toVersion).toBe("3.0.0");
    expect(outcome.changeKey).toBe("acme-sdk@3.0.0");
    expect(recorded).toHaveLength(1);
    expect(recorded[0]?.corroborations.map((c) => c.kind).sort()).toEqual([
      "artifact",
      "registry",
      "spec",
    ]);
  });

  it("never approves its own output", async () => {
    // A change reaches fan-out only after a human approves it, and this
    // workflow is not a human. Self-approval would collapse the §5.2 defence
    // into a formality.
    const recorded: RecordedChange[] = [];
    const outcome = await run(deps({}, recorded));

    expect(recorded[0]?.approvedAt).toBeNull();
    if (outcome.kind !== "eligible") return;
    expect(outcome.requiresApproval).toBe(true);
  });

  it("does not fan out — it sizes a canary and stops", async () => {
    // Detecting and acting in one step would make a detection bug a fan-out
    // incident with no gate between them.
    const outcome = await run(deps({ downstreamCount: async () => 5000 }));
    if (outcome.kind !== "eligible") return;
    expect(outcome.canarySize).toBeGreaterThan(0);
    expect(outcome.canarySize).toBeLessThanOrEqual(25);
  });

  it("carries the impacted symbols forward for blast radius derivation", async () => {
    const outcome = await run(deps());
    if (outcome.kind !== "eligible") return;
    expect(outcome.impactedSymbols).toContain("createClient");
  });
});

describe("changes that must not proceed", () => {
  it("stops when there is no newer stable version", async () => {
    const outcome = await run(
      deps({
        collector: new NpmCollector(
          stubHttp({ name: "acme-sdk", versions: { "2.9.1": versionEntry("2.9.1") } }),
        ),
      }),
    );
    expect(outcome.kind).toBe("no-newer-version");
  });

  it("ignores a prerelease as a migration target", async () => {
    // We do not move anyone onto an unreleased version, however loudly it is
    // announced.
    const outcome = await run(
      deps({
        collector: new NpmCollector(
          stubHttp({
            name: "acme-sdk",
            versions: {
              "2.9.1": versionEntry("2.9.1"),
              "3.0.0-rc.1": versionEntry("3.0.0-rc.1"),
            },
          }),
        ),
      }),
    );
    expect(outcome.kind).toBe("no-newer-version");
  });

  it("declines when the surface did not actually change", async () => {
    // Registry and artifact call it breaking; the interface disagrees. Hard
    // sources disagreeing means we do not understand the change.
    const outcome = await run(
      deps({
        surfaces: surfaceSource({
          "2.9.1": [symbol("createClient")],
          "3.0.0": [symbol("createClient")],
        }),
      }),
    );
    expect(outcome.kind).toBe("not-eligible");
    if (outcome.kind !== "not-eligible") return;
    expect(outcome.reason).toBe("sources-disagree");
  });

  it("holds a migration whose exports were removed for human guidance", async () => {
    // Something must take a removed export's place and only the publisher
    // knows what. Generating a plausible-looking wrong migration is worse than
    // generating none.
    const outcome = await run(
      deps({
        surfaces: surfaceSource({
          "2.9.1": [symbol("createClient"), symbol("close")],
          "3.0.0": [symbol("close")],
        }),
      }),
    );
    expect(outcome.kind).toBe("not-eligible");
    if (outcome.kind !== "not-eligible") return;
    expect(outcome.reason).toBe("capability-requires-approval");
  });

  it("records an ineligible change rather than discarding it", async () => {
    // Keeps us from re-examining it every sweep, and is the evidence trail if
    // someone later asks why we did nothing.
    const recorded: RecordedChange[] = [];
    await run(
      deps(
        {
          surfaces: surfaceSource({
            "2.9.1": [symbol("createClient")],
            "3.0.0": [symbol("createClient")],
          }),
        },
        recorded,
      ),
    );
    expect(recorded).toHaveLength(1);
    expect(recorded[0]?.summary).toContain("not eligible");
    expect(recorded[0]?.approvedAt).toBeNull();
  });

  it("keeps describing the change in the summary of one it declined", async () => {
    // `summary` is the only prose description of an upstream change this
    // system keeps, and `migrate-repository` hands it to the agent verbatim as
    // `changeSummary`. A decline that overwrote it left the agent prompted
    // with a gate label instead of a change — and `capability-requires-approval`
    // is exactly the decline a human overturns with `db:approve`, so the
    // description has to still be there when the rollout finally runs.
    const recorded: RecordedChange[] = [];
    await run(
      deps(
        {
          surfaces: surfaceSource({
            "2.9.1": [symbol("createClient"), symbol("close")],
            "3.0.0": [symbol("close")],
          }),
        },
        recorded,
      ),
    );
    const summary = recorded[0]?.summary ?? "";
    expect(summary).toContain("acme-sdk 2.9.1 → 3.0.0");
    expect(summary).toContain("createClient");
    expect(summary).toContain("not eligible: capability-requires-approval");
  });
});

describe("missing evidence", () => {
  it("loses a source rather than inventing one when declarations are absent", async () => {
    // Plenty of packages ship no type declarations. Registry plus artifact
    // still clears the bar, at moderate confidence rather than high.
    const outcome = await run(
      deps({ surfaces: surfaceSource({ "2.9.1": null, "3.0.0": null }) }),
    );
    expect(outcome.kind).toBe("eligible");
    if (outcome.kind !== "eligible") return;
    expect(outcome.confidence).toBe("moderate");
    expect(outcome.impactedSymbols).toEqual([]);
  });

  it("reaches high confidence when all three sources agree", async () => {
    const outcome = await run(deps());
    if (outcome.kind !== "eligible") return;
    expect(outcome.confidence).toBe("high");
  });
});

describe("input validation", () => {
  it("fails permanently on a package name that is a traversal attempt", async () => {
    // A malformed name is a bug or an injection attempt, and neither improves
    // with a retry — so it must not consume the retry budget.
    await expect(
      run(deps(), { ...INPUT, packageName: "../../etc/passwd" }),
    ).rejects.toThrow(PermanentFailure);
  });

  it("fails permanently on an unparseable current version", async () => {
    await expect(run(deps(), { ...INPUT, currentVersion: "latest" })).rejects.toThrow(
      PermanentFailure,
    );
  });

  it("validates before making any network call", async () => {
    const get = vi.fn();
    await expect(
      run(deps({ collector: new NpmCollector({ get }) }), {
        ...INPUT,
        packageName: "../evil",
      }),
    ).rejects.toThrow(PermanentFailure);
    expect(get).not.toHaveBeenCalled();
  });
});

describe("durability", () => {
  it("puts every external call inside a step", async () => {
    const ctx = testContext();
    await run(deps(), INPUT, ctx);
    expect(ctx.stepKeys).toEqual([
      "find-next-version",
      "corroborate-registry",
      "corroborate-artifact",
      "corroborate-surface",
      "record-change",
      "count-downstream",
    ]);
  });

  it("does not re-run completed steps on replay", async () => {
    // A sweep that dies partway through resumes rather than re-querying
    // registries it has already read.
    const ctx = testContext();
    const recorded: RecordedChange[] = [];
    const d = deps({}, recorded);

    await run(d, INPUT, ctx);
    const stepsAfterFirst = [...ctx.stepKeys];
    await run(d, INPUT, ctx);

    expect(ctx.stepKeys).toEqual(stepsAfterFirst);
    expect(recorded).toHaveLength(1);
  });

  it("isolates each source in its own step", async () => {
    // A registry that times out must not cost us the artifact check we already
    // completed.
    const ctx = testContext();
    await run(deps(), INPUT, ctx);
    expect(ctx.stepKeys).toContain("corroborate-registry");
    expect(ctx.stepKeys).toContain("corroborate-artifact");
    expect(ctx.stepKeys).toContain("corroborate-surface");
  });
});
