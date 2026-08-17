import { describe, expect, it } from "vitest";
import {
  planRolloutWorkflow,
  type CandidateRepository,
  type RolloutDeps,
  type RolloutOutcome,
  type StoredChange,
} from "../../src/workflows/plan-rollout.ts";
import { PermanentFailure, type WorkflowContext } from "../../src/workflow/types.ts";
import type { Corroboration } from "../../src/detect/corroborate.ts";

/**
 * Fan-out planning.
 *
 * The most dangerous workflow in the system. Every other one is scoped to a
 * single repository and fails alone; a bug here does not produce one bad pull
 * request but hundreds, simultaneously, under our name, on repositories that
 * never asked.
 *
 * So most of these tests are about refusal — what stops the fan-out, and what
 * keeps it small when it proceeds.
 */

function testContext(): WorkflowContext & { stepKeys: string[]; logs: string[] } {
  const results = new Map<string, unknown>();
  const stepKeys: string[] = [];
  const logs: string[] = [];
  return {
    jobId: "job-1",
    providerId: "11111111-1111-4111-8111-111111111111",
    attempt: 1,
    stepKeys,
    logs,
    async step<T>(key: string, fn: () => Promise<T>): Promise<T> {
      if (results.has(key)) return results.get(key) as T;
      stepKeys.push(key);
      const value = await fn();
      results.set(key, value);
      return value;
    },
    async heartbeat() {},
    log(event: string) {
      logs.push(event);
    },
  };
}

/** Two hard sources: enough weight and enough kinds to be eligible. */
const OBSERVED_AT = "2026-01-01T00:00:00Z";
const CORROBORATED: Corroboration[] = [
  {
    kind: "registry",
    breaking: true,
    detail: "major version bump",
    origin: "registry.npmjs.org",
    observedAt: OBSERVED_AT,
  },
  {
    kind: "artifact",
    breaking: true,
    detail: "export removed",
    origin: "registry.npmjs.org",
    observedAt: OBSERVED_AT,
  },
];

function change(overrides: Partial<StoredChange> = {}): StoredChange {
  return {
    changeKey: "acme-sdk@3.0.0",
    ecosystem: "npm",
    packageName: "acme-sdk",
    fromVersion: "2.9.1",
    toVersion: "3.0.0",
    corroborations: CORROBORATED,
    approvedAt: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

function repo(n: number, overrides: Partial<CandidateRepository> = {}): CandidateRepository {
  return {
    repositoryId: `repo-${n}`,
    installationId: `install-${n}`,
    forgeRepositoryId: 1000 + n,
    forgeInstallationId: 5000 + n,
    forgeOwner: "acme",
    forgeName: `widgets-${n}`,
    defaultBranch: "main",
    archived: false,
    fork: false,
    stars: n,
    ...overrides,
  };
}

const MANIFEST = JSON.stringify({
  name: "widgets",
  dependencies: { "acme-sdk": "^2.9.0" },
});

interface Enqueued {
  repositoryId: string;
  baseSha: string;
  impact: string;
  dedupeKey: string;
}

function buildDeps(overrides: Partial<RolloutDeps> = {}): {
  deps: RolloutDeps;
  enqueued: Enqueued[];
} {
  const enqueued: Enqueued[] = [];
  const deps: RolloutDeps = {
    loadChange: async () => change(),
    candidates: async () => [repo(1)],
    readManifest: async () => ({ headSha: "a".repeat(40), manifest: MANIFEST }),
    enqueueMigration: async (input) => {
      const duplicate = enqueued.some((e) => e.dedupeKey === input.dedupeKey);
      enqueued.push({
        repositoryId: input.repositoryId,
        baseSha: input.baseSha,
        impact: input.impact,
        dedupeKey: input.dedupeKey,
      });
      return { created: !duplicate };
    },
    withTenant: async (_providerId, fn) => fn({} as never),
    ...overrides,
  };
  return { deps, enqueued };
}

async function run(deps: RolloutDeps, ctx = testContext()): Promise<RolloutOutcome> {
  return planRolloutWorkflow(deps)(ctx, { changeId: "change-1" });
}

describe("the approval gate", () => {
  it("refuses to fan out a change no human approved", async () => {
    // detect-changes stops deliberately so that detecting and acting are two
    // decisions. This is the gate between them; without it a detection bug
    // becomes a fan-out incident.
    const { deps, enqueued } = buildDeps({
      loadChange: async () => change({ approvedAt: null }),
    });

    const outcome = await run(deps);

    expect(outcome).toEqual({ kind: "not-approved", changeKey: "acme-sdk@3.0.0" });
    expect(enqueued).toHaveLength(0);
  });

  it("does not treat missing approval as retryable", async () => {
    // A human will approve it or they will not. Retrying does not ask them.
    const { deps } = buildDeps({ loadChange: async () => change({ approvedAt: null }) });
    await expect(run(deps)).resolves.toMatchObject({ kind: "not-approved" });
  });

  it("checks approval before reading a single repository", async () => {
    let listed = false;
    const { deps } = buildDeps({
      loadChange: async () => change({ approvedAt: null }),
      candidates: async () => {
        listed = true;
        return [];
      },
    });

    await run(deps);
    expect(listed).toBe(false);
  });

  it("fails permanently when the change does not exist", async () => {
    const { deps } = buildDeps({ loadChange: async () => null });
    await expect(run(deps)).rejects.toBeInstanceOf(PermanentFailure);
  });
});

describe("eligibility, re-assessed", () => {
  it("refuses a change whose corroborations no longer clear the bar", async () => {
    // The stored row may predate the current corroboration policy, and this
    // is the step that spends the budget — so the policy is applied here as
    // well as at detection.
    const { deps, enqueued } = buildDeps({
      loadChange: async () =>
        change({
          corroborations: [
            {
              kind: "changelog",
              breaking: true,
              detail: "prose",
              origin: "github.com",
              observedAt: OBSERVED_AT,
            },
          ],
        }),
    });

    const outcome = await run(deps);

    expect(outcome.kind).toBe("not-eligible");
    expect(enqueued).toHaveLength(0);
  });

  it("refuses a change with no version pair rather than guessing impact", async () => {
    // Without versions, no declared range can be assessed — and a guess would
    // produce a confident wrong impact for every repository at once.
    const { deps } = buildDeps({ loadChange: async () => change({ toVersion: null }) });
    await expect(run(deps)).rejects.toThrow(/no version pair/);
  });
});

describe("choosing who to contact", () => {
  it("skips a repository that does not declare the package", async () => {
    // The credibility-destroying case: a pull request against a repository
    // that does not use the package at all.
    const { deps, enqueued } = buildDeps({
      readManifest: async () => ({
        headSha: "a".repeat(40),
        manifest: JSON.stringify({ name: "other", dependencies: { lodash: "^4.0.0" } }),
      }),
    });

    const outcome = await run(deps);

    expect(enqueued).toHaveLength(0);
    expect(outcome).toMatchObject({ kind: "planned", targeted: 0 });
  });

  it("skips a repository whose manifest cannot be read, and says so", async () => {
    const { deps, enqueued } = buildDeps({ readManifest: async () => null });

    const outcome = await run(deps);

    expect(enqueued).toHaveLength(0);
    expect(outcome).toMatchObject({
      kind: "planned",
      skipped: [{ owner: "acme", name: "widgets-1", reason: "manifest could not be read" }],
    });
  });

  it("does not let one malformed manifest end the rollout", async () => {
    // Manifests are attacker-authored (threat-model §5.1). One repository's
    // broken JSON must not deny every other repository its migration.
    const { deps, enqueued } = buildDeps({
      candidates: async () => [repo(1), repo(2)],
      readManifest: async (repository) =>
        repository.repositoryId === "repo-1"
          ? { headSha: "a".repeat(40), manifest: "{not json" }
          : { headSha: "b".repeat(40), manifest: MANIFEST },
    });

    const outcome = await run(deps);

    expect(enqueued.map((e) => e.repositoryId)).toEqual(["repo-2"]);
    expect(outcome).toMatchObject({ kind: "planned", targeted: 1 });
    expect((outcome as { skipped: readonly { reason: string }[] }).skipped[0]?.reason).toMatch(
      /unparseable/,
    );
  });

  it("skips archived repositories, where a pull request reaches nobody", async () => {
    const { deps, enqueued } = buildDeps({
      candidates: async () => [repo(1, { archived: true })],
    });

    const outcome = await run(deps);

    expect(enqueued).toHaveLength(0);
    expect((outcome as { skipped: readonly { reason: string }[] }).skipped[0]?.reason).toMatch(/archived/);
  });

  it("skips forks, since the upstream is the meaningful target", async () => {
    const { deps, enqueued } = buildDeps({ candidates: async () => [repo(1, { fork: true })] });
    await run(deps);
    expect(enqueued).toHaveLength(0);
  });

  it("uses a lockfile to sharpen the assessment when one is available", async () => {
    const { deps, enqueued } = buildDeps({
      readManifest: async () => ({
        headSha: "a".repeat(40),
        manifest: MANIFEST,
        lockfile: {
          filename: "package-lock.json",
          content: JSON.stringify({
            packages: { "node_modules/acme-sdk": { version: "2.9.1" } },
          }),
        },
      }),
    });

    await run(deps);
    expect(enqueued).toHaveLength(1);
  });
});

describe("keeping the wave small", () => {
  it("enqueues a canary rather than every target", async () => {
    // The whole point of this step is fan-out, which is exactly why it must
    // not fan out all at once.
    const candidates = Array.from({ length: 100 }, (_, i) => repo(i + 1));
    const { deps, enqueued } = buildDeps({ candidates: async () => candidates });

    const outcome = await run(deps);

    expect(outcome).toMatchObject({ kind: "planned", targeted: 100 });
    expect(enqueued.length).toBeLessThan(candidates.length);
    expect(enqueued.length).toBe((outcome as { canarySize: number }).canarySize);
  });

  it("sends the first wave to the smallest repositories", async () => {
    // A mistake on a small repository is a smaller mistake. Sending the first
    // wave to the most-watched repositories in the ecosystem is backwards.
    const candidates = [repo(1, { stars: 9000 }), repo(2, { stars: 12 }), repo(3, { stars: 400 })];
    const { deps, enqueued } = buildDeps({ candidates: async () => candidates });

    await run(deps);

    expect(enqueued[0]?.repositoryId).toBe("repo-2");
  });

  it("refuses a candidate set above the ceiling rather than silently slicing it", async () => {
    // Rolling out to the first 500 of 5000 looks like success and is not.
    const candidates = Array.from({ length: 12 }, (_, i) => repo(i + 1));
    const { deps, enqueued } = buildDeps({
      candidates: async () => candidates,
      maxCandidates: 10,
    });

    await expect(run(deps)).rejects.toThrow(/exceeds the 10 ceiling/);
    expect(enqueued).toHaveLength(0);
  });
});

describe("enqueuing", () => {
  it("pins each migration to the commit it was planned against", async () => {
    const { deps, enqueued } = buildDeps({
      readManifest: async () => ({ headSha: "f".repeat(40), manifest: MANIFEST }),
    });

    await run(deps);

    expect(enqueued[0]?.baseSha).toBe("f".repeat(40));
    expect(enqueued[0]?.dedupeKey).toContain("f".repeat(40));
  });

  it("carries the impact it computed into the job, so nothing recomputes it", async () => {
    // The impact is the sentence the pull request opens with. It was derived
    // here, from the manifest at this exact commit; deriving it a second time
    // in the migration would be a second chance to tell a maintainer something
    // untrue about their own repository.
    const { deps, enqueued } = buildDeps();

    await run(deps);

    // `^2.9.0` cannot admit 3.0.0: stuck rather than broken.
    expect(enqueued[0]?.impact).toBe("stranded");
  });

  it("marks a repository whose range admits the new version as exposed", async () => {
    const { deps, enqueued } = buildDeps({
      readManifest: async () => ({
        headSha: "a".repeat(40),
        manifest: JSON.stringify({ name: "widgets", dependencies: { "acme-sdk": ">=2.0.0" } }),
      }),
    });

    await run(deps);

    expect(enqueued[0]?.impact).toBe("exposed");
  });

  it("does not duplicate work a previous rollout already queued", async () => {
    // ADR-0004. A duplicate here is a duplicate pull request.
    const { deps, enqueued } = buildDeps();

    await run(deps);
    const second = await run(deps, testContext());

    expect(enqueued).toHaveLength(2);
    expect(second).toMatchObject({ enqueued: 0, duplicates: 1 });
  });

  it("replays a completed step without enqueuing again", async () => {
    // The step boundary memoises, so a workflow resumed mid-flight must not
    // re-send the wave.
    const ctx = testContext();
    const { deps, enqueued } = buildDeps();
    const workflow = planRolloutWorkflow(deps);

    await workflow(ctx, { changeId: "change-1" });
    await workflow(ctx, { changeId: "change-1" });

    expect(enqueued).toHaveLength(1);
  });

  it("reports what it did, including what it skipped", async () => {
    const { deps } = buildDeps({
      candidates: async () => [repo(1), repo(2, { archived: true })],
    });

    const outcome = await run(deps);

    expect(outcome).toMatchObject({
      kind: "planned",
      changeKey: "acme-sdk@3.0.0",
      // Two hard sources clear the bar but do not reach "high" — that needs a
      // third kind. The confidence is carried through because it sizes the
      // canary, so a weaker case reaches fewer repositories.
      confidence: "moderate",
      targeted: 1,
      enqueued: 1,
      duplicates: 0,
    });
    expect((outcome as { skipped: readonly unknown[] }).skipped).toHaveLength(1);
  });
});
