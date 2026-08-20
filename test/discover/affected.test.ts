import { describe, expect, it } from "vitest";
import {
  assessRepository,
  decideTarget,
  prioritise,
  type ChangeUnderTest,
  type DependencyKind,
  type RepositoryCandidate,
} from "../../src/discover/affected.ts";

/**
 * Impact classification.
 *
 * The failure mode here is not an exception. It is contacting the wrong
 * repositories with confidence — spamming people who are fine, or missing
 * people whose builds are already failing. Both cost credibility that a
 * cold-start product cannot spare.
 */

const CHANGE: ChangeUnderTest = {
  packageName: "acme-sdk",
  fromVersion: "2.9.1",
  toVersion: "3.0.0",
};

function repo(
  range: string,
  overrides: Partial<RepositoryCandidate> = {},
  kind: DependencyKind = "dependencies",
): RepositoryCandidate {
  return {
    forge: "github",
    owner: "consumer",
    name: "app",
    dependencies: [{ packageName: "acme-sdk", range, kind }],
    ...overrides,
  };
}

describe("stranded — the core case", () => {
  it("classifies a caret range that excludes the new major", () => {
    // Nothing is broken and nothing will break. They are simply stuck, and no
    // signal will ever reach them. This is the population the product is for.
    const assessment = assessRepository(repo("^2.0.0"), CHANGE);
    expect(assessment.impact).toBe("stranded");
    expect(assessment.detail).toContain("will never receive it");
  });

  it("classifies an exact pin", () => {
    expect(assessRepository(repo("2.9.1"), CHANGE).impact).toBe("stranded");
  });

  it("classifies a tilde range", () => {
    expect(assessRepository(repo("~2.9.0"), CHANGE).impact).toBe("stranded");
  });

  it("classifies a bounded compound range", () => {
    expect(assessRepository(repo(">=2.0.0 <3.0.0"), CHANGE).impact).toBe("stranded");
  });

  it("classifies a 0.x caret against a 0.x minor bump", () => {
    const assessment = assessRepository(repo("^0.4.0"), {
      packageName: "acme-sdk",
      fromVersion: "0.4.2",
      toVersion: "0.5.0",
    });
    expect(assessment.impact).toBe("stranded");
  });
});

describe("exposed — already at risk", () => {
  it("classifies an open lower bound", () => {
    // Their next install takes the breaking change. Same upstream event,
    // urgent rather than routine.
    const assessment = assessRepository(repo(">=2.0.0"), CHANGE);
    expect(assessment.impact).toBe("exposed");
    expect(assessment.detail).toContain("next install");
  });

  it("classifies a wildcard", () => {
    expect(assessRepository(repo("*"), CHANGE).impact).toBe("exposed");
  });

  it("classifies a union that admits the new major", () => {
    expect(assessRepository(repo("^2.0.0 || ^3.0.0"), CHANGE).impact).toBe("exposed");
  });
});

describe("current and unrelated", () => {
  it("treats a lockfile already on the new version as current", () => {
    // The lockfile is stronger evidence than the range: it says what is
    // installed, not what would be permitted.
    const assessment = assessRepository(
      repo("^2.0.0 || ^3.0.0", { lockedVersion: "3.0.1" }),
      CHANGE,
    );
    expect(assessment.impact).toBe("current");
  });

  it("treats a lockfile ahead of the change as current even with a stranding range", () => {
    const assessment = assessRepository(repo("^2.0.0", { lockedVersion: "3.2.0" }), CHANGE);
    expect(assessment.impact).toBe("current");
  });

  it("treats a repository not declaring the package as unrelated", () => {
    const assessment = assessRepository(
      { ...repo("^2.0.0"), dependencies: [] },
      CHANGE,
    );
    expect(assessment.impact).toBe("unrelated");
  });

  it("treats a range admitting neither version as unrelated", () => {
    // On 1.x. Our 2.9.1 → 3.0.0 change is not their change.
    expect(assessRepository(repo("^1.0.0"), CHANGE).impact).toBe("unrelated");
  });
});

describe("unknown — refuses to guess", () => {
  it("does not classify a git dependency", () => {
    // Guessing would produce a confident, wrong pull request.
    const assessment = assessRepository(repo("git+https://github.com/acme/sdk.git"), CHANGE);
    expect(assessment.impact).toBe("unknown");
  });

  it("does not classify a tag or workspace protocol", () => {
    for (const specifier of ["latest", "workspace:*", "file:../sdk"]) {
      expect(assessRepository(repo(specifier), CHANGE).impact, specifier).toBe("unknown");
    }
  });

  it("truncates an over-long specifier in the detail", () => {
    const assessment = assessRepository(repo(`git+https://x.example/${"a".repeat(200)}`), CHANGE);
    expect(assessment.detail.length).toBeLessThan(140);
  });
});

describe("targeting policy", () => {
  it("targets stranded and exposed by default", () => {
    expect(decideTarget(repo("^2.0.0"), CHANGE).targeted).toBe(true);
    expect(decideTarget(repo(">=2.0.0"), CHANGE).targeted).toBe(true);
  });

  it("does not target current, unrelated or unknown", () => {
    for (const range of ["^1.0.0", "latest"]) {
      expect(decideTarget(repo(range), CHANGE).targeted, range).toBe(false);
    }
    expect(decideTarget(repo("^2.0.0", { lockedVersion: "3.1.0" }), CHANGE).targeted).toBe(
      false,
    );
  });

  it("says which kind of untargeted impact, not just that it was one", () => {
    // "unrelated" is reached two ways and they are different problems: a
    // repository that never declared the package was never a consumer, while
    // one declaring a range admitting neither version is pinned out of reach.
    // A rollout that skipped everything is unattributable without this, and a
    // stale manifest reads exactly like a correct skip.
    const undeclared = decideTarget({ ...repo("^2.0.0"), dependencies: [] }, CHANGE);
    expect(undeclared.skipReason).toContain("does not declare this package");

    const outOfRange = decideTarget(repo("^1.0.0"), CHANGE);
    expect(outOfRange.skipReason).toContain("admits neither");

    // The policy verdict survives alongside the fact that produced it.
    for (const decision of [undeclared, outOfRange]) {
      expect(decision.skipReason).toContain('impact "unrelated" is not targeted');
    }
  });

  it("skips archived repositories", () => {
    // A pull request there reaches nobody.
    const decision = decideTarget(repo("^2.0.0", { archived: true }), CHANGE);
    expect(decision.targeted).toBe(false);
    expect(decision.skipReason).toContain("archived");
  });

  it("skips forks", () => {
    const decision = decideTarget(repo("^2.0.0", { fork: true }), CHANGE);
    expect(decision.targeted).toBe(false);
    expect(decision.skipReason).toContain("fork");
  });

  it("skips optionalDependencies by default", () => {
    const decision = decideTarget(repo("^2.0.0", {}, "optionalDependencies"), CHANGE);
    expect(decision.targeted).toBe(false);
    expect(decision.skipReason).toContain("optionalDependencies");
  });

  it("honours explicit rules over the defaults", () => {
    const decision = decideTarget(repo("^2.0.0", { archived: true }), CHANGE, {
      skipArchived: false,
    });
    expect(decision.targeted).toBe(true);
  });

  it("keeps the factual assessment even when skipping", () => {
    // Assessment is a claim about the repository; eligibility is policy about
    // who we contact. Both are recorded, so either can be audited.
    const decision = decideTarget(repo("^2.0.0", { archived: true }), CHANGE);
    expect(decision.assessment.impact).toBe("stranded");
    expect(decision.targeted).toBe(false);
  });
});

describe("fan-out ordering", () => {
  it("puts exposed repositories before stranded ones", () => {
    const targets = [
      decideTarget(repo("^2.0.0", { name: "stranded" }), CHANGE),
      decideTarget(repo(">=2.0.0", { name: "exposed" }), CHANGE),
    ];
    expect(prioritise(targets)[0]?.repository.name).toBe("exposed");
  });

  it("sends the canary to smaller repositories first", () => {
    // A mistake on a small repository is a smaller mistake. Opening the first
    // wave against the most-watched repositories in the ecosystem is exactly
    // backwards.
    const targets = [
      decideTarget(repo("^2.0.0", { name: "popular", stars: 40000 }), CHANGE),
      decideTarget(repo("^2.0.0", { name: "quiet", stars: 12 }), CHANGE),
    ];
    expect(prioritise(targets).map((t) => t.repository.name)).toEqual(["quiet", "popular"]);
  });

  it("does not mutate its input", () => {
    const targets = [
      decideTarget(repo("^2.0.0", { name: "a", stars: 5 }), CHANGE),
      decideTarget(repo(">=2.0.0", { name: "b", stars: 1 }), CHANGE),
    ];
    const before = targets.map((t) => t.repository.name);
    prioritise(targets);
    expect(targets.map((t) => t.repository.name)).toEqual(before);
  });
});
