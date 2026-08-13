import { describe, expect, it } from "vitest";
import {
  assessEligibility,
  canarySize,
  type ChangeSignal,
  type Corroboration,
  type SourceKind,
} from "../../src/detect/corroborate.ts";

/**
 * Corroboration (threat-model §5.2).
 *
 * The attack here is the one where our correctness is the vulnerability: a
 * forged "breaking change" whose migration inserts something hostile, which
 * we then propagate faithfully to every downstream consumer at scale.
 *
 * So the tests are written as attempts to get a fabricated signal past the
 * gate, not as coverage of the happy path.
 */

function source(kind: SourceKind, breaking = true, origin: string = kind): Corroboration {
  return { kind, origin, breaking, observedAt: new Date().toISOString() };
}

function signal(overrides: Partial<ChangeSignal> = {}): ChangeSignal {
  return {
    changeKey: "acme-sdk@3.0.0",
    ecosystem: "npm",
    packageName: "acme-sdk",
    fromVersion: "2.9.1",
    toVersion: "3.0.0",
    corroborations: [],
    ...overrides,
  };
}

describe("a forged signal cannot reach fan-out", () => {
  it("refuses a changelog on its own", () => {
    // The §5.2 attack in its simplest form: prose someone typed.
    const result = assessEligibility(
      signal({ corroborations: [source("changelog")] }),
    );
    expect(result.eligible).toBe(false);
    if (result.eligible) return;
    expect(result.reason).toBe("changelog-only");
  });

  it("refuses many changelogs restating each other", () => {
    // Three sources by count, one by substance. Counting them separately is
    // exactly how a single forged signal clears a threshold.
    const result = assessEligibility(
      signal({
        corroborations: [
          source("changelog", true, "github release"),
          source("changelog", true, "blog post"),
          source("changelog", true, "mailing list"),
        ],
      }),
    );
    expect(result.eligible).toBe(false);
    if (result.eligible) return;
    expect(result.reason).toBe("changelog-only");
  });

  it("refuses a single hard source", () => {
    const result = assessEligibility(signal({ corroborations: [source("registry")] }));
    expect(result.eligible).toBe(false);
    if (result.eligible) return;
    expect(result.reason).toBe("insufficient-sources");
  });

  it("refuses when a hard source disagrees", () => {
    // Disagreement means we do not understand the change. Fan-out is the
    // wrong response to confusion.
    const result = assessEligibility(
      signal({
        corroborations: [
          source("changelog"),
          source("registry"),
          source("artifact", false),
        ],
      }),
    );
    expect(result.eligible).toBe(false);
    if (result.eligible) return;
    expect(result.reason).toBe("sources-disagree");
  });

  it("refuses a migration that introduces a capability", () => {
    // New dependency, network destination, or credential use — never
    // auto-generated, however well corroborated the change itself is.
    const result = assessEligibility(
      signal({
        corroborations: [source("registry"), source("artifact"), source("spec")],
        introducesCapability: true,
      }),
    );
    expect(result.eligible).toBe(false);
    if (result.eligible) return;
    expect(result.reason).toBe("capability-requires-approval");
  });

  it("refuses when nothing reports a breaking change", () => {
    const result = assessEligibility(
      signal({ corroborations: [source("registry", false), source("spec", false)] }),
    );
    expect(result.eligible).toBe(false);
    if (result.eligible) return;
    expect(result.reason).toBe("not-breaking");
  });

  it("refuses an empty signal", () => {
    expect(assessEligibility(signal()).eligible).toBe(false);
  });
});

describe("a genuine change passes", () => {
  it("accepts registry plus artifact evidence", () => {
    const result = assessEligibility(
      signal({ corroborations: [source("registry"), source("artifact")] }),
    );
    expect(result.eligible).toBe(true);
  });

  it("accepts a changelog once hard evidence agrees", () => {
    // Changelogs are useful — they explain the change. They just cannot
    // establish it.
    const result = assessEligibility(
      signal({ corroborations: [source("changelog"), source("registry"), source("spec")] }),
    );
    expect(result.eligible).toBe(true);
  });

  it("rates three independent hard sources as high confidence", () => {
    const result = assessEligibility(
      signal({ corroborations: [source("registry"), source("artifact"), source("spec")] }),
    );
    expect(result.eligible).toBe(true);
    if (!result.eligible) return;
    expect(result.confidence).toBe("high");
  });

  it("rates the minimum passing set as moderate", () => {
    // Two hard kinds, weight 5 — clears the bar without the third independent
    // source that would justify high confidence.
    const result = assessEligibility(
      signal({ corroborations: [source("registry"), source("spec")] }),
    );
    expect(result.eligible).toBe(true);
    if (!result.eligible) return;
    expect(result.confidence).toBe("moderate");
  });

  it("tolerates a changelog dissenting against hard evidence", () => {
    // A stale or wrong changelog is ordinary. A dissenting artifact is not.
    const result = assessEligibility(
      signal({
        corroborations: [
          source("registry"),
          source("artifact"),
          source("changelog", false),
        ],
      }),
    );
    expect(result.eligible).toBe(true);
  });

  it("honours a stricter policy", () => {
    const corroborations = [source("registry"), source("artifact")];
    expect(assessEligibility(signal({ corroborations })).eligible).toBe(true);
    expect(
      assessEligibility(signal({ corroborations }), { minimumKinds: 3 }).eligible,
    ).toBe(false);
  });
});

describe("staged fan-out", () => {
  it("sends nothing when the change is ineligible", () => {
    const result = assessEligibility(signal({ corroborations: [source("changelog")] }));
    expect(canarySize(result, 5000)).toBe(0);
  });

  it("keeps the first wave small even at large scale", () => {
    // A mistake should cost a handful of pull requests, not a thousand.
    const high = assessEligibility(
      signal({ corroborations: [source("registry"), source("artifact"), source("spec")] }),
    );
    expect(canarySize(high, 5000)).toBeLessThanOrEqual(25);
    expect(canarySize(high, 5000)).toBeGreaterThanOrEqual(3);
  });

  it("sends a smaller canary for moderate confidence than for high", () => {
    const high = assessEligibility(
      signal({ corroborations: [source("registry"), source("artifact"), source("spec")] }),
    );
    const moderate = assessEligibility(
      signal({ corroborations: [source("registry"), source("spec")] }),
    );
    expect(canarySize(moderate, 1000)).toBeLessThan(canarySize(high, 1000));
  });

  it("does not stage a fan-out smaller than the canary", () => {
    const high = assessEligibility(
      signal({ corroborations: [source("registry"), source("artifact"), source("spec")] }),
    );
    expect(canarySize(high, 4)).toBe(4);
  });
});
