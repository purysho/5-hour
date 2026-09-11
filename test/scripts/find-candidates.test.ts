import { describe, it, expect } from "vitest";
import {
  parseArgs,
  renderCandidates,
  renderDecisions,
  discover,
  type CandidateSource,
} from "../../scripts/find-candidates.ts";
import { DiscoveryError } from "../../src/discover/github-code-search.ts";
import { decideTarget, type RepositoryCandidate } from "../../src/discover/affected.ts";
import { Secret } from "../../src/config.ts";

/**
 * The operator command for choosing a cold-start cohort.
 *
 * Its output is read by a human deciding who to contact first, so the tests
 * are about whether that output is honest and complete rather than about
 * formatting.
 */

const CREDENTIAL = new Secret("ghp_not_a_real_token_00000000", "GITHUB_SEARCH_TOKEN");

function candidate(overrides: Partial<RepositoryCandidate> = {}): RepositoryCandidate {
  return {
    forge: "github",
    owner: "acme",
    name: "widgets",
    defaultBranch: "main",
    dependencies: [{ packageName: "acme-sdk", range: "^2.0.0", kind: "dependencies" }],
    stars: 40,
    archived: false,
    fork: false,
    ...overrides,
  };
}

function source(candidates: readonly RepositoryCandidate[]): CandidateSource {
  return { findCandidates: async () => [...candidates] };
}

describe("argument parsing", () => {
  it("takes a package name", () => {
    expect(parseArgs(["acme-sdk"])).toEqual({
      packageName: "acme-sdk",
      from: null,
      to: null,
      limit: 25,
    });
  });

  it("accepts a version pair in either flag form", () => {
    expect(parseArgs(["acme-sdk", "--from", "2.4.0", "--to", "3.0.0"])).toMatchObject({
      from: "2.4.0",
      to: "3.0.0",
    });
    expect(parseArgs(["acme-sdk", "--from=2.4.0", "--to=3.0.0"])).toMatchObject({
      from: "2.4.0",
      to: "3.0.0",
    });
  });

  it("refuses one version without the other", () => {
    // An impact classification compares two versions. Defaulting the missing
    // one would assess a change nobody asked about.
    expect(() => parseArgs(["acme-sdk", "--from", "2.4.0"])).toThrow(/together/);
  });

  it("refuses a flag with no value", () => {
    expect(() => parseArgs(["acme-sdk", "--limit"])).toThrow(DiscoveryError);
    expect(() => parseArgs(["acme-sdk", "--from", "--to"])).toThrow(DiscoveryError);
  });

  it("refuses a nonsense limit", () => {
    expect(() => parseArgs(["acme-sdk", "--limit", "0"])).toThrow(DiscoveryError);
    expect(() => parseArgs(["acme-sdk", "--limit", "half"])).toThrow(DiscoveryError);
  });

  it("requires a package name", () => {
    expect(() => parseArgs([])).toThrow(/usage/);
  });
});

describe("candidate output", () => {
  it("shows the declared range, which is what decides impact", () => {
    const [line] = renderCandidates([candidate()], "acme-sdk");
    expect(line).toContain("acme/widgets");
    expect(line).toContain("dependencies:^2.0.0");
    expect(line).toContain("★40");
  });

  it("marks archived and forked repositories rather than hiding them", () => {
    const [line] = renderCandidates(
      [candidate({ archived: true, fork: true })],
      "acme-sdk",
    );
    expect(line).toContain("archived");
    expect(line).toContain("fork");
  });

  it("says so plainly when there is nothing", () => {
    expect(renderCandidates([], "acme-sdk")).toEqual([
      "no repositories found declaring acme-sdk",
    ]);
  });
});

describe("decision output", () => {
  it("reports why a repository was skipped, not just that it was", () => {
    const change = { packageName: "acme-sdk", fromVersion: "2.4.0", toVersion: "3.0.0" };
    const lines = renderDecisions([decideTarget(candidate({ archived: true }), change)]);
    expect(lines[0]).toContain("skip");
    expect(lines[0]).toContain("repository is archived");
  });

  it("marks a stranded repository as a target", () => {
    const change = { packageName: "acme-sdk", fromVersion: "2.4.0", toVersion: "3.0.0" };
    const lines = renderDecisions([decideTarget(candidate(), change)]);
    expect(lines[0]).toContain("TARGET");
    expect(lines[0]).toContain("stranded");
  });
});

describe("the command", () => {
  it("prints candidates without an assessment when no versions are given", async () => {
    const lines: string[] = [];
    const count = await discover(
      { packageName: "acme-sdk", from: null, to: null, limit: 25 },
      CREDENTIAL,
      (line) => lines.push(line),
      source([candidate()]),
    );

    expect(count).toBe(1);
    expect(lines.join("\n")).toContain("1 candidate(s) declaring acme-sdk");
    expect(lines.join("\n")).not.toContain("would be targeted");
  });

  it("adds the impact and rollout order when versions are given", async () => {
    const lines: string[] = [];
    await discover(
      { packageName: "acme-sdk", from: "2.4.0", to: "3.0.0", limit: 25 },
      CREDENTIAL,
      (line) => lines.push(line),
      source([
        candidate({ name: "stranded-one" }),
        candidate({
          name: "exposed-one",
          dependencies: [{ packageName: "acme-sdk", range: ">=2.0.0", kind: "dependencies" }],
        }),
      ]),
    );

    const output = lines.join("\n");
    expect(output).toContain("2.4.0 → 3.0.0");
    expect(output).toContain("2 of 2 would be targeted");

    // Exposed before stranded: an exposed repository may already be broken.
    // Measured inside the rollout section only — the candidate listing above
    // it is in discovery order, and matching against the whole output would
    // assert the wrong thing while appearing to pass or fail for the right
    // reason.
    const rollout = output.slice(output.indexOf("in rollout order"));
    expect(rollout.indexOf("exposed-one")).toBeLessThan(rollout.indexOf("stranded-one"));
  });

  it("never prints the credential", async () => {
    const lines: string[] = [];
    await discover(
      { packageName: "acme-sdk", from: "2.4.0", to: "3.0.0", limit: 25 },
      CREDENTIAL,
      (line) => lines.push(line),
      source([candidate()]),
    );
    expect(lines.join("\n")).not.toContain("ghp_not_a_real_token_00000000");
  });
});
