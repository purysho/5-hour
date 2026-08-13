import { describe, expect, it } from "vitest";
import {
  classifyBump,
  compareVersions,
  InvalidVersionError,
  isBreakingBump,
  latestStableVersion,
  latestVersion,
  parseVersion,
  tryParseVersion,
} from "../../src/detect/semver.ts";

/**
 * Version comparison decides whether a change is breaking, which decides
 * whether we open pull requests across thousands of repositories. Getting
 * precedence wrong does not produce an error — it produces confident,
 * incorrect fan-out.
 */

const v = parseVersion;

describe("parsing", () => {
  it("parses a plain version", () => {
    expect(v("1.2.3")).toMatchObject({ major: 1, minor: 2, patch: 3, prerelease: [] });
  });

  it("parses prerelease and build metadata", () => {
    const parsed = v("1.0.0-rc.1+build.5");
    expect(parsed.prerelease).toEqual(["rc", 1]);
    expect(parsed.build).toBe("build.5");
  });

  it("accepts a leading v, as tags and changelogs use it", () => {
    expect(v("v2.0.0").major).toBe(2);
  });

  it("rejects leading zeroes, which npm also rejects", () => {
    expect(() => v("01.2.3")).toThrow(InvalidVersionError);
  });

  it("rejects partial and malformed versions", () => {
    for (const bad of ["1.2", "1", "", "1.2.3.4", "next", "1.2.x", "^1.2.3"]) {
      expect(() => v(bad), bad).toThrow(InvalidVersionError);
    }
  });

  it("rejects an absurdly long string rather than running a regex over it", () => {
    // A hostile registry response should not become a CPU denial of service.
    expect(() => v("1.2.3-" + "a".repeat(500))).toThrow(/exceeds/);
  });

  it("tryParseVersion returns null instead of throwing", () => {
    expect(tryParseVersion("nonsense")).toBeNull();
    expect(tryParseVersion("1.0.0")).not.toBeNull();
  });
});

describe("precedence", () => {
  it("orders by major, then minor, then patch", () => {
    expect(compareVersions(v("1.0.0"), v("2.0.0"))).toBeLessThan(0);
    expect(compareVersions(v("1.2.0"), v("1.1.0"))).toBeGreaterThan(0);
    expect(compareVersions(v("1.1.1"), v("1.1.1"))).toBe(0);
  });

  it("ranks a prerelease below its release", () => {
    // The rule most often inverted, and the one that would make us treat an
    // rc as newer than the release it precedes.
    expect(compareVersions(v("1.0.0-rc.1"), v("1.0.0"))).toBeLessThan(0);
    expect(compareVersions(v("1.0.0"), v("1.0.0-rc.1"))).toBeGreaterThan(0);
  });

  it("compares numeric prerelease identifiers numerically", () => {
    // String comparison would put 10 before 9.
    expect(compareVersions(v("1.0.0-alpha.9"), v("1.0.0-alpha.10"))).toBeLessThan(0);
  });

  it("ranks numeric identifiers below alphanumeric ones", () => {
    expect(compareVersions(v("1.0.0-1"), v("1.0.0-alpha"))).toBeLessThan(0);
  });

  it("ranks a longer identifier set above a shorter prefix", () => {
    expect(compareVersions(v("1.0.0-alpha"), v("1.0.0-alpha.1"))).toBeLessThan(0);
  });

  it("ignores build metadata entirely", () => {
    expect(compareVersions(v("1.0.0+a"), v("1.0.0+b"))).toBe(0);
  });

  it("matches the SemVer 2.0.0 worked example", () => {
    const ordered = [
      "1.0.0-alpha",
      "1.0.0-alpha.1",
      "1.0.0-alpha.beta",
      "1.0.0-beta",
      "1.0.0-beta.2",
      "1.0.0-beta.11",
      "1.0.0-rc.1",
      "1.0.0",
    ];
    for (let i = 1; i < ordered.length; i++) {
      expect(
        compareVersions(v(ordered[i - 1]!), v(ordered[i]!)),
        `${ordered[i - 1]} < ${ordered[i]}`,
      ).toBeLessThan(0);
    }
  });
});

describe("bump classification", () => {
  it("classifies the ordinary cases", () => {
    expect(classifyBump(v("1.0.0"), v("2.0.0"))).toBe("major");
    expect(classifyBump(v("1.0.0"), v("1.1.0"))).toBe("minor");
    expect(classifyBump(v("1.0.0"), v("1.0.1"))).toBe("patch");
    expect(classifyBump(v("1.0.0-rc.1"), v("1.0.0-rc.2"))).toBe("prerelease");
    expect(classifyBump(v("1.0.0"), v("1.0.0"))).toBe("none");
  });

  it("recognises a downgrade rather than reporting a bump", () => {
    // Registries do serve these — an unpublish, a mirror lagging, a yanked
    // release. Treating one as an upgrade would migrate people backwards.
    expect(classifyBump(v("2.0.0"), v("1.0.0"))).toBe("downgrade");
  });
});

describe("breaking detection", () => {
  it("treats a major bump as breaking", () => {
    expect(isBreakingBump(v("1.4.2"), v("2.0.0"))).toBe(true);
  });

  it("treats a minor bump below 1.0.0 as breaking", () => {
    // Where the AI SDK ecosystem actually lives. Applying 1.x rules to 0.x
    // would under-detect precisely where churn is highest.
    expect(isBreakingBump(v("0.4.0"), v("0.5.0"))).toBe(true);
  });

  it("does not treat a 0.x patch as breaking", () => {
    expect(isBreakingBump(v("0.4.0"), v("0.4.1"))).toBe(false);
  });

  it("does not treat an ordinary minor or patch bump as breaking", () => {
    expect(isBreakingBump(v("1.4.0"), v("1.5.0"))).toBe(false);
    expect(isBreakingBump(v("1.4.0"), v("1.4.1"))).toBe(false);
  });

  it("does not treat a downgrade as breaking", () => {
    expect(isBreakingBump(v("2.0.0"), v("1.0.0"))).toBe(false);
  });
});

describe("selection", () => {
  it("finds the highest version", () => {
    expect(latestVersion(["1.0.0", "2.1.0", "2.0.9"])?.raw).toBe("2.1.0");
  });

  it("skips unparseable entries instead of failing", () => {
    // Real registries contain junk. One bad entry must not blind us to the
    // rest.
    expect(latestVersion(["1.0.0", "not-a-version", "1.2.0"])?.raw).toBe("1.2.0");
  });

  it("excludes prereleases when asked for a stable version", () => {
    expect(latestStableVersion(["1.0.0", "2.0.0-rc.1"])?.raw).toBe("1.0.0");
  });

  it("returns null when nothing qualifies", () => {
    expect(latestVersion([])).toBeNull();
    expect(latestStableVersion(["1.0.0-rc.1"])).toBeNull();
  });
});
