import { describe, expect, it } from "vitest";
import { parseRange, satisfies, satisfiesRaw } from "../../src/detect/range.ts";
import { parseVersion } from "../../src/detect/semver.ts";

/**
 * Range satisfaction decides who is affected by a change, which decides who
 * gets a pull request. An error here does not surface as a failure — it
 * surfaces as confident contact with the wrong repositories.
 */

function ok(version: string, range: string): boolean {
  const result = satisfiesRaw(version, range);
  expect(result, `${range} could not be evaluated against ${version}`).not.toBeNull();
  return result as boolean;
}

describe("exact and comparator ranges", () => {
  it("matches an exact version", () => {
    expect(ok("1.2.3", "1.2.3")).toBe(true);
    expect(ok("1.2.4", "1.2.3")).toBe(false);
  });

  it("handles each comparator", () => {
    expect(ok("2.0.0", ">=2.0.0")).toBe(true);
    expect(ok("1.9.9", ">=2.0.0")).toBe(false);
    expect(ok("2.0.1", ">2.0.0")).toBe(true);
    expect(ok("2.0.0", ">2.0.0")).toBe(false);
    expect(ok("1.9.9", "<2.0.0")).toBe(true);
    expect(ok("2.0.0", "<=2.0.0")).toBe(true);
  });

  it("treats whitespace as AND", () => {
    expect(ok("2.5.0", ">=2.0.0 <3.0.0")).toBe(true);
    expect(ok("3.0.0", ">=2.0.0 <3.0.0")).toBe(false);
  });

  it("treats || as OR", () => {
    expect(ok("1.5.0", "^1.0.0 || ^3.0.0")).toBe(true);
    expect(ok("3.2.0", "^1.0.0 || ^3.0.0")).toBe(true);
    expect(ok("2.0.0", "^1.0.0 || ^3.0.0")).toBe(false);
  });

  it("completes partial versions in comparators", () => {
    expect(ok("2.5.0", ">=2")).toBe(true);
    expect(ok("1.9.0", ">=2")).toBe(false);
  });
});

describe("caret ranges", () => {
  it("allows minor and patch above 1.0.0", () => {
    expect(ok("1.5.9", "^1.2.3")).toBe(true);
    expect(ok("1.2.2", "^1.2.3")).toBe(false);
    expect(ok("2.0.0", "^1.2.3")).toBe(false);
  });

  it("pins to the minor for 0.x", () => {
    // ^0.2.3 → >=0.2.3 <0.3.0. Where the AI SDK ecosystem lives, and where
    // treating 0.x like 1.x would mis-classify everyone.
    expect(ok("0.2.9", "^0.2.3")).toBe(true);
    expect(ok("0.3.0", "^0.2.3")).toBe(false);
  });

  it("pins to the patch for 0.0.x", () => {
    expect(ok("0.0.3", "^0.0.3")).toBe(true);
    expect(ok("0.0.4", "^0.0.3")).toBe(false);
  });

  it("handles partial carets", () => {
    expect(ok("1.9.0", "^1.2")).toBe(true);
    expect(ok("2.0.0", "^1.2")).toBe(false);
  });
});

describe("tilde ranges", () => {
  it("allows patch when a minor is given", () => {
    expect(ok("1.2.9", "~1.2.3")).toBe(true);
    expect(ok("1.3.0", "~1.2.3")).toBe(false);
  });

  it("allows minor when only a major is given", () => {
    expect(ok("1.9.0", "~1")).toBe(true);
    expect(ok("2.0.0", "~1")).toBe(false);
  });
});

describe("x-ranges and wildcards", () => {
  it("accepts anything for * and empty", () => {
    expect(ok("99.0.0", "*")).toBe(true);
    expect(ok("0.0.1", "")).toBe(true);
  });

  it("bounds by the specified components", () => {
    expect(ok("1.9.9", "1.x")).toBe(true);
    expect(ok("2.0.0", "1.x")).toBe(false);
    expect(ok("1.2.9", "1.2.x")).toBe(true);
    expect(ok("1.3.0", "1.2.x")).toBe(false);
  });

  it("treats a bare major as an x-range", () => {
    expect(ok("1.5.0", "1")).toBe(true);
    expect(ok("2.0.0", "1")).toBe(false);
  });
});

describe("hyphen ranges", () => {
  it("is inclusive at both ends when fully specified", () => {
    expect(ok("1.2.3", "1.2.3 - 2.3.4")).toBe(true);
    expect(ok("2.3.4", "1.2.3 - 2.3.4")).toBe(true);
    expect(ok("2.3.5", "1.2.3 - 2.3.4")).toBe(false);
  });

  it("treats a partial upper bound as the end of that range", () => {
    // "1.2.3 - 2.3" means < 2.4.0, not <= 2.3.0.
    expect(ok("2.3.9", "1.2.3 - 2.3")).toBe(true);
    expect(ok("2.4.0", "1.2.3 - 2.3")).toBe(false);
  });
});

describe("prereleases", () => {
  it("ranks a prerelease below its release", () => {
    expect(ok("2.0.0-rc.1", ">=2.0.0")).toBe(false);
    expect(ok("2.0.0", ">=2.0.0")).toBe(true);
  });

  it("matches an explicitly requested prerelease", () => {
    expect(ok("2.0.0-rc.1", ">=2.0.0-rc.1")).toBe(true);
  });
});

describe("things that are not version ranges", () => {
  it("returns null rather than guessing", () => {
    // Guessing here would produce confident nonsense about who is affected.
    // Null forces the caller to treat it as unknown.
    for (const specifier of [
      "latest",
      "next",
      "git+https://github.com/acme/sdk.git",
      "github:acme/sdk",
      "file:../local",
      "workspace:*",
      "npm:other-package@1.0.0",
      "https://example.com/pkg.tgz",
    ]) {
      expect(parseRange(specifier), specifier).toBeNull();
    }
  });

  it("returns null for an over-long range rather than parsing it", () => {
    expect(parseRange(">=1.0.0 ".repeat(100))).toBeNull();
  });

  it("satisfiesRaw returns null when either side is unusable", () => {
    expect(satisfiesRaw("1.0.0", "latest")).toBeNull();
    expect(satisfiesRaw("not-a-version", "^1.0.0")).toBeNull();
  });
});

describe("the distinction the product depends on", () => {
  const three = parseVersion("3.0.0");

  it("caret excludes the next major — stranded", () => {
    // Will never resolve to 3.0.0. Stuck, not broken.
    expect(satisfies(three, parseRange("^2.0.0")!)).toBe(false);
  });

  it("open lower bound admits the next major — exposed", () => {
    // Resolves to 3.0.0 on the next install. May already be broken.
    expect(satisfies(three, parseRange(">=2.0.0")!)).toBe(true);
  });

  it("wildcard admits everything — exposed", () => {
    expect(satisfies(three, parseRange("*")!)).toBe(true);
  });

  it("an exact pin excludes it — stranded", () => {
    expect(satisfies(three, parseRange("2.9.1")!)).toBe(false);
  });
});
