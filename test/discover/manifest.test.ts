import { describe, expect, it } from "vitest";
import { lockedVersion, ManifestError, parseManifest } from "../../src/discover/manifest.ts";
import { assessRepository } from "../../src/discover/affected.ts";

/**
 * Reading a downstream repository's manifest and lockfile.
 *
 * The manifest is JSON and is parsed properly. The lockfile contributes only
 * `lockedVersion`, which is additional evidence — so an extractor that returns
 * null for anything unusual costs a piece of evidence rather than producing a
 * wrong one. Most of these tests are the "returns null" half, because that is
 * the property doing the work.
 */

describe("parseManifest", () => {
  it("reads every dependency field", () => {
    const parsed = parseManifest(
      JSON.stringify({
        name: "widgets",
        dependencies: { "acme-sdk": "^1.0.0" },
        devDependencies: { vitest: "^2.0.0" },
        peerDependencies: { react: ">=18" },
        optionalDependencies: { fsevents: "*" },
      }),
    );

    expect(parsed.name).toBe("widgets");
    expect(parsed.dependencies.map((d) => `${d.packageName}:${d.kind}`).sort()).toEqual([
      "acme-sdk:dependencies",
      "fsevents:optionalDependencies",
      "react:peerDependencies",
      "vitest:devDependencies",
    ]);
  });

  it("keeps the runtime declaration when a package appears twice", () => {
    // Whether consumers break is a question about runtime, so `dependencies`
    // wins over `devDependencies` rather than whichever came last.
    const parsed = parseManifest(
      JSON.stringify({
        dependencies: { "acme-sdk": "^1.0.0" },
        devDependencies: { "acme-sdk": "^2.0.0" },
      }),
    );
    expect(parsed.dependencies).toHaveLength(1);
    expect(parsed.dependencies[0]).toMatchObject({ kind: "dependencies", range: "^1.0.0" });
  });

  it("carries the range verbatim, however strange", () => {
    // Interpreting it here would be guessing. `assessRepository` says "unknown"
    // for a range it cannot reason about, which is a refusal rather than a
    // wrong answer.
    const parsed = parseManifest(
      JSON.stringify({
        dependencies: {
          "acme-sdk": "github:acme/sdk#deadbeef",
          "other-pkg": "workspace:*",
        },
      }),
    );
    expect(parsed.dependencies.map((d) => d.range)).toEqual([
      "github:acme/sdk#deadbeef",
      "workspace:*",
    ]);
  });

  it("skips a package name that is not one", () => {
    const parsed = parseManifest(
      JSON.stringify({
        dependencies: { "acme-sdk": "^1.0.0", "../../etc/passwd": "1.0.0", "": "1.0.0" },
      }),
    );
    expect(parsed.dependencies.map((d) => d.packageName)).toEqual(["acme-sdk"]);
    expect(parsed.skipped).toContain("../../etc/passwd");
  });

  it("skips __proto__ rather than carrying it forward", () => {
    // JSON.parse makes this an ordinary own property rather than polluting
    // anything, but it is not a package name, and carrying it invites a later
    // lookup to misbehave.
    const parsed = parseManifest('{"dependencies":{"__proto__":"1.0.0","acme-sdk":"^1.0.0"}}');
    expect(parsed.dependencies.map((d) => d.packageName)).toEqual(["acme-sdk"]);
  });

  it("skips a range that is not a string", () => {
    const parsed = parseManifest('{"dependencies":{"acme-sdk":{"version":"1.0.0"}}}');
    expect(parsed.dependencies).toHaveLength(0);
    expect(parsed.skipped).toEqual(["acme-sdk"]);
  });

  it("tolerates a manifest with no dependencies at all", () => {
    expect(parseManifest('{"name":"widgets"}').dependencies).toEqual([]);
  });

  it("ignores a dependency field of the wrong type", () => {
    expect(parseManifest('{"dependencies":["acme-sdk"]}').dependencies).toEqual([]);
  });

  it("refuses invalid JSON", () => {
    expect(() => parseManifest("{ not json")).toThrow(ManifestError);
  });

  it("refuses a manifest that is not an object", () => {
    expect(() => parseManifest("[]")).toThrow(/not a JSON object/);
    expect(() => parseManifest('"a string"')).toThrow(/not a JSON object/);
  });

  it("refuses an oversized manifest", () => {
    expect(() => parseManifest("x".repeat(200), { maxBytes: 100 })).toThrow(/exceeds/);
  });

  it("refuses an implausible number of dependencies", () => {
    const dependencies: Record<string, string> = {};
    for (let i = 0; i < 20; i++) dependencies[`pkg-${i}`] = "^1.0.0";
    expect(() =>
      parseManifest(JSON.stringify({ dependencies }), { maxDependencies: 5 }),
    ).toThrow(/more than 5/);
  });

  it("feeds impact classification directly", () => {
    const parsed = parseManifest(JSON.stringify({ dependencies: { "acme-sdk": "^1.0.0" } }));
    const assessment = assessRepository(
      { forge: "github", owner: "acme", name: "widgets", dependencies: parsed.dependencies },
      { packageName: "acme-sdk", fromVersion: "1.4.2", toVersion: "2.0.0" },
    );
    expect(assessment.impact).toBe("stranded");
  });
});

describe("lockedVersion — package-lock.json", () => {
  const lockV3 = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "": { name: "widgets" },
      "node_modules/acme-sdk": { version: "1.4.2" },
      "node_modules/other": { version: "9.9.9" },
    },
  });

  it("reads a top-level install", () => {
    expect(lockedVersion({ filename: "package-lock.json", content: lockV3 }, "acme-sdk")).toBe(
      "1.4.2",
    );
  });

  it("reads the v1 shape", () => {
    const lockV1 = JSON.stringify({
      lockfileVersion: 1,
      dependencies: { "acme-sdk": { version: "1.4.2" } },
    });
    expect(lockedVersion({ filename: "package-lock.json", content: lockV1 }, "acme-sdk")).toBe(
      "1.4.2",
    );
  });

  it("ignores a nested copy installed for one dependent", () => {
    const nested = JSON.stringify({
      packages: {
        "node_modules/other": { version: "9.9.9" },
        "node_modules/other/node_modules/acme-sdk": { version: "0.1.0" },
      },
    });
    expect(lockedVersion({ filename: "package-lock.json", content: nested }, "acme-sdk")).toBeNull();
  });

  it("returns null when the package is not in the lockfile", () => {
    expect(lockedVersion({ filename: "package-lock.json", content: lockV3 }, "absent")).toBeNull();
  });

  it("returns null for a lockfile that will not parse", () => {
    expect(lockedVersion({ filename: "package-lock.json", content: "{ no" }, "acme-sdk")).toBeNull();
  });

  it("finds the file under a subdirectory", () => {
    expect(
      lockedVersion({ filename: "apps/web/package-lock.json", content: lockV3 }, "acme-sdk"),
    ).toBe("1.4.2");
  });

  it("reads npm-shrinkwrap.json too", () => {
    expect(lockedVersion({ filename: "npm-shrinkwrap.json", content: lockV3 }, "acme-sdk")).toBe(
      "1.4.2",
    );
  });
});

describe("lockedVersion — pnpm-lock.yaml", () => {
  it("reads the slash-separated key shape", () => {
    const content = ["packages:", "", "  /acme-sdk/1.4.2:", "    resolution: {integrity: sha}"].join(
      "\n",
    );
    expect(lockedVersion({ filename: "pnpm-lock.yaml", content }, "acme-sdk")).toBe("1.4.2");
  });

  it("reads the at-separated key shape", () => {
    const content = ["packages:", "", "  /acme-sdk@1.4.2:", "    resolution: {integrity: sha}"].join(
      "\n",
    );
    expect(lockedVersion({ filename: "pnpm-lock.yaml", content }, "acme-sdk")).toBe("1.4.2");
  });

  it("reads a scoped package", () => {
    const content = "packages:\n\n  /@acme/sdk@1.4.2:\n    resolution: {}";
    expect(lockedVersion({ filename: "pnpm-lock.yaml", content }, "@acme/sdk")).toBe("1.4.2");
  });

  it("reads a key carrying peer-dependency suffixes", () => {
    const content = "packages:\n\n  /acme-sdk@1.4.2(react@18.0.0):\n    resolution: {}";
    expect(lockedVersion({ filename: "pnpm-lock.yaml", content }, "acme-sdk")).toBe("1.4.2");
  });

  it("returns null when two versions are present", () => {
    // Ambiguity is not resolved by picking one. A confident wrong version
    // produces a confident wrong impact classification.
    const content = "packages:\n\n  /acme-sdk@1.4.2:\n    x: y\n  /acme-sdk@2.0.0:\n    x: y";
    expect(lockedVersion({ filename: "pnpm-lock.yaml", content }, "acme-sdk")).toBeNull();
  });

  it("does not match a package whose name merely ends the same way", () => {
    const content = "packages:\n\n  /not-acme-sdk@1.4.2:\n    x: y";
    expect(lockedVersion({ filename: "pnpm-lock.yaml", content }, "acme-sdk")).toBeNull();
  });
});

describe("lockedVersion — yarn.lock", () => {
  it("reads the classic format", () => {
    const content = [
      '"acme-sdk@^1.0.0":',
      '  version "1.4.2"',
      '  resolved "https://registry.yarnpkg.com/acme-sdk/-/acme-sdk-1.4.2.tgz"',
      "",
    ].join("\n");
    expect(lockedVersion({ filename: "yarn.lock", content }, "acme-sdk")).toBe("1.4.2");
  });

  it("reads an unquoted specifier", () => {
    const content = ["acme-sdk@^1.0.0:", '  version "1.4.2"', ""].join("\n");
    expect(lockedVersion({ filename: "yarn.lock", content }, "acme-sdk")).toBe("1.4.2");
  });

  it("reads the berry format", () => {
    const content = ['"acme-sdk@npm:^1.0.0":', "  version: 1.4.2", "  resolution: acme-sdk@npm:1.4.2", ""].join(
      "\n",
    );
    expect(lockedVersion({ filename: "yarn.lock", content }, "acme-sdk")).toBe("1.4.2");
  });

  it("returns null when the same package resolves twice", () => {
    const content = [
      '"acme-sdk@^1.0.0":',
      '  version "1.4.2"',
      "",
      '"acme-sdk@^2.0.0":',
      '  version "2.1.0"',
      "",
    ].join("\n");
    expect(lockedVersion({ filename: "yarn.lock", content }, "acme-sdk")).toBeNull();
  });

  it("does not match a different package with a similar name", () => {
    const content = ['"not-acme-sdk@^1.0.0":', '  version "1.4.2"', ""].join("\n");
    expect(lockedVersion({ filename: "yarn.lock", content }, "acme-sdk")).toBeNull();
  });
});

describe("lockedVersion — refusals", () => {
  it("returns null for a format it does not know", () => {
    expect(lockedVersion({ filename: "Cargo.lock", content: 'name = "acme-sdk"' }, "acme-sdk")).toBeNull();
  });

  it("returns null for an oversized lockfile", () => {
    expect(
      lockedVersion({ filename: "yarn.lock", content: "x".repeat(500) }, "acme-sdk", {
        maxBytes: 100,
      }),
    ).toBeNull();
  });

  it("returns null for a package name that is not one", () => {
    // The name reaches a regular expression. It is escaped, and it is also
    // validated — neither alone is a reason to skip the other.
    expect(
      lockedVersion({ filename: "yarn.lock", content: 'version "1.0.0"' }, ".*"),
    ).toBeNull();
  });

  it("returns null rather than accepting a non-version value", () => {
    const content = ['"acme-sdk@^1.0.0":', '  version "latest"', ""].join("\n");
    expect(lockedVersion({ filename: "yarn.lock", content }, "acme-sdk")).toBeNull();
  });
});
