import { describe, expect, it } from "vitest";
import { deriveBlastRadius, type SourceFile } from "../../src/policy/blast-radius.ts";
import { evaluateDiff } from "../../src/policy/diff-policy.ts";

/**
 * Blast radius derivation (ADR-0003 layer 3).
 *
 * The radius is an upper bound on where the agent may write, which makes its
 * failure modes asymmetric: too wide is a security failure, too narrow is an
 * annoyance. These tests are weighted accordingly — most of them are attempts
 * to make it wider than it should be.
 */

function file(path: string, content: string): SourceFile {
  return { path, content };
}

const TREE: SourceFile[] = [
  file("src/client.ts", "import { createClient } from 'acme-sdk';\nexport const c = createClient();"),
  file("src/helpers.ts", "export function unrelated() { return 1; }"),
  file("src/legacy.ts", "// TODO: migrate away from createClient eventually"),
  file("src/naming.ts", "const HttpClientFactory = 1; export { HttpClientFactory };"),
  file("test/client.test.ts", "import { createClient } from 'acme-sdk';"),
  file("README.md", "Use createClient to get started."),
  file(".github/workflows/ci.yml", "run: createClient"),
  file("node_modules/acme-sdk/index.js", "exports.createClient = () => {};"),
  file("dist/bundle.js", "createClient()"),
];

describe("selection", () => {
  it("includes files referencing an impacted symbol", () => {
    const radius = deriveBlastRadius(TREE, ["createClient"]);
    expect(radius.files).toContain("src/client.ts");
    expect(radius.files).toContain("test/client.test.ts");
  });

  it("excludes files that do not reference it", () => {
    const radius = deriveBlastRadius(TREE, ["createClient"]);
    expect(radius.files).not.toContain("src/helpers.ts");
  });

  it("includes a comment-only reference", () => {
    // Being in the radius permits an edit; it does not require one. Erring
    // toward inclusion is the safe direction for a candidate set.
    expect(deriveBlastRadius(TREE, ["createClient"]).files).toContain("src/legacy.ts");
  });

  it("does not match a symbol embedded in a longer identifier", () => {
    // \b alone would be wrong: it treats $ and _ as boundaries, both of which
    // are legal identifier characters.
    const radius = deriveBlastRadius(TREE, ["Client"]);
    expect(radius.files).not.toContain("src/naming.ts");
  });

  it("does not match across identifier characters in either direction", () => {
    const tree = [
      file("a.ts", "const myClient$ = 1;"),
      file("b.ts", "const _Client = 1;"),
      file("c.ts", "const Client = 1;"),
    ];
    const radius = deriveBlastRadius(tree, ["Client"]);
    expect(radius.files).toEqual(["c.ts"]);
  });

  it("reports where each symbol was found", () => {
    const radius = deriveBlastRadius(TREE, ["createClient"]);
    expect(radius.matches.get("createClient")).toContain("src/client.ts");
  });
});

describe("paths that are never included", () => {
  it("excludes CI configuration", () => {
    // The diff policy rejects these outright anyway, so admitting them would
    // only widen the space an injection has to work in.
    expect(deriveBlastRadius(TREE, ["createClient"]).files).not.toContain(
      ".github/workflows/ci.yml",
    );
  });

  it("excludes vendored and generated trees", () => {
    const radius = deriveBlastRadius(TREE, ["createClient"]);
    expect(radius.files).not.toContain("node_modules/acme-sdk/index.js");
    expect(radius.files).not.toContain("dist/bundle.js");
  });

  it("excludes non-source files by default", () => {
    expect(deriveBlastRadius(TREE, ["createClient"]).files).not.toContain("README.md");
  });

  it("excludes denied paths even when explicitly requested", () => {
    const radius = deriveBlastRadius(TREE, [], {
      alwaysInclude: ["package.json", "src/client.ts"],
    });
    expect(radius.files).toContain("package.json");
  });
});

describe("hostile symbol names", () => {
  it("ignores a symbol that is a regex metacharacter pattern", () => {
    // Symbol names come from publisher-controlled declarations. Without
    // validation, ".*" would match every file and hand an attacker a
    // repository-wide blast radius — the control becoming its own bypass.
    const radius = deriveBlastRadius(TREE, [".*"]);
    expect(radius.files).toEqual([]);
  });

  it("ignores other non-identifier symbols", () => {
    for (const hostile of ["[a-z]+", "^", "(?:.*)", "a|b", "", " ", "a".repeat(200)]) {
      expect(deriveBlastRadius(TREE, [hostile]).files, hostile).toEqual([]);
    }
  });

  it("still handles legitimate identifiers containing $ and _", () => {
    const tree = [file("a.ts", "export const $internal_fn = 1;")];
    expect(deriveBlastRadius(tree, ["$internal_fn"]).files).toEqual(["a.ts"]);
  });

  it("does not let one hostile symbol poison a valid batch", () => {
    const radius = deriveBlastRadius(TREE, [".*", "createClient"]);
    expect(radius.files).toContain("src/client.ts");
    expect(radius.files).not.toContain("src/helpers.ts");
  });
});

describe("capping", () => {
  it("truncates rather than widening when over the cap", () => {
    const many = Array.from({ length: 100 }, (_, i) =>
      file(`src/f${String(i).padStart(3, "0")}.ts`, "createClient()"),
    );
    const radius = deriveBlastRadius(many, ["createClient"], { maxFiles: 10 });
    expect(radius.files).toHaveLength(10);
    expect(radius.truncated).toBe(true);
  });

  it("does not report truncation when under the cap", () => {
    expect(deriveBlastRadius(TREE, ["createClient"]).truncated).toBe(false);
  });
});

describe("feeding the diff policy", () => {
  it("a migration inside the derived radius is allowed", () => {
    const radius = deriveBlastRadius(TREE, ["createClient"]);
    const diff = [
      "diff --git a/src/client.ts b/src/client.ts",
      "--- a/src/client.ts",
      "+++ b/src/client.ts",
      "@@ -1,1 +1,1 @@",
      "+export const c = new AcmeClient();",
      "",
    ].join("\n");

    expect(evaluateDiff(diff, { blastRadius: radius.files }).verdict).toBe("allow");
  });

  it("a steered edit outside the derived radius is rejected", () => {
    // End to end: the symbol set comes from the upstream change, the radius
    // from the symbol set, and the policy from the radius. An injection that
    // moves the agent into auth code fails at the last step regardless of how
    // convincing it was.
    const radius = deriveBlastRadius(TREE, ["createClient"]);
    const diff = [
      "diff --git a/src/auth/session.ts b/src/auth/session.ts",
      "--- a/src/auth/session.ts",
      "+++ b/src/auth/session.ts",
      "@@ -1,1 +1,1 @@",
      "+const verifySignature = false;",
      "",
    ].join("\n");

    const decision = evaluateDiff(diff, { blastRadius: radius.files });
    expect(decision.verdict).toBe("reject");
    expect(decision.findings[0]?.rule).toBe("blast-radius");
  });
});
