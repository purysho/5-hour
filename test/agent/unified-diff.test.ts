import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { formatUnifiedDiff, UnifiedDiffError } from "../../src/agent/unified-diff.ts";
import { parseUnifiedDiff } from "../../src/policy/diff.ts";

/**
 * Diff rendering (ADR-0013 §4).
 *
 * Driftless renders the diff rather than accepting one from the model, so the
 * artifact the policy engine reads is the artifact that was applied. That
 * shifts a class of bug onto us, and these tests are where it gets caught.
 *
 * Two properties matter, and they are not the same property:
 *
 *   The policy engine can read what we render — otherwise a correct migration
 *   is rejected as unparseable.
 *   Git applies what we render, and the result is byte-identical to the
 *   content we diffed — otherwise the policy engine approved a diff that is
 *   not the change that lands.
 *
 * The second is checked against real git, not a model of it.
 */

const dir = mkdtempSync(join(tmpdir(), "driftless-diff-"));

beforeAll(() => {
  execFileSync("git", ["init", "--quiet"], { cwd: dir });
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** Writes `before`, applies the rendered diff with git, returns the result. */
function applyWithGit(path: string, before: string, after: string): string {
  const target = join(dir, path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, before);

  const diff = formatUnifiedDiff([{ path, before, after }]);
  const patchFile = join(dir, "patch.diff");
  writeFileSync(patchFile, diff);

  execFileSync("git", ["apply", "--unsafe-paths", patchFile], { cwd: dir });
  return readFileSync(target, "utf8");
}

describe("round trip through git", () => {
  it("applies a single-line replacement", () => {
    const before = "line one\nline two\nline three\n";
    const after = "line one\nline TWO\nline three\n";
    expect(applyWithGit("src/a.ts", before, after)).toBe(after);
  });

  it("applies edits in two distant regions of one file", () => {
    // Distant regions become separate hunks, so the second hunk's line
    // numbers have to account for the first hunk's net line change. This is
    // the arithmetic that hand-written diff generators get wrong.
    const before = Array.from({ length: 60 }, (_, i) => `line ${i}`).join("\n") + "\n";
    const lines = before.split("\n");
    lines[5] = "line five, edited";
    lines[50] = "line fifty, edited\nand an inserted line";
    const after = lines.join("\n");
    expect(applyWithGit("src/b.ts", before, after)).toBe(after);
  });

  it("applies a pure insertion", () => {
    const before = "a\nb\nc\n";
    const after = "a\nb\nb.5\nc\n";
    expect(applyWithGit("src/c.ts", before, after)).toBe(after);
  });

  it("applies a pure deletion", () => {
    const before = "a\nb\nc\nd\n";
    const after = "a\nd\n";
    expect(applyWithGit("src/d.ts", before, after)).toBe(after);
  });

  it("applies a change to a file with no trailing newline", () => {
    // The "\ No newline at end of file" marker. Getting this wrong produces a
    // patch git rejects, or worse, one it applies while silently adding a
    // newline.
    const before = "alpha\nbeta";
    const after = "alpha\ngamma";
    expect(applyWithGit("src/e.ts", before, after)).toBe(after);
  });

  it("applies a change that adds a trailing newline", () => {
    const before = "alpha\nbeta";
    const after = "alpha\nbeta\n";
    expect(applyWithGit("src/f.ts", before, after)).toBe(after);
  });

  it("applies a change that removes the trailing newline", () => {
    const before = "alpha\nbeta\n";
    const after = "alpha\nbeta";
    expect(applyWithGit("src/f2.ts", before, after)).toBe(after);
  });

  it("applies a change touching the first and last lines", () => {
    const before = "first\nmiddle\nlast\n";
    const after = "FIRST\nmiddle\nLAST\n";
    expect(applyWithGit("src/g.ts", before, after)).toBe(after);
  });

  it("applies a wholesale rewrite", () => {
    const before = "one\ntwo\nthree\n";
    const after = "completely\ndifferent\ncontent\nentirely\n";
    expect(applyWithGit("src/h.ts", before, after)).toBe(after);
  });

  it("applies a change to a file that was empty", () => {
    const before = "";
    const after = "now it has content\n";
    expect(applyWithGit("src/i.ts", before, after)).toBe(after);
  });

  it("preserves lines that merely look like diff syntax", () => {
    // Repository content is attacker-controlled, and a file containing diff
    // markers is the obvious attempt at making one file's hunk swallow
    // another's header.
    const before = "--- a/etc/passwd\n+++ b/etc/passwd\n@@ -1 +1 @@\nreal content\n";
    const after = "--- a/etc/passwd\n+++ b/etc/passwd\n@@ -1 +1 @@\nreal content, edited\n";
    expect(applyWithGit("src/j.ts", before, after)).toBe(after);
  });
});

describe("the policy engine can read what we render", () => {
  it("parses back to the changes that were made", () => {
    const diff = formatUnifiedDiff([
      { path: "src/a.ts", before: "a\nb\nc\n", after: "a\nB\nc\n" },
      { path: "src/b.ts", before: "x\n", after: "x\ny\n" },
    ]);
    const parsed = parseUnifiedDiff(diff);

    expect(parsed.files.map((f) => f.path)).toEqual(["src/a.ts", "src/b.ts"]);
    expect(parsed.addedCount).toBe(2);
    expect(parsed.removedCount).toBe(1);
    expect(parsed.files[0]?.change).toBe("modified");
  });

  it("survives a file whose content contains a diff header", () => {
    const diff = formatUnifiedDiff([
      {
        path: "src/a.ts",
        before: 'const x = "diff --git a/evil b/evil";\n',
        after: 'const x = "diff --git a/evil b/evil"; // edited\n',
      },
    ]);
    // The parser sees the embedded header, because a diff genuinely cannot
    // distinguish it from a real one. What matters is that it appears as a
    // *file we are changing* rather than smuggling an unrelated path — and
    // the diff-policy blast-radius rule then rejects the unlisted path.
    const parsed = parseUnifiedDiff(diff);
    expect(parsed.files.some((f) => f.path === "src/a.ts")).toBe(true);
  });

  it("emits nothing for an unchanged file", () => {
    expect(formatUnifiedDiff([{ path: "src/a.ts", before: "same\n", after: "same\n" }])).toBe("");
  });
});

describe("paths that cannot be rendered safely", () => {
  it("refuses a path containing a newline", () => {
    // A newline in a path lets one file header inject a second file into the
    // diff — one the policy engine would attribute to us.
    expect(() =>
      formatUnifiedDiff([
        { path: "src/a.ts\ndiff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml", before: "a\n", after: "b\n" },
      ]),
    ).toThrow(UnifiedDiffError);
  });

  it("refuses a path containing the header delimiter", () => {
    expect(() =>
      formatUnifiedDiff([{ path: "src/a b/etc/passwd", before: "a\n", after: "b\n" }]),
    ).toThrow(UnifiedDiffError);
  });

  it("refuses an empty path", () => {
    expect(() => formatUnifiedDiff([{ path: "", before: "a\n", after: "b\n" }])).toThrow(
      UnifiedDiffError,
    );
  });
});

describe("large inputs", () => {
  it("renders a change in a large file without quadratic blow-up", () => {
    // The head/tail trim is what makes this practical: an anchored edit in a
    // 20,000-line file leaves a matrix a few lines square.
    const lines = Array.from({ length: 20_000 }, (_, i) => `line ${i}`);
    const before = lines.join("\n") + "\n";
    const edited = [...lines];
    edited[10_000] = "line 10000, edited";
    const after = edited.join("\n") + "\n";

    const started = Date.now();
    const diff = formatUnifiedDiff([{ path: "src/big.ts", before, after }]);
    expect(Date.now() - started).toBeLessThan(2_000);

    const parsed = parseUnifiedDiff(diff);
    expect(parsed.addedCount).toBe(1);
    expect(parsed.removedCount).toBe(1);
  });
});
