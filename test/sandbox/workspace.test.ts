import { describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, stat, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  assertWithinWorkspace,
  materialiseWorkspace,
  WorkspaceError,
  type CommandRunner,
} from "../../src/sandbox/workspace.ts";

/**
 * The working tree verification runs in.
 *
 * Two things matter here. That the tree is the *repository* with the migration
 * overlaid — not the handful of files the agent was shown, which would fail a
 * suite for reasons unrelated to the migration — and that a model-proposed
 * path cannot write outside it.
 */

/** A clone that just writes the files a real one would have produced. */
function fakeClone(files: Record<string, string> = {}, code = 0, stderr = ""): CommandRunner {
  return {
    async run(_command, _args, options) {
      if (code === 0) {
        await mkdir(join(options.cwd, ".git"), { recursive: true });
        for (const [path, content] of Object.entries(files)) {
          const target = join(options.cwd, path);
          await mkdir(join(target, ".."), { recursive: true });
          await writeFile(target, content, "utf8");
        }
      }
      return { code, stdout: "", stderr };
    },
  };
}

const CHECKOUT = { url: "https://github.com/acme/widgets.git", ref: "main" };

describe("materialising a workspace", () => {
  it("overlays the migration onto a real checkout", async () => {
    // The suite needs the modules the changed files import. A tree built from
    // the blast radius alone would fail for reasons that are not the
    // migration's fault, which reads as a verdict.
    const workspace = await materialiseWorkspace({
      checkout: CHECKOUT,
      overlay: [{ path: "src/index.ts", content: "migrated" }],
      runner: fakeClone({
        "src/index.ts": "original",
        "src/untouched.ts": "still here",
        "package.json": "{}",
      }),
    });

    try {
      expect(await readFile(join(workspace.path, "src/index.ts"), "utf8")).toBe("migrated");
      expect(await readFile(join(workspace.path, "src/untouched.ts"), "utf8")).toBe("still here");
    } finally {
      await workspace.dispose();
    }
  });

  it("creates directories for a file the checkout did not have", async () => {
    const workspace = await materialiseWorkspace({
      checkout: CHECKOUT,
      overlay: [{ path: "src/deep/nested/new.ts", content: "added" }],
      runner: fakeClone({ "package.json": "{}" }),
    });

    try {
      expect(await readFile(join(workspace.path, "src/deep/nested/new.ts"), "utf8")).toBe("added");
    } finally {
      await workspace.dispose();
    }
  });

  it("passes the token in a header, never in the remote URL", async () => {
    // A token in the URL persists in .git/config, inside a tree that untrusted
    // code is about to run in.
    const seen: string[][] = [];
    const runner: CommandRunner = {
      async run(_c, args, options) {
        seen.push([...args]);
        await mkdir(join(options.cwd, ".git"), { recursive: true });
        return { code: 0, stdout: "", stderr: "" };
      },
    };

    const workspace = await materialiseWorkspace({
      checkout: { ...CHECKOUT, token: "ghs_supersecrettoken" },
      overlay: [],
      runner,
    });

    try {
      const args = seen[0]!;
      expect(args.some((a) => a.includes("Authorization: Bearer ghs_supersecrettoken"))).toBe(true);
      expect(args.some((a) => a.startsWith("https://") && a.includes("ghs_"))).toBe(false);
    } finally {
      await workspace.dispose();
    }
  });

  it("keeps the token out of a clone failure message", async () => {
    await expect(
      materialiseWorkspace({
        checkout: { ...CHECKOUT, token: "ghs_supersecrettoken" },
        overlay: [],
        runner: fakeClone({}, 128, "fatal: could not read Authorization: Bearer ghs_supersecrettoken"),
      }),
    ).rejects.toThrow(/\[REDACTED\]/);
  });

  it("removes the tree when the clone fails", async () => {
    // A failed verification must not leave a checkout on the worker.
    const roots = await mkdtemp(join(tmpdir(), "driftless-test-root-"));
    try {
      await expect(
        materialiseWorkspace({
          checkout: CHECKOUT,
          overlay: [],
          runner: fakeClone({}, 128, "fatal: repository not found"),
          root: roots,
        }),
      ).rejects.toThrow(WorkspaceError);

      const { readdir } = await import("node:fs/promises");
      expect(await readdir(roots)).toEqual([]);
    } finally {
      await rm(roots, { recursive: true, force: true });
    }
  });

  it("disposes twice without throwing", async () => {
    const workspace = await materialiseWorkspace({
      checkout: CHECKOUT,
      overlay: [],
      runner: fakeClone(),
    });
    await workspace.dispose();
    await expect(workspace.dispose()).resolves.toBeUndefined();
    await expect(stat(workspace.path)).rejects.toThrow();
  });
});

describe("refusing to write outside the workspace", () => {
  const ROOT = "/tmp/driftless-workspace";

  it("refuses a traversal", () => {
    expect(() => assertWithinWorkspace(ROOT, "../../etc/passwd")).toThrow(WorkspaceError);
  });

  it("refuses a traversal that returns inside", () => {
    // normalize() collapses this to something inside, but only after leaving.
    expect(() => assertWithinWorkspace(ROOT, "src/../../driftless-workspace-evil/x")).toThrow(
      WorkspaceError,
    );
  });

  it("refuses an absolute path", () => {
    expect(() => assertWithinWorkspace(ROOT, "/etc/passwd")).toThrow(WorkspaceError);
  });

  it("refuses a null byte", () => {
    expect(() => assertWithinWorkspace(ROOT, "src/index.ts\0.png")).toThrow(WorkspaceError);
  });

  it("refuses a write into .git", () => {
    // Hooks execute on ordinary git commands, so this changes what the host
    // does rather than what the suite does.
    expect(() => assertWithinWorkspace(ROOT, ".git/hooks/pre-commit")).toThrow(WorkspaceError);
    expect(() => assertWithinWorkspace(ROOT, ".git/config")).toThrow(WorkspaceError);
  });

  it("allows an ordinary nested path", () => {
    expect(assertWithinWorkspace(ROOT, "src/a/b.ts")).toBe(`${ROOT}/src/a/b.ts`);
  });

  it("allows a dotfile that is not .git", () => {
    expect(assertWithinWorkspace(ROOT, ".github/workflows/ci.yml")).toBe(
      `${ROOT}/.github/workflows/ci.yml`,
    );
  });
});

describe("refusing traversal through materialise", () => {
  it("does not write the file, and cleans up", async () => {
    const roots = await mkdtemp(join(tmpdir(), "driftless-test-root-"));
    try {
      await expect(
        materialiseWorkspace({
          checkout: CHECKOUT,
          overlay: [{ path: "../escaped.ts", content: "should not exist" }],
          runner: fakeClone({ "package.json": "{}" }),
          root: roots,
        }),
      ).rejects.toThrow(/outside the workspace/);

      const { readdir } = await import("node:fs/promises");
      expect(await readdir(roots)).toEqual([]);
    } finally {
      await rm(roots, { recursive: true, force: true });
    }
  });
});
