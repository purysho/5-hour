import { describe, expect, it } from "vitest";
import {
  GitHubContentClient,
  selectSourcePaths,
  type TreeEntry,
} from "../../src/forge/github-contents.ts";
import { ForgeError, type ForgeHttpClient, type ForgeHttpResponse } from "../../src/forge/github-forge.ts";
import { ScopedToken, REQUIRED_PERMISSIONS } from "../../src/github/token.ts";

/**
 * Reading a downstream repository.
 *
 * Two concerns, and they pull in opposite directions. The reads must be
 * bounded — a repository is attacker-authored and can be arbitrarily large —
 * and they must be honest about what they could not read, because a file
 * silently dropped becomes a call site the migration misses.
 */

const SHA = "b".repeat(40);
const COMMIT = "a".repeat(40);
const COORD = { owner: "acme", name: "widgets" };

interface Call {
  method: string;
  url: string;
}

function stubHttp(routes: {
  [key: string]: ForgeHttpResponse | ((call: Call) => ForgeHttpResponse);
}): { http: ForgeHttpClient; calls: Call[] } {
  const calls: Call[] = [];
  const http: ForgeHttpClient = {
    async request(method, url) {
      const call = { method, url };
      calls.push(call);
      const path = url.replace("https://api.github.com", "");
      for (const [pattern, response] of Object.entries(routes)) {
        const [routeMethod, routePath] = pattern.split(" ");
        if (routeMethod !== method) continue;
        if (routePath !== path && !path.startsWith(routePath as string)) continue;
        return typeof response === "function" ? response(call) : response;
      }
      return { status: 599, body: `{"unrouted":${JSON.stringify(`${method} ${path}`)}}` };
    },
  };
  return { http, calls };
}

const json = (status: number, value: unknown): ForgeHttpResponse => ({
  status,
  body: JSON.stringify(value),
});

const blob = (content: string, size = Buffer.byteLength(content, "utf8")) =>
  json(200, { encoding: "base64", size, content: Buffer.from(content, "utf8").toString("base64") });

function token(): ScopedToken {
  return new ScopedToken(
    "ghs_realsecrettokenvalue",
    {
      providerId: "provider-1",
      repositoryId: "repo-1",
      installationId: "install-1",
      permissions: REQUIRED_PERMISSIONS,
    } as never,
    new Date(Date.now() + 600_000),
    "token-1",
  );
}

function treeRoutes(entries: unknown[], truncated = false) {
  return {
    "GET /repos/acme/widgets/commits/": json(200, {
      sha: COMMIT,
      commit: { tree: { sha: "tree-root" } },
    }),
    "GET /repos/acme/widgets/git/trees/": json(200, { truncated, tree: entries }),
  };
}

describe("snapshotting a repository", () => {
  it("resolves a branch to the commit a migration would be based on", async () => {
    // The base sha is what pins the whole migration — the policy decision, the
    // dedupe key, and the commit's parent. Resolving it here, once, is what
    // stops the base moving underneath the pipeline.
    const { http } = stubHttp(
      treeRoutes([{ path: "src/a.ts", sha: SHA, type: "blob", size: 10 }]),
    );
    const client = new GitHubContentClient({ http });

    const snapshot = await client.snapshot(token(), COORD, "main");

    expect(snapshot?.commitSha).toBe(COMMIT);
    expect(snapshot?.entries).toEqual([{ path: "src/a.ts", sha: SHA, size: 10 }]);
  });

  it("returns null for an empty repository rather than failing the job", async () => {
    // GitHub answers 409 for a repository with no commits. There is nothing to
    // migrate, which is an ordinary state and not an error worth a retry.
    const { http } = stubHttp({ "GET /repos/acme/widgets/commits/": json(409, { message: "Git Repository is empty." }) });
    const client = new GitHubContentClient({ http });

    await expect(client.snapshot(token(), COORD, "main")).resolves.toBeNull();
  });

  it("keeps trees and submodules out of the entry list", async () => {
    // A submodule entry carries a commit sha, not a blob sha. Reading it as a
    // blob would 404 at best and read the wrong repository at worst.
    const { http } = stubHttp(
      treeRoutes([
        { path: "src", sha: "t".repeat(40), type: "tree" },
        { path: "deps/lib", sha: "c".repeat(40), type: "commit" },
        { path: "src/a.ts", sha: SHA, type: "blob", size: 4 },
      ]),
    );
    const client = new GitHubContentClient({ http });

    const snapshot = await client.snapshot(token(), COORD, "main");
    expect(snapshot?.entries.map((entry) => entry.path)).toEqual(["src/a.ts"]);
  });

  it("reports truncation instead of pretending the tree was complete", async () => {
    // A truncated tree means a file's absence proves nothing. Callers need to
    // know that before they conclude a repository has no manifest.
    const events: string[] = [];
    const { http } = stubHttp(treeRoutes([], true));
    const client = new GitHubContentClient({ http, log: (event) => events.push(event) });

    const snapshot = await client.snapshot(token(), COORD, "main");

    expect(snapshot?.truncated).toBe(true);
    expect(events).toContain("contents.tree_truncated");
  });

  it("refuses a ref that could reshape the request path", async () => {
    const { http, calls } = stubHttp({});
    const client = new GitHubContentClient({ http });

    await expect(client.snapshot(token(), COORD, "../../etc")).rejects.toBeInstanceOf(ForgeError);
    expect(calls).toHaveLength(0);
  });
});

describe("reading a blob", () => {
  it("decodes base64 rather than trusting a utf-8 round trip", async () => {
    const { http } = stubHttp({ "GET /repos/acme/widgets/git/blobs/": blob("const x = 1;\n") });
    const client = new GitHubContentClient({ http });

    await expect(client.readBlob(token(), COORD, SHA)).resolves.toBe("const x = 1;\n");
  });

  it("returns null for a binary file rather than mojibake", async () => {
    // A NUL byte means this is not source. Decoding it to a string and showing
    // it to a model produces a proposal to edit bytes that are not text.
    const withNul = Buffer.from([0x61, 0x00, 0x62]).toString("base64");
    const { http } = stubHttp({
      "GET /repos/acme/widgets/git/blobs/": json(200, { encoding: "base64", size: 3, content: withNul }),
    });
    const client = new GitHubContentClient({ http });

    await expect(client.readBlob(token(), COORD, SHA)).resolves.toBeNull();
  });

  it("refuses a file above the size ceiling", async () => {
    const { http } = stubHttp({ "GET /repos/acme/widgets/git/blobs/": blob("x", 900_000) });
    const client = new GitHubContentClient({ http, maxFileBytes: 1000 });

    await expect(client.readBlob(token(), COORD, SHA)).resolves.toBeNull();
  });

  it("refuses a size the response understated", async () => {
    // The declared size is GitHub's claim about the content. The decoded
    // length is the thing that actually costs us memory and prompt budget, so
    // it is checked too.
    const { http } = stubHttp({ "GET /repos/acme/widgets/git/blobs/": blob("y".repeat(5_000), 1) });
    const client = new GitHubContentClient({ http, maxFileBytes: 1000 });

    await expect(client.readBlob(token(), COORD, SHA)).resolves.toBeNull();
  });

  it("does not put the token in the error when a read fails", async () => {
    const { http } = stubHttp({
      "GET /repos/acme/widgets/git/blobs/": json(401, { message: "Bad credentials for ghs_realsecrettokenvalue" }),
    });
    const client = new GitHubContentClient({ http });

    await expect(client.readBlob(token(), COORD, SHA)).rejects.toThrow(
      /^(?!.*ghs_realsecrettokenvalue).*$/s,
    );
  });
});

describe("reading a set of files", () => {
  it("stops at the total budget instead of reading the whole repository", async () => {
    const { http, calls } = stubHttp({ "GET /repos/acme/widgets/git/blobs/": blob("x".repeat(400)) });
    const client = new GitHubContentClient({ http });
    const entries: TreeEntry[] = [
      { path: "src/a.ts", sha: SHA, size: 400 },
      { path: "src/b.ts", sha: SHA, size: 400 },
      { path: "src/c.ts", sha: SHA, size: 400 },
    ];

    const files = await client.readFiles(token(), COORD, entries, { maxTotalBytes: 900 });

    expect(files.map((file) => file.path)).toEqual(["src/a.ts", "src/b.ts"]);
    expect(calls).toHaveLength(2);
  });

  it("skips a file it cannot read without losing the rest", async () => {
    let call = 0;
    const { http } = stubHttp({
      "GET /repos/acme/widgets/git/blobs/": () =>
        ++call === 1 ? json(404, { message: "Not Found" }) : blob("ok"),
    });
    const client = new GitHubContentClient({ http });
    const entries: TreeEntry[] = [
      { path: "src/a.ts", sha: SHA, size: 2 },
      { path: "src/b.ts", sha: SHA, size: 2 },
    ];

    const files = await client.readFiles(token(), COORD, entries, { maxTotalBytes: 10_000 });
    expect(files.map((file) => file.path)).toEqual(["src/b.ts"]);
  });
});

describe("choosing which files to show the agent", () => {
  const entry = (path: string, size = 100): TreeEntry => ({ path, sha: SHA, size });

  it("excludes vendored and generated trees", async () => {
    // A pull request that edits `node_modules` or `dist` changes code the
    // maintainer neither wrote nor reviews — and `dist` is worse, because the
    // next build silently reverts it.
    const selected = selectSourcePaths([
      entry("src/client.ts"),
      entry("node_modules/acme-sdk/index.js"),
      entry("dist/bundle.js"),
      entry("vendor/acme/client.js"),
      entry("coverage/lcov-report/index.js"),
    ]);

    expect(selected.map((file) => file.path)).toEqual(["src/client.ts"]);
  });

  it("excludes minified bundles and declaration files", async () => {
    const selected = selectSourcePaths([
      entry("src/app.ts"),
      entry("public/jquery.min.js"),
      entry("types/index.d.ts"),
    ]);

    expect(selected.map((file) => file.path)).toEqual(["src/app.ts"]);
  });

  it("excludes files above the per-file ceiling", async () => {
    const selected = selectSourcePaths([entry("src/small.ts", 10), entry("src/huge.ts", 900_000)], {
      maxFileBytes: 1000,
    });
    expect(selected.map((file) => file.path)).toEqual(["src/small.ts"]);
  });

  it("ignores files that are not source at all", async () => {
    const selected = selectSourcePaths([
      entry("README.md"),
      entry("logo.png"),
      entry("src/index.ts"),
    ]);
    expect(selected.map((file) => file.path)).toEqual(["src/index.ts"]);
  });

  it("spends the budget on src/ before anywhere else", async () => {
    // The cap truncates, so order decides what a repository gets migrated on.
    // Alphabetical order would spend it all in app/ on a repository that keeps
    // its code in src/.
    const selected = selectSourcePaths(
      [entry("app/a.ts"), entry("src/z.ts"), entry("lib/b.ts")],
      { maxFiles: 1 },
    );
    expect(selected.map((file) => file.path)).toEqual(["src/z.ts"]);
  });

  it("prefers shallower files within the same tree", async () => {
    const selected = selectSourcePaths([
      entry("src/a/b/c/deep.ts"),
      entry("src/shallow.ts"),
    ]);
    expect(selected.map((file) => file.path)[0]).toBe("src/shallow.ts");
  });

  it("is deterministic for a given tree", async () => {
    // Two workers must select the same files for the same commit, or a retry
    // migrates a different set than the attempt it is resuming.
    const entries = [entry("src/b.ts"), entry("src/a.ts"), entry("lib/c.ts")];
    const first = selectSourcePaths(entries).map((file) => file.path);
    const second = selectSourcePaths([...entries].reverse()).map((file) => file.path);
    expect(first).toEqual(second);
  });
});
