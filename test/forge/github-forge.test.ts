import { describe, expect, it } from "vitest";
import {
  ForgeError,
  GitHubForgeClient,
  type ForgeHttpClient,
  type ForgeHttpResponse,
  type OpenPullRequestRequest,
} from "../../src/forge/github-forge.ts";
import { ScopedToken, REQUIRED_PERMISSIONS, REDACTED } from "../../src/github/token.ts";
import type { FileChange } from "../../src/agent/unified-diff.ts";

/**
 * Writing the migration to GitHub.
 *
 * The first step in the pipeline that leaves a permanent artifact in somebody
 * else's repository, so the tests are mostly about restraint: what it refuses
 * to write, what it refuses to overwrite, and what it does when it meets its
 * own half-finished work.
 */

const BASE_SHA = "a".repeat(40);

interface Call {
  method: string;
  url: string;
  body: unknown;
  headers: Record<string, string>;
}

/** Records every request and answers from a routing table. */
function stubHttp(routes: {
  [key: string]: ForgeHttpResponse | ((call: Call) => ForgeHttpResponse);
}): { http: ForgeHttpClient; calls: Call[] } {
  const calls: Call[] = [];
  const http: ForgeHttpClient = {
    async request(method, url, body, headers) {
      const call = { method, url, body, headers: headers as Record<string, string> };
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

/** The happy path: no branch, base tree readable, four writes, a pull request. */
function happyRoutes(overrides: Record<string, ForgeHttpResponse> = {}) {
  return {
    "GET /repos/acme/widgets/git/ref/heads/": json(404, { message: "Not Found" }),
    "GET /repos/acme/widgets/git/commits/": json(200, { tree: { sha: "tree-base" } }),
    "GET /repos/acme/widgets/git/trees/": json(200, {
      truncated: false,
      tree: [
        { path: "src/index.ts", mode: "100644", type: "blob" },
        { path: "src/other.ts", mode: "100644", type: "blob" },
        { path: "scripts/build.sh", mode: "100755", type: "blob" },
      ],
    }),
    "POST /repos/acme/widgets/git/blobs": json(201, { sha: "blob-1" }),
    "POST /repos/acme/widgets/git/trees": json(201, { sha: "tree-new" }),
    "POST /repos/acme/widgets/git/commits": json(201, { sha: "c".repeat(40) }),
    "POST /repos/acme/widgets/git/refs": json(201, { ref: "refs/heads/driftless/abc" }),
    "POST /repos/acme/widgets/pulls": json(201, {
      number: 42,
      html_url: "https://github.com/acme/widgets/pull/42",
    }),
    ...overrides,
  };
}

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

function request(overrides: Partial<OpenPullRequestRequest> = {}): OpenPullRequestRequest {
  const files: FileChange[] = [
    { path: "src/index.ts", before: "createClient()", after: "createClient({})" },
  ];
  return {
    token: token(),
    owner: "acme",
    name: "widgets",
    baseSha: BASE_SHA,
    branch: "driftless/abc12345",
    baseBranch: "main",
    title: "Migrate to acme-sdk 3.0.0",
    body: "Body text",
    files,
    commitMessage: "Migrate to acme-sdk 3.0.0",
    ...overrides,
  };
}

describe("writing the commit", () => {
  it("writes the content it was given, never a re-reading of the diff", async () => {
    // The property the whole design rests on (see the header of
    // unified-diff.ts): what the policy engine inspected and what lands in
    // the branch must be the same object. That holds only if the bytes
    // travel here directly.
    const { http, calls } = stubHttp(happyRoutes());
    const client = new GitHubForgeClient({ http });

    await client.openPullRequest(
      request({
        files: [{ path: "src/index.ts", before: "old contents", after: "new contents" }],
      }),
    );

    const blob = calls.find((call) => call.url.endsWith("/git/blobs"));
    const body = blob?.body as { content: string; encoding: string };
    expect(body.encoding).toBe("base64");
    expect(Buffer.from(body.content, "base64").toString("utf8")).toBe("new contents");
  });

  it("commits every changed file at once, parented on the generated base", async () => {
    // One commit, not one per file: a tree that lands half-applied is a
    // repository in a state the migration never produced or tested.
    const { http, calls } = stubHttp(happyRoutes());
    const client = new GitHubForgeClient({ http });

    await client.openPullRequest(
      request({
        files: [
          { path: "src/index.ts", before: "a", after: "b" },
          { path: "src/other.ts", before: "c", after: "d" },
        ],
      }),
    );

    expect(calls.filter((call) => call.url.endsWith("/git/blobs"))).toHaveLength(2);
    const commits = calls.filter((call) => call.url.endsWith("/git/commits"));
    expect(commits).toHaveLength(1);
    expect((commits[0]?.body as { parents: string[] }).parents).toEqual([BASE_SHA]);
  });

  it("builds on the base tree so untouched files survive", async () => {
    const { http, calls } = stubHttp(happyRoutes());
    await new GitHubForgeClient({ http }).openPullRequest(request());

    const tree = calls.find((call) => call.method === "POST" && call.url.endsWith("/git/trees"));
    expect((tree?.body as { base_tree: string }).base_tree).toBe("tree-base");
  });

  it("preserves the executable bit", async () => {
    // Writing a 100755 script back at 100644 clears the executable bit with
    // no line in the diff to explain it — a broken build the maintainer
    // cannot attribute to us.
    const { http, calls } = stubHttp(happyRoutes());
    await new GitHubForgeClient({ http }).openPullRequest(
      request({
        files: [{ path: "scripts/build.sh", before: "#!/bin/sh\na", after: "#!/bin/sh\nb" }],
      }),
    );

    const tree = calls.find((call) => call.method === "POST" && call.url.endsWith("/git/trees"));
    const entries = (tree?.body as { tree: { path: string; mode: string }[] }).tree;
    expect(entries[0]?.mode).toBe("100755");
  });

  it("narrows a symlink or submodule mode to a regular file", async () => {
    // A migration that turns a source file into a symlink is a content change
    // the diff does not describe.
    const { http, calls } = stubHttp(
      happyRoutes({
        "GET /repos/acme/widgets/git/trees/": json(200, {
          truncated: false,
          tree: [{ path: "src/index.ts", mode: "120000", type: "blob" }],
        }),
      }),
    );
    await new GitHubForgeClient({ http }).openPullRequest(request());

    const tree = calls.find((call) => call.method === "POST" && call.url.endsWith("/git/trees"));
    const entries = (tree?.body as { tree: { mode: string }[] }).tree;
    expect(entries[0]?.mode).toBe("100644");
  });

  it("refuses when the file is absent from the base commit", async () => {
    // The base moved between generation and write. Committing anyway would
    // write content derived from a file that no longer exists.
    const { http } = stubHttp(
      happyRoutes({
        "GET /repos/acme/widgets/git/trees/": json(200, { truncated: false, tree: [] }),
      }),
    );
    await expect(
      new GitHubForgeClient({ http }).openPullRequest(request()),
    ).rejects.toThrow(/not present at the base commit/);
  });

  it("walks subtrees when the recursive listing truncates", async () => {
    // Large monorepos truncate. Falling back to 100644 would silently clear
    // executable bits on exactly the repositories where that hurts most.
    let recursive = true;
    const { http, calls } = stubHttp({
      ...happyRoutes(),
      "GET /repos/acme/widgets/git/trees/": (call) => {
        if (recursive && call.url.includes("recursive=1")) {
          recursive = false;
          return json(200, { truncated: true, tree: [] });
        }
        if (call.url.includes("/git/trees/tree-base")) {
          return json(200, {
            tree: [{ path: "scripts", mode: "040000", type: "tree", sha: "tree-scripts" }],
          });
        }
        return json(200, {
          tree: [{ path: "build.sh", mode: "100755", type: "blob", sha: "blob-x" }],
        });
      },
    });

    await new GitHubForgeClient({ http }).openPullRequest(
      request({ files: [{ path: "scripts/build.sh", before: "a", after: "b" }] }),
    );

    const tree = calls.find((call) => call.method === "POST" && call.url.endsWith("/git/trees"));
    expect((tree?.body as { tree: { mode: string }[] }).tree[0]?.mode).toBe("100755");
  });
});

describe("meeting its own previous attempt", () => {
  it("returns the existing pull request rather than opening a second", async () => {
    // ADR-0004. A retry that duplicates the pull request is worse than one
    // that fails: the maintainer sees two.
    const { http } = stubHttp(
      happyRoutes({
        "POST /repos/acme/widgets/pulls": json(422, {
          message: "A pull request already exists for acme:driftless/abc12345.",
        }),
        "GET /repos/acme/widgets/pulls": json(200, [
          { number: 7, html_url: "https://github.com/acme/widgets/pull/7" },
        ]),
      }),
    );

    const result = await new GitHubForgeClient({ http }).openPullRequest(request());
    expect(result).toEqual({
      number: 7,
      url: "https://github.com/acme/widgets/pull/7",
      alreadyOpen: true,
    });
  });

  it("resolves an existing branch to its open pull request without writing", async () => {
    const { http, calls } = stubHttp(
      happyRoutes({
        "GET /repos/acme/widgets/git/ref/heads/": json(200, { object: { sha: "d".repeat(40) } }),
        "GET /repos/acme/widgets/pulls": json(200, [
          { number: 9, html_url: "https://github.com/acme/widgets/pull/9" },
        ]),
      }),
    );

    const result = await new GitHubForgeClient({ http }).openPullRequest(request());

    expect(result.alreadyOpen).toBe(true);
    expect(result.number).toBe(9);
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(0);
  });

  it("never force-updates a branch that has no pull request", async () => {
    // The case this protects: a maintainer pushed a fixup onto our branch.
    // Force-updating destroys the most valuable thing that can happen to one
    // of these pull requests.
    const { http, calls } = stubHttp(
      happyRoutes({
        "GET /repos/acme/widgets/git/ref/heads/": json(200, { object: { sha: "d".repeat(40) } }),
        "GET /repos/acme/widgets/pulls": json(200, []),
      }),
    );

    await expect(new GitHubForgeClient({ http }).openPullRequest(request())).rejects.toThrow(
      /Refusing to force-update/,
    );
    expect(calls.some((call) => call.method === "PATCH")).toBe(false);
    expect(calls.some((call) => call.method === "POST")).toBe(false);
  });
});

describe("what it refuses to write", () => {
  const cases: { name: string; overrides: Partial<OpenPullRequestRequest>; pattern: RegExp }[] = [
    {
      name: "a path escaping the repository",
      overrides: { files: [{ path: "../../etc/passwd", before: "a", after: "b" }] },
      pattern: /Refusing to write path/,
    },
    {
      name: "anything under .git",
      overrides: { files: [{ path: ".git/config", before: "a", after: "b" }] },
      pattern: /Refusing to write path/,
    },
    {
      name: "an absolute path",
      overrides: { files: [{ path: "/etc/hosts", before: "a", after: "b" }] },
      pattern: /Refusing to write path/,
    },
    {
      name: "a branch name git itself would reject",
      overrides: { branch: "driftless/../../main" },
      pattern: /Invalid branch name/,
    },
    {
      name: "a branch name carrying a control character",
      overrides: { branch: "driftless/a\nb" },
      pattern: /Invalid branch name/,
    },
    {
      name: "an owner that is not a coordinate",
      overrides: { owner: "acme/../other" },
      pattern: /Invalid owner/,
    },
    {
      name: "a base that is not a commit sha",
      overrides: { baseSha: "HEAD" },
      pattern: /Invalid base commit sha/,
    },
    {
      name: "an empty change set",
      overrides: { files: [] },
      pattern: /no changes/,
    },
    {
      name: "the same path twice",
      overrides: {
        files: [
          { path: "src/index.ts", before: "a", after: "b" },
          { path: "src/index.ts", before: "a", after: "c" },
        ],
      },
      pattern: /appears twice/,
    },
    {
      name: "a file that did not actually change",
      overrides: { files: [{ path: "src/index.ts", before: "same", after: "same" }] },
      pattern: /unchanged/,
    },
  ];

  for (const testCase of cases) {
    it(`refuses ${testCase.name}`, async () => {
      const { http, calls } = stubHttp(happyRoutes());
      await expect(
        new GitHubForgeClient({ http }).openPullRequest(request(testCase.overrides)),
      ).rejects.toThrow(testCase.pattern);
      // Refused before the credential is read or a request is made.
      expect(calls).toHaveLength(0);
    });
  }

  it("refuses a file above the size ceiling", async () => {
    const { http } = stubHttp(happyRoutes());
    const client = new GitHubForgeClient({ http, maxFileBytes: 16 });
    await expect(
      client.openPullRequest(
        request({ files: [{ path: "src/index.ts", before: "a", after: "x".repeat(64) }] }),
      ),
    ).rejects.toThrow(/above the 16 ceiling/);
  });

  it("refuses a change set above the file ceiling", async () => {
    const { http } = stubHttp(happyRoutes());
    const client = new GitHubForgeClient({ http, maxFiles: 2 });
    const files: FileChange[] = ["a", "b", "c"].map((n) => ({
      path: `src/${n}.ts`,
      before: "x",
      after: "y",
    }));
    await expect(client.openPullRequest(request({ files }))).rejects.toThrow(/above the 2 ceiling/);
  });
});

describe("the credential", () => {
  it("sends the revealed token and never the wrapper", async () => {
    const { http, calls } = stubHttp(happyRoutes());
    await new GitHubForgeClient({ http }).openPullRequest(request());

    expect(calls.length).toBeGreaterThan(0);
    for (const call of calls) {
      expect(call.headers["authorization"]).toBe("Bearer ghs_realsecrettokenvalue");
      expect(call.headers["authorization"]).not.toContain(REDACTED);
    }
  });

  it("keeps the token out of an error built from a response body", async () => {
    // A 401 body has been known to echo the credential that produced it, and
    // this message goes to logs and the audit chain.
    const { http } = stubHttp(
      happyRoutes({
        "GET /repos/acme/widgets/git/commits/": json(401, {
          message: "Bad credentials: ghs_realsecrettokenvalue",
        }),
      }),
    );

    await expect(new GitHubForgeClient({ http }).openPullRequest(request())).rejects.toThrow(
      ForgeError,
    );
    await expect(
      new GitHubForgeClient({ http }).openPullRequest(request()),
    ).rejects.not.toThrow(/ghs_realsecrettokenvalue/);
  });

  it("keeps the token out of an error thrown by the transport", async () => {
    const http: ForgeHttpClient = {
      async request(_method, url, _body, headers) {
        throw new Error(`connect ECONNREFUSED ${url} (${headers["authorization"]})`);
      },
    };
    await expect(new GitHubForgeClient({ http }).openPullRequest(request())).rejects.not.toThrow(
      /ghs_realsecrettokenvalue/,
    );
  });

  it("refuses an expired token before making a request", async () => {
    const expired = new ScopedToken(
      "ghs_expired",
      {
        providerId: "provider-1",
        repositoryId: "repo-1",
        installationId: "install-1",
        permissions: REQUIRED_PERMISSIONS,
      } as never,
      new Date(Date.now() - 1_000),
      "token-old",
    );
    const { http, calls } = stubHttp(happyRoutes());
    await expect(
      new GitHubForgeClient({ http }).openPullRequest(request({ token: expired })),
    ).rejects.toThrow(/expired/);
    expect(calls).toHaveLength(0);
  });
});

describe("the pull request itself", () => {
  it("targets the base branch and lets maintainers push to it", async () => {
    const { http, calls } = stubHttp(happyRoutes());
    await new GitHubForgeClient({ http }).openPullRequest(request({ baseBranch: "develop" }));

    const pull = calls.find((call) => call.method === "POST" && call.url.endsWith("/pulls"));
    expect(pull?.body).toMatchObject({
      base: "develop",
      head: "driftless/abc12345",
      maintainer_can_modify: true,
    });
  });

  it("reports a failure to open rather than claiming success", async () => {
    const { http } = stubHttp(
      happyRoutes({ "POST /repos/acme/widgets/pulls": json(403, { message: "Forbidden" }) }),
    );
    await expect(new GitHubForgeClient({ http }).openPullRequest(request())).rejects.toThrow(
      /returned 403/,
    );
  });

  it("refuses a 201 that does not carry a usable pull request", async () => {
    const { http } = stubHttp(
      happyRoutes({ "POST /repos/acme/widgets/pulls": json(201, { number: 42 }) }),
    );
    await expect(new GitHubForgeClient({ http }).openPullRequest(request())).rejects.toThrow(
      /unusable response/,
    );
  });

  it("does not mistake a non-JSON body for a result", async () => {
    const { http } = stubHttp(
      happyRoutes({
        "POST /repos/acme/widgets/pulls": { status: 201, body: "<html>504 Gateway Timeout</html>" },
      }),
    );
    await expect(new GitHubForgeClient({ http }).openPullRequest(request())).rejects.toThrow(
      /not JSON/,
    );
  });
});
