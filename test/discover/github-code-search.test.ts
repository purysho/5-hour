import { describe, it, expect, beforeEach } from "vitest";
import {
  GitHubCodeSearchCrawler,
  DiscoveryError,
  isValidPackageName,
} from "../../src/discover/github-code-search.ts";
import type { ForgeHttpClient, ForgeHttpResponse } from "../../src/forge/github-forge.ts";
import { Secret } from "../../src/config.ts";
import { decideTarget } from "../../src/discover/affected.ts";

/**
 * The downstream crawler.
 *
 * The property under test throughout is that a code-search hit is a lead and
 * never evidence: a candidate exists only once the real root `package.json`
 * has been fetched and parsed and genuinely declares the package. Everything
 * else here — dedupe, bounds, skip semantics — protects that one claim or
 * protects the credential that makes the crawl possible.
 */

const CREDENTIAL_VALUE = "ghp_supersecret_credential_value_0001";
const CREDENTIAL = new Secret(CREDENTIAL_VALUE, "GITHUB_SEARCH_TOKEN");

interface Programmed {
  readonly status: number;
  readonly body: string;
}

class FakeHttp implements ForgeHttpClient {
  readonly requests: { method: string; url: string; headers: Record<string, string> }[] = [];
  readonly routes = new Map<string, Programmed>();
  fallback: Programmed = { status: 404, body: '{"message":"Not Found"}' };

  on(match: string, response: Programmed): this {
    this.routes.set(match, response);
    return this;
  }

  async request(
    method: "GET" | "POST" | "PATCH",
    url: string,
    _body: unknown,
    headers: Readonly<Record<string, string>>,
  ): Promise<ForgeHttpResponse> {
    this.requests.push({ method, url, headers: { ...headers } });
    for (const [match, response] of this.routes) {
      if (url.includes(match)) return response;
    }
    return this.fallback;
  }
}

function searchBody(items: unknown[]): string {
  return JSON.stringify({ total_count: items.length, incomplete_results: false, items });
}

function hit(owner: string, name: string, path = "package.json") {
  return { path, repository: { name, owner: { login: owner } } };
}

function repoBody(
  owner: string,
  name: string,
  overrides: Record<string, unknown> = {},
): string {
  return JSON.stringify({
    name,
    owner: { login: owner },
    default_branch: "main",
    stargazers_count: 120,
    archived: false,
    fork: false,
    ...overrides,
  });
}

function manifest(dependencies: Record<string, string>): string {
  return JSON.stringify({ name: "consumer", version: "1.0.0", dependencies });
}

let http: FakeHttp;
let logged: { event: string; detail: Record<string, unknown> }[];

function crawler(overrides: Partial<ConstructorParameters<typeof GitHubCodeSearchCrawler>[0]> = {}) {
  return new GitHubCodeSearchCrawler({
    http,
    log: (event, detail) => logged.push({ event, detail }),
    ...overrides,
  });
}

beforeEach(() => {
  http = new FakeHttp();
  logged = [];
});

describe("a genuine consumer", () => {
  it("becomes a candidate", async () => {
    http
      .on("/search/code", { status: 200, body: searchBody([hit("acme", "widgets")]) })
      .on("/repos/acme/widgets/contents/package.json", {
        status: 200,
        body: manifest({ "acme-sdk": "^2.0.0" }),
      })
      .on("/repos/acme/widgets", { status: 200, body: repoBody("acme", "widgets") });

    const candidates = await crawler().findCandidates("acme-sdk", CREDENTIAL);

    expect(candidates).toHaveLength(1);
    expect(candidates[0]).toMatchObject({
      forge: "github",
      owner: "acme",
      name: "widgets",
      defaultBranch: "main",
      stars: 120,
      archived: false,
      fork: false,
    });
    expect(candidates[0]!.dependencies).toEqual([
      { packageName: "acme-sdk", range: "^2.0.0", kind: "dependencies" },
    ]);
  });

  it("does not invent a lockedVersion", async () => {
    // assessRepository treats a locked version as the strongest evidence
    // available. A fabricated one would override a correct reading of the
    // declared range.
    http
      .on("/search/code", { status: 200, body: searchBody([hit("acme", "widgets")]) })
      .on("/repos/acme/widgets/contents/package.json", {
        status: 200,
        body: manifest({ "acme-sdk": "^2.0.0" }),
      })
      .on("/repos/acme/widgets", { status: 200, body: repoBody("acme", "widgets") });

    const [candidate] = await crawler().findCandidates("acme-sdk", CREDENTIAL);
    expect(candidate!.lockedVersion).toBeUndefined();
  });

  it("produces a candidate decideTarget can judge", async () => {
    http
      .on("/search/code", { status: 200, body: searchBody([hit("acme", "widgets")]) })
      .on("/repos/acme/widgets/contents/package.json", {
        status: 200,
        body: manifest({ "acme-sdk": "^2.0.0" }),
      })
      .on("/repos/acme/widgets", { status: 200, body: repoBody("acme", "widgets") });

    const [candidate] = await crawler().findCandidates("acme-sdk", CREDENTIAL);
    const decision = decideTarget(candidate!, {
      packageName: "acme-sdk",
      fromVersion: "2.4.0",
      toVersion: "3.0.0",
    });

    expect(decision.targeted).toBe(true);
    expect(decision.assessment.impact).toBe("stranded");
  });
});

describe("a code-search false positive", () => {
  it("is rejected after the manifest is parsed", async () => {
    // The package name appears in a script, not in the dependencies. This is
    // the case the whole module exists to catch: acting on it means opening a
    // pull request against a repository that never depended on the package.
    http
      .on("/search/code", { status: 200, body: searchBody([hit("acme", "mentions")]) })
      .on("/repos/acme/mentions/contents/package.json", {
        status: 200,
        body: JSON.stringify({
          name: "mentions",
          scripts: { check: "npx acme-sdk --version" },
          dependencies: { lodash: "^4.0.0" },
        }),
      })
      .on("/repos/acme/mentions", { status: 200, body: repoBody("acme", "mentions") });

    const candidates = await crawler().findCandidates("acme-sdk", CREDENTIAL);

    expect(candidates).toHaveLength(0);
    expect(logged).toContainEqual({
      event: "discovery.repository_skipped",
      detail: { owner: "acme", name: "mentions", reason: "root manifest does not declare acme-sdk" },
    });
  });
});

describe("a nested manifest hit", () => {
  it("is ignored without a repository request", async () => {
    http.on("/search/code", {
      status: 200,
      body: searchBody([hit("acme", "monorepo", "packages/foo/package.json")]),
    });

    const candidates = await crawler().findCandidates("acme-sdk", CREDENTIAL);

    expect(candidates).toHaveLength(0);
    // Only the search itself. A nested hit never costs a round trip.
    expect(http.requests).toHaveLength(1);
    expect(logged[0]).toMatchObject({
      event: "discovery.search_complete",
      detail: { nestedIgnored: 1, rootManifests: 0 },
    });
  });
});

describe("duplicate hits", () => {
  it("emit one candidate and cost one inspection", async () => {
    http
      .on("/search/code", {
        status: 200,
        body: searchBody([hit("acme", "widgets"), hit("Acme", "Widgets"), hit("acme", "widgets")]),
      })
      .on("/repos/acme/widgets/contents/package.json", {
        status: 200,
        body: manifest({ "acme-sdk": "^2.0.0" }),
      })
      .on("/repos/acme/widgets", { status: 200, body: repoBody("acme", "widgets") });

    const candidates = await crawler().findCandidates("acme-sdk", CREDENTIAL);

    expect(candidates).toHaveLength(1);
    // search + repo + contents. GitHub treats owner/name case-insensitively,
    // so the differently-cased spelling is the same repository.
    expect(http.requests).toHaveLength(3);
  });
});

describe("a malformed manifest", () => {
  it("is skipped with a structured reason rather than a partial candidate", async () => {
    http
      .on("/search/code", { status: 200, body: searchBody([hit("acme", "broken")]) })
      .on("/repos/acme/broken/contents/package.json", { status: 200, body: "{ not json at all" })
      .on("/repos/acme/broken", { status: 200, body: repoBody("acme", "broken") });

    const candidates = await crawler().findCandidates("acme-sdk", CREDENTIAL);

    expect(candidates).toHaveLength(0);
    const skip = logged.find((entry) => entry.event === "discovery.repository_skipped");
    expect(skip?.detail["reason"]).toMatch(/unparseable manifest/);
  });

  it("does not log the manifest contents", async () => {
    // A manifest is attacker-authored and this reaches an operator's terminal.
    http
      .on("/search/code", { status: 200, body: searchBody([hit("acme", "broken")]) })
      .on("/repos/acme/broken/contents/package.json", {
        status: 200,
        body: '{ "evil": "SENTINEL_MANIFEST_BODY" ',
      })
      .on("/repos/acme/broken", { status: 200, body: repoBody("acme", "broken") });

    await crawler().findCandidates("acme-sdk", CREDENTIAL);
    expect(JSON.stringify(logged)).not.toContain("SENTINEL_MANIFEST_BODY");
  });
});

describe("repository metadata", () => {
  it("carries archived and fork through rather than rewriting them", async () => {
    // decideTarget owns eligibility. A candidate that silently normalised
    // these would be judged against flags it never declared.
    http
      .on("/search/code", { status: 200, body: searchBody([hit("acme", "old")]) })
      .on("/repos/acme/old/contents/package.json", {
        status: 200,
        body: manifest({ "acme-sdk": "^2.0.0" }),
      })
      .on("/repos/acme/old", {
        status: 200,
        body: repoBody("acme", "old", { archived: true, fork: true, stargazers_count: 3 }),
      });

    const [candidate] = await crawler().findCandidates("acme-sdk", CREDENTIAL);

    expect(candidate).toMatchObject({ archived: true, fork: true, stars: 3 });
    // And the policy layer, not the crawler, is what excludes it.
    const decision = decideTarget(candidate!, {
      packageName: "acme-sdk",
      fromVersion: "2.4.0",
      toVersion: "3.0.0",
    });
    expect(decision.targeted).toBe(false);
    expect(decision.skipReason).toBe("repository is archived");
  });

  it("skips a repository whose metadata has no usable default branch", async () => {
    http
      .on("/search/code", { status: 200, body: searchBody([hit("acme", "odd")]) })
      .on("/repos/acme/odd", {
        status: 200,
        body: JSON.stringify({ name: "odd", owner: { login: "acme" } }),
      });

    const candidates = await crawler().findCandidates("acme-sdk", CREDENTIAL);
    expect(candidates).toHaveLength(0);
  });

  it("skips a repository that 404s", async () => {
    // Renamed, deleted, or made private between the search and now. Ordinary,
    // and it must not abort the crawl.
    http
      .on("/search/code", {
        status: 200,
        body: searchBody([hit("acme", "gone"), hit("acme", "widgets")]),
      })
      .on("/repos/acme/gone", { status: 404, body: '{"message":"Not Found"}' })
      .on("/repos/acme/widgets/contents/package.json", {
        status: 200,
        body: manifest({ "acme-sdk": "^2.0.0" }),
      })
      .on("/repos/acme/widgets", { status: 200, body: repoBody("acme", "widgets") });

    const candidates = await crawler().findCandidates("acme-sdk", CREDENTIAL);

    expect(candidates).toHaveLength(1);
    expect(candidates[0]!.name).toBe("widgets");
  });

  it("skips a repository with no readable root package.json", async () => {
    http
      .on("/search/code", { status: 200, body: searchBody([hit("acme", "empty")]) })
      .on("/repos/acme/empty/contents/package.json", { status: 404, body: "{}" })
      .on("/repos/acme/empty", { status: 200, body: repoBody("acme", "empty") });

    const candidates = await crawler().findCandidates("acme-sdk", CREDENTIAL);
    expect(candidates).toHaveLength(0);
    expect(logged).toContainEqual({
      event: "discovery.repository_skipped",
      detail: { owner: "acme", name: "empty", reason: "no readable root package.json" },
    });
  });
});

describe("search failures", () => {
  it("fails loudly on a rate limit, rather than returning a short cohort", async () => {
    // A truncated result set is indistinguishable from "this package has few
    // consumers", and would quietly produce a small, wrong cohort.
    http.on("/search/code", { status: 429, body: "" });

    await expect(crawler().findCandidates("acme-sdk", CREDENTIAL)).rejects.toThrow(
      /code search rate limit/i,
    );
  });

  it("names the code search limit category on a 403", async () => {
    http.on("/search/code", { status: 403, body: '{"message":"rate limit exceeded"}' });

    await expect(crawler().findCandidates("acme-sdk", CREDENTIAL)).rejects.toThrow(
      /code search rate limit/i,
    );
  });

  it("fails loudly on a rejected credential", async () => {
    http.on("/search/code", { status: 401, body: "{}" });
    await expect(crawler().findCandidates("acme-sdk", CREDENTIAL)).rejects.toThrow(DiscoveryError);
  });

  it("fails loudly on a body that is not JSON", async () => {
    http.on("/search/code", { status: 200, body: "<html>gateway timeout</html>" });
    await expect(crawler().findCandidates("acme-sdk", CREDENTIAL)).rejects.toThrow(/not JSON/);
  });

  it("fails loudly on a JSON body with no items array", async () => {
    http.on("/search/code", { status: 200, body: '{"total_count":3}' });
    await expect(crawler().findCandidates("acme-sdk", CREDENTIAL)).rejects.toThrow(/items array/);
  });
});

describe("the credential", () => {
  it("never appears in a thrown error", async () => {
    http.on("/search/code", {
      status: 401,
      // Auth failures have been observed echoing the request that produced them.
      body: JSON.stringify({ message: `Bad credentials: ${CREDENTIAL_VALUE}` }),
    });

    await expect(crawler().findCandidates("acme-sdk", CREDENTIAL)).rejects.toSatisfy(
      (error: unknown) => {
        expect(String(error)).not.toContain(CREDENTIAL_VALUE);
        expect(JSON.stringify(error, Object.getOwnPropertyNames(error))).not.toContain(
          CREDENTIAL_VALUE,
        );
        return true;
      },
    );
  });

  it("never appears in captured log data", async () => {
    http
      .on("/search/code", { status: 200, body: searchBody([hit("acme", "widgets")]) })
      .on("/repos/acme/widgets/contents/package.json", {
        status: 200,
        body: manifest({ "acme-sdk": "^2.0.0" }),
      })
      .on("/repos/acme/widgets", { status: 200, body: repoBody("acme", "widgets") });

    await crawler().findCandidates("acme-sdk", CREDENTIAL);

    expect(logged.length).toBeGreaterThan(0);
    expect(JSON.stringify(logged)).not.toContain(CREDENTIAL_VALUE);
  });

  it("is not retained on the crawler after a crawl", async () => {
    http.on("/search/code", { status: 200, body: searchBody([]) });
    const instance = crawler();
    await instance.findCandidates("acme-sdk", CREDENTIAL);

    // The credential is a parameter, not a field. Nothing on the object should
    // serialise to it — this object outlives the credential's usefulness.
    expect(JSON.stringify(instance, Object.getOwnPropertyNames(instance))).not.toContain(
      CREDENTIAL_VALUE,
    );
  });

  it("is not returned in the candidates", async () => {
    http
      .on("/search/code", { status: 200, body: searchBody([hit("acme", "widgets")]) })
      .on("/repos/acme/widgets/contents/package.json", {
        status: 200,
        body: manifest({ "acme-sdk": "^2.0.0" }),
      })
      .on("/repos/acme/widgets", { status: 200, body: repoBody("acme", "widgets") });

    const candidates = await crawler().findCandidates("acme-sdk", CREDENTIAL);
    expect(JSON.stringify(candidates)).not.toContain(CREDENTIAL_VALUE);
  });
});

describe("bounds", () => {
  it("stops at the configured maximum candidates", async () => {
    const hits = Array.from({ length: 10 }, (_, index) => hit("acme", `repo${index}`));
    http.on("/search/code", { status: 200, body: searchBody(hits) });
    for (let index = 0; index < 10; index += 1) {
      http
        .on(`/repos/acme/repo${index}/contents/package.json`, {
          status: 200,
          body: manifest({ "acme-sdk": "^2.0.0" }),
        })
        .on(`/repos/acme/repo${index}`, { status: 200, body: repoBody("acme", `repo${index}`) });
    }

    const candidates = await crawler({ maxCandidates: 3 }).findCandidates("acme-sdk", CREDENTIAL);
    expect(candidates).toHaveLength(3);
  });

  it("inspects no more search hits than configured", async () => {
    const hits = Array.from({ length: 10 }, (_, index) => hit("acme", `repo${index}`));
    http.on("/search/code", { status: 200, body: searchBody(hits) });

    await crawler({ maxSearchResults: 2, maxCandidates: 25 }).findCandidates(
      "acme-sdk",
      CREDENTIAL,
    );

    const search = http.requests[0]!;
    expect(search.url).toContain("per_page=2");
    // Search, then at most two repository lookups.
    expect(http.requests.length).toBeLessThanOrEqual(3);
  });

  for (const [label, options] of [
    ["zero candidates", { maxCandidates: 0 }],
    ["a fractional candidate count", { maxCandidates: 2.5 }],
    ["a negative search bound", { maxSearchResults: -1 }],
    ["a search bound above GitHub's page ceiling", { maxSearchResults: 500 }],
  ] as const) {
    it(`rejects ${label} at construction`, () => {
      expect(() => crawler(options)).toThrow(DiscoveryError);
    });
  }
});

describe("package name validation", () => {
  it("happens before any network request", async () => {
    await expect(crawler().findCandidates("Not A Package", CREDENTIAL)).rejects.toThrow(
      /not a valid npm package name/,
    );
    expect(http.requests).toHaveLength(0);
  });

  it("rejects a name that would escape the search query", async () => {
    // `foo" OR path:` would change what is searched for rather than searching
    // for a package.
    await expect(
      crawler().findCandidates('foo" OR path:secrets', CREDENTIAL),
    ).rejects.toThrow(DiscoveryError);
    expect(http.requests).toHaveLength(0);
  });

  it("accepts scoped names", () => {
    expect(isValidPackageName("@anthropic-ai/sdk")).toBe(true);
    expect(isValidPackageName("openai")).toBe(true);
    expect(isValidPackageName("UPPERCASE")).toBe(false);
    expect(isValidPackageName("")).toBe(false);
  });

  it("sends the quoted name and the filename qualifier", async () => {
    http.on("/search/code", { status: 200, body: searchBody([]) });
    await crawler().findCandidates("@anthropic-ai/sdk", CREDENTIAL);

    const query = decodeURIComponent(new URL(http.requests[0]!.url).searchParams.get("q") ?? "");
    expect(query).toBe('"@anthropic-ai/sdk" filename:package.json');
  });
});
