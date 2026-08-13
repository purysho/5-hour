import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  GitHubApp,
  TokenMintError,
  type AuditSink,
  type HttpClient,
  type HttpResponse,
} from "../../src/github/app.ts";
import { createAppJwt, LocalSigner } from "../../src/github/signer.ts";
import { REQUIRED_PERMISSIONS, ScopedToken } from "../../src/github/token.ts";

/**
 * Per-job token minting (ADR-0002 §3).
 *
 * The HTTP client is injected, so the real minting path runs without network.
 * What is under test is not "does GitHub work" but the properties we promise
 * customers: one repository, two permissions, minutes of life, an audit record
 * written before the credential exists, and nothing leaked on the failure
 * paths.
 */

const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const PEM = privateKey.export({ type: "pkcs1", format: "pem" }) as string;

function signer(): LocalSigner {
  return new LocalSigner(PEM, "test-key");
}

function auditSink(): AuditSink & {
  intents: unknown[];
  outcomes: unknown[];
  order: string[];
} {
  const order: string[] = [];
  const intents: unknown[] = [];
  const outcomes: unknown[] = [];
  return {
    intents,
    outcomes,
    order,
    async recordMintIntent(entry) {
      order.push("intent");
      intents.push(entry);
    },
    async recordMintOutcome(entry) {
      order.push("outcome");
      outcomes.push(entry);
    },
  };
}

function httpReturning(response: HttpResponse): HttpClient & {
  calls: { url: string; body: unknown; headers: Record<string, string> }[];
} {
  const calls: { url: string; body: unknown; headers: Record<string, string> }[] = [];
  return {
    calls,
    async post(url, body, headers) {
      calls.push({ url, body, headers: { ...headers } });
      return response;
    },
  };
}

const OK: HttpResponse = {
  status: 201,
  body: JSON.stringify({
    token: "ghs_mintedtokenvalue00000000000000000000",
    expires_at: new Date(Date.now() + 3_600_000).toISOString(),
    permissions: { contents: "write", pull_requests: "write" },
  }),
};

const REQUEST = {
  installationId: "install-1",
  forgeInstallationId: 12345,
  repositoryId: "repo-1",
  forgeRepositoryId: 98765,
};

describe("minting", () => {
  it("requests exactly one repository and the fixed permission set", async () => {
    const http = httpReturning(OK);
    const app = new GitHubApp({ appId: "1", signer: signer(), http });
    await app.mintInstallationToken(REQUEST, auditSink());

    const body = http.calls[0]!.body as {
      repository_ids: number[];
      permissions: Record<string, string>;
    };
    expect(body.repository_ids).toEqual([98765]);
    expect(body.permissions).toEqual(REQUIRED_PERMISSIONS);
    expect(http.calls[0]!.url).toContain("/app/installations/12345/access_tokens");
  });

  it("does not let callers widen the permission manifest", async () => {
    // The manifest is not a parameter, so a bug or an injected instruction
    // cannot request `administration`. There is no argument to pass.
    const http = httpReturning(OK);
    const app = new GitHubApp({ appId: "1", signer: signer(), http });
    await app.mintInstallationToken(
      { ...REQUEST, permissions: { administration: "write" } } as never,
      auditSink(),
    );
    const body = http.calls[0]!.body as { permissions: Record<string, string> };
    expect(body.permissions).toEqual(REQUIRED_PERMISSIONS);
    expect(body.permissions["administration"]).toBeUndefined();
  });

  it("caps the lifetime locally rather than trusting the returned expiry", async () => {
    // GitHub returned an hour; we asked for five minutes and hold to it.
    const app = new GitHubApp({
      appId: "1",
      signer: signer(),
      http: httpReturning(OK),
      tokenTtlSeconds: 300,
    });
    const token = await app.mintInstallationToken(REQUEST, auditSink());
    expect(token.secondsRemaining).toBeLessThanOrEqual(300);
    expect(token.secondsRemaining).toBeGreaterThan(290);
  });

  it("honours a shorter expiry from GitHub", async () => {
    const app = new GitHubApp({
      appId: "1",
      signer: signer(),
      http: httpReturning({
        status: 201,
        body: JSON.stringify({
          token: "ghs_short0000000000000000000000000000",
          expires_at: new Date(Date.now() + 30_000).toISOString(),
          permissions: REQUIRED_PERMISSIONS,
        }),
      }),
      tokenTtlSeconds: 600,
    });
    const token = await app.mintInstallationToken(REQUEST, auditSink());
    expect(token.secondsRemaining).toBeLessThanOrEqual(30);
  });

  it("refuses a TTL beyond one hour", () => {
    expect(
      () =>
        new GitHubApp({
          appId: "1",
          signer: signer(),
          http: httpReturning(OK),
          tokenTtlSeconds: 7200,
        }),
    ).toThrow(/short-lived credential model/);
  });

  it("rejects a token GitHub grants more broadly than requested", async () => {
    // A GitHub bug, an installation misconfiguration, or a proxy rewriting the
    // body. Using such a token would silently break the guarantee the design
    // rests on, so we check the echo rather than assuming our request stuck.
    const app = new GitHubApp({
      appId: "1",
      signer: signer(),
      http: httpReturning({
        status: 201,
        body: JSON.stringify({
          token: "ghs_toobroad0000000000000000000000000",
          expires_at: new Date(Date.now() + 300_000).toISOString(),
          permissions: { contents: "write", administration: "write" },
        }),
      }),
    });
    await expect(app.mintInstallationToken(REQUEST, auditSink())).rejects.toThrow(
      /forbidden|administration/i,
    );
  });
});

describe("audit ordering", () => {
  it("records the intent before the credential exists", async () => {
    // ADR-0007 §2. A token that exists without a preceding intent record is
    // evidence of compromise, which only holds if we always write first.
    const audit = auditSink();
    const app = new GitHubApp({ appId: "1", signer: signer(), http: httpReturning(OK) });
    await app.mintInstallationToken(REQUEST, audit);

    expect(audit.order).toEqual(["intent", "outcome"]);
    expect(audit.intents[0]).toMatchObject({
      installationId: "install-1",
      repositoryId: "repo-1",
      permissions: REQUIRED_PERMISSIONS,
    });
  });

  it("records an intent even when minting fails", async () => {
    const audit = auditSink();
    const app = new GitHubApp({
      appId: "1",
      signer: signer(),
      http: httpReturning({ status: 403, body: "forbidden" }),
    });
    await expect(app.mintInstallationToken(REQUEST, audit)).rejects.toThrow(TokenMintError);
    expect(audit.order).toEqual(["intent", "outcome"]);
    expect(audit.outcomes[0]).toMatchObject({ succeeded: false });
  });

  it("logs the token id, never the token", async () => {
    const audit = auditSink();
    const app = new GitHubApp({ appId: "1", signer: signer(), http: httpReturning(OK) });
    const token = await app.mintInstallationToken(REQUEST, audit);

    const serialised = JSON.stringify([audit.intents, audit.outcomes]);
    expect(serialised).toContain(token.tokenId);
    expect(serialised).not.toContain("ghs_");
  });
});

describe("failure paths do not leak", () => {
  it("redacts a token echoed in an error body", async () => {
    // GitHub error bodies and proxy responses have been known to echo request
    // material. Scrubbing happens in the TokenMintError constructor, because
    // an error object travels to places we do not control.
    const app = new GitHubApp({
      appId: "1",
      signer: signer(),
      http: httpReturning({
        status: 500,
        body: "upstream error: ghs_leakedtokenvalue0000000000000000",
      }),
    });
    const error = await app.mintInstallationToken(REQUEST, auditSink()).catch((e) => e);
    expect(error).toBeInstanceOf(TokenMintError);
    expect((error as Error).message).not.toContain("ghs_leaked");
    expect((error as Error).message).toContain("[REDACTED");
  });

  it("redacts a JWT echoed by a transport failure", async () => {
    const failing: HttpClient = {
      post: async (_url, _body, headers) => {
        throw new Error(`connect ECONNREFUSED, sent ${headers["authorization"]}`);
      },
    };
    const app = new GitHubApp({ appId: "1", signer: signer(), http: failing });
    const error = await app.mintInstallationToken(REQUEST, auditSink()).catch((e) => e);
    expect((error as Error).message).not.toMatch(/eyJ[A-Za-z0-9_-]{10,}\./);
    expect((error as Error).message).toContain("[REDACTED");
  });
});

describe("app JWT", () => {
  it("is signed through the signer interface, never with a held key", async () => {
    // The application holds a signing capability, not the key. In production
    // the signer is KMS-backed and the key cannot be exported.
    const sign = vi.fn(async () => Buffer.from("signature"));
    const jwt = await createAppJwt({ sign, keyId: "kms-key-1" }, "12345");
    expect(sign).toHaveBeenCalledOnce();
    expect(jwt.split(".")).toHaveLength(3);
  });

  it("backdates iat to tolerate clock skew and expires within ten minutes", async () => {
    const jwt = await createAppJwt(signer(), "12345");
    const payload = JSON.parse(
      Buffer.from(jwt.split(".")[1]!, "base64url").toString("utf8"),
    ) as { iat: number; exp: number; iss: string };

    const now = Math.floor(Date.now() / 1000);
    expect(payload.iat).toBeLessThan(now);
    expect(payload.iss).toBe("12345");
    // This JWT can mint tokens for any installation, so its life is the window
    // in which a leaked one is useful. GitHub permits ten minutes; we use one.
    expect(payload.exp - payload.iat).toBeLessThanOrEqual(600);
    expect(payload.exp - payload.iat).toBeLessThanOrEqual(120);
  });

  it("refuses a local signer in production", async () => {
    const previous = process.env["NODE_ENV"];
    process.env["NODE_ENV"] = "production";
    try {
      expect(() => new LocalSigner(PEM)).toThrow(/must not be used in production/);
    } finally {
      if (previous === undefined) delete process.env["NODE_ENV"];
      else process.env["NODE_ENV"] = previous;
    }
  });
});

describe("the minted token", () => {
  it("is scoped to the requested repository and installation", async () => {
    const app = new GitHubApp({ appId: "1", signer: signer(), http: httpReturning(OK) });
    const token = await app.mintInstallationToken(REQUEST, auditSink());
    expect(token.scope.repositoryId).toBe("repo-1");
    expect(token.scope.installationId).toBe("install-1");
    expect(token).toBeInstanceOf(ScopedToken);
  });

  it("carries a fresh token id per mint", async () => {
    const app = new GitHubApp({ appId: "1", signer: signer(), http: httpReturning(OK) });
    const first = await app.mintInstallationToken(REQUEST, auditSink());
    const second = await app.mintInstallationToken(REQUEST, auditSink());
    expect(first.tokenId).not.toBe(second.tokenId);
  });
});
