import { describe, expect, it } from "vitest";
import {
  ExpiredTokenError,
  ForbiddenPermissionError,
  redactSecrets,
  REDACTED,
  REQUIRED_PERMISSIONS,
  ScopedToken,
} from "../../src/github/token.ts";

/**
 * Credential handling (ADR-0002).
 *
 * The mirror of the UntrustedContent suite. There the danger is hostile data
 * getting into a prompt; here it is a secret getting into a log, an error
 * tracker, or a JSON payload. Both arrive by the same invisible route — string
 * interpolation — so both are tested the same way: by writing the mistake and
 * asserting it does not produce the secret.
 */

function token(overrides: { expiresAt?: Date; permissions?: Record<string, string> } = {}) {
  return new ScopedToken(
    "ghs_supersecretinstallationtoken000000",
    {
      repositoryId: "repo-1",
      installationId: "install-1",
      permissions: overrides.permissions ?? REQUIRED_PERMISSIONS,
    },
    overrides.expiresAt ?? new Date(Date.now() + 300_000),
    "token-abc",
  );
}

describe("a token cannot leak through implicit conversion", () => {
  it("redacts in a template literal", () => {
    const t = token();
    expect(`minted ${t} for repo`).toBe(`minted ${REDACTED} for repo`);
  });

  it("redacts in an error message", () => {
    // The path that matters most: this runs during an incident, and the
    // resulting Error object travels to an error tracker.
    const t = token();
    const error = new Error(`push failed using ${t}`);
    expect(error.message).not.toContain("ghs_");
    expect(error.message).toContain(REDACTED);
  });

  it("redacts in JSON.stringify", () => {
    const t = token();
    const payload = JSON.stringify({ context: { token: t } });
    expect(payload).not.toContain("ghs_");
    expect(payload).toContain(REDACTED);
  });

  it("redacts in String() and concatenation", () => {
    const t = token();
    expect(String(t)).toBe(REDACTED);
    expect("prefix" + (t as unknown as string)).toBe(`prefix${REDACTED}`);
  });

  it("inspects usefully without revealing the secret", () => {
    const t = token();
    const inspected = (
      t as unknown as { [k: symbol]: () => string }
    )[Symbol.for("nodejs.util.inspect.custom")]!();
    expect(inspected).toContain("token-abc");
    expect(inspected).toContain("repo=repo-1");
    expect(inspected).not.toContain("ghs_");
  });

  it("redacts rather than throwing, unlike UntrustedContent", () => {
    // Deliberate asymmetry. Interpolating untrusted content is always a bug,
    // so it throws. Interpolating a token usually happens in an error path,
    // where throwing would replace a redacted log line with a crashed handler.
    expect(() => `${token()}`).not.toThrow();
  });
});

describe("the permission manifest", () => {
  it("requests only contents and pull_requests", () => {
    expect(Object.keys(REQUIRED_PERMISSIONS).sort()).toEqual([
      "contents",
      "pull_requests",
    ]);
    expect(REQUIRED_PERMISSIONS["contents"]).toBe("write");
    expect(REQUIRED_PERMISSIONS["pull_requests"]).toBe("write");
  });

  it("is frozen, so it cannot be widened at runtime", () => {
    expect(Object.isFrozen(REQUIRED_PERMISSIONS)).toBe(true);
  });

  it("refuses to construct a token carrying a forbidden permission", () => {
    // Merge rights or workflow permissions would destroy the guarantee that
    // human review cannot be bypassed, even by a fully compromised Driftless.
    for (const forbidden of ["administration", "workflows", "actions", "secrets"]) {
      expect(
        () => token({ permissions: { ...REQUIRED_PERMISSIONS, [forbidden]: "write" } }),
        `${forbidden} was accepted`,
      ).toThrow(ForbiddenPermissionError);
    }
  });

  it("freezes the scope on the instance", () => {
    const t = token();
    expect(Object.isFrozen(t)).toBe(true);
    expect(Object.isFrozen(t.scope)).toBe(true);
    expect(Object.isFrozen(t.scope.permissions)).toBe(true);
  });
});

describe("expiry", () => {
  it("reports remaining life", () => {
    const t = token({ expiresAt: new Date(Date.now() + 120_000) });
    expect(t.expired).toBe(false);
    expect(t.secondsRemaining).toBeGreaterThan(115);
    expect(t.secondsRemaining).toBeLessThanOrEqual(120);
  });

  it("refuses to reveal an expired token", () => {
    // Using one produces a confusing 401 far from the cause.
    const t = token({ expiresAt: new Date(Date.now() - 1000) });
    expect(t.expired).toBe(true);
    expect(() =>
      ScopedToken.revealForAuthorisedUse(t, "git-credential-helper"),
    ).toThrow(ExpiredTokenError);
  });

  it("reveals a live token to an authorised use", () => {
    const t = token();
    expect(ScopedToken.revealForAuthorisedUse(t, "github-api-request")).toBe(
      "ghs_supersecretinstallationtoken000000",
    );
  });
});

describe("redactSecrets", () => {
  /**
   * The last-resort scrub. The typed boundary above is the real control; this
   * catches secrets that arrived as plain strings from a third-party client's
   * error message, which is where they escape in practice.
   */
  it("scrubs GitHub token formats", () => {
    const inputs = [
      "failed with ghs_abcdefghijklmnopqrstuvwxyz0123456789",
      "using ghp_abcdefghijklmnopqrstuvwxyz0123456789",
      "token github_pat_11ABCDEFG0abcdefghijklmnop",
    ];
    for (const input of inputs) {
      const output = redactSecrets(input);
      expect(output).toContain(REDACTED);
      expect(output).not.toMatch(/gh[sp]_[A-Za-z0-9]{20,}/);
      expect(output).not.toMatch(/github_pat_[A-Za-z0-9_]{20,}/);
    }
  });

  it("scrubs JWTs", () => {
    const jwt =
      "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiIxMjM0NSJ9.c2lnbmF0dXJlLWhlcmUtcGFkZGluZw";
    expect(redactSecrets(`authorization: Bearer ${jwt}`)).not.toContain(jwt);
  });

  it("scrubs PEM private keys", () => {
    const pem =
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";
    const output = redactSecrets(`key was ${pem}`);
    expect(output).not.toContain("MIIEowIBAAKCAQEA");
    expect(output).toContain(REDACTED);
  });

  it("leaves ordinary text alone", () => {
    const text = "opened pull request #42 in acme/widgets after migrating 3 call sites";
    expect(redactSecrets(text)).toBe(text);
  });
});
