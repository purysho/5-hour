import { describe, expect, it } from "vitest";
import {
  assertNoSecrets,
  buildSandboxEnvironment,
  DEFAULT_EGRESS_ALLOWLIST,
  FORBIDDEN_ENV_KEYS,
  isEgressAllowed,
  PERMITTED_ENV_KEYS,
  SecretInEnvironmentError,
} from "../../src/sandbox/environment.ts";

/**
 * The "nothing to steal" half of ADR-0003 layer 4.
 *
 * This is what lets the layering work: the agent can be persuaded of anything
 * and still find no credential. So the tests are written from the attacker's
 * position — assume the injection succeeded, and check that the environment it
 * reaches is empty of value.
 */

const HOSTILE_SOURCE: Record<string, string> = {
  PATH: "/usr/bin:/bin",
  HOME: "/home/runner",
  GITHUB_TOKEN: "ghs_realtokenvalue000000000000000000000",
  AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
  DATABASE_URL: "postgresql://app:hunter2@db.internal:5432/driftless",
  ANTHROPIC_API_KEY: "sk-ant-api03-realkeyvalue000000000000",
  GITHUB_APP_PRIVATE_KEY: "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----",
};

describe("the runner environment carries no credentials", () => {
  it("drops every secret present in the parent process", async () => {
    const env = buildSandboxEnvironment({
      jobId: "job-1",
      workspace: "/work",
      source: HOSTILE_SOURCE,
    });

    expect(env["PATH"]).toBe("/usr/bin:/bin");
    for (const secret of [
      "GITHUB_TOKEN",
      "AWS_SECRET_ACCESS_KEY",
      "DATABASE_URL",
      "ANTHROPIC_API_KEY",
      "GITHUB_APP_PRIVATE_KEY",
    ]) {
      expect(env[secret], `${secret} reached the runner`).toBeUndefined();
    }

    // And nothing anywhere in the environment carries a secret value.
    const serialised = JSON.stringify(env);
    expect(serialised).not.toContain("ghs_");
    expect(serialised).not.toContain("hunter2");
    expect(serialised).not.toContain("sk-ant");
    expect(serialised).not.toContain("PRIVATE KEY");
  });

  it("is an allowlist, so an unknown variable never leaks by default", async () => {
    // The property that survives someone adding a new secret next month
    // without touching this file.
    const env = buildSandboxEnvironment({
      jobId: "job-1",
      workspace: "/work",
      source: {
        PATH: "/usr/bin",
        SOME_FUTURE_CREDENTIAL_NOBODY_LISTED: "very-secret-value",
      },
    });
    expect(env["SOME_FUTURE_CREDENTIAL_NOBODY_LISTED"]).toBeUndefined();
    expect(Object.keys(env).every((k) => PERMITTED_ENV_KEYS.includes(k))).toBe(true);
  });

  it("sets job identity", async () => {
    const env = buildSandboxEnvironment({ jobId: "job-42", workspace: "/w", source: {} });
    expect(env["DRIFTLESS_JOB_ID"]).toBe("job-42");
    expect(env["DRIFTLESS_WORKSPACE"]).toBe("/w");
  });

  it("refuses an extra variable that is not on the allowlist", () => {
    expect(() =>
      buildSandboxEnvironment({
        jobId: "job-1",
        workspace: "/w",
        source: {},
        extra: { SNEAKY_TOKEN: "value" },
      }),
    ).toThrow(/allowlist/);
  });

  it("permits an explicitly allowlisted extra", () => {
    const env = buildSandboxEnvironment({
      jobId: "job-1",
      workspace: "/w",
      source: {},
      extra: { NPM_CONFIG_REGISTRY: "https://registry.npmjs.org" },
    });
    expect(env["NPM_CONFIG_REGISTRY"]).toBe("https://registry.npmjs.org");
  });
});

describe("verification catches what construction misses", () => {
  it("rejects a secret smuggled through a permitted key", () => {
    // The interesting case: the key is legitimate, the value is not. A
    // name-based check alone would pass this.
    expect(() =>
      buildSandboxEnvironment({
        jobId: "job-1",
        workspace: "/w",
        source: {},
        extra: {
          NPM_CONFIG_REGISTRY: "https://ghp_realtokenvalue00000000000000000@registry.npmjs.org",
        },
      }),
    ).toThrow(SecretInEnvironmentError);
  });

  it("names the variable but never reproduces the value", () => {
    // An error message that echoes the secret moves it from the environment
    // into the logs, which is not an improvement.
    const error = (() => {
      try {
        assertNoSecrets({ TMPDIR: "/tmp/ghp_realtokenvalue00000000000000000" });
        return null;
      } catch (e) {
        return e as Error;
      }
    })();
    expect(error).toBeInstanceOf(SecretInEnvironmentError);
    expect(error!.message).toContain("TMPDIR");
    expect(error!.message).not.toContain("ghp_realtoken");
  });

  it("detects each credential shape", () => {
    const cases: [string, string][] = [
      ["github token", "ghs_abcdefghijklmnopqrstuvwxyz012345"],
      ["fine-grained pat", "github_pat_11ABCDEFG0abcdefghijklmnop"],
      ["pem key", "-----BEGIN EC PRIVATE KEY-----"],
      ["api key", "sk-abcdefghijklmnopqrstuvwxyz0123"],
      ["aws key id", "AKIAIOSFODNN7EXAMPLE"],
      ["jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"],
      ["db url", "postgresql://user:password@host:5432/db"],
    ];
    for (const [label, value] of cases) {
      expect(() => assertNoSecrets({ TMPDIR: value }), `${label} not detected`).toThrow(
        SecretInEnvironmentError,
      );
    }
  });

  it("rejects a forbidden key even if the allowlist were widened", () => {
    // Redundant with the allowlist by construction, and deliberately so. If a
    // refactor ever inverts the allowlist, this still fails.
    for (const forbidden of FORBIDDEN_ENV_KEYS) {
      expect(() => assertNoSecrets({ [forbidden]: "anything" })).toThrow(
        SecretInEnvironmentError,
      );
    }
  });

  it("leaves an ordinary environment alone", () => {
    expect(() =>
      assertNoSecrets({ PATH: "/usr/bin:/bin", HOME: "/home/runner", TZ: "UTC" }),
    ).not.toThrow();
  });

  it("shares no key between the allowlist and the forbidden list", () => {
    const overlap = PERMITTED_ENV_KEYS.filter((k) => FORBIDDEN_ENV_KEYS.includes(k));
    expect(overlap, `contradictory keys: ${overlap.join(", ")}`).toEqual([]);
  });
});

describe("egress allowlist", () => {
  it("permits package registries a build legitimately needs", () => {
    for (const host of DEFAULT_EGRESS_ALLOWLIST) {
      expect(isEgressAllowed(host), `${host} was denied`).toBe(true);
    }
  });

  it("permits subdomains of allowlisted hosts", () => {
    expect(isEgressAllowed("cdn.registry.npmjs.org")).toBe(true);
  });

  it("denies everything else", () => {
    for (const host of [
      "collect.evil.example",
      "registry.npmjs.org.evil.example",
      "npmjs.org",
      "169.254.169.254",
      "metadata.google.internal",
    ]) {
      expect(isEgressAllowed(host), `${host} was allowed`).toBe(false);
    }
  });

  it("denies a lookalike that merely contains an allowed host", () => {
    // The classic bypass: substring matching instead of suffix matching.
    expect(isEgressAllowed("evil-registry.npmjs.org.attacker.test")).toBe(false);
  });

  it("normalises case and trailing dots", () => {
    expect(isEgressAllowed("REGISTRY.NPMJS.ORG.")).toBe(true);
  });

  it("denies the cloud metadata endpoint, the standard pivot", () => {
    // Code execution to cloud credentials is the usual next step, and the
    // metadata endpoint is how it happens.
    expect(isEgressAllowed("169.254.169.254")).toBe(false);
    expect(isEgressAllowed("metadata.google.internal")).toBe(false);
  });
});
