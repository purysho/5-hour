import { describe, expect, it } from "vitest";
import { ConfigError, loadConfig, optOutUrl, Secret, type Env } from "../src/config.ts";

/**
 * Configuration.
 *
 * A process that starts with a missing secret and fails on the first request
 * is worse than one that refuses to start: the first fails in production under
 * load, the second fails in a deploy where someone is watching.
 */

const VALID: Env = {
  NODE_ENV: "production",
  DATABASE_URL: "postgresql://localhost/driftless",
  GITHUB_APP_ID: "123456",
  GITHUB_WEBHOOK_SECRET: "a".repeat(40),
  GITHUB_SIGNING_KEY_ID: "arn:aws:kms:eu-west-1:1:key/abc",
  PUBLIC_ORIGIN: "https://driftless.dev",
};

describe("refusing to start", () => {
  it("requires every secret, with no development fallback", () => {
    // A default that reaches production is a publicly known credential.
    for (const key of [
      "DATABASE_URL",
      "GITHUB_APP_ID",
      "GITHUB_WEBHOOK_SECRET",
      "GITHUB_SIGNING_KEY_ID",
      "PUBLIC_ORIGIN",
    ]) {
      const env = { ...VALID, [key]: undefined };
      expect(() => loadConfig(env), key).toThrow(ConfigError);
    }
  });

  it("treats an empty value as missing", () => {
    expect(() => loadConfig({ ...VALID, GITHUB_APP_ID: "   " })).toThrow(/required/);
  });

  it("reports every problem at once", () => {
    // Fixing configuration one error per deploy is a bad afternoon.
    try {
      loadConfig({ NODE_ENV: "production" });
      expect.unreachable();
    } catch (error) {
      const message = (error as Error).message;
      expect(message).toContain("DATABASE_URL");
      expect(message).toContain("GITHUB_APP_ID");
      expect(message).toContain("PUBLIC_ORIGIN");
    }
  });

  it("rejects a short webhook secret", () => {
    // Brute-forceable against a public endpoint that accepts unlimited
    // attempts.
    expect(() => loadConfig({ ...VALID, GITHUB_WEBHOOK_SECRET: "short" })).toThrow(
      /at least 32/,
    );
  });

  it("rejects a private key in the environment", () => {
    // The signing key belongs in the KMS (ADR-0002). If one is in the
    // environment it is already exposed, so refusing to start AND saying to
    // rotate it is the only honest response.
    const error = (() => {
      try {
        loadConfig({ ...VALID, GITHUB_PRIVATE_KEY: "-----BEGIN RSA PRIVATE KEY-----" });
      } catch (e) {
        return e as Error;
      }
      return null;
    })();
    expect(error?.message).toContain("must not be set");
    expect(error?.message).toContain("Rotate it");
  });

  it("rejects an http public origin in production", () => {
    // Opt-out links are printed into pull request bodies on public
    // repositories — an http origin is a downgrade we would be publishing
    // ourselves.
    expect(() =>
      loadConfig({ ...VALID, PUBLIC_ORIGIN: "http://driftless.dev" }),
    ).toThrow(/https in production/);
  });

  it("allows http outside production", () => {
    const config = loadConfig({
      ...VALID,
      NODE_ENV: "development",
      PUBLIC_ORIGIN: "http://localhost:8080",
    });
    expect(config.http.publicOrigin).toBe("http://localhost:8080");
  });

  it("rejects a non-numeric app id and a malformed origin", () => {
    expect(() => loadConfig({ ...VALID, GITHUB_APP_ID: "abc" })).toThrow(/numeric/);
    expect(() => loadConfig({ ...VALID, PUBLIC_ORIGIN: "not a url" })).toThrow(/valid URL/);
  });

  it("rejects out-of-range numeric settings rather than clamping", () => {
    for (const [key, value] of [
      ["PORT", "0"],
      ["PORT", "70000"],
      ["WORKER_CONCURRENCY", "0"],
      ["WORKER_CONCURRENCY", "1000"],
      ["WORKER_POLL_INTERVAL_MS", "10"],
      ["SHUTDOWN_GRACE_MS", "1"],
    ] as const) {
      expect(() => loadConfig({ ...VALID, [key]: value }), `${key}=${value}`).toThrow(
        ConfigError,
      );
    }
  });
});

describe("secrets do not leak", () => {
  it("redacts on every implicit conversion", () => {
    const config = loadConfig(VALID);
    expect(String(config.databaseUrl)).toContain("REDACTED");
    expect(`${config.github.webhookSecret}`).toContain("REDACTED");
    expect(JSON.stringify(config)).not.toContain("aaaaaaaa");
    expect(JSON.stringify(config)).not.toContain("postgresql://");
  });

  it("survives the reflexive console.log during an incident", () => {
    const config = loadConfig(VALID);
    const inspected = (
      config.databaseUrl as unknown as { [k: symbol]: () => string }
    )[Symbol.for("nodejs.util.inspect.custom")]!();
    expect(inspected).toBe("[Secret DATABASE_URL]");
  });

  it("reveals only through a conspicuous accessor", () => {
    const config = loadConfig(VALID);
    expect(Secret.reveal(config.github.webhookSecret)).toBe("a".repeat(40));
  });
});

describe("defaults and derivation", () => {
  it("applies sensible worker defaults", () => {
    const config = loadConfig(VALID);
    expect(config.worker).toMatchObject({
      concurrency: 4,
      pollIntervalMs: 1000,
      shutdownGraceMs: 30_000,
    });
    expect(config.http.port).toBe(8080);
  });

  it("falls back to the primary database url for platform access", () => {
    const config = loadConfig(VALID);
    expect(Secret.reveal(config.platformDatabaseUrl)).toBe(
      "postgresql://localhost/driftless",
    );
  });

  it("uses a distinct platform url when given one", () => {
    const config = loadConfig({
      ...VALID,
      PLATFORM_DATABASE_URL: "postgresql://localhost/driftless?user=worker",
    });
    expect(Secret.reveal(config.platformDatabaseUrl)).toContain("user=worker");
  });

  it("builds opt-out links without a double slash", () => {
    const config = loadConfig({ ...VALID, PUBLIC_ORIGIN: "https://driftless.dev/" });
    expect(optOutUrl(config, "abc123")).toBe("https://driftless.dev/opt-out/abc123");
  });
});
