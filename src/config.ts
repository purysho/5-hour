/**
 * Configuration.
 *
 * Parsed once at startup and validated completely before anything else runs.
 * A process that starts with a missing secret and fails on the first request
 * is strictly worse than one that refuses to start: the first fails in
 * production under load, the second fails in a deploy where someone is
 * watching.
 *
 * Two rules this module exists to enforce:
 *
 *   Every secret is required, never defaulted. A development fallback for a
 *   webhook secret or a signing key is the classic route to that default
 *   reaching production, where it is a publicly known credential.
 *
 *   Secrets never reach a log. The parsed config carries them in a shape that
 *   redacts on inspection, so the reflexive `console.log(config)` during an
 *   incident does not put the GitHub App key in a log aggregator.
 */

export class ConfigError extends Error {
  override readonly name = "ConfigError";
}

/**
 * A configured secret.
 *
 * Same reasoning as `ScopedToken` in src/github/token.ts, applied at startup:
 * the dangerous operation is string interpolation, and it is invisible in
 * review.
 */
export class Secret {
  readonly #value: string;
  readonly name: string;

  constructor(value: string, name: string) {
    this.#value = value;
    this.name = name;
    Object.freeze(this);
  }

  toString(): string {
    return `[REDACTED ${this.name}]`;
  }

  toJSON(): string {
    return `[REDACTED ${this.name}]`;
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return `[Secret ${this.name}]`;
  }

  /** Conspicuous by design; every call site should be obvious in review. */
  static reveal(secret: Secret): string {
    return secret.#value;
  }
}

export interface Config {
  readonly env: "development" | "test" | "production";
  readonly databaseUrl: Secret;
  /** Platform-role connection used for dequeue and cross-tenant lookups. */
  readonly platformDatabaseUrl: Secret;
  readonly github: {
    readonly appId: string;
    readonly webhookSecret: Secret;
    /** Key id in the KMS. The key itself never enters this process (ADR-0002). */
    readonly signingKeyId: string;
  };
  readonly http: {
    readonly port: number;
    /** Public origin, used to build opt-out links. */
    readonly publicOrigin: string;
  };
  readonly worker: {
    readonly concurrency: number;
    readonly pollIntervalMs: number;
    readonly shutdownGraceMs: number;
  };
}

export type Env = Readonly<Record<string, string | undefined>>;

export function loadConfig(env: Env = process.env): Config {
  const problems: string[] = [];

  const require_ = (key: string): string => {
    const value = env[key];
    if (value === undefined || value.trim() === "") {
      problems.push(`${key} is required`);
      return "";
    }
    return value.trim();
  };

  const number_ = (key: string, fallback: number, min: number, max: number): number => {
    const raw = env[key];
    if (raw === undefined || raw.trim() === "") return fallback;
    const value = Number(raw);
    if (!Number.isInteger(value) || value < min || value > max) {
      problems.push(`${key} must be an integer between ${min} and ${max}`);
      return fallback;
    }
    return value;
  };

  const nodeEnv = env["NODE_ENV"] ?? "development";
  if (!["development", "test", "production"].includes(nodeEnv)) {
    problems.push(`NODE_ENV must be development, test, or production`);
  }

  const databaseUrl = require_("DATABASE_URL");
  const platformDatabaseUrl = env["PLATFORM_DATABASE_URL"]?.trim() || databaseUrl;

  const appId = require_("GITHUB_APP_ID");
  if (appId && !/^\d+$/.test(appId)) {
    problems.push("GITHUB_APP_ID must be numeric");
  }

  const webhookSecret = require_("GITHUB_WEBHOOK_SECRET");
  // A short webhook secret is brute-forceable against a public endpoint that
  // accepts unlimited attempts.
  if (webhookSecret && webhookSecret.length < 32) {
    problems.push("GITHUB_WEBHOOK_SECRET must be at least 32 characters");
  }

  const signingKeyId = require_("GITHUB_SIGNING_KEY_ID");
  // The private key must never be an environment variable. If someone has set
  // one, that is a misconfiguration worth refusing to start over rather than
  // quietly ignoring — the key is now in the process environment either way.
  if (env["GITHUB_PRIVATE_KEY"] !== undefined) {
    problems.push(
      "GITHUB_PRIVATE_KEY must not be set — the signing key stays in the KMS (ADR-0002). " +
        "Rotate it: it has been exposed to this process's environment.",
    );
  }

  const publicOrigin = require_("PUBLIC_ORIGIN");
  if (publicOrigin) {
    try {
      const url = new URL(publicOrigin);
      // Opt-out links are printed into pull request bodies on public
      // repositories. An http origin there is a downgrade we would be
      // publishing ourselves.
      if (url.protocol !== "https:" && nodeEnv === "production") {
        problems.push("PUBLIC_ORIGIN must be https in production");
      }
    } catch {
      problems.push("PUBLIC_ORIGIN must be a valid URL");
    }
  }

  // Numeric settings are parsed BEFORE the problems check, not inline in the
  // returned object. Parsing them after the throw would mean their validation
  // could never fail the load — the errors would be pushed to an array nobody
  // reads again. Found by a test asserting PORT=0 is rejected.
  const port = number_("PORT", 8080, 1, 65535);
  const concurrency = number_("WORKER_CONCURRENCY", 4, 1, 64);
  const pollIntervalMs = number_("WORKER_POLL_INTERVAL_MS", 1000, 100, 60_000);
  const shutdownGraceMs = number_("SHUTDOWN_GRACE_MS", 30_000, 1000, 300_000);

  if (problems.length > 0) {
    throw new ConfigError(
      `Refusing to start with invalid configuration:\n  - ${problems.join("\n  - ")}`,
    );
  }

  return {
    env: nodeEnv as Config["env"],
    databaseUrl: new Secret(databaseUrl, "DATABASE_URL"),
    platformDatabaseUrl: new Secret(platformDatabaseUrl, "PLATFORM_DATABASE_URL"),
    github: {
      appId,
      webhookSecret: new Secret(webhookSecret, "GITHUB_WEBHOOK_SECRET"),
      signingKeyId,
    },
    http: {
      port,
      publicOrigin: publicOrigin.replace(/\/+$/, ""),
    },
    worker: { concurrency, pollIntervalMs, shutdownGraceMs },
  };
}

/** Opt-out URL for a repository, built from the configured public origin. */
export function optOutUrl(config: Config, token: string): string {
  return `${config.http.publicOrigin}/opt-out/${token}`;
}
