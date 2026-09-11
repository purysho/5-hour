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

import type { PlanId } from "./billing/plans.ts";

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
    /**
     * How the App JWT gets signed. Exactly one, never both.
     *
     * `kms` is the destination (ADR-0002 §2): the key cannot be exported and
     * the process can only request signatures. `file` is the bounded interim
     * position (ADR-0012) — the key is in process memory, acceptable only
     * while acting on repositories you own.
     */
    readonly signing:
      | { readonly kind: "kms"; readonly keyId: string }
      | { readonly kind: "file"; readonly path: string };
  };
  /**
   * Migration generation (ADR-0013).
   *
   * Optional, because the two processes need different things: the server
   * never generates a migration, and a worker running only `detect-changes`
   * does not either. A worker that finds it absent declines to register
   * `migrate-repository` rather than dequeuing jobs it cannot finish.
   */
  readonly anthropic: { readonly apiKey: Secret | null };
  /**
   * The provider new installations enrol into (migration 011).
   *
   * A webhook says which account installed the App, never which paying tenant
   * that installation belongs to. A single-tenant deployment answers that here
   * and installations enrol automatically; leaving it unset keeps the
   * multi-tenant behaviour, where an unrecognised installation is recorded and
   * otherwise ignored. Null rather than a default on purpose — a default would
   * silently file one customer's repositories under another.
   */
  readonly defaultProviderSlug: string | null;
  /**
   * Billing, or null for a deployment that does not sell.
   *
   * All-or-nothing on purpose. A half-configured Stripe — a secret key with no
   * webhook secret, say — produces a deployment that can take money and cannot
   * hear that it was taken, so customers are charged and never provisioned.
   * That failure is silent on our side and infuriating on theirs, so it is
   * refused at startup instead.
   *
   * Null is a legitimate configuration: a single-tenant or self-hosted
   * deployment enrols through DEFAULT_PROVIDER_SLUG and never sees a price.
   */
  readonly billing: {
    readonly secretKey: Secret;
    readonly webhookSecret: Secret;
    readonly priceIds: Readonly<Record<PlanId, string>>;
    /**
     * Connects as a role granted `driftless_billing` and nothing else.
     *
     * Never the application role: that one cannot execute
     * `provision_subscription` at all (migration 012), so pointing this at
     * DATABASE_URL produces a permission error on the first paying customer.
     * Never a role holding `driftless_app` as well — see non-negotiable 10.
     */
    readonly databaseUrl: Secret;
    /** Where a paid customer is sent to install the App. */
    readonly appInstallUrl: string;
  } | null;
  readonly http: {
    readonly port: number;
    /** Public origin, used to build opt-out links. */
    readonly publicOrigin: string;
  };
  readonly worker: {
    readonly concurrency: number;
    readonly pollIntervalMs: number;
    readonly shutdownGraceMs: number;
    /**
     * How often the scheduler looks for packages due a sweep. Not the sweep
     * interval itself — that is per-package, in `watched_package`. This only
     * bounds how late a due sweep can be.
     */
    readonly schedulerIntervalMs: number;
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

  // The private key must never be an environment variable. Environment
  // variables leak into crash dumps, child processes, `docker inspect`,
  // platform dashboards and support tickets — so a key that has been one is
  // already compromised, and saying so is more useful than ignoring it.
  if (env["GITHUB_PRIVATE_KEY"] !== undefined) {
    problems.push(
      "GITHUB_PRIVATE_KEY must not be set — a key in the environment is already " +
        "exposed. Rotate it, then use GITHUB_SIGNING_KEY_ID (KMS) or " +
        "GITHUB_PRIVATE_KEY_FILE (a file, mode 600). See ADR-0002 and ADR-0012.",
    );
  }

  // Exactly one signing method. Accepting both would make it ambiguous which
  // key actually signs, and the answer would be decided by code order rather
  // than by anyone's intent.
  const kmsKeyId = env["GITHUB_SIGNING_KEY_ID"]?.trim();
  const keyFile = env["GITHUB_PRIVATE_KEY_FILE"]?.trim();
  let signing: Config["github"]["signing"] | null = null;

  if (kmsKeyId && keyFile) {
    problems.push(
      "Set GITHUB_SIGNING_KEY_ID or GITHUB_PRIVATE_KEY_FILE, not both — " +
        "otherwise which key signs is decided by code order, not by you.",
    );
  } else if (kmsKeyId) {
    signing = { kind: "kms", keyId: kmsKeyId };
  } else if (keyFile) {
    signing = { kind: "file", path: keyFile };
  } else {
    problems.push(
      "One of GITHUB_SIGNING_KEY_ID (KMS, preferred) or GITHUB_PRIVATE_KEY_FILE " +
        "(interim, see ADR-0012) is required",
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
  // Present or absent, never partially present: a truncated key produces a 401
  // on the first migration rather than at startup, which is the wrong place to
  // discover a copy-paste error.
  const anthropicKey = env["ANTHROPIC_API_KEY"]?.trim();
  if (anthropicKey !== undefined && anthropicKey !== "" && anthropicKey.length < 20) {
    problems.push("ANTHROPIC_API_KEY looks truncated");
  }

  // Slugs land in a lookup and in log lines; the shape is checked here so a
  // typo fails the deploy rather than quietly matching no provider.
  const defaultProviderSlug = env["DEFAULT_PROVIDER_SLUG"]?.trim() || null;
  if (defaultProviderSlug !== null && !/^[a-z0-9][a-z0-9-]{0,62}$/.test(defaultProviderSlug)) {
    problems.push(
      "DEFAULT_PROVIDER_SLUG must be lowercase alphanumeric with hyphens, " +
        "and must match a provider created with `pnpm db:provider`",
    );
  }

  // Billing. Absent entirely, or complete — see the Config comment for why a
  // partial configuration is refused rather than defaulted.
  const billingKeys = [
    "STRIPE_SECRET_KEY",
    "STRIPE_WEBHOOK_SECRET",
    "STRIPE_PRICE_STARTER",
    "STRIPE_PRICE_TEAM",
    "STRIPE_PRICE_SCALE",
    "BILLING_DATABASE_URL",
    "GITHUB_APP_INSTALL_URL",
  ] as const;
  const billingPresent = billingKeys.filter((key) => (env[key]?.trim() ?? "") !== "");
  let billing: Config["billing"] = null;

  if (billingPresent.length > 0 && billingPresent.length < billingKeys.length) {
    const missing = billingKeys.filter((key) => !billingPresent.includes(key));
    problems.push(
      `Billing is partially configured. Set all of these or none: missing ${missing.join(", ")}`,
    );
  } else if (billingPresent.length === billingKeys.length) {
    const secretKey = require_("STRIPE_SECRET_KEY");
    const stripeWebhookSecret = require_("STRIPE_WEBHOOK_SECRET");
    const billingDatabaseUrl = require_("BILLING_DATABASE_URL");
    const installUrl = require_("GITHUB_APP_INSTALL_URL");

    // Prefix checks catch the two mistakes that actually happen: pasting a
    // publishable key where a secret key goes (which fails on every API call
    // with a confusing message), and pasting the webhook's *endpoint* id where
    // its signing secret goes (which fails every signature, silently, forever).
    if (secretKey && !secretKey.startsWith("sk_") && !secretKey.startsWith("rk_")) {
      problems.push("STRIPE_SECRET_KEY must be a secret or restricted key (sk_ or rk_)");
    }
    if (stripeWebhookSecret && !stripeWebhookSecret.startsWith("whsec_")) {
      problems.push("STRIPE_WEBHOOK_SECRET must be the signing secret (whsec_...)");
    }
    if (billingDatabaseUrl && billingDatabaseUrl === databaseUrl) {
      problems.push(
        "BILLING_DATABASE_URL must not equal DATABASE_URL — the application role " +
          "cannot create tenants by construction (migration 012), and a role holding " +
          "both sets of rights defeats tenant isolation (ADR-0010).",
      );
    }
    if (installUrl) {
      try {
        const parsed = new URL(installUrl);
        if (parsed.protocol !== "https:") {
          problems.push("GITHUB_APP_INSTALL_URL must be https");
        }
      } catch {
        problems.push("GITHUB_APP_INSTALL_URL must be a valid URL");
      }
    }

    const priceIds: Record<PlanId, string> = {
      starter: env["STRIPE_PRICE_STARTER"]?.trim() ?? "",
      team: env["STRIPE_PRICE_TEAM"]?.trim() ?? "",
      scale: env["STRIPE_PRICE_SCALE"]?.trim() ?? "",
    };
    for (const [plan, priceId] of Object.entries(priceIds)) {
      if (!priceId.startsWith("price_")) {
        problems.push(`STRIPE_PRICE_${plan.toUpperCase()} must be a price id (price_...)`);
      }
    }

    billing = {
      secretKey: new Secret(secretKey, "STRIPE_SECRET_KEY"),
      webhookSecret: new Secret(stripeWebhookSecret, "STRIPE_WEBHOOK_SECRET"),
      priceIds: Object.freeze(priceIds),
      databaseUrl: new Secret(billingDatabaseUrl, "BILLING_DATABASE_URL"),
      appInstallUrl: installUrl,
    };
  }

  const port = number_("PORT", 8080, 1, 65535);
  const concurrency = number_("WORKER_CONCURRENCY", 4, 1, 64);
  const pollIntervalMs = number_("WORKER_POLL_INTERVAL_MS", 1000, 100, 60_000);
  const shutdownGraceMs = number_("SHUTDOWN_GRACE_MS", 30_000, 1000, 300_000);
  const schedulerIntervalMs = number_("SCHEDULER_INTERVAL_MS", 60_000, 5_000, 3_600_000);

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
      signing: signing as Config["github"]["signing"],
    },
    anthropic: {
      apiKey: anthropicKey ? new Secret(anthropicKey, "ANTHROPIC_API_KEY") : null,
    },
    defaultProviderSlug,
    billing,
    http: {
      port,
      publicOrigin: publicOrigin.replace(/\/+$/, ""),
    },
    worker: { concurrency, pollIntervalMs, shutdownGraceMs, schedulerIntervalMs },
  };
}

/** Opt-out URL for a repository, built from the configured public origin. */
export function optOutUrl(config: Config, token: string): string {
  return `${config.http.publicOrigin}/opt-out/${token}`;
}
