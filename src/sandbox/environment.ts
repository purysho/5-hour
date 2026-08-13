/**
 * Sandbox environment construction (ADR-0002 §5, ADR-0006 §4).
 *
 * ADR-0003 layer 4 says a successful prompt injection should find no
 * credential and no route out. This file is the "no credential" half, and it
 * is the reason the layering works: the agent can be persuaded of anything and
 * still have nothing to steal.
 *
 * Two rules, both enforced here rather than by convention:
 *
 *   Allowlist, never denylist. The runner environment is built from an
 *   explicit list of permitted variables. Inheriting `process.env` and
 *   removing the dangerous ones fails the moment a new secret is introduced
 *   with a name nobody thought to add to the list — and it fails silently, in
 *   the direction of disclosure.
 *
 *   Verify the result, don't trust the construction. Every value in the final
 *   environment is checked against secret-shaped patterns. Belt and braces,
 *   because the cost of being wrong is a customer's credentials in a
 *   third-party build script.
 *
 * The token is not here and never will be. Git operations needing credentials
 * run in a separate process outside the sandbox (ADR-0002 §5).
 */

/**
 * Variables a build legitimately needs. Anything absent from this list does
 * not reach the runner, including variables that look harmless.
 */
export const PERMITTED_ENV_KEYS: readonly string[] = Object.freeze([
  "PATH",
  "HOME",
  "LANG",
  "LC_ALL",
  "TZ",
  "TMPDIR",
  "SHELL",
  "TERM",
  // Ecosystem toolchains
  "NODE_ENV",
  "NPM_CONFIG_REGISTRY",
  "NPM_CONFIG_CACHE",
  "PNPM_HOME",
  "PIP_INDEX_URL",
  "PIP_CACHE_DIR",
  "PYTHONPATH",
  "PYTHONDONTWRITEBYTECODE",
  "VIRTUAL_ENV",
  "GOPATH",
  "GOMODCACHE",
  "GOPROXY",
  "CARGO_HOME",
  "RUSTUP_HOME",
  "JAVA_HOME",
  "GRADLE_USER_HOME",
  // Egress proxy (ADR-0006 §3). Values are ours, not customer secrets.
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "NO_PROXY",
  "http_proxy",
  "https_proxy",
  "no_proxy",
  // Job identity. Non-secret, useful in logs.
  "DRIFTLESS_JOB_ID",
  "DRIFTLESS_WORKSPACE",
]);

/**
 * Names that must never appear, whatever their value.
 *
 * Redundant with the allowlist by construction — that is the point. If a
 * refactor ever turns the allowlist into a denylist, or someone adds a
 * permitted key carelessly, this still fails.
 */
export const FORBIDDEN_ENV_KEYS: readonly string[] = Object.freeze([
  "GITHUB_TOKEN",
  "GH_TOKEN",
  "GITHUB_APP_PRIVATE_KEY",
  "DRIFTLESS_APP_PRIVATE_KEY",
  "DATABASE_URL",
  "PLATFORM_DATABASE_URL",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
  "ANTHROPIC_API_KEY",
  "OPENAI_API_KEY",
  "KMS_KEY_ID",
  "NPM_TOKEN",
  "PYPI_TOKEN",
  "GIT_ASKPASS",
  "GIT_CONFIG_PARAMETERS",
  "LD_PRELOAD",
]);

/**
 * Values shaped like credentials. Checked against the constructed environment,
 * so a secret smuggled through a permitted key — a token appended to
 * `NPM_CONFIG_REGISTRY`, say — is caught by shape rather than by name.
 */
const SECRET_VALUE_PATTERNS: readonly { pattern: RegExp; label: string }[] = [
  { pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}/, label: "GitHub token" },
  { pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}/, label: "GitHub fine-grained PAT" },
  { pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/, label: "PEM private key" },
  { pattern: /\bsk-[A-Za-z0-9_-]{20,}/, label: "API key" },
  { pattern: /\bAKIA[0-9A-Z]{16}\b/, label: "AWS access key id" },
  { pattern: /\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./, label: "JWT" },
  { pattern: /\b(postgres|postgresql|mysql|mongodb):\/\/[^@\s]*:[^@\s]+@/, label: "database URL with password" },
];

export interface SandboxEnvironmentOptions {
  readonly jobId: string;
  readonly workspace: string;
  /** Explicit extras. Subject to the same verification as everything else. */
  readonly extra?: Readonly<Record<string, string>>;
  /** Source environment. Defaults to the current process. */
  readonly source?: Readonly<Record<string, string | undefined>>;
}

export class SecretInEnvironmentError extends Error {
  override readonly name = "SecretInEnvironmentError";
}

/**
 * Builds the environment for a runner process.
 *
 * Throws rather than dropping the offending value. A silent drop leaves a
 * broken build and a confusing debugging session; a throw names the variable
 * and stops the job before any untrusted code runs.
 */
export function buildSandboxEnvironment(
  options: SandboxEnvironmentOptions,
): Record<string, string> {
  const source = options.source ?? (process.env as Record<string, string | undefined>);
  const env: Record<string, string> = {};

  for (const key of PERMITTED_ENV_KEYS) {
    const value = source[key];
    if (typeof value === "string" && value.length > 0) {
      env[key] = value;
    }
  }

  for (const [key, value] of Object.entries(options.extra ?? {})) {
    if (!PERMITTED_ENV_KEYS.includes(key)) {
      throw new SecretInEnvironmentError(
        `"${key}" is not in PERMITTED_ENV_KEYS. The runner environment is an ` +
          `allowlist — add it deliberately, or do not pass it.`,
      );
    }
    env[key] = value;
  }

  env["DRIFTLESS_JOB_ID"] = options.jobId;
  env["DRIFTLESS_WORKSPACE"] = options.workspace;

  assertNoSecrets(env);
  return env;
}

/**
 * Verification pass, exported so it can be asserted directly in tests and
 * called again immediately before spawn.
 */
export function assertNoSecrets(env: Readonly<Record<string, string>>): void {
  for (const forbidden of FORBIDDEN_ENV_KEYS) {
    if (forbidden in env) {
      throw new SecretInEnvironmentError(
        `"${forbidden}" must never reach a runner. The agent holds no ` +
          `credentials (ADR-0002 §5) — git operations run outside the sandbox.`,
      );
    }
  }

  for (const [key, value] of Object.entries(env)) {
    for (const { pattern, label } of SECRET_VALUE_PATTERNS) {
      if (pattern.test(value)) {
        throw new SecretInEnvironmentError(
          `"${key}" contains something shaped like a ${label}. Refusing to ` +
            `start a runner with it. (Value not reproduced here.)`,
        );
      }
    }
  }
}

/**
 * Egress allowlist for the runner's proxy (ADR-0006 §3).
 *
 * Package registries a build legitimately reaches, and nothing else. A denied
 * egress attempt is a signal worth alerting on: it usually means either a
 * compromised dependency or a successful injection.
 *
 * Deliberately not exhaustive and deliberately not easy to extend at runtime —
 * additions should be a reviewed change, not a config toggle, or the allowlist
 * becomes the thing everyone routes around.
 */
export const DEFAULT_EGRESS_ALLOWLIST: readonly string[] = Object.freeze([
  "registry.npmjs.org",
  "pypi.org",
  "files.pythonhosted.org",
  "proxy.golang.org",
  "sum.golang.org",
  "crates.io",
  "static.crates.io",
  "repo.maven.apache.org",
  "rubygems.org",
]);

export function isEgressAllowed(
  host: string,
  allowlist: readonly string[] = DEFAULT_EGRESS_ALLOWLIST,
): boolean {
  const normalised = host.toLowerCase().replace(/\.$/, "");
  return allowlist.some(
    (allowed) => normalised === allowed || normalised.endsWith(`.${allowed}`),
  );
}
