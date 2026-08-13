/**
 * Scoped, short-lived credentials (ADR-0002).
 *
 * The mirror image of `UntrustedContent`. That type stops hostile data getting
 * *out* of the data channel; this one stops a secret getting *out* of the code
 * that legitimately holds it.
 *
 * Both exist because the dangerous operation in each case is the same one —
 * string interpolation — and it is invisible in review:
 *
 *     logger.info(`minted ${token} for ${repo}`);      // token in the logs
 *     throw new Error(`push failed with ${token}`);     // token in Sentry
 *     await fetch(url, { body: JSON.stringify(ctx) });  // token over the wire
 *
 * So `ScopedToken` redacts on every implicit conversion. Reading the actual
 * secret requires calling a deliberately conspicuous method, which makes the
 * handful of legitimate call sites obvious in a diff.
 *
 * This is layer three of the defence, not the first. Per ADR-0002 §5 the agent
 * never holds a token at all, and per ADR-0006 the sandbox has no egress route
 * to send one. This type protects the narrow band of code that does hold one.
 */

export interface TokenScope {
  /** Exactly one repository. Never an org-wide or multi-repo token. */
  readonly repositoryId: string;
  readonly installationId: string;
  /**
   * The permission manifest (ADR-0002 §4). Widening this is a security
   * decision requiring an ADR, so it is frozen and asserted in tests rather
   * than being a parameter callers can pass.
   */
  readonly permissions: Readonly<Record<string, string>>;
}

export const REQUIRED_PERMISSIONS: Readonly<Record<string, string>> = Object.freeze({
  contents: "write",
  pull_requests: "write",
});

/**
 * Permissions we will never request. Not merely unused — requesting any of
 * them would break the guarantee in threat-model §2 that human review cannot
 * be bypassed, even by a fully compromised Driftless.
 */
export const FORBIDDEN_PERMISSIONS: readonly string[] = Object.freeze([
  "administration",
  "workflows",
  "actions",
  "members",
  "organization_administration",
  "secrets",
  "environments",
]);

export const REDACTED = "[REDACTED ScopedToken]";

export class ScopedToken {
  readonly #value: string;

  readonly scope: TokenScope;
  readonly expiresAt: Date;
  /** Stable, non-secret handle safe to log and to write to the audit chain. */
  readonly tokenId: string;

  constructor(value: string, scope: TokenScope, expiresAt: Date, tokenId: string) {
    for (const permission of Object.keys(scope.permissions)) {
      if (FORBIDDEN_PERMISSIONS.includes(permission)) {
        throw new ForbiddenPermissionError(
          `Refusing to construct a token with "${permission}". ` +
            `See ADR-0002 §4 — the permission manifest is a security control.`,
        );
      }
    }
    this.#value = value;
    this.scope = Object.freeze({ ...scope, permissions: Object.freeze({ ...scope.permissions }) });
    this.expiresAt = expiresAt;
    this.tokenId = tokenId;
    Object.freeze(this);
  }

  get expired(): boolean {
    return Date.now() >= this.expiresAt.getTime();
  }

  get secondsRemaining(): number {
    return Math.max(0, Math.round((this.expiresAt.getTime() - Date.now()) / 1000));
  }

  /**
   * Redacts rather than throwing.
   *
   * `UntrustedContent` throws, because interpolating it is always a bug and
   * failing loudly is the right answer. A token is different: the interpolation
   * is often in an error path or a log line that runs during an incident, and
   * throwing there would replace a redacted log with a crashed error handler.
   * Redacting keeps the diagnostic and loses only the secret.
   */
  toString(): string {
    return REDACTED;
  }

  toJSON(): string {
    return REDACTED;
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return `[ScopedToken ${this.tokenId} repo=${this.scope.repositoryId} ttl=${this.secondsRemaining}s]`;
  }

  /**
   * The only reader. Named to be conspicuous in review: every call site should
   * be one of the few places a credential legitimately crosses a boundary.
   *
   * Refuses to hand back an expired token — using one produces a confusing
   * 401 far from the cause.
   */
  static revealForAuthorisedUse(token: ScopedToken, reason: AuthorisedUse): string {
    if (token.expired) {
      throw new ExpiredTokenError(
        `Token ${token.tokenId} expired ${-token.secondsRemaining}s ago. Mint a new one.`,
      );
    }
    void reason;
    return token.#value;
  }
}

/**
 * The complete set of places a token may legitimately be read. A union rather
 * than a string, so adding a new one is a type change that shows up in review.
 */
export type AuthorisedUse = "git-credential-helper" | "github-api-request";

export class ForbiddenPermissionError extends Error {
  override readonly name = "ForbiddenPermissionError";
}

export class ExpiredTokenError extends Error {
  override readonly name = "ExpiredTokenError";
}

/**
 * Last-resort scrub for anything heading to a log sink or an error tracker.
 *
 * The typed boundary above is the real control; this catches tokens that
 * arrived as plain strings from a third-party client's error message, which is
 * exactly where they escape in practice.
 */
const TOKEN_PATTERNS: readonly RegExp[] = [
  /\bghs_[A-Za-z0-9]{20,}/g, // installation tokens
  /\bghp_[A-Za-z0-9]{20,}/g, // personal access tokens
  /\bgithub_pat_[A-Za-z0-9_]{20,}/g,
  /\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, // JWTs
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
];

export function redactSecrets(input: string): string {
  let output = input;
  for (const pattern of TOKEN_PATTERNS) {
    output = output.replace(pattern, REDACTED);
  }
  return output;
}
