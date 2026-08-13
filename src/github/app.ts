import { randomUUID } from "node:crypto";
import { createAppJwt, type Signer } from "./signer.ts";
import {
  FORBIDDEN_PERMISSIONS,
  REQUIRED_PERMISSIONS,
  ScopedToken,
  redactSecrets,
} from "./token.ts";

/**
 * Per-job installation token minting (ADR-0002 §3).
 *
 * One repository, two permissions, minutes of life, never persisted.
 *
 * The commercially important consequence, and the reason this file is worth
 * getting exactly right: it lets us tell a customer "we cannot access your
 * repository except during a job you triggered, we cannot merge anything, and
 * you can revoke us without contacting us" — and have that be true rather than
 * a policy commitment.
 */

export interface HttpResponse {
  readonly status: number;
  readonly body: string;
}

/**
 * Injected rather than a hard dependency on a GitHub SDK.
 *
 * Two reasons. Tests exercise the real minting path without network, and the
 * most security-sensitive code in the system does not inherit the behaviour of
 * a client library we do not control — particularly its error messages, which
 * are a common route for credentials to reach a log.
 */
export interface HttpClient {
  post(
    url: string,
    body: unknown,
    headers: Readonly<Record<string, string>>,
  ): Promise<HttpResponse>;
}

export interface AppConfig {
  readonly appId: string;
  readonly signer: Signer;
  readonly http: HttpClient;
  readonly baseUrl?: string;
  /** Token lifetime. Bounded low; GitHub's own ceiling is one hour. */
  readonly tokenTtlSeconds?: number;
}

export interface MintRequest {
  readonly installationId: string;
  readonly forgeInstallationId: string | number;
  readonly repositoryId: string;
  /** GitHub's numeric repository id. Scopes the token to exactly this repo. */
  readonly forgeRepositoryId: number;
}

export interface AuditSink {
  /**
   * Called BEFORE the mint is attempted (ADR-0007 §2). A token that exists
   * without a preceding intent record is evidence of compromise, so this must
   * not be moved after the network call for convenience.
   */
  recordMintIntent(entry: {
    tokenId: string;
    installationId: string;
    repositoryId: string;
    permissions: Readonly<Record<string, string>>;
    ttlSeconds: number;
  }): Promise<void>;
  recordMintOutcome(entry: {
    tokenId: string;
    succeeded: boolean;
    expiresAt?: string;
    error?: string;
  }): Promise<void>;
}

export class TokenMintError extends Error {
  override readonly name = "TokenMintError";
  constructor(
    message: string,
    readonly status: number,
  ) {
    // Redacted at the constructor, not at the log sink. An error object
    // travels — to an error tracker, into a job's last_error column, into a
    // support ticket — and scrubbing at every destination is a losing game.
    super(redactSecrets(message));
  }
}

const DEFAULT_TTL_SECONDS = 300;

export class GitHubApp {
  readonly #config: Required<Omit<AppConfig, "signer" | "http">> &
    Pick<AppConfig, "signer" | "http">;

  constructor(config: AppConfig) {
    const ttl = config.tokenTtlSeconds ?? DEFAULT_TTL_SECONDS;
    if (ttl > 3600) {
      throw new Error(
        "Token TTL above one hour exceeds what GitHub issues and defeats the " +
          "short-lived credential model (ADR-0002).",
      );
    }
    this.#config = {
      appId: config.appId,
      signer: config.signer,
      http: config.http,
      baseUrl: config.baseUrl ?? "https://api.github.com",
      tokenTtlSeconds: ttl,
    };
  }

  /**
   * Mints a token scoped to one repository.
   *
   * The permission manifest is not a parameter. Callers cannot widen it, so a
   * bug or an injected instruction cannot request `administration` — the
   * request GitHub receives is fixed at compile time (ADR-0002 §4).
   */
  async mintInstallationToken(
    request: MintRequest,
    audit: AuditSink,
  ): Promise<ScopedToken> {
    const tokenId = randomUUID();

    await audit.recordMintIntent({
      tokenId,
      installationId: request.installationId,
      repositoryId: request.repositoryId,
      permissions: REQUIRED_PERMISSIONS,
      ttlSeconds: this.#config.tokenTtlSeconds,
    });

    let response: HttpResponse;
    try {
      const jwt = await createAppJwt(this.#config.signer, this.#config.appId);
      response = await this.#config.http.post(
        `${this.#config.baseUrl}/app/installations/${request.forgeInstallationId}/access_tokens`,
        {
          repository_ids: [request.forgeRepositoryId],
          permissions: REQUIRED_PERMISSIONS,
        },
        {
          authorization: `Bearer ${jwt}`,
          accept: "application/vnd.github+json",
          "x-github-api-version": "2022-11-28",
        },
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      await audit.recordMintOutcome({
        tokenId,
        succeeded: false,
        error: redactSecrets(message),
      });
      throw new TokenMintError(`Token mint failed: ${message}`, 0);
    }

    if (response.status !== 201) {
      await audit.recordMintOutcome({
        tokenId,
        succeeded: false,
        error: `status ${response.status}`,
      });
      throw new TokenMintError(
        `Token mint returned ${response.status}: ${response.body}`,
        response.status,
      );
    }

    const parsed = JSON.parse(response.body) as {
      token: string;
      expires_at: string;
      permissions?: Record<string, string>;
    };

    // Trust GitHub's echo of the granted permissions over our own request.
    // If a token ever comes back broader than asked for — a GitHub bug, an
    // installation misconfiguration, a proxy rewriting the body — using it
    // would silently break the guarantee the whole design rests on.
    const granted = parsed.permissions ?? REQUIRED_PERMISSIONS;
    for (const permission of Object.keys(granted)) {
      if (FORBIDDEN_PERMISSIONS.includes(permission)) {
        await audit.recordMintOutcome({
          tokenId,
          succeeded: false,
          error: `token granted forbidden permission "${permission}"`,
        });
        throw new TokenMintError(
          `Refusing a token granted "${permission}". Expected only ` +
            `${Object.keys(REQUIRED_PERMISSIONS).join(", ")} (ADR-0002 §4).`,
          response.status,
        );
      }
    }

    // Bound the lifetime ourselves rather than trusting the returned expiry.
    // GitHub's default is an hour; we asked for minutes and we hold ourselves
    // to that regardless of what comes back.
    const remoteExpiry = new Date(parsed.expires_at);
    const localExpiry = new Date(Date.now() + this.#config.tokenTtlSeconds * 1000);
    const expiresAt = remoteExpiry < localExpiry ? remoteExpiry : localExpiry;

    await audit.recordMintOutcome({
      tokenId,
      succeeded: true,
      expiresAt: expiresAt.toISOString(),
    });

    return new ScopedToken(
      parsed.token,
      {
        repositoryId: request.repositoryId,
        installationId: request.installationId,
        permissions: granted,
      },
      expiresAt,
      tokenId,
    );
  }
}
