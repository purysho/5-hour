import { createSign, createPrivateKey, type KeyObject } from "node:crypto";
import { readFileSync, statSync } from "node:fs";

/**
 * App authentication signing (ADR-0002 §2).
 *
 * The GitHub App private key is the single most dangerous asset in the system
 * — it mints installation tokens for every installation, so holding it is
 * equivalent to holding write access to every customer repository, durably
 * (threat-model A2).
 *
 * So the application never holds it. It holds a *signing interface*. In
 * production that is backed by a KMS or HSM where the key material cannot be
 * exported: compromising the application yields the ability to request
 * signatures — rate-limited, logged, revocable — rather than the key itself.
 *
 * The local implementation exists for development and tests only, and says so
 * loudly enough that shipping it by accident is difficult.
 */

export interface Signer {
  /** RS256 signature over `data`. Returns raw bytes. */
  sign(data: Buffer): Promise<Buffer>;
  /** Identifies the key, for the audit chain. Never the key itself. */
  readonly keyId: string;
}

/**
 * KMS-backed signer. The key never enters this process.
 *
 * Deliberately an interface over an injected client rather than a hard
 * dependency on one cloud's SDK: the provider is an operational choice, and
 * binding the most security-critical path in the system to it would make that
 * choice expensive to revisit.
 */
export interface KmsClient {
  sign(keyId: string, message: Buffer): Promise<Buffer>;
}

export class KmsSigner implements Signer {
  readonly #kms: KmsClient;
  readonly keyId: string;

  constructor(kms: KmsClient, keyId: string) {
    this.#kms = kms;
    this.keyId = keyId;
  }

  sign(data: Buffer): Promise<Buffer> {
    return this.#kms.sign(this.keyId, data);
  }
}

/**
 * Local signer. Development and tests only.
 *
 * Refuses to construct when NODE_ENV is production. A guard rather than a
 * comment, because "we'll swap it before launch" is how private keys end up in
 * environment variables.
 */
export class LocalSigner implements Signer {
  readonly #key: KeyObject;
  readonly keyId: string;

  constructor(privateKeyPem: string, keyId = "local-dev") {
    if (process.env["NODE_ENV"] === "production") {
      throw new Error(
        "LocalSigner must not be used in production. The GitHub App private key " +
          "belongs in a KMS or HSM where it cannot be exported (ADR-0002 §2).",
      );
    }
    this.#key = createPrivateKey(privateKeyPem);
    this.keyId = keyId;
  }

  sign(data: Buffer): Promise<Buffer> {
    const signer = createSign("RSA-SHA256");
    signer.update(data);
    signer.end();
    return Promise.resolve(signer.sign(this.#key));
  }
}

/**
 * File-backed signer. The interim position, not the destination.
 *
 * ── Why this exists ─────────────────────────────────────────────────────────
 *
 * ADR-0002 says the key lives in a KMS. That remains correct and remains the
 * target. But a solo team registering a GitHub App today has a PEM that GitHub
 * generated and handed them, and no KMS. The realistic options are:
 *
 *   1. Block all progress until KMS is provisioned.
 *   2. Put the key in an environment variable.
 *   3. Read it from a file, with the risk written down and bounded.
 *
 * (1) is theatre — it does not make anyone safer, it just stops the work.
 * (2) is the failure mode `loadConfig` refuses outright: environment variables
 * leak into crash dumps, child processes, `docker inspect`, platform dashboards
 * and support tickets. (3) is worse than KMS and much better than (2), so it
 * is what this class does — loudly, with guards, and with a stated trigger for
 * when it must stop (ADR-0012).
 *
 * ── The guards ──────────────────────────────────────────────────────────────
 *
 * Production requires explicit, awkward acknowledgement. The variable name is
 * deliberately unpleasant to type and impossible to set by accident, because
 * the whole risk of an escape hatch is that it becomes the default.
 *
 * The file must not be group- or world-readable. A key at mode 0644 on a
 * shared host is a key everyone on that host has.
 */
export class FileSigner implements Signer {
  readonly #key: KeyObject;
  readonly keyId: string;

  static readonly ACK_VAR = "DRIFTLESS_ACCEPT_IN_PROCESS_SIGNING_KEY";
  static readonly ACK_VALUE = "yes-i-know-this-is-not-a-kms";

  /**
   * Windows has no POSIX mode. Node fabricates `stat().mode` there from the
   * read-only attribute, so the permission check below is not measuring
   * anything — see the comment at the check itself. This variable is the
   * operator asserting they have restricted the file by the means their
   * platform actually has.
   */
  static readonly WINDOWS_ACK_VAR = "DRIFTLESS_ACCEPT_UNVERIFIED_KEY_PERMISSIONS";
  static readonly WINDOWS_ACK_VALUE = "windows-acl-checked-by-hand";

  constructor(
    path: string,
    options: {
      keyId?: string;
      env?: NodeJS.ProcessEnv;
      /** Injected so both branches are testable from one machine. */
      platform?: NodeJS.Platform;
    } = {},
  ) {
    const env = options.env ?? process.env;
    const platform = options.platform ?? process.platform;

    if (env["NODE_ENV"] === "production" && env[FileSigner.ACK_VAR] !== FileSigner.ACK_VALUE) {
      throw new Error(
        `Refusing to hold the GitHub App private key in process memory in production.\n` +
          `The key belongs in a KMS where it cannot be exported (ADR-0002 §2).\n` +
          `If you are knowingly accepting this — see ADR-0012, which bounds it to ` +
          `repositories you own — set ${FileSigner.ACK_VAR}=${FileSigner.ACK_VALUE}.`,
      );
    }

    let mode: number;
    try {
      mode = statSync(path).mode;
    } catch {
      throw new Error(`Signing key file not found or unreadable: ${path}`);
    }

    if (platform === "win32") {
      // Windows has no POSIX mode. Node synthesises one from the read-only
      // attribute — every file reads as 0o666 or 0o444 — so `mode & 0o077`
      // would refuse every key on the platform while measuring nothing about
      // the ACL that actually governs access.
      //
      // Reading the real ACL means shelling out to `icacls` and parsing output
      // that is localised, or writing SDDL to a temporary file. Both are a
      // subprocess in a security-critical constructor, for a check whose
      // failure mode we can instead make explicit. So the honest position is:
      // say we cannot verify it, and require the operator to assert they have.
      if (env[FileSigner.WINDOWS_ACK_VAR] !== FileSigner.WINDOWS_ACK_VALUE) {
        throw new Error(
          `Cannot verify the permissions of ${path} on Windows: Node reports a ` +
            `POSIX mode the filesystem does not have, so the check that runs ` +
            `elsewhere would be measuring nothing.\n` +
            `Restrict the file to your account, then assert that you have:\n\n` +
            `  icacls "${path}" /inheritance:r /grant:r "$($env:USERNAME):(R)"\n` +
            `  $env:${FileSigner.WINDOWS_ACK_VAR} = "${FileSigner.WINDOWS_ACK_VALUE}"\n\n` +
            `Running under WSL instead avoids this: the check is real there.`,
        );
      }
    } else if ((mode & 0o077) !== 0) {
      // 0o077 covers group and other. A private key readable by anyone else on
      // the host is not private.
      throw new Error(
        `Signing key file ${path} is group- or world-readable (mode ` +
          `${(mode & 0o777).toString(8)}). Run: chmod 600 ${path}`,
      );
    }

    const pem = readFileSync(path, "utf8");
    if (!pem.includes("PRIVATE KEY")) {
      throw new Error(
        `${path} does not look like a private key. GitHub's download is named ` +
          `<app>.<date>.private-key.pem and begins with -----BEGIN RSA PRIVATE KEY-----.`,
      );
    }

    this.#key = createPrivateKey(pem);
    // The path, never the contents. This ends up in logs and the audit chain.
    this.keyId = options.keyId ?? `file:${path}`;
  }

  sign(data: Buffer): Promise<Buffer> {
    const signer = createSign("RSA-SHA256");
    signer.update(data);
    signer.end();
    return Promise.resolve(signer.sign(this.#key));
  }
}

/**
 * Builds the App JWT GitHub requires to mint installation tokens.
 *
 * Short-lived on purpose. GitHub permits up to ten minutes; we use one. This
 * JWT can mint tokens for any installation, so its lifetime is the window in
 * which a leaked one is useful.
 *
 * `iat` is backdated 60 seconds because GitHub rejects a JWT whose issue time
 * is in the future by even a second, and clock skew between our host and
 * theirs is routine. This is documented GitHub guidance, not a workaround.
 */
export async function createAppJwt(
  signer: Signer,
  appId: string,
  now: Date = new Date(),
): Promise<string> {
  const issuedAt = Math.floor(now.getTime() / 1000) - 60;
  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iat: issuedAt,
    exp: issuedAt + 60 + 60,
    iss: appId,
  };

  const encode = (value: object): string =>
    Buffer.from(JSON.stringify(value)).toString("base64url");

  const signingInput = `${encode(header)}.${encode(payload)}`;
  const signature = await signer.sign(Buffer.from(signingInput, "utf8"));

  return `${signingInput}.${signature.toString("base64url")}`;
}
