import { createSign, createPrivateKey, type KeyObject } from "node:crypto";

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
