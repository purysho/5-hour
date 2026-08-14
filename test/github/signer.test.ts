import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { generateKeyPairSync, createVerify, type KeyObject } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createAppJwt,
  FileSigner,
  KmsSigner,
  LocalSigner,
  type KmsClient,
} from "../../src/github/signer.ts";

/**
 * App JWT signing (ADR-0002 §2, ADR-0012).
 *
 * The GitHub App private key mints installation tokens for every installation,
 * so holding it is equivalent to holding durable write access to every
 * customer repository. These tests are about the guards around where it lives.
 */

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const PEM = privateKey.export({ type: "pkcs1", format: "pem" }) as string;
const PUBLIC: KeyObject = publicKey;

describe("KmsSigner", () => {
  it("delegates signing without ever holding key material", async () => {
    // The property that matters: the process can request a signature and
    // cannot obtain the key.
    const calls: { keyId: string; length: number }[] = [];
    const kms: KmsClient = {
      async sign(keyId, message) {
        calls.push({ keyId, length: message.length });
        return Buffer.from("signature-bytes");
      },
    };

    const signer = new KmsSigner(kms, "arn:aws:kms:eu-west-1:1:key/abc");
    const signature = await signer.sign(Buffer.from("payload"));

    expect(signature.toString()).toBe("signature-bytes");
    expect(calls[0]?.keyId).toBe("arn:aws:kms:eu-west-1:1:key/abc");
  });

  it("exposes a key id safe to log", () => {
    const signer = new KmsSigner({ sign: async () => Buffer.alloc(0) }, "key-arn");
    expect(signer.keyId).toBe("key-arn");
  });
});

describe("LocalSigner", () => {
  it("signs in development", async () => {
    const signer = new LocalSigner(PEM);
    expect((await signer.sign(Buffer.from("x"))).length).toBeGreaterThan(0);
  });

  it("refuses to construct in production", () => {
    // A guard rather than a comment, because "we'll swap it before launch" is
    // how private keys end up in environment variables.
    const original = process.env["NODE_ENV"];
    process.env["NODE_ENV"] = "production";
    try {
      expect(() => new LocalSigner(PEM)).toThrow(/must not be used in production/);
    } finally {
      if (original === undefined) delete process.env["NODE_ENV"];
      else process.env["NODE_ENV"] = original;
    }
  });
});

describe("FileSigner", () => {
  /**
   * The interim signing path (ADR-0012). It exists because blocking all
   * progress on KMS provisioning is theatre — it stops the work without making
   * anyone safer — while a key in an environment variable is genuinely
   * dangerous. This is the bounded middle, and these tests are the bounds.
   */

  const dir = mkdtempSync(join(tmpdir(), "driftless-signer-"));
  const keyPath = join(dir, "app.private-key.pem");

  beforeAll(() => {
    writeFileSync(keyPath, PEM, { mode: 0o600 });
  });

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("signs with a key read from a file", async () => {
    const signer = new FileSigner(keyPath, { env: { NODE_ENV: "development" } });
    expect((await signer.sign(Buffer.from("payload"))).length).toBeGreaterThan(0);
  });

  it("identifies the key by path, never by contents", () => {
    // keyId reaches logs and the audit chain.
    const signer = new FileSigner(keyPath, { env: { NODE_ENV: "development" } });
    expect(signer.keyId).toBe(`file:${keyPath}`);
    expect(signer.keyId).not.toContain("PRIVATE KEY");
  });

  it("refuses a group- or world-readable key file", () => {
    // A private key at mode 0644 on a shared host is a key everyone on that
    // host has.
    const loose = join(dir, "loose.pem");
    writeFileSync(loose, PEM, { mode: 0o644 });
    expect(() => new FileSigner(loose, { env: { NODE_ENV: "development" } })).toThrow(
      /world-readable|chmod 600/,
    );
  });

  it("does not apply the POSIX check on Windows, where it measures nothing", () => {
    // Node synthesises `stat().mode` on Windows from the read-only attribute,
    // so every file reads as 0o666 whatever its ACL says. Applying the check
    // there refuses every key on the platform and tells the operator to run
    // `chmod`, which does not exist. Found by an operator on PowerShell.
    const loose = join(dir, "windows.pem");
    writeFileSync(loose, PEM, { mode: 0o644 });

    expect(
      () =>
        new FileSigner(loose, {
          platform: "win32",
          env: {
            NODE_ENV: "development",
            [FileSigner.WINDOWS_ACK_VAR]: FileSigner.WINDOWS_ACK_VALUE,
          },
        }),
    ).not.toThrow();
  });

  it("refuses on Windows without the acknowledgement, and says how to restrict the file", () => {
    // The honest position: the ACL cannot be verified cheaply, so say so and
    // require the operator to assert they have restricted it.
    try {
      new FileSigner(keyPath, { platform: "win32", env: { NODE_ENV: "development" } });
      expect.unreachable();
    } catch (error) {
      const message = (error as Error).message;
      expect(message).toContain("Cannot verify the permissions");
      expect(message).toContain("icacls");
      expect(message).toContain(FileSigner.WINDOWS_ACK_VAR);
      expect(message).not.toContain("chmod");
    }
  });

  it("does not let the Windows acknowledgement excuse a loose file elsewhere", () => {
    const loose = join(dir, "posix.pem");
    writeFileSync(loose, PEM, { mode: 0o644 });
    expect(
      () =>
        new FileSigner(loose, {
          platform: "linux",
          env: {
            NODE_ENV: "development",
            [FileSigner.WINDOWS_ACK_VAR]: FileSigner.WINDOWS_ACK_VALUE,
          },
        }),
    ).toThrow(/world-readable|chmod 600/);
  });

  it("still requires the production acknowledgement on Windows", () => {
    // Two independent guards. Being unable to verify permissions is not a
    // reason to stop asking about the thing ADR-0012 actually bounds.
    expect(
      () =>
        new FileSigner(keyPath, {
          platform: "win32",
          env: {
            NODE_ENV: "production",
            [FileSigner.WINDOWS_ACK_VAR]: FileSigner.WINDOWS_ACK_VALUE,
          },
        }),
    ).toThrow(/Refusing to hold the GitHub App private key/);
  });

  it("refuses a missing file with a useful message", () => {
    expect(
      () => new FileSigner(join(dir, "nope.pem"), { env: { NODE_ENV: "development" } }),
    ).toThrow(/not found or unreadable/);
  });

  it("refuses a file that is not a private key", () => {
    const wrong = join(dir, "wrong.pem");
    writeFileSync(wrong, "just some text", { mode: 0o600 });
    expect(() => new FileSigner(wrong, { env: { NODE_ENV: "development" } })).toThrow(
      /does not look like a private key/,
    );
  });

  it("refuses production without explicit acknowledgement", () => {
    expect(() => new FileSigner(keyPath, { env: { NODE_ENV: "production" } })).toThrow(
      /Refusing to hold the GitHub App private key in process memory/,
    );
  });

  it("names the acknowledgement and the ADR in the refusal", () => {
    // Someone hitting this at 3am should not have to go looking for what to do.
    try {
      new FileSigner(keyPath, { env: { NODE_ENV: "production" } });
      expect.unreachable();
    } catch (error) {
      const message = (error as Error).message;
      expect(message).toContain(FileSigner.ACK_VAR);
      expect(message).toContain("ADR-0012");
      expect(message).toContain("KMS");
    }
  });

  it("permits production only with the exact acknowledgement value", () => {
    // Deliberately awkward to type and impossible to set by accident — the
    // whole risk of an escape hatch is that it quietly becomes the default.
    expect(
      () =>
        new FileSigner(keyPath, {
          env: { NODE_ENV: "production", [FileSigner.ACK_VAR]: "true" },
        }),
    ).toThrow();

    expect(
      () =>
        new FileSigner(keyPath, {
          env: { NODE_ENV: "production", [FileSigner.ACK_VAR]: FileSigner.ACK_VALUE },
        }),
    ).not.toThrow();
  });

  it("produces signatures a verifier accepts", async () => {
    const signer = new FileSigner(keyPath, { env: { NODE_ENV: "development" } });
    const data = Buffer.from("the quick brown fox");
    const signature = await signer.sign(data);

    const verifier = createVerify("RSA-SHA256");
    verifier.update(data);
    verifier.end();
    expect(verifier.verify(PUBLIC, signature)).toBe(true);
  });
});

describe("createAppJwt", () => {
  it("produces a verifiable RS256 JWT", async () => {
    const signer = new LocalSigner(PEM);
    const jwt = await createAppJwt(signer, "123456");
    const [header, payload, signature] = jwt.split(".");

    const verifier = createVerify("RSA-SHA256");
    verifier.update(`${header}.${payload}`);
    verifier.end();
    expect(verifier.verify(PUBLIC, Buffer.from(signature as string, "base64url"))).toBe(true);
  });

  it("backdates iat to survive clock skew", async () => {
    // GitHub rejects a JWT issued even a second in the future, and skew
    // between our host and theirs is routine. Their documented guidance, not a
    // workaround.
    const now = new Date("2026-01-01T00:00:00Z");
    const jwt = await createAppJwt(new LocalSigner(PEM), "123456", now);
    const payload = JSON.parse(
      Buffer.from(jwt.split(".")[1] as string, "base64url").toString("utf8"),
    );
    expect(payload.iat).toBe(Math.floor(now.getTime() / 1000) - 60);
  });

  it("expires quickly, bounding the window a leaked JWT is useful", async () => {
    // This JWT can mint tokens for ANY installation, so its lifetime is the
    // blast radius. GitHub permits ten minutes; we use one.
    const now = new Date("2026-01-01T00:00:00Z");
    const jwt = await createAppJwt(new LocalSigner(PEM), "123456", now);
    const payload = JSON.parse(
      Buffer.from(jwt.split(".")[1] as string, "base64url").toString("utf8"),
    );
    expect(payload.exp - payload.iat).toBeLessThanOrEqual(120);
  });

  it("issues for the configured app id", async () => {
    const jwt = await createAppJwt(new LocalSigner(PEM), "999888");
    const payload = JSON.parse(
      Buffer.from(jwt.split(".")[1] as string, "base64url").toString("utf8"),
    );
    expect(payload.iss).toBe("999888");
  });
});
