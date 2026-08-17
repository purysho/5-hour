import { describe, expect, it } from "vitest";
import { SignCommand } from "@aws-sdk/client-kms";
import { AwsKmsClient, type KmsSendClient } from "../../src/github/kms-signer.ts";
import type { KmsClient } from "../../src/github/signer.ts";

/**
 * A stand-in for the AWS SDK client.
 *
 * The signing path is worth testing with a fake rather than only against live
 * KMS: the branches that matter most (no signature returned, transport error)
 * are the ones a real key will never produce on demand.
 */
function fakeKms(
  handler: (command: SignCommand) => Promise<{ Signature?: Uint8Array | undefined }>,
): KmsSendClient & { destroyed: boolean; commands: SignCommand[] } {
  const commands: SignCommand[] = [];
  return {
    commands,
    destroyed: false,
    async send(command) {
      commands.push(command);
      return handler(command);
    },
    destroy() {
      this.destroyed = true;
    },
  };
}

const signature = new Uint8Array([1, 2, 3, 4]);

describe("AwsKmsClient", () => {
  it("implements KmsClient interface", () => {
    const client: KmsClient = new AwsKmsClient("us-east-1", fakeKms(async () => ({ Signature: signature })));
    expect(client).toHaveProperty("sign");
  });

  it("accepts an explicit region", () => {
    expect(new AwsKmsClient("eu-west-1", fakeKms(async () => ({}))).region).toBe("eu-west-1");
  });

  it("defaults to AWS_REGION environment variable", () => {
    const original = process.env["AWS_REGION"];
    process.env["AWS_REGION"] = "ap-southeast-1";
    try {
      expect(new AwsKmsClient(undefined, fakeKms(async () => ({}))).region).toBe("ap-southeast-1");
    } finally {
      if (original === undefined) delete process.env["AWS_REGION"];
      else process.env["AWS_REGION"] = original;
    }
  });

  it("defaults to us-east-1 when no region is configured", () => {
    const original = process.env["AWS_REGION"];
    delete process.env["AWS_REGION"];
    try {
      expect(new AwsKmsClient(undefined, fakeKms(async () => ({}))).region).toBe("us-east-1");
    } finally {
      if (original !== undefined) process.env["AWS_REGION"] = original;
    }
  });
});

describe("signing", () => {
  it("returns the signature KMS produced", async () => {
    const kms = fakeKms(async () => ({ Signature: signature }));
    const client = new AwsKmsClient("us-east-1", kms);

    const result = await client.sign("alias/driftless", Buffer.from("payload"));

    expect(result).toBeInstanceOf(Buffer);
    expect([...result]).toEqual([1, 2, 3, 4]);
  });

  it("signs with the algorithm GitHub App JWTs require", async () => {
    const kms = fakeKms(async () => ({ Signature: signature }));
    const client = new AwsKmsClient("us-east-1", kms);

    await client.sign("key-1", Buffer.from("payload"));

    // RS256. GitHub rejects a JWT signed any other way, and the failure it
    // returns says only "invalid token", so pin it here instead.
    expect(kms.commands[0]!.input.SigningAlgorithm).toBe("RSASSA_PKCS1_V1_5_SHA_256");
    expect(kms.commands[0]!.input.KeyId).toBe("key-1");
    expect(Buffer.from(kms.commands[0]!.input.Message!).toString()).toBe("payload");
  });

  it("fails when KMS returns no signature", async () => {
    const client = new AwsKmsClient("us-east-1", fakeKms(async () => ({})));

    // Not "KMS signing failed" — nothing failed in transport. This assertion
    // is the regression guard: the throw used to sit inside the try block
    // that wraps transport errors, so it was re-thrown with a prefix
    // describing a network failure that had not happened.
    await expect(client.sign("key-1", Buffer.from("x"))).rejects.toThrow(
      "KMS did not return a signature",
    );
    await expect(client.sign("key-1", Buffer.from("x"))).rejects.not.toThrow(
      /KMS signing failed/,
    );
  });

  it("wraps transport errors with context", async () => {
    const client = new AwsKmsClient(
      "us-east-1",
      fakeKms(async () => {
        throw new Error("AccessDeniedException: no kms:Sign on this key");
      }),
    );

    await expect(client.sign("key-1", Buffer.from("x"))).rejects.toThrow(
      "KMS signing failed: AccessDeniedException: no kms:Sign on this key",
    );
  });

  it("rethrows non-Error throws untouched", async () => {
    const client = new AwsKmsClient(
      "us-east-1",
      fakeKms(async () => {
        throw "socket hang up";
      }),
    );

    await expect(client.sign("key-1", Buffer.from("x"))).rejects.toBe("socket hang up");
  });

  it("never puts the key id in the error message", async () => {
    // Key ARNs are not secret, but they name an account. Keep them out of
    // anything that reaches a log by way of an exception.
    const client = new AwsKmsClient(
      "us-east-1",
      fakeKms(async () => {
        throw new Error("KMSInvalidStateException");
      }),
    );

    const error = await client
      .sign("arn:aws:kms:us-east-1:123456789012:key/abc", Buffer.from("x"))
      .then(
        () => null,
        (e: unknown) => e as Error,
      );

    expect(error).not.toBeNull();
    expect(error!.message).not.toContain("123456789012");
  });

  it("closes the underlying client on destroy", async () => {
    const kms = fakeKms(async () => ({ Signature: signature }));
    const client = new AwsKmsClient("us-east-1", kms);

    await client.destroy();

    expect(kms.destroyed).toBe(true);
  });
});

describe("live KMS", () => {
  /**
   * Integration test: requires AWS credentials and a real KMS key.
   * Skipped unless KMS_KEY_ID is set.
   *
   * To run locally:
   * export KMS_KEY_ID="arn:aws:kms:us-east-1:123:key/abc"
   * pnpm test test/github/kms-signer.test.ts
   */
  const kmsKeyId = process.env["KMS_KEY_ID"];
  const skipIfNoKms = kmsKeyId ? it : it.skip;

  skipIfNoKms("signs data with a real KMS key", async () => {
    const client = new AwsKmsClient();
    const result = await client.sign(kmsKeyId!, Buffer.from("test message"));

    expect(result).toBeInstanceOf(Buffer);
    expect(result.length).toBeGreaterThan(0);
  });

  skipIfNoKms("produces consistent signatures", async () => {
    const client = new AwsKmsClient();
    const message = Buffer.from("test message");

    // RSASSA_PKCS1_V1_5 is deterministic.
    const first = await client.sign(kmsKeyId!, message);
    const second = await client.sign(kmsKeyId!, message);

    expect(first.toString("hex")).toBe(second.toString("hex"));
  });

  skipIfNoKms("rejects an invalid key id", async () => {
    const client = new AwsKmsClient();
    await expect(
      client.sign("arn:aws:kms:us-east-1:123:key/invalid", Buffer.from("test")),
    ).rejects.toThrow();
  });
});
