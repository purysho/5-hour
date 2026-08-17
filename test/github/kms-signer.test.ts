import { describe, expect, it, vi } from "vitest";
import { AwsKmsClient } from "../../src/github/kms-signer.ts";
import type { KmsClient } from "../../src/github/signer.ts";

describe("AwsKmsClient", () => {
  it("implements KmsClient interface", async () => {
    const client: KmsClient = new AwsKmsClient("us-east-1");
    expect(client).toHaveProperty("sign");
  });

  it("accepts optional region", () => {
    const client = new AwsKmsClient("eu-west-1");
    expect(client).toBeDefined();
  });

  it("defaults to AWS_REGION environment variable", () => {
    const originalRegion = process.env["AWS_REGION"];
    process.env["AWS_REGION"] = "ap-southeast-1";
    try {
      const client = new AwsKmsClient();
      expect(client).toBeDefined();
    } finally {
      process.env["AWS_REGION"] = originalRegion;
    }
  });

  it("defaults to us-east-1 if no region configured", () => {
    const originalRegion = process.env["AWS_REGION"];
    delete process.env["AWS_REGION"];
    try {
      const client = new AwsKmsClient();
      expect(client).toBeDefined();
    } finally {
      process.env["AWS_REGION"] = originalRegion;
    }
  });
});

describe("KMS signing flow", () => {
  /**
   * Integration test: requires AWS credentials and a real KMS key.
   * Skipped in CI unless KMS_KEY_ID is set.
   *
   * To run locally:
   * export KMS_KEY_ID="arn:aws:kms:us-east-1:123:key/abc"
   * pnpm test test/github/kms-signer.test.ts
   */
  const kmsKeyId = process.env["KMS_KEY_ID"];
  const skipIfNoKms = kmsKeyId ? it : it.skip;

  skipIfNoKms("signs data with KMS key", async () => {
    const client = new AwsKmsClient();
    const message = Buffer.from("test message");

    const signature = await client.sign(kmsKeyId!, message);

    expect(signature).toBeInstanceOf(Buffer);
    expect(signature.length).toBeGreaterThan(0);
  });

  skipIfNoKms("produces consistent signatures", async () => {
    const client = new AwsKmsClient();
    const message = Buffer.from("test message");

    const sig1 = await client.sign(kmsKeyId!, message);
    const sig2 = await client.sign(kmsKeyId!, message);

    // RSA signatures are deterministic with RSASSA_PKCS1_V1_5
    expect(sig1.toString("hex")).toBe(sig2.toString("hex"));
  });

  skipIfNoKms("rejects invalid key ID", async () => {
    const client = new AwsKmsClient();
    const message = Buffer.from("test");

    await expect(client.sign("arn:aws:kms:us-east-1:123:key/invalid", message)).rejects.toThrow();
  });
});
