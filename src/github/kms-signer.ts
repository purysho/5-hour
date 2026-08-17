/**
 * AWS KMS signing client.
 *
 * Implements the KmsClient interface using AWS KMS for GitHub App JWT signing.
 * The private key never enters the application process; only the ability to
 * request signatures is granted (ADR-0002 §2).
 *
 * ── Session credentials ──────────────────────────────────────────────────────
 *
 * This client uses default AWS SDK credential chain:
 * 1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
 * 2. ~/.aws/credentials
 * 3. EC2 IAM instance role (preferred in production)
 *
 * On EC2, attach an IAM role with:
 * - `kms:Sign` permission on the signing key
 * - Optionally `kms:DescribeKey` for key verification
 *
 * ── Key format ───────────────────────────────────────────────────────────────
 *
 * keyId can be:
 * - Key ARN: `arn:aws:kms:us-east-1:123456789012:key/12345678-1234-...`
 * - Key ID: `12345678-1234-1234-1234-123456789012`
 * - Alias: `alias/driftless-signing-key`
 *
 * ARN is recommended in production for explicit, auditable key selection.
 */

import { KMSClient, SignCommand } from "@aws-sdk/client-kms";
import type { KmsClient } from "./signer.ts";

/**
 * AWS KMS implementation of KmsClient.
 *
 * Each instance holds a KMS client and region. The client is reused across
 * signing requests to benefit from connection pooling.
 */
export class AwsKmsClient implements KmsClient {
  readonly #kms: KMSClient;
  readonly #region: string;

  /**
   * Create an AWS KMS client.
   *
   * @param region AWS region (e.g., 'us-east-1'). Defaults to AWS_REGION env var.
   */
  constructor(region?: string) {
    this.#region = region ?? process.env["AWS_REGION"] ?? "us-east-1";
    this.#kms = new KMSClient({ region: this.#region });
  }

  async sign(keyId: string, message: Buffer): Promise<Buffer> {
    try {
      const response = await this.#kms.send(
        new SignCommand({
          KeyId: keyId,
          Message: message,
          SigningAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256",
        }),
      );

      if (!response.Signature) {
        throw new Error("KMS did not return a signature");
      }

      return Buffer.from(response.Signature);
    } catch (error) {
      // AWS SDK errors are detailed; include context
      if (error instanceof Error) {
        throw new Error(`KMS signing failed: ${error.message}`);
      }
      throw error;
    }
  }

  /**
   * Clean up KMS client connection.
   *
   * Call this when the application shuts down to ensure pending requests
   * complete and the connection is properly closed.
   */
  async destroy(): Promise<void> {
    await this.#kms.destroy();
  }
}
