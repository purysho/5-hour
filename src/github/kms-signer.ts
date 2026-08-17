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
 * The one thing this module needs from the AWS SDK.
 *
 * Narrowed to a `send` rather than taking a `KMSClient`, so the failure paths
 * below are reachable from a test. They were not, before: signing was wired
 * directly to a live client, which made "KMS returned no signature" and the
 * error-wrapping branch code that had never once been executed. Those are
 * exactly the branches that only ever run during an incident, so they are the
 * ones least affordable to leave unproven.
 */
export interface KmsSendClient {
  send(command: SignCommand): Promise<{ Signature?: Uint8Array | undefined }>;
  destroy(): void;
}

/**
 * AWS KMS implementation of KmsClient.
 *
 * Each instance holds a KMS client and region. The client is reused across
 * signing requests to benefit from connection pooling.
 */
export class AwsKmsClient implements KmsClient {
  readonly #kms: KmsSendClient;
  readonly #region: string;

  /**
   * Create an AWS KMS client.
   *
   * @param region AWS region (e.g., 'us-east-1'). Defaults to AWS_REGION env var.
   * @param client Pre-built client, for tests. Production passes nothing and
   *        gets a real `KMSClient` built from the default credential chain.
   */
  constructor(region?: string, client?: KmsSendClient) {
    this.#region = region ?? process.env["AWS_REGION"] ?? "us-east-1";
    if (client) {
      this.#kms = client;
    } else {
      // Wrapped rather than assigned: `KMSClient.send` is heavily overloaded,
      // and narrowing it here keeps the overloads out of this module's types.
      const kms = new KMSClient({ region: this.#region });
      this.#kms = {
        send: (command) => kms.send(command),
        destroy: () => kms.destroy(),
      };
    }
  }

  /** The region this client signs in. Read by tests and by boot-time logging. */
  get region(): string {
    return this.#region;
  }

  async sign(keyId: string, message: Buffer): Promise<Buffer> {
    let response: { Signature?: Uint8Array | undefined };
    try {
      response = await this.#kms.send(
        new SignCommand({
          KeyId: keyId,
          Message: message,
          SigningAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256",
        }),
      );
    } catch (error) {
      // AWS SDK errors are detailed; include context.
      //
      // Only the transport call is wrapped. Wrapping the whole body — as this
      // did — meant the "no signature" error below was caught by its own
      // handler and re-thrown with a "KMS signing failed:" prefix, describing
      // a network failure that had not happened.
      if (error instanceof Error) {
        throw new Error(`KMS signing failed: ${error.message}`);
      }
      throw error;
    }

    if (!response.Signature) {
      throw new Error("KMS did not return a signature");
    }

    return Buffer.from(response.Signature);
  }

  /**
   * Clean up KMS client connection.
   *
   * Call this when the application shuts down to ensure pending requests
   * complete and the connection is properly closed.
   */
  async destroy(): Promise<void> {
    this.#kms.destroy();
  }
}
