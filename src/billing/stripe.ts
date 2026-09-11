/**
 * The Stripe boundary.
 *
 * Deliberately not the Stripe SDK. Two reasons, and the second is the real
 * one:
 *
 *   The webhook receiver is an unauthenticated, internet-facing route in the
 *   same process that holds a GitHub App signing key. Every dependency there
 *   is supply-chain surface against the highest-value process we run, and the
 *   threat model (§2) is explicit that a compromised Driftless is an efficient
 *   supply-chain attack. Signature verification is twenty lines of
 *   `node:crypto`, and `src/http/webhook.ts` already does exactly this for
 *   GitHub.
 *
 *   The SDK's ergonomics are mostly for things we do not do — retries against
 *   idempotency keys, pagination, expansion. We create checkout sessions and
 *   read webhooks.
 *
 * ── What is trusted here ─────────────────────────────────────────────────────
 *
 * Everything arriving on the webhook route is attacker-controlled until the
 * signature verifies. After it verifies it is Stripe-controlled, which is not
 * the same as safe: field values still originate from a customer who typed
 * them into a checkout form. `client_reference_id` and metadata are customer
 * data and are validated before use, never interpolated.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { Secret } from "../config.ts";

const STRIPE_API = "https://api.stripe.com/v1";

/**
 * How far a signature timestamp may be from now.
 *
 * Stripe's own default. A replayed delivery inside the window is handled by
 * the `billing_event` claim rather than by this check — the two controls cover
 * different attacks and neither substitutes for the other.
 */
export const SIGNATURE_TOLERANCE_SECONDS = 300;

export type SignatureFailure =
  | "missing-header"
  | "malformed-header"
  | "timestamp-outside-tolerance"
  | "no-matching-signature";

export type SignatureResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: SignatureFailure };

/**
 * Verifies a `Stripe-Signature` header against the raw request body.
 *
 * The body must be the bytes as received. Parsing and re-serialising JSON
 * changes key order and whitespace, and the signature is over the original —
 * a re-serialised body fails verification for every request, which tends to be
 * diagnosed as "Stripe is broken".
 */
export function verifyStripeSignature(
  rawBody: string,
  header: string | undefined,
  secret: Secret,
  nowSeconds: number = Math.floor(Date.now() / 1000),
  toleranceSeconds: number = SIGNATURE_TOLERANCE_SECONDS,
): SignatureResult {
  if (header === undefined || header === "") return { ok: false, reason: "missing-header" };

  let timestamp: string | null = null;
  const candidates: string[] = [];

  for (const part of header.split(",")) {
    const separator = part.indexOf("=");
    if (separator === -1) continue;
    const key = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (key === "t") timestamp = value;
    // Stripe sends every signature it considers valid, so a secret rotation
    // has a window where two are present. Collect all and accept any match.
    else if (key === "v1") candidates.push(value);
  }

  if (timestamp === null || candidates.length === 0) {
    return { ok: false, reason: "malformed-header" };
  }

  const issued = Number(timestamp);
  if (!Number.isFinite(issued)) return { ok: false, reason: "malformed-header" };

  // Rejects futures as well as pasts. A timestamp far in the future would
  // otherwise be accepted forever.
  if (Math.abs(nowSeconds - issued) > toleranceSeconds) {
    return { ok: false, reason: "timestamp-outside-tolerance" };
  }

  const expected = createHmac("sha256", Secret.reveal(secret))
    .update(`${timestamp}.${rawBody}`, "utf8")
    .digest("hex");

  for (const candidate of candidates) {
    if (equalsConstantTime(expected, candidate)) return { ok: true };
  }
  return { ok: false, reason: "no-matching-signature" };
}

function equalsConstantTime(expected: string, provided: string): boolean {
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(provided, "utf8");
  // timingSafeEqual throws on a length mismatch, and the throw is itself a
  // timing signal. Compare against ourselves to burn the same work, then
  // return false. Same treatment as src/http/webhook.ts.
  if (a.length !== b.length) {
    timingSafeEqual(a, a);
    return false;
  }
  return timingSafeEqual(a, b);
}

/**
 * The subset of a Stripe event we act on.
 *
 * Narrow on purpose: a wide type invites reading fields we have not thought
 * about, and every field here originates outside our trust boundary.
 */
export interface StripeEvent {
  readonly id: string;
  readonly type: string;
  readonly object: Record<string, unknown>;
}

export function parseEvent(rawBody: string): StripeEvent | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody);
  } catch {
    return null;
  }
  if (!isRecord(parsed)) return null;

  const id = parsed["id"];
  const type = parsed["type"];
  const data = parsed["data"];
  if (typeof id !== "string" || typeof type !== "string" || !isRecord(data)) return null;

  const object = data["object"];
  if (!isRecord(object)) return null;

  return { id, type, object };
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export interface CheckoutSessionRequest {
  readonly priceId: string;
  readonly successUrl: string;
  readonly cancelUrl: string;
  /** Our own correlation id, echoed back on the completed event. */
  readonly clientReferenceId: string;
  readonly planId: string;
}

export interface StripeClient {
  createCheckoutSession(request: CheckoutSessionRequest): Promise<{ url: string }>;
  createPortalSession(customerId: string, returnUrl: string): Promise<{ url: string }>;
}

export class StripeApiError extends Error {
  override readonly name = "StripeApiError";
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/**
 * A Stripe client over `fetch`.
 *
 * `fetchImpl` is injectable so every failure path — a 500, a malformed body, a
 * response with no URL — is testable without a network or a live account. The
 * alternative is tests that only cover the happy path, which is the path that
 * does not need covering.
 */
export function createStripeClient(
  apiKey: Secret,
  fetchImpl: typeof fetch = fetch,
): StripeClient {
  async function post(path: string, form: Record<string, string>): Promise<Record<string, unknown>> {
    const response = await fetchImpl(`${STRIPE_API}${path}`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${Secret.reveal(apiKey)}`,
        "content-type": "application/x-www-form-urlencoded",
        // Pinned: Stripe changes response shapes between versions, and
        // inheriting whatever the account defaults to means a dashboard
        // setting can break production.
        "stripe-version": "2024-06-20",
      },
      body: new URLSearchParams(form).toString(),
    });

    const text = await response.text();
    if (!response.ok) {
      // The body may contain the key in an echoed request under some error
      // shapes, so it never reaches the message.
      throw new StripeApiError(response.status, `Stripe request to ${path} failed`);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new StripeApiError(response.status, `Stripe returned a non-JSON body for ${path}`);
    }
    if (!isRecord(parsed)) {
      throw new StripeApiError(response.status, `Stripe returned an unexpected body for ${path}`);
    }
    return parsed;
  }

  return {
    async createCheckoutSession(request) {
      const body = await post("/checkout/sessions", {
        mode: "subscription",
        "line_items[0][price]": request.priceId,
        "line_items[0][quantity]": "1",
        success_url: request.successUrl,
        cancel_url: request.cancelUrl,
        client_reference_id: request.clientReferenceId,
        "metadata[plan]": request.planId,
        // Carried onto the subscription so a later `customer.subscription.*`
        // event can still tell us the plan without a second API call.
        "subscription_data[metadata][plan]": request.planId,
        allow_promotion_codes: "true",
      });

      const url = body["url"];
      if (typeof url !== "string" || url === "") {
        throw new StripeApiError(200, "Stripe checkout session has no URL");
      }
      return { url };
    },

    async createPortalSession(customerId, returnUrl) {
      const body = await post("/billing_portal/sessions", {
        customer: customerId,
        return_url: returnUrl,
      });
      const url = body["url"];
      if (typeof url !== "string" || url === "") {
        throw new StripeApiError(200, "Stripe portal session has no URL");
      }
      return { url };
    },
  };
}
