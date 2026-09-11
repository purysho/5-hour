import { describe, it, expect } from "vitest";
import { createHmac } from "node:crypto";
import {
  verifyStripeSignature,
  parseEvent,
  createStripeClient,
  StripeApiError,
  SIGNATURE_TOLERANCE_SECONDS,
} from "../../src/billing/stripe.ts";
import { Secret } from "../../src/config.ts";

const SECRET = new Secret("whsec_testsecret_testsecret_testsecret", "STRIPE_WEBHOOK_SECRET");
const NOW = 1_800_000_000;

function sign(body: string, timestamp: number, secret = SECRET): string {
  const signature = createHmac("sha256", Secret.reveal(secret))
    .update(`${timestamp}.${body}`, "utf8")
    .digest("hex");
  return `t=${timestamp},v1=${signature}`;
}

describe("Stripe signature verification", () => {
  const body = '{"id":"evt_1","type":"customer.subscription.updated"}';

  it("accepts a correctly signed body", () => {
    expect(verifyStripeSignature(body, sign(body, NOW), SECRET, NOW).ok).toBe(true);
  });

  it("rejects a body that was modified after signing", () => {
    const header = sign(body, NOW);
    const result = verifyStripeSignature(body + " ", header, SECRET, NOW);
    expect(result).toEqual({ ok: false, reason: "no-matching-signature" });
  });

  it("rejects a signature made with a different secret", () => {
    const attacker = new Secret("whsec_attacker_attacker_attacker_xx", "STRIPE_WEBHOOK_SECRET");
    const result = verifyStripeSignature(body, sign(body, NOW, attacker), SECRET, NOW);
    expect(result).toEqual({ ok: false, reason: "no-matching-signature" });
  });

  it("rejects a replayed delivery from outside the tolerance window", () => {
    const stale = NOW - SIGNATURE_TOLERANCE_SECONDS - 1;
    const result = verifyStripeSignature(body, sign(body, stale), SECRET, NOW);
    expect(result).toEqual({ ok: false, reason: "timestamp-outside-tolerance" });
  });

  it("rejects a timestamp far in the future, not only a stale one", () => {
    // A future timestamp would otherwise be accepted forever.
    const future = NOW + SIGNATURE_TOLERANCE_SECONDS + 1;
    const result = verifyStripeSignature(body, sign(body, future), SECRET, NOW);
    expect(result).toEqual({ ok: false, reason: "timestamp-outside-tolerance" });
  });

  it("accepts a delivery at the edge of the window", () => {
    const edge = NOW - SIGNATURE_TOLERANCE_SECONDS;
    expect(verifyStripeSignature(body, sign(body, edge), SECRET, NOW).ok).toBe(true);
  });

  it("accepts when any one of several v1 signatures matches, for secret rotation", () => {
    const valid = sign(body, NOW).split("v1=")[1];
    const header = `t=${NOW},v1=${"0".repeat(64)},v1=${valid}`;
    expect(verifyStripeSignature(body, header, SECRET, NOW).ok).toBe(true);
  });

  it("rejects a missing header", () => {
    expect(verifyStripeSignature(body, undefined, SECRET, NOW)).toEqual({
      ok: false,
      reason: "missing-header",
    });
  });

  it("rejects a header with no timestamp", () => {
    expect(verifyStripeSignature(body, `v1=${"a".repeat(64)}`, SECRET, NOW)).toEqual({
      ok: false,
      reason: "malformed-header",
    });
  });

  it("rejects a header with no signature", () => {
    expect(verifyStripeSignature(body, `t=${NOW}`, SECRET, NOW)).toEqual({
      ok: false,
      reason: "malformed-header",
    });
  });

  it("rejects a non-numeric timestamp rather than coercing it", () => {
    expect(verifyStripeSignature(body, `t=soon,v1=${"a".repeat(64)}`, SECRET, NOW)).toEqual({
      ok: false,
      reason: "malformed-header",
    });
  });

  it("rejects a signature of a different length without throwing", () => {
    // timingSafeEqual throws on a length mismatch; the throw would itself be a
    // timing signal, and an uncaught one here would 500 the endpoint.
    expect(verifyStripeSignature(body, `t=${NOW},v1=abc`, SECRET, NOW)).toEqual({
      ok: false,
      reason: "no-matching-signature",
    });
  });
});

describe("event parsing", () => {
  it("reads id, type and the data object", () => {
    const event = parseEvent(
      JSON.stringify({ id: "evt_1", type: "customer.subscription.created", data: { object: { id: "sub_1" } } }),
    );
    expect(event).toEqual({
      id: "evt_1",
      type: "customer.subscription.created",
      object: { id: "sub_1" },
    });
  });

  it("returns null rather than throwing on a body that is not JSON", () => {
    expect(parseEvent("<html>an error page</html>")).toBeNull();
  });

  for (const [label, body] of [
    ["a JSON array", "[]"],
    ["a bare string", '"evt_1"'],
    ["no data object", '{"id":"evt_1","type":"x"}'],
    ["a non-object data.object", '{"id":"evt_1","type":"x","data":{"object":3}}'],
    ["a numeric id", '{"id":1,"type":"x","data":{"object":{}}}'],
  ] as const) {
    it(`returns null for ${label}`, () => {
      expect(parseEvent(body)).toBeNull();
    });
  }
});

describe("the Stripe API client", () => {
  const key = new Secret("sk_test_key", "STRIPE_SECRET_KEY");

  function stubFetch(status: number, body: string): { calls: Request[]; impl: typeof fetch } {
    const calls: Request[] = [];
    const impl = (async (url: string | URL | Request, init?: RequestInit) => {
      calls.push(new Request(String(url), init));
      return new Response(body, { status });
    }) as unknown as typeof fetch;
    return { calls, impl };
  }

  it("creates a subscription checkout session and returns its URL", async () => {
    const { calls, impl } = stubFetch(200, JSON.stringify({ url: "https://checkout.stripe.com/c/pay/abc" }));
    const client = createStripeClient(key, impl);

    const session = await client.createCheckoutSession({
      priceId: "price_team",
      planId: "team",
      successUrl: "https://driftless.dev/welcome",
      cancelUrl: "https://driftless.dev/pricing",
      clientReferenceId: "ref-1",
    });

    expect(session.url).toBe("https://checkout.stripe.com/c/pay/abc");

    const body = await calls[0]!.text();
    const form = new URLSearchParams(body);
    expect(form.get("mode")).toBe("subscription");
    expect(form.get("line_items[0][price]")).toBe("price_team");
    // Carried onto the subscription so a later subscription event can resolve
    // the plan without a second API call.
    expect(form.get("subscription_data[metadata][plan]")).toBe("team");
  });

  it("sends the secret key as a bearer token and pins the API version", async () => {
    const { calls, impl } = stubFetch(200, JSON.stringify({ url: "https://checkout.stripe.com/x" }));
    await createStripeClient(key, impl).createCheckoutSession({
      priceId: "price_team",
      planId: "team",
      successUrl: "s",
      cancelUrl: "c",
      clientReferenceId: "r",
    });
    expect(calls[0]!.headers.get("authorization")).toBe("Bearer sk_test_key");
    expect(calls[0]!.headers.get("stripe-version")).toBe("2024-06-20");
  });

  it("throws without echoing the response body, which can contain the key", async () => {
    const { impl } = stubFetch(401, JSON.stringify({ error: { message: "Invalid API Key: sk_test_key" } }));
    const client = createStripeClient(key, impl);
    await expect(
      client.createCheckoutSession({
        priceId: "price_team",
        planId: "team",
        successUrl: "s",
        cancelUrl: "c",
        clientReferenceId: "r",
      }),
    ).rejects.toSatisfy((error: unknown) => {
      expect(error).toBeInstanceOf(StripeApiError);
      expect(String(error)).not.toContain("sk_test_key");
      return true;
    });
  });

  it("throws when Stripe returns HTML instead of JSON", async () => {
    // A gateway error page is a 200 with a body that is not JSON. Parsing it
    // as a session would redirect the customer to `undefined`.
    const { impl } = stubFetch(200, "<html>maintenance</html>");
    await expect(
      createStripeClient(key, impl).createCheckoutSession({
        priceId: "price_team",
        planId: "team",
        successUrl: "s",
        cancelUrl: "c",
        clientReferenceId: "r",
      }),
    ).rejects.toThrow(StripeApiError);
  });

  it("throws when a session comes back with no URL, rather than redirecting to undefined", async () => {
    const { impl } = stubFetch(200, JSON.stringify({ id: "cs_1" }));
    await expect(
      createStripeClient(key, impl).createCheckoutSession({
        priceId: "price_team",
        planId: "team",
        successUrl: "s",
        cancelUrl: "c",
        clientReferenceId: "r",
      }),
    ).rejects.toThrow(/no URL/);
  });
});

describe("checkout when Stripe is unavailable", () => {
  it("reports unavailable rather than throwing into the request handler", async () => {
    // This is the click that makes money. Letting it reach the server's
    // generic handler answers an unstyled "Internal error" with a 500, and a
    // customer who sees a crash on the buy button does not come back.
    const { startCheckout } = await import("../../src/http/pricing.ts");
    const logged: { message: string; fields?: Record<string, unknown> }[] = [];

    const outcome = await startCheckout("team", {
      stripe: {
        createCheckoutSession: async () => {
          throw new StripeApiError(503, "Stripe request to /checkout/sessions failed");
        },
      },
      priceIds: { starter: "price_a", team: "price_b", scale: "price_c" },
      publicOrigin: "https://driftless.dev",
      log: (message, fields) => logged.push({ message, ...(fields ? { fields } : {}) }),
    });

    expect(outcome.kind).toBe("unavailable");
    // Logged loudly: a misconfigured key produces exactly this, and is
    // otherwise invisible until someone notices nobody has signed up.
    expect(logged.map((entry) => entry.message)).toContain("checkout could not be created");
  });

  it("does not leak the key through the failure log", async () => {
    const { startCheckout } = await import("../../src/http/pricing.ts");
    const logged: unknown[] = [];

    await startCheckout("team", {
      stripe: {
        createCheckoutSession: async () => {
          throw new StripeApiError(401, "Stripe request to /checkout/sessions failed");
        },
      },
      priceIds: { starter: "price_a", team: "price_b", scale: "price_c" },
      publicOrigin: "https://driftless.dev",
      log: (message, fields) => logged.push({ message, fields }),
    });

    expect(JSON.stringify(logged)).not.toContain("sk_");
  });
});
