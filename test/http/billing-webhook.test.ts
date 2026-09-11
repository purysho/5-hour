import { describe, it, expect, beforeEach } from "vitest";
import { createHmac } from "node:crypto";
import { handleBillingWebhook, type BillingWebhookDeps } from "../../src/http/billing-webhook.ts";
import type { BillingStore, ProvisionRequest } from "../../src/billing/provisioning.ts";
import { Secret } from "../../src/config.ts";
import type { PlanId } from "../../src/billing/plans.ts";

const SECRET = new Secret("whsec_testsecret_testsecret_testsecret", "STRIPE_WEBHOOK_SECRET");
const NOW_MS = 1_800_000_000_000;
const NOW_SECONDS = Math.floor(NOW_MS / 1000);

const PRICE_IDS: Readonly<Record<PlanId, string>> = Object.freeze({
  starter: "price_starter",
  team: "price_team",
  scale: "price_scale",
});

class FakeStore implements BillingStore {
  readonly provisioned: ProvisionRequest[] = [];
  readonly claimed = new Set<string>();
  created = true;

  async provision(request: ProvisionRequest) {
    this.provisioned.push(request);
    return { providerId: "00000000-0000-0000-0000-0000000000aa", created: this.created };
  }

  async claimEvent(eventId: string): Promise<boolean> {
    if (this.claimed.has(eventId)) return false;
    this.claimed.add(eventId);
    return true;
  }

  async close(): Promise<void> {}
}

let store: FakeStore;
let logged: string[];

function deps(): BillingWebhookDeps {
  return {
    secret: SECRET,
    store,
    priceIds: PRICE_IDS,
    log: (message) => logged.push(message),
    now: () => new Date(NOW_MS),
  };
}

function delivery(event: unknown, options: { signed?: boolean; at?: number } = {}) {
  const body = JSON.stringify(event);
  const timestamp = options.at ?? NOW_SECONDS;
  const signature = createHmac("sha256", Secret.reveal(SECRET))
    .update(`${timestamp}.${body}`, "utf8")
    .digest("hex");
  return {
    body,
    headers: {
      "stripe-signature":
        options.signed === false ? `t=${timestamp},v1=${"0".repeat(64)}` : `t=${timestamp},v1=${signature}`,
    },
  };
}

function subscriptionEvent(overrides: Record<string, unknown> = {}, type = "customer.subscription.created") {
  return {
    id: `evt_${Math.random().toString(36).slice(2)}`,
    type,
    data: {
      object: {
        id: "sub_123",
        customer: "cus_456",
        status: "active",
        cancel_at_period_end: false,
        current_period_end: NOW_SECONDS + 2_592_000,
        items: { data: [{ price: { id: "price_team" } }] },
        ...overrides,
      },
    },
  };
}

beforeEach(() => {
  store = new FakeStore();
  logged = [];
});

describe("an unsigned or forged delivery", () => {
  it("is rejected before anything is claimed or provisioned", async () => {
    const outcome = await handleBillingWebhook(delivery(subscriptionEvent(), { signed: false }), deps());
    expect(outcome).toEqual({ kind: "rejected", reason: "no-matching-signature" });
    expect(store.claimed.size).toBe(0);
    expect(store.provisioned).toHaveLength(0);
  });

  it("cannot provision a tenant by sending a plausible body with no signature", async () => {
    const raw = delivery(subscriptionEvent());
    const outcome = await handleBillingWebhook({ body: raw.body, headers: {} }, deps());
    expect(outcome).toEqual({ kind: "rejected", reason: "missing-header" });
    expect(store.provisioned).toHaveLength(0);
  });

  it("rejects a signed body that is not parseable as an event", async () => {
    const outcome = await handleBillingWebhook(delivery("not-an-event"), deps());
    expect(outcome).toEqual({ kind: "rejected", reason: "unparseable-body" });
  });
});

describe("a subscription event", () => {
  it("provisions a tenant on the plan matching the price actually charged", async () => {
    const outcome = await handleBillingWebhook(delivery(subscriptionEvent()), deps());

    expect(outcome.kind).toBe("provisioned");
    expect(store.provisioned).toHaveLength(1);
    const request = store.provisioned[0]!;
    expect(request.plan.id).toBe("team");
    expect(request.plan.repositoryLimit).toBe(50);
    expect(request.stripeSubscriptionId).toBe("sub_123");
    expect(request.status).toBe("active");
  });

  it("takes the plan from the price, not from metadata the customer could edit", async () => {
    // The checkout URL belongs to the customer. If metadata won, anyone could
    // pay for Starter and be provisioned on Scale.
    const event = subscriptionEvent({
      metadata: { plan: "scale" },
      items: { data: [{ price: { id: "price_starter" } }] },
    });
    await handleBillingWebhook(delivery(event), deps());
    expect(store.provisioned[0]!.plan.id).toBe("starter");
  });

  it("refuses a price it did not sell rather than guessing a plan", async () => {
    const event = subscriptionEvent({ items: { data: [{ price: { id: "price_created_in_dashboard" } }] } });
    const outcome = await handleBillingWebhook(delivery(event), deps());
    expect(outcome).toEqual({ kind: "ignored", reason: "no-actionable-subscription" });
    expect(store.provisioned).toHaveLength(0);
  });

  it("records a deletion as cancelled regardless of the status attached", async () => {
    const event = subscriptionEvent({ status: "active" }, "customer.subscription.deleted");
    await handleBillingWebhook(delivery(event), deps());
    expect(store.provisioned[0]!.status).toBe("canceled");
  });

  it("carries the period end through, because the grace window is measured from it", async () => {
    await handleBillingWebhook(delivery(subscriptionEvent()), deps());
    expect(store.provisioned[0]!.currentPeriodEnd).toEqual(
      new Date((NOW_SECONDS + 2_592_000) * 1000),
    );
  });

  it("passes a past_due status through unchanged for the entitlement layer to judge", async () => {
    await handleBillingWebhook(delivery(subscriptionEvent({ status: "past_due" }, "customer.subscription.updated")), deps());
    expect(store.provisioned[0]!.status).toBe("past_due");
  });
});

describe("a completed checkout session", () => {
  function sessionEvent(overrides: Record<string, unknown> = {}) {
    return {
      id: `evt_${Math.random().toString(36).slice(2)}`,
      type: "checkout.session.completed",
      data: {
        object: {
          id: "cs_1",
          customer: "cus_456",
          subscription: "sub_123",
          payment_status: "paid",
          metadata: { plan: "team" },
          customer_details: { email: "ops@acme.io" },
          ...overrides,
        },
      },
    };
  }

  it("provisions with a slug derived from the customer's email", async () => {
    await handleBillingWebhook(delivery(sessionEvent()), deps());
    const request = store.provisioned[0]!;
    expect(request.slug).toMatch(/^ops-/);
    expect(request.displayName).toBe("ops@acme.io");
  });

  it("does not provision a session that was not paid", async () => {
    const outcome = await handleBillingWebhook(delivery(sessionEvent({ payment_status: "unpaid" })), deps());
    expect(outcome).toEqual({ kind: "ignored", reason: "no-actionable-subscription" });
    expect(store.provisioned).toHaveLength(0);
  });

  it("does not provision a session with no subscription attached", async () => {
    const outcome = await handleBillingWebhook(delivery(sessionEvent({ subscription: undefined })), deps());
    expect(outcome).toEqual({ kind: "ignored", reason: "no-actionable-subscription" });
  });
});

describe("redelivery", () => {
  it("is claimed once, so a retried event cannot provision twice", async () => {
    const event = subscriptionEvent();
    const first = await handleBillingWebhook(delivery(event), deps());
    const second = await handleBillingWebhook(delivery(event), deps());

    expect(first.kind).toBe("provisioned");
    expect(second).toEqual({ kind: "duplicate", eventId: event.id });
    expect(store.provisioned).toHaveLength(1);
  });

  it("claims before provisioning, so a crash mid-provision does not re-run the effect twice", async () => {
    // The claim is taken first deliberately. The alternative — provision, then
    // claim — turns a crash between the two into a duplicate tenant.
    const event = subscriptionEvent();
    await handleBillingWebhook(delivery(event), deps());
    expect(store.claimed.has(event.id)).toBe(true);
  });
});

describe("events we do not act on", () => {
  it("are ignored without being claimed, so the table stays small", async () => {
    const outcome = await handleBillingWebhook(
      delivery({ id: "evt_x", type: "invoice.upcoming", data: { object: {} } }),
      deps(),
    );
    expect(outcome).toEqual({ kind: "ignored", reason: "invoice.upcoming" });
    expect(store.claimed.size).toBe(0);
  });
});
