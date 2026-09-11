/**
 * The Stripe webhook receiver — the only route by which a tenant comes into
 * existence.
 *
 * Everything here is untrusted until the signature verifies, and
 * customer-authored after it does. The shape of every field is checked before
 * use; nothing is interpolated anywhere.
 *
 * ── Which event decides entitlement ─────────────────────────────────────────
 *
 * `customer.subscription.*` is authoritative. It carries the status, the price
 * actually charged, and the period end — all of them Stripe's own record of
 * what happened, none of them inferred.
 *
 * `checkout.session.completed` is handled too, for one reason that is not
 * about entitlement: it is the only event carrying the customer's email, and
 * therefore the only chance to give the tenant a slug an operator can read.
 * Its status is inferred from `payment_status`, and a subsequent
 * `customer.subscription.updated` — which Stripe sends for any real state
 * change — corrects the inference. So the inference can only ever be
 * temporarily wrong in the direction of a customer who has just paid.
 *
 * Order is not guaranteed between the two, and neither one depends on the
 * other having arrived: `provision_subscription` resolves an existing tenant
 * by subscription id before it considers the slug, so whichever lands first
 * creates the tenant and the other converges onto it.
 *
 * ── Why the plan comes from the price id ────────────────────────────────────
 *
 * Not from metadata, and never from anything the browser sent. The checkout
 * URL belongs to the customer and metadata is echoed back verbatim; the only
 * authority on what was paid for is the price Stripe charged. Metadata is read
 * only as a fallback on the session event, where the price is not expanded,
 * and a mismatch resolves to the price.
 */

import type { Secret } from "../config.ts";
import { verifyStripeSignature, parseEvent, isRecord, type StripeEvent } from "../billing/stripe.ts";
import { PLANS, planForPriceId, isPlanId, type Plan, type PlanId } from "../billing/plans.ts";
import { slugFor, type BillingStore } from "../billing/provisioning.ts";
import { hashToken } from "../outbound/suppression.ts";

export interface BillingWebhookDeps {
  readonly secret: Secret;
  readonly store: BillingStore;
  readonly priceIds: Readonly<Record<PlanId, string>>;
  readonly log: (message: string, fields?: Record<string, unknown>) => void;
  readonly now?: () => Date;
}

export type BillingWebhookOutcome =
  | { readonly kind: "rejected"; readonly reason: string }
  | { readonly kind: "ignored"; readonly reason: string }
  | { readonly kind: "duplicate"; readonly eventId: string }
  | {
      readonly kind: "provisioned";
      readonly eventId: string;
      readonly providerId: string;
      readonly created: boolean;
    };

export interface RawBillingRequest {
  readonly body: string;
  readonly headers: Readonly<Record<string, string | undefined>>;
}

const SUBSCRIPTION_EVENTS = new Set([
  "customer.subscription.created",
  "customer.subscription.updated",
  "customer.subscription.deleted",
]);

export async function handleBillingWebhook(
  raw: RawBillingRequest,
  deps: BillingWebhookDeps,
): Promise<BillingWebhookOutcome> {
  const signature = raw.headers["stripe-signature"];
  const nowSeconds = Math.floor((deps.now?.() ?? new Date()).getTime() / 1000);

  const verified = verifyStripeSignature(raw.body, signature, deps.secret, nowSeconds);
  if (!verified.ok) return { kind: "rejected", reason: verified.reason };

  const event = parseEvent(raw.body);
  if (event === null) return { kind: "rejected", reason: "unparseable-body" };

  const relevant =
    SUBSCRIPTION_EVENTS.has(event.type) || event.type === "checkout.session.completed";
  if (!relevant) return { kind: "ignored", reason: event.type };

  // Claimed before any effect, so a redelivery arriving while the first is
  // still in flight loses the race here rather than provisioning twice.
  //
  // The claim is released if the work then fails — see the try/catch below.
  // It has to be, because a claim that outlives a failure is worse than no
  // claim at all: Stripe retries, the retry is dismissed as a duplicate, and a
  // customer who paid is never provisioned while Stripe is told the delivery
  // succeeded. That is the exact failure the config loader refuses to boot on
  // elsewhere, and it must not be reintroduced here.
  const claimed = await deps.store.claimEvent(event.id, event.type);
  if (!claimed) return { kind: "duplicate", eventId: event.id };

  const intent = SUBSCRIPTION_EVENTS.has(event.type)
    ? fromSubscriptionEvent(event, deps.priceIds)
    : fromCheckoutSession(event, deps.priceIds);

  if (intent === null) {
    deps.log("billing event carried no actionable subscription", { type: event.type });
    return { kind: "ignored", reason: "no-actionable-subscription" };
  }

  let result;
  try {
    result = await deps.store.provision(intent);
  } catch (error) {
    // Release, then rethrow. Rethrowing is what makes the server answer 5xx,
    // which is what makes Stripe retry at all; swallowing the error here would
    // leave the customer unprovisioned just as silently.
    //
    // A release that itself fails must not mask the original error — that one
    // is the reason provisioning failed, and it is the one worth reading.
    await deps.store.releaseEvent(event.id).catch((releaseError) => {
      deps.log("failed to release billing event claim", {
        eventId: event.id,
        error: String(releaseError),
      });
    });
    throw error;
  }

  deps.log("tenant provisioned", {
    eventType: event.type,
    plan: intent.plan.id,
    status: intent.status,
    created: result.created,
  });

  return {
    kind: "provisioned",
    eventId: event.id,
    providerId: result.providerId,
    created: result.created,
  };
}

interface Intent {
  readonly slug: string;
  readonly displayName: string;
  readonly stripeCustomerId: string;
  readonly stripeSubscriptionId: string;
  readonly status: string;
  readonly plan: Plan;
  readonly currentPeriodEnd: Date | null;
  readonly cancelAtPeriodEnd: boolean;
  readonly enrolmentRefHash: string | null;
}

function fromSubscriptionEvent(
  event: StripeEvent,
  priceIds: Readonly<Record<PlanId, string>>,
): Intent | null {
  const object = event.object;
  const subscriptionId = stringField(object, "id");
  const customerId = stringField(object, "customer");
  const status = stringField(object, "status");
  if (subscriptionId === null || customerId === null || status === null) return null;

  const priceId = firstPriceId(object);
  const plan = resolvePlan(priceId, metadataPlan(object), priceIds);
  if (plan === null) return null;

  return {
    slug: slugFor(null, customerId),
    displayName: customerId,
    stripeCustomerId: customerId,
    stripeSubscriptionId: subscriptionId,
    // A deleted subscription is reported as canceled regardless of the status
    // Stripe attaches, because the event itself is the cancellation.
    status: event.type === "customer.subscription.deleted" ? "canceled" : status,
    plan,
    currentPeriodEnd: unixField(object, "current_period_end"),
    cancelAtPeriodEnd: object["cancel_at_period_end"] === true,
    // Subscription events carry no checkout reference. Only the session event
    // does, and whichever arrives first wins in the function.
    enrolmentRefHash: null,
  };
}

function fromCheckoutSession(
  event: StripeEvent,
  priceIds: Readonly<Record<PlanId, string>>,
): Intent | null {
  const object = event.object;
  const subscriptionId = stringField(object, "subscription");
  const customerId = stringField(object, "customer");
  if (subscriptionId === null || customerId === null) return null;

  // Only a paid session provisions. `unpaid` and `no_payment_required` both
  // reach this event, and neither is a customer we have been paid by.
  if (stringField(object, "payment_status") !== "paid") return null;

  const plan = resolvePlan(null, metadataPlan(object), priceIds);
  if (plan === null) return null;

  const email = customerEmail(object);
  const reference = stringField(object, "client_reference_id");

  return {
    slug: slugFor(email, customerId),
    displayName: email ?? customerId,
    stripeCustomerId: customerId,
    stripeSubscriptionId: subscriptionId,
    // Inferred, and corrected by the next customer.subscription.* event. See
    // the header for why this is safe in the only direction it can be wrong.
    status: "active",
    plan,
    currentPeriodEnd: null,
    cancelAtPeriodEnd: false,
    // The reference that binds a GitHub installation to the tenant this
    // payment created. Hashed here and never stored in the clear: it travels
    // in a URL, and anyone holding one could bind their own installation to
    // this tenant.
    enrolmentRefHash: reference === null ? null : hashToken(reference),
  };
}

function resolvePlan(
  priceId: string | null,
  metadata: string | null,
  priceIds: Readonly<Record<PlanId, string>>,
): Plan | null {
  if (priceId !== null) {
    const byPrice = planForPriceId(priceId, priceIds);
    if (byPrice !== null) return byPrice;
    // A price we do not recognise is a plan we did not sell — a price created
    // in the dashboard, or an id from another account. Refusing is correct:
    // guessing a plan sets a repository limit nobody agreed to.
    return null;
  }
  if (metadata !== null && isPlanId(metadata)) return PLANS[metadata];
  return null;
}

function firstPriceId(subscription: Record<string, unknown>): string | null {
  const items = subscription["items"];
  if (!isRecord(items)) return null;
  const data = items["data"];
  if (!Array.isArray(data) || data.length === 0) return null;
  const first = data[0];
  if (!isRecord(first)) return null;
  const price = first["price"];
  if (!isRecord(price)) return null;
  return stringField(price, "id");
}

function metadataPlan(object: Record<string, unknown>): string | null {
  const metadata = object["metadata"];
  if (!isRecord(metadata)) return null;
  return stringField(metadata, "plan");
}

function customerEmail(session: Record<string, unknown>): string | null {
  const details = session["customer_details"];
  if (isRecord(details)) {
    const email = stringField(details, "email");
    if (email !== null) return email;
  }
  return stringField(session, "customer_email");
}

function stringField(object: Record<string, unknown>, key: string): string | null {
  const value = object[key];
  return typeof value === "string" && value !== "" ? value : null;
}

function unixField(object: Record<string, unknown>, key: string): Date | null {
  const value = object[key];
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  return new Date(value * 1000);
}
