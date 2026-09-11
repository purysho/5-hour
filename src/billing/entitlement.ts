/**
 * Is this tenant entitled to have work done for it?
 *
 * This is the module that turns a product into a business, and it is small on
 * purpose. Driftless delivers value through exactly one act — opening a pull
 * request — so there is exactly one place entitlement has to be checked, and
 * it is `authoriseOutboundWrite`. Checking anywhere else is decoration;
 * checking there is the whole of enforcement.
 *
 * ── Fails closed ────────────────────────────────────────────────────────────
 *
 * Every path that is not positively entitled returns not-entitled: no
 * subscription row, an unrecognised status, a status Stripe added after this
 * was written. The failure mode of failing open is giving the product away
 * silently and finding out at renewal; the failure mode of failing closed is a
 * support ticket from someone who is paying, which we hear about immediately
 * and can fix in one UPDATE. Those costs are not symmetric.
 *
 * ── Why `past_due` still works ──────────────────────────────────────────────
 *
 * A card fails for reasons that have nothing to do with intent to pay —
 * expiry, a bank's fraud heuristic, a billing address change. Stripe retries
 * over several days (dunning), and most of those recover. Cutting a customer
 * off on the first failed charge converts a recoverable payment into a
 * cancelled account and a bad taste. So `past_due` keeps working through a
 * grace window past the period it already paid for, and only then stops.
 *
 * The grace window is deliberately not infinite. `unpaid` and `canceled` are
 * Stripe's own verdicts that dunning is over; at that point continuing to work
 * is not generosity, it is an unbilled cost with no path to revenue.
 */

import type { TenantClient, ProviderId } from "../db/client.ts";

/** How long a `past_due` subscription keeps working past its paid period. */
export const DUNNING_GRACE_MS = 7 * 24 * 60 * 60 * 1000;

export type EntitlementReason =
  | "active"
  | "trialing"
  | "grace-period"
  | "no-subscription"
  | "grace-expired"
  | "cancelled"
  | "unknown-status";

export type Entitlement =
  | {
      readonly entitled: true;
      readonly reason: Extract<EntitlementReason, "active" | "trialing" | "grace-period">;
      readonly plan: string;
      readonly repositoryLimit: number;
    }
  | {
      readonly entitled: false;
      readonly reason: Exclude<EntitlementReason, "active" | "trialing" | "grace-period">;
      readonly detail: string;
    };

export interface SubscriptionRecord {
  readonly status: string;
  readonly plan: string;
  readonly repository_limit: number;
  readonly current_period_end: Date | null;
  readonly cancel_at_period_end: boolean;
}

/**
 * The decision, as a pure function of a subscription row.
 *
 * Separated from the query so every branch is testable without a database, and
 * so the clock is injectable — a grace-period boundary tested against
 * `Date.now()` is a test that passes for a week and then does not.
 */
export function decideEntitlement(
  subscription: SubscriptionRecord | null,
  now: Date = new Date(),
): Entitlement {
  if (subscription === null) {
    return {
      entitled: false,
      reason: "no-subscription",
      detail: "no subscription on record for this tenant",
    };
  }

  const { status, plan, repository_limit: repositoryLimit } = subscription;

  if (status === "active") {
    return { entitled: true, reason: "active", plan, repositoryLimit };
  }
  if (status === "trialing") {
    return { entitled: true, reason: "trialing", plan, repositoryLimit };
  }

  if (status === "past_due") {
    const periodEnd = subscription.current_period_end;
    // No period end on a past_due subscription is a shape we do not expect.
    // Treating it as an unbounded grace window would be the one bug in this
    // file that costs money indefinitely, so it is treated as expired.
    if (periodEnd === null) {
      return {
        entitled: false,
        reason: "grace-expired",
        detail: "past_due with no period end on record",
      };
    }
    const graceEnds = periodEnd.getTime() + DUNNING_GRACE_MS;
    if (now.getTime() < graceEnds) {
      return { entitled: true, reason: "grace-period", plan, repositoryLimit };
    }
    return {
      entitled: false,
      reason: "grace-expired",
      detail: `payment overdue since ${periodEnd.toISOString()}`,
    };
  }

  if (status === "canceled" || status === "unpaid" || status === "incomplete_expired") {
    return {
      entitled: false,
      reason: "cancelled",
      detail: `subscription status is ${status}`,
    };
  }

  // Including `incomplete` and `paused`, and anything Stripe adds later.
  return {
    entitled: false,
    reason: "unknown-status",
    detail: `unrecognised subscription status: ${status}`,
  };
}

/**
 * Reads the calling tenant's subscription.
 *
 * Runs on a tenant connection, so RLS scopes it to the current provider and no
 * predicate is needed or possible — a `WHERE provider_id = $1` here would be
 * application-enforced isolation shadowing the database-enforced kind, and
 * would read as the real control while not being it.
 */
export async function loadSubscription(
  client: TenantClient,
): Promise<SubscriptionRecord | null> {
  const { rows } = await client.query<SubscriptionRecord>(
    `SELECT status, plan, repository_limit, current_period_end, cancel_at_period_end
       FROM subscription
      LIMIT 1`,
  );
  return rows[0] ?? null;
}

export async function entitlementFor(
  client: TenantClient,
  now: Date = new Date(),
): Promise<Entitlement> {
  return decideEntitlement(await loadSubscription(client), now);
}

/** Narrows a provider id for logging without widening what is disclosed. */
export function tenantLabel(providerId: ProviderId): string {
  return providerId.slice(0, 8);
}
