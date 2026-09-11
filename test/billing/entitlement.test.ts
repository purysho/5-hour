import { describe, it, expect } from "vitest";
import { decideEntitlement, DUNNING_GRACE_MS, type SubscriptionRecord } from "../../src/billing/entitlement.ts";

/**
 * The entitlement decision.
 *
 * Every branch is exercised against an injected clock. A grace-period test
 * written against Date.now() passes for a week and then starts failing for
 * reasons unrelated to the code.
 */

function subscription(overrides: Partial<SubscriptionRecord> = {}): SubscriptionRecord {
  return {
    status: "active",
    plan: "team",
    repository_limit: 50,
    current_period_end: new Date("2026-02-01T00:00:00Z"),
    cancel_at_period_end: false,
    ...overrides,
  };
}

const NOW = new Date("2026-01-15T00:00:00Z");

describe("a paying tenant", () => {
  it("is entitled while active", () => {
    const result = decideEntitlement(subscription(), NOW);
    expect(result.entitled).toBe(true);
    if (result.entitled) {
      expect(result.reason).toBe("active");
      expect(result.repositoryLimit).toBe(50);
      expect(result.plan).toBe("team");
    }
  });

  it("is entitled during a trial", () => {
    const result = decideEntitlement(subscription({ status: "trialing" }), NOW);
    expect(result.entitled).toBe(true);
    if (result.entitled) expect(result.reason).toBe("trialing");
  });

  it("stays entitled while cancelling at period end, because they have paid for it", () => {
    const result = decideEntitlement(
      subscription({ cancel_at_period_end: true }),
      NOW,
    );
    expect(result.entitled).toBe(true);
  });
});

describe("a tenant whose payment failed", () => {
  const periodEnd = new Date("2026-01-10T00:00:00Z");

  it("keeps working inside the dunning grace window", () => {
    const insideWindow = new Date(periodEnd.getTime() + DUNNING_GRACE_MS - 1000);
    const result = decideEntitlement(
      subscription({ status: "past_due", current_period_end: periodEnd }),
      insideWindow,
    );
    expect(result.entitled).toBe(true);
    if (result.entitled) expect(result.reason).toBe("grace-period");
  });

  it("stops at the moment the window closes, not a second later", () => {
    const atBoundary = new Date(periodEnd.getTime() + DUNNING_GRACE_MS);
    const result = decideEntitlement(
      subscription({ status: "past_due", current_period_end: periodEnd }),
      atBoundary,
    );
    expect(result.entitled).toBe(false);
    if (!result.entitled) expect(result.reason).toBe("grace-expired");
  });

  it("is refused when past_due carries no period end, rather than granted forever", () => {
    // The one bug in this file that would cost money indefinitely: treating a
    // missing period end as an unbounded grace window.
    const result = decideEntitlement(
      subscription({ status: "past_due", current_period_end: null }),
      NOW,
    );
    expect(result.entitled).toBe(false);
    if (!result.entitled) expect(result.reason).toBe("grace-expired");
  });
});

describe("a tenant who is not paying", () => {
  it("is refused when there is no subscription at all", () => {
    const result = decideEntitlement(null, NOW);
    expect(result.entitled).toBe(false);
    if (!result.entitled) expect(result.reason).toBe("no-subscription");
  });

  for (const status of ["canceled", "unpaid", "incomplete_expired"]) {
    it(`is refused when the subscription is ${status}`, () => {
      const result = decideEntitlement(subscription({ status }), NOW);
      expect(result.entitled).toBe(false);
      if (!result.entitled) expect(result.reason).toBe("cancelled");
    });
  }

  it("is refused when Stripe reports a status this code has never seen", () => {
    // Fails closed. A status added by Stripe after this was written must not
    // read as entitled by default — that failure is silent and permanent.
    const result = decideEntitlement(subscription({ status: "quantum_superposition" }), NOW);
    expect(result.entitled).toBe(false);
    if (!result.entitled) expect(result.reason).toBe("unknown-status");
  });

  it("is refused while a first payment is still incomplete", () => {
    const result = decideEntitlement(subscription({ status: "incomplete" }), NOW);
    expect(result.entitled).toBe(false);
  });
});
