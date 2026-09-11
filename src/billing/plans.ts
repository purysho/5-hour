/**
 * The plan catalogue.
 *
 * Prices live here rather than only in Stripe because two of them are load
 * bearing in code: `repositoryLimit` is enforced at enrolment, and the plan
 * name appears in the pull request body a maintainer reads. A price that
 * exists only in the Stripe dashboard cannot be tested, and drift between the
 * two surfaces as "the plan we sold" versus "the plan we enforce".
 *
 * The Stripe price id is configuration, not code: it differs between test and
 * live mode, and hard-coding one guarantees that whichever mode is not in the
 * source is the one that breaks in production.
 *
 * ── Why these numbers ────────────────────────────────────────────────────────
 *
 * Priced against the alternative, which is an engineer spending most of a day
 * on a migration nobody wanted — not against Dependabot, which is free,
 * ubiquitous, and does not write the fix. The comparison that matters to a
 * buyer is "one afternoon of senior engineering time per month", and every
 * tier sits below it.
 */

export type PlanId = "starter" | "team" | "scale";

export interface Plan {
  readonly id: PlanId;
  readonly displayName: string;
  /** Monthly price in the smallest currency unit, for display only. */
  readonly monthlyCents: number;
  /**
   * Repositories the tenant may enrol. Enforced at install time, not at
   * detection time: refusing to watch a repository the customer already
   * connected is a support ticket, refusing to connect one more is a pricing
   * conversation.
   */
  readonly repositoryLimit: number;
  readonly blurb: string;
  readonly features: readonly string[];
}

export const PLANS: Readonly<Record<PlanId, Plan>> = Object.freeze({
  starter: Object.freeze({
    id: "starter",
    displayName: "Starter",
    monthlyCents: 4900,
    repositoryLimit: 10,
    blurb: "For a small team with a handful of services on the same SDKs.",
    features: Object.freeze([
      "10 repositories",
      "Breaking-change detection across npm",
      "Fixing pull requests, opened with the reasoning",
      "Tamper-evident audit log you can verify yourself",
    ]),
  }),
  team: Object.freeze({
    id: "team",
    displayName: "Team",
    monthlyCents: 19900,
    repositoryLimit: 50,
    blurb: "For an engineering org that feels every SDK bump across many repos.",
    features: Object.freeze([
      "50 repositories",
      "Everything in Starter",
      "Canary rollout — one repository first, then the rest",
      "Priority detection sweeps",
    ]),
  }),
  scale: Object.freeze({
    id: "scale",
    displayName: "Scale",
    monthlyCents: 49900,
    repositoryLimit: 200,
    blurb: "For a platform team that owns the dependency story company-wide.",
    features: Object.freeze([
      "200 repositories",
      "Everything in Team",
      "Private package registries",
      "Named support channel",
    ]),
  }),
});

export function isPlanId(value: string): value is PlanId {
  return Object.hasOwn(PLANS, value);
}

/**
 * Resolves a Stripe price id back to a plan.
 *
 * The webhook learns which plan was bought from the price on the subscription,
 * not from anything the browser sent. A plan chosen client-side is a plan the
 * customer can edit: the checkout URL is theirs to tamper with, and the only
 * authority on what was actually paid for is Stripe.
 */
export function planForPriceId(
  priceId: string,
  priceIds: Readonly<Record<PlanId, string>>,
): Plan | null {
  for (const plan of Object.values(PLANS)) {
    if (priceIds[plan.id] === priceId) return plan;
  }
  return null;
}

export function formatPrice(cents: number): string {
  return `$${Math.round(cents / 100)}`;
}
