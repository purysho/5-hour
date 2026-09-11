/**
 * The pricing page, and the checkout it posts to.
 *
 * Static and self-contained, for the same reason as the homepage: this is an
 * unauthenticated route, and a page that pulls a font or a script from a CDN
 * leaks every visitor to that CDN. The buy button is a plain form POST — no
 * client-side Stripe SDK, no publishable key in the page, no JavaScript at all
 * on the path to taking money. The redirect to Stripe's hosted checkout
 * happens server-side, so the only thing that can break between a decision to
 * buy and a payment page is our own handler.
 *
 * ── On CSRF ─────────────────────────────────────────────────────────────────
 *
 * There is no session and no authenticated state, so a forged POST achieves
 * exactly what an honest one does: it sends the victim's browser to a payment
 * page they can close. There is nothing to forge *against*. What the endpoint
 * does need is a bound on how often an anonymous caller can make us call
 * Stripe, which is why the handler validates the plan before any network call
 * and returns without one on anything unrecognised.
 */

import { PLANS, isPlanId, formatPrice, type Plan, type PlanId } from "../billing/plans.ts";
import type { StripeClient } from "../billing/stripe.ts";
import { randomUUID } from "node:crypto";

const SECURITY_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  "content-type": "text/html; charset=utf-8",
  "content-security-policy":
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "cache-control": "public, max-age=300",
  "strict-transport-security": "max-age=63072000; includeSubDomains",
});

export function pricingResponse(): {
  status: number;
  headers: Readonly<Record<string, string>>;
  body: string;
} {
  return { status: 200, headers: SECURITY_HEADERS, body: renderPricing() };
}

export interface CheckoutDeps {
  readonly stripe: StripeClient;
  readonly priceIds: Readonly<Record<PlanId, string>>;
  readonly publicOrigin: string;
  readonly log: (message: string, fields?: Record<string, unknown>) => void;
}

export type CheckoutOutcome =
  | { readonly kind: "redirect"; readonly url: string }
  | { readonly kind: "rejected"; readonly reason: string };

export async function startCheckout(
  planField: string | undefined,
  deps: CheckoutDeps,
): Promise<CheckoutOutcome> {
  if (planField === undefined || !isPlanId(planField)) {
    return { kind: "rejected", reason: "unknown-plan" };
  }

  const priceId = deps.priceIds[planField];
  if (priceId === undefined || priceId === "") {
    // Configured wrong rather than requested wrong. Worth a log line: it means
    // a plan is on sale on the pricing page that cannot be bought.
    deps.log("checkout requested for a plan with no configured price", { plan: planField });
    return { kind: "rejected", reason: "plan-not-configured" };
  }

  const session = await deps.stripe.createCheckoutSession({
    priceId,
    planId: planField,
    successUrl: `${deps.publicOrigin}/welcome?session={CHECKOUT_SESSION_ID}`,
    cancelUrl: `${deps.publicOrigin}/pricing`,
    // Correlates our logs with a Stripe session without carrying anything
    // about the customer.
    clientReferenceId: randomUUID(),
  });

  return { kind: "redirect", url: session.url };
}

/**
 * The page shown after a successful checkout.
 *
 * It does not confirm the subscription — at this moment the webhook may not
 * have arrived, and claiming "you're all set" before the tenant exists is the
 * kind of small lie that produces a support ticket. It tells the customer the
 * one thing they must now do, which is install the GitHub App.
 */
export function welcomeResponse(installUrl: string): {
  status: number;
  headers: Readonly<Record<string, string>>;
  body: string;
} {
  return {
    status: 200,
    headers: { ...SECURITY_HEADERS, "cache-control": "no-store" },
    body: renderWelcome(installUrl),
  };
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const STYLE = `
  :root { color-scheme: light dark; --fg: #16161a; --muted: #5b5b66; --bg: #fdfdfd; --line: #e4e4e8; --accent: #1a5fb4; --card: #ffffff; }
  @media (prefers-color-scheme: dark) {
    :root { --fg: #e8e8ea; --muted: #a0a0ac; --bg: #131316; --line: #2a2a30; --accent: #7aa8e8; --card: #1a1a1f; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--fg); font: 16px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif; }
  main { max-width: 960px; margin: 0 auto; padding: 64px 20px 96px; }
  h1 { font-size: 2rem; line-height: 1.2; margin: 0 0 12px; letter-spacing: -0.02em; }
  .lede { color: var(--muted); margin: 0 0 48px; max-width: 60ch; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px; }
  .plan { border: 1px solid var(--line); border-radius: 10px; padding: 24px; background: var(--card); display: flex; flex-direction: column; }
  .plan h2 { font-size: 1.05rem; margin: 0 0 4px; }
  .price { font-size: 2rem; font-weight: 600; letter-spacing: -0.02em; margin: 12px 0 2px; }
  .per { color: var(--muted); font-size: 0.85rem; }
  .blurb { color: var(--muted); font-size: 0.9rem; margin: 14px 0 18px; }
  ul { list-style: none; padding: 0; margin: 0 0 24px; font-size: 0.9rem; }
  li { padding: 5px 0 5px 20px; position: relative; }
  li::before { content: "—"; position: absolute; left: 0; color: var(--muted); }
  button { width: 100%; margin-top: auto; padding: 11px 16px; font: inherit; font-weight: 500; color: #fff; background: var(--accent); border: 0; border-radius: 7px; cursor: pointer; }
  button:hover { filter: brightness(1.08); }
  .note { margin-top: 48px; padding-top: 24px; border-top: 1px solid var(--line); color: var(--muted); font-size: 0.88rem; max-width: 68ch; }
  a { color: var(--accent); }
  @media (max-width: 640px) { main { padding: 40px 16px 64px; } h1 { font-size: 1.6rem; } }
`;

function planCard(plan: Plan): string {
  const features = plan.features.map((f) => `<li>${escapeHtml(f)}</li>`).join("");
  return `
    <section class="plan">
      <h2>${escapeHtml(plan.displayName)}</h2>
      <div class="price">${escapeHtml(formatPrice(plan.monthlyCents))}</div>
      <div class="per">per month</div>
      <p class="blurb">${escapeHtml(plan.blurb)}</p>
      <ul>${features}</ul>
      <form method="POST" action="/checkout">
        <input type="hidden" name="plan" value="${escapeHtml(plan.id)}">
        <button type="submit">Start with ${escapeHtml(plan.displayName)}</button>
      </form>
    </section>`;
}

function renderPricing(): string {
  const cards = Object.values(PLANS).map(planCard).join("");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pricing — Driftless</title>
<meta name="description" content="Driftless detects breaking changes in the packages you depend on and opens the fixing pull request. Plans from $49/month.">
<style>${STYLE}</style>
</head>
<body>
<main>
  <h1>Stop paying engineers to chase SDK bumps</h1>
  <p class="lede">
    Driftless watches the packages you depend on, detects the changes that
    actually break consumers, writes the migration, and opens the pull request
    with its reasoning attached. You review and merge. It never merges, and it
    never holds permission to.
  </p>
  <div class="grid">${cards}</div>
  <p class="note">
    Every plan is month to month and cancels from the billing portal. Pull
    requests are opened under a GitHub App scoped to <code>contents:write</code>
    and <code>pull_requests:write</code> — never merge rights, so human review
    cannot be bypassed. Credentials are minted per job, scoped to one
    repository, and expire in minutes.
    <a href="/">How it works</a>.
  </p>
</main>
</body>
</html>`;
}

function renderWelcome(installUrl: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>One step left — Driftless</title>
<style>${STYLE}</style>
</head>
<body>
<main>
  <h1>Payment received. One step left.</h1>
  <p class="lede">
    Driftless cannot see any repository until you install the GitHub App. Until
    you do, nothing is watched and no pull request can be opened.
  </p>
  <p><a href="${escapeHtml(installUrl)}"><button type="button">Install the GitHub App</button></a></p>
  <p class="note">
    Choose the repositories you want covered — you can change the selection at
    any time from GitHub, and removing the App revokes our access immediately.
    If you closed this page, the same link is in your receipt.
  </p>
</main>
</body>
</html>`;
}
