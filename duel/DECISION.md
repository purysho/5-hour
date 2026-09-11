# DECISION — what we are building, and why

**Locked at T+0:40. Not reopened.**

## The pick

Build the **commercial layer for Driftless**: self-serve checkout, automatic
tenant provisioning, entitlement enforcement, and a customer dashboard.

Not a new product. This repository already contains ~14,000 lines of tested
production TypeScript that detects breaking upstream changes and opens the
fixing pull request downstream. 573 tests. Thirteen ADRs. A threat model. The
pipeline is connected end to end.

What it does not contain is any way to be paid.

## Why this beats greenfield

The instruction was: the highest-probability path to revenue within one
window. Three facts decided it.

1. **The expensive half is already built.** A greenfield product spends the
   whole window reaching "it runs". Driftless already runs. The marginal hour
   here buys revenue mechanics, not scaffolding.
2. **The gap is precisely the revenue gap.** Onboarding a paying customer
   today means a human running `pnpm db:provider <slug>` by hand. There is no
   pricing page, no checkout, no subscription record, and nothing that stops
   a non-paying tenant from consuming the product. Every one of those is
   between the code and the money.
3. **Nothing about the gap is architecturally cheap to do badly.** Provider
   creation is deliberately impossible for the application role — the RLS
   policy on `provider` checks `id = app.current_provider_id()`, so a row that
   does not yet exist can never satisfy it (ADR-0005). A billing webhook that
   creates tenants runs directly into that wall. The naive fix — give the app
   role more rights — silently destroys cross-tenant isolation. That is
   exactly the kind of thing worth spending a window getting right.

## What "makes money" means here, concretely

Four things, in dependency order:

| | Without it |
|---|---|
| Stripe Checkout → subscription | No way to pay |
| Webhook → automatic tenant provisioning | Every signup needs a human |
| Entitlement enforced at the outbound write | Non-payers get the product free |
| Dashboard showing opened PRs | Nothing proves the value that justifies renewal |

The third is the one people skip, and it is the one that turns a product into
a business. Driftless's value is delivered by a single act — opening a pull
request — and `authoriseOutboundWrite` is the chokepoint every one of them
passes through. Entitlement belongs there, failing closed, checked before the
idempotency claim is consumed.

## Rejected alternatives

- **Greenfield SaaS.** Loses by arithmetic. Five hours buys a landing page and
  a toy; here it buys a sellable product.
- **Build the dashboard first.** Prettier, and worth less. A dashboard without
  checkout displays a business that cannot take money.
- **Finish the gVisor sandbox.** The most technically interesting gap, and the
  wrong one. It improves a product nobody can buy yet, and the handoff notes
  the real blocker is a workspace abstraction — a multi-day change.
- **The dependent-repository crawler.** Also real, also not revenue. It widens
  the funnel into a product with no till.

## How this makes money, stated plainly

Self-serve: land on `/pricing`, pay, get redirected to install the GitHub App,
which enrols into the tenant the payment just created. Driftless then detects
breaking changes in watched packages and opens fixing PRs in their repos. If
the subscription lapses, the outbound guard refuses and the PRs stop.

Price: $49/mo Starter (10 repositories), $199/mo Team (50), $499/mo Scale
(200). $10k MRR is roughly 50 Team customers, or 20 Scale. Priced against the
alternative — an engineer spending a day per migration — not against
Dependabot, which is free and does not write the fix.
