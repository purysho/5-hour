# ADR-0008 — Deferred concerns and their triggers

**Status:** Accepted · 2026-08-13

## Context

The engineering standard for this project is deliberately high, because the
product's premise is that customers can trust it with write access to their
source code. The full list of concerns that standard implies — disaster
recovery, chaos engineering, formal accessibility auditing, SOC 2, load testing
at scale, HIPAA, and much else — cannot all be built to depth by a very small
team while also proving the product works.

Attempting all of them simultaneously is the most likely way this project fails:
it produces an exquisitely engineered system with no evidence that anyone wants
it.

But there is a large difference between a concern that was *considered and
deferred with a stated trigger* and one that was never thought about. The first
is engineering judgment and reads as such in a security review. The second is a
gap. Undocumented sophistication is invisible; documented intent is legible and
costs hours rather than weeks.

## Decision

**Concerns not yet implemented are recorded here with an explicit trigger that
promotes them to in-scope. Deferral is a decision with a stated condition, not
an omission.**

Nothing on this list may be deferred *silently*. Adding an item here requires
the same consideration as building it; the difference is only in timing.

### Deferred

| Concern | Position | Trigger |
|---|---|---|
| Formal DR plan with tested RTO/RPO | Stateless services; Postgres PITR from the start. No documented objectives, no rehearsal. | First production customer data. Rehearsal required, not just a document. |
| Chaos engineering | The exactly-once guarantee (ADR-0004) is verified by targeted fault injection, which covers the highest-risk failure. No systematic programme. | Sustained fan-out beyond a few hundred concurrent jobs. |
| Load and stress testing at scale | Tested at expected volume plus a margin. Not to breaking point. | Before first large-provider onboarding, where fan-out steps up by an order of magnitude. |
| SOC 2 Type II | Controls are being built in a way that will satisfy an audit; no audit engaged. | First enterprise deal that requires it. Expect ~6 months lead time — start the readiness work at first serious enterprise conversation, not at signature. |
| Third-party penetration test | Internal adversarial testing only (ADR-0003 corpus). | First paying customer, or first handling of private repositories at volume — whichever is first. |
| HIPAA / PCI | No such data processed by design. | Any change to that premise. Treated as a product decision, not a compliance one. |
| GDPR tooling (DSAR, export, erasure) | Data minimisation done: source code not retained, personal data incidental (threat-model §7). No self-service tooling. | First EU customer, or first request. Manual handling is defensible at low volume; the design must not make it impossible. |
| Self-hosted / customer-managed inference | Third-party model providers under zero-retention terms, disclosed. | First customer refusal on model-provider grounds. Expected from security-conscious buyers; likely the first hard commercial blocker on this list. |
| Customer-hosted runners | All execution on our infrastructure (ADR-0006). | Enterprise requirement that code never leaves their perimeter. Open question in threat-model §9.2 about preserving audit verifiability. |
| Database-per-tenant isolation | RLS (ADR-0005). | Customer requiring physical isolation. Additive, not a replacement. |
| Full accessibility audit (WCAG 2.2 AA) | Semantic markup, keyboard navigability, and contrast are requirements from the first commit — cheap when done as you go, expensive when retrofitted. No formal audit or assistive-technology testing. | Before general availability of the dashboard. |
| Multi-region / HA | Single region. | Customer SLA requiring it, or a latency requirement measurement actually supports. |
| Formal incident response plan | Kill switch (ADR-0004) and alerting exist. No written runbook, no declared severities, no comms plan. | First paying customer. This one is cheap and high-value — likely the first item promoted off this list. |

### Not deferred — built from the start

Recorded for contrast, because these are load-bearing and cheap now,
disproportionately expensive later:

- Secrets discipline and `.gitignore` before any other file
- Zero standing privilege (ADR-0002)
- Instruction/data separation and the adversarial corpus (ADR-0003)
- Idempotency invariant at the database (ADR-0004)
- RLS on every tenant-scoped table (ADR-0005)
- Kernel-isolated sandboxing (ADR-0006)
- Hash-chained audit log (ADR-0007)
- TLS everywhere, HSTS, security headers, parameterised queries, input
  validation at trust boundaries
- Dependency scanning and automated patching — with the noted irony that a
  product which keeps other people's dependencies current must be exemplary
  about its own
- CI enforcing tests, coverage thresholds, linting, type checking, and secret
  scanning; `main` protected, PRs only
- Structured logging and error tracking with credential redaction at the sink

## Consequences

**Good.** Effort concentrates on what differentiates the product and on what is
irreversible if skipped. The list is directly usable in a security review — "not
yet, here is why, here is what changes it" is a credible answer, where silence
is not.

**Costs.** A trigger only works if someone notices it firing. This document must
be reviewed at each milestone, or it becomes a list of things that were
plausibly deferred once and then quietly forgotten. Review at every material
change in customer status is a standing obligation of this ADR.

There is also a real risk of the list being read as a roadmap by an
outside party. It is not. It is a record of judgment about sequencing.

## Reversal trigger

Team growth past the point where parallel work on these is affordable, or a
customer commitment that makes several items simultaneously mandatory. Either
way, items move off this list individually and with their own ADR where the
decision warrants one.
