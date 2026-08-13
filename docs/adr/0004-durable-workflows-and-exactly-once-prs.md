# ADR-0004 — Durable workflows and exactly-once pull requests

**Status:** Accepted · 2026-08-13

## Context

One upstream breaking change fans out to every affected downstream repository —
potentially thousands of independent, long-running, failure-prone jobs, each
involving clone, analysis, model inference, test execution, and a write to a
third party's repository.

Every component in that path fails routinely. Model providers time out. GitHub
rate-limits. Runners are preempted. Webhooks are delivered more than once, out
of order, or not at all.

The consequence of getting retries wrong is unusually severe here, and not for
the usual reasons. A duplicated internal job wastes money. A duplicated
*outbound write* opens forty pull requests in a customer's repository, which is
visible, embarrassing, and unrecoverable in the way that matters: the customer's
trust. Threat-model §5.6 identifies this as the most probable serious failure
the system faces — more likely than any attack.

The naive implementation — a queue, a worker, and retry-on-failure — produces
exactly this failure, because "did the PR get created?" is unanswerable after a
crash between creating it and recording that fact.

## Decision

**Job execution is durable and resumable; outbound writes are idempotent and
enforced exactly-once at the database, not in application logic.**

### Durable execution

Job orchestration uses a durable workflow engine (Temporal, or a
Postgres-backed durable queue such as River if we choose to avoid the
operational surface). Requirement, whichever is chosen: workflow state survives
process death, and a resumed workflow continues from its last completed step
rather than restarting.

This is not merely convenient. It is what makes retry safe at all: without
durable step boundaries, "retry the job" means "redo the side effects".

### Exactly-once outbound writes

Every outbound write carries an idempotency key:

```
(installation_id, repository_id, change_id, base_sha)
```

The key is inserted into a uniquely-constrained table **before** the write is
attempted, and the row records the outcome. A retry finds the existing row and
returns the prior result instead of writing again. The guarantee lives in a
unique index — a database invariant that holds regardless of application bugs,
concurrent workers, or duplicate webhook deliveries.

`base_sha` is part of the key deliberately: if the repository has moved on, it
is a genuinely different migration and should produce a new PR rather than being
suppressed as a duplicate.

### Rate ceilings and staged fan-out

Per-installation and per-repository hard ceilings on outbound writes, enforced
centrally. A new migration template is released to a small canary set of
repositories before broad fan-out, with automatic halt on anomalous rejection
or revert rates.

### Kill switch

A global halt on all outbound writes, effective without a deploy. Threat-model
§5.6 makes runaway automation the most probable serious incident; the ability
to stop it in seconds rather than minutes is proportionate.

## Consequences

**Good.** Retries become safe, which means they can be aggressive, which means
transient failures stop being incidents. The exactly-once guarantee is
demonstrable rather than asserted — kill workers mid-job under load and show
that no duplicate and no lost PR results. That test is the natural home for the
load, stress, and chaos testing on the engineering plan, and it produces
evidence rather than reassurance.

**Costs.** A durable workflow engine is significant operational surface for a
solo team; Temporal in particular is not free to run or to learn. The
Postgres-backed alternative trades capability for one less system to operate,
and given the team size that tradeoff may well be correct — the decision between
them is deferred to implementation, since the guarantees above are what matter
and both can provide them.

Workflow code must be written to be deterministic and replay-safe, which is a
real constraint that catches people out.

## Reversal trigger

If fan-out volume stays low enough that a simpler queue provides the same
guarantees, the durable engine is unnecessary complexity and should be removed.
The idempotency key and its unique constraint are **not** subject to this —
they stay regardless of orchestration choice.

## Alternatives considered

**Queue plus retries, dedup in application code.** Rejected. The dedup check and
the write are not atomic, so a crash between them produces exactly the duplicate
the check exists to prevent. This is the default implementation and it is wrong.

**At-most-once delivery (never retry outbound writes).** Rejected — trades
duplicate PRs for silently missing ones, which is worse: it fails invisibly, and
the product's entire value is that nothing gets missed.

**Idempotency keyed on `(repository, change_id)` without `base_sha`.** Rejected
— suppresses legitimate re-migration after the base branch moves, causing the
system to silently skip repositories that still need the fix.
