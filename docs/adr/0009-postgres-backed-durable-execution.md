# ADR-0009 — Postgres-backed durable execution

**Status:** Accepted · 2026-08-13
**Closes the open decision in** [ADR-0004](0004-durable-workflows-and-exactly-once-prs.md)

## Context

ADR-0004 established that job execution must be durable and resumable, and
deliberately deferred the choice of engine: Temporal, or a Postgres-backed
durable queue. The guarantees were specified; the mechanism was not.

That deferral has to close now, because everything else hangs off it — the
GitHub App integration, change detection, and fan-out all need somewhere to
run.

The workload is specific and worth stating plainly before choosing. Jobs are
short (minutes, bounded by the token TTL in ADR-0002), independent (one
repository each), numerous under fan-out, and failure-prone at every step. The
hard requirement is not throughput. It is that a crash between "we opened a
pull request" and "we recorded that we opened a pull request" must not produce
a second pull request.

Temporal solves this well and is the more capable system. It is also a
significant operational surface: a server, a datastore, worker versioning, and
a programming model with determinism constraints that catch people out. For a
solo team whose scarcest resource is attention, every additional system is
paid for continuously.

## Decision

**Durable execution is built on Postgres — the database we already operate —
using a leased job queue with step-level memoisation.**

Three mechanisms, all in `migrations/004_jobs.sql` and `src/workflow/`:

### 1. Leased dequeue

Workers claim jobs with `FOR UPDATE SKIP LOCKED` and hold a time-bounded
lease. A worker that dies stops renewing; the lease expires and the job
returns to the queue. No job is lost to a dead worker, and no job is executed
by two workers at once for longer than one lease period.

`SKIP LOCKED` is what makes this scale: workers never queue behind each other
for the same row.

### 2. Step memoisation

A workflow declares its side effects as named steps:

```ts
const pr = await ctx.step("open-pr", () => github.openPullRequest(...));
```

The result of a completed step is recorded, keyed on `(job_id, step_key)`
under a unique constraint. On retry, a completed step returns its recorded
result **without re-executing**. This is the property that makes retries safe:
without it, "retry the job" means "redo the side effects", which is exactly
the duplicate-PR failure of threat-model §5.6.

Steps are the durability boundary. Anything with an external side effect must
be inside one.

### 3. Bounded retry with backoff and a dead letter

Exponential backoff with jitter, a per-workflow attempt ceiling, then the job
moves to a terminal `dead` state rather than retrying forever. A job retrying
indefinitely is how a transient outage becomes a rate-limit ban and a customer
incident.

Jitter matters more than it looks: without it, a provider outage produces
synchronised retries from every worker at once, and the recovery attempt
becomes a second outage.

## Consequences

**Good.** One datastore to operate, back up, and reason about. The queue is
inspectable with SQL, which matters at 3am. Jobs, steps, tenancy, audit, and
the idempotency invariant live in one transactional boundary, so a job can
claim an outbound write and record its audit intent atomically — with Temporal
those would span two systems and need reconciling. Local development and CI
need no extra infrastructure, which keeps the test suite honest: the tests run
against the real mechanism rather than a mock of it.

**Costs.** We are writing execution infrastructure rather than buying it, and
some of Temporal's harder-won features are simply absent — signals, child
workflows, long timers, versioned workflow migration, a query API. Postgres
becomes a throughput ceiling: a leased queue on one primary handles thousands
of jobs per minute comfortably and tens of thousands with care, which is well
beyond where this product needs to be, but it is a real ceiling.

Long-running workflows are not supported and are not intended to be. Jobs are
bounded by the token TTL by design (ADR-0002); a job needing more time is
re-scheduled, not extended.

## Reversal trigger

Move to Temporal when any of these become true:

- sustained throughput approaches the practical ceiling of a leased Postgres
  queue and vertical scaling is no longer the cheap answer;
- workflows genuinely need signals, child workflows, or multi-day timers —
  human-in-the-loop approval spanning days would qualify;
- the time spent maintaining this execution layer exceeds the operational cost
  of running Temporal.

The migration path is deliberately preserved: workflows are written as plain
functions over a `ctx.step` interface that Temporal's activity model also
satisfies. Porting should mean replacing the runtime, not rewriting the
workflows. Keep it that way — no Postgres-specific behaviour leaks into
workflow code.

## Alternatives considered

**Temporal.** The stronger system, and the right answer at a larger scale or a
larger team. Rejected now on operational cost: it is a second stateful system
to run and understand, for guarantees we can obtain from the database we
already have, at a volume far below where its advantages appear.

**An off-the-shelf Postgres queue (River, pg-boss, Graphile Worker).** Close to
what is built here and genuinely tempting. Rejected because none provides step
memoisation, which is the part that actually delivers ADR-0004's guarantee —
they give durable *queuing*, not durable *execution*. Wrapping one to add
steps is most of this work plus a dependency in the most security-sensitive
path in the system. Worth revisiting if one grows the feature.

**Redis-backed queue (BullMQ).** Rejected outright. Job state would live
outside the transactional boundary that holds the idempotency invariant, so a
crash could commit a job outcome without the write claim, or the reverse. That
is the exact failure mode ADR-0004 exists to eliminate.

**No durable layer — cron plus idempotent handlers.** Tempting for its
simplicity, and the idempotency index would still prevent duplicate pull
requests. Rejected because it provides no way to resume a multi-step job:
every failure restarts from the beginning, so a job that fails after opening a
pull request but before recording it has no path back to consistency.
