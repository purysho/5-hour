# ADR-0010 — Separate login roles for tenant and platform access

**Status:** Accepted · 2026-08-13
**Refines** [ADR-0005](0005-multi-tenancy-via-row-level-security.md) and
[ADR-0009](0009-postgres-backed-durable-execution.md)

## Context

ADR-0009 introduced one genuinely cross-tenant operation: a worker polling a
shared job queue cannot know whose job it will receive, so it cannot have
tenant context set beforehand. That operation was confined to the
`driftless_admin` role, with an explicit RLS policy on `job` and `job_step`
and no policy on any tenant data table.

The first implementation gave the worker a single login role holding
membership in both `driftless_app` and `driftless_admin` — one set of
credentials, both capabilities, switching between them with `SET LOCAL ROLE`.

**This silently destroyed tenant isolation, and a test caught it.**

Postgres applies *every* policy attached to *any* role the current user is a
member of, combined with `OR`. A login role inheriting both grants therefore
picks up `job_platform_access` (`USING (true)`) in addition to
`job_tenant_isolation`. Every tenant-scoped query against `job` and `job_step`
returned other tenants' rows.

The severity is in how it fails. No error is raised, no query fails, nothing
appears in a log. A code review sees `withTenant(providerId, ...)` and reads it
as correctly scoped, because at the application layer it is. The defect lives
entirely in role membership, which is not visible from the code that suffers
from it.

`SET LOCAL ROLE` does not help. Membership is inherited, so the policies still
apply.

## Decision

**Tenant access and platform access use separate login roles. No login role is
ever granted both `driftless_app` and `driftless_admin`.**

1. The application connects as a role granted `driftless_app` only.
2. Workers hold a second, separate connection as a role granted
   `driftless_admin` only, used exclusively to dequeue.
3. `Database` maintains two pools. `withPlatformContext` uses the platform
   pool; if none is configured it throws. A process that is not a worker
   configures no platform connection and therefore cannot make a cross-tenant
   query at all.
4. The platform pool is deliberately small (4 connections). The only operation
   on it is dequeue; a large pool would make an accidental cross-tenant path
   cheap to run at volume.
5. Two tests enforce this: one fails if any role holds both grants, another
   fails if `driftless_admin` acquires a policy on any table other than `job`
   and `job_step`.

**Capability is decided by which credentials a process holds, not by which
code path it takes.** A bug in application logic cannot escalate into platform
access, because the application process does not possess platform credentials.

## Consequences

**Good.** The isolation boundary moves from "the code calls the right helper"
to "the process holds the right credentials" — the second is far harder to
violate by accident and far easier to verify. The blast radius of a
compromised application process no longer includes the queue.

**Costs.** Two sets of credentials to provision, rotate, and keep in sync, and
a deployment that must not accidentally hand both to one process. The tests
above are the guard, and they are the reason this is recorded as a decision
rather than a fix.

A worker holds two connections and therefore two pool lifecycles. `close()`
drains both.

## Reversal trigger

None. The failure mode is silent cross-tenant disclosure, which ADR-0005
identifies as ending the business. If the queue's tenancy model changes such
that dequeue no longer needs cross-tenant reach — per-tenant queues, for
instance — then `driftless_admin` disappears entirely and this ADR becomes
moot rather than reversed. That would be a strictly better outcome; it is
worth revisiting if tenant counts stay low.

## Alternatives considered

**`BYPASSRLS` on the platform role.** Rejected. It is invisible in the schema,
applies to every table forever, and grows silently as tables are added. An
explicit policy names the two tables it covers and appears where a reviewer is
already looking.

**`SECURITY DEFINER` on `dequeue_jobs`.** Would work, and avoids a second role.
Rejected because it moves the privilege boundary inside a function body where
it is easy to overlook, and because `SECURITY DEFINER` functions are a
well-known source of privilege-escalation bugs when their search path or
arguments are not handled with care. Two roles is more machinery but far less
subtlety.

**One role, relying on `SET LOCAL ROLE` to switch.** This was the
implementation that failed. Recorded here explicitly because it is the obvious
design, it looks correct, and it does not work.

## Lesson

This was found by a test asserting a property nobody expected to fail —
"tenant B cannot see tenant A's job steps" — rather than by review of the
migration that caused it. The isolation tests in ADR-0005 §4 were written as
routine coverage. They paid for themselves within a day.

Keep writing tests for properties that "obviously" hold. They are the only
thing that catches a defect whose entire existence is outside the code you are
reading.
