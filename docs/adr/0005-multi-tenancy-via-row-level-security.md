# ADR-0005 — Multi-tenancy enforced by Postgres row-level security

**Status:** Accepted · 2026-08-13

## Context

Driftless has an unusual two-level tenancy structure. The paying tenant is an
API **provider**. Beneath each provider sit the **consumers** whose repositories
we act on — and a consumer may appear under more than one provider, since a
codebase can depend on several APIs we cover.

Providers are frequently direct competitors. Knowing which companies consume a
competitor's API, and which versions they are stranded on, is commercially
sensitive information that we will hold for all of them simultaneously. A
cross-tenant leak here is not an embarrassment; it is the end of the business.

The default approach — a `tenant_id` column and a `WHERE tenant_id = ?` clause
in application code — fails open. One forgotten predicate on one query, in one
endpoint, at 2am, leaks across the boundary silently. It cannot be verified by
inspection at any scale, and it is exactly the mistake a tired solo developer
makes.

## Decision

**Tenant isolation is enforced by the database through row-level security, so
that a missing application-layer check fails closed rather than open.**

1. **RLS enabled and forced on every tenant-scoped table.** No table holding
   tenant data is exempt. The application's database role has no `BYPASSRLS`.

2. **Tenant context is set per transaction** from a server-derived session
   identity — never from a client-supplied parameter (threat-model §5.3). A
   query issued without tenant context returns zero rows rather than all rows.

3. **The two-level structure is modelled explicitly.** Provider tenancy is the
   RLS boundary. Consumer records are scoped beneath a provider, and the same
   underlying repository appearing under two providers produces two distinct
   scoped records with no shared row.

4. **Isolation is tested, not assumed.** The integration suite includes
   cross-tenant probes: for every tenant-scoped table, an attempt to read and to
   write another tenant's row under a legitimate session must return empty or
   error. A new tenant-scoped table without a corresponding probe fails CI.

5. **Migrations are covered.** A migration adding a table without RLS fails the
   build. This is where the discipline realistically decays, so it is automated.

6. **Privileged paths are narrow and audited.** Some operations legitimately
   span tenants (platform administration, aggregate billing). These use a
   separate role, are confined to an explicit module, and every use is written
   to the audit log (ADR-0007).

## Consequences

**Good.** The catastrophic failure mode requires defeating a database policy
rather than forgetting a `WHERE` clause. The guarantee is stated in one place
and is inspectable — a security reviewer can be shown the policies and the
cross-tenant probes, which is a far better answer than "we're careful".

**Costs.** RLS carries a query-planning cost, and policies interact badly with
some ORM patterns and with connection pooling — tenant context must be set
correctly per transaction, and a pooler handing out a connection with stale
context is a real hazard that needs explicit handling.

Local development is more awkward, since queries fail closed when context is
missing. Accepted: that is the control working.

## Reversal trigger

If a customer requires physical rather than logical isolation — a separate
database or deployment — RLS becomes insufficient on its own. That is an
addition rather than a reversal: the policies stay, and a dedicated instance is
layered on top for that customer.

## Alternatives considered

**Application-layer scoping only.** Rejected — fails open, and cannot be
verified by inspection. This is the industry default and it is the reason
cross-tenant leaks are common.

**Schema-per-tenant.** Stronger isolation, rejected on operational grounds:
migrations across many schemas become painful quickly, and it does not model the
consumer level cleanly.

**Database-per-tenant from the start.** Rejected as premature — the operational
cost is real and immediate, the benefit is speculative until a customer demands
it. Available later per ADR-0008.
