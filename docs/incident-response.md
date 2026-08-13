# Incident Response

Status: living document. Last revised 2026-08-13.

Promoted off the deferred list in [ADR-0008](adr/0008-deferred-concerns.md).
Written before it is needed, because the one thing you cannot do during an
incident is calmly decide what your policy should be.

Currently a solo team. Everything below assumes one person, possibly at 3am,
possibly the person who caused the incident.

---

## First, the only thing you must remember

**Halt outbound writes. Then think.**

```sql
UPDATE outbound_kill_switch
   SET halted = true, reason = 'brief description', halted_by = 'your name';
```

No deploy, no restart, effective immediately. It stops every pull request
across every tenant.

Halting is cheap and reversible; a wrong pull request in a customer's
repository is neither. If you are unsure whether an incident warrants it, it
does. Nobody has ever regretted halting for twenty minutes.

Resuming is the same statement with `halted = false`. Jobs blocked while
halted consumed no idempotency claim (ADR-0004), so they resume rather than
being silently skipped.

## Severities

| | Definition | Response |
|---|---|---|
| **SEV1** | Customer repositories affected, or credentials possibly exposed, or cross-tenant disclosure | Halt immediately. Notify affected customers within 24h. |
| **SEV2** | Wrong behaviour contained to our systems; no customer-visible effect yet | Halt if it could become SEV1. Fix before resuming. |
| **SEV3** | Degraded but correct — backlog, retries, slow jobs | No halt. Fix in normal hours. |

When torn between two levels, take the higher one. Downgrading later is free.

## Playbooks

### Duplicate or unwanted pull requests

Most probable serious incident in the system (threat-model §5.6).

1. Halt.
2. Scope it: `SELECT installation_id, count(*) FROM outbound_write WHERE claimed_at > now() - interval '2 hours' GROUP BY 1 ORDER BY 2 DESC;`
3. Close the pull requests. Do **not** delete the `outbound_write` rows —
   they are what stops the next run repeating the mistake. If a genuine
   re-run is needed, it needs a new `base_sha`, which means a new row.
4. Tell the affected customer before they find it. This is a trust incident,
   not a technical one, and the response is judged on speed and candour.
5. Only then find the cause.

### Suspected credential exposure

1. Halt.
2. Rotate the GitHub App private key in the KMS. Installation tokens live
   minutes (ADR-0002), so the App key is the asset that matters.
3. Check the audit chain for mints you cannot account for:
   `SELECT * FROM audit_export('<provider-id>');` — every mint is written
   before the token exists, so an unexplained mint is real and a *missing*
   one is worse.
4. If the App key may have leaked, assume every token minted under it is
   compromised and notify all customers. Do not scope this down to make the
   notification smaller.

### Cross-tenant disclosure

Treat as SEV1 unconditionally. Providers are frequently competitors
(ADR-0005).

1. Halt.
2. Identify the boundary that failed: RLS policy, role membership
   (ADR-0010 — this has already happened once, in development), or an
   application path that bypassed `withTenant`.
3. Determine what was actually read, not what could have been. The audit
   chain and Postgres logs are the evidence.
4. Notify both parties. Both, not just the one who was exposed.

### Prompt injection bypass

A bypass is SEV1 **even if nothing reached a repository**, because it means
the layering assumption in ADR-0003 has failed.

1. Halt.
2. Add the case to `test/adversarial/corpus.test.ts` **before** fixing it.
   The corpus is the regression suite; a fix without a case will be undone.
3. Identify which layer failed and why the layers below it did not catch it.
4. Assume more instances of the same shape exist. Search for them.

### Runaway job or retry storm

Usually SEV3, but check whether it is producing outbound writes first.

1. Ceilings should have contained it. If they did not, that is the bug.
2. `UPDATE job SET status = 'cancelled', finished_at = now() WHERE workflow = '<name>' AND status IN ('pending','failed');`
3. Check `attempts` — repeated reclaim means workers are dying mid-job, which
   is a different incident wearing this one's clothes.

## Communication

Say what happened, what you did, and what you changed. Say it before the
customer notices.

Do not minimise, do not use passive voice about your own errors, and do not
promise a root cause before you have one — "we are still investigating, next
update in two hours" is a complete and acceptable message.

For a company whose entire premise is that customers trust it with write
access to their code, the disclosure is the product. A well-handled incident
is better evidence of trustworthiness than never having one.

## After

Within a week, write down: timeline, what failed, what caught it (or why
nothing did), and what changes. If the fix is a control rather than a patch,
it gets an ADR.

The bar is not "this will never happen again". It is "this specific failure
now has a test, and we know which class of failure it belongs to".

## Deliberately not here

- Formal on-call rotation, escalation tree, status page — meaningless for a
  team of one. Trigger: second engineer.
- Regulator notification timelines — no regulated data is processed by
  design (threat-model §7). Trigger: any change to that premise.
