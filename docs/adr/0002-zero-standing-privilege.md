# ADR-0002 — Zero standing privilege for customer repository access

**Status:** Accepted · 2026-08-13

## Context

Driftless requires write access to repositories it does not own. This is the
hardest thing we ask of a customer and the single largest objection in any
security review.

The conventional approach — store a long-lived OAuth token or PAT per customer,
encrypt it at rest, use it when needed — creates a standing capability: at any
moment, our database contains material sufficient to write to every customer
repository. That is precisely the asset described as A1/A2 in the threat model,
and it makes the honest answer to "what happens if you are breached?" very bad.

We also cannot offer the reassurance customers actually want — *"you can't read
my code except when I ask you to"* — if we hold credentials that let us do so
at will.

## Decision

**No credential capable of accessing a customer repository is stored in a
persistently usable form. Access is minted per job and expires in minutes.**

Concretely:

1. **GitHub App, not OAuth tokens or PATs.** Access derives from an App
   installation the customer controls and can revoke instantly, without our
   cooperation.

2. **The App private key is never held by the application.** It lives in a
   managed KMS/HSM and is used through a signing interface. Application
   compromise does not yield the key; it yields the ability to request
   signatures, which is rate-limited, logged, and revocable.

3. **Installation tokens are minted per job**, scoped to the single repository
   the job targets, with the minimum permission set (`contents:write`,
   `pull_requests:write`), and a TTL on the order of minutes. They are never
   written to durable storage, never logged, and never reused across jobs.

4. **Permissions we will never request:** `administration`, workflow
   modification, merge or branch-protection bypass, organisation-level scopes.
   These are not merely unused — requesting them would destroy the guarantee in
   threat-model §2.2 that human review cannot be bypassed. The permission
   manifest is a security control and changes to it require an ADR.

5. **The agent never holds the token.** Git operations requiring credentials
   are performed by a separate process outside the model's control, via a
   credential helper. The token is not in the agent's context, environment, or
   filesystem. A successful prompt injection (threat-model §5.1) therefore has
   no credential to steal.

## Consequences

**Good.** We can truthfully tell a customer: we cannot access your repository
except during a job you triggered, we cannot merge anything, and you can revoke
us without contacting us. A breach of our database yields no repository access.
The blast radius of a compromised runner is one repository for a few minutes.

**Costs.** Token minting is on the critical path of every job, so the KMS and
GitHub's token endpoint become availability dependencies — mitigated with
circuit breakers and bounded retry, never with a cache of minted tokens.

Long-running jobs may outlive their token. Jobs are therefore designed to be
short and resumable; a job needing more time re-mints rather than requesting a
longer TTL.

Debugging is harder, deliberately. We cannot reproduce a customer issue by
reaching into their repository; we work from the retained diff and audit trail.
Treated as a design constraint on observability, not a reason to relax the
model.

## Reversal trigger

If GitHub removes or materially changes fine-grained installation tokens, or if
we expand to a forge whose auth model cannot express per-repository short-lived
credentials. In that case the answer is a customer-hosted runner (ADR-0008),
not stored long-lived credentials.

## Alternatives considered

**Encrypted long-lived tokens with strict access controls.** Rejected — reduces
the probability of compromise but not the blast radius, and does not support the
customer-facing guarantee, which is the commercially important part.

**Customer-hosted runners from day one.** Correct end state for the most
security-conscious buyers, rejected as a starting point on complexity grounds.
Tracked in ADR-0008.

**Per-repository OAuth from an end-user account.** Rejected — ties access to an
individual's account, inherits their full permissions (violating least
privilege), and breaks when they leave the company.
