# ADR-0007 — Tamper-evident audit log

**Status:** Accepted · 2026-08-13

## Context

Driftless writes code into repositories it does not own. The customer's
reasonable question is not only "what did you do?" but "how do I know that's
what you did?"

An ordinary application log cannot answer the second question. It is written by
us, stored by us, and mutable by us. A customer relying on it is trusting our
word, and an attacker who compromises our infrastructure (threat-model §5.4) can
edit it to conceal their actions. Under the residual-risk position taken in that
section — we cannot make control-plane compromise impossible — the ability to
*conceal* is what turns a bad incident into an unbounded one.

There is a commercial dimension too. "Trust us with write access to your
codebase" is the hardest sentence in our sales motion. Being able to follow it
with "and here is how you verify, without trusting us, everything we have ever
done in your repositories" is the strongest available answer.

## Decision

**Every action taken against a customer repository is recorded in an
append-only, hash-chained audit log that the customer can verify independently.**

1. **Hash chaining.** Each entry includes the hash of its predecessor, so any
   modification or deletion of a historical entry invalidates every subsequent
   hash. Tampering becomes detectable rather than merely discouraged.

2. **Write-ahead.** Sensitive actions — minting a token, pushing a commit,
   opening a PR, a cross-tenant administrative access — are logged *before* they
   are performed, with the outcome recorded after. An action absent from the log
   but visible in the repository is itself evidence of compromise.

3. **Periodic signed checkpoints**, published where we cannot silently rewrite
   them and retrievable by customers. A checkpoint commits to the entire history
   up to that point, so an attacker cannot rewrite history without invalidating
   a checkpoint the customer already holds.

4. **Customer-facing verification.** Customers can export their tenant's slice
   of the chain and verify it — that entries are well-formed, that the chain is
   unbroken, that it matches published checkpoints, and that the actions
   recorded match what is visible in their repository. Verification must not
   require trusting any Driftless-controlled service at verification time.

5. **Append-only in the storage layer**, not merely by convention. The
   application role holds insert rights and no update or delete rights on audit
   tables.

6. **Log the sensitive metadata, never the sensitive content.** Which repository,
   which commit, which files, which permissions, which token identifier and
   TTL — never token values, never repository file contents. The log is a
   high-value read target and must not become an exfiltration route.

## Consequences

**Good.** Undetectable tampering requires defeating the chain *and* the
published checkpoints *and* the customer's independently held copies. The log
becomes evidence rather than testimony. This directly serves the residual-risk
position in threat-model §5.4, and it converts an audit-and-compliance chore
into a differentiated trust feature — one that shortens security reviews rather
than lengthening them.

**Costs.** Chaining serialises audit writes, which constrains throughput. This
needs care under fan-out: likely per-tenant chains rather than one global chain,
which weakens cross-tenant ordering guarantees but is an acceptable trade.

Append-only means mistakes are permanent. A correction is a new compensating
entry, never an edit. Which means care about what enters the log in the first
place — particularly anything that could later require deletion under a privacy
request. Deletion obligations are satisfied by keeping personal data out of the
chain, not by rewriting it.

Verification tooling is real work that no customer will ask for until the deal
is nearly closed, at which point it must already exist.

## Reversal trigger

None foreseen for the chaining itself. The checkpoint publication mechanism may
change as scale or customer requirements dictate. If no customer ever exercises
verification, the *tooling* may be deprioritised — but the chain stays, since
its value under §5.4 is independent of whether anyone checks it.

## Alternatives considered

**Standard structured logging to a managed provider.** Necessary for operations
and we will have it, but rejected for this purpose: mutable by us, therefore
worthless as evidence in the scenario it is needed for.

**Write-once cloud storage (object lock / immutable buckets).** Genuinely useful
and complementary, but immutability is enforced by a provider whose
configuration we control. Weaker than a chain the customer can verify
themselves.

**Full transparency-log infrastructure (Merkle tree with inclusion proofs, à la
Certificate Transparency).** The rigorous end state and the right direction of
travel. Rejected as a starting point on complexity grounds — a hash chain with
signed checkpoints delivers most of the assurance for a fraction of the work,
and can be upgraded to a proper Merkle structure without changing the customer
promise.
