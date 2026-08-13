# ADR-0001 — Record architecture decisions

**Status:** Accepted · 2026-08-13

## Context

Driftless is being built by a very small team under time pressure, and it is
being built in a domain where the *reasoning* behind a decision is part of the
deliverable. Prospective customers are granting write access to their source
repositories; their security reviewers will ask why the system is built the way
it is. A codebase can demonstrate what was built. It cannot demonstrate what was
considered and rejected, or under what conditions a choice should be revisited.

There is a second, more selfish reason. A solo developer moving fast will
forget their own reasoning within weeks. Undocumented decisions get silently
reversed by later work, usually at the worst possible moment.

## Decision

Every architecturally significant decision is recorded as a numbered ADR in
`docs/adr/`, following the lightweight format popularised by Michael Nygard.

A decision is architecturally significant if it is expensive to reverse, if it
constrains later decisions, if it involves a security or privacy tradeoff, or
if a reasonable engineer would ask "why is it like this?"

Rules:

- ADRs are immutable once accepted. A changed decision is a *new* ADR that
  supersedes the old one; the old one is marked `Superseded by ADR-XXXX` and
  left in place. History is the point.
- Every ADR states what would make us change our mind. A decision without a
  reversal trigger is an assumption in disguise.
- Deliberate omissions are recorded too. "We are not doing X yet, and here is
  what would change that" is a decision, and the most commonly lost one.

## Consequences

Writing these costs real time that could go to shipping. Accepted, for two
reasons: the security-relevant subset doubles as customer-facing collateral, so
the time is not purely overhead; and at this stage the documents are cheaper
than the code they will prevent us from writing twice.

The risk is ADRs drifting out of step with the implementation. Mitigation: an
ADR describes a *decision*, not an implementation. Decisions change rarely.
When code contradicts an accepted ADR, that is a bug in one of them and is
treated as such.

## Alternatives considered

**A single design document.** Rejected — a living document loses the history,
which is exactly the part with the value here.

**Decisions in commit messages and PR descriptions.** Rejected — not
discoverable months later, and not something a security reviewer can be handed.

**Nothing, until there is a team to communicate with.** Rejected — the audience
is not only future colleagues. It is customer security reviews, investor
diligence, and this author in six weeks.
