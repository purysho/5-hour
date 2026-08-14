# ADR-0013 — Model output is a proposal, applied deterministically

**Status:** Accepted · 2026-08-14
**Extends** [ADR-0003](0003-untrusted-repository-content.md)

## Context

ADR-0003 established the first three layers of the injection defence: content
never enters the instruction channel, the runtime holds no credential and no
egress route, and every diff passes a deterministic policy. It left one
question open, because there was no generator yet to ask it of: **what shape
does the model's output take?**

The default answer is a patch. Ask for a unified diff, apply it with
`git apply`, run the policy over the text. It is what most tools in this space
do, and it has three problems that only become visible once you write down the
threat model.

**The artifact the policy reads is not provably the artifact that lands.**
`git apply --3way` relocates hunks whose line numbers are wrong. Some appliers
tolerate a hunk header that misstates its own length; some do not. Every one of
those behaviours is a gap between "what the policy engine parsed" and "what
ended up in the branch", and a gap like that is precisely what an injection
aims at. The policy engine can be perfectly correct about a diff that is not
the diff that was applied.

**Diff syntax is a capability.** A patch can create files, delete files,
change modes, and rename paths. A migration needs none of those. Handing the
model a format that expresses them means the controls have to *take them back
away*, and a control that subtracts capability is weaker than one that never
granted it.

**Line numbers are a thing the model has to count.** They are the most common
source of malformed model-authored patches, and every retry is another
inference spent on a repository whose content we already know is hostile.

There is a second, subtler problem, in a different place. The workflow passed
`PolicyContext.blastRadius` straight through from the agent's return value —
so the rule that stops an injection steering the agent into an unrelated file
was being enforced against a bound the agent itself supplied. The rule was
sound; its input was not. `blast-radius.ts` even states the required property
in its own header — "file inclusion is never derived from anything the agent
produced" — and the wiring contradicted it.

## Decision

**The model returns a proposal. Driftless applies it, and Driftless renders
the diff.**

### 1. The proposal is anchored replacements

`{ path, find, replace }`, applied in order. No creation, no deletion, no mode
change, no rename — those capabilities are absent from the format rather than
forbidden by a rule.

`find` must be an exact substring occurring **exactly once** in the current
content. Not a line number, which must be counted; not a regular expression,
which is a program the model would be writing. Zero matches is a mistake and
two matches is an ambiguity, and both are refused rather than resolved —
"first match wins" is a rule whose failure mode is a plausible-looking wrong
edit, which is the worst outcome available here.

### 2. The model may only edit files it was shown

An edit naming an unsupplied path is refused at application time. This is what
makes `…and also update .github/workflows/release.yml` inert rather than
merely rejected three stages later: there is no path from that sentence to a
file handle.

### 3. The blast radius is fixed before inference

`deriveBlastRadius` runs on the sources and the impacted symbols from our own
change record, before the model is called. It determines which files are shown
*and* which may be written, and the agent returns that set — not the set of
files it touched. `MigrationAgent.generate` now takes `impactedSymbols`
explicitly so the workflow supplies the bound from the change record, closing
the loop described above.

### 4. Driftless renders the diff

From the before/after pair, with its own generator (`unified-diff.ts`, the
inverse of the parser that feeds the policy). The diff is therefore a
*description of a transformation already performed*, which makes the policy
engine's reading of it authoritative by construction.

### 5. Structured output is a convenience, not a control

The schema constrains the model, but that constraint is enforced across a
network boundary by a service we do not run. `parseEditPlan` re-checks the
whole shape locally, where the consequences of it being wrong are ours.

### 6. No tools, no second turn

The model gets one request and returns JSON. A tool would be a capability an
injection could reach; a second turn would let repository content influence
what we ask next.

### 7. Prose from the model never reaches a maintainer

The proposal carries one free-text field, and it is for our logs. Pull request
bodies are composed from structured facts only (`forge/pull-request.ts`) —
a body assembled from model prose would carry an injection to the one place in
the pipeline where persuasion still works.

The same applies to the injection signal. The model reports *paths* where it
saw text addressed to it, never a description of that text — a description is
a paraphrased copy of the payload, and it would land in our logs, our alerts,
and eventually on a screen with our credibility attached.

### 8. Verification is reported honestly

The sandbox that would make running a repository's test suite safe is not
built (ADR-0006), so the agent reports `not-run`. It does not imply otherwise.
A migration presented as verified when it is not destroys the only thing that
makes these pull requests worth opening.

## Consequences

**Good.** The failure modes shrink to one shape: a refused proposal, which
costs an inference and nothing else. What a successfully-injected model gets
to do is bounded to *proposing a replacement inside a file we already chose*,
which a deterministic policy then reads. Prompt injection stops being a
question of whether the model can be tricked — it can — and becomes a question
about the size of the resulting capability.

**Costs.** Anchored replacement cannot express a migration that must add a new
file, delete one, or rename one. Those exist; they are rarer than the
alternative's failure modes, and the answer for now is that such a migration is
not attempted rather than attempted unsafely. When one is genuinely needed it
gets an ADR and its own bounded capability, not a widening of this format.

Diff rendering is code we own, so its bugs are ours. It is covered by
round-trip tests against the parser that feeds the policy engine, which is the
pairing that matters: a diff we render and the policy cannot read is a bug we
find in CI rather than in production.

**The injection signal is not a control.** A model persuaded not to migrate is
equally persuaded not to mention it. It is triage information and is treated
as such — the controls that do the work run whether it fires or not.

## Reversal trigger

If migrations that must add or remove files become a material share of the
work, this format is insufficient. The replacement is a *narrower* extension —
an explicit `create` operation with its own path validation and its own policy
rule — not a return to model-authored patches.

## Alternatives considered

**Model-authored unified diffs.** Rejected for the three reasons above. The
decisive one is the gap between what the policy engine parses and what git
applies.

**Whole-file rewrites.** The model returns the complete new content of each
file. Simple, and it removes the anchor-matching failure mode entirely — but
it makes every diff a full-file diff, which destroys reviewability, and it
gives an injection the entire file as its canvas instead of one anchored
region. Rejected.

**Line-range edits.** `{ path, startLine, endLine, replacement }`. Removes the
ambiguity problem but reintroduces counting, and an off-by-one silently edits
the wrong code rather than failing. Rejected: the anchor's failure mode is a
refusal, and the line range's is a wrong edit.

**A second model to review the first.** Rejected on the same grounds ADR-0003
rejects it for the diff policy: an attacker who can influence one can
influence both, and it converts a deterministic control into a probabilistic
one.
