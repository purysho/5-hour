# ADR-0003 — Repository content is data, never instruction

**Status:** Accepted · 2026-08-13

## Context

Driftless reads repositories it does not own and cannot vet. In the open-source
cold-start motion, it reads repositories belonging to *anyone*. Every byte of
that content — code, comments, docstrings, README files, test fixtures, commit
messages, issue titles — is authored by a party who may be hostile and who
knows an agent will read it.

This is threat-model §5.1, and it is the primary threat to the system. The
attack requires no credentials, no access, and no sophistication: an attacker
commits a comment to a public repository and waits.

The failure mode is severe because a successful injection does not merely leak
data. It can direct the agent to write attacker-chosen code into a pull request
that a human is predisposed to approve, converting our distribution into a
supply-chain attack (threat-model §2).

Compounding this: the industry-standard practice of concatenating retrieved
content into a prompt makes the attack trivial, and a large fraction of
agent-based tooling shipping today is vulnerable to it.

## Decision

**Repository content is treated as untrusted data at every layer. It is never
permitted to act as instruction, and the system is designed so that a
successful injection has nothing worth stealing and nowhere to send it.**

Four independent layers, no one of which is trusted to be sufficient:

### 1. Channel separation

Instructions come from Driftless-authored templates only. Repository content is
passed in explicitly delimited data channels, marked as untrusted, with a
standing directive that content within them is material to be analysed and
never directions to follow. Content is never interpolated into the instruction
channel — no string concatenation of repository text into a system or task
prompt, at any layer, ever. This is enforced by type at the boundary: the
prompt-assembly API accepts untrusted content only as a distinct wrapped type
that cannot be passed where instructions are expected.

### 2. Constrained capability

The agent operates against a fixed, enumerated tool surface: read files within
the workspace, propose a patch, run the declared test command. There is no
general shell, no arbitrary network access, no dynamic tool acquisition, and no
ability to initiate work outside the current job's single repository. An
injected instruction that says "run this command" addresses a capability that
does not exist.

### 3. Output policy enforcement

The generated diff is validated before any PR is opened, by deterministic code
rather than by a model:

- **Blast radius.** Files touched must fall within the set predicted from the
  upstream change. Edits to unrelated files are rejected.
- **Categorical rejections.** New network destinations, new dependencies,
  changes to CI/workflow configuration, changes to lockfile provenance, and
  newly introduced code that reads credentials or environment secrets are
  rejected or escalated to human review. These are the shapes a supply-chain
  payload takes.
- **Scale.** Diffs exceeding size thresholds for their migration class are
  escalated rather than opened.

### 4. Nothing to steal, nowhere to send it

Per ADR-0002, no credential exists in the agent's context or environment. Per
ADR-0006, sandbox egress is allowlisted. An injection that successfully
generates an exfiltration payload finds no secret and no route out.

### Verification

A corpus of adversarial repositories is maintained in-tree, covering token
exfiltration, scope expansion, unrelated-file modification, CI tampering, and
instruction-shaped content in every plausible location (comments, README,
fixtures, commit messages, filenames). **Every case must fail to influence the
agent, and this is a blocking CI gate.** New attack shapes are added to the
corpus as they are discovered, and a discovered bypass requires a new case
before the fix is merged.

## Consequences

**Good.** The primary threat is addressed in depth rather than by a single
fragile mitigation. The adversarial corpus is directly demonstrable — being able
to show an attack failing is worth more in a security review, and in an investor
meeting, than any written assurance. It also produces a genuine differentiator:
most agent tooling shipping today cannot make this demonstration.

**Costs.** Channel separation constrains prompt engineering and rules out some
convenient patterns. Output policy will produce false positives, and a
migration escalated for review when it did not need to be is a real cost to the
value proposition — the thresholds need tuning against a corpus of legitimate
migrations, and the tuning is never finished.

The layered design means an injection bypass is a severity-one incident even
when no harm results, because it indicates the depth assumption has failed.

## Reversal trigger

None foreseen. This decision is closer to a founding constraint than a
preference; abandoning it would change what the company is. Individual
mechanisms may be replaced by stronger ones — the principle that repository
content never acts as instruction is not up for revision.

## Alternatives considered

**Model-based injection detection (a classifier screening input).** Rejected as
a *primary* control — it is probabilistic, and the adversary iterates against it
freely. Retained as an optional additional signal, never load-bearing.

**Sanitising or stripping instruction-like content on ingest.** Rejected —
unbounded problem, trivially evaded by paraphrase and encoding, and destructive
to legitimate content. Also produces false confidence, which is worse than no
control.

**Human review of every diff before it is opened.** This is the correct control
at current volume and is what we will do initially. Rejected as the *long-term*
primary defence because it does not scale to the fan-out the product requires,
and because reviewer attention degrades sharply on repetitive diffs — exactly
the condition an attacker relies on.
