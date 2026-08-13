# ADR-0011 — Credentials are brokered outside the sandbox and gated by phase

**Status:** Accepted · 2026-08-13
**Implements** [ADR-0002](0002-zero-standing-privilege.md) §5

## Context

ADR-0002 §5 states that the agent never holds a token: git operations
requiring credentials are performed by a separate process outside the model's
control. That was the right principle, but it was never implemented, and
implementing it surfaced a hole in the obvious design.

The obvious design is a git credential helper that holds the scoped token and
answers git's requests, refusing anything outside its one repository. The
scope checks in `credential-helper.ts` do that well — they defeat the
submodule redirect, where a hostile `.gitmodules` causes git to request
credentials for a repository the attacker controls.

But scope checking asks *what is being requested*. It never asks *who is
asking*. And validating a migration means running the repository's own test
suite (ADR-0006) — arbitrary attacker-authored code, inside the sandbox, at a
point where the helper is available:

```sh
printf 'protocol=https\nhost=github.com\npath=acme/widgets\n' \
  | git-credential-driftless get
```

Every check passes. The protocol is https. The host matches. The path is
exactly the repository we are scoped to — because it *is* the repository we
are scoped to. The token is printed to a process the attacker controls.

This route is worse than it first appears, because the controls that look like
they should catch it do not. The egress allowlist (ADR-0006) permits git
traffic to github.com, so a push of stolen content to another repository on
the same host is fully allowed network activity. The diff policy (ADR-0003)
never runs, because no diff is involved. And nothing in the audit chain looks
unusual: a token was minted for a job that legitimately needed one.

## Decision

**The token never enters the sandbox, and the credential path is armed only
during the phases that legitimately need it.**

### Brokered, not held

The token lives in the supervisor, outside the isolation boundary. Inside the
sandbox, the credential helper is a thin client that forwards git's request
over a unix socket and copies back the answer. There is no credential material
inside the sandbox at any point, so a filesystem or memory compromise of the
sandbox yields nothing.

### Phase gating

Brokering alone is insufficient — attacker code can talk to the socket as
easily as git can. So the broker tracks the job phase and is armed only during
`clone` and `push`:

| Phase | Armed | Why |
|---|---|---|
| clone | yes | fetch needs credentials |
| analyse | no | reads a local working tree |
| test | **no** | attacker-authored code runs here |
| push | yes | one grant, then closed |

A request arriving while disarmed is **not** treated as a refusal. Nothing
legitimate asks for credentials during test execution, so it is raised as a
`CredentialAccessViolation`, logged as a security event, and fails the job.
Declining quietly would discard the most reliable compromise signal the system
has.

### Single-use grants

Each arm permits one grant by default. Code that races the push window gets at
most one token, scoped to one repository, for minutes, with no merge rights.

### Scoped invocation

Credential configuration is passed as `git -c` arguments rather than written to
`.git/config`: on-disk configuration is readable by the agent and can be
overridden by committed repository config. The argument set also clears
inherited helpers, forces `credential.useHttpPath=true`, restricts protocols to
https, and disables submodule recursion.

`useHttpPath` deserves its own note. Without it git omits the path from
credential requests, and since every GitHub repository shares one host, host
matching alone would authorise *every* repository on github.com. A request
arriving without a path is therefore refused outright rather than treated as a
host-level match.

## Consequences

**Good.** The strongest statement in ADR-0002 becomes literally true: there is
no credential inside the sandbox to steal. Attacker-authored code reaching for
the token produces a loud, attributable security event instead of a silent
success. The blast radius of a raced grant is one repository, for minutes,
without merge rights.

**Costs.** Job orchestration must now track phase correctly, and a bug there is
a security bug — an over-broad arm silently reopens the hole. `withCredentials`
exists to make the safe pattern the easy one, because a thrown error between a
manual arm and disarm would leave the window open across the test phase.

The broker is a new failure mode on the critical path: a broker that is down or
mis-phased fails the push. Failing closed is correct here, but it means
credential brokering needs the same operational attention as the database.

Legitimate git operations that need credentials outside `clone` and `push`
would break. None currently exist; if one appears, it gets a phase and an
entry in the table above, not a general relaxation.

## Reversal trigger

None foreseen for brokering. Phase boundaries may change as the pipeline
gains steps — adding a phase is a normal change; making `test` armed is not,
and would require superseding this ADR with an explicit argument for why
attacker-controlled code should be able to request credentials.

## Alternatives considered

**Helper holds the token, scope checks only.** The design this ADR rejects.
Defeats the submodule redirect but not the local invocation above, and the
failure is silent.

**Token in an environment variable for git.** Worse in every respect: readable
by every process in the sandbox, including the test suite, with no request
boundary at which to check anything.

**Push from outside the sandbox entirely** — the sandbox emits a patch, the
supervisor applies and pushes it. Genuinely stronger, and worth revisiting.
Rejected for now because the supervisor would then need the working tree to
apply against, which either duplicates the clone or moves the trust boundary
rather than removing it. Phase gating gets most of the benefit at a fraction
of the restructuring.

**Authenticate git with a short-lived SSH certificate instead.** Avoids the
credential-helper protocol, but GitHub App installation tokens are the only
mechanism that carries per-repository permission scoping, which is a stronger
property than avoiding this protocol.
