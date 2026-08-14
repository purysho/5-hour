# ADR-0012 — Interim file-backed signing key

**Status:** Accepted · 2026-08-14
**Bounds an exception to** [ADR-0002](0002-zero-standing-privilege.md) §2

## Context

ADR-0002 §2 states that the GitHub App private key lives in a KMS or HSM,
used through a signing interface, so that compromising the application yields
the ability to *request signatures* rather than the key itself. That remains
correct. It is the single most consequential control in the system: the key
mints installation tokens for every installation, so holding it is equivalent
to holding durable write access to every customer repository (threat-model A2).

It is also not achievable this week.

GitHub generates the key and hands you a `.pem` download. You cannot ask GitHub
to sign with a key you hold in a KMS — the key originates with them. So the
sequence is necessarily: receive a PEM, then move it into a KMS. Between those
two events the key exists as a file, and a solo team registering an App today
has the file and no KMS account.

That leaves three options, and it is worth being explicit that the first is
not the safe one:

1. **Block all progress until KMS is provisioned.** This is theatre. It stops
   the work without making anyone safer — the PEM already exists, sitting in a
   Downloads folder, which is strictly worse than a deliberate location with
   deliberate permissions.
2. **Put the key in an environment variable.** Genuinely dangerous, and the
   most common thing teams actually do. Environment variables leak into crash
   dumps, child process environments, `docker inspect`, platform dashboards,
   and support tickets. `loadConfig` refuses this outright.
3. **Read it from a file, with the risk bounded and written down.** Worse than
   KMS, much better than (2).

## Decision

**`FileSigner` is permitted as an interim signing path, bounded to
repositories the operator owns, with guards that make accidental production
use difficult and a stated trigger for when it must stop.**

### The bound

File-backed signing is acceptable **only while Driftless acts exclusively on
repositories the operator owns or controls.** In that posture the blast radius
of a leaked key is the operator's own repositories — a bad day, not a
supply-chain incident.

**The trigger is the first pull request to a repository we do not own.** At
that point the promise on the homepage and in every pull request body — no
standing access, credentials minted per job — depends on a key that lives in
process memory on a platform we do not control. KMS is required before that
sentence is published to anyone else.

This is not a date. It is a condition, and it is the same condition that
governs the runner sandbox in ADR-0006.

### The guards

- **Never an environment variable.** `GITHUB_PRIVATE_KEY` being set at all is
  a startup failure that tells the operator to rotate, because a key that has
  been in an environment is already exposed.
- **File permissions are checked.** Group- or world-readable refuses to start.
  A private key at mode 0644 on a shared host is a key everyone on that host
  has.
- **Production requires explicit acknowledgement.**
  `DRIFTLESS_ACCEPT_IN_PROCESS_SIGNING_KEY=yes-i-know-this-is-not-a-kms`. The
  name and value are deliberately unpleasant to type and impossible to set by
  accident — the whole risk of an escape hatch is that it quietly becomes the
  default.
- **Exactly one signing method may be configured.** Accepting both KMS and a
  file would make it ambiguous which key actually signs, and the answer would
  be decided by code order rather than by anyone's intent.
- **The key id is the path, never the contents.** It reaches logs and the
  audit chain.
- **On Windows, the permission check says it cannot check.** Node synthesises
  `stat().mode` from the read-only attribute there, so `mode & 0o077` refuses
  every key on the platform while measuring nothing about the ACL that
  actually governs access. Reading the real ACL means a subprocess in a
  security-critical constructor, parsing localised `icacls` output. So the
  guard states plainly that it cannot verify, prints the `icacls` command that
  restricts the file, and requires
  `DRIFTLESS_ACCEPT_UNVERIFIED_KEY_PERMISSIONS=windows-acl-checked-by-hand`.

  A check that cannot run should say so rather than pass quietly — and it
  should not pretend to have run, which is what a platform-blind `chmod`
  message does. The production acknowledgement is unaffected: both are
  required on Windows in production, because being unable to verify
  permissions is not a reason to stop asking about what ADR-0012 bounds.

## Consequences

**Good.** Work proceeds. The risk is bounded, guarded, and written down rather
than taken silently — which is the difference between an accepted risk and an
undiscovered one. `Signer` was already an interface, so swapping to `KmsSigner`
is a configuration change and a deploy, not a refactor.

**Costs.** The key is in process memory on a platform we do not control. A
memory disclosure bug, a compromised dependency, or a platform-level
compromise yields the key rather than the ability to request signatures. There
is no rate limiting on its use and no independent log of what it signed — both
of which KMS would provide.

Rotation is manual: generate a new key in GitHub App settings, replace the
file, delete the old key in GitHub. Worth rehearsing once before it is needed
urgently.

**The honest summary:** this is the weakest control in the system, and it is
the first thing a security reviewer should be told about rather than the last
thing they find.

## Reversal trigger

Superseded the moment KMS is provisioned — which must be **before the first
pull request to a repository we do not own**, not merely before general
availability.

When that happens: import the PEM as external key material, switch
`GITHUB_SIGNING_KEY_ID`, delete every copy of the file, and rotate the key in
GitHub App settings on the assumption that the file-era key is tainted.

## Alternatives considered

**Block until KMS exists.** Rejected as described — it stops work without
reducing risk, because the PEM already exists in a worse location.

**Environment variable.** Rejected. The failure modes are numerous, silent,
and well documented.

**A secrets manager that injects as a file** (Vault agent, AWS Secrets Manager
with a file sink, Kubernetes secret volume). Better than a bare file and
strictly worse than KMS, since the key still lands in the process. Worth
adopting if the hosting platform offers it cheaply, but it does not change the
bound above: the key is still in process memory, so the trigger stands.

**Ship without a GitHub App at all** — use a personal access token for early
testing. Rejected outright. A PAT carries the operator's full account
permissions, which is a categorical widening of the manifest that ADR-0002 §4
exists to prevent.
