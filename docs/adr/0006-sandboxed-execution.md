# ADR-0006 — Sandboxed execution of untrusted code

**Status:** Accepted · 2026-08-13

## Context

Validating a migration requires running the target repository's test suite. That
means executing arbitrary code, written by parties we have not vetted, on our
infrastructure — as a routine operation, thousands of times a day.

A repository's build scripts and tests can do anything: read the environment,
reach the network, attempt container escape, query cloud instance metadata, or
simply consume unbounded resources. In the open-source motion, an attacker can
publish a repository specifically to be processed by us.

Not running tests is not an option. An unvalidated migration is a guess, and the
product's credibility rests on PRs that actually work.

## Decision

**Untrusted code executes in single-use, kernel-isolated, network-restricted
sandboxes that hold no credentials and no durable state.**

1. **Kernel-level isolation.** gVisor or Firecracker microVMs, not shared-kernel
   containers. Docker's isolation boundary is not a security boundary against
   hostile code, and treating it as one is a well-documented mistake.

2. **One job per instance, destroyed after.** No reuse between jobs, so
   cross-job contamination is impossible rather than merely unlikely. This also
   makes the retention policy in threat-model §7 architectural: the clone is
   destroyed with the runner, so no deletion pipeline is required to honour it.

3. **Egress through an allowlisting proxy.** Only the package registries and
   hosts a build legitimately needs. Everything else is denied and logged — a
   denied egress attempt is a signal worth alerting on, since it often indicates
   either a compromised dependency or a successful injection (ADR-0003).

4. **No credentials in the environment.** Per ADR-0002, the token is held by a
   separate process outside the sandbox. Cloud instance-metadata endpoints are
   blocked, which is the standard pivot from code execution to cloud
   credentials.

5. **Runners are isolated from the control plane** at the account and network
   level. A full runner compromise must not yield control-plane access, the
   GitHub App key, or another tenant's data.

6. **Hard resource bounds** on CPU, memory, disk, process count, and wall clock,
   with unconditional termination. Resource exhaustion is the most common
   hostile behaviour and the easiest to trigger accidentally.

## Consequences

**Good.** Executing hostile code becomes a bounded, routine operation rather
than an accepted risk. The blast radius of a full sandbox compromise is one
ephemeral instance, holding one repository's code, with no credentials and no
route out.

**Costs.** Kernel-isolated sandboxes are slower to start and more expensive than
containers, and job latency is a real product concern at fan-out scale — mitigated
with warm pools, which must be built so that pooling never becomes reuse of a
*dirty* instance.

The egress allowlist will break legitimate builds that fetch from unanticipated
hosts. This needs a fast, low-friction path to review and extend the allowlist,
or it will become the thing everyone routes around.

gVisor imposes syscall-compatibility limits that some toolchains trip over.
Expect a tail of ecosystem-specific breakage.

## Reversal trigger

If per-job latency or cost becomes the binding constraint on the product and
measurement shows sandbox startup is the dominant term. Even then the answer is
faster isolation (Firecracker snapshots, pre-warmed microVMs), not weaker
isolation. Running untrusted code in shared-kernel containers is not on the
table.

## Alternatives considered

**Standard containers with a hardened profile (seccomp, AppArmor, non-root).**
Rejected as the primary boundary — a defence-in-depth measure worth having
*inside* the microVM, but the shared kernel remains a single exploitable
surface, and we are executing hostile code by design rather than by accident.

**Static analysis only; never run tests.** Rejected — eliminates the threat but
guts the product. A migration that has not been validated against the
repository's own tests is not worth opening a PR for.

**Customer-hosted runners.** Moves the execution risk to the customer, who is
better placed to accept it for their own code. Genuinely attractive and wanted by
security-conscious buyers, but it does not address the open-source cold-start
motion where there is no customer to host anything. Tracked in ADR-0008.
