# Handoff — context for future sessions

Written to be pasted, or read first, at the start of a new session. It assumes
no memory of previous ones.

---

## What this is

Driftless detects breaking changes in upstream APIs and opens the fixing PR in
downstream codebases. Provider ships a breaking change → we detect it → find
affected repositories → generate and validate a fix → open a pull request.

It is a YC application project (RFS #13, "Self-Maintaining APIs"), built by a
solo founder working with AI tooling, with no network and no capital. Two
consequences shape every decision:

1. **Traction must be manufacturable without permission.** The cold-start
   motion is opening PRs against public repositories affected by real breaking
   changes in the AI SDK ecosystem (OpenAI, Anthropic, LangChain, LlamaIndex,
   vector DB clients) — the highest-churn corner of software. Merged PRs are
   the metric. They also create the network the founder doesn't have.
2. **Security architecture is the sales motion.** Nobody grants write access
   to their codebase to a vendor who can't explain their isolation model. Time
   spent on the controls is not overhead; it is customer-facing collateral.

Read `docs/threat-model.md` before changing anything. The governing insight is
in §2: Driftless ingests untrusted content, executes untrusted code, holds
write credentials to many third-party repos, and authors code at scale — which
makes a compromised Driftless an efficient supply-chain attack. That fact
orders every control.

## Where things stand

**Done and tested** (1127 tests, live Postgres required):

| Area | Where |
|---|---|
| Tenancy + row-level security | `migrations/001_tenancy.sql`, `test/db/rls.test.ts` |
| Exactly-once outbound writes | `migrations/002_outbound_writes.sql`, `test/db/idempotency.test.ts` |
| Tamper-evident audit chain | `migrations/003_audit_chain.sql`, `src/audit/verify.ts` |
| Instruction/data boundary | `src/agent/untrusted.ts` |
| Diff policy engine | `src/policy/` |
| Adversarial corpus (CI gate) | `test/adversarial/corpus.test.ts` |
| Durable job execution | `migrations/004_jobs.sql`, `src/workflow/`, `test/db/jobs.test.ts` |
| Outbound write guard | `src/outbound/guard.ts`, `test/db/outbound-guard.test.ts` |
| GitHub App credentials | `src/github/`, `test/github/` |
| Credential broker + git helper | `src/github/credential-{helper,broker}.ts` |
| Sandbox environment + egress | `src/sandbox/environment.ts`, `test/sandbox/` |
| End-to-end migration workflow | `src/workflows/migrate-repository.ts`, `test/workflows/` |
| Fan-out planning (canary) | `src/workflows/plan-rollout.ts`, `test/workflows/plan-rollout.test.ts` |
| Opening the pull request | `src/forge/github-forge.ts`, `test/forge/github-forge.test.ts` |
| Reading a downstream repository | `src/forge/github-contents.ts`, `test/forge/github-contents.test.ts` |
| Audit sink for token mints | `src/audit/sink.ts`, `test/audit/sink.test.ts` |
| Production dependency wiring | `src/main/wiring.ts`, `test/main/wiring.test.ts` |
| Approval → rollout trigger | `src/schedule/approval-trigger.ts`, `migrations/010_approved_changes.sql` |
| Test verification architecture | `src/sandbox/gvisor-verifier.ts`, `docs/SANDBOX_SETUP.md` |
| Change corroboration + canary sizing | `src/detect/corroborate.ts`, `test/detect/` |
| Semver precedence + breaking detection | `src/detect/semver.ts` |
| npm registry + artifact collectors | `src/detect/npm.ts` |
| Range satisfaction + impact classification | `src/detect/range.ts`, `src/discover/affected.ts` |
| API surface diffing (third hard source) | `src/detect/api-surface.ts` |
| Blast radius derivation | `src/policy/blast-radius.ts` |
| Pull request composition | `src/forge/pull-request.ts` |
| Detection sweep workflow | `src/workflows/detect-changes.ts` |
| Suppression / opt-out | `migrations/005_suppression.sql`, `src/outbound/suppression.ts` |
| Opt-out endpoint | `src/http/opt-out.ts`, `test/http/` |
| Webhook ingestion + apply | `src/http/webhook.ts`, `src/http/webhook-apply.ts` |
| Config validation | `src/config.ts` |
| HTTP server + worker lifecycle | `src/main/` |
| Runnable entry points | `src/main/run-server.ts`, `src/main/run-worker.ts` |
| Public homepage | `src/http/landing.ts` (served at `/`) |
| File-backed signer (interim) | `src/github/signer.ts`, ADR-0012 |
| Subscriptions + tenant provisioning | `migrations/012_billing.sql`, `test/db/billing.test.ts` |
| Entitlement at the outbound write | `src/billing/entitlement.ts`, `test/db/entitlement-enforcement.test.ts` |
| Stripe boundary (no SDK) | `src/billing/stripe.ts`, `test/billing/stripe.test.ts` |
| Checkout, pricing, welcome | `src/http/pricing.ts` |
| Stripe webhook → tenant | `src/http/billing-webhook.ts`, `test/http/billing-webhook.test.ts` |
| Plan repository limits | `src/billing/limits.ts`, `test/db/repository-limit.test.ts` |

**Not started:** the customer dashboard.

**Billing, in one paragraph.** A customer pays at `/pricing`, Stripe posts to
`/webhooks/stripe`, and `provision_subscription` creates the tenant and its
subscription in one idempotent call. The application role still cannot create a
tenant — provisioning runs as `driftless_billing`, a third login role that can
create tenants and read nothing, because Postgres ORs together the policies of
every role you hold (non-negotiable 10 applies to all three roles now, and
`pnpm preflight` checks it). Entitlement is read on every outbound write, fails
closed, and consumes no idempotency claim, so a lapsed customer who pays finds
the outstanding work still doable.

The pipeline is now connected end to end: an installation webhook records
repositories, the scheduler sweeps watched packages, a human sets
`approved_at`, the approval trigger enqueues `plan-rollout`, and that enqueues
one `migrate-repository` job per canary target. What each stage does *not* do
is as load-bearing as what it does — see the file headers, particularly
`plan-rollout.ts` on why the canary is small and `wiring.ts` on why nothing is
defaulted to make a job runnable.

The credential layer is complete in logic and now wired to a real GitHub App in
`run-worker.ts`. `AwsKmsClient` (`src/github/kms-signer.ts`) implements the real
KMS path, so `GITHUB_SIGNING_KIND=kms` signs through a non-exportable key per
ADR-0002 §2; the file-backed signer under ADR-0012 remains for local
development. Not yet wired: the unix-socket transport.

The KMS signer takes an optional pre-built client so its failure paths are
testable without live AWS. That was not cosmetic — signing was previously wired
straight to a `KMSClient`, and with the branches unreachable a real bug sat
there unnoticed: the `if (!response.Signature)` throw was inside the `try` that
wraps transport errors, so "KMS did not return a signature" came back to the
caller as `KMS signing failed: KMS did not return a signature`, describing a
network failure that had not happened. Fixed, with a regression test.

**P3: Test verification sandbox.** Not done, and the earlier claim here that it
was scaffolded and awaiting deployment was wrong in a way worth recording.
`GVisorVerifier` is wired into `ClaudeMigrationAgent` and reports `not-run`,
which is honest — but it does not invoke gVisor, and installing `runsc` would
not change that.

The blocker is the interface, not the host. `Verifier.verify` receives
`{ repository, diff, changedPaths }`; running a suite needs a checkout with the
diff applied and dependencies installed, and no caller has one — the workflow
operates on content fetched through the forge API, never a working tree. So the
next step is a workspace abstraction in `migrate-repository`, and only then the
host provisioning in `docs/SANDBOX_SETUP.md`.

What is implemented and tested is the part that does not need a workspace:
`detectTestCommand` (parses a `package.json`, and rejects the `npm init`
placeholder so a repository with no suite is not reported as one whose tests
broke) and `isSandboxAvailable` (probes PATH for `runsc`, so a worker without it
says so per migration). Outcomes once unblocked are `passed`, `failed`, or
`no-suite` — the shared `TestOutcome` type has no `error` member.

One remaining honest gap: `downstreamCount` is the tenant's installed
repository count rather than the number of repositories that declare the
package, because nothing stores the latter; it is an upper bound, used only
where an upper bound is safe.

## Non-negotiables

Breaking one of these is a security regression, not a refactor. Each has a test
that should fail if it is violated; if you find yourself editing the test to
make a change pass, stop.

1. **Repository content never reaches the instruction channel.** No
   concatenation of untrusted text into a prompt, at any layer. Use
   `assemblePrompt`. `UntrustedContent.toString()` throws on purpose — do not
   "fix" it.
2. **The idempotency index stays unique and non-partial.** Making it partial
   (to "cleanly retry failed writes") reintroduces duplicate PRs: a write that
   failed to *report* success may still have succeeded remotely.
3. **RLS enabled and forced, with `WITH CHECK`, on every table carrying
   `provider_id`.** A test enumerates this; a new table without it fails CI.
4. **No long-lived customer credentials, ever.** Tokens are minted per job,
   scoped to one repository, minutes-long TTL, never persisted, never in the
   agent's context or environment.
5. **The permission manifest never widens** beyond `contents:write` and
   `pull_requests:write`. Merge rights or workflow permissions would destroy
   the guarantee that human review cannot be bypassed. Changing it requires an
   ADR.
6. **The audit log is append-only.** Corrections are new compensating entries.
   Never an UPDATE.
7. **Driftless opens pull requests. It never merges them.**
8. **The opt-out endpoint never changes state on GET.** GitHub, Slack, mail
   providers and security scanners fetch links automatically to build previews.
   A state-changing GET fires when nobody clicked — including when GitHub
   renders our own pull request body — and the result is indistinguishable
   from a real opt-out, so we would silently stop contacting repositories that
   never asked. GET renders, POST acts.
9. **Suppression is checked before every outbound write, and fails closed.**
   Every pull request body promises "one click, no account, and we will not
   open another pull request here". `OutboundRequest.target` is required
   rather than optional precisely so a caller cannot forget it — a bypass here
   has no visible symptom until a maintainer complains in public. A suppressed
   target must also consume no idempotency claim, or lifting the opt-out later
   would find the work already claimed and silently skip it.
10. **No login role holds both `driftless_app` and `driftless_admin`.** Postgres
   ORs together every policy for every role you are a member of, so combining
   them silently grants cross-tenant visibility with no error and nothing to
   see in review. See ADR-0010 — this was found by a test, not by reading the
   code.
11. **The broker is never armed during `test` or `analyse`.** Repository test
   code is attacker-authored and can issue a perfectly in-scope credential
   request — every scope check passes, because none of them asks who is
   asking. Only phase gating stops it. Use `withCredentials`, never a manual
   arm/disarm pair that a thrown error can escape. See ADR-0011.
12. **Neither a credential nor repository content may be a step result.** Step
   results are persisted for replay, so a token there is standing privilege in
   the database and repository content there breaks the "process, never store"
   promise — and comes back as a plain string with its untrusted marking gone.
   Acquire both inside the step that consumes them. Both types throw or redact
   on serialisation, so violating this fails loudly.
13. **The model proposes; Driftless applies.** The model returns anchored
   replacements, never a patch, and never a path it was not shown. Driftless
   applies them and renders the diff itself, so the artifact the policy engine
   reads is the artifact that was applied. Do not add a `create`, `delete`,
   `rename`, or `mode` field to the proposal — their absence is the control.
   See ADR-0013.
14. **The blast radius is computed before inference and is not negotiable
   afterwards.** It comes from the impacted symbols in our own change record,
   never from the agent's output. An agent that supplied its own bound would
   be judged against a limit it chose.
15. **Model prose never reaches a maintainer.** `composePullRequest` takes
   structured facts only. The proposal's one free-text field is for our logs,
   and the injection signal carries paths rather than a description of what
   the model saw — a description is a copy of the payload.
16. **Verification is reported honestly.** Until the sandbox exists the agent
   says `not-run`, and the pull request body says so too. A migration
   presented as verified when it is not destroys the only thing that makes
   these pull requests worth opening.
17. **Nothing published is fetched or parsed with a filesystem behind it.**
   The compiler host in `dts-surface.ts` is backed by a map; the tarball
   reader never writes. Both are attacker-authored input processed inside the
   control plane, and the safety comes from the absence of the capability
   rather than from checks around it. Adding `fs` to either file is a design
   change, not a refactor.
18. **Entitlement is checked before the idempotency claim, never after.** A
   refused tenant must consume no claim. Consuming one means that when they
   pay, the work is already marked done and is never performed — a silent
   failure indistinguishable from the product not working. The same reasoning
   as suppression, and the same position in `authoriseOutboundWrite`.
19. **The application role cannot write to `subscription`.** It holds SELECT
   and nothing else. If it could write, entitlement would be advisory: any
   path that reaches a tenant connection could grant itself a plan. Tested by
   attempting both an INSERT and an UPDATE as the app login role.
20. **A tarball URL is checked against an allowlist before it is fetched.**
   `dist.tarball` is chosen by the registry, so an unchecked fetch is
   server-side request forgery with our network position behind it.

## Next, in order

1. ~~Durable workflow engine.~~ Done — ADR-0009 chose Postgres-backed durable
   execution; `src/workflow/` implements leased dequeue and step memoisation.
2. **GitHub App integration.** Credential layer done — `src/github/` mints
   per-job, single-repository tokens through an injected signer, caps TTL
   locally, verifies the granted permissions against the manifest, and redacts
   on every implicit conversion. The credential helper and phase-gated broker
   are done (ADR-0011). Still to do: a real KMS signer, the unix-socket
   transport between sandbox client and supervisor broker. Webhook ingestion
   is done — signature verification, replay claims, and the apply path that
   makes revocation take effect.
3. **Change detection.** Done end to end. Gate, semver, ranges, and npm
   collectors; API surface diffing; surface *extraction* via the TypeScript
   compiler (`src/detect/dts-surface.ts`) over a host backed by a map rather
   than a filesystem; the tarball reader (`src/detect/tarball.ts`), which
   decodes entirely in memory; and the scheduler — `watched_package` plus
   `claim_due_sweeps` (migration 007) put the claim in the database, so every
   worker can run one without duplicating sweeps.

   Two properties to preserve. Neither the compiler host nor the tarball
   reader touches `fs`: the moment one of them writes a file or reads one,
   symlink attacks, path traversal, and `/// <reference path>` file reads stop
   being *inapplicable* and start needing real defences. And nothing is swept
   until a row exists in `watched_package` — an empty table is a silent
   no-op, which is the correct default but is worth knowing when detection
   appears to be doing nothing.

4. **Downstream discovery.** Impact classification and prioritisation are done
   in `src/discover/affected.ts`, and manifest and lockfile reading is done in
   `src/discover/manifest.ts`. What remains is the crawler that produces
   `RepositoryCandidate`s from public dependency data — GitHub's dependency
   graph, registry dependents, or code search.

   The lockfile reader is a targeted extractor rather than a parser, and the
   reason it is allowed to be is worth keeping straight: it contributes only
   `lockedVersion`, which sharpens a verdict `assessRepository` already reaches
   from the declared range. It returns null on any ambiguity. That trade does
   *not* transfer to `dts-surface.ts`, where an approximation would decide
   whether a change is breaking.

5. **Runner sandbox** per ADR-0006. Still open. `GVisorVerifier` is wired in and
   reports `not-run` truthfully, but nothing executes and gVisor is never
   invoked. Three things are needed, in this order:

   1. A **workspace** — something that materialises a checkout, applies the
      diff, installs dependencies, and hands over a path. This is the real
      blocker: `Verifier.verify` takes a diff and a path list, so verification
      is not expressible through the current interface no matter how the host
      is provisioned. It is a change to `migrate-repository`, not to
      `src/sandbox/`.
   2. `runsc` and a rootfs on the worker host — `docs/SANDBOX_SETUP.md`.
      `isSandboxAvailable()` already probes for it.
   3. An egress-proxied network namespace enforcing `DEFAULT_EGRESS_ALLOWLIST`
      from `src/sandbox/environment.ts`.

   Note that `buildSandboxEnvironment`/`assertNoSecrets` in
   `src/sandbox/environment.ts` are complete and thoroughly tested, but are
   currently referenced *only by tests* — no production path builds a runner
   environment yet, because no production path starts a runner. They are ready
   for step 1 to use; they are not evidence that step 1 is done.
6. **Migration generation.** `ClaudeMigrationAgent` is done (ADR-0013):
   anchored replacements against the Claude API, a blast radius fixed before
   inference, deterministic application, and a diff Driftless renders itself.
   `src/agent/unified-diff.ts` is round-tripped against real `git apply` and
   against the parser that feeds the policy engine. What remains here is the
   `Verifier`, which is blocked on the sandbox, item 5. The `ForgeClient` now
   exists (`src/forge/github-forge.ts`): it writes file *contents* through the
   Git Data API rather than applying a diff, never force-updates a branch, and
   preserves file modes — each for a reason its header explains.

   `migrate-repository` is registered whenever `ANTHROPIC_API_KEY` is present.
   Running without a sandbox is not a stub: verification reports `not-run`,
   truthfully, everywhere it is reported. Running without a model would be, so
   that case stays unregistered.

**Deploying:** `docs/DEPLOYMENT.md`, start to finish.

**If something breaks:** `docs/incident-response.md`. The one thing to
remember is that halting outbound writes is a single UPDATE against
`outbound_kill_switch`, needs no deploy, and consumes no idempotency claims —
so halting early costs nothing and is always the right first move.

## Running it

```bash
scripts/dev-postgres.sh          # sandbox/laptop Postgres
pnpm db:migrate
pnpm start:server                # opt-out page + webhook receiver
pnpm start:worker                # job runner
```

Configuration is validated at startup and the process refuses to boot on any
problem — including `GITHUB_PRIVATE_KEY` being set at all, which means the
signing key has been exposed to the environment and needs rotating.

`run-worker.ts` registers `detect-changes`, `plan-rollout`, and —
when `ANTHROPIC_API_KEY` is set — `migrate-repository`. It also starts two
clocks: the sweep scheduler and the approval trigger. Both are safe to run in
every worker, by different mechanisms: the scheduler claims in the database,
the trigger relies on a job dedupe key that is unique across every status.

The registration rule has not changed, only what satisfies it. A workflow
whose collaborators do not exist is not registered, because dequeuing a real
job to fail it for reasons unrelated to the job burns its retry budget.
Queued is recoverable; failed-and-retried-to-death is not.

**Source must stay strip-mode compatible.** The project runs under
`node --experimental-strip-types`, which erases types but does not transform
code. No TypeScript parameter properties (`constructor(private readonly x: T)`),
no enums, no namespaces, no decorators. Vitest transpiles, so the test suite
will not catch a violation — only actually running a process will.

## Conventions

- Decisions before code. Anything expensive to reverse, or that a reasonable
  engineer would ask "why is it like this?" about, gets an ADR with a stated
  reversal trigger and rejected alternatives.
- Feature branches, PR into `main`. Never push to `main` directly.
- Comments explain *why*, especially where the non-obvious choice is
  deliberate. Do not narrate what the code already says.
- Tests must be capable of failing. A test asserting behaviour the code cannot
  violate is worse than no test, because it reads as coverage.
- Forward-only migrations. Rollback of a destructive migration is a restore,
  not a script.

## Environment notes

Tests need a live Postgres 16 — RLS and the idempotency invariant are database
behaviour, and mocking them would test the mock.

In a sandbox without a running server, Postgres binaries usually exist but
cannot run as root:

```bash
mkdir -p /tmp/pgdata /tmp/pgrun && chown -R postgres:postgres /tmp/pgdata /tmp/pgrun
chmod 700 /tmp/pgdata
su postgres -c "/usr/lib/postgresql/16/bin/initdb -D /tmp/pgdata -U postgres --auth=trust"
su postgres -c "/usr/lib/postgresql/16/bin/pg_ctl -D /tmp/pgdata -l /tmp/pgdata/server.log -o '-p 5433 -k /tmp/pgrun' start"
su postgres -c "/usr/lib/postgresql/16/bin/createdb -h /tmp/pgrun -p 5433 driftless_test"
```

Or just run `scripts/dev-postgres.sh`, which does all of the above and is safe
to re-run. Sandboxes tend to reap the server between sessions.

The default `DATABASE_URL` in `test/global-setup.ts` points at that socket.
Schema reset happens once in global setup — never in per-file setup, or test
files racing in separate workers will drop the schema underneath each other.

Global setup creates two login roles, `driftless_app_login` and
`driftless_worker_login`. Do not collapse them into one — see non-negotiable 10
and ADR-0010.

## Open questions

Carried from the threat model §9 and unresolved:

1. One Driftless GitHub App, or one per provider? Per-provider limits blast
   radius and reads better to end customers, but multiplies key management.
   Leaning per-provider.
2. Can a customer-hosted runner keep the audit chain verifiable, when we no
   longer control the execution environment?
3. What is the disclosure policy when Driftless finds a genuine vulnerability
   while performing an unrelated migration? Needs writing before it happens.
