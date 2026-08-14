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

**Done and tested** (573 tests, live Postgres required):

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

**Not started:** downstream repository discovery, the runner sandbox itself,
migration generation, the dashboard. Detection has its gate, its version
semantics, and its npm collectors, but nothing yet schedules a sweep. The
credential layer is complete in logic but is not wired to a real GitHub App,
a real KMS, or the unix-socket transport.

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
3. **Change detection.** Gate, semver, ranges, npm collectors, and API surface
   diffing are done. What remains: extracting an `ApiSurface` from real
   published `.d.ts` files (use the TypeScript compiler API — a regex parser
   will silently mis-report on conditional types, re-exports, and overloads),
   and a scheduler that enqueues `detect-changes` jobs for watched packages
   on an interval. The sweep workflow itself is done.
4. **Downstream discovery.** Impact classification and prioritisation are done
   in `src/discover/affected.ts`. What remains is the crawler that produces
   `RepositoryCandidate`s from public dependency data — GitHub's dependency
   graph, registry dependents, or code search.
5. **Runner sandbox** per ADR-0006. The environment builder and egress
   allowlist exist and are tested; what remains is the isolation itself —
   gVisor or Firecracker, single-use instances, the proxy that enforces the
   allowlist. Do not ship a shared-kernel container and promise to fix it
   later.
6. **Migration generation.** `ClaudeMigrationAgent` is done (ADR-0013):
   anchored replacements against the Claude API, a blast radius fixed before
   inference, deterministic application, and a diff Driftless renders itself.
   `src/agent/unified-diff.ts` is round-tripped against real `git apply` and
   against the parser that feeds the policy engine. What remains here is the
   `Verifier` — which is blocked on the sandbox, item 5 — and a `ForgeClient`
   that actually opens the pull request. Until both exist,
   `src/main/run-worker.ts` declines to register `migrate-repository` and logs
   the remaining blockers individually.

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

`run-worker.ts` deliberately registers only `detect-changes`. Registering
`migrate-repository` without real `MigrationAgent` and `ForgeClient`
implementations would dequeue real jobs and burn their retry budget failing
for reasons unrelated to the job. Queued is recoverable;
failed-and-retried-to-death is not.

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
