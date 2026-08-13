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

**Done and tested** (105 tests, ~94% line coverage, live Postgres required):

| Area | Where |
|---|---|
| Tenancy + row-level security | `migrations/001_tenancy.sql`, `test/db/rls.test.ts` |
| Exactly-once outbound writes | `migrations/002_outbound_writes.sql`, `test/db/idempotency.test.ts` |
| Tamper-evident audit chain | `migrations/003_audit_chain.sql`, `src/audit/verify.ts` |
| Instruction/data boundary | `src/agent/untrusted.ts` |
| Diff policy engine | `src/policy/` |
| Adversarial corpus (CI gate) | `test/adversarial/corpus.test.ts` |

**Not started:** change detection and corroboration, downstream repository
discovery, the runner sandbox, migration generation, GitHub App integration,
the durable workflow engine itself, the dashboard.

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

## Next, in order

1. **Durable workflow engine.** Decide between Temporal and a Postgres-backed
   durable queue (River / pg-boss) and wire the claim/resolve protocol into it.
   ADR-0004 deliberately left this open; given a solo team, the Postgres option
   is probably right — write the ADR that closes it either way.
2. **GitHub App integration** against ADR-0002: KMS-held key, per-job token
   minting, credential helper outside the agent's reach. This is the piece
   most likely to be done wrong under time pressure.
3. **Change detection** for one ecosystem (npm first — best metadata), with the
   multi-source corroboration ADR-0004 requires.
4. **Downstream discovery** via public dependency data.
5. **Runner sandbox** per ADR-0006. Do not ship a shared-kernel container and
   promise to fix it later.
6. **Migration generation**, last — it is the part that looks like the product
   but is worthless without everything above it.

**Cheapest high-value item on the deferred list** (ADR-0008): a written
incident response plan. Hours of work, and the first thing a security reviewer
asks for.

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

The default `DATABASE_URL` in `test/global-setup.ts` points at that socket.
Schema reset happens once in global setup — never in per-file setup, or test
files racing in separate workers will drop the schema underneath each other.

## Open questions

Carried from the threat model §9 and unresolved:

1. One Driftless GitHub App, or one per provider? Per-provider limits blast
   radius and reads better to end customers, but multiplies key management.
   Leaning per-provider.
2. Can a customer-hosted runner keep the audit chain verifiable, when we no
   longer control the execution environment?
3. What is the disclosure policy when Driftless finds a genuine vulnerability
   while performing an unrelated migration? Needs writing before it happens.
