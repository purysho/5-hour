# Red team — attacking my own work

Astra froze. I own both roles now, which is worth stating plainly because it
is a weakness in this document rather than a feature of it: **an agent
reviewing its own work in the same context converges rather than diverges.**
I said so when reviewing the original prompt, and it is still true here.

So this audit is deliberately biased toward things that can be *executed*
rather than judged. Execution does not share my priors. Every finding below
was produced by running the system, not by re-reading it approvingly — and the
two most serious ones were invisible to a test suite that was, at the time,
1172 tests and entirely green.

---

## The headline

**The product could take money and then deliver nothing, and every test
passed.** I built checkout, provisioning, entitlement and plan limits — and
never once started the server. When I finally did, a paying customer installed
the GitHub App and the log said:

```
installation 987654321 for smoketest-customer is not enrolled
and no default provider is configured (DEFAULT_PROVIDER_SLUG)
```

Zero installations. Paid, connected to nothing, permanently.

This is the exact failure I warned about when reviewing the prompt that started
this project: impressive machinery, missing the unglamorous join between two
halves. I then built the impressive machinery and missed the join.

---

## Findings

### F1 — Paying customers could never be connected · CRITICAL · fixed

A customer paid, a tenant was created, they installed the App, and the
installation resolved to no tenant and was dropped.

The alternative configuration was worse. With `DEFAULT_PROVIDER_SLUG` set,
*every* installation from *every* customer enrolled into the one configured
tenant — filing one customer's repositories under another, which is precisely
the boundary ADR-0005 exists to defend. Both states were live: one delivered
nothing, the other leaked across tenants.

The cause is structural, not a slip. GitHub's `installation.created` webhook
says which *account* installed the App and cannot say which paying tenant that
account belongs to, because GitHub has never heard of our tenants. Nothing in
the system ever saw both facts.

**Fixed** (migration 013): a reference minted at checkout travels to Stripe as
`client_reference_id`, comes back on `checkout.session.completed`, and travels
through the App install as `state`. GitHub returns it to a new `/setup`
callback — the only request in which both the installation and the paying
tenant are knowable. Stored hashed, because it rides in a URL and anyone
holding one could bind their own installation to someone else's paid tenant.
Single-use. An unknown reference is refused rather than defaulted, because the
default *is* the cross-tenant bug.

Proven end to end against a running server: pay → tenant, install → parked,
setup → connected with both repositories, replayed reference → 400.

### F2 — Billed, never provisioned, permanently · HIGH · fixed

The Stripe webhook claimed an event id before provisioning. If provisioning
then failed — database briefly unreachable, connection exhausted, deploy
mid-flight — the claim survived the failure. Stripe retries, the retry is
recognised as a duplicate, and we answer **200 OK**. The customer has paid, no
tenant exists, and Stripe has been told the delivery succeeded. Forever.

Worse than the bug: **I wrote a test that asserted this ordering and praised
it**, on the reasoning that claiming first prevents a duplicate tenant. But the
claim was never the idempotency guarantee — `provision_subscription` is an
upsert keyed on the tenant, so provisioning twice converges harmlessly. I
traded a harmless duplicate for a permanent revenue loss and then wrote
documentation congratulating myself for it.

**Fixed**: a failed delivery releases its claim and rethrows, so the server
answers 5xx and Stripe's retry can still do the work. The test that praised the
bug is gone.

### F3 — Parking failed on every call · HIGH · fixed

Found only by running the server: `permission denied for table
pending_installation`. The grant was `SELECT, INSERT, DELETE`; the writer
upserts. Postgres checks the `UPDATE` privilege for `ON CONFLICT DO UPDATE` at
plan time whether or not a conflict occurs, so every call failed.

The consequence was silent and expensive: the install webhook 500'd, the
customer's repository selection — the only copy we are ever sent — was lost,
and the setup callback then connected them with **zero repositories**. Which is
the exact failure parking was written to prevent.

A plain `INSERT` as the same role succeeded, which is why a naive test would
have passed. **Fixed**, with a test that issues the real statement twice, as
the real login role, so the conflict branch itself is exercised.

### F4 — Attacker-authored content reaching operator logs · MEDIUM · fixed

`parseManifest` builds its JSON failure message from V8's parser error, and V8
echoes about sixteen bytes of the input:

```
Unexpected token 'S', "{"a": SENTINEL_L"... is not valid JSON
```

The crawler forwarded that message into `discovery.repository_skipped`, so a
stranger's `package.json` reached an operator's terminal and log aggregator —
violating the rule Astra specified and the codebase's own "reasons, never
contents".

**Fixed**: a closed vocabulary (`too-large`, `not-json`, `not-an-object`,
`too-many-dependencies`, `rejected`, `unknown`). Every branch returns a
constant, including the unrecognised one — a fallback to the error text would
reintroduce the leak on the one path nobody tests.

### F5 — A test that could not fail · MEDIUM (meta) · fixed

My test "does not log the manifest contents" used one malformed body and
asserted a sentinel was absent. It passed and proved nothing: V8 emits two
different parse errors, and my fixture happened to land in the form that
reports only a position. The test could not have failed for the case it claimed
to cover.

**Fixed**: three payloads that actually produce the quoting form, plus a test
that asserts the payloads *would* leak if the message were forwarded — so if
V8 ever stops quoting input, the fixtures announce themselves as vacuous
instead of rotting into coverage that asserts nothing.

This is the finding I would most expect a self-review to miss, and the reason
the audit was run by execution rather than by reading.

---

## Open, and not fixed

Stated because leaving them undocumented would be the same failure as F1.

### O1 — `/checkout` is unauthenticated and calls a paid third-party API

Anyone can POST a valid plan and make us create a Stripe Checkout Session.
There is no rate limit. The cost is bounded by Stripe's own API limits, not by
anything we control, and the endpoint is the one place an anonymous caller can
make us spend money. The plan is validated before any network call, which
bounds the *garbage* case but not the valid-plan case.

### O2 — Stripe signature verification has never met Stripe

It is verified against HMACs this codebase generates. If my reading of Stripe's
signing scheme is wrong, both sides are wrong identically and the tests agree
with each other. This can only be closed against a real endpoint in test mode.
The same applies to the code-search crawler, which has never spoken to GitHub.

### O3 — Slug collision would merge two tenants

A new subscription resolves its tenant by slug, and slugs derive from the email
local part plus eight characters of the Stripe customer id. A collision would
make the second customer adopt the first customer's tenant and repositories.
The probability is negligible; the consequence is a cross-tenant merge, which
is the most serious class of failure this architecture recognises. Probability
times severity is not obviously small enough to leave alone.

### O4 — `checkout.session.completed` infers `active`

Status is inferred from `payment_status: paid` and corrected by the next
subscription event. The window is small and self-correcting, and it can only be
wrong in favour of someone who has just paid — but it is an inference sitting
in the entitlement path.

### O5 — Repository limits fail open when no subscription is visible

Deliberate: the outbound guard already refuses unentitled tenants, and blocking
enrolment would cost a paying customer their repositories over a race. The
residual is that an unentitled tenant can enrol unlimited repositories and
consume storage. Bounded, and cheaper than the alternative.

### O6 — Still unbuilt

No customer dashboard, so nothing shows a customer the value that justifies
renewal. The gVisor sandbox remains unbuilt, so migrations are honestly
reported as `tests: not-run` — which is the single largest obstacle to anyone
merging a pull request we open, and therefore to the product being worth
paying for at all.

---

## Process failures worth recording

- **I shipped `/pricing` before verifying anyone could be connected.** Tests
  passing is not the same as the product working, and I treated it as such for
  three commits.
- **A commit message contained backticks inside a double-quoted shell string**,
  so command substitution ate part of it and I force-pushed a correction.
- **I killed my own shell twice** with `pkill -f` patterns that matched the
  command line containing them.

## What I would do next, in order

1. O6 — the sandbox. Unverified migrations are the reason a maintainer closes
   the pull request, and everything else here is upstream of a product nobody
   merges.
2. O1 — bound the cost of the one endpoint that spends money anonymously.
3. O2 — one real Stripe test-mode transaction, which retires the largest
   remaining untested assumption in the revenue path.
