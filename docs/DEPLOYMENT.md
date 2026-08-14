# Deployment

Everything needed to get Driftless running, in the order it actually has to
happen. Written for a solo operator with no prior deployment.

---

## 1. Register the GitHub App

**Settings → Developer settings → GitHub Apps → New GitHub App.**

| Field | Value |
|---|---|
| Name | Anything unique on GitHub |
| Homepage URL | Your `PUBLIC_ORIGIN` once deployed. Before then, your GitHub profile — it is editable at any time |
| Webhook → Active | Leave **off** until you have a public URL |
| Webhook URL (later) | `https://<your-origin>/webhooks/github` |
| Webhook secret | `openssl rand -hex 32` |

Then `pnpm preflight` — it will tell you if the key and the App ID disagree,
which is the failure that is otherwise invisible until the first pull request.

**Repository permissions — these two and nothing else:**

- Contents: **Read and write**
- Pull requests: **Read and write**

This is the manifest in ADR-0002 §4. Merge rights or workflow permissions
would destroy the guarantee that human review cannot be bypassed, so widening
this requires an ADR, not a settings change.

**Subscribe to events:** *Pull request* only. Installation events arrive
automatically.

**Where can this be installed:** *Only on this account* until you are ready to
open pull requests on repositories you do not own.

After creating it, note the **App ID** (6–7 digits, near the top). Then
**Generate a private key** — GitHub downloads a `.pem`.

### The `.pem` is the crown jewel

It mints installation tokens for every installation. Holding it is equivalent
to holding durable write access to every repository the App is installed on
(threat-model A2).

```bash
mkdir -p ~/.driftless && chmod 700 ~/.driftless
mv ~/Downloads/<app>.<date>.private-key.pem ~/.driftless/github-app.pem
chmod 600 ~/.driftless/github-app.pem
```

- **Never commit it.** `.gitignore` blocks `*.pem`; do not test that.
- **Never put it in an environment variable.** `loadConfig` refuses to start
  if `GITHUB_PRIVATE_KEY` is set, because a key that has been in an
  environment is already exposed.
- **Never paste it into a chat, an issue, or a support ticket.**

### Install it

**Install App** in the sidebar → your account → **Only select repositories** →
one throwaway test repository. Not this one.

---

## 2. Signing key: the interim position

The destination is KMS (ADR-0002 §2). The interim is a file (ADR-0012), and
the boundary between them is not a date:

> File-backed signing is acceptable **only while acting on repositories you
> own**. KMS is required **before the first pull request to a repository you do
> not own** — that is when the promises on the homepage start applying to
> someone else.

`FileSigner` enforces what it can: it refuses a group- or world-readable file,
refuses a file that is not a private key, and refuses production entirely
unless you set

```
DRIFTLESS_ACCEPT_IN_PROCESS_SIGNING_KEY=yes-i-know-this-is-not-a-kms
```

which is deliberately awkward so it cannot become the default by accident.

### Moving to KMS later

1. AWS KMS → Create key → **Asymmetric**, *Sign and verify*, `RSA_2048`,
   origin **External**.
2. Import the PEM as key material.
3. Set `GITHUB_SIGNING_KEY_ID` to the key ARN, unset
   `GITHUB_PRIVATE_KEY_FILE`.
4. Delete every copy of the file, then **rotate the key in GitHub App
   settings** — treat the file-era key as tainted.
5. Grant the deploy role `kms:Sign` and nothing else.

---

## 3. Railway

Railway connects to **private** repositories through its GitHub integration —
nothing needs to be made public.

**One Postgres, two services from the same repo:**

| Service | Start command |
|---|---|
| `driftless-server` | `pnpm start:server` |
| `driftless-worker` | `pnpm start:worker` |

Run migrations once before either starts: `pnpm db:migrate`.

### Two database roles

The schema defines `driftless_app` (tenant-scoped, RLS applies) and
`driftless_admin` (platform, for dequeue and the minimal-disclosure lookups).
ADR-0010 is emphatic that **no login role may hold both** — Postgres
ORs together the policies of every role you belong to, so combining them
silently grants cross-tenant visibility with no error and nothing to see in
review.

```sql
CREATE ROLE driftless_app_login   LOGIN PASSWORD '...' INHERIT NOBYPASSRLS;
CREATE ROLE driftless_worker_login LOGIN PASSWORD '...' INHERIT NOBYPASSRLS;
GRANT driftless_app    TO driftless_app_login;
GRANT driftless_admin  TO driftless_worker_login;
```

`DATABASE_URL` uses the first; `PLATFORM_DATABASE_URL` uses the second.

### The key file on Railway

Railway injects secrets as environment variables, which is exactly what the
config rejects. Options, best first:

1. **KMS**, and the problem disappears.
2. A **secret file mount**, if the platform offers one.
3. Write the file at boot from a base64 secret, in the start command, to a
   path with mode 600. Least good — the key passes through an environment
   variable to get there, so treat it as tainted and rotate when you move to
   KMS.

---

## 4. Environment

```bash
NODE_ENV=production
DATABASE_URL=postgresql://driftless_app_login:...@host/driftless
PLATFORM_DATABASE_URL=postgresql://driftless_worker_login:...@host/driftless
GITHUB_APP_ID=1234567
GITHUB_WEBHOOK_SECRET=<openssl rand -hex 32>
PUBLIC_ORIGIN=https://your-app.up.railway.app

# Exactly one of these two:
GITHUB_SIGNING_KEY_ID=arn:aws:kms:...       # preferred
GITHUB_PRIVATE_KEY_FILE=/etc/driftless/github-app.pem
DRIFTLESS_ACCEPT_IN_PROCESS_SIGNING_KEY=yes-i-know-this-is-not-a-kms

# Required only on a worker that generates migrations (ADR-0013).
# Without it the worker runs detect-changes and declines to register
# migrate-repository, saying so in its startup log.
ANTHROPIC_API_KEY=sk-ant-...

# Optional
PORT=8080
WORKER_CONCURRENCY=4
SHUTDOWN_GRACE_MS=30000
SCHEDULER_INTERVAL_MS=60000
```

The scheduler runs inside every worker and is safe to duplicate: the claim
happens in the database, so N workers produce one sweep per package per
interval rather than N. `SCHEDULER_INTERVAL_MS` is how often it *looks* for due
packages, not how often a package is swept — that is per-package, in
`watched_package.sweep_interval_seconds`.

Nothing is swept until a package is watched:

```sql
INSERT INTO watched_package (provider_id, ecosystem, package_name, baseline_version)
VALUES ('<provider-uuid>', 'npm', 'acme-sdk', '1.4.2');
```

Configuration is validated completely at startup and **every** problem is
reported at once, so a misconfigured deploy fails immediately and legibly
rather than on the first request under load.

---

## 5. Verify

Before anything else:

```bash
pnpm preflight
```

It is read-only — it mints nothing and opens nothing — and it checks the
things configuration cannot:

- **the private key actually belongs to this App.** An App ID and a `.pem`
  from different Apps produce a JWT GitHub rejects, and without this the first
  place you find out is inside a job, behind a retry
- **the permission manifest is still `contents:write` + `pull_requests:write`
  and holds none of the forbidden permissions.** Widening it is a settings
  change on a web page — ten seconds, no diff, no review — so this is the only
  automated check that a box has not been ticked
- **the two database roles are separate**, neither is a superuser, and neither
  has `BYPASSRLS`
- **the migrations are applied**

Then the endpoints:

```bash
curl https://<origin>/                # 200, the homepage
curl https://<origin>/health          # {"status":"ok"}
curl -X POST https://<origin>/webhooks/github -d '{}'   # 400, unsigned
```

Then turn on webhooks in the App settings, pointed at
`https://<origin>/webhooks/github`, and uninstall/reinstall the App on your
test repository. The worker log should show the installation event applied.

The worker deliberately registers only `detect-changes`. `MigrationAgent` now
has a production implementation (`ClaudeMigrationAgent`), but `ForgeClient`
does not and neither does the sandbox that test verification needs, so
`migrate-repository` stays unregistered — registering it with stubs would
dequeue real jobs and burn their retry budget failing for reasons unrelated to
the job. Queued is recoverable; failed-and-retried-to-death is not.

The startup log lists the remaining blockers individually, so you can see which
ones you have cleared.

---

## 6. Before the first external pull request

Not optional, and not a checklist to skim:

- [ ] **KMS**, per ADR-0012's trigger
- [ ] **Runner isolation** — gVisor or Firecracker (ADR-0006). Do not ship a
      shared-kernel container and plan to fix it later; that is executing
      attacker-authored test suites beside the control plane
- [ ] **Opt-out links live** — every pull request body promises one, and a
      promise printed on a trusted artifact and not kept is worse than no
      promise
- [ ] **Kill switch rehearsed** — `UPDATE outbound_kill_switch SET halted =
      true;`. Know it works before you need it at 3am
- [ ] **`docs/incident-response.md` read once**, while calm

---

## Rollback

Services are stateless; roll back by redeploying the previous image.
Migrations are forward-only — a rollback of a destructive migration is a
restore from PITR, not a script. Nothing in migrations 001–006 is destructive.
