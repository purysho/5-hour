# Production Deployment Guide

This guide walks through deploying Driftless to production, from infrastructure provisioning through enabling the GitHub App to start receiving real migrations.

## Architecture Overview

Driftless has three components:

1. **HTTP Server** (`run-server.ts`)
   - Receives GitHub webhook events
   - Serves opt-out landing page
   - Stateless, can scale horizontally
   - Needs: `DATABASE_URL`, `GITHUB_WEBHOOK_SECRET`, `PUBLIC_ORIGIN`

2. **Worker(s)** (`run-worker.ts`)
   - Dequeues and executes jobs (detect-changes, plan-rollout, migrate-repository)
   - Runs detection scheduler and approval trigger
   - Can run multiple instances (they coordinate via database claims)
   - Needs: `DATABASE_URL`, `ANTHROPIC_API_KEY`, GitHub signing credentials

3. **PostgreSQL Database**
   - Shared state: repositories, changes, job queue, audit trail
   - RLS enforces multi-tenant isolation (one row per provider/customer)
   - Migrations create schema and roles

## Deploying on Railway

The rest of this guide provisions AWS directly. Railway is the shortcut, and the
one thing to get right there is that **the server and the worker are two
services, not one.** A Railway service runs a single process, and the two
components above are not interchangeable:

| Railway service | Start command | Public? | Purpose |
| --- | --- | --- | --- |
| `Driftless` | `pnpm start:server` | yes | GitHub webhooks, opt-out pages |
| `Driftless-worker` | `pnpm start:worker` | no | job queue, scheduler, approval trigger |

`pnpm start` is an alias for `start:server`, because the server is the half that
has to be publicly reachable — GitHub cannot deliver a webhook to a private
service. Railpack looks for `start` and fails the build outright when it is
absent, which is what "No start command detected" meant.

Deploying only the `Driftless` service leaves you with a system that records
installations and then does nothing with them: no sweeps, no rollouts, no
migrations. The worker is not optional, it is just not the one with a URL.

`railway.json` pins the builder, the start command, and `/health` as the
healthcheck path. Override `startCommand` on the worker service to
`pnpm start:worker`.

### Required environment variables

The server refuses to boot without all of these, by design — `loadConfig`
validates and then throws rather than starting half-configured:

| Variable | Notes |
| --- | --- |
| `DATABASE_URL` | Railway Postgres provides this; reference it as `${{Postgres.DATABASE_URL}}` |
| `GITHUB_APP_ID` | numeric, from the App settings page |
| `GITHUB_WEBHOOK_SECRET` | **at least 32 characters** |
| `PUBLIC_ORIGIN` | must be `https` when `NODE_ENV=production` |
| `GITHUB_SIGNING_KEY_ID` **or** `GITHUB_PRIVATE_KEY_FILE` | exactly one, never both (ADR-0002 §2, ADR-0012) |
| `DEFAULT_PROVIDER_SLUG` | optional; **required to onboard anyone in a single-tenant deployment** — see Enrolment |

`PORT` is injected by Railway and honoured; the default is 8080 otherwise. The
worker additionally wants `ANTHROPIC_API_KEY` — without it `migrate-repository`
stays unregistered and its jobs stay queued, which is deliberate (see the header
of `run-worker.ts`).

### Migrations

Run `pnpm db:migrate` against the production database **before** the first
deploy, and after any deploy that adds a migration. It is deliberately not wired
to `preDeployCommand`: the migrations create roles and RLS policies, and a schema
change that runs automatically on every push is one nobody reviewed. Add it there
yourself if you would rather trade that review for the convenience.

### Enrolment

Installing the GitHub App is not enough to onboard anyone, and the failure is
quiet: webhooks arrive, verify, and resolve to no tenant, so the pipeline has
nothing to act on and nothing errors. The log line is

```
webhook applied  event: push  applied: false  detail: no installation matching forge id 154772267
```

The missing fact is one GitHub never sends. A webhook says which *account*
installed the App; it cannot say which **provider** — the paying tenant, and the
RLS boundary from ADR-0005 — that installation belongs to. Guessing is not
available: a wrong guess files one customer's repositories under another, which
is the boundary migration 001 exists to defend. So the provider is named
explicitly, once:

```bash
# 1. Create the provider (needs the same connection as db:migrate — the
#    RLS policy on `provider` makes this impossible for the app role, by design)
pnpm db:provider acme "Acme Inc"

# 2. Point the deployment at it, on BOTH services
DEFAULT_PROVIDER_SLUG=acme
```

With that set, an `installation.created` webhook for an unknown installation
enrols itself: the consumer, the installation, and its repositories are written
in one transaction. Leave `DEFAULT_PROVIDER_SLUG` unset and unknown
installations stay unenrolled — the correct behaviour for a multi-tenant
deployment, where the answer has to come from a signup flow instead.

If the App was already installed before the provider existed, **reinstall it**
after setting the variable. Enrolment rides on `installation.created`, and
GitHub only sends that at install time.

### Watching a package

Enrolment gives the system repositories. It still needs something to detect.

Driftless is driven by *upstream* packages, not by pushes: the sweep scheduler
turns `watched_package` rows into `detect-changes` jobs on a clock, and
plan-rollout and migrate-repository hang off that. A push to a consumer
repository is recorded and goes no further, by design.

`watched_package` had the same gap enrolment did — nothing outside the test
suite ever inserted a row, so the scheduler swept an empty list on every tick:

```bash
pnpm db:watch react 18.2.0                  # uses DEFAULT_PROVIDER_SLUG
pnpm db:watch react 18.2.0 --interval 600   # sweep every 10 minutes
```

The baseline is the version consumers are assumed to be **on**, and every
comparison is made against it. Setting it to the latest release finds nothing —
set it to the version you are migrating *from*. The sweep never advances the
baseline itself, deliberately: a sweep that moved its own baseline would forget
the change it had just found the moment it ran again.

A new row has `last_swept_at` NULL and sorts first, so the scheduler claims it
on its next tick rather than one interval later.

`--interval` is honoured down to 60 seconds, the floor the
`watched_package_interval_sane` constraint enforces. Note that a claimed sweep
and an executed one are different events: `claim_due_sweeps` advances
`last_swept_at` as it claims, so a recent `last swept` in `pnpm db:status` says
the scheduler reached the package, not that detection ran. The `detect-changes`
count in the Jobs section is the one that says that — if `last swept` keeps
moving while that count does not, sweeps are being claimed and dropped.

### Approving a change

Detection does not open pull requests. `plan-rollout` refuses to fan out a
change until a human has set `approved_at`, because fanning out the moment
detection finds something turns one detection bug into an incident across every
repository at once (ADR-0013). Nothing ever set that column, so detected
changes sat at the gate indefinitely.

```bash
pnpm db:approve                                  # what is waiting, and why
pnpm db:approve react-19-defaultprops --by alice # approve one
```

`--by` is required: approval is recorded against whoever authorised it, because
"who decided to touch a thousand repositories" is the first question asked
afterwards. Re-approving keeps the original approver rather than relabelling it.

The approval trigger enqueues `plan-rollout` on its next tick, and one approval
earns exactly one rollout — guaranteed by a unique dedupe key, not by the
scheduler behaving.

### Watching it run

Approving a change removes it from `pnpm db:approve` — that command lists what
is *waiting*, and an approved change is not. That is correct for a to-do list
and leaves nothing to watch a rollout with, so there is a read-only view:

```bash
pnpm db:status
```

It prints the four places this pipeline stalls, in the order it runs: nothing
watched, nothing detected, nothing approved, nothing dequeued. Reading it top
to bottom is meant to identify which one without needing a query.

Two fields repay attention. `last swept never` is a different problem from a
recent sweep with no change to show for it — the first means the scheduler has
not reached the package, the second means detection ran and found nothing.
And `approved` and `rollout queued` are reported separately: the gap between
them is the approval trigger not having ticked, and collapsing them would hide
exactly that.

### Re-planning after a fix

One approval earns exactly one rollout, ever — `job_dedupe_key_idx` makes
`rollout:<change id>` unique across every job status, so the approval trigger
enqueues nothing once a rollout exists. That bounds a scheduler bug to one
fan-out, and it also means a rollout that skipped every repository for a
reason you have since fixed will not retry on its own.

```bash
pnpm db:replan react@19.2.8
```

It removes that one change's rollout job and leaves `approved_at` and
`approved_by` untouched: the person who authorised the change still authorised
it, and rewriting that to make a rollout run again falsifies the record anyone
will actually ask for. There is no bulk form, deliberately.

Note that the change key is `<package>@<to-version>` — the baseline is not part
of it. Re-running `pnpm db:watch` with a different baseline therefore updates
the existing change rather than creating a second one, and does not produce a
new rollout.

### The whole first-run sequence

```bash
pnpm db:migrate                          # schema, roles, RLS
pnpm db:provider acme "Acme Inc"         # the paying tenant
# set DEFAULT_PROVIDER_SLUG=acme on both services, then install the App
pnpm db:watch react 18.2.0               # something to detect
# wait for a sweep, then:
pnpm db:approve                          # review what was found
pnpm db:approve <change-key> --by you    # open the gate
pnpm db:status                           # watch the rollout from there
```

Skip any one of these and the system runs, logs cleanly, and does nothing.

Two things it will still not do, deliberately and visibly: without
`ANTHROPIC_API_KEY` the worker leaves `migrate-repository` unregistered and its
jobs queued rather than failing them, and every pull request it opens reports
`tests: not-run` in its body because the verification sandbox is not built
(ADR-0006). Both are stated in the worker's boot log on every start.

## Prerequisites

### AWS Account & CLI

```bash
# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Configure credentials
aws configure
```

### GitHub App Registration

Register at your GitHub account settings → Developer settings → GitHub Apps:

1. **Create new app** with:
   - **Name**: `Driftless`
   - **Homepage URL**: `https://your-domain.com`
   - **Webhook secret**: Random 32+ character string
   - **Permissions**: `contents:write`, `pull_requests:write`
   - **Subscribe to events**: `Push`, `Installation`, `Installation repositories`

2. **Generate and save** a private key

## Step 1: Set Up KMS Signing Key

GitHub App signing key must be non-exportable in AWS KMS (ADR-0002 §2):

**The key material has to come from GitHub. KMS must not generate it.**

This is the one step where the obvious command is the wrong one. `--origin
AWS_KMS` makes KMS generate its own keypair, and GitHub has never seen that
key's public half — GitHub Apps generate the keypair themselves and hand you a
`.pem`, and there is no facility to register a public key you brought. A JWT
signed with a KMS-generated key is therefore rejected, and the rejection does
not say "wrong key":

```
401 {"message":"A JSON web token could not be decoded"}
```

Which reads like a malformed token and sends you to inspect the JWT encoding,
where nothing is wrong. Every installation token mint fails, so every
repository is skipped, so a rollout targets nothing and succeeds.

So the key is created empty and GitHub's `.pem` is imported into it:

```bash
# 1. A key with NO material of its own.
aws kms create-key \
  --description "Driftless GitHub App signing key" \
  --key-usage SIGN_VERIFY \
  --key-spec RSA_2048 \
  --origin EXTERNAL \
  --region us-east-1

export KMS_KEY_ID="arn:aws:kms:us-east-1:123456789012:key/..."

# 2. A wrapping key and a single-use import token.
#
#    RSA_AES_KEY_WRAP_SHA_256, not RSAES_OAEP_SHA_256. The latter is for
#    256-bit symmetric material and cannot carry a private key: RSA-OAEP over a
#    4096-bit key holds ~446 bytes, and a PKCS#8 RSA-2048 private key is ~1.2 KB.
#    Choosing it fails at the wrap step with "data too large for key size".
aws kms get-parameters-for-import \
  --key-id "$KMS_KEY_ID" \
  --wrapping-algorithm RSA_AES_KEY_WRAP_SHA_256 \
  --wrapping-key-spec RSA_4096 \
  --region us-east-1 \
  --query '{key:PublicKey,token:ImportToken}' --output json > import-params.json

python3 -c "
import base64, json
p = json.load(open('import-params.json'))
open('wrapping.der','wb').write(base64.b64decode(p['key']))
open('token.bin','wb').write(base64.b64decode(p['token']))
"

# 3. GitHub hands out PKCS#1; KMS imports PKCS#8.
openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER \
  -in github-app.private-key.pem -out key.pkcs8.der

# 4. The hybrid wrap, which is what RSA_AES_KEY_WRAP_SHA_256 means: an
#    ephemeral AES key wraps the material under RFC 5649, RSA-OAEP wraps the
#    AES key, and the result is the RSA part followed by the AES part.
#    A65959A6 is RFC 5649's alternative IV and is fixed, not a nonce.
#
#    `od` rather than `xxd` for the hex: xxd ships with vim-common and is
#    absent from several minimal images including some CloudShell builds, where
#    it fails by producing an empty -K that OpenSSL pads to an all-zero key
#    rather than by erroring.
openssl rand -out aes-key.bin 32
HEXKEY=$(od -An -vtx1 < aes-key.bin | tr -d ' \n')

openssl enc -id-aes256-wrap-pad -K "$HEXKEY" -iv A65959A6 \
  -in key.pkcs8.der -out material-wrapped.bin

openssl pkeyutl -encrypt -in aes-key.bin -out aes-key-wrapped.bin \
  -pubin -inkey wrapping.der -keyform DER \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256

cat aes-key-wrapped.bin material-wrapped.bin > EncryptedKeyMaterial.bin

# 5. Import. EXPIRES_ON is available if you would rather it lapse.
aws kms import-key-material \
  --key-id "$KMS_KEY_ID" \
  --encrypted-key-material fileb://EncryptedKeyMaterial.bin \
  --import-token fileb://token.bin \
  --expiration-model KEY_MATERIAL_DOES_NOT_EXPIRE \
  --region us-east-1

# 6. The plaintext key has now existed on this disk. Remove it.
shred -u key.pkcs8.der aes-key.bin material-wrapped.bin aes-key-wrapped.bin \
  EncryptedKeyMaterial.bin github-app.private-key.pem \
  wrapping.der token.bin import-params.json
unset HEXKEY
```

Step 5 is not tidiness. ADR-0002 §2 wants a key that cannot be exported, and
the import unavoidably puts the plaintext key on a filesystem for the duration
— which is the whole risk this arrangement exists to end. Delete the GitHub
copy from the App settings page too, once a mint has succeeded.

Verify before deploying, rather than discovering it through skipped
repositories:

```bash
aws kms describe-key --key-id "$KMS_KEY_ID" \
  --query 'KeyMetadata.{Origin:Origin,State:KeyState}'
# Origin EXTERNAL, KeyState Enabled. PendingImport means step 5 did not take.
```

### Granting the signer access

Signing is implemented — `AwsKmsClient` in `src/github/kms-signer.ts`, reached
through `KmsSigner` when `GITHUB_SIGNING_KEY_ID` is set. `@aws-sdk/client-kms`
is already a dependency. Nothing to write; the runtime needs credentials that
can use the key:

```json
{ "Effect": "Allow", "Action": ["kms:Sign"], "Resource": "arn:aws:kms:region:account:key/key-id" }
```

Resolved through the default AWS chain — instance role on EC2, environment
variables elsewhere. `kms:Sign` alone is enough; `kms:GetPublicKey` is worth
adding only if you want to verify the imported key matches GitHub's.

Note what a credentials failure looks like, because it is *not* the 401 above:
a missing or unauthorised credential throws `KMS signing failed: …` before any
request reaches GitHub. A 401 from GitHub means signing worked and the key is
the wrong one.

## Step 2: Provision Infrastructure

### PostgreSQL Database (RDS)

```bash
aws rds create-db-instance \
  --db-instance-identifier driftless-prod \
  --db-instance-class db.t3.small \
  --engine postgres \
  --engine-version 16 \
  --allocated-storage 100 \
  --db-name driftless_prod \
  --multi-az true \
  --region us-east-1

# Wait for ready
aws rds wait db-instance-available --db-instance-identifier driftless-prod

# Get endpoint
aws rds describe-db-instances \
  --db-instance-identifier driftless-prod \
  --query 'DBInstances[0].Endpoint.Address'
```

### EC2 Instances

```bash
# Create security group
SG_ID=$(aws ec2 create-security-group \
  --group-name driftless \
  --description "Driftless" \
  --region us-east-1 | jq -r '.GroupId')

# Allow traffic
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID --protocol tcp --port 8080 --cidr 0.0.0.0/0

# Create instances
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t3.medium \
  --key-name driftless \
  --security-group-ids $SG_ID \
  --count 2 \
  --region us-east-1
```

## Step 3: Configure Environment

Create `.env` on each instance:

```bash
# Core
NODE_ENV=production

# Database
DATABASE_URL=postgresql://postgres:PASSWORD@host:5432/driftless_prod
PLATFORM_DATABASE_URL=$DATABASE_URL

# GitHub App
GITHUB_APP_ID=123456
GITHUB_WEBHOOK_SECRET=<32+ chars>
GITHUB_SIGNING_KEY_ID=arn:aws:kms:us-east-1:...

# Anthropic
ANTHROPIC_API_KEY=sk-ant-...

# HTTP
PORT=8080
PUBLIC_ORIGIN=https://driftless.your-domain.com

# Worker
WORKER_CONCURRENCY=4
WORKER_POLL_INTERVAL_MS=1000
SCHEDULER_INTERVAL_MS=60000
```

## Step 4: Deploy and Initialize Database

On instances:

```bash
# Install Node.js 22
curl -sL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs

# Clone and install
cd /opt/driftless
git clone https://github.com/purysho/YC-Hunter.git .
pnpm install --prod

# Initialize database (once)
export $(cat /etc/driftless/.env | xargs)
pnpm db:migrate
```

### Set Up Systemd Services

Server:

```bash
sudo tee /etc/systemd/system/driftless-server.service > /dev/null <<'EOF'
[Unit]
Description=Driftless HTTP Server
After=network.target

[Service]
Type=simple
User=driftless
WorkingDirectory=/opt/driftless
ExecStart=/usr/bin/node --experimental-strip-types src/main/run-server.ts
Restart=always
EnvironmentFile=/etc/driftless/.env
Environment="NODE_ENV=production"

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now driftless-server
```

Worker:

```bash
sudo tee /etc/systemd/system/driftless-worker.service > /dev/null <<'EOF'
[Unit]
Description=Driftless Worker
After=network.target

[Service]
Type=simple
User=driftless
WorkingDirectory=/opt/driftless
ExecStart=/usr/bin/node --experimental-strip-types src/main/run-worker.ts
Restart=always
EnvironmentFile=/etc/driftless/.env
Environment="NODE_ENV=production"

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now driftless-worker
```

## Step 5: Configure GitHub App Webhook

Update GitHub App settings:

1. Set **Webhook URL** to `https://driftless.your-domain.com/webhooks/github`
2. Confirm **Webhook secret** matches config

Test:

```bash
curl -X POST https://driftless.your-domain.com/webhooks/github \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Delivery: $(uuidgen)" \
  -H "X-GitHub-Event: ping" \
  -d '{"zen":"Keep it logically awesome."}'
```

## Step 6: Verify End-to-End

### Check Server Health

```bash
curl https://driftless.your-domain.com/health
```

### Check Worker Logs

```bash
ssh -i ~/.ssh/driftless.pem ubuntu@worker-ip
sudo journalctl -u driftless-worker -f
```

Should show:

```
worker starting
  workerId: ...
  workflows: ["detect-changes", "plan-rollout", "migrate-repository"]
  verification: sandbox implemented but not provisioned on this host ...
```

`migrate-repository` is absent from that list when `ANTHROPIC_API_KEY` is
unset; its jobs queue rather than fail.

### Confirm the App can authenticate

Do this before waiting on a rollout. A signing failure does not announce
itself: every repository is skipped, `plan-rollout` succeeds, and the result is
a rollout that targeted nothing and reported no error.

```bash
pnpm db:status
```

`read failed: Token mint returned 401 ... could not be decoded` against every
repository means the signing key is not the one GitHub issued — Step 1.

`pnpm preflight` does not catch this, and it is worth knowing why: its
permission check needs the App's identity, fetching that identity needs a
working JWT, and when signing fails it records the key as `not exercised here`
and skips the check rather than failing. A preflight with no `permissions:`
lines in its output has not passed that check — it has silently not run it.

### Test GitHub App

Install Driftless on a test repository. Server should record the installation webhook.

## Operations

### Kill Switch

If critical issue occurs:

```bash
psql $DATABASE_URL -c "
  UPDATE outbound_kill_switch SET halted = true
  WHERE reason = 'critical issue';
"
```

No deploy needed. Re-enable to resume.

### Audit Trail

```bash
psql $DATABASE_URL -c "
  SELECT * FROM audit_entry
  ORDER BY created_at DESC LIMIT 100;
"
```

### Job Queue Status

```bash
psql $DATABASE_URL -c "
  SELECT workflow, status, COUNT(*) as count
  FROM job
  GROUP BY workflow, status;
"
```

## Costs (Rough)

- RDS db.t3.small (Multi-AZ): $60/month
- EC2 t3.medium × 2: $60/month
- Data transfer: $10/month
- KMS: $1/month
- **Total**: ~$130/month baseline

## See Also

- `docs/HANDOFF.md` — Architecture overview
- `docs/threat-model.md` — Security model
- `docs/incident-response.md` — Operational procedures
- `src/config.ts` — Configuration requirements
