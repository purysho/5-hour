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

```bash
# Create RSA 2048 key for signing
aws kms create-key \
  --description "Driftless GitHub App signing key" \
  --key-usage SIGN_VERIFY \
  --key-spec RSA_2048 \
  --origin AWS_KMS \
  --region us-east-1

# Save the ARN
export KMS_KEY_ID="arn:aws:kms:us-east-1:123456789012:key/..."
```

### Implement KMS Signer

Add AWS SDK:

```bash
pnpm add @aws-sdk/client-kms
```

Implement `src/github/signer.ts::KmsSigner.sign()`:

```typescript
async sign(data: Buffer): Promise<Buffer> {
  const response = await this.kmsClient.sign({
    KeyId: this.keyId,
    Message: data,
    SigningAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256",
  });
  return Buffer.from(response.Signature!);
}
```

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
  verification: sandbox not implemented; migrations report tests as not-run
```

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
