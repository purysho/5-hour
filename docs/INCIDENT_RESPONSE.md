# Incident Response Procedures

Driftless handles sensitive operations (writing code to customer repositories, holding write credentials). When something goes wrong, the response must be fast and correct.

## Golden Rule: Kill Switch First

On ANY critical incident (generating bad code, credential leak, security breach):

```bash
psql $DATABASE_URL -c "
  UPDATE outbound_kill_switch SET halted = true
  WHERE reason = 'incident reason';
"
```

**This halts ALL outbound writes immediately.** It:

- Consumes NO idempotency claims (jobs stay queued, resumable later)
- Requires no deploy or service restart
- Takes <1 second
- Is immediately visible in logs and dashboards

Re-enable only after the issue is resolved and verified:

```bash
psql $DATABASE_URL -c "
  UPDATE outbound_kill_switch SET halted = false
  WHERE reason = 'incident reason';
"
```

## Incident Classifications

### P1: Security Breach (Credential Leak)

**If GitHub App key or Anthropic API key is exposed:**

1. **Kill switch**: Halt outbound writes
2. **Rotate keys**: GitHub App and/or Anthropic API immediately
3. **Audit**: Check `audit_entry` for unauthorized token mints
4. **Notify**: Tell affected customers their repositories were accessed
5. **Investigate**: Review logs for what was compromised

```bash
# Check for unauthorized token mints
psql $DATABASE_URL -c "
  SELECT * FROM audit_entry
  WHERE event = 'token_mint' AND created_at > NOW() - INTERVAL '24 hours'
  ORDER BY created_at DESC;
"

# Check for unauthorized outbound writes
psql $DATABASE_URL -c "
  SELECT * FROM outbound_result
  WHERE created_at > NOW() - INTERVAL '24 hours' AND status != 'suppressed'
  ORDER BY created_at DESC;
"
```

### P2: Bad Migration Generation

**If Driftless starts generating malicious or incorrect code:**

1. **Kill switch**: Halt outbound writes (unmerged PRs are safe)
2. **Identify**: Which migrations were affected
3. **Audit**: Check PRs opened in last N hours
4. **Notify**: Find and notify repositories that received PRs
5. **Investigate**: Debug the agent or policy engine

```bash
# Find recently opened PRs
psql $DATABASE_URL -c "
  SELECT pr_number, owner, name, change_id, status, created_at
  FROM outbound_result
  WHERE status = 'succeeded' AND created_at > NOW() - INTERVAL '1 hour'
  ORDER BY created_at DESC;
"

# Manually check a PR for issues
# (Visit GitHub directly, inspect the diff)
```

**Steps to re-enable:**

1. Deploy a fix to the agent or policy engine
2. Verify the fix on a staging environment
3. Deploy to production
4. Resume outbound writes via kill switch

### P3: Database Issues

**If database is unreachable or corrupted:**

1. **Kill switch**: Halt outbound writes (jobs stay queued)
2. **Investigate**: Check database connectivity and disk space
3. **Restore**: Restore from backup if needed
4. **Resume**: Repair database, then re-enable outbound writes

```bash
# Check database status
psql $DATABASE_URL -c "\d"  # List tables

# Check disk space on RDS
aws rds describe-db-instances \
  --db-instance-identifier driftless-prod \
  --query 'DBInstances[0].AllocatedStorage'

# Restore from backup
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier driftless-restore \
  --db-snapshot-identifier <snapshot-id>
```

### P4: Worker Crash Loop

**If workers are crashing and restarting continuously:**

1. **Check logs**: What error is repeating?

```bash
ssh ubuntu@worker-ip
sudo journalctl -u driftless-worker -f --no-pager | tail -100
```

2. **Kill switch**: Halt outbound writes
3. **Stop workers**: Prevent retry storms

```bash
ssh ubuntu@worker-ip
sudo systemctl stop driftless-worker
```

4. **Fix**: Deploy code fix or configuration change
5. **Resume**: Restart workers and verify recovery

### P5: GitHub Rate Limiting

**If hitting GitHub API rate limits:**

1. **Reduce worker concurrency**: Slow down job dequeue
2. **Check**: Are migrations requesting too much API data?
3. **Optimize**: Reduce per-job API calls or add exponential backoff

```bash
# Check job queue depth
psql $DATABASE_URL -c "
  SELECT COUNT(*) FROM job WHERE status = 'queued';
"

# Slow down workers
# (Edit WORKER_CONCURRENCY in config, restart)
```

## Monitoring Checklist

Run this regularly to check system health:

```bash
# Database connectivity
psql $DATABASE_URL -c "SELECT NOW();"

# Kill switch status
psql $DATABASE_URL -c "SELECT halted FROM outbound_kill_switch;"

# Job queue health
psql $DATABASE_URL -c "
  SELECT 
    workflow,
    status,
    COUNT(*) as count,
    MIN(created_at) as oldest
  FROM job
  GROUP BY workflow, status
  ORDER BY count DESC;
"

# Recent errors
psql $DATABASE_URL -c "
  SELECT COUNT(*) as errors FROM job WHERE status = 'failed';
"

# Worker health
ssh ubuntu@worker-ip "sudo systemctl status driftless-worker"

# Server health
curl https://driftless.your-domain.com/health
```

## Common Issues & Fixes

### Workers Stuck Dequeuing Same Job

**Problem**: A job runs forever without progressing to next step.

**Diagnosis**:

```bash
psql $DATABASE_URL -c "
  SELECT id, workflow, status, attempt, created_at
  FROM job
  WHERE status = 'running' AND created_at < NOW() - INTERVAL '1 hour';
"
```

**Fix**: Either fix the issue blocking the job, or manually mark it failed:

```bash
# Mark as failed so next attempt can try
psql $DATABASE_URL -c "
  UPDATE job SET status = 'failed', error = 'manual intervention'
  WHERE id = 'job-id';
"
```

### Webhook Events Not Being Received

**Problem**: No jobs are being enqueued from GitHub events.

**Check**:

```bash
# Verify GitHub App is installed
# (Visit GitHub repository settings → Apps)

# Check webhook deliveries
# (GitHub App settings → Advanced → Recent Deliveries)

# Verify webhook secret matches
grep GITHUB_WEBHOOK_SECRET /etc/driftless/.env | head -c 20
# Compare to GitHub App settings

# Check server logs
ssh ubuntu@server-ip
sudo journalctl -u driftless-server -f | grep webhook
```

### Migrations Reporting "not-run" Tests

**Problem**: Tests are not being run in sandbox.

**Expected in current state**: Until gVisor is deployed, `tests: not-run` is correct behavior per ADR-0006.

**Once gVisor is deployed**: Tests should report as `passed`, `failed`, or `error`.

## Escalation Path

1. **Immediate**: Kill switch and notify team
2. **Quick assessment** (15 min): Check audit trail and recent PRs
3. **Root cause analysis** (1-4 hours): Debug logs, code review
4. **Fix and verification** (1-2 hours): Deploy fix, test in staging
5. **Re-enable** (immediate): Resume outbound writes

## Post-Incident

1. **Document**: What happened, how it was detected, how it was fixed
2. **Communicate**: Brief customers on impact (if any)
3. **Prevent**: Add monitoring/tests to catch similar issues
4. **Review**: Should this have had a kill switch sooner?

## See Also

- `docs/DEPLOYMENT.md` — How to deploy
- `docs/threat-model.md` — What can go wrong and why
- `src/config.ts` — Configuration requirements
- `migrations/002_outbound_writes.sql` — Kill switch table schema
