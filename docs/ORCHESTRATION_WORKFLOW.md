# Driftless Orchestration Workflow

## Overview

The **migration orchestrator** implements a **Command → Agent → Skill** pattern with human-in-the-loop approval gates. It combines automated migration generation, parallel code review, and human expert sign-off before merging into downstream repositories.

## Architecture

```
┌─────────────────┐
│  /migrate-      │ Entry point: user specifies package & versions
│  orchestrator   │
└────────┬────────┘
         │
         ▼
    ┌─────────────────────────────────────────┐
    │  migration-orchestrator-agent           │
    │  (wraps migrateRepositoryWorkflow)      │
    └────────────┬────────────────────────────┘
                 │
         ┌───────┴───────┐
         │               │
         ▼               ▼
    ┌────────────┐  ┌──────────────┐
    │  Code      │  │  Blast       │
    │  Review    │  │  Radius      │
    │  Agent     │  │  Agent       │
    └─────┬──────┘  └────────┬─────┘
          │                  │
          │  (parallel)      │
          └────────┬─────────┘
                   │
                   ▼
         ┌──────────────────────┐
         │  HumanLayer Gate     │
         │  (10-minute window)  │
         └────────┬─────────────┘
                  │
         ┌────────┴────────┐
         │                 │
         ▼                 ▼
    ┌────────┐      ┌──────────┐
    │Approved│      │ Rejected │
    │ Merge  │      │ Report   │
    └────────┘      │ Feedback │
                    └──────────┘
```

## Flow

### 1. Invocation

```bash
# Orchestrated migration with human approval
/migrate-orchestrator lodash 4.17.21 5.0.0

# Legacy background migration (no approval gate)
# migrate-repository (via scheduler)
```

### 2. Diff Generation

The agent calls `migrateRepositoryWorkflow` (existing code) to generate the migration diff. This step is unchanged from the background workflow.

**Inputs:**
- Package name
- From/to versions
- List of downstream repositories (from database)

**Output:**
- Unified diff
- PR description with metadata
- Verification result (tests: not-run | passed | failed)

### 3. Parallel Review

After diff generation, two agents run in parallel:

**Code Review Agent** (`subagent_type: "code-reviewer"`):
- Scans for correctness bugs, security issues, edge cases
- Returns: `{ verdict: "pass" | "fail"; issues: string[] }`

**Blast Radius Agent** (`subagent_type: "Explore"`):
- Assesses scope of impact
- Checks for risky patterns (new dependencies, auth changes, etc.)
- Returns: `{ affected: number; high_risk: boolean }`

Both complete within 2 minutes. The agent waits for both before advancing.

### 4. HumanLayer Gate

Once reviews complete, the agent calls the `humanloop-gate` skill:

```typescript
const result = await submitToHumanLayer({
  diff: generatedDiff,
  findings: {
    codeReview: codeReviewResult,
    blastRadius: blastRadiusResult,
    testVerification: verificationResult,
  },
  package, fromVersion, toVersion,
  repositoryUrl, prUrl,
  humanloopApiKey: process.env["HUMANLOOP_API_KEY"],
  timeoutSeconds: 600, // 10 minutes
});
```

**What the human sees:**
- Formatted diff (first 2000 chars)
- Automated findings summary
- PR link for full review
- Questions: Is this migration safe? Edge cases? Test results acceptable?

**Decision options:**
- ✅ **Approve**: Proceed to merge
- ❌ **Reject**: Return feedback to user for remediation
- ⚠️ **Escalate**: Flag for oncall review, continue in escalation queue

**Timeout behavior:** If no decision in 10 minutes, fail safe. Do NOT auto-approve. The migration stays queued for retry.

### 5. Conditional Merge

**If approved:**
- Merge the PR into the downstream repository
- Log approval to audit chain (ADR-0001)
- Report success to user

**If rejected:**
- Return human feedback
- Keep PR open for developer remediation
- Log rejection to audit chain
- User can re-trigger after fixes

## Configuration

### Environment Variables

```bash
# HumanLayer API
HUMANLOOP_API_KEY=sk-hl-...              # Required to enable orchestration
HUMANLOOP_ENDPOINT=https://api.humanloop.co/v0
HUMANLOOP_TIMEOUT_SECONDS=600            # Default 10 minutes

# Optional: monitoring and alerts
HUMANLOOP_SLACK_CHANNEL=#approvals       # Notify on submission
```

### Enabling the Feature

1. Set `HUMANLOOP_API_KEY` in `run-worker.ts` environment
2. Ensure HumanLayer organization is set up (HUMANLOOP_ORG_ID)
3. Test with `/migrate-orchestrator` command in Claude Code

### Disabling (fallback)

If HumanLayer is unreachable:
- The orchestrator fails with a retry-safe error
- Migration jobs stay queued
- Retry when HumanLayer is restored
- No auto-merge or skip-merge on infrastructure failure

## Audit Trail

All decisions recorded via `auditFor(db, providerId)` sink:

```json
{
  "type": "human_review",
  "event": "migration_submitted",
  "package": "lodash",
  "from_version": "4.17.21",
  "to_version": "5.0.0",
  "pr_url": "https://github.com/.../pull/123",
  "timestamp_utc": "2026-08-17T10:53:00Z"
}
```

```json
{
  "type": "human_review",
  "event": "migration_approved",
  "reviewer_id": "rev_xyz123",
  "feedback": "Migration looks good",
  "pr_url": "https://github.com/.../pull/123",
  "timestamp_utc": "2026-08-17T10:54:30Z"
}
```

## Timing

| Stage | Duration | Notes |
|-------|----------|-------|
| Diff generation | ~5 min | Using `ClaudeMigrationAgent` |
| Code review | ~2 min | Parallel with blast radius |
| Blast radius | ~2 min | Parallel with code review |
| HumanLayer gate | 0–10 min | User-interactive, 10-min window |
| Merge | <1 min | Conditional on approval |
| **Total** | ~12–17 min | Mostly waiting on human |

## Failure Modes & Recovery

| Failure | Impact | Recovery |
|---------|--------|----------|
| Diff generation fails | Migration not attempted | Auto-retry queue picks it up |
| Code review timeout | Use best-effort findings | Proceed with caution, log warning |
| Blast radius timeout | Use best-effort findings | Proceed with caution, log warning |
| HumanLayer unreachable | Migration stalls | Retry when service recovered |
| Human rejects | PR stays open | Developer fixes, re-triggers manually |
| PR merge fails | Migration incomplete | Check downstream repo state, manual intervention |

## Comparison: Orchestrated vs. Background

| Aspect | `/migrate-orchestrator` | `migrate-repository` job |
|--------|------------------------|-------------------------|
| Invocation | Manual (Claude Code) | Automatic (scheduler) |
| Approval | Human-gated (HumanLayer) | Policy-gated (drift policy) |
| Timeframe | ~15 min interactive | Background, no time pressure |
| Best for | High-stakes migrations, early validation | Canary rollouts, sweep coverage |
| Retry | Immediate (user can retry) | Job queue (respects backoff) |

Both systems use the same `ClaudeMigrationAgent` and `migrateRepositoryWorkflow`. The orchestrator adds review and human gates; the background job adds scale and scheduling.

## Example: Adopting a New Dependency Version

```bash
# Terminal: Start orchestrated migration
/migrate-orchestrator axios 1.5.0 1.6.0

# Claude Code logs in to HumanLayer, submits a human task
# → Human reviewer sees: diff + code review + blast radius + test results
# → Reviews PR at https://github.com/my-org/app/pull/456

# While waiting, human can:
# - Review the full diff in GitHub
# - Run tests locally if needed
# - Ask for clarification in PR comments

# After ~5 minutes, human approves
# ✅ PR is merged automatically
# → Audit trail records: approved by @reviewer-name

# User sees: "Migration complete: axios 1.5.0 → 1.6.0 (12 repositories upgraded)"
```

## Implementation Roadmap

**Phase 1** (current):
- ✅ HumanLayer gate implementation (`src/schedule/humanloop-gate.ts`)
- ✅ Orchestration agent and command definitions (`.claude/agents/`, `.claude/commands/`)
- ⏳ Integration test with mock HumanLayer API

**Phase 2** (next):
- Workspace abstraction for sandbox (blocks real verification)
- gVisor deployment (sandbox unblocked)
- Optional: email notifications to reviewers

**Phase 3** (future):
- Escalation workflow (human marks for oncall, ticket opened)
- Batch orchestration (multiple packages in one session)
- Analytics dashboard (approval rates, time-to-decision)
