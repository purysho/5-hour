---
name: humanloop-gate
description: Human-in-the-loop approval gate using HumanLayer — routes migration diffs to human reviewers and returns approval/rejection decisions
user-invocable: false
allowed-tools:
  - "WebFetch(*)"
model: haiku
---

# HumanLayer Approval Gate Skill

Routes migration reviews to HumanLayer for human expert sign-off. Used by the `migration-orchestrator-agent` to gate PR merges on human approval.

## What This Does

Takes a **migration diff** + **automated review findings** and:

1. Formats as a HumanLayer task (markdown + structured fields)
2. Submits via HumanLayer REST API with a 10-minute approval window
3. Polls for human decision every 10 seconds
4. Returns: `{ approved: boolean, feedback?: string, reviewerId: string }`

## Inputs

```typescript
interface HumanLoopInput {
  // The migration diff (unified format, <10KB)
  diff: string;
  
  // Automated findings to present to the reviewer
  findings: {
    codeReview: { verdict: "pass" | "fail"; issues: string[] };
    blastRadius: { affected: number; high_risk: boolean };
    testVerification: { outcome: "passed" | "failed" | "not-run" };
  };
  
  // Context
  package: string;
  fromVersion: string;
  toVersion: string;
  repositoryUrl: string;
  prUrl: string;
  
  // HumanLayer config (read from env)
  humanloopApiKey: string; // HUMANLOOP_API_KEY
  timeoutSeconds: number;  // Default 600 (10 min)
}
```

## Outputs

```typescript
interface HumanLoopResult {
  approved: boolean;
  feedback: string;        // Human reviewer's notes
  reviewerId: string;      // Anonymized reviewer ID for audit
  decisionTimestamp: number; // Unix timestamp
  escalated: boolean;      // True if human marked for escalation
}
```

## Behavior

**Approval criteria** (human decides):
- Code quality acceptable
- Blast radius justified
- Tests passing (or acceptable risk)
- Migration strategy sound

**Rejection** triggers:
- Code issues that need fixes
- Blast radius too large
- Tests failing and unacceptable
- Manual human rejection for any reason

**Escalation flag**: Human can mark for escalation (e.g., "needs oncall review") without rejecting — agent logs and continues.

## Configuration

### Environment Variables

```bash
HUMANLOOP_API_KEY=sk-hl-...     # HumanLayer API key
HUMANLOOP_ENDPOINT=https://api.humanloop.co/v0
HUMANLOOP_ORG_ID=org-...        # HumanLayer organization
HUMANLOOP_TIMEOUT_SECONDS=600   # Approval window (default 10 min)
```

### Integration Pattern

Used by `migration-orchestrator-agent.ts`:

```typescript
// After code-review and blast-radius agents complete:
const result = await skillHumanloopGate({
  diff: generatedDiff,
  findings: {
    codeReview: codeReviewResult,
    blastRadius: blastRadiusResult,
    testVerification: verificationResult,
  },
  package: "lodash",
  fromVersion: "4.17.21",
  toVersion: "5.0.0",
  repositoryUrl: "https://github.com/my-org/repo",
  prUrl: `https://github.com/my-org/repo/pull/${prNumber}`,
  humanloopApiKey: process.env["HUMANLOOP_API_KEY"],
  timeoutSeconds: 600,
});

if (result.approved) {
  // Merge the PR
  await forge.mergePullRequest(prNumber);
} else {
  // Report rejection with feedback
  console.log(`Human rejected: ${result.feedback}`);
}
```

## Audit Trail

Every HumanLayer decision is recorded in the audit chain (`src/audit/sink.ts`):

```json
{
  "type": "human_review",
  "package": "lodash",
  "from": "4.17.21",
  "to": "5.0.0",
  "decision": "approved",
  "reviewer_id": "rev_xxxxxxx",
  "pr_url": "https://github.com/...",
  "timestamp_utc": "2026-08-17T10:53:00Z"
}
```

## Error Handling

- **API key missing**: Fail fast with clear message (not a retry-safe failure)
- **HumanLayer unreachable**: Fail and notify, retry budget intact
- **Timeout (no response in 10min)**: Fail safe — do not auto-approve or reject
- **Malformed response**: Log and treat as rejection (safer default)

## Testing

Unit tests mock HumanLayer responses and verify:
- Poll loop terminates on approval/rejection
- Timeout exits after N seconds
- Feedback is preserved in result
- Escalation flag is honored
