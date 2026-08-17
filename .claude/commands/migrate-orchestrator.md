---
name: migrate-orchestrator
description: Orchestrated migration workflow with human approval gates — generates migrations, routes to review agents, and requires HumanLayer sign-off before PR merge
---

# Migration Orchestrator Command

Entry point for the **Driftless migration system** with human-in-the-loop approval.

## Flow

This command implements the **Command → Agent → Human Gate** pattern:

1. **User triggers**: `/migrate-orchestrator <package> <from-version> <to-version>`
2. **Agent executes**: Generates migration diff using `ClaudeMigrationAgent`
3. **Review agents**: Parallel code review, blast-radius assessment, test verification
4. **Human gate**: Routes to HumanLayer for human reviewer approval
5. **Conditional merge**: Auto-merges PR if approved, otherwise reports to user

```
┌─────────────────┐
│  /migrate-      │
│  orchestrator   │
└────────┬────────┘
         │
         ▼
    ┌─────────────────────────────────┐
    │  migration-orchestrator-agent   │
    │  (generates diff, calls review) │
    └────────────┬────────────────────┘
                 │
         ┌───────┴────────┐
         │                │
         ▼                ▼
    ┌────────────┐  ┌──────────────┐
    │Code Review │  │Blast Radius  │
    │   Agent    │  │  Assessment  │
    └────────────┘  └──────────────┘
         │                │
         └───────┬────────┘
                 │
                 ▼
         ┌──────────────────┐
         │ HumanLayer Gate  │
         │ (Review & Sign)  │
         └────────┬─────────┘
                  │
         ┌────────┴────────┐
         │                 │
      Approved          Rejected
         │                 │
         ▼                 ▼
    ┌────────┐      ┌──────────┐
    │Auto-   │      │Report to │
    │Merge   │      │Developer │
    └────────┘      └──────────┘
```

## Invocation

```bash
/migrate-orchestrator lodash 4.17.21 5.0.0
```

## Parameters

- `package`: npm package name (e.g., `lodash`, `typescript`)
- `from-version`: Current version constraint
- `to-version`: Target version constraint

## Output

Returns:

- **If approved**: PR merged, migration complete, changeset report
- **If rejected**: Review feedback, suggested changes, user action items
- **On error**: Detailed diagnostic from the failed stage (diff generation, review, HumanLayer submission)

## Implementation Notes

- Review agents run in parallel; HumanLayer gates run sequentially
- Timeouts: 5min (diff generation), 2min (reviews), 10min (human approval gate)
- Failures do not burn retry budget; migration can be re-triggered with same parameters
- HumanLayer integration via `humanloop` Python SDK or REST API (see `src/schedule/humanloop-gate.ts`)
