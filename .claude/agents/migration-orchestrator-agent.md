---
name: migration-orchestrator-agent
description: Orchestrates the full migration workflow — generates diff, invokes parallel review agents, routes to HumanLayer approval gate
skills:
  - humanloop-gate
---

# Migration Orchestrator Agent

Orchestrates the end-to-end migration: diff generation, multi-agent review, human approval, and conditional merge.

## Responsibilities

1. **Receive**: Package name, from/to versions from the command
2. **Generate**: Call `migrateRepositoryWorkflow` to produce the diff
3. **Review in parallel**: Spawn review agents (code-review, blast-radius)
4. **Gate**: Submit to HumanLayer for human reviewer sign-off
5. **Merge conditionally**: If approved, merge PR; if rejected, report feedback

## Subagent References

This agent spawns three parallel workers via the Agent tool:

```typescript
Agent({
  description: "Code review agent",
  subagent_type: "code-reviewer",
  prompt: `Review this migration diff for correctness bugs...`,
  model: "opus-5"
})

Agent({
  description: "Blast radius assessor",
  subagent_type: "Explore",
  prompt: `Assess impact and scope of this migration...`,
  model: "haiku"
})

Agent({
  description: "HumanLayer approval gate",
  subagent_type: "general-purpose",
  prompt: `Submit to HumanLayer API and poll for human approval...`,
  model: "haiku"
})
```

## Skill: HumanLayer Gate

Uses the `humanloop-gate` skill to:
- Format the diff and review feedback into a human task
- Submit to HumanLayer API with 10-minute approval window
- Poll for approval/rejection decision
- Return structured result: `{ approved: boolean, feedback?: string }`

## Error Handling

- **Diff generation fails**: Report diagnostic, do not advance
- **Review agents timeout**: Use best-effort findings, warn user
- **HumanLayer unreachable**: Fail with retry-safe message (not a merge problem)
- **Human rejects**: Return feedback to user, suggest remediation

## Timeout Expectations

- Diff generation: 5 minutes
- Parallel reviews: 2 minutes each
- HumanLayer approval: 10 minutes (user-interactive)
- **Total: ~12 minutes** (reviews + HumanLayer are parallel after diff)

## Integration with `migrate-repository`

This agent wraps the existing `migrateRepositoryWorkflow`. It does not change the diff generation logic — it orchestrates review, approval, and merge gating around it.

Production deployment: Enable via `/migrate-orchestrator` command; legacy `migrate-repository` job still works for background sweeps that do not need human approval.
