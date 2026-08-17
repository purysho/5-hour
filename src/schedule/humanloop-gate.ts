/**
 * HumanLayer approval gate for migrations.
 *
 * Routes migration diffs to human reviewers via HumanLayer API and returns
 * approval/rejection decisions. Polls until timeout or decision received.
 *
 * Audit trail integration: all decisions logged to the audit chain (ADR-0001).
 */

export interface HumanLoopInput {
  readonly diff: string;
  readonly findings: {
    readonly codeReview: { readonly verdict: "pass" | "fail"; readonly issues: readonly string[] };
    readonly blastRadius: { readonly affected: number; readonly high_risk: boolean };
    readonly testVerification: { readonly outcome: "passed" | "failed" | "not-run" };
  };
  readonly package: string;
  readonly fromVersion: string;
  readonly toVersion: string;
  readonly repositoryUrl: string;
  readonly prUrl: string;
  readonly humanloopApiKey: string;
  readonly timeoutSeconds?: number;
}

export interface HumanLoopResult {
  readonly approved: boolean;
  readonly feedback: string;
  readonly reviewerId: string;
  readonly decisionTimestamp: number;
  readonly escalated: boolean;
}

/**
 * API shape from HumanLayer (REST responses).
 */
interface HumanLoopApiTask {
  id: string;
  status: "pending" | "approved" | "rejected" | "expired";
  feedback?: string;
  reviewer_id?: string;
  created_at: string;
  completed_at?: string;
  /**
   * Set when the reviewer wants a second pair of eyes without blocking the
   * merge. Carried through to the caller rather than dropped: an escalation
   * that never leaves this function is the same as no escalation at all.
   */
  escalated?: boolean;
}

const DEFAULT_TIMEOUT_SECONDS = 600; // 10 minutes
const DEFAULT_POLL_INTERVAL_MS = 10_000; // Poll every 10 seconds

export interface HumanLoopOptions {
  readonly log?: (event: string, detail: Record<string, unknown>) => void;
  /**
   * Overridden in tests. The timeout path is the safety-critical one — it must
   * never auto-approve — and with a hard-coded ten-second poll there was no way
   * to reach it in a unit test, so it went unverified.
   */
  readonly pollIntervalMs?: number;
}

/**
 * Formats review findings into a markdown prompt for the human reviewer.
 */
function formatPrompt(input: HumanLoopInput): string {
  const codeReviewSection =
    input.findings.codeReview.verdict === "pass"
      ? "✅ Code review passed"
      : `❌ Code review flagged issues:\n${input.findings.codeReview.issues.map((i) => `  - ${i}`).join("\n")}`;

  const blastRadiusSection = input.findings.blastRadius.high_risk
    ? `⚠️  High-risk blast radius: affects ${input.findings.blastRadius.affected} repositories`
    : `✅ Blast radius acceptable: affects ${input.findings.blastRadius.affected} repositories`;

  const testSection =
    input.findings.testVerification.outcome === "passed"
      ? "✅ Tests passed"
      : input.findings.testVerification.outcome === "failed"
        ? "❌ Tests failed"
        : "⚠️  Tests not run (sandbox not yet deployed)";

  return `
# Migration Review: ${input.package}

**Version upgrade**: ${input.fromVersion} → ${input.toVersion}

**Pull request**: [${input.prUrl}](${input.prUrl})

## Automated Findings

${codeReviewSection}

${blastRadiusSection}

${testSection}

## Your Decision

Please review the diff and the findings above. Approve to merge, reject if changes are needed.

**Diff** (first 2000 chars):
\`\`\`diff
${input.diff.slice(0, 2000)}
${input.diff.length > 2000 ? "\n... (full diff available in PR)\n" : ""}
\`\`\`

**Questions for the reviewer**:
- Is this migration safe for the affected repositories?
- Are there edge cases the automated review missed?
- Do the test results justify merging without full test coverage?
`;
}

/**
 * Submits a task to HumanLayer and polls for decision.
 *
 * Returns approval/rejection result or throws on timeout/API error.
 * Does NOT auto-approve on timeout — failure is the safe default.
 */
export async function submitToHumanLayer(
  input: HumanLoopInput,
  options: HumanLoopOptions = {},
): Promise<HumanLoopResult> {
  const log = options.log ?? (() => {});
  const pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const timeoutSeconds = input.timeoutSeconds ?? DEFAULT_TIMEOUT_SECONDS;

  log("humanloop.submit_start", {
    package: input.package,
    fromVersion: input.fromVersion,
    toVersion: input.toVersion,
    timeoutSeconds,
  });

  // Create the task in HumanLayer
  const taskId = await createHumanLoopTask(input);

  log("humanloop.task_created", {
    taskId,
    prUrl: input.prUrl,
  });

  // Poll for decision with timeout
  const startTime = Date.now();
  const deadline = startTime + timeoutSeconds * 1000;

  while (Date.now() < deadline) {
    const task = await getHumanLoopTask(input.humanloopApiKey, taskId);

    if (task.status === "approved") {
      log("humanloop.approved", {
        taskId,
        reviewerId: task.reviewer_id,
        feedback: task.feedback,
        escalated: task.escalated ?? false,
      });

      return {
        approved: true,
        feedback: task.feedback ?? "",
        reviewerId: task.reviewer_id ?? "unknown",
        decisionTimestamp: task.completed_at ? new Date(task.completed_at).getTime() : Date.now(),
        escalated: task.escalated ?? false,
      };
    }

    if (task.status === "rejected") {
      log("humanloop.rejected", {
        taskId,
        reviewerId: task.reviewer_id,
        feedback: task.feedback,
        escalated: task.escalated ?? false,
      });

      return {
        approved: false,
        feedback: task.feedback ?? "No feedback provided",
        reviewerId: task.reviewer_id ?? "unknown",
        decisionTimestamp: task.completed_at ? new Date(task.completed_at).getTime() : Date.now(),
        escalated: task.escalated ?? false,
      };
    }

    if (task.status === "expired") {
      log("humanloop.expired", {
        taskId,
        timeoutSeconds,
      });

      throw new Error(`HumanLayer task expired after ${timeoutSeconds}s with no decision`);
    }

    // Still pending, wait before polling again
    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
  }

  // Timeout reached without decision
  log("humanloop.timeout", {
    taskId,
    elapsedSeconds: timeoutSeconds,
  });

  throw new Error(
    `HumanLayer approval timeout: no decision after ${timeoutSeconds}s. ` +
      `Task remains pending. Do not auto-merge without human sign-off.`,
  );
}

/**
 * Create a new task in HumanLayer.
 * Returns the task ID.
 */
async function createHumanLoopTask(input: HumanLoopInput): Promise<string> {
  const apiKey = input.humanloopApiKey;
  if (!apiKey) {
    throw new Error(
      "HUMANLOOP_API_KEY not set. Cannot submit migration for human review. " +
        "Set the env var or pass it explicitly.",
    );
  }

  const endpoint = process.env["HUMANLOOP_ENDPOINT"] ?? "https://api.humanloop.co/v0";

  const response = await fetch(`${endpoint}/tasks`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      type: "review",
      title: `Approve migration: ${input.package} ${input.fromVersion} → ${input.toVersion}`,
      description: formatPrompt(input),
      priority: "high",
      metadata: {
        package: input.package,
        from_version: input.fromVersion,
        to_version: input.toVersion,
        repository_url: input.repositoryUrl,
        pr_url: input.prUrl,
        affected_repositories: input.findings.blastRadius.affected,
        high_risk: input.findings.blastRadius.high_risk,
      },
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`HumanLayer API error: ${response.status} ${body}`);
  }

  const data = (await response.json()) as { id: string };
  return data.id;
}

/**
 * Poll HumanLayer for task status.
 */
async function getHumanLoopTask(apiKey: string, taskId: string): Promise<HumanLoopApiTask> {
  const endpoint = process.env["HUMANLOOP_ENDPOINT"] ?? "https://api.humanloop.co/v0";

  const response = await fetch(`${endpoint}/tasks/${taskId}`, {
    method: "GET",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(`HumanLayer API error: ${response.status}`);
  }

  return (await response.json()) as HumanLoopApiTask;
}
