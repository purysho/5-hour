import type { TenantClient } from "../db/client.ts";

/**
 * The last gate before anything is written to a customer repository
 * (ADR-0004).
 *
 * Threat-model §5.6 rates runaway automation as the most probable serious
 * incident this system faces — more likely than any attack, and unrecoverable
 * in the way that matters. So there are three independent brakes, checked in
 * increasing order of cost:
 *
 *   1. the global kill switch    — stop everything, no deploy required
 *   2. per-installation ceilings — bound the damage to one customer
 *   3. the idempotency claim     — the exactly-once guarantee itself
 *
 * Order matters. A halted system must not consume claims, or resuming after an
 * incident would find every write already claimed and silently skip the work.
 */

export type OutboundDecision =
  | { allowed: true; writeId: string; attempts: number }
  | { allowed: false; reason: "kill-switch"; detail: string }
  | { allowed: false; reason: "rate-limit"; detail: string }
  | {
      allowed: false;
      reason: "already-written";
      writeId: string;
      status: string;
      prNumber: number | null;
      prUrl: string | null;
    };

export interface OutboundRequest {
  readonly providerId: string;
  readonly installationId: string;
  readonly repositoryId: string;
  readonly changeId: string;
  readonly baseSha: string;
}

const SHA_RE = /^[0-9a-f]{40}$/;

export async function authoriseOutboundWrite(
  client: TenantClient,
  request: OutboundRequest,
): Promise<OutboundDecision> {
  if (!SHA_RE.test(request.baseSha)) {
    throw new Error("baseSha must be a 40-character lowercase hex sha");
  }

  const halt = await client.query<{ halted: boolean; reason: string | null }>(
    "SELECT halted, reason FROM outbound_kill_switch WHERE id",
  );
  if (halt.rows[0]?.halted) {
    return {
      allowed: false,
      reason: "kill-switch",
      detail: halt.rows[0].reason ?? "outbound writes are globally halted",
    };
  }

  const limit = await client.query<{
    max_writes_per_hour: number;
    max_open_prs: number;
    writes_last_hour: string;
    open_prs: string;
  }>(
    `SELECT
       COALESCE(l.max_writes_per_hour, 20) AS max_writes_per_hour,
       COALESCE(l.max_open_prs, 50)        AS max_open_prs,
       (SELECT count(*) FROM outbound_write w
         WHERE w.installation_id = $1
           AND w.claimed_at > now() - interval '1 hour')::text AS writes_last_hour,
       (SELECT count(*) FROM outbound_write w
         WHERE w.installation_id = $1
           AND w.status = 'succeeded')::text AS open_prs
     FROM (SELECT 1) dummy
     LEFT JOIN outbound_rate_limit l ON l.installation_id = $1`,
    [request.installationId],
  );

  const row = limit.rows[0];
  if (row) {
    const writes = Number(row.writes_last_hour);
    if (writes >= row.max_writes_per_hour) {
      return {
        allowed: false,
        reason: "rate-limit",
        detail: `installation has made ${writes} writes in the last hour, ceiling is ${row.max_writes_per_hour}`,
      };
    }
    const open = Number(row.open_prs);
    if (open >= row.max_open_prs) {
      return {
        allowed: false,
        reason: "rate-limit",
        detail: `installation has ${open} open pull requests, ceiling is ${row.max_open_prs}`,
      };
    }
  }

  const claim = await client.query<{
    write_id: string;
    is_owner: boolean;
    status: string;
    pr_number: number | null;
    pr_url: string | null;
    attempts: number;
  }>("SELECT * FROM claim_outbound_write($1, $2, $3, $4, $5)", [
    request.providerId,
    request.installationId,
    request.repositoryId,
    request.changeId,
    request.baseSha,
  ]);

  const result = claim.rows[0]!;
  if (!result.is_owner) {
    return {
      allowed: false,
      reason: "already-written",
      writeId: result.write_id,
      status: result.status,
      prNumber: result.pr_number,
      prUrl: result.pr_url,
    };
  }

  return { allowed: true, writeId: result.write_id, attempts: result.attempts };
}

export async function recordOutboundResult(
  client: TenantClient,
  writeId: string,
  outcome:
    | { status: "succeeded"; prNumber: number; prUrl: string }
    | { status: "failed"; error: string },
): Promise<void> {
  if (outcome.status === "succeeded") {
    await client.query(
      "SELECT resolve_outbound_write($1, 'succeeded'::outbound_write_status, $2, $3, NULL)",
      [writeId, outcome.prNumber, outcome.prUrl],
    );
  } else {
    await client.query(
      "SELECT resolve_outbound_write($1, 'failed'::outbound_write_status, NULL, NULL, $2)",
      [writeId, outcome.error],
    );
  }
}

/**
 * Halt or resume all outbound writes.
 *
 * Deliberately a single UPDATE against one row, so it can be executed from a
 * psql session by someone who has never seen this codebase, during an incident,
 * without a deploy.
 */
export async function setKillSwitch(
  client: TenantClient,
  halted: boolean,
  reason: string,
  actor: string,
): Promise<void> {
  await client.query(
    `UPDATE outbound_kill_switch
        SET halted = $1, reason = $2, halted_by = $3, updated_at = now()
      WHERE id`,
    [halted, reason, actor],
  );
}
