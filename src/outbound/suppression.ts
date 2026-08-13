/**
 * Suppression — honouring the opt-out.
 *
 * Every pull request body promises: "one click, no account, and we will not
 * open another pull request here." This module is what makes that true.
 *
 * A promise printed on a trusted artifact and not enforced is worse than no
 * promise at all — it converts a maintainer's goodwill into a grievance the
 * first time we open a second pull request after they clicked. In the
 * open-source cold-start motion, that grievance is public.
 *
 * ── Fail closed ──────────────────────────────────────────────────────────────
 *
 * Every other check in the outbound path fails closed because a mistake writes
 * to a customer repository. This one fails closed for a different reason: the
 * cost of wrongly suppressing is one pull request we do not open, and the cost
 * of wrongly *not* suppressing is a broken promise to someone who already told
 * us to stop. Those are not comparable, so an error here refuses the write.
 */

import type { TenantClient } from "../db/client.ts";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export type SuppressionScope = "repository" | "owner" | "installation";

export interface SuppressionTarget {
  readonly forge: string;
  readonly owner: string;
  readonly name: string;
}

export type SuppressionCheck =
  | { readonly suppressed: false }
  | {
      readonly suppressed: true;
      readonly scope: SuppressionScope;
      readonly since: string;
    };

/**
 * Checked before every outbound write.
 *
 * Owner-scoped suppression covers every repository that owner has: a
 * maintainer with forty repositories should not have to click forty times to
 * be left alone.
 */
export async function checkSuppression(
  client: TenantClient,
  target: SuppressionTarget,
): Promise<SuppressionCheck> {
  const { rows } = await client.query<{
    scope: SuppressionScope;
    created_at: string;
  }>(
    `SELECT scope, created_at
       FROM suppression
      WHERE forge = $1
        AND forge_owner = lower($2)
        AND (
          (scope = 'repository' AND forge_name = lower($3))
          OR scope <> 'repository'
        )
        AND (expires_at IS NULL OR expires_at > now())
      ORDER BY CASE scope
                 WHEN 'installation' THEN 0
                 WHEN 'owner' THEN 1
                 ELSE 2
               END
      LIMIT 1`,
    [target.forge, target.owner, target.name],
  );

  const row = rows[0];
  if (!row) return { suppressed: false };
  return { suppressed: true, scope: row.scope, since: row.created_at };
}

export interface SuppressInput extends SuppressionTarget {
  readonly scope: SuppressionScope;
  /** Untrusted free text. Stored for context; never rendered anywhere trusted. */
  readonly reason?: string;
  readonly source?: string;
  readonly expiresAt?: Date;
}

/**
 * Records an opt-out. Idempotent — clicking the link twice is not an error,
 * and a maintainer who clicks again because nothing visibly happened should
 * not get a failure page.
 */
export async function suppress(
  client: TenantClient,
  providerId: string,
  input: SuppressInput,
): Promise<void> {
  // Reason is stored truncated. It arrives from an unauthenticated endpoint,
  // so an unbounded value is free storage for anyone who wants it.
  const reason = input.reason?.slice(0, 500) ?? null;

  await client.query(
    `INSERT INTO suppression
       (provider_id, scope, forge, forge_owner, forge_name, reason, source, expires_at)
     VALUES ($1, $2, $3, lower($4), $5, $6, $7, $8)
     ON CONFLICT DO NOTHING`,
    [
      providerId,
      input.scope,
      input.forge,
      input.owner,
      input.scope === "repository" ? input.name.toLowerCase() : null,
      reason,
      input.source ?? "opt-out-link",
      input.expiresAt ?? null,
    ],
  );
}

// ── Opt-out tokens ──────────────────────────────────────────────────────────

const TOKEN_BYTES = 32;

export interface IssuedToken {
  /** Goes in the URL. Never stored. */
  readonly token: string;
  readonly hash: string;
}

/**
 * Mints an opt-out token for one repository.
 *
 * Only the hash is stored. A database read therefore does not yield working
 * opt-out links for every repository we have ever contacted, which would
 * otherwise be a tidy denial-of-service list against our own customers.
 */
export function issueOptOutToken(): IssuedToken {
  const token = randomBytes(TOKEN_BYTES).toString("base64url");
  return { token, hash: hashToken(token) };
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export async function recordOptOutToken(
  client: TenantClient,
  providerId: string,
  hash: string,
  target: SuppressionTarget,
): Promise<void> {
  await client.query(
    `INSERT INTO opt_out_token (token_hash, provider_id, forge, forge_owner, forge_name)
     VALUES ($1, $2, $3, lower($4), lower($5))
     ON CONFLICT (token_hash) DO NOTHING`,
    [hash, providerId, target.forge, target.owner, target.name],
  );
}

export type RedemptionResult =
  | { readonly redeemed: true; readonly target: SuppressionTarget }
  | { readonly redeemed: false; readonly reason: "unknown-token" };

/**
 * Redeems a token and suppresses its repository.
 *
 * Tokens never expire. A maintainer finding an old pull request in their inbox
 * two years from now should still be able to make it stop — an expired opt-out
 * link is an opt-out that does not work.
 *
 * Redemption is idempotent, and a token stays valid after use so that a
 * second click still lands on a page saying "you are opted out" rather than
 * an error.
 */
export async function redeemOptOutToken(
  client: TenantClient,
  providerId: string,
  token: string,
  reason?: string,
): Promise<RedemptionResult> {
  const hash = hashToken(token);

  const { rows } = await client.query<{
    forge: string;
    forge_owner: string;
    forge_name: string;
  }>(
    `SELECT forge, forge_owner, forge_name
       FROM opt_out_token
      WHERE token_hash = $1`,
    [hash],
  );

  const row = rows[0];
  if (!row) return { redeemed: false, reason: "unknown-token" };

  const target: SuppressionTarget = {
    forge: row.forge,
    owner: row.forge_owner,
    name: row.forge_name,
  };

  await suppress(client, providerId, { ...target, scope: "repository", ...(reason !== undefined && { reason }) });

  await client.query(
    `UPDATE opt_out_token SET redeemed_at = COALESCE(redeemed_at, now())
      WHERE token_hash = $1`,
    [hash],
  );

  return { redeemed: true, target };
}

/**
 * Constant-time comparison for token equality.
 *
 * Not used by the lookup above — that compares hashes in the database, where
 * the index makes timing analysis impractical — but exported for any code path
 * that ends up comparing tokens directly, so the obvious `===` is never the
 * convenient option.
 */
export function tokensEqual(a: string, b: string): boolean {
  const left = Buffer.from(hashToken(a), "hex");
  const right = Buffer.from(hashToken(b), "hex");
  return left.length === right.length && timingSafeEqual(left, right);
}
