/**
 * The audit sink the token minter writes through (ADR-0007).
 *
 * `GitHubApp.mintInstallationToken` has always required one; until now nothing
 * implemented it, which is a large part of why `migrate-repository` could not
 * be registered. The interface is small and the implementation is a pair of
 * inserts, but the ordering it preserves is the whole point.
 *
 * ── Intent before mint, always ───────────────────────────────────────────────
 *
 * ADR-0007 §2: the intent record is written *before* the credential is
 * requested, so a token that exists without a preceding intent entry is
 * evidence of compromise rather than an ambiguous gap. That ordering is
 * enforced by `app.ts` awaiting this call; what this module must not do is
 * make the write cheap by deferring or batching it. So the insert is awaited,
 * inside the tenant's transaction, and a failure to record propagates — a mint
 * we could not account for does not happen.
 *
 * ── Why the sink is per-provider ─────────────────────────────────────────────
 *
 * `AuditSink` carries no tenant. It cannot: it is called from inside the mint
 * path, which knows about installations and repositories, not about the RLS
 * boundary. Binding the provider at construction keeps every insert inside one
 * tenant's chain without threading a provider id through the credential code,
 * where an accidentally-wrong value would write another tenant's audit log.
 *
 * ── What is not recorded ─────────────────────────────────────────────────────
 *
 * Never the token. ADR-0007 §6: this log records which repository, which
 * permissions, which token *identifier* and TTL — the shape of the grant, not
 * the grant. `metadata` is assembled field by field here rather than spread
 * from a caller's object, so a future field cannot arrive by accident.
 */

import type { AuditSink } from "../github/app.ts";
import type { TenantClient } from "../db/client.ts";

export interface AuditSinkDeps {
  readonly withTenant: <T>(
    providerId: string,
    fn: (client: TenantClient) => Promise<T>,
  ) => Promise<T>;
}

export const MINT_INTENT = "token.mint_intent";
export const MINT_OUTCOME = "token.mint_outcome";

/**
 * A sink bound to one tenant's chain.
 *
 * The intent row's id is remembered so the outcome can reference it. The map
 * is per-instance and per-job, so it holds at most a handful of entries; a
 * process that dies between the two writes leaves an unresolved intent, which
 * is exactly what an interrupted mint should look like.
 */
export function postgresAuditSink(deps: AuditSinkDeps, providerId: string): AuditSink {
  const intents = new Map<string, string>();

  return {
    async recordMintIntent(entry) {
      const id = await deps.withTenant(providerId, async (client) => {
        const { rows } = await client.query<{ id: string }>(
          `INSERT INTO audit_entry (provider_id, action, subject, metadata)
           VALUES ($1, $2, $3, $4)
           RETURNING id`,
          [
            providerId,
            MINT_INTENT,
            `repository:${entry.repositoryId}`,
            JSON.stringify({
              tokenId: entry.tokenId,
              installationId: entry.installationId,
              repositoryId: entry.repositoryId,
              permissions: entry.permissions,
              ttlSeconds: entry.ttlSeconds,
            }),
          ],
        );
        return rows[0]?.id ?? null;
      });

      if (!id) {
        // The chain trigger assigns seq and hashes on insert, so a row that
        // did not come back means the append did not happen. Minting a
        // credential we could not account for is worse than failing the job.
        throw new Error("Audit intent was not recorded; refusing to mint");
      }
      intents.set(entry.tokenId, id);
    },

    async recordMintOutcome(entry) {
      const intentId = intents.get(entry.tokenId) ?? null;
      await deps.withTenant(providerId, async (client) => {
        await client.query(
          `INSERT INTO audit_entry (provider_id, action, subject, intent_id, metadata)
           VALUES ($1, $2, $3, $4, $5)`,
          [
            providerId,
            MINT_OUTCOME,
            intentId ? `intent:${intentId}` : `token:${entry.tokenId}`,
            intentId,
            JSON.stringify({
              tokenId: entry.tokenId,
              succeeded: entry.succeeded,
              ...(entry.expiresAt !== undefined && { expiresAt: entry.expiresAt }),
              // The error text comes from GitHub's response body. It is
              // recorded because "why did the mint fail" is the question this
              // log exists to answer, and truncated because a response body is
              // not a bounded thing.
              ...(entry.error !== undefined && { error: entry.error.slice(0, 500) }),
            }),
          ],
        );
      });
      intents.delete(entry.tokenId);
    },
  };
}
