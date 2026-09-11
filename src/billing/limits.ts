/**
 * The repository limit, which is what distinguishes one plan from the next.
 *
 * Enforced at enrolment rather than at detection. The two produce very
 * different customer experiences from the same rule: refusing to *watch* a
 * repository someone already connected means their pull requests quietly stop
 * arriving and they discover it weeks later, while refusing to *connect* one
 * more is a sentence in a log and a prompt to upgrade. The first is a support
 * ticket and a refund; the second is a pricing conversation.
 *
 * ── What counts against the limit ───────────────────────────────────────────
 *
 * Live repositories. A repository already on record does not consume capacity
 * again when GitHub re-sends it — which it does on every re-install, and on
 * any `repositories.added` event that includes the existing selection. Without
 * that distinction a customer at their limit who adds one repository would see
 * their entire existing selection reported as refused, which is alarming and
 * wrong.
 *
 * ── Why this fails open ─────────────────────────────────────────────────────
 *
 * Deliberately the opposite of `entitlement.ts`, and worth being explicit
 * about. Entitlement decides whether to do work for someone who may not be
 * paying, so it fails closed. This decides how much work to do for someone who
 * *is* paying, and the failure mode of refusing them is losing a customer who
 * has already given us money. A tenant with no subscription row never reaches
 * here: `authoriseOutboundWrite` has already refused them.
 */

import type { TenantClient } from "../db/client.ts";

export interface RepositoryRef {
  readonly owner: string;
  readonly name: string;
}

export interface LimitOutcome<T extends RepositoryRef> {
  /** Repositories to record: everything already known, plus new ones up to capacity. */
  readonly accepted: readonly T[];
  /** New repositories the plan has no room for. */
  readonly refused: readonly T[];
  readonly limit: number;
  readonly liveCount: number;
}

/**
 * Splits an incoming grant into what the plan has room for and what it does not.
 *
 * Ordering of the refused set follows the order GitHub sent them, so the
 * outcome is deterministic for the same grant rather than depending on row
 * order in a database.
 */
export async function applyRepositoryLimit<T extends RepositoryRef>(
  client: TenantClient,
  repositories: readonly T[],
): Promise<LimitOutcome<T>> {
  const subscription = await client.query<{ repository_limit: number }>(
    "SELECT repository_limit FROM subscription LIMIT 1",
  );
  const limit = subscription.rows[0]?.repository_limit ?? null;

  if (limit === null) {
    // No subscription visible to this tenant. Not our decision to make here —
    // the outbound guard refuses unentitled tenants long before a pull request
    // is opened, and blocking enrolment too would mean a customer whose
    // webhook arrived a second before their subscription row lost their
    // repositories permanently.
    return { accepted: repositories, refused: [], limit: Number.POSITIVE_INFINITY, liveCount: 0 };
  }

  // RLS scopes this to the calling tenant; no predicate is possible or needed.
  const live = await client.query<{ forge_owner: string; forge_name: string }>(
    "SELECT forge_owner, forge_name FROM repository WHERE archived_at IS NULL",
  );

  const known = new Set(live.rows.map((row) => key(row.forge_owner, row.forge_name)));
  const liveCount = known.size;

  const accepted: T[] = [];
  const refused: T[] = [];
  let capacity = Math.max(0, limit - liveCount);

  for (const repository of repositories) {
    if (known.has(key(repository.owner, repository.name))) {
      // Already counted. Re-recording it changes nothing about capacity.
      accepted.push(repository);
      continue;
    }
    if (capacity > 0) {
      accepted.push(repository);
      capacity -= 1;
      continue;
    }
    refused.push(repository);
  }

  return { accepted, refused, limit, liveCount };
}

function key(owner: string, name: string): string {
  // Forge coordinates are case-insensitive on GitHub, and a customer who
  // reconnects `Acme/Widgets` after `acme/widgets` must not consume a second
  // slot for the same repository.
  return `${owner.toLowerCase()}/${name.toLowerCase()}`;
}
