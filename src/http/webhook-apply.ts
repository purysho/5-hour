/**
 * Applying webhook events.
 *
 * Parsing an event is not the same as honouring it. This is the half that
 * makes revocation real: when a customer uninstalls the app, the effect has to
 * reach the database before the next job mints a token.
 *
 * ── Revocation is treated as terminal and immediate ──────────────────────────
 *
 * `installation.revoked` is the customer saying stop, through the only channel
 * GitHub gives them. Continuing to act afterwards — even briefly, even because
 * a job was already queued — is the single worst thing this system can do, so:
 *
 *   * the installation is marked suspended immediately, which stops token
 *     minting at the source (ADR-0002 mints per job, so nothing already
 *     issued outlives its few-minute TTL);
 *   * queued jobs for that installation are cancelled rather than left to
 *     discover the revocation on their own;
 *   * the action is written to the audit chain, because "when did you stop?"
 *     is exactly the question a customer will ask afterwards.
 *
 * Suspension is reversible and revocation is not: an unsuspend restores the
 * installation, but a deleted installation stays marked and would need a fresh
 * install to come back.
 */

import type { TenantClient } from "../db/client.ts";
import type { AddedRepository, ForgeEvent, RepositoryRef } from "./webhook.ts";

export interface ApplyResult {
  readonly applied: boolean;
  readonly detail: string;
  /** Non-secret summary for the audit chain and logs. */
  readonly auditAction: string | null;
}

export interface ApplyDeps {
  readonly withTenant: <T>(
    providerId: string,
    fn: (client: TenantClient) => Promise<T>,
  ) => Promise<T>;
  /** Resolves a forge installation id to its provider. Minimal disclosure. */
  readonly providerForInstallation: (forgeInstallationId: number) => Promise<string | null>;
}

export async function applyForgeEvent(
  event: ForgeEvent,
  deps: ApplyDeps,
): Promise<ApplyResult> {
  const providerId = await deps.providerForInstallation(event.installationId);

  if (!providerId) {
    // An event for an installation we do not know about. Common and benign —
    // a stale delivery after a tenant was deleted, or an app installed and
    // removed before we recorded it. Not an error.
    return {
      applied: false,
      detail: `no installation matching forge id ${event.installationId}`,
      auditAction: null,
    };
  }

  return deps.withTenant(providerId, async (client) => {
    switch (event.type) {
      case "installation.revoked":
        return revoke(client, event.installationId, "revoked");
      case "installation.suspended":
        return revoke(client, event.installationId, "suspended");
      case "installation.unsuspended":
        return unsuspend(client, event.installationId);
      case "repositories.added":
        return addRepositories(client, providerId, event.installationId, event.repositories);
      case "repositories.removed":
        return removeRepositories(client, event.installationId, event.repositories);
      case "pull_request.closed":
        return recordPullRequestOutcome(client, event);
      case "push":
        return {
          applied: true,
          detail: `push to ${event.repository.owner}/${event.repository.name} on ${event.ref}`,
          auditAction: "push",
        };
    }
  });
}

async function revoke(
  client: TenantClient,
  forgeInstallationId: number,
  kind: "revoked" | "suspended",
): Promise<ApplyResult> {
  // Marked suspended in both cases: the difference is whether it can come
  // back, not whether we stop. Stopping is unconditional.
  const { rowCount } = await client.query(
    `UPDATE installation
        SET suspended_at = COALESCE(suspended_at, now())
      WHERE forge_installation_id = $1`,
    [forgeInstallationId],
  );

  // Cancelling queued work matters as much as the flag. A job already in the
  // queue would otherwise run, discover the suspension, and only then stop —
  // and "only then" is after it has already tried to mint a token.
  const cancelled = await client.query(
    `UPDATE job
        SET status = 'cancelled', finished_at = now(),
            last_error = 'installation ${kind}'
      WHERE status IN ('pending', 'failed')
        AND input->>'installationId' IN (
          SELECT id::text FROM installation WHERE forge_installation_id = $1
        )`,
    [forgeInstallationId],
  );

  return {
    applied: (rowCount ?? 0) > 0,
    detail: `installation ${kind}; ${cancelled.rowCount ?? 0} queued job(s) cancelled`,
    auditAction: `installation.${kind}`,
  };
}

async function unsuspend(
  client: TenantClient,
  forgeInstallationId: number,
): Promise<ApplyResult> {
  const { rowCount } = await client.query(
    `UPDATE installation SET suspended_at = NULL WHERE forge_installation_id = $1`,
    [forgeInstallationId],
  );
  return {
    applied: (rowCount ?? 0) > 0,
    detail: "installation unsuspended",
    auditAction: "installation.unsuspended",
  };
}

/**
 * Records repositories a customer has just granted us.
 *
 * The row this writes is the only thing that makes a repository visible to the
 * rest of the pipeline, so what it does *not* write matters as much as what it
 * does. The payload carries no default branch and no star count; those are
 * left at their defaults for the worker to learn with a credential, because a
 * guessed default branch produces a repository we silently never manage to
 * read.
 *
 * Re-granting a previously withdrawn repository clears `archived_at`. That is
 * the customer re-inviting us, and it must not require a support ticket to
 * take effect — while the audit trail of what we did during the first grant
 * stays exactly where it was.
 */
async function addRepositories(
  client: TenantClient,
  providerId: string,
  forgeInstallationId: number,
  repositories: readonly AddedRepository[],
): Promise<ApplyResult> {
  if (repositories.length === 0) {
    return { applied: false, detail: "no repositories in grant", auditAction: null };
  }

  const { rows } = await client.query<{ id: string }>(
    `INSERT INTO repository
       (provider_id, installation_id, forge, forge_owner, forge_name,
        forge_repository_id, is_private)
     SELECT $1, i.id, 'github', t.owner, t.name, t.forge_id, t.is_private
       FROM installation i,
            unnest($3::text[], $4::text[], $5::bigint[], $6::boolean[])
              AS t(owner, name, forge_id, is_private)
      WHERE i.forge_installation_id = $2
        AND i.provider_id = $1
     ON CONFLICT (provider_id, forge, forge_owner, forge_name) DO UPDATE
        SET forge_repository_id = EXCLUDED.forge_repository_id,
            installation_id     = EXCLUDED.installation_id,
            is_private          = EXCLUDED.is_private,
            archived_at         = NULL
     RETURNING id`,
    [
      providerId,
      forgeInstallationId,
      repositories.map((repository) => repository.owner),
      repositories.map((repository) => repository.name),
      repositories.map((repository) => repository.forgeRepositoryId),
      repositories.map((repository) => repository.isPrivate),
    ],
  );

  return {
    applied: rows.length > 0,
    detail: `${rows.length} repository(ies) recorded from grant`,
    auditAction: "repositories.added",
  };
}

async function removeRepositories(
  client: TenantClient,
  forgeInstallationId: number,
  repositories: readonly RepositoryRef[],
): Promise<ApplyResult> {
  // Archived rather than deleted: the audit trail must still explain what we
  // did there while we had access, and deleting the row would orphan the
  // outbound_write records that prove it.
  const owners = repositories.map((r) => r.owner);
  const names = repositories.map((r) => r.name);

  const { rowCount } = await client.query(
    `UPDATE repository r
        SET archived_at = COALESCE(archived_at, now())
       FROM unnest($2::text[], $3::text[]) AS t(owner, name)
      WHERE r.installation_id IN (
              SELECT id FROM installation WHERE forge_installation_id = $1
            )
        AND lower(r.forge_owner) = t.owner
        AND lower(r.forge_name) = t.name`,
    [forgeInstallationId, owners, names],
  );

  return {
    applied: (rowCount ?? 0) > 0,
    detail: `${rowCount ?? 0} repository(ies) archived after withdrawal`,
    auditAction: "repositories.removed",
  };
}

async function recordPullRequestOutcome(
  client: TenantClient,
  event: Extract<ForgeEvent, { type: "pull_request.closed" }>,
): Promise<ApplyResult> {
  // Merged versus closed-unmerged is the only real quality signal this system
  // gets. It is also the metric the whole product is judged on, so it is
  // recorded against the write that produced the pull request rather than
  // being inferred later.
  const { rowCount } = await client.query(
    `UPDATE outbound_write w
        SET pr_outcome = $2, pr_outcome_at = now()
       FROM repository r
      WHERE w.repository_id = r.id
        AND w.pr_number = $1
        AND lower(r.forge_owner) = $3
        AND lower(r.forge_name) = $4`,
    [
      event.number,
      event.merged ? "merged" : "closed",
      event.repository.owner,
      event.repository.name,
    ],
  );

  return {
    applied: (rowCount ?? 0) > 0,
    detail: event.merged
      ? `pull request #${event.number} merged`
      : `pull request #${event.number} closed without merging`,
    auditAction: `pull_request.${event.merged ? "merged" : "closed"}`,
  };
}
