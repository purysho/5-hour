/**
 * Resolving a change key to exactly one change.
 *
 * `change_key` is unique per *provider*, not globally — migration 001 declares
 * `UNIQUE (provider_id, change_key)`, because two tenants watching react both
 * legitimately record `react@19.2.8`. Matching on the key alone therefore
 * matches an unknown number of rows, and every operator script here was doing
 * exactly that.
 *
 * On a read that produced the wrong tenant's row. On `db:approve` it was worse:
 * `UPDATE ... WHERE change_key = $1` approved the change for every provider
 * holding that key at once — one operator authorising a fan-out across tenants
 * who never asked for it, recorded against their name. The RLS boundary in
 * ADR-0005 exists to make that impossible from the application role; these
 * scripts run on the migration connection, which is precisely the connection
 * that boundary does not protect.
 *
 * So ambiguity is refused rather than resolved. Picking the first row, the
 * newest, or the only one that happens to be unapproved would all be a guess,
 * and the cost of guessing wrong is a rollout against someone else's
 * repositories.
 */

import type pg from "pg";

export interface ResolvedChange {
  readonly id: string;
  readonly providerId: string;
  readonly providerSlug: string;
  readonly packageName: string;
  readonly approvedAt: Date | null;
  readonly approvedBy: string | null;
}

export class AmbiguousChangeError extends Error {
  constructor(changeKey: string, slugs: readonly string[]) {
    super(
      `"${changeKey}" matches ${slugs.length} providers (${slugs.join(", ")}). ` +
        `Name one with --provider <slug>.`,
    );
    this.name = "AmbiguousChangeError";
  }
}

export async function resolveChange(
  client: pg.Client,
  changeKey: string,
  providerSlug?: string,
): Promise<ResolvedChange> {
  const { rows } = await client.query<{
    id: string;
    provider_id: string;
    slug: string;
    package_name: string;
    approved_at: Date | null;
    approved_by: string | null;
  }>(
    `SELECT c.id, c.provider_id, p.slug, c.package_name, c.approved_at, c.approved_by
       FROM upstream_change c
       JOIN provider p ON p.id = c.provider_id
      WHERE c.change_key = $1
        AND ($2::text IS NULL OR p.slug = $2)
      ORDER BY p.slug`,
    [changeKey, providerSlug ?? null],
  );

  if (rows.length === 0) {
    throw new Error(
      providerSlug
        ? `no change with key "${changeKey}" for provider "${providerSlug}"`
        : `no change with key "${changeKey}"`,
    );
  }
  if (rows.length > 1) {
    throw new AmbiguousChangeError(
      changeKey,
      rows.map((r) => r.slug),
    );
  }

  const row = rows[0]!;
  return {
    id: row.id,
    providerId: row.provider_id,
    providerSlug: row.slug,
    packageName: row.package_name,
    approvedAt: row.approved_at,
    approvedBy: row.approved_by,
  };
}
