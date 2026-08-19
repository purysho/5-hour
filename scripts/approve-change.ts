/**
 * Approves a detected change for rollout, or lists what is waiting.
 *
 * The last gate before this system writes to anyone else's repository.
 * `plan-rollout` refuses to fan out a change whose `approved_at` is null, and
 * migration 010 built the scheduler that watches for approvals — but nothing
 * anywhere ever set the column. Detection ran, changes were recorded, and
 * every one of them sat at the gate forever.
 *
 * The gate itself is not the bug and is not being removed. Fanning a change
 * out to every consumer the moment detection finds it turns one detection bug
 * into an incident across every repository at once (ADR-0013: model output is
 * a proposal). So this is a command a person runs, deliberately, after looking
 * at what was found:
 *
 *   pnpm db:approve                          # what is waiting
 *   pnpm db:approve <change-key> --by alice  # approve one
 *
 * Approval is recorded with who did it, because "who decided to touch a
 * thousand repositories" is the first question anyone asks afterwards, and
 * `approved_by` is where the answer has to already be.
 *
 * Re-approving an already-approved change is a no-op rather than an error: it
 * keeps the original timestamp and approver, so a second run cannot quietly
 * relabel who authorised a rollout that has already happened.
 */

import pg from "pg";

export interface PendingChange {
  readonly changeKey: string;
  readonly providerSlug: string;
  readonly ecosystem: string;
  readonly packageName: string;
  readonly fromVersion: string | null;
  readonly toVersion: string | null;
  readonly summary: string;
  readonly corroborations: number;
  readonly impactedSymbols: number;
}

export async function listPending(connectionString: string): Promise<PendingChange[]> {
  const client = new pg.Client({ connectionString });
  await client.connect();
  try {
    const { rows } = await client.query<{
      change_key: string;
      slug: string;
      ecosystem: string;
      package_name: string;
      from_version: string | null;
      to_version: string | null;
      summary: string;
      corroborations: number;
      impacted_symbols: number;
    }>(
      `SELECT c.change_key, p.slug, c.ecosystem, c.package_name,
              c.from_version, c.to_version, c.summary,
              jsonb_array_length(c.corroborations) AS corroborations,
              coalesce(array_length(c.impacted_symbols, 1), 0) AS impacted_symbols
         FROM upstream_change c
         JOIN provider p ON p.id = c.provider_id
        WHERE c.approved_at IS NULL
        ORDER BY c.created_at DESC`,
    );
    return rows.map((r) => ({
      changeKey: r.change_key,
      providerSlug: r.slug,
      ecosystem: r.ecosystem,
      packageName: r.package_name,
      fromVersion: r.from_version,
      toVersion: r.to_version,
      summary: r.summary,
      corroborations: Number(r.corroborations),
      impactedSymbols: Number(r.impacted_symbols),
    }));
  } finally {
    await client.end();
  }
}

export async function approveChange(
  connectionString: string,
  changeKey: string,
  approvedBy: string,
): Promise<{ alreadyApproved: boolean; packageName: string }> {
  const client = new pg.Client({ connectionString });
  await client.connect();
  try {
    const existing = await client.query<{ package_name: string; approved_at: string | null }>(
      "SELECT package_name, approved_at FROM upstream_change WHERE change_key = $1",
      [changeKey],
    );
    const row = existing.rows[0];
    if (!row) throw new Error(`no change with key "${changeKey}"`);
    if (row.approved_at !== null) {
      return { alreadyApproved: true, packageName: row.package_name };
    }

    // Guarded on approved_at IS NULL as well as the key, so two operators
    // approving at once cannot overwrite each other's attribution.
    await client.query(
      `UPDATE upstream_change
          SET approved_at = now(), approved_by = $2
        WHERE change_key = $1 AND approved_at IS NULL`,
      [changeKey, approvedBy],
    );
    return { alreadyApproved: false, packageName: row.package_name };
  } finally {
    await client.end();
  }
}

function flag(argv: readonly string[], name: string): string | undefined {
  const index = argv.indexOf(`--${name}`);
  return index === -1 ? undefined : argv[index + 1];
}

const isEntrypoint =
  process.argv[1] !== undefined && import.meta.url === `file://${process.argv[1]}`;

if (isEntrypoint) {
  const argv = process.argv.slice(2);
  const connectionString = process.env["DATABASE_URL"];
  const changeKey = argv[0]?.startsWith("--") ? undefined : argv[0];
  const approvedBy = flag(argv, "by");

  if (!connectionString) {
    console.error("DATABASE_URL is required");
    process.exit(1);
  }

  if (!changeKey) {
    const pending = await listPending(connectionString);
    if (pending.length === 0) {
      console.log(
        "Nothing awaiting approval.\n" +
          "Changes appear here after a sweep detects one — check that a package " +
          "is watched (`pnpm db:watch`) and that the worker is running.",
      );
    } else {
      console.log(`${pending.length} change(s) awaiting approval:\n`);
      for (const c of pending) {
        console.log(
          `  ${c.changeKey}\n` +
            `    ${c.ecosystem}:${c.packageName} ${c.fromVersion ?? "?"} → ${c.toVersion ?? "?"} ` +
            `(provider: ${c.providerSlug})\n` +
            `    ${c.summary}\n` +
            `    ${c.corroborations} corroboration(s), ${c.impactedSymbols} impacted symbol(s)\n`,
        );
      }
      console.log("Approve one with: pnpm db:approve <change-key> --by <your name>");
    }
    process.exit(0);
  }

  if (!approvedBy) {
    console.error(
      "--by is required: approval is recorded against whoever authorised it.\n" +
        "Usage: pnpm db:approve <change-key> --by <your name>",
    );
    process.exit(1);
  }

  const { alreadyApproved, packageName } = await approveChange(
    connectionString,
    changeKey,
    approvedBy,
  );
  console.log(
    alreadyApproved
      ? `${changeKey} (${packageName}) was already approved — leaving the original approver in place.`
      : `Approved ${changeKey} (${packageName}) as ${approvedBy}.\n` +
          `The approval trigger enqueues plan-rollout on its next tick.`,
  );
}
