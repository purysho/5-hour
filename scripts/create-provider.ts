/**
 * Creates a provider — the paying tenant, and the RLS boundary (ADR-0005).
 *
 * Deliberately a script and not something the application can do. The policy
 * on `provider` in migration 001 checks `id = app.current_provider_id()`, so a
 * row that does not exist yet can never satisfy it: the application role
 * cannot create a tenant, by construction. That is the correct shape —
 * provider creation is an operator and billing decision, not something a
 * webhook from the internet gets to trigger.
 *
 * It therefore runs on the same connection as `pnpm db:migrate` (the owner or
 * superuser), and like that script it is expected to be run by a human who
 * knows why.
 *
 *   pnpm db:provider <slug> [display name]
 *
 * The slug is what `DEFAULT_PROVIDER_SLUG` points at. Re-running with the same
 * slug updates the display name and returns the existing id rather than
 * creating a second tenant.
 */

import pg from "pg";
import { operatorConnectionString, OPERATOR_URL_VAR } from "./operator-connection.ts";

export async function createProvider(
  connectionString: string,
  slug: string,
  displayName: string,
): Promise<{ id: string; created: boolean }> {
  const client = new pg.Client({ connectionString });
  await client.connect();
  try {
    const { rows } = await client.query<{ id: string; created: boolean }>(
      `INSERT INTO provider (slug, display_name)
            VALUES ($1, $2)
       ON CONFLICT (slug) DO UPDATE SET display_name = EXCLUDED.display_name
         RETURNING id, (xmax = 0) AS created`,
      [slug, displayName],
    );
    const row = rows[0];
    if (!row) throw new Error("provider insert returned no row");
    return row;
  } finally {
    await client.end();
  }
}

const isEntrypoint =
  process.argv[1] !== undefined && import.meta.url === `file://${process.argv[1]}`;

if (isEntrypoint) {
  const connectionString = operatorConnectionString();
  const slug = process.argv[2];
  const displayName = process.argv.slice(3).join(" ") || slug;

  if (!connectionString) {
    console.error(`${OPERATOR_URL_VAR} or DATABASE_URL is required`);
    process.exit(1);
  }
  if (!slug || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(slug)) {
    console.error(
      "Usage: pnpm db:provider <slug> [display name]\n" +
        "  slug: lowercase alphanumeric with hyphens — the value of DEFAULT_PROVIDER_SLUG",
    );
    process.exit(1);
  }

  const { id, created } = await createProvider(connectionString, slug, displayName as string);
  console.log(
    `${created ? "Created" : "Updated"} provider ${slug} (${id})\n` +
      `Set DEFAULT_PROVIDER_SLUG=${slug} so new installations enrol into it.`,
  );
}
