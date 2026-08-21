/**
 * Adds an upstream package to the sweep list.
 *
 * The sweep scheduler turns `watched_package` rows into `detect-changes` jobs
 * on a clock, and everything downstream — plan-rollout, migrate-repository,
 * the pull request itself — hangs off that. Nothing outside the test suite
 * ever inserted a row, so the scheduler swept an empty list on every tick and
 * the pipeline had nothing to detect. Same silent shape as the missing
 * enrolment path in migration 011: healthy-looking, and completely inert.
 *
 * This is the operator half of that fix. It is a script rather than an API
 * because deciding which upstream packages a provider watches is a product
 * decision, not something a webhook from the internet gets to make — the same
 * reasoning as scripts/create-provider.ts, and it runs on the same connection.
 *
 *   pnpm db:watch <package> <baseline-version> [--provider slug] [--interval seconds]
 *
 * The baseline is the version consumers are assumed to be on: every comparison
 * is made against it, and the sweep deliberately never advances it on its own
 * (see the column comment in migration 007). Setting it to the latest release
 * therefore finds nothing — set it to the version you are migrating *from*.
 *
 * Re-running for the same package updates the baseline and interval and
 * re-enables it, rather than creating a second row.
 */

import pg from "pg";
import { operatorConnectionString, OPERATOR_URL_VAR } from "./operator-connection.ts";

export interface WatchOptions {
  readonly ecosystem?: string;
  readonly sweepIntervalSeconds?: number;
}

export async function watchPackage(
  connectionString: string,
  providerSlug: string,
  packageName: string,
  baselineVersion: string,
  options: WatchOptions = {},
): Promise<{ id: string; created: boolean }> {
  const ecosystem = options.ecosystem ?? "npm";
  const sweepIntervalSeconds = options.sweepIntervalSeconds ?? 3600;

  const client = new pg.Client({ connectionString });
  await client.connect();
  try {
    // Resolved here rather than taken as an id so the operator types the same
    // slug they put in DEFAULT_PROVIDER_SLUG.
    const provider = await client.query<{ id: string }>(
      "SELECT id FROM provider WHERE slug = $1 AND deleted_at IS NULL",
      [providerSlug],
    );
    const providerId = provider.rows[0]?.id;
    if (!providerId) {
      throw new Error(
        `no provider with slug "${providerSlug}" — create it first with ` +
          `\`pnpm db:provider ${providerSlug} "<display name>"\``,
      );
    }

    const { rows } = await client.query<{ id: string; created: boolean }>(
      `INSERT INTO watched_package
              (provider_id, ecosystem, package_name, baseline_version, sweep_interval_seconds)
            VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (provider_id, ecosystem, package_name)
       DO UPDATE SET baseline_version       = EXCLUDED.baseline_version,
                     sweep_interval_seconds = EXCLUDED.sweep_interval_seconds,
                     enabled                = true
         RETURNING id, (xmax = 0) AS created`,
      [providerId, ecosystem, packageName, baselineVersion, sweepIntervalSeconds],
    );
    const row = rows[0];
    if (!row) throw new Error("watched_package upsert returned no row");
    return row;
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
  const positional = argv.filter(
    (arg, i) => !arg.startsWith("--") && !(i > 0 && argv[i - 1]?.startsWith("--")),
  );

  const connectionString = operatorConnectionString();
  const packageName = positional[0];
  const baselineVersion = positional[1];
  const providerSlug = flag(argv, "provider") ?? process.env["DEFAULT_PROVIDER_SLUG"];
  const intervalRaw = flag(argv, "interval");
  const ecosystem = flag(argv, "ecosystem") ?? "npm";

  const usage =
    "Usage: pnpm db:watch <package> <baseline-version> [--provider slug] " +
    "[--interval seconds] [--ecosystem npm]";

  if (!connectionString) {
    console.error(`${OPERATOR_URL_VAR} or DATABASE_URL is required`);
    process.exit(1);
  }
  if (!packageName || !baselineVersion) {
    console.error(usage);
    process.exit(1);
  }
  if (!providerSlug) {
    console.error(
      "No provider. Pass --provider <slug>, or set DEFAULT_PROVIDER_SLUG.\n" + usage,
    );
    process.exit(1);
  }
  // Checked here rather than left to the CHECK constraint, so the error names
  // the flag the operator typed instead of a constraint they have never seen.
  const sweepIntervalSeconds = intervalRaw === undefined ? 3600 : Number(intervalRaw);
  if (!Number.isInteger(sweepIntervalSeconds) ||
      sweepIntervalSeconds < 60 ||
      sweepIntervalSeconds > 604_800) {
    console.error("--interval must be a whole number of seconds between 60 and 604800");
    process.exit(1);
  }
  if (ecosystem !== "npm") {
    console.error(`--ecosystem ${ecosystem} is not supported; only npm is`);
    process.exit(1);
  }

  const { id, created } = await watchPackage(
    connectionString,
    providerSlug,
    packageName,
    baselineVersion,
    { ecosystem, sweepIntervalSeconds },
  );
  console.log(
    `${created ? "Watching" : "Updated"} ${ecosystem}:${packageName} ` +
      `from baseline ${baselineVersion} (${id})\n` +
      `The scheduler claims it on its next tick — a new row has never been swept.`,
  );
}
