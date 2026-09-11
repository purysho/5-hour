/**
 * Finds public repositories that actually depend on a package.
 *
 * The operator's half of `src/discover/github-code-search.ts`. It exists to
 * answer one question before any outreach happens: for this package, which
 * real repositories would a breaking change strand, and which are exposed to
 * it already?
 *
 *   pnpm discover <package-name> [--from 2.4.0 --to 3.0.0] [--limit 25]
 *
 * With `--from` and `--to` it prints the impact classification and the
 * targeting decision for each candidate, prioritised the way a rollout would
 * order them. Without them it prints the candidates and their declared ranges,
 * which is enough to see whether a package is worth watching at all.
 *
 * Writes nothing. Choosing a cold-start cohort is a judgement made by reading
 * this output, and a script that also recorded its findings would make that
 * judgement by accident.
 *
 * The credential comes from GITHUB_SEARCH_TOKEN and needs no scopes beyond
 * public read — code search requires an authenticated request, not a
 * privileged one. It is passed per call and never held.
 */

import { GitHubCodeSearchCrawler, DiscoveryError } from "../src/discover/github-code-search.ts";
import { createFetchHttpClient } from "../src/forge/fetch-http.ts";
import { decideTarget, prioritise, type TargetDecision } from "../src/discover/affected.ts";
import type { RepositoryCandidate } from "../src/discover/affected.ts";
import { Secret } from "../src/config.ts";

export interface DiscoverArgs {
  readonly packageName: string;
  readonly from: string | null;
  readonly to: string | null;
  readonly limit: number;
}

export function parseArgs(argv: readonly string[]): DiscoverArgs {
  const positional: string[] = [];
  const flags = new Map<string, string>();

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!;
    if (argument.startsWith("--")) {
      const eq = argument.indexOf("=");
      if (eq !== -1) {
        flags.set(argument.slice(2, eq), argument.slice(eq + 1));
      } else {
        const value = argv[index + 1];
        if (value === undefined || value.startsWith("--")) {
          throw new DiscoveryError(`${argument} needs a value`);
        }
        flags.set(argument.slice(2), value);
        index += 1;
      }
    } else {
      positional.push(argument);
    }
  }

  const packageName = positional[0];
  if (packageName === undefined) {
    throw new DiscoveryError("usage: pnpm discover <package-name> [--from X --to Y] [--limit N]");
  }

  const from = flags.get("from") ?? null;
  const to = flags.get("to") ?? null;
  // Both or neither. An impact classification needs two versions to compare,
  // and defaulting the missing one would silently assess a change nobody asked
  // about.
  if ((from === null) !== (to === null)) {
    throw new DiscoveryError("--from and --to must be given together");
  }

  const rawLimit = flags.get("limit");
  const limit = rawLimit === undefined ? 25 : Number(rawLimit);
  if (!Number.isInteger(limit) || limit < 1) {
    throw new DiscoveryError("--limit must be a positive integer");
  }

  return { packageName, from, to, limit };
}

/** Rendering is separated from fetching so the output shape is testable. */
export function renderCandidates(
  candidates: readonly RepositoryCandidate[],
  packageName: string,
): string[] {
  if (candidates.length === 0) {
    return [`no repositories found declaring ${packageName}`];
  }
  return candidates.map((candidate) => {
    const declared = candidate.dependencies.find((d) => d.packageName === packageName);
    const marks = [candidate.archived ? "archived" : null, candidate.fork ? "fork" : null]
      .filter((mark) => mark !== null)
      .join(" ");
    return [
      pad(`${candidate.owner}/${candidate.name}`, 44),
      pad(`★${candidate.stars ?? 0}`, 8),
      pad(declared ? `${declared.kind}:${declared.range}` : "-", 34),
      marks,
    ]
      .join(" ")
      .trimEnd();
  });
}

export function renderDecisions(decisions: readonly TargetDecision[]): string[] {
  return decisions.map((decision) => {
    const { repository: repo, assessment } = decision;
    return [
      pad(decision.targeted ? "TARGET" : "skip", 7),
      pad(`${repo.owner}/${repo.name}`, 44),
      pad(assessment.impact, 10),
      decision.targeted ? assessment.detail : (decision.skipReason ?? ""),
    ]
      .join(" ")
      .trimEnd();
  });
}

function pad(value: string, width: number): string {
  return value.length >= width ? value : value + " ".repeat(width - value.length);
}

/** Just enough of the crawler to run against, so this is testable offline. */
export interface CandidateSource {
  findCandidates(packageName: string, credential: Secret): Promise<RepositoryCandidate[]>;
}

export function defaultSource(limit: number): CandidateSource {
  return new GitHubCodeSearchCrawler({
    http: createFetchHttpClient(),
    maxCandidates: limit,
    // Structured progress on stderr, so piping stdout to a file keeps the
    // candidate list clean.
    log: (event, detail) => console.error(JSON.stringify({ event, ...detail })),
  });
}

export async function discover(
  args: DiscoverArgs,
  credential: Secret,
  write: (line: string) => void = console.log,
  source: CandidateSource = defaultSource(args.limit),
): Promise<number> {
  const candidates = await source.findCandidates(args.packageName, credential);

  write(`${candidates.length} candidate(s) declaring ${args.packageName}`);
  write("");
  for (const line of renderCandidates(candidates, args.packageName)) write(line);

  if (args.from !== null && args.to !== null) {
    const change = { packageName: args.packageName, fromVersion: args.from, toVersion: args.to };
    const decisions = prioritise(candidates.map((candidate) => decideTarget(candidate, change)));

    write("");
    write(`impact of ${args.packageName} ${args.from} → ${args.to}, in rollout order`);
    write("");
    for (const line of renderDecisions(decisions)) write(line);

    const targeted = decisions.filter((decision) => decision.targeted).length;
    write("");
    write(`${targeted} of ${decisions.length} would be targeted`);
  }

  return candidates.length;
}

const isEntrypoint =
  process.argv[1] !== undefined && import.meta.url === `file://${process.argv[1]}`;

if (isEntrypoint) {
  const token = process.env["GITHUB_SEARCH_TOKEN"]?.trim();
  if (!token) {
    console.error(
      "GITHUB_SEARCH_TOKEN is required. A token with public read access is enough — " +
        "GitHub code search requires an authenticated request, not a privileged one.",
    );
    process.exit(2);
  }

  try {
    const args = parseArgs(process.argv.slice(2));
    await discover(args, new Secret(token, "GITHUB_SEARCH_TOKEN"));
  } catch (error) {
    // The message only. A stack here would print the script's own source
    // lines, and the error may have been built from a response body.
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}
