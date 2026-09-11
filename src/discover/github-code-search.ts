/**
 * Finding repositories that actually depend on a package.
 *
 * This is the crawler `docs/HANDOFF.md` item 4 leaves open: impact
 * classification in `affected.ts` can decide whether a repository is stranded
 * or exposed, but nothing produced the `RepositoryCandidate` values for it to
 * judge. This does, from public GitHub.
 *
 * ── Search is a lead generator, never evidence ───────────────────────────────
 *
 * The governing rule, and the reason this file is longer than a search call
 * needs to be. GitHub code search matches text. A repository whose
 * `package.json` mentions a package in a script, a description, a
 * `bundledDependencies` entry, an `overrides` block, or a comment in a
 * `//`-tolerant parser is a *hit*, and is not a consumer.
 *
 * Acting on a hit means opening a pull request against a repository that never
 * depended on the package. In a cold-outreach motion that is not a small
 * error: it is the one that gets the App blocked, reported, and written about.
 * So a hit only ever earns a repository the right to be *checked*. The real
 * root `package.json` is then fetched and parsed through `parseManifest`, and
 * a candidate exists only if the parsed dependencies genuinely contain the
 * package.
 *
 * Precision over recall, deliberately. Missing a consumer costs one pull
 * request nobody sees. Inventing one costs the channel.
 *
 * ── Root manifests only, in this version ─────────────────────────────────────
 *
 * A hit at `packages/thing/package.json` is ignored rather than followed. A
 * monorepo's workspace manifest is a genuine consumer, but the repository's
 * dependency story is spread across manifests we would have to merge, and a
 * partial merge produces a confident wrong answer about which range applies.
 * The first cohort does not need monorepos; it needs targets we are certain
 * about.
 *
 * ── What this deliberately does not do ───────────────────────────────────────
 *
 * No pagination beyond the first page, no persistence, no queue, no cache, no
 * lockfile reading. The requirement is enough precise candidates to assemble a
 * first outreach cohort, not an index of the ecosystem. `lockedVersion` is left
 * unset rather than guessed: `assessRepository` treats it as the strongest
 * evidence available, and a fabricated one would override a correct reading of
 * the declared range.
 */

import type { ForgeHttpClient } from "../forge/github-forge.ts";
import type { RepositoryCandidate } from "./affected.ts";
import { parseManifest, ManifestError } from "./manifest.ts";
import { Secret } from "../config.ts";

export class DiscoveryError extends Error {
  override readonly name = "DiscoveryError";
  readonly status: number;

  constructor(message: string, status = 0) {
    super(message);
    this.status = status;
  }
}

export interface CodeSearchOptions {
  readonly http: ForgeHttpClient;
  readonly baseUrl?: string;
  readonly userAgent?: string;
  /** Candidates emitted before the crawl stops. */
  readonly maxCandidates?: number;
  /** Search hits inspected. Bounds the number of repository round trips. */
  readonly maxSearchResults?: number;
  readonly log?: (event: string, detail: Record<string, unknown>) => void;
}

const DEFAULT_BASE_URL = "https://api.github.com";
const DEFAULT_USER_AGENT = "driftless";
const DEFAULT_MAX_CANDIDATES = 25;
const DEFAULT_MAX_SEARCH_RESULTS = 100;

/** GitHub's own ceiling for `per_page` on the search endpoints. */
const SEARCH_PAGE_CEILING = 100;

/**
 * npm's package name rules, as much of them as matter here.
 *
 * Validated before any network call, for two reasons. A name containing a
 * quote or a qualifier would otherwise be interpolated into the search query
 * and change what is searched for — `foo" OR path:` is a query, not a package.
 * And a crawl for a name that cannot exist should fail immediately rather than
 * spending a rate-limited search request discovering it.
 */
const PACKAGE_NAME_RE = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;

export function isValidPackageName(value: string): boolean {
  return value.length > 0 && value.length <= 214 && PACKAGE_NAME_RE.test(value);
}

interface RepositoryMetadata {
  readonly owner: string;
  readonly name: string;
  readonly defaultBranch: string;
  readonly stars: number | null;
  readonly archived: boolean;
  readonly fork: boolean;
}

export class GitHubCodeSearchCrawler {
  readonly #http: ForgeHttpClient;
  readonly #baseUrl: string;
  readonly #userAgent: string;
  readonly #maxCandidates: number;
  readonly #maxSearchResults: number;
  readonly #log: (event: string, detail: Record<string, unknown>) => void;

  constructor(options: CodeSearchOptions) {
    const maxCandidates = options.maxCandidates ?? DEFAULT_MAX_CANDIDATES;
    const maxSearchResults = options.maxSearchResults ?? DEFAULT_MAX_SEARCH_RESULTS;

    // Rejected at construction rather than clamped. A caller asking for zero
    // candidates, or for two thousand, has a bug; silently substituting a
    // different number hides it until someone wonders why the cohort is the
    // size it is.
    if (!Number.isInteger(maxCandidates) || maxCandidates < 1) {
      throw new DiscoveryError("maxCandidates must be a positive integer");
    }
    if (
      !Number.isInteger(maxSearchResults) ||
      maxSearchResults < 1 ||
      maxSearchResults > SEARCH_PAGE_CEILING
    ) {
      throw new DiscoveryError(
        `maxSearchResults must be an integer between 1 and ${SEARCH_PAGE_CEILING}`,
      );
    }

    this.#http = options.http;
    this.#baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.#userAgent = options.userAgent ?? DEFAULT_USER_AGENT;
    this.#maxCandidates = maxCandidates;
    this.#maxSearchResults = maxSearchResults;
    this.#log = options.log ?? (() => {});
  }

  /**
   * Candidates that genuinely declare `packageName`.
   *
   * The credential is a parameter rather than a field. A crawler that holds one
   * for its lifetime is a crawler whose every instance is a place a token can
   * be read from — and this object is long-lived while a search credential is
   * not. It is never logged, never returned, never put in an error message, and
   * never stored.
   */
  async findCandidates(
    packageName: string,
    credential: Secret,
  ): Promise<RepositoryCandidate[]> {
    if (!isValidPackageName(packageName)) {
      // Before the network, deliberately. See PACKAGE_NAME_RE.
      throw new DiscoveryError(`"${packageName}" is not a valid npm package name`);
    }

    const hits = await this.#search(packageName, credential);
    const candidates: RepositoryCandidate[] = [];

    for (const coordinate of hits) {
      if (candidates.length >= this.#maxCandidates) break;

      const candidate = await this.#inspect(coordinate, packageName, credential);
      if (candidate !== null) candidates.push(candidate);
    }

    return candidates;
  }

  /**
   * The search request, returning deduplicated repository coordinates.
   *
   * Only hits whose path is exactly `package.json` survive. Everything else is
   * a nested manifest, and this version does not follow those.
   */
  async #search(
    packageName: string,
    credential: Secret,
  ): Promise<{ owner: string; name: string }[]> {
    // The package name is quoted so the search is for the literal string, and
    // it has already been validated against a character set that cannot escape
    // the quotes.
    const query = `"${packageName}" filename:package.json`;
    const url =
      `${this.#baseUrl}/search/code` +
      `?q=${encodeURIComponent(query)}&per_page=${this.#maxSearchResults}`;

    const response = await this.#http.request("GET", url, undefined, {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${Secret.reveal(credential)}`,
      "user-agent": this.#userAgent,
      "x-github-api-version": "2022-11-28",
    });

    // Code search has its own rate-limit category, separate from core, and a
    // far smaller allowance. Exhausting it is a normal operational event rather
    // than an anomaly — and it must stop the crawl rather than degrade it,
    // because a truncated result set looks exactly like "this package has few
    // consumers" and would quietly produce a small, wrong cohort.
    //
    // The status alone distinguishes these, which matters because this HTTP
    // boundary intentionally does not surface response headers: headers are
    // where a credential is most likely to be echoed back into a log. So the
    // rate-limit category is inferred from the status and named in the message
    // rather than read from x-ratelimit-*.
    if (response.status === 429) {
      throw new DiscoveryError(
        "GitHub code search rate limit exhausted (429); code search has its own " +
          "limit category, separate from the core API",
        429,
      );
    }
    if (response.status === 403) {
      throw new DiscoveryError(
        "GitHub refused the code search (403) — the code search rate limit is " +
          "exhausted, or the credential lacks the scope the endpoint requires",
        403,
      );
    }
    if (response.status === 401) {
      throw new DiscoveryError("GitHub rejected the search credential (401)", 401);
    }
    if (response.status < 200 || response.status >= 300) {
      // The body is not included. It is attacker-influenceable and, on auth
      // failures, has been observed echoing the request that produced it.
      throw new DiscoveryError(`GitHub code search failed with ${response.status}`, response.status);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(response.body);
    } catch {
      throw new DiscoveryError("GitHub code search returned a body that is not JSON", 200);
    }
    if (!isRecord(parsed) || !Array.isArray(parsed["items"])) {
      throw new DiscoveryError("GitHub code search returned no items array", 200);
    }

    const seen = new Set<string>();
    const coordinates: { owner: string; name: string }[] = [];
    let nested = 0;

    for (const item of parsed["items"].slice(0, this.#maxSearchResults)) {
      if (!isRecord(item)) continue;
      if (item["path"] !== "package.json") {
        nested += 1;
        continue;
      }

      const repository = item["repository"];
      if (!isRecord(repository)) continue;
      const owner = ownerLogin(repository);
      const name = stringField(repository, "name");
      if (owner === null || name === null) continue;

      // GitHub treats owner/name case-insensitively, so the same repository can
      // arrive under two spellings and would otherwise be inspected twice and
      // emitted twice.
      const key = `${owner.toLowerCase()}/${name.toLowerCase()}`;
      if (seen.has(key)) continue;
      seen.add(key);
      coordinates.push({ owner, name });
    }

    this.#log("discovery.search_complete", {
      packageName,
      hits: parsed["items"].length,
      rootManifests: coordinates.length,
      nestedIgnored: nested,
    });

    return coordinates;
  }

  /**
   * Turns one coordinate into a candidate, or into nothing.
   *
   * Every failure here is a skip rather than a throw. One unreachable
   * repository among a hundred is an ordinary outcome — it was renamed, made
   * private, or deleted between the search and now — and aborting the crawl
   * over it would make the whole cohort hostage to the least stable repository
   * in it. The search failures above are different: they mean the result set
   * itself is wrong.
   */
  async #inspect(
    coordinate: { owner: string; name: string },
    packageName: string,
    credential: Secret,
  ): Promise<RepositoryCandidate | null> {
    const skip = (reason: string): null => {
      this.#log("discovery.repository_skipped", {
        owner: coordinate.owner,
        name: coordinate.name,
        reason,
      });
      return null;
    };

    const metadata = await this.#repository(coordinate, credential);
    if (metadata === null) return skip("repository metadata unavailable");

    const manifestSource = await this.#rootManifest(coordinate, credential);
    if (manifestSource === null) return skip("no readable root package.json");

    let dependencies;
    try {
      // The one parser. A second, more permissive reading of a manifest here
      // would mean discovery and migration disagree about what a repository
      // depends on, and discovery's answer is the one nobody reviews.
      dependencies = parseManifest(manifestSource).dependencies;
    } catch (error) {
      // A closed vocabulary, not the error's message. `parseManifest` builds
      // its JSON failure from V8's parser error, and V8 echoes the input:
      //   Unexpected token 'S', "{"a": SENTINEL_L"... is not valid JSON
      // A manifest is attacker-authored and this line goes to an operator's
      // terminal and their log aggregator, so passing the message through
      // publishes up to sixteen bytes of a stranger's file into our logs.
      //
      // Classifying instead of forwarding also makes the reasons aggregatable,
      // which is what an operator actually wants from a skip: how many, of
      // which kind, not one prose sentence per repository.
      return skip(`unparseable manifest: ${classifyManifestFailure(error)}`);
    }

    // The check the whole module exists for. Up to this point the repository is
    // a search hit; only here does it become a consumer.
    const declares = dependencies.some((dependency) => dependency.packageName === packageName);
    if (!declares) {
      return skip(`root manifest does not declare ${packageName}`);
    }

    this.#log("discovery.candidate_found", {
      owner: metadata.owner,
      name: metadata.name,
      stars: metadata.stars,
      archived: metadata.archived,
      fork: metadata.fork,
    });

    // archived and fork are carried through rather than filtered here.
    // `decideTarget` owns eligibility, and a candidate that silently omitted
    // them would be judged against defaults it never declared.
    return {
      forge: "github",
      owner: metadata.owner,
      name: metadata.name,
      defaultBranch: metadata.defaultBranch,
      dependencies,
      ...(metadata.stars === null ? {} : { stars: metadata.stars }),
      archived: metadata.archived,
      fork: metadata.fork,
    };
  }

  async #repository(
    coordinate: { owner: string; name: string },
    credential: Secret,
  ): Promise<RepositoryMetadata | null> {
    const response = await this.#http.request(
      "GET",
      `${this.#baseUrl}/repos/${encodeURIComponent(coordinate.owner)}/${encodeURIComponent(coordinate.name)}`,
      undefined,
      {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${Secret.reveal(credential)}`,
        "user-agent": this.#userAgent,
        "x-github-api-version": "2022-11-28",
      },
    );

    if (response.status < 200 || response.status >= 300) return null;

    let parsed: unknown;
    try {
      parsed = JSON.parse(response.body);
    } catch {
      return null;
    }
    if (!isRecord(parsed)) return null;

    const owner = ownerLogin(parsed);
    const name = stringField(parsed, "name");
    const defaultBranch = stringField(parsed, "default_branch");
    // A repository with no usable identity is skipped rather than patched up
    // with the coordinate we searched with. A candidate carrying a branch we
    // guessed would send a migration at a ref that may not exist.
    if (owner === null || name === null || defaultBranch === null) return null;

    const stars = parsed["stargazers_count"];

    return {
      owner,
      name,
      defaultBranch,
      stars: typeof stars === "number" && Number.isFinite(stars) ? stars : null,
      archived: parsed["archived"] === true,
      fork: parsed["fork"] === true,
    };
  }

  async #rootManifest(
    coordinate: { owner: string; name: string },
    credential: Secret,
  ): Promise<string | null> {
    const response = await this.#http.request(
      "GET",
      `${this.#baseUrl}/repos/${encodeURIComponent(coordinate.owner)}/${encodeURIComponent(coordinate.name)}/contents/package.json`,
      undefined,
      {
        // Raw, so the body is the manifest rather than a base64 envelope. The
        // JSON form would need decoding before parsing and gains nothing.
        accept: "application/vnd.github.raw",
        authorization: `Bearer ${Secret.reveal(credential)}`,
        "user-agent": this.#userAgent,
        "x-github-api-version": "2022-11-28",
      },
    );

    if (response.status < 200 || response.status >= 300) return null;
    return response.body;
  }
}

/**
 * Maps a manifest failure to a fixed reason.
 *
 * Every branch returns a constant. That is the point: a classifier that falls
 * back to the error's text for an unrecognised case would reintroduce exactly
 * the leak it exists to prevent, on the one path nobody tested.
 */
export function classifyManifestFailure(error: unknown): string {
  if (!(error instanceof ManifestError)) return "unknown";
  const message = error.message;
  if (message.startsWith("Manifest exceeds")) return "too-large";
  if (message.startsWith("Manifest is not valid JSON")) return "not-json";
  if (message.startsWith("Manifest is not a JSON object")) return "not-an-object";
  if (message.startsWith("Manifest declares more than")) return "too-many-dependencies";
  return "rejected";
}

function ownerLogin(record: Record<string, unknown>): string | null {
  const owner = record["owner"];
  if (!isRecord(owner)) return null;
  return stringField(owner, "login");
}

function stringField(record: Record<string, unknown>, key: string): string | null {
  const value = record[key];
  return typeof value === "string" && value !== "" ? value : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
