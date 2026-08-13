/**
 * Semantic version parsing and comparison.
 *
 * Written rather than taken from a dependency, for a reason specific to this
 * system: version comparison decides whether a change is breaking, which
 * decides whether we open pull requests across thousands of repositories. It
 * is a control, and a control belongs in code we can read in full.
 *
 * It also keeps the dependency surface of the detection path minimal, which
 * matters more here than elsewhere — a compromised dependency in the component
 * that decides what to propagate would be a very efficient supply-chain
 * attack (threat-model §5.2).
 *
 * Implements the SemVer 2.0.0 precedence rules, including the ones people
 * usually get wrong:
 *
 *   - a prerelease has LOWER precedence than its release (1.0.0-rc < 1.0.0)
 *   - numeric prerelease identifiers compare numerically, alphanumeric ones
 *     compare in ASCII order, and numeric always sorts below alphanumeric
 *   - build metadata is ignored entirely for precedence
 *   - below 1.0.0, a MINOR bump is breaking by convention
 */

export interface Version {
  readonly major: number;
  readonly minor: number;
  readonly patch: number;
  readonly prerelease: readonly (string | number)[];
  readonly build: string | null;
  readonly raw: string;
}

export class InvalidVersionError extends Error {
  override readonly name = "InvalidVersionError";
}

const SEMVER =
  /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

/** Longer than any real version; guards against a hostile registry response. */
const MAX_LENGTH = 256;

export function parseVersion(input: string): Version {
  if (input.length > MAX_LENGTH) {
    throw new InvalidVersionError(`Version string exceeds ${MAX_LENGTH} characters`);
  }
  const match = SEMVER.exec(input.trim());
  if (!match) {
    throw new InvalidVersionError(`Not a semantic version: ${JSON.stringify(input)}`);
  }
  const [, major, minor, patch, prerelease, build] = match;
  return {
    major: Number(major),
    minor: Number(minor),
    patch: Number(patch),
    prerelease: prerelease
      ? prerelease.split(".").map((part) => (/^\d+$/.test(part) ? Number(part) : part))
      : [],
    build: build ?? null,
    raw: input.trim(),
  };
}

export function tryParseVersion(input: string): Version | null {
  try {
    return parseVersion(input);
  } catch {
    return null;
  }
}

/** Negative if a < b, positive if a > b, zero if equal precedence. */
export function compareVersions(a: Version, b: Version): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  if (a.patch !== b.patch) return a.patch - b.patch;

  // A version with a prerelease has lower precedence than one without.
  const aPre = a.prerelease.length > 0;
  const bPre = b.prerelease.length > 0;
  if (aPre && !bPre) return -1;
  if (!aPre && bPre) return 1;
  if (!aPre && !bPre) return 0;

  const length = Math.max(a.prerelease.length, b.prerelease.length);
  for (let i = 0; i < length; i++) {
    const left = a.prerelease[i];
    const right = b.prerelease[i];
    // A larger set of identifiers takes precedence, all else equal.
    if (left === undefined) return -1;
    if (right === undefined) return 1;

    const leftNumeric = typeof left === "number";
    const rightNumeric = typeof right === "number";
    if (leftNumeric && rightNumeric) {
      if (left !== right) return left - right;
      continue;
    }
    // Numeric identifiers always have lower precedence than alphanumeric.
    if (leftNumeric) return -1;
    if (rightNumeric) return 1;
    if (left !== right) return left < right ? -1 : 1;
  }
  return 0;
}

export type BumpKind = "major" | "minor" | "patch" | "prerelease" | "none" | "downgrade";

export function classifyBump(from: Version, to: Version): BumpKind {
  const order = compareVersions(from, to);
  if (order === 0) return "none";
  if (order > 0) return "downgrade";

  if (to.major !== from.major) return "major";
  if (to.minor !== from.minor) return "minor";
  if (to.patch !== from.patch) return "patch";
  return "prerelease";
}

/**
 * Whether a version transition is breaking by semver convention alone.
 *
 * Convention is evidence, not proof. This answers "does the version number
 * claim a breaking change?", which is one input to corroboration — never the
 * decision itself. Publishers routinely ship breaking changes in patch
 * releases, and equally often bump majors for nothing.
 */
export function isBreakingBump(from: Version, to: Version): boolean {
  const kind = classifyBump(from, to);
  if (kind === "major") return true;

  // Below 1.0.0 the major is pinned at zero and the minor carries breaking
  // changes. Callers treating 0.x like 1.x under-detect exactly where churn is
  // highest — which, in the AI SDK ecosystem, is most of it.
  if (kind === "minor" && from.major === 0 && to.major === 0) return true;

  return false;
}

/** Highest-precedence version in a list. Unparseable entries are skipped. */
export function latestVersion(versions: readonly string[]): Version | null {
  let best: Version | null = null;
  for (const candidate of versions) {
    const parsed = tryParseVersion(candidate);
    if (!parsed) continue;
    if (best === null || compareVersions(parsed, best) > 0) best = parsed;
  }
  return best;
}

/** Stable releases only — prereleases excluded. */
export function latestStableVersion(versions: readonly string[]): Version | null {
  return latestVersion(versions.filter((v) => {
    const parsed = tryParseVersion(v);
    return parsed !== null && parsed.prerelease.length === 0;
  }));
}
