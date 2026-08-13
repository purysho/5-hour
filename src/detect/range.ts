/**
 * npm version range parsing and satisfaction.
 *
 * This decides who is affected by a change, which decides who gets a pull
 * request. Like `semver.ts` it is written rather than imported, for the same
 * reason: it is a control on fan-out, and a control belongs in code we can
 * read in full.
 *
 * ── The distinction that matters ─────────────────────────────────────────────
 *
 * A declared range does not just say "which versions work". It says whether a
 * consumer will *ever* receive the new one, and that splits the population
 * into two groups needing opposite treatment:
 *
 *   `^2.0.0` will never resolve to 3.0.0. That consumer is **stranded** — they
 *   are fine today and permanently stuck. They are the ones who need a pull
 *   request.
 *
 *   `>=2.0.0` will resolve to 3.0.0 on the next install. That consumer is
 *   **exposed** — their build may already be broken, and they may not know it
 *   yet. Same upstream change, urgent rather than routine.
 *
 * Treating both identically is the most obvious way to get this product wrong:
 * it either spams people who are fine or ignores people who are already
 * failing.
 *
 * Supported syntax: exact versions, `^`, `~`, comparators (`>` `>=` `<` `<=`
 * `=`), x-ranges (`1.x`, `1.2.*`, `*`), hyphen ranges, whitespace as AND, and
 * `||` as OR. Deliberately unsupported: npm tags (`latest`), URLs, git
 * specifiers, and `workspace:` — these are not version ranges, and guessing at
 * them would produce confident nonsense. They parse as `null` and callers must
 * handle that explicitly.
 */

import { compareVersions, parseVersion, tryParseVersion, type Version } from "./semver.ts";

export type Operator = ">" | ">=" | "<" | "<=" | "=";

export interface Comparator {
  readonly operator: Operator;
  readonly version: Version;
}

/** A range is a union (OR) of comparator sets (AND). */
export type ComparatorSet = readonly Comparator[];
export type Range = readonly ComparatorSet[];

const MAX_RANGE_LENGTH = 256;

/**
 * Returns null for anything that is not a version range — a tag, a URL, a git
 * or file specifier, or syntax we do not support. Null means "we cannot reason
 * about this", which callers must treat as unknown rather than as no-match.
 */
export function parseRange(input: string): Range | null {
  const trimmed = input.trim();
  if (trimmed.length === 0) return [[{ operator: ">=", version: parseVersion("0.0.0") }]];
  if (trimmed.length > MAX_RANGE_LENGTH) return null;

  // Not version ranges. Recognised explicitly so they are never mistaken for
  // an unparseable range that might otherwise be guessed at.
  if (/^(npm:|git\+|git:|https?:|file:|link:|workspace:|portal:)/.test(trimmed)) return null;
  if (/^[a-zA-Z][a-zA-Z0-9-]*$/.test(trimmed) && !/^[vV]?\d/.test(trimmed)) return null;

  const unions = trimmed.split("||");
  const parsed: ComparatorSet[] = [];

  for (const union of unions) {
    const set = parseComparatorSet(union.trim());
    if (set === null) return null;
    parsed.push(set);
  }
  return parsed;
}

function parseComparatorSet(input: string): ComparatorSet | null {
  if (input === "" || input === "*" || input === "x" || input === "X") {
    return [{ operator: ">=", version: parseVersion("0.0.0") }];
  }

  // Hyphen range: "1.2.3 - 2.3.4" (spaces around the hyphen are required).
  const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(input);
  if (hyphen) {
    return parseHyphenRange(hyphen[1] as string, hyphen[2] as string);
  }

  const comparators: Comparator[] = [];
  for (const token of input.split(/\s+/).filter(Boolean)) {
    const expanded = parseToken(token);
    if (expanded === null) return null;
    comparators.push(...expanded);
  }
  return comparators.length > 0 ? comparators : null;
}

function parseHyphenRange(from: string, to: string): ComparatorSet | null {
  const lower = tryParseVersion(normalisePartial(from, "0"));
  if (!lower) return null;

  // An upper bound of "2.3" means "< 2.4.0", not "<= 2.3.0".
  const parts = to.replace(/^[vV]/, "").split(".");
  if (parts.length < 3) {
    const major = Number(parts[0]);
    const minor = parts[1] === undefined ? undefined : Number(parts[1]);
    if (!Number.isFinite(major)) return null;
    const bound =
      minor === undefined
        ? `${major + 1}.0.0`
        : `${major}.${minor + 1}.0`;
    const upper = tryParseVersion(bound);
    if (!upper) return null;
    return [
      { operator: ">=", version: lower },
      { operator: "<", version: upper },
    ];
  }

  const upper = tryParseVersion(normalisePartial(to, "0"));
  if (!upper) return null;
  return [
    { operator: ">=", version: lower },
    { operator: "<=", version: upper },
  ];
}

function parseToken(token: string): Comparator[] | null {
  const match = /^(\^|~>?|>=|<=|>|<|=|v)?\s*(.+)$/.exec(token);
  if (!match) return null;
  const prefix = match[1] ?? "";
  const rest = (match[2] as string).trim();

  if (prefix === "^") return caretRange(rest);
  if (prefix === "~" || prefix === "~>") return tildeRange(rest);

  // x-ranges without an operator: 1.x, 1.2.*, 1
  if (prefix === "" || prefix === "v" || prefix === "=") {
    const expanded = xRange(rest);
    if (expanded !== null) return expanded;
    const exact = tryParseVersion(rest);
    return exact ? [{ operator: "=", version: exact }] : null;
  }

  const version = tryParseVersion(normalisePartial(rest, "0"));
  if (!version) return null;
  return [{ operator: prefix as Operator, version }];
}

/**
 * `^` — compatible within the leftmost non-zero component.
 *
 * The 0.x cases are the ones that catch people out, and they are also where
 * the AI SDK ecosystem lives:
 *
 *     ^1.2.3  →  >=1.2.3 <2.0.0
 *     ^0.2.3  →  >=0.2.3 <0.3.0
 *     ^0.0.3  →  >=0.0.3 <0.0.4
 */
function caretRange(input: string): Comparator[] | null {
  const parts = splitPartial(input);
  if (!parts) return null;
  const { major, minor, patch, raw } = parts;
  const lower = tryParseVersion(raw);
  if (!lower) return null;

  let upper: string;
  if (major !== 0) upper = `${major + 1}.0.0`;
  else if (minor !== 0) upper = `0.${minor + 1}.0`;
  else upper = `0.0.${patch + 1}`;

  const upperVersion = tryParseVersion(upper);
  if (!upperVersion) return null;
  return [
    { operator: ">=", version: lower },
    { operator: "<", version: upperVersion },
  ];
}

/** `~` — patch-level changes if a minor is specified. `~1.2.3` → >=1.2.3 <1.3.0 */
function tildeRange(input: string): Comparator[] | null {
  const parts = splitPartial(input);
  if (!parts) return null;
  const { major, minor, specified, raw } = parts;
  const lower = tryParseVersion(raw);
  if (!lower) return null;

  const upper = specified >= 2 ? `${major}.${minor + 1}.0` : `${major + 1}.0.0`;
  const upperVersion = tryParseVersion(upper);
  if (!upperVersion) return null;
  return [
    { operator: ">=", version: lower },
    { operator: "<", version: upperVersion },
  ];
}

function xRange(input: string): Comparator[] | null {
  if (!/^[vV]?\d+(\.(\d+|[xX*]))?(\.(\d+|[xX*]))?$/.test(input)) return null;
  const cleaned = input.replace(/^[vV]/, "");
  const segments = cleaned.split(".");
  const wildcardAt = segments.findIndex((s) => s === "x" || s === "X" || s === "*");
  const specified = wildcardAt === -1 ? segments.length : wildcardAt;
  if (specified === 3) return null; // fully specified — not an x-range

  const major = Number(segments[0]);
  const minor = specified >= 2 ? Number(segments[1]) : 0;
  if (!Number.isFinite(major)) return null;

  const lower = tryParseVersion(`${major}.${minor}.0`);
  const upper = tryParseVersion(specified >= 2 ? `${major}.${minor + 1}.0` : `${major + 1}.0.0`);
  if (!lower || !upper) return null;
  return [
    { operator: ">=", version: lower },
    { operator: "<", version: upper },
  ];
}

interface PartialVersion {
  readonly major: number;
  readonly minor: number;
  readonly patch: number;
  /** How many components the author actually wrote. */
  readonly specified: number;
  readonly raw: string;
}

function splitPartial(input: string): PartialVersion | null {
  const cleaned = input.replace(/^[vV]/, "");
  const [core = "", ...suffix] = cleaned.split(/(?=[-+])/);
  const segments = core.split(".");
  if (segments.length === 0 || segments.length > 3) return null;

  const numbers = segments.map((s) => (s === "x" || s === "X" || s === "*" ? 0 : Number(s)));
  if (numbers.some((n) => !Number.isFinite(n))) return null;

  const specified = segments.findIndex((s) => s === "x" || s === "X" || s === "*");
  return {
    major: numbers[0] ?? 0,
    minor: numbers[1] ?? 0,
    patch: numbers[2] ?? 0,
    specified: specified === -1 ? segments.length : specified,
    raw: `${numbers[0] ?? 0}.${numbers[1] ?? 0}.${numbers[2] ?? 0}${suffix.join("")}`,
  };
}

function normalisePartial(input: string, fill: string): string {
  const cleaned = input.replace(/^[vV]/, "");
  const [core = "", ...suffix] = cleaned.split(/(?=[-+])/);
  const segments = core.split(".");
  while (segments.length < 3) segments.push(fill);
  return segments.join(".") + suffix.join("");
}

export function satisfies(version: Version, range: Range): boolean {
  return range.some((set) => set.every((comparator) => matches(version, comparator)));
}

function matches(version: Version, comparator: Comparator): boolean {
  const order = compareVersions(version, comparator.version);
  switch (comparator.operator) {
    case ">":
      return order > 0;
    case ">=":
      return order >= 0;
    case "<":
      return order < 0;
    case "<=":
      return order <= 0;
    case "=":
      return order === 0;
  }
}

export function satisfiesRaw(version: string, range: string): boolean | null {
  const parsedVersion = tryParseVersion(version);
  const parsedRange = parseRange(range);
  if (!parsedVersion || !parsedRange) return null;
  return satisfies(parsedVersion, parsedRange);
}
