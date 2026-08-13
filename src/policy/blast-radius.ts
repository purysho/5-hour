/**
 * Blast radius derivation (ADR-0003 layer 3).
 *
 * `PolicyContext.blastRadius` is the rule that stops a prompt injection from
 * steering the agent into an unrelated file — but until now nothing produced
 * it, so it was a parameter with no source. This closes that loop: the set of
 * symbols an upstream change impacts (from `api-surface.ts`) becomes the set
 * of files a migration is permitted to touch.
 *
 * ── The property this must have ──────────────────────────────────────────────
 *
 * The blast radius is an upper bound on where the agent may write. That makes
 * its failure modes asymmetric:
 *
 *   Too wide — an injection gains room to work. A security failure.
 *   Too narrow — a legitimate migration is rejected. An annoyance.
 *
 * So the matching is deliberately generous about *including* a file and strict
 * about how a file gets included: a file is in scope if it plausibly
 * references an impacted symbol, and file inclusion is never derived from
 * anything the agent produced. The bound is computed before the agent runs and
 * is not negotiable afterwards.
 *
 * ── Why identifier matching rather than parsing ──────────────────────────────
 *
 * Resolving which files truly reference a symbol needs per-language semantic
 * analysis across every ecosystem we support. Identifier occurrence with word
 * boundaries is language-agnostic, cheap, and errs toward including files —
 * which is the safe direction for a *candidate* set that a human-authored
 * migration then narrows.
 *
 * It is emphatically not a semantic claim. A file containing the word
 * `createClient` in a comment is in the radius. That is fine: being in the
 * radius permits an edit, it does not require one.
 */

export interface SourceFile {
  readonly path: string;
  readonly content: string;
}

export interface BlastRadiusOptions {
  /** Files the migration may always touch, e.g. the manifest being bumped. */
  readonly alwaysInclude?: readonly string[];
  /** Cap on files. A migration wider than this is escalated, not widened. */
  readonly maxFiles?: number;
  /** Extensions considered source. Everything else is excluded by default. */
  readonly sourceExtensions?: readonly string[];
}

const DEFAULT_SOURCE_EXTENSIONS: readonly string[] = Object.freeze([
  ".ts", ".tsx", ".mts", ".cts",
  ".js", ".jsx", ".mjs", ".cjs",
  ".vue", ".svelte",
  ".py", ".rb", ".go", ".rs", ".java", ".kt", ".cs", ".php",
]);

/**
 * Paths never included, regardless of content.
 *
 * These are the shapes the diff policy rejects outright anyway
 * (`ci-configuration`, `lockfile-provenance`), so admitting them to the radius
 * would only produce diffs that are generated and then thrown away — while
 * widening the space an injection has to work in.
 */
const NEVER_INCLUDE: readonly RegExp[] = Object.freeze([
  /^\.github\//,
  /^\.gitlab-ci\.ya?ml$/,
  /^\.circleci\//,
  /(^|\/)Dockerfile(\.|$)/,
  /^Jenkinsfile$/,
  /(^|\/)node_modules\//,
  /(^|\/)vendor\//,
  /(^|\/)\.git\//,
  /(^|\/)dist\//,
  /(^|\/)build\//,
]);

export interface BlastRadius {
  readonly files: readonly string[];
  /** Which impacted symbols were found, and where. For the PR body. */
  readonly matches: ReadonlyMap<string, readonly string[]>;
  readonly truncated: boolean;
}

export function deriveBlastRadius(
  files: readonly SourceFile[],
  impactedSymbols: readonly string[],
  options: BlastRadiusOptions = {},
): BlastRadius {
  const maxFiles = options.maxFiles ?? 50;
  const extensions = options.sourceExtensions ?? DEFAULT_SOURCE_EXTENSIONS;
  const alwaysInclude = new Set(options.alwaysInclude ?? []);

  const matches = new Map<string, string[]>();
  const selected: string[] = [];

  // Built once. Symbol names come from published declarations, so they are
  // escaped rather than trusted — a "symbol" containing regex metacharacters
  // would otherwise become a pattern of the publisher's choosing.
  const patterns = impactedSymbols
    .filter(isPlausibleIdentifier)
    .map((symbol) => ({ symbol, pattern: identifierPattern(symbol) }));

  for (const file of files) {
    if (NEVER_INCLUDE.some((deny) => deny.test(file.path))) continue;

    if (alwaysInclude.has(file.path)) {
      selected.push(file.path);
      continue;
    }

    if (!extensions.some((extension) => file.path.endsWith(extension))) continue;

    const found: string[] = [];
    for (const { symbol, pattern } of patterns) {
      pattern.lastIndex = 0;
      if (pattern.test(file.content)) found.push(symbol);
    }

    if (found.length > 0) {
      selected.push(file.path);
      for (const symbol of found) {
        const existing = matches.get(symbol);
        if (existing) existing.push(file.path);
        else matches.set(symbol, [file.path]);
      }
    }
  }

  // Files that were requested unconditionally but absent from the tree are
  // still permitted — a migration may create a file that does not yet exist.
  for (const path of alwaysInclude) {
    if (!selected.includes(path)) selected.push(path);
  }

  const sorted = [...new Set(selected)].sort();
  const truncated = sorted.length > maxFiles;

  return {
    // Truncation narrows rather than widens. A migration touching more files
    // than the cap is escalated by the diff-scale rule, which is the correct
    // outcome — the alternative is granting an injection a larger canvas.
    files: truncated ? sorted.slice(0, maxFiles) : sorted,
    matches: new Map([...matches].map(([k, v]) => [k, [...new Set(v)].sort()])),
    truncated,
  };
}

/**
 * Rejects anything that is not a bare identifier.
 *
 * Symbol names arrive from published package declarations, which are
 * publisher-controlled. Without this, a "symbol" such as `.*` would match
 * every file in the repository and hand an attacker a repository-wide blast
 * radius — turning the control into its own bypass.
 */
function isPlausibleIdentifier(symbol: string): boolean {
  return /^[A-Za-z_$][A-Za-z0-9_$]{0,127}$/.test(symbol);
}

function identifierPattern(symbol: string): RegExp {
  // Identifier characters are excluded on both sides so `Client` does not
  // match `HttpClientFactory`. `\b` alone is wrong here: it treats `$` and
  // `_` as boundaries, and both are legal in identifiers.
  return new RegExp(`(?<![A-Za-z0-9_$])${escapeRegExp(symbol)}(?![A-Za-z0-9_$])`, "g");
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
