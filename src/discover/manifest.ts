/**
 * Reading a downstream repository's manifest and lockfile.
 *
 * The other half of downstream discovery: `affected.ts` decides what a
 * declared range *means* for a given change; this decides what was declared.
 *
 * ── Why a targeted extractor is acceptable here and is not in `dts-surface` ──
 *
 * `api-surface.ts` refuses to parse declarations with regular expressions,
 * because an approximation there produces a wrong answer about whether a
 * change is breaking — and that answer opens or withholds thousands of pull
 * requests.
 *
 * Lockfiles are a different shape of problem. The manifest is JSON and is
 * parsed properly. The lockfile contributes only `lockedVersion`, which is
 * *additional* evidence: `assessRepository` reaches its verdict from the declared
 * range alone, and a resolved version only sharpens it. So an extractor that
 * finds the version in the common formats and returns null for everything else
 * costs a piece of evidence when it fails, rather than producing a wrong one —
 * the same trade `NpmSurfaceSource` makes, and the same reason it is safe.
 *
 * Writing a YAML parser to do better would mean writing a YAML parser for
 * attacker-authored input, which is a considerably worse trade.
 *
 * ── Everything here is attacker-authored ────────────────────────────────────
 *
 * A `package.json` comes from a repository, which is threat-model §5.1
 * territory. Package names are validated rather than trusted, sizes are
 * bounded, and every range is carried verbatim rather than interpreted — an
 * unparseable range becomes `unknown` downstream, which is a refusal to guess.
 */

import { assertValidPackageName } from "../detect/npm.ts";
import type { DeclaredDependency, DependencyKind } from "./affected.ts";

export class ManifestError extends Error {
  override readonly name = "ManifestError";
}

const DEPENDENCY_FIELDS: readonly DependencyKind[] = Object.freeze([
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "optionalDependencies",
]);

export interface ManifestLimits {
  readonly maxBytes?: number;
  readonly maxDependencies?: number;
}

const DEFAULT_MAX_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAX_DEPENDENCIES = 5_000;

export interface ParsedManifest {
  readonly name: string | null;
  readonly dependencies: readonly DeclaredDependency[];
  /** Names that were not usable. Kept so a skip is visible rather than silent. */
  readonly skipped: readonly string[];
}

/**
 * Parses a `package.json` into declared dependencies.
 *
 * A dependency declared in more than one field appears once, under the first
 * field it was found in. The order in `DEPENDENCY_FIELDS` is deliberate:
 * `dependencies` before `devDependencies` before the rest, so a package that
 * is both a runtime and a development dependency is treated as the runtime one
 * — which is the reading that matters for whether consumers break.
 */
export function parseManifest(source: string, limits: ManifestLimits = {}): ParsedManifest {
  const maxBytes = limits.maxBytes ?? DEFAULT_MAX_BYTES;
  const maxDependencies = limits.maxDependencies ?? DEFAULT_MAX_DEPENDENCIES;

  if (Buffer.byteLength(source, "utf8") > maxBytes) {
    throw new ManifestError(`Manifest exceeds ${maxBytes} bytes`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch (error) {
    throw new ManifestError(`Manifest is not valid JSON: ${(error as Error).message}`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new ManifestError("Manifest is not a JSON object");
  }

  const record = parsed as Record<string, unknown>;
  const dependencies: DeclaredDependency[] = [];
  const seen = new Set<string>();
  const skipped: string[] = [];

  for (const kind of DEPENDENCY_FIELDS) {
    const field = record[kind];
    if (typeof field !== "object" || field === null || Array.isArray(field)) continue;

    for (const [packageName, range] of Object.entries(field as Record<string, unknown>)) {
      if (dependencies.length >= maxDependencies) {
        throw new ManifestError(`Manifest declares more than ${maxDependencies} dependencies`);
      }
      if (seen.has(packageName)) continue;
      // A range is carried verbatim, but it still has to be a string — an
      // object here would reach `parseRange` as something it cannot refuse
      // cleanly.
      if (typeof range !== "string") {
        skipped.push(packageName);
        continue;
      }
      if (!isUsableName(packageName)) {
        skipped.push(packageName);
        continue;
      }

      seen.add(packageName);
      dependencies.push({ packageName, range, kind });
    }
  }

  const name = typeof record["name"] === "string" ? record["name"] : null;
  return { name, dependencies, skipped };
}

function isUsableName(name: string): boolean {
  // `__proto__` and friends arrive as ordinary own properties from JSON.parse
  // rather than polluting anything, but they are not package names and
  // carrying them forward invites a later `{}[name]` lookup to misbehave.
  if (name === "__proto__" || name === "constructor" || name === "prototype") return false;
  try {
    assertValidPackageName(name);
    return true;
  } catch {
    return false;
  }
}

/**
 * Finds the version a lockfile resolved a package to.
 *
 * Returns null whenever the answer is not unambiguous — an unrecognised
 * format, a package that appears at several versions, a value that is not a
 * version. Null costs evidence; a wrong version would produce a confident
 * wrong impact classification, which is worse.
 */
export function lockedVersion(
  lockfile: { readonly filename: string; readonly content: string },
  packageName: string,
  limits: ManifestLimits = {},
): string | null {
  const maxBytes = limits.maxBytes ?? 32 * 1024 * 1024;
  if (Buffer.byteLength(lockfile.content, "utf8") > maxBytes) return null;
  if (!isUsableName(packageName)) return null;

  const base = lockfile.filename.split("/").pop() ?? lockfile.filename;

  if (base === "package-lock.json" || base === "npm-shrinkwrap.json") {
    return fromNpmLock(lockfile.content, packageName);
  }
  if (base === "pnpm-lock.yaml") {
    return fromPnpmLock(lockfile.content, packageName);
  }
  if (base === "yarn.lock") {
    return fromYarnLock(lockfile.content, packageName);
  }
  return null;
}

/**
 * npm's lockfile is JSON, so this one is parsed properly.
 *
 * v2 and v3 key `packages` by install path; v1 nests under `dependencies`. A
 * package installed at several paths — the normal outcome of two dependents
 * wanting incompatible versions — resolves to null rather than to whichever
 * copy happened to be first.
 */
function fromNpmLock(content: string, packageName: string): string | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const record = parsed as Record<string, unknown>;

  const found = new Set<string>();

  const packages = record["packages"];
  if (typeof packages === "object" && packages !== null) {
    for (const [path, entry] of Object.entries(packages as Record<string, unknown>)) {
      // Only a top-level install counts. `node_modules/a/node_modules/b` is a
      // nested copy for one dependent, not what the repository resolves to.
      if (path !== `node_modules/${packageName}`) continue;
      const version = (entry as Record<string, unknown> | null)?.["version"];
      if (typeof version === "string") found.add(version);
    }
  }

  if (found.size === 0) {
    const v1 = record["dependencies"];
    if (typeof v1 === "object" && v1 !== null) {
      const entry = (v1 as Record<string, unknown>)[packageName];
      const version = (entry as Record<string, unknown> | null)?.["version"];
      if (typeof version === "string") found.add(version);
    }
  }

  return found.size === 1 ? [...found][0]! : null;
}

/**
 * pnpm keys its `packages` map by an identifier that has changed shape across
 * lockfile versions: `/acme-sdk/1.4.2`, `/acme-sdk@1.4.2`, and scoped variants
 * of both. Matching all of them is a small, bounded thing; parsing the YAML
 * around them is not.
 */
function fromPnpmLock(content: string, packageName: string): string | null {
  const escaped = escapeRegExp(packageName);
  const patterns = [
    new RegExp(`^\\s*/${escaped}@(${VERSION_SOURCE})[:(]`, "gm"),
    new RegExp(`^\\s*/${escaped}/(${VERSION_SOURCE})[:(]`, "gm"),
    new RegExp(`^\\s*'?${escaped}@(${VERSION_SOURCE})'?:`, "gm"),
  ];

  const found = new Set<string>();
  for (const pattern of patterns) {
    for (const match of content.matchAll(pattern)) {
      if (match[1]) found.add(match[1]);
    }
  }
  return found.size === 1 ? [...found][0]! : null;
}

/**
 * Classic yarn.lock is a bespoke format: one or more quoted specifiers, then
 * an indented `version "x.y.z"`. Berry's is YAML-shaped but keeps the same
 * two lines, so the same extraction finds both.
 */
function fromYarnLock(content: string, packageName: string): string | null {
  const escaped = escapeRegExp(packageName);
  // A specifier line naming this package, then the first `version` line under
  // it. `[^:\n]*` stops the specifier match from running past its own line.
  const pattern = new RegExp(
    `^"?${escaped}@[^\\n]*:\\n(?:[ \\t]+[^\\n]*\\n)*?[ \\t]+version:?\\s+"?(${VERSION_SOURCE})"?`,
    "gm",
  );

  const found = new Set<string>();
  for (const match of content.matchAll(pattern)) {
    if (match[1]) found.add(match[1]);
  }
  return found.size === 1 ? [...found][0]! : null;
}

/** Deliberately strict: anything that is not a plain version is not an answer. */
const VERSION_SOURCE = "\\d+\\.\\d+\\.\\d+(?:-[0-9A-Za-z.-]+)?(?:\\+[0-9A-Za-z.-]+)?";

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
