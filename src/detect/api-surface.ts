/**
 * API surface diffing — the third hard corroboration source.
 *
 * Registry metadata says what the publisher *claims*. The artifact says what
 * *shipped*. This says what actually *changed about the interface*, which is
 * the only one of the three that speaks to whether consumers will break.
 *
 * A major version bump with an identical export surface is a publisher being
 * cautious. A patch release that deletes three exported functions is a
 * breaking change wearing a disguise — and the second is far more common than
 * the ecosystem's version numbers would suggest.
 *
 * ── Why this takes a structured surface rather than parsing .d.ts ────────────
 *
 * Extracting an API surface from TypeScript declarations properly requires a
 * real compiler. Doing it with regular expressions produces something that
 * looks right on the examples you tested and silently mis-reports on
 * conditional types, declaration merging, re-exports, and overloads.
 *
 * Since this decides whether thousands of pull requests get opened, a
 * plausible-looking approximation is worse than no answer. So extraction is
 * the caller's problem — supplied by the TypeScript compiler API in
 * production, and by fixtures in tests — and this module owns the part that is
 * genuinely subtle: deciding what a difference *means*.
 *
 * It also produces the impacted symbol set, which is what the diff policy's
 * blast radius is ultimately derived from (ADR-0003 layer 3).
 */

import type { Corroboration } from "./corroborate.ts";

export type SymbolKind =
  | "function"
  | "class"
  | "interface"
  | "type"
  | "const"
  | "enum"
  | "namespace";

export interface ExportedSymbol {
  readonly name: string;
  readonly kind: SymbolKind;
  /**
   * Normalised signature. Compared as an opaque string — this module does not
   * attempt to understand type compatibility, only whether the declaration
   * changed at all.
   */
  readonly signature: string;
  /** Marked deprecated in the source declaration. */
  readonly deprecated?: boolean;
}

export interface ApiSurface {
  readonly packageName: string;
  readonly version: string;
  readonly symbols: readonly ExportedSymbol[];
}

export type SurfaceChangeKind =
  | "removed"
  | "kind-changed"
  | "signature-changed"
  | "newly-deprecated"
  | "added";

export interface SurfaceChange {
  readonly symbol: string;
  readonly change: SurfaceChangeKind;
  readonly detail: string;
}

export interface SurfaceDiff {
  readonly changes: readonly SurfaceChange[];
  /** Symbols whose disappearance or change can break a consumer. */
  readonly impactedSymbols: readonly string[];
  readonly removedCount: number;
  readonly changedCount: number;
  readonly addedCount: number;
}

/**
 * Changes that break consumers, in the order of how unambiguous they are.
 *
 * `added` is deliberately absent: adding an export cannot break a consumer
 * who was not using it, and treating additions as breaking would flag every
 * feature release in the ecosystem.
 */
const BREAKING_CHANGES: readonly SurfaceChangeKind[] = Object.freeze([
  "removed",
  "kind-changed",
  "signature-changed",
]);

export function diffSurfaces(from: ApiSurface, to: ApiSurface): SurfaceDiff {
  const before = new Map(from.symbols.map((symbol) => [symbol.name, symbol]));
  const after = new Map(to.symbols.map((symbol) => [symbol.name, symbol]));
  const changes: SurfaceChange[] = [];

  for (const [name, previous] of before) {
    const current = after.get(name);

    if (!current) {
      changes.push({
        symbol: name,
        change: "removed",
        detail: `${previous.kind} "${name}" is no longer exported`,
      });
      continue;
    }

    // A symbol changing kind is a rename in disguise — `class Foo` becoming
    // `type Foo` breaks every `new Foo()` while the name survives, so a
    // name-only comparison would miss it entirely.
    if (current.kind !== previous.kind) {
      changes.push({
        symbol: name,
        change: "kind-changed",
        detail: `"${name}" changed from ${previous.kind} to ${current.kind}`,
      });
      continue;
    }

    if (current.signature !== previous.signature) {
      changes.push({
        symbol: name,
        change: "signature-changed",
        detail: `signature of ${current.kind} "${name}" changed`,
      });
      continue;
    }

    if (current.deprecated === true && previous.deprecated !== true) {
      // Not breaking today. Recorded because it predicts the removal, and
      // migrating ahead of it is the whole point of the product.
      changes.push({
        symbol: name,
        change: "newly-deprecated",
        detail: `${current.kind} "${name}" is newly deprecated`,
      });
    }
  }

  for (const [name, current] of after) {
    if (!before.has(name)) {
      changes.push({
        symbol: name,
        change: "added",
        detail: `${current.kind} "${name}" is newly exported`,
      });
    }
  }

  const impacted = changes
    .filter((change) => BREAKING_CHANGES.includes(change.change))
    .map((change) => change.symbol);

  return {
    changes,
    impactedSymbols: [...new Set(impacted)].sort(),
    removedCount: changes.filter((c) => c.change === "removed").length,
    changedCount: changes.filter(
      (c) => c.change === "signature-changed" || c.change === "kind-changed",
    ).length,
    addedCount: changes.filter((c) => c.change === "added").length,
  };
}

export function isBreakingSurfaceDiff(diff: SurfaceDiff): boolean {
  return diff.impactedSymbols.length > 0;
}

/**
 * Converts a surface diff into a corroboration record.
 *
 * Weighted as `spec` by the gate — harder to forge than a changelog, since it
 * derives from the published declarations, but softer than the artifact
 * itself.
 */
export function surfaceCorroboration(
  from: ApiSurface,
  to: ApiSurface,
  origin: string,
): Corroboration {
  const diff = diffSurfaces(from, to);
  return {
    kind: "spec",
    origin,
    breaking: isBreakingSurfaceDiff(diff),
    observedAt: new Date().toISOString(),
    detail: describeSurfaceDiff(diff),
  };
}

function describeSurfaceDiff(diff: SurfaceDiff): string {
  if (diff.impactedSymbols.length === 0) {
    return diff.addedCount > 0
      ? `${diff.addedCount} export(s) added, none removed or changed`
      : "no change to the exported surface";
  }
  const parts: string[] = [];
  if (diff.removedCount > 0) parts.push(`${diff.removedCount} export(s) removed`);
  if (diff.changedCount > 0) parts.push(`${diff.changedCount} signature(s) changed`);
  // Symbol names come from published declarations and are bounded in length,
  // but the list is capped so a hostile package cannot produce an unbounded
  // audit record.
  const sample = diff.impactedSymbols.slice(0, 8).join(", ");
  const suffix = diff.impactedSymbols.length > 8 ? ", …" : "";
  return `${parts.join("; ")} (${sample}${suffix})`;
}

/**
 * The migration a consumer would need, derived from the surface diff.
 *
 * Deliberately conservative about what it claims. A removed export needs
 * human-authored guidance about its replacement — this reports *what* broke,
 * never invents *how* to fix it, because a plausible-sounding wrong migration
 * is worse than no migration.
 */
export interface MigrationScope {
  readonly impactedSymbols: readonly string[];
  readonly requiresGuidance: boolean;
  readonly reason: string;
}

export function migrationScope(diff: SurfaceDiff): MigrationScope {
  const removed = diff.changes.filter((c) => c.change === "removed");
  return {
    impactedSymbols: diff.impactedSymbols,
    // Removals cannot be migrated mechanically — something must take their
    // place, and only the publisher knows what.
    requiresGuidance: removed.length > 0,
    reason:
      removed.length > 0
        ? `${removed.length} export(s) removed with no mechanical replacement`
        : "changes are signature-level and may be mechanically migratable",
  };
}
