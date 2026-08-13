import { describe, expect, it } from "vitest";
import {
  diffSurfaces,
  isBreakingSurfaceDiff,
  migrationScope,
  surfaceCorroboration,
  type ApiSurface,
  type ExportedSymbol,
} from "../../src/detect/api-surface.ts";
import { assessEligibility } from "../../src/detect/corroborate.ts";

/**
 * API surface diffing.
 *
 * Registry metadata says what the publisher claims; the artifact says what
 * shipped; this says what changed about the interface — the only one of the
 * three that speaks to whether consumers actually break.
 */

function symbol(
  name: string,
  overrides: Partial<ExportedSymbol> = {},
): ExportedSymbol {
  return { name, kind: "function", signature: `(): void`, ...overrides };
}

function surface(version: string, symbols: ExportedSymbol[]): ApiSurface {
  return { packageName: "acme-sdk", version, symbols };
}

describe("detecting breaking surface changes", () => {
  it("flags a removed export", () => {
    const diff = diffSurfaces(
      surface("2.9.1", [symbol("createClient"), symbol("close")]),
      surface("3.0.0", [symbol("close")]),
    );
    expect(diff.removedCount).toBe(1);
    expect(diff.impactedSymbols).toEqual(["createClient"]);
    expect(isBreakingSurfaceDiff(diff)).toBe(true);
  });

  it("flags a changed signature", () => {
    const diff = diffSurfaces(
      surface("2.9.1", [symbol("createClient", { signature: "(url: string): Client" })]),
      surface("3.0.0", [symbol("createClient", { signature: "(options: Options): Client" })]),
    );
    expect(diff.changedCount).toBe(1);
    expect(isBreakingSurfaceDiff(diff)).toBe(true);
  });

  it("flags a symbol that changed kind while keeping its name", () => {
    // `class Foo` becoming `type Foo` breaks every `new Foo()` while the name
    // survives. A name-only comparison misses this entirely.
    const diff = diffSurfaces(
      surface("2.9.1", [symbol("Client", { kind: "class" })]),
      surface("3.0.0", [symbol("Client", { kind: "type" })]),
    );
    expect(diff.changes[0]?.change).toBe("kind-changed");
    expect(isBreakingSurfaceDiff(diff)).toBe(true);
  });

  it("catches a breaking change hiding in a patch release", () => {
    // Far more common than the ecosystem's version numbers suggest, and the
    // reason surface diffing is worth having at all.
    const diff = diffSurfaces(
      surface("1.0.0", [symbol("a"), symbol("b"), symbol("c")]),
      surface("1.0.1", [symbol("a")]),
    );
    expect(diff.removedCount).toBe(2);
    expect(isBreakingSurfaceDiff(diff)).toBe(true);
  });
});

describe("changes that are not breaking", () => {
  it("does not flag added exports", () => {
    // Adding an export cannot break a consumer who was not using it. Treating
    // additions as breaking would flag every feature release in the ecosystem.
    const diff = diffSurfaces(
      surface("1.0.0", [symbol("a")]),
      surface("1.1.0", [symbol("a"), symbol("b")]),
    );
    expect(diff.addedCount).toBe(1);
    expect(isBreakingSurfaceDiff(diff)).toBe(false);
  });

  it("does not flag an identical surface", () => {
    const diff = diffSurfaces(
      surface("1.0.0", [symbol("a")]),
      surface("2.0.0", [symbol("a")]),
    );
    // A major bump with an unchanged surface is a cautious publisher, not a
    // breaking change.
    expect(isBreakingSurfaceDiff(diff)).toBe(false);
    expect(diff.changes).toEqual([]);
  });

  it("records a new deprecation without treating it as breaking", () => {
    const diff = diffSurfaces(
      surface("1.0.0", [symbol("legacy")]),
      surface("1.1.0", [symbol("legacy", { deprecated: true })]),
    );
    expect(diff.changes[0]?.change).toBe("newly-deprecated");
    expect(isBreakingSurfaceDiff(diff)).toBe(false);
  });

  it("does not re-report a deprecation that was already there", () => {
    const diff = diffSurfaces(
      surface("1.0.0", [symbol("legacy", { deprecated: true })]),
      surface("1.1.0", [symbol("legacy", { deprecated: true })]),
    );
    expect(diff.changes).toEqual([]);
  });
});

describe("corroboration output", () => {
  it("produces a spec corroboration for a breaking diff", () => {
    const corroboration = surfaceCorroboration(
      surface("2.9.1", [symbol("createClient")]),
      surface("3.0.0", []),
      "unpkg:acme-sdk/index.d.ts",
    );
    expect(corroboration.kind).toBe("spec");
    expect(corroboration.breaking).toBe(true);
    expect(corroboration.detail).toContain("createClient");
  });

  it("caps the symbol list so a hostile package cannot bloat the record", () => {
    const many = Array.from({ length: 200 }, (_, i) => symbol(`sym${i}`));
    const corroboration = surfaceCorroboration(
      surface("1.0.0", many),
      surface("2.0.0", []),
      "origin",
    );
    expect(corroboration.detail?.length).toBeLessThan(300);
    expect(corroboration.detail).toContain("…");
  });

  it("reports a non-breaking surface honestly", () => {
    const corroboration = surfaceCorroboration(
      surface("1.0.0", [symbol("a")]),
      surface("2.0.0", [symbol("a")]),
      "origin",
    );
    expect(corroboration.breaking).toBe(false);
    expect(corroboration.detail).toContain("no change");
  });
});

describe("migration scope", () => {
  it("requires human guidance when exports were removed", () => {
    // Something must take a removed export's place, and only the publisher
    // knows what. Reporting what broke is safe; inventing a fix is not.
    const scope = migrationScope(
      diffSurfaces(surface("1.0.0", [symbol("gone")]), surface("2.0.0", [])),
    );
    expect(scope.requiresGuidance).toBe(true);
    expect(scope.impactedSymbols).toEqual(["gone"]);
  });

  it("treats signature-only changes as potentially mechanical", () => {
    const scope = migrationScope(
      diffSurfaces(
        surface("1.0.0", [symbol("f", { signature: "(a: string): void" })]),
        surface("2.0.0", [symbol("f", { signature: "(a: string, b?: number): void" })]),
      ),
    );
    expect(scope.requiresGuidance).toBe(false);
  });
});

describe("as the third hard source", () => {
  it("lifts a registry-only signal to high confidence", () => {
    // Registry plus artifact clears the bar at moderate confidence; the spec
    // diff is the independent third source that makes it high.
    const observedAt = new Date().toISOString();
    const eligibility = assessEligibility({
      changeKey: "acme-sdk@3.0.0",
      ecosystem: "npm",
      packageName: "acme-sdk",
      fromVersion: "2.9.1",
      toVersion: "3.0.0",
      corroborations: [
        { kind: "registry", origin: "npm", breaking: true, observedAt },
        { kind: "artifact", origin: "npm", breaking: true, observedAt },
        surfaceCorroboration(
          surface("2.9.1", [symbol("createClient")]),
          surface("3.0.0", []),
          "unpkg",
        ),
      ],
    });
    expect(eligibility.eligible).toBe(true);
    if (!eligibility.eligible) return;
    expect(eligibility.confidence).toBe("high");
  });

  it("dissents when the surface did not actually change", () => {
    // A major bump the registry reports as breaking, contradicted by the
    // interface itself. Hard sources disagreeing means we do not understand
    // the change, and the gate fails closed.
    const observedAt = new Date().toISOString();
    const eligibility = assessEligibility({
      changeKey: "acme-sdk@3.0.0",
      ecosystem: "npm",
      packageName: "acme-sdk",
      fromVersion: "2.9.1",
      toVersion: "3.0.0",
      corroborations: [
        { kind: "registry", origin: "npm", breaking: true, observedAt },
        { kind: "artifact", origin: "npm", breaking: true, observedAt },
        surfaceCorroboration(
          surface("2.9.1", [symbol("createClient")]),
          surface("3.0.0", [symbol("createClient")]),
          "unpkg",
        ),
      ],
    });
    expect(eligibility.eligible).toBe(false);
    if (eligibility.eligible) return;
    expect(eligibility.reason).toBe("sources-disagree");
  });
});
