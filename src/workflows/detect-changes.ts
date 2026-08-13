/**
 * Detection sweep.
 *
 * Turns "packages we watch" into corroborated, eligible change signals. This
 * is the front of the pipeline: nothing downstream runs until a change gets
 * through here, which makes it the cheapest place to stop a bad one.
 *
 * The sweep deliberately does NOT fan out. It produces a persisted
 * `upstream_change` row and a canary-sized target list; scheduling the
 * per-repository migration jobs is a separate decision, taken by a separate
 * workflow, on a separate approval. Detecting and acting in one step would
 * mean a detection bug becomes a fan-out incident with no gate between them.
 *
 * Every external call is inside a `ctx.step`, so a sweep that dies partway
 * through resumes rather than re-querying registries it has already read
 * (ADR-0009).
 */

import { PermanentFailure, type WorkflowContext } from "../workflow/types.ts";
import {
  assessEligibility,
  canarySize,
  type ChangeSignal,
  type Corroboration,
  type Eligibility,
} from "../detect/corroborate.ts";
import { assertValidPackageName, type NpmCollector } from "../detect/npm.ts";
import { parseVersion, type Version } from "../detect/semver.ts";
import {
  diffSurfaces,
  migrationScope,
  surfaceCorroboration,
  type ApiSurface,
} from "../detect/api-surface.ts";

export interface DetectInput extends Record<string, unknown> {
  readonly packageName: string;
  /** Version consumers are currently on — the baseline for the comparison. */
  readonly currentVersion: string;
  readonly ecosystem: "npm";
}

/**
 * Supplies the exported API surface for a published version.
 *
 * Injected because extracting one properly needs the TypeScript compiler, and
 * a regex approximation would silently mis-report (see `api-surface.ts`).
 * Returning null means "we could not determine it" — which costs a
 * corroboration source rather than producing a wrong one.
 */
export interface SurfaceSource {
  surfaceFor(packageName: string, version: string): Promise<ApiSurface | null>;
}

export interface ChangeRecorder {
  /**
   * Persists the change and returns its id. Must be idempotent on
   * `(providerId, changeKey)` — the sweep can legitimately run twice.
   */
  record(input: RecordedChange): Promise<string>;
}

export interface RecordedChange {
  readonly providerId: string;
  readonly changeKey: string;
  readonly ecosystem: string;
  readonly packageName: string;
  readonly fromVersion: string;
  readonly toVersion: string;
  readonly summary: string;
  readonly corroborations: readonly Corroboration[];
  readonly impactedSymbols: readonly string[];
  /** Null until a human approves; see threat-model §5.2. */
  readonly approvedAt: string | null;
}

export interface DetectDeps {
  readonly collector: NpmCollector;
  readonly surfaces: SurfaceSource;
  readonly recorder: ChangeRecorder;
  /** How many downstream repositories are known. Sizes the canary. */
  readonly downstreamCount: (packageName: string) => Promise<number>;
}

export type DetectOutcome =
  | { readonly kind: "no-newer-version" }
  | {
      readonly kind: "not-eligible";
      readonly toVersion: string;
      readonly reason: string;
      readonly detail: string;
    }
  | {
      readonly kind: "eligible";
      readonly changeId: string;
      readonly changeKey: string;
      readonly toVersion: string;
      readonly confidence: "high" | "moderate";
      readonly impactedSymbols: readonly string[];
      readonly canarySize: number;
      readonly requiresApproval: boolean;
    };

export function detectChangesWorkflow(deps: DetectDeps) {
  return async function detectChanges(
    ctx: WorkflowContext,
    rawInput: Record<string, unknown>,
  ): Promise<DetectOutcome> {
    const input = rawInput as DetectInput;

    // Validate before any network call. A malformed package name is a bug or
    // an injection attempt, and neither improves with a retry.
    try {
      assertValidPackageName(input.packageName);
      parseVersion(input.currentVersion);
    } catch (error) {
      throw new PermanentFailure(
        `Invalid detection input: ${(error as Error).message}`,
      );
    }

    const next = await ctx.step("find-next-version", async () => {
      const version = await deps.collector.nextStableAfter(
        input.packageName,
        input.currentVersion,
      );
      return version ? version.raw : null;
    });

    if (next === null) {
      ctx.log("no newer stable version", { package: input.packageName });
      return { kind: "no-newer-version" };
    }

    const toVersion = parseVersion(next);
    const changeKey = `${input.packageName}@${toVersion.raw}`;

    // Each source is its own step. A registry that times out does not cost us
    // the artifact check we already completed.
    const registry = await ctx.step("corroborate-registry", async () =>
      deps.collector.corroborate(input.packageName, input.currentVersion, toVersion.raw),
    );

    const artifact = await ctx.step("corroborate-artifact", async () =>
      deps.collector.corroborateArtifact(input.packageName, toVersion.raw),
    );

    const surface = await ctx.step("corroborate-surface", async () =>
      collectSurface(deps, input.packageName, input.currentVersion, toVersion),
    );

    const corroborations: Corroboration[] = [registry, artifact];
    if (surface.corroboration) corroborations.push(surface.corroboration);

    const signal: ChangeSignal = {
      changeKey,
      ecosystem: input.ecosystem,
      packageName: input.packageName,
      fromVersion: input.currentVersion,
      toVersion: toVersion.raw,
      corroborations,
      // Removed exports have no mechanical replacement, so the migration needs
      // human-authored guidance before anything is generated.
      ...(surface.requiresGuidance ? { introducesCapability: true } : {}),
    };

    const eligibility = assessEligibility(signal);

    if (!eligibility.eligible) {
      ctx.log("change not eligible for fan-out", {
        package: input.packageName,
        to: toVersion.raw,
        reason: eligibility.reason,
      });
      // Recorded even when ineligible. A change we examined and declined is
      // worth keeping: it stops us re-examining it every sweep, and it is the
      // evidence trail if someone later asks why we did nothing.
      await ctx.step("record-ineligible", async () =>
        deps.recorder.record({
          providerId: ctx.providerId,
          changeKey,
          ecosystem: input.ecosystem,
          packageName: input.packageName,
          fromVersion: input.currentVersion,
          toVersion: toVersion.raw,
          summary: `not eligible: ${eligibility.reason}`,
          corroborations,
          impactedSymbols: surface.impactedSymbols,
          approvedAt: null,
        }),
      );
      return {
        kind: "not-eligible",
        toVersion: toVersion.raw,
        reason: eligibility.reason,
        detail: eligibility.detail,
      };
    }

    const changeId = await ctx.step("record-change", async () =>
      deps.recorder.record({
        providerId: ctx.providerId,
        changeKey,
        ecosystem: input.ecosystem,
        packageName: input.packageName,
        fromVersion: input.currentVersion,
        toVersion: toVersion.raw,
        summary: summarise(input.packageName, input.currentVersion, toVersion.raw, surface),
        corroborations,
        impactedSymbols: surface.impactedSymbols,
        // Never self-approving. A change reaches fan-out only after a human
        // approves it, and this workflow is not a human.
        approvedAt: null,
      }),
    );

    const downstream = await ctx.step("count-downstream", async () =>
      deps.downstreamCount(input.packageName),
    );

    ctx.log("change eligible", {
      package: input.packageName,
      to: toVersion.raw,
      confidence: eligibility.confidence,
      downstream,
    });

    return {
      kind: "eligible",
      changeId,
      changeKey,
      toVersion: toVersion.raw,
      confidence: eligibility.confidence,
      impactedSymbols: surface.impactedSymbols,
      canarySize: canarySize(eligibility satisfies Eligibility, downstream),
      requiresApproval: true,
    };
  };
}

interface SurfaceResult {
  readonly corroboration: Corroboration | null;
  readonly impactedSymbols: readonly string[];
  readonly requiresGuidance: boolean;
}

async function collectSurface(
  deps: DetectDeps,
  packageName: string,
  fromVersion: string,
  to: Version,
): Promise<SurfaceResult> {
  const [before, after] = await Promise.all([
    deps.surfaces.surfaceFor(packageName, fromVersion),
    deps.surfaces.surfaceFor(packageName, to.raw),
  ]);

  // Missing declarations are ordinary — plenty of packages ship none. Losing a
  // source is the correct cost; inventing one is not.
  if (!before || !after) {
    return { corroboration: null, impactedSymbols: [], requiresGuidance: false };
  }

  const diff = diffSurfaces(before, after);
  const scope = migrationScope(diff);
  return {
    corroboration: surfaceCorroboration(before, after, `surface:${packageName}`),
    impactedSymbols: diff.impactedSymbols,
    requiresGuidance: scope.requiresGuidance,
  };
}

function summarise(
  packageName: string,
  from: string,
  to: string,
  surface: SurfaceResult,
): string {
  const base = `${packageName} ${from} → ${to}`;
  if (surface.impactedSymbols.length === 0) return `${base}: breaking change`;
  const shown = surface.impactedSymbols.slice(0, 5).join(", ");
  const suffix = surface.impactedSymbols.length > 5 ? ", …" : "";
  return `${base}: affects ${shown}${suffix}`;
}
