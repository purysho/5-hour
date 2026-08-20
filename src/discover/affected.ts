/**
 * Downstream impact classification.
 *
 * Given an upstream change and a repository's declared dependency, decides
 * whether that repository is affected and — crucially — *how*.
 *
 * ── Why "affected" is not one thing ──────────────────────────────────────────
 *
 * The obvious model is binary: does this repo depend on the package, yes or
 * no. It is wrong, and getting it wrong is the most direct route to this
 * product being annoying instead of useful.
 *
 * A consumer declaring `^2.0.0` will never resolve to 3.0.0. Nothing is
 * broken. Nothing will break. They are simply stuck on a version that stops
 * receiving fixes, and they will stay stuck indefinitely because no signal
 * ever reaches them. That is the population this product exists for, and the
 * appropriate response is a pull request they can take at their leisure.
 *
 * A consumer declaring `>=2.0.0` resolves to 3.0.0 on their next install. Same
 * upstream change, entirely different situation: their build may already be
 * failing, and the pull request is a fix rather than an upgrade.
 *
 * A consumer already on 3.0.0 needs nothing, and sending them anything at all
 * costs credibility we cannot spare.
 *
 * So impact is a classification, not a boolean, and each class gets different
 * urgency, different pull request framing, and different fan-out priority.
 */

import { compareVersions, parseVersion, tryParseVersion, type Version } from "../detect/semver.ts";
import { parseRange, satisfies } from "../detect/range.ts";

export type Impact =
  /** Range excludes the new version. Stuck, not broken. The core case. */
  | "stranded"
  /** Range admits the new version. May already be broken. */
  | "exposed"
  /** Already resolves to the new version or later. Nothing to do. */
  | "current"
  /** Declared range cannot admit the old version either — not our change. */
  | "unrelated"
  /** Not a version range we can reason about (tag, git URL, workspace). */
  | "unknown";

export type DependencyKind =
  | "dependencies"
  | "devDependencies"
  | "peerDependencies"
  | "optionalDependencies";

export interface DeclaredDependency {
  readonly packageName: string;
  /** Verbatim from the manifest. May not be a version range at all. */
  readonly range: string;
  readonly kind: DependencyKind;
}

export interface RepositoryCandidate {
  readonly forge: string;
  readonly owner: string;
  readonly name: string;
  readonly defaultBranch?: string;
  readonly dependencies: readonly DeclaredDependency[];
  /** Resolved version from a lockfile, when we have one. Strongest evidence. */
  readonly lockedVersion?: string;
  readonly stars?: number;
  readonly archived?: boolean;
  readonly fork?: boolean;
}

export interface Assessment {
  readonly impact: Impact;
  readonly kind: DependencyKind | null;
  readonly declaredRange: string | null;
  readonly detail: string;
}

export interface ChangeUnderTest {
  readonly packageName: string;
  readonly fromVersion: string;
  readonly toVersion: string;
}

export function assessRepository(
  repository: RepositoryCandidate,
  change: ChangeUnderTest,
): Assessment {
  const declared = repository.dependencies.find(
    (dependency) => dependency.packageName === change.packageName,
  );

  if (!declared) {
    return {
      impact: "unrelated",
      kind: null,
      declaredRange: null,
      detail: "repository does not declare this package",
    };
  }

  const to = parseVersion(change.toVersion);

  // A lockfile is stronger evidence than a declared range: it says what is
  // actually installed rather than what would be permitted.
  const locked = repository.lockedVersion ? tryParseVersion(repository.lockedVersion) : null;
  if (locked && compareVersions(locked, to) >= 0) {
    return {
      impact: "current",
      kind: declared.kind,
      declaredRange: declared.range,
      detail: `lockfile already resolves to ${locked.raw}`,
    };
  }

  const range = parseRange(declared.range);
  if (range === null) {
    // A git URL, a tag, or a workspace protocol. We cannot reason about it,
    // and guessing would produce confident nonsense. Left for a human.
    return {
      impact: "unknown",
      kind: declared.kind,
      declaredRange: declared.range,
      detail: `"${truncate(declared.range)}" is not a version range we can evaluate`,
    };
  }

  const from = parseVersion(change.fromVersion);
  const admitsOld = satisfies(from, range);
  const admitsNew = satisfies(to, range);

  if (admitsNew) {
    // Their next install takes the new version. If they are already on it,
    // they are current; otherwise they are one `npm install` from finding out.
    if (locked && compareVersions(locked, to) >= 0) {
      return {
        impact: "current",
        kind: declared.kind,
        declaredRange: declared.range,
        detail: "range admits the new version and the lockfile is already there",
      };
    }
    return {
      impact: "exposed",
      kind: declared.kind,
      declaredRange: declared.range,
      detail: `"${truncate(declared.range)}" admits ${to.raw}; the next install takes the breaking change`,
    };
  }

  if (!admitsOld) {
    return {
      impact: "unrelated",
      kind: declared.kind,
      declaredRange: declared.range,
      detail: `"${truncate(declared.range)}" admits neither ${from.raw} nor ${to.raw}`,
    };
  }

  return {
    impact: "stranded",
    kind: declared.kind,
    declaredRange: declared.range,
    detail: `"${truncate(declared.range)}" excludes ${to.raw}; this repository will never receive it`,
  };
}

export interface EligibilityRules {
  /** Skip archived repositories — a pull request there reaches nobody. */
  readonly skipArchived?: boolean;
  /** Skip forks; the upstream is the meaningful target. */
  readonly skipForks?: boolean;
  /** Which dependency kinds are worth a pull request. */
  readonly kinds?: readonly DependencyKind[];
  readonly impacts?: readonly Impact[];
}

const DEFAULT_KINDS: readonly DependencyKind[] = Object.freeze([
  "dependencies",
  "devDependencies",
  "peerDependencies",
]);

const DEFAULT_IMPACTS: readonly Impact[] = Object.freeze(["stranded", "exposed"]);

export interface TargetDecision {
  readonly repository: RepositoryCandidate;
  readonly assessment: Assessment;
  readonly targeted: boolean;
  readonly skipReason: string | null;
}

/**
 * Applies eligibility rules on top of the assessment.
 *
 * Separate from `assessRepository` on purpose: the assessment is a factual
 * claim about the repository, while eligibility is policy about who we choose
 * to contact. Mixing them makes it impossible to audit either.
 */
export function decideTarget(
  repository: RepositoryCandidate,
  change: ChangeUnderTest,
  rules: EligibilityRules = {},
): TargetDecision {
  const assessment = assessRepository(repository, change);
  const kinds = rules.kinds ?? DEFAULT_KINDS;
  const impacts = rules.impacts ?? DEFAULT_IMPACTS;

  const skip = (reason: string): TargetDecision => ({
    repository,
    assessment,
    targeted: false,
    skipReason: reason,
  });

  if ((rules.skipArchived ?? true) && repository.archived) {
    return skip("repository is archived");
  }
  if ((rules.skipForks ?? true) && repository.fork) {
    return skip("repository is a fork");
  }
  if (!impacts.includes(assessment.impact)) {
    // The detail travels with the verdict. "unrelated" is reached two ways —
    // the repository does not declare the package at all, or it declares a
    // range admitting neither version — and they are not the same problem:
    // the first means this repository was never a consumer, the second means
    // it is pinned somewhere the change cannot reach it. Reporting only the
    // impact makes a rollout that skipped everything unattributable, which is
    // how a stale manifest and a correct skip come to look identical.
    return skip(`impact "${assessment.impact}" is not targeted: ${assessment.detail}`);
  }
  if (assessment.kind !== null && !kinds.includes(assessment.kind)) {
    return skip(`dependency kind "${assessment.kind}" is not targeted`);
  }

  return { repository, assessment, targeted: true, skipReason: null };
}

/**
 * Orders targets for staged fan-out.
 *
 * `exposed` before `stranded`, because an exposed repository may already be
 * broken. Within a class, fewer stars first: a mistake on a small repository
 * is a smaller mistake, and the canary should carry the cheapest failures.
 * Sending the first wave to the most-watched repositories in the ecosystem is
 * exactly backwards.
 */
export function prioritise(targets: readonly TargetDecision[]): TargetDecision[] {
  const rank: Record<Impact, number> = {
    exposed: 0,
    stranded: 1,
    unknown: 2,
    current: 3,
    unrelated: 4,
  };
  return [...targets].sort((a, b) => {
    const byImpact = rank[a.assessment.impact] - rank[b.assessment.impact];
    if (byImpact !== 0) return byImpact;
    return (a.repository.stars ?? 0) - (b.repository.stars ?? 0);
  });
}

function truncate(value: string, limit = 60): string {
  return value.length <= limit ? value : `${value.slice(0, limit)}…`;
}
