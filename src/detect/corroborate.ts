/**
 * Multi-source corroboration of upstream change signals (threat-model §5.2,
 * required by ADR-0004).
 *
 * The attack this exists to stop is subtle and severe. A compromised or
 * malicious upstream — or anyone who can influence a changelog — announces a
 * "breaking change" that is not one, whose described migration inserts an
 * attacker-controlled dependency or endpoint. Driftless then propagates it
 * faithfully to every downstream consumer.
 *
 * That weaponises our distribution. It is the one attack where our
 * correctness is the vulnerability: the system does exactly what it is
 * supposed to, at scale, on behalf of an attacker.
 *
 * The defence is not to trust any single source. A change is eligible for
 * fan-out only when independent evidence agrees:
 *
 *   registry   package metadata — versions, deprecations, dist-tags
 *   artifact   the published package itself — what actually shipped
 *   spec       an OpenAPI/type-definition diff
 *   changelog  human-written release notes
 *
 * Changelogs are the easiest to forge and the most persuasive to a model, so
 * they carry the least weight and can never corroborate alone.
 */

export type SourceKind = "registry" | "artifact" | "spec" | "changelog";

export interface Corroboration {
  readonly kind: SourceKind;
  /** Where this came from. Recorded for audit; never treated as instruction. */
  readonly origin: string;
  /** Does this source agree a breaking change occurred? */
  readonly breaking: boolean;
  readonly observedAt: string;
  /** Free-form evidence. Untrusted text — never rendered into a prompt. */
  readonly detail?: string;
}

export interface ChangeSignal {
  readonly changeKey: string;
  readonly ecosystem: string;
  readonly packageName: string;
  readonly fromVersion: string | null;
  readonly toVersion: string | null;
  readonly corroborations: readonly Corroboration[];
  /**
   * Set when the described migration would introduce a dependency, a network
   * destination, or credential usage. Those are never auto-generated — they
   * wait for human approval on our side (threat-model §5.2).
   */
  readonly introducesCapability?: boolean;
}

export type Eligibility =
  | { eligible: true; confidence: "high" | "moderate" }
  | { eligible: false; reason: EligibilityFailure; detail: string };

export type EligibilityFailure =
  | "insufficient-sources"
  | "changelog-only"
  | "sources-disagree"
  | "capability-requires-approval"
  | "not-breaking";

/**
 * Weights reflect how hard a source is to forge, not how informative it is.
 *
 * Registry and artifact evidence require control of the published package;
 * a spec diff is derived from what shipped. A changelog is prose someone
 * typed, and is the natural carrier for the §5.2 attack — so it is worth
 * something only alongside harder evidence.
 */
const WEIGHTS: Readonly<Record<SourceKind, number>> = Object.freeze({
  artifact: 3,
  registry: 3,
  spec: 2,
  changelog: 1,
});

const MINIMUM_WEIGHT = 4;

export interface CorroborationPolicy {
  /** Minimum combined weight of agreeing sources. */
  readonly minimumWeight?: number;
  /** Require at least this many distinct source kinds. */
  readonly minimumKinds?: number;
}

export function assessEligibility(
  signal: ChangeSignal,
  policy: CorroborationPolicy = {},
): Eligibility {
  const minimumWeight = policy.minimumWeight ?? MINIMUM_WEIGHT;
  const minimumKinds = policy.minimumKinds ?? 2;

  const agreeing = signal.corroborations.filter((c) => c.breaking);
  const dissenting = signal.corroborations.filter((c) => !c.breaking);

  if (agreeing.length === 0) {
    return {
      eligible: false,
      reason: "not-breaking",
      detail: "no source reports a breaking change",
    };
  }

  // Deduplicate by kind. Three changelogs restating each other is one
  // changelog, and treating it as three is exactly how a single forged
  // source clears a threshold.
  const kinds = new Set(agreeing.map((c) => c.kind));

  if (kinds.size === 1 && kinds.has("changelog")) {
    return {
      eligible: false,
      reason: "changelog-only",
      detail:
        "only changelog evidence — prose is the easiest signal to forge and " +
        "cannot corroborate a breaking change alone",
    };
  }

  const weight = [...kinds].reduce((total, kind) => total + WEIGHTS[kind], 0);

  if (kinds.size < minimumKinds || weight < minimumWeight) {
    return {
      eligible: false,
      reason: "insufficient-sources",
      detail: `weight ${weight} across ${kinds.size} source kind(s); need ${minimumWeight} across ${minimumKinds}`,
    };
  }

  // Disagreement between hard sources means we do not understand the change.
  // Fan-out is the wrong response to confusion.
  const hardDissent = dissenting.filter((c) => c.kind !== "changelog");
  if (hardDissent.length > 0) {
    return {
      eligible: false,
      reason: "sources-disagree",
      detail: `${hardDissent.map((c) => c.kind).join(", ")} report no breaking change`,
    };
  }

  if (signal.introducesCapability) {
    return {
      eligible: false,
      reason: "capability-requires-approval",
      detail:
        "migration introduces a dependency, network destination, or credential " +
        "use — requires human approval before any fan-out (threat-model §5.2)",
    };
  }

  return {
    eligible: true,
    confidence: weight >= 6 && kinds.size >= 3 ? "high" : "moderate",
  };
}

/**
 * Canary sizing for staged fan-out (ADR-0004).
 *
 * A new migration reaches a small subset first, so a mistake costs a handful
 * of pull requests rather than a thousand. Moderate-confidence changes get a
 * smaller canary than high-confidence ones.
 */
export function canarySize(
  eligibility: Eligibility,
  totalRepositories: number,
): number {
  if (!eligibility.eligible) return 0;
  if (totalRepositories <= 5) return totalRepositories;
  const fraction = eligibility.confidence === "high" ? 0.05 : 0.02;
  return Math.max(3, Math.min(25, Math.ceil(totalRepositories * fraction)));
}
