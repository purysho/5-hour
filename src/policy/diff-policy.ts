/**
 * Diff policy enforcement (ADR-0003, layer 3).
 *
 * Every generated diff passes through here before a pull request is opened.
 *
 * Two design commitments, both load-bearing:
 *
 *   Deterministic code, not a model. If the control that decides whether a
 *   model's output is safe is itself a model, an attacker who can influence
 *   one can influence both. This module contains no inference.
 *
 *   Default deny on the shapes a payload takes. The rules do not attempt to
 *   recognise malice — an unbounded and losing problem. They recognise the
 *   small set of *capabilities* a supply-chain payload needs: reaching the
 *   network, pulling in code, reading credentials, or altering what runs in
 *   CI. A migration legitimately needing one of those is rare and can wait for
 *   a human (threat-model §5.1, §5.2).
 *
 * Verdicts:
 *   allow     — open the pull request
 *   escalate  — a human at Driftless reviews before anything is opened
 *   reject    — discard; the job fails and is reported
 */

import { parseUnifiedDiff, type DiffFile, type ParsedDiff } from "./diff.ts";

export type Verdict = "allow" | "escalate" | "reject";

export type RuleId =
  | "blast-radius"
  | "ci-configuration"
  | "lockfile-provenance"
  | "new-dependency"
  | "new-network-destination"
  | "credential-access"
  | "diff-scale"
  | "unparseable";

export interface Finding {
  readonly rule: RuleId;
  readonly verdict: Exclude<Verdict, "allow">;
  readonly file: string;
  readonly line: number | null;
  readonly detail: string;
  /** The offending text, truncated. Never rendered into a prompt. */
  readonly evidence: string | null;
}

export interface PolicyDecision {
  readonly verdict: Verdict;
  readonly findings: readonly Finding[];
}

export interface PolicyContext {
  /**
   * Files the upstream change is predicted to affect. Anything outside this
   * set is out of scope for the migration by definition — this is the rule
   * that stops an injected instruction from editing an unrelated file.
   */
  readonly blastRadius: readonly string[];
  /**
   * Hosts already referenced by the repository before the change. A
   * destination already present is not new, so re-emitting it is not
   * exfiltration.
   */
  readonly knownHosts?: readonly string[];
  readonly maxChangedFiles?: number;
  readonly maxAddedLines?: number;
  /**
   * Migrations whose whole purpose is a dependency bump set this. It relaxes
   * `new-dependency` to escalate-on-unexpected-package rather than blanket
   * escalation — it never disables the rule.
   */
  readonly expectedDependencyChanges?: readonly string[];
}

const CI_PATHS = [
  /^\.github\/workflows\//,
  /^\.github\/actions\//,
  /^\.gitlab-ci\.ya?ml$/,
  /^\.circleci\//,
  /^azure-pipelines\.ya?ml$/,
  /^Jenkinsfile$/,
  /^\.buildkite\//,
  /^\.drone\.ya?ml$/,
  /^bitbucket-pipelines\.ya?ml$/,
  /(^|\/)Dockerfile(\.|$)/,
  /^\.githooks\//,
  /^\.husky\//,
];

const LOCKFILES = [
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "poetry.lock",
  "Cargo.lock",
  "Gemfile.lock",
  "composer.lock",
  "go.sum",
  "uv.lock",
];

const MANIFESTS = [
  "package.json",
  "requirements.txt",
  "pyproject.toml",
  "Pipfile",
  "go.mod",
  "Cargo.toml",
  "Gemfile",
  "composer.json",
  "build.gradle",
  "pom.xml",
];

/** Provenance fields — the ones that decide what code is actually fetched. */
const LOCKFILE_PROVENANCE = /"?(resolved|integrity|checksum)"?\s*[:=]/i;

const URL_PATTERN = /\bhttps?:\/\/([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?/gi;

/**
 * Added code that reads credentials. Not exhaustive and not intended to be —
 * with the egress allowlist (ADR-0006) and no credentials in the sandbox
 * (ADR-0002), this is the third layer, not the first.
 */
const CREDENTIAL_PATTERNS: readonly { pattern: RegExp; detail: string }[] = [
  { pattern: /process\.env\b/, detail: "reads process environment" },
  { pattern: /\bos\.environ\b/, detail: "reads process environment" },
  { pattern: /\bos\.getenv\s*\(/, detail: "reads process environment" },
  { pattern: /\bgetenv\s*\(/, detail: "reads process environment" },
  { pattern: /\bSystem\.getenv\s*\(/, detail: "reads process environment" },
  { pattern: /\b(GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|PYPI_TOKEN)\b/, detail: "references a forge or registry token" },
  { pattern: /\bAWS_(SECRET_ACCESS_KEY|ACCESS_KEY_ID|SESSION_TOKEN)\b/, detail: "references AWS credentials" },
  { pattern: /\b(?:api[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret)\b/i, detail: "references a credential by name" },
  { pattern: /~\/\.(ssh|aws|netrc|docker|npmrc)/, detail: "reads a credential file path" },
  { pattern: /\/\.git-credentials\b/, detail: "reads stored git credentials" },
];

export function evaluateDiff(diffText: string, context: PolicyContext): PolicyDecision {
  let parsed: ParsedDiff;
  try {
    parsed = parseUnifiedDiff(diffText);
  } catch (error) {
    return {
      verdict: "reject",
      findings: [
        {
          rule: "unparseable",
          verdict: "reject",
          file: "<diff>",
          line: null,
          detail: `Diff could not be parsed: ${(error as Error).message}`,
          evidence: null,
        },
      ],
    };
  }
  return evaluateParsedDiff(parsed, context);
}

export function evaluateParsedDiff(
  parsed: ParsedDiff,
  context: PolicyContext,
): PolicyDecision {
  const findings: Finding[] = [];
  const blastRadius = new Set(context.blastRadius);
  const knownHosts = new Set((context.knownHosts ?? []).map((h) => h.toLowerCase()));
  const maxChangedFiles = context.maxChangedFiles ?? 25;
  const maxAddedLines = context.maxAddedLines ?? 400;

  for (const file of parsed.files) {
    findings.push(...checkBlastRadius(file, blastRadius));
    findings.push(...checkCiConfiguration(file));
    findings.push(...checkLockfileProvenance(file));
    findings.push(...checkNewDependency(file, context.expectedDependencyChanges ?? []));
    findings.push(...checkNetworkDestinations(file, knownHosts));
    findings.push(...checkCredentialAccess(file));
  }

  findings.push(...checkScale(parsed, maxChangedFiles, maxAddedLines));

  const verdict: Verdict = findings.some((f) => f.verdict === "reject")
    ? "reject"
    : findings.some((f) => f.verdict === "escalate")
      ? "escalate"
      : "allow";

  return { verdict, findings };
}

/**
 * The rule that most directly answers threat-model §5.1. An injected
 * instruction that persuades the agent to modify an unrelated file produces a
 * diff outside the predicted blast radius, and dies here regardless of how
 * convincing the injection was.
 */
function checkBlastRadius(file: DiffFile, blastRadius: ReadonlySet<string>): Finding[] {
  if (blastRadius.has(file.path)) return [];
  if (file.oldPath && blastRadius.has(file.oldPath)) return [];
  return [
    {
      rule: "blast-radius",
      verdict: "reject",
      file: file.path,
      line: null,
      detail:
        `File is outside the predicted blast radius of this change. ` +
        `The migration should not touch it.`,
      evidence: null,
    },
  ];
}

/**
 * CI configuration decides what executes with the repository's own
 * credentials. A migration has no business here — if a genuine one does, a
 * human opens that pull request.
 */
function checkCiConfiguration(file: DiffFile): Finding[] {
  if (!CI_PATHS.some((p) => p.test(file.path))) return [];
  return [
    {
      rule: "ci-configuration",
      verdict: "reject",
      file: file.path,
      line: null,
      detail: "Modifies CI or build configuration, which controls privileged execution.",
      evidence: null,
    },
  ];
}

/**
 * Lockfile provenance decides which bytes get installed. Changing a `resolved`
 * URL or an `integrity` hash substitutes code without touching a single line
 * of source, which is the quietest supply-chain edit available.
 */
function checkLockfileProvenance(file: DiffFile): Finding[] {
  const base = basename(file.path);
  if (!LOCKFILES.includes(base)) return [];

  const findings: Finding[] = [];
  for (const line of file.lines) {
    if (line.kind !== "added") continue;
    if (LOCKFILE_PROVENANCE.test(line.text)) {
      findings.push({
        rule: "lockfile-provenance",
        verdict: "escalate",
        file: file.path,
        line: line.newLineNumber,
        detail: "Alters lockfile provenance (resolved URL, integrity, or checksum).",
        evidence: truncate(line.text),
      });
    }
  }
  return findings;
}

function checkNewDependency(file: DiffFile, expected: readonly string[]): Finding[] {
  if (!MANIFESTS.includes(basename(file.path))) return [];

  const findings: Finding[] = [];
  for (const line of file.lines) {
    if (line.kind !== "added") continue;
    const name = extractDependencyName(line.text);
    if (!name) continue;
    if (expected.includes(name)) continue;
    findings.push({
      rule: "new-dependency",
      verdict: "escalate",
      file: file.path,
      line: line.newLineNumber,
      detail: `Introduces or changes dependency "${name}", which was not expected for this migration.`,
      evidence: truncate(line.text),
    });
  }
  return findings;
}

/**
 * A new outbound destination in generated code is the exfiltration shape. With
 * no credentials in the sandbox and allowlisted egress it should never
 * succeed — but it should also never be opened as a pull request, because at
 * that point it runs on the customer's infrastructure with the customer's
 * secrets.
 */
function checkNetworkDestinations(
  file: DiffFile,
  knownHosts: ReadonlySet<string>,
): Finding[] {
  const findings: Finding[] = [];
  for (const line of file.lines) {
    if (line.kind !== "added") continue;
    URL_PATTERN.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = URL_PATTERN.exec(line.text)) !== null) {
      const host = (match[1] as string).toLowerCase();
      if (knownHosts.has(host)) continue;
      findings.push({
        rule: "new-network-destination",
        verdict: "reject",
        file: file.path,
        line: line.newLineNumber,
        detail: `Introduces a network destination not previously referenced: ${host}`,
        evidence: truncate(line.text),
      });
    }
  }
  return findings;
}

function checkCredentialAccess(file: DiffFile): Finding[] {
  const findings: Finding[] = [];
  for (const line of file.lines) {
    if (line.kind !== "added") continue;
    for (const { pattern, detail } of CREDENTIAL_PATTERNS) {
      if (pattern.test(line.text)) {
        findings.push({
          rule: "credential-access",
          verdict: "reject",
          file: file.path,
          line: line.newLineNumber,
          detail: `Introduces code that ${detail}.`,
          evidence: truncate(line.text),
        });
        break;
      }
    }
  }
  return findings;
}

/**
 * Scale is a proxy for "this is not the migration we predicted". A migration
 * that has grown far beyond its expected size has usually either gone wrong or
 * been steered.
 */
function checkScale(
  parsed: ParsedDiff,
  maxChangedFiles: number,
  maxAddedLines: number,
): Finding[] {
  const findings: Finding[] = [];
  if (parsed.files.length > maxChangedFiles) {
    findings.push({
      rule: "diff-scale",
      verdict: "escalate",
      file: "<diff>",
      line: null,
      detail: `Changes ${parsed.files.length} files, above the threshold of ${maxChangedFiles}.`,
      evidence: null,
    });
  }
  if (parsed.addedCount > maxAddedLines) {
    findings.push({
      rule: "diff-scale",
      verdict: "escalate",
      file: "<diff>",
      line: null,
      detail: `Adds ${parsed.addedCount} lines, above the threshold of ${maxAddedLines}.`,
      evidence: null,
    });
  }
  return findings;
}

function extractDependencyName(text: string): string | null {
  // package.json / composer.json — "name": "^1.2.3"
  const json = /^\s*"([^"]+)"\s*:\s*"[^"]*"/.exec(text);
  if (json) return json[1] as string;
  // requirements.txt — name==1.2.3, name>=1.0
  const req = /^\s*([A-Za-z0-9._-]+)\s*(?:[=<>!~]=|[<>])/.exec(text);
  if (req) return req[1] as string;
  // go.mod — require example.com/mod v1.2.3  (or inside a require block)
  const go = /^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]{2,}\/[^\s]+)\s+v\d/.exec(text);
  if (go) return go[1] as string;
  // Cargo.toml / pyproject — name = "1.2.3"
  const toml = /^\s*([A-Za-z0-9._-]+)\s*=\s*[{"]/.exec(text);
  if (toml) return toml[1] as string;
  return null;
}

function basename(path: string): string {
  const index = path.lastIndexOf("/");
  return index === -1 ? path : path.slice(index + 1);
}

function truncate(text: string, limit = 200): string {
  const trimmed = text.trim();
  return trimmed.length <= limit ? trimmed : `${trimmed.slice(0, limit)}…`;
}
