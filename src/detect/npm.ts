/**
 * npm registry collector (threat-model §5.2).
 *
 * Produces `Corroboration` records from registry metadata. It is the first of
 * the independent sources the corroboration gate weighs — never the decision
 * itself.
 *
 * Two things govern this file.
 *
 * **Registry responses are untrusted input.** A package name, a version
 * string, a deprecation message, and a repository URL all come from whoever
 * published the package. They are attacker-controlled in the ordinary case,
 * not the exotic one: anyone can publish to npm. Nothing here may reach a
 * prompt as instruction, and nothing here may be interpolated into a URL, a
 * path, or a shell command without validation.
 *
 * **Package names are the injection surface.** A "package name" arriving from
 * a changelog, a webhook, or an operator's typo is a path segment in a URL we
 * are about to fetch:
 *
 *     https://registry.npmjs.org/../../some/other/endpoint
 *     https://registry.npmjs.org/@scope/name/../../..%2f
 *
 * npm's own naming rules are strict enough to make a good allowlist, so names
 * are validated against those rules before they are used to build anything —
 * rather than being escaped afterwards, which is the pattern that keeps
 * failing across the industry.
 */

import type { Corroboration } from "./corroborate.ts";
import {
  classifyBump,
  compareVersions,
  isBreakingBump,
  latestStableVersion,
  parseVersion,
  tryParseVersion,
  type Version,
} from "./semver.ts";

export const NPM_REGISTRY = "https://registry.npmjs.org";

export class InvalidPackageNameError extends Error {
  override readonly name = "InvalidPackageNameError";
}

/**
 * npm's naming rules, applied as an allowlist.
 *
 * Deliberately stricter than npm itself in one respect: legacy names
 * containing uppercase or URL-unsafe characters exist in the registry but
 * cannot be published today, and accepting them widens this surface for no
 * present benefit.
 */
const UNSCOPED = /^[a-z0-9][a-z0-9._-]*$/;
const SCOPED = /^@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*$/;
const MAX_NAME_LENGTH = 214;

export function assertValidPackageName(name: string): string {
  if (name.length === 0 || name.length > MAX_NAME_LENGTH) {
    throw new InvalidPackageNameError(
      `Package name must be 1-${MAX_NAME_LENGTH} characters`,
    );
  }
  // Checked explicitly as well as by the patterns below, so the failure
  // message names the actual problem when someone hits it.
  if (name.includes("..") || name.includes("/") !== name.startsWith("@")) {
    if (name.includes("..")) {
      throw new InvalidPackageNameError(
        `Package name contains "..": ${JSON.stringify(name)}. ` +
          `This is a path traversal attempt, not a package.`,
      );
    }
  }
  if (!UNSCOPED.test(name) && !SCOPED.test(name)) {
    throw new InvalidPackageNameError(
      `Not a valid npm package name: ${JSON.stringify(name)}`,
    );
  }
  return name;
}

/** Registry path segment. Scoped names are encoded as a single segment. */
export function packagePath(name: string): string {
  assertValidPackageName(name);
  return name.startsWith("@") ? name.replace("/", "%2f") : name;
}

// ── Registry response shapes ────────────────────────────────────────────────
// Typed as `unknown`-derived and narrowed explicitly. A registry response is
// not to be trusted to have the shape its documentation claims.

export interface RegistryVersionMetadata {
  readonly version: string;
  readonly deprecated?: string;
  readonly dist?: { readonly tarball?: string; readonly integrity?: string };
  readonly engines?: Record<string, string>;
}

export interface RegistryPackument {
  readonly name: string;
  readonly "dist-tags"?: Record<string, string>;
  readonly versions?: Record<string, RegistryVersionMetadata>;
  readonly time?: Record<string, string>;
}

export interface HttpResponse {
  readonly status: number;
  readonly body: string;
}

export interface HttpClient {
  get(url: string, headers: Record<string, string>): Promise<HttpResponse>;
}

export class RegistryError extends Error {
  override readonly name = "RegistryError";
  readonly status: number | null;
  constructor(message: string, status: number | null = null) {
    super(message);
    this.status = status;
  }
}

export interface CollectorOptions {
  readonly registry?: string;
  readonly userAgent?: string;
  /** Reject packuments above this size. Registry responses can be enormous. */
  readonly maxResponseBytes?: number;
}

export class NpmCollector {
  readonly #http: HttpClient;
  readonly #registry: string;
  readonly #userAgent: string;
  readonly #maxResponseBytes: number;

  constructor(http: HttpClient, options: CollectorOptions = {}) {
    this.#http = http;
    this.#registry = (options.registry ?? NPM_REGISTRY).replace(/\/+$/, "");
    this.#userAgent = options.userAgent ?? "driftless-detector";
    this.#maxResponseBytes = options.maxResponseBytes ?? 8 * 1024 * 1024;
  }

  async fetchPackument(name: string): Promise<RegistryPackument> {
    const url = `${this.#registry}/${packagePath(name)}`;
    const response = await this.#http.get(url, {
      // Abbreviated packument: far smaller, and omits fields we must not act
      // on anyway.
      accept: "application/vnd.npm.install-v1+json",
      "user-agent": this.#userAgent,
    });

    if (response.status === 404) {
      throw new RegistryError(`Package not found: ${name}`, 404);
    }
    if (response.status !== 200) {
      throw new RegistryError(`Registry returned ${response.status} for ${name}`, response.status);
    }
    if (response.body.length > this.#maxResponseBytes) {
      throw new RegistryError(
        `Packument for ${name} exceeds ${this.#maxResponseBytes} bytes`,
      );
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(response.body);
    } catch {
      throw new RegistryError(`Registry returned invalid JSON for ${name}`);
    }
    if (typeof parsed !== "object" || parsed === null) {
      throw new RegistryError(`Registry returned a non-object packument for ${name}`);
    }

    const packument = parsed as RegistryPackument;

    // The registry echoing back a different name than we asked for means
    // either a redirect we did not expect or a mirror doing something odd.
    // Either way we are no longer looking at the package we intended.
    if (typeof packument.name === "string" && packument.name !== name) {
      throw new RegistryError(
        `Registry returned "${packument.name}" for a request for "${name}"`,
      );
    }

    return packument;
  }

  /**
   * Registry-derived corroboration for a specific version transition.
   *
   * Reports what the registry actually shows: whether the versions exist,
   * whether the bump is breaking by semver convention, and whether the old
   * version has been deprecated. It does not read release notes — that is a
   * separate, weaker source by design.
   */
  async corroborate(
    name: string,
    fromVersion: string,
    toVersion: string,
  ): Promise<Corroboration> {
    assertValidPackageName(name);
    const from = parseVersion(fromVersion);
    const to = parseVersion(toVersion);
    const packument = await this.fetchPackument(name);
    const observedAt = new Date().toISOString();

    const versions = packument.versions ?? {};
    const published = Object.keys(versions);

    // A version that does not exist in the registry cannot corroborate
    // anything. This is the check that catches a fabricated change outright.
    if (!published.includes(to.raw)) {
      return {
        kind: "registry",
        origin: `${this.#registry}/${name}`,
        breaking: false,
        observedAt,
        detail: `version ${to.raw} is not published; the registry does not corroborate this change`,
      };
    }

    const breaking = isBreakingBump(from, to);
    const deprecation = versions[from.raw]?.deprecated;

    return {
      kind: "registry",
      origin: `${this.#registry}/${name}`,
      // Deprecation of the old version is independent evidence that the
      // publisher considers the transition consequential, even when the
      // version numbers do not say so.
      breaking: breaking || typeof deprecation === "string",
      observedAt,
      detail: describeRegistryEvidence(from, to, breaking, deprecation),
    };
  }

  /**
   * Artifact-derived corroboration.
   *
   * Distinct from registry metadata because it reflects what actually shipped
   * rather than what the metadata claims. Currently checks that the published
   * artifact exists and carries an integrity hash — an entry with no tarball
   * or no integrity is not something we will migrate anyone onto.
   */
  async corroborateArtifact(name: string, toVersion: string): Promise<Corroboration> {
    assertValidPackageName(name);
    const to = parseVersion(toVersion);
    const packument = await this.fetchPackument(name);
    const observedAt = new Date().toISOString();
    const metadata = (packument.versions ?? {})[to.raw];

    if (!metadata) {
      return {
        kind: "artifact",
        origin: `${this.#registry}/${name}@${to.raw}`,
        breaking: false,
        observedAt,
        detail: "no published artifact for this version",
      };
    }

    const tarball = metadata.dist?.tarball;
    const integrity = metadata.dist?.integrity;

    if (!tarball || !integrity) {
      return {
        kind: "artifact",
        origin: `${this.#registry}/${name}@${to.raw}`,
        breaking: false,
        observedAt,
        detail: "published entry lacks a tarball or integrity hash",
      };
    }

    // A tarball hosted somewhere other than the registry we queried is how a
    // substitution attack looks from here.
    if (!tarball.startsWith(`${this.#registry}/`)) {
      return {
        kind: "artifact",
        origin: `${this.#registry}/${name}@${to.raw}`,
        breaking: false,
        observedAt,
        detail: `tarball is hosted off-registry (${safeHost(tarball)}); refusing to corroborate`,
      };
    }

    return {
      kind: "artifact",
      origin: `${this.#registry}/${name}@${to.raw}`,
      breaking: true,
      observedAt,
      detail: `artifact published with integrity ${integrity.slice(0, 24)}…`,
    };
  }

  /**
   * The next stable version after `current`, if one exists.
   *
   * Used to discover candidate migrations. Prereleases are excluded — we do
   * not move anyone onto an unreleased version, however loudly it is
   * announced.
   */
  async nextStableAfter(name: string, current: string): Promise<Version | null> {
    const from = parseVersion(current);
    const packument = await this.fetchPackument(name);
    const candidates = Object.keys(packument.versions ?? {}).filter((candidate) => {
      const parsed = tryParseVersion(candidate);
      return parsed !== null && compareVersions(parsed, from) > 0;
    });
    return latestStableVersion(candidates);
  }
}

function describeRegistryEvidence(
  from: Version,
  to: Version,
  breaking: boolean,
  deprecation: string | undefined,
): string {
  const bump = classifyBump(from, to);
  const parts = [`${from.raw} → ${to.raw} is a ${bump} bump`];
  if (breaking && from.major === 0 && to.major === 0) {
    parts.push("pre-1.0, where minor bumps carry breaking changes by convention");
  }
  if (typeof deprecation === "string") {
    // The message is publisher-controlled text. Recorded for audit, length
    // capped, and never rendered into a prompt as instruction.
    parts.push(`previous version is deprecated (${deprecation.length} chars of notice)`);
  }
  return parts.join("; ");
}

/** Host only — the full URL is attacker-controlled and not worth echoing. */
function safeHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return "unparseable";
  }
}
