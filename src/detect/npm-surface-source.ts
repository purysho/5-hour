/**
 * The production `SurfaceSource`: fetch the published tarball, read its
 * declarations, extract the API surface.
 *
 * This is the third corroboration source, and the only one of the three that
 * speaks to whether consumers will actually break — registry metadata says
 * what the publisher claims, the artifact says what shipped, and this says
 * what changed about the interface.
 *
 * ── Failing to null is the correct failure ──────────────────────────────────
 *
 * Every failure here returns null rather than throwing: a package with no
 * types, a tarball that will not parse, declarations that are not a module, a
 * registry that is down. `detect-changes` treats null as "we could not
 * determine it", which costs a corroboration source — the gate then requires
 * registry and artifact to agree, at moderate confidence instead of high.
 *
 * That is the right shape. The alternative is a detection sweep that fails
 * because a package we watch published a malformed tarball, which converts one
 * publisher's mistake into an outage of our own.
 *
 * The exception is the tarball URL check below, which is not a failure to
 * determine something — it is a registry telling us to fetch from somewhere
 * else.
 */

import type { ApiSurface } from "./api-surface.ts";
import { extractApiSurface } from "./dts-surface.ts";
import type { NpmCollector } from "./npm.ts";
import { compareVersions, tryParseVersion, type Version } from "./semver.ts";
import { readTarball } from "./tarball.ts";

export interface BinaryHttpClient {
  get(url: string, headers: Record<string, string>): Promise<{ status: number; body: Buffer }>;
}

export interface SurfaceSourceOptions {
  /**
   * Hosts a tarball may be fetched from.
   *
   * `dist.tarball` is a URL the registry chooses, and a registry response is
   * not to be trusted to point where its documentation says. Without this, a
   * compromised or hostile registry could redirect artifact fetching anywhere
   * — including at an internal address, which makes this a server-side request
   * forgery with our network position behind it.
   */
  readonly allowedHosts?: readonly string[];
  readonly userAgent?: string;
  readonly log?: (event: string, detail: Record<string, unknown>) => void;
}

const DEFAULT_ALLOWED_HOSTS = Object.freeze(["registry.npmjs.org"]);

/** Declarations and the manifest. Everything else in the tarball is skipped. */
function wanted(path: string): boolean {
  return path === "package.json" || path.endsWith(".d.ts") || path.endsWith(".d.mts");
}

/**
 * The DefinitelyTyped package name for a runtime package.
 *
 * Scoped packages flatten with a double underscore — `@scope/name` is
 * described by `@types/scope__name` — which is the convention DefinitelyTyped
 * uses because npm scopes cannot nest.
 */
export function definitelyTypedName(packageName: string): string {
  if (packageName.startsWith("@types/")) return packageName;
  if (packageName.startsWith("@")) {
    return `@types/${packageName.slice(1).replace("/", "__")}`;
  }
  return `@types/${packageName}`;
}

export class NpmSurfaceSource {
  readonly #collector: NpmCollector;
  readonly #http: BinaryHttpClient;
  readonly #allowedHosts: ReadonlySet<string>;
  readonly #userAgent: string;
  readonly #log: (event: string, detail: Record<string, unknown>) => void;

  constructor(
    collector: NpmCollector,
    http: BinaryHttpClient,
    options: SurfaceSourceOptions = {},
  ) {
    this.#collector = collector;
    this.#http = http;
    this.#allowedHosts = new Set(options.allowedHosts ?? DEFAULT_ALLOWED_HOSTS);
    this.#userAgent = options.userAgent ?? "driftless-detector";
    this.#log = options.log ?? (() => {});
  }

  async surfaceFor(packageName: string, version: string): Promise<ApiSurface | null> {
    const own = await this.#surfaceFromTarball(packageName, version, packageName, version);
    if (own) return own;

    // A package that ships no declarations of its own is not untyped — for a
    // large share of npm (react, express, lodash) the types live in a separate
    // DefinitelyTyped package, and treating that as "untyped" makes us blind
    // to exactly the packages most likely to be depended on. Verified against
    // the live registry: react ships none, and without this the surface
    // corroboration is unavailable for it and every package like it.
    const typesName = definitelyTypedName(packageName);
    const typesVersion = await this.#matchingTypesVersion(typesName, version);
    if (!typesVersion) return null;

    this.#log("surface.using_definitely_typed", {
      packageName,
      version,
      typesPackage: typesName,
      typesVersion,
    });
    // Reported under the original package's name and version: the surface
    // describes that package, and a diff between two surfaces labelled
    // `@types/react` would compare the wrong pair of things downstream.
    return this.#surfaceFromTarball(typesName, typesVersion, packageName, version);
  }

  /**
   * The highest published `@types` version whose major matches the runtime
   * package's.
   *
   * DefinitelyTyped tracks the major of what it describes (react 19.x is
   * described by @types/react 19.x), so the major is the join. Anything looser
   * would diff a surface against declarations for a different major, which
   * produces confident and entirely wrong impacted symbols.
   */
  async #matchingTypesVersion(typesName: string, version: string): Promise<string | null> {
    const target = tryParseVersion(version);
    if (!target) return null;

    let packument;
    try {
      packument = await this.#collector.fetchPackument(typesName);
    } catch {
      // No @types package. Common and expected — most packages ship their own.
      return null;
    }

    let best: Version | null = null;
    for (const raw of Object.keys(packument.versions ?? {})) {
      const candidate = tryParseVersion(raw);
      if (!candidate) continue;
      // Prereleases are excluded: a surface taken from @types/react@19.0.0-rc
      // describes declarations nobody's consumers have installed.
      if (candidate.prerelease.length > 0) continue;
      if (candidate.major !== target.major) continue;
      if (!best || compareVersions(candidate, best) > 0) best = candidate;
    }
    return best?.raw ?? null;
  }

  /** Fetches one package's tarball and extracts a surface, labelled as `asName@asVersion`. */
  async #surfaceFromTarball(
    fetchName: string,
    fetchVersion: string,
    asName: string,
    asVersion: string,
  ): Promise<ApiSurface | null> {
    const packageName = fetchName;
    const version = fetchVersion;
    try {
      const packument = await this.#collector.fetchPackument(packageName);
      const tarballUrl = packument.versions?.[version]?.dist?.tarball;
      if (!tarballUrl) {
        this.#log("surface.no_tarball", { packageName, version });
        return null;
      }

      if (!this.#isAllowed(tarballUrl)) {
        // Not a "could not determine". A registry pointing us somewhere else
        // is a finding, and quietly declining to fetch is the right response
        // — but it should be loud in the log rather than indistinguishable
        // from a package that ships no types.
        this.#log("surface.tarball_host_refused", { packageName, version });
        return null;
      }

      const response = await this.#http.get(tarballUrl, {
        accept: "application/octet-stream",
        "user-agent": this.#userAgent,
      });
      if (response.status !== 200) {
        this.#log("surface.tarball_fetch_failed", { packageName, version, status: response.status });
        return null;
      }

      const files = readTarball(response.body, { filter: wanted });
      const entry = resolveTypesEntry(files);
      if (!entry) {
        this.#log("surface.no_types", { packageName, version });
        return null;
      }

      // Keyed with a leading slash so relative module specifiers resolve from
      // a root the compiler host actually has.
      const virtual = new Map<string, string>();
      for (const [path, content] of files) {
        if (path.endsWith(".d.ts") || path.endsWith(".d.mts")) {
          virtual.set(`/${path}`, content.toString("utf8"));
        }
      }

      return extractApiSurface({
        packageName: asName,
        version: asVersion,
        entry: `/${entry}`,
        files: virtual,
      });
    } catch (error) {
      this.#log("surface.extraction_failed", {
        packageName,
        version,
        error: error instanceof Error ? error.message : String(error),
      });
      return null;
    }
  }

  #isAllowed(url: string): boolean {
    try {
      const parsed = new URL(url);
      return parsed.protocol === "https:" && this.#allowedHosts.has(parsed.hostname.toLowerCase());
    } catch {
      return false;
    }
  }
}

/**
 * Finds the entry declaration file.
 *
 * `package.json` is publisher-authored, so every value read here is checked
 * against the files actually present rather than trusted. A `types` field
 * naming a file that is not in the tarball falls through to the next
 * candidate, which is what a consumer's toolchain would effectively do too.
 *
 * Exported for tests: entry resolution is where the ecosystem's variety lives,
 * and it deserves its own cases rather than being reachable only through a
 * network fetch.
 */
export function resolveTypesEntry(files: ReadonlyMap<string, Buffer>): string | null {
  const candidates: string[] = [];
  const manifest = files.get("package.json");

  if (manifest) {
    try {
      const parsed = JSON.parse(manifest.toString("utf8")) as Record<string, unknown>;

      for (const field of ["types", "typings"] as const) {
        const value = parsed[field];
        if (typeof value === "string") candidates.push(value);
      }

      // `exports` is the modern shape and can nest arbitrarily. Only the root
      // export is considered — a package whose root has no types is one we
      // cannot describe as a single surface anyway.
      const root = (parsed["exports"] as Record<string, unknown> | undefined)?.["."];
      collectExportTypes(root, candidates);

      // A `main` of dist/index.js very often sits beside dist/index.d.ts.
      const main = parsed["main"];
      if (typeof main === "string") {
        candidates.push(main.replace(/\.(c|m)?js$/, ".d.ts"));
      }
    } catch {
      // A manifest that will not parse tells us nothing; the conventional
      // locations below are still worth trying.
    }
  }

  candidates.push("index.d.ts", "dist/index.d.ts", "types/index.d.ts", "lib/index.d.ts");

  for (const candidate of candidates) {
    const normalised = candidate.replace(/^\.\//, "").replace(/^\/+/, "");
    if (normalised && files.has(normalised)) return normalised;
  }
  return null;
}

function collectExportTypes(node: unknown, into: string[], depth = 0): void {
  if (depth > 4 || node === null || node === undefined) return;
  if (typeof node === "string") {
    if (node.endsWith(".d.ts") || node.endsWith(".d.mts")) into.push(node);
    return;
  }
  if (typeof node !== "object") return;

  const record = node as Record<string, unknown>;
  // "types" first: the conditional-exports convention puts it ahead of runtime
  // conditions, and taking "default" first would find a .js file.
  if (typeof record["types"] === "string") into.push(record["types"] as string);
  for (const key of ["import", "require", "default", "node"]) {
    collectExportTypes(record[key], into, depth + 1);
  }
}
