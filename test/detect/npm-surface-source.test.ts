import { describe, expect, it } from "vitest";
import { gzipSync } from "node:zlib";
import {
  NpmSurfaceSource,
  resolveTypesEntry,
  type BinaryHttpClient,
} from "../../src/detect/npm-surface-source.ts";
import { NpmCollector, type HttpClient } from "../../src/detect/npm.ts";

/**
 * The production surface source.
 *
 * Two things are being tested. That the pieces compose — packument, tarball,
 * declarations, surface — and that every way this can fail returns null rather
 * than throwing, because a detection sweep that dies when a publisher ships a
 * malformed tarball turns their mistake into an outage of ours.
 */

const BLOCK = 512;

function entry(name: string, content: string): Buffer {
  const data = Buffer.from(content, "utf8");
  const header = Buffer.alloc(BLOCK, 0);
  header.write(name.slice(0, 100), 0, "utf8");
  header.write("0000644\0", 100, "utf8");
  header.write(`${data.byteLength.toString(8).padStart(11, "0")}\0`, 124, "utf8");
  header.write("0", 156, "utf8");
  header.write("ustar\0", 257, "utf8");
  const padding = data.byteLength % BLOCK === 0 ? 0 : BLOCK - (data.byteLength % BLOCK);
  return Buffer.concat([header, data, Buffer.alloc(padding, 0)]);
}

function tarball(files: Record<string, string>): Buffer {
  return gzipSync(
    Buffer.concat([
      ...Object.entries(files).map(([name, content]) => entry(`package/${name}`, content)),
      Buffer.alloc(BLOCK * 2, 0),
    ]),
  );
}

const TARBALL_URL = "https://registry.npmjs.org/acme-sdk/-/acme-sdk-2.0.0.tgz";

function packumentJson(tarballUrl: string = TARBALL_URL): string {
  return JSON.stringify({
    name: "acme-sdk",
    versions: { "2.0.0": { version: "2.0.0", dist: { tarball: tarballUrl } } },
  });
}

function collectorReturning(body: string): NpmCollector {
  const http: HttpClient = { async get() { return { status: 200, body }; } };
  return new NpmCollector(http);
}

function binary(body: Buffer, status = 200): BinaryHttpClient & { urls: string[] } {
  const urls: string[] = [];
  return {
    urls,
    async get(url) {
      urls.push(url);
      return { status, body };
    },
  };
}

const PACKAGE = {
  "package.json": JSON.stringify({ name: "acme-sdk", types: "dist/index.d.ts" }),
  "dist/index.d.ts": `export declare function createClient(key: string): void;`,
};

describe("extracting a surface end to end", () => {
  it("fetches the tarball and returns the declared surface", async () => {
    const http = binary(tarball(PACKAGE));
    const source = new NpmSurfaceSource(collectorReturning(packumentJson()), http);

    const surface = await source.surfaceFor("acme-sdk", "2.0.0");

    expect(http.urls).toEqual([TARBALL_URL]);
    expect(surface?.version).toBe("2.0.0");
    expect(surface?.symbols.map((s) => s.name)).toEqual(["createClient"]);
  });

  it("resolves relative imports between declaration files", async () => {
    // The barrel-file shape, which is most of the ecosystem.
    const http = binary(
      tarball({
        "package.json": JSON.stringify({ name: "acme-sdk", types: "index.d.ts" }),
        "index.d.ts": `export { createClient } from "./client";`,
        "client.d.ts": `export declare function createClient(key: string): void;`,
      }),
    );
    const surface = await new NpmSurfaceSource(collectorReturning(packumentJson()), http).surfaceFor(
      "acme-sdk",
      "2.0.0",
    );
    expect(surface?.symbols.map((s) => s.name)).toEqual(["createClient"]);
  });
});

describe("refusing to fetch from anywhere the registry names", () => {
  it("refuses a tarball URL on another host", async () => {
    // `dist.tarball` is chosen by the registry. Without this check a hostile
    // or compromised registry redirects our fetching wherever it likes, with
    // our network position behind it.
    const http = binary(tarball(PACKAGE));
    const source = new NpmSurfaceSource(
      collectorReturning(packumentJson("https://evil.example/acme-sdk.tgz")),
      http,
    );

    expect(await source.surfaceFor("acme-sdk", "2.0.0")).toBeNull();
    expect(http.urls).toEqual([]);
  });

  it("refuses an internal address", async () => {
    const http = binary(tarball(PACKAGE));
    const source = new NpmSurfaceSource(
      collectorReturning(packumentJson("https://169.254.169.254/latest/meta-data/")),
      http,
    );
    expect(await source.surfaceFor("acme-sdk", "2.0.0")).toBeNull();
    expect(http.urls).toEqual([]);
  });

  it("refuses plain http even on an allowed host", async () => {
    const http = binary(tarball(PACKAGE));
    const source = new NpmSurfaceSource(
      collectorReturning(packumentJson("http://registry.npmjs.org/acme-sdk.tgz")),
      http,
    );
    expect(await source.surfaceFor("acme-sdk", "2.0.0")).toBeNull();
    expect(http.urls).toEqual([]);
  });

  it("logs a refused host distinctly from a package with no types", async () => {
    // Both return null, and an operator needs to be able to tell them apart.
    const events: string[] = [];
    const source = new NpmSurfaceSource(
      collectorReturning(packumentJson("https://evil.example/x.tgz")),
      binary(tarball(PACKAGE)),
      { log: (event) => events.push(event) },
    );
    await source.surfaceFor("acme-sdk", "2.0.0");
    expect(events).toContain("surface.tarball_host_refused");
  });

  it("honours a configured registry host", async () => {
    const http = binary(tarball(PACKAGE));
    const source = new NpmSurfaceSource(
      collectorReturning(packumentJson("https://npm.internal.example/acme-sdk.tgz")),
      http,
      { allowedHosts: ["npm.internal.example"] },
    );
    expect(await source.surfaceFor("acme-sdk", "2.0.0")).not.toBeNull();
  });
});

describe("failing to null", () => {
  it("returns null when the version has no tarball", async () => {
    const source = new NpmSurfaceSource(
      collectorReturning(JSON.stringify({ name: "acme-sdk", versions: { "2.0.0": {} } })),
      binary(Buffer.alloc(0)),
    );
    expect(await source.surfaceFor("acme-sdk", "2.0.0")).toBeNull();
  });

  it("returns null when the tarball fetch fails", async () => {
    const source = new NpmSurfaceSource(
      collectorReturning(packumentJson()),
      binary(Buffer.alloc(0), 503),
    );
    expect(await source.surfaceFor("acme-sdk", "2.0.0")).toBeNull();
  });

  it("returns null when the tarball will not parse", async () => {
    const source = new NpmSurfaceSource(
      collectorReturning(packumentJson()),
      binary(Buffer.from("not a tarball")),
    );
    expect(await source.surfaceFor("acme-sdk", "2.0.0")).toBeNull();
  });

  it("returns null for a package that ships no declarations", async () => {
    const source = new NpmSurfaceSource(
      collectorReturning(packumentJson()),
      binary(tarball({ "package.json": '{"name":"acme-sdk"}', "index.js": "module.exports={}" })),
    );
    expect(await source.surfaceFor("acme-sdk", "2.0.0")).toBeNull();
  });

  it("returns null when declarations are ambient globals rather than a module", async () => {
    const source = new NpmSurfaceSource(
      collectorReturning(packumentJson()),
      binary(
        tarball({
          "package.json": JSON.stringify({ types: "index.d.ts" }),
          "index.d.ts": "declare const x: string;",
        }),
      ),
    );
    expect(await source.surfaceFor("acme-sdk", "2.0.0")).toBeNull();
  });

  it("returns null when the registry itself fails", async () => {
    const http: HttpClient = { async get() { return { status: 500, body: "" }; } };
    const source = new NpmSurfaceSource(new NpmCollector(http), binary(Buffer.alloc(0)));
    expect(await source.surfaceFor("acme-sdk", "2.0.0")).toBeNull();
  });
});

describe("resolveTypesEntry", () => {
  const buf = (s: string) => Buffer.from(s, "utf8");

  it("prefers an explicit types field", () => {
    const files = new Map([
      ["package.json", buf(JSON.stringify({ types: "dist/api.d.ts" }))],
      ["dist/api.d.ts", buf("export {};")],
      ["index.d.ts", buf("export {};")],
    ]);
    expect(resolveTypesEntry(files)).toBe("dist/api.d.ts");
  });

  it("accepts the older typings field", () => {
    const files = new Map([
      ["package.json", buf(JSON.stringify({ typings: "./types.d.ts" }))],
      ["types.d.ts", buf("export {};")],
    ]);
    expect(resolveTypesEntry(files)).toBe("types.d.ts");
  });

  it("reads conditional exports", () => {
    const files = new Map([
      [
        "package.json",
        buf(JSON.stringify({ exports: { ".": { import: { types: "dist/index.d.mts" } } } })),
      ],
      ["dist/index.d.mts", buf("export {};")],
    ]);
    expect(resolveTypesEntry(files)).toBe("dist/index.d.mts");
  });

  it("prefers types over default within a conditional export", () => {
    // Taking "default" first would find the .js file.
    const files = new Map([
      [
        "package.json",
        buf(JSON.stringify({ exports: { ".": { types: "d.d.ts", default: "d.js" } } })),
      ],
      ["d.d.ts", buf("export {};")],
    ]);
    expect(resolveTypesEntry(files)).toBe("d.d.ts");
  });

  it("derives a candidate from main", () => {
    const files = new Map([
      ["package.json", buf(JSON.stringify({ main: "dist/index.js" }))],
      ["dist/index.d.ts", buf("export {};")],
    ]);
    expect(resolveTypesEntry(files)).toBe("dist/index.d.ts");
  });

  it("ignores a types field naming a file that is not there", () => {
    // package.json is publisher-authored, so every value is checked against
    // the files actually present rather than trusted.
    const files = new Map([
      ["package.json", buf(JSON.stringify({ types: "nope.d.ts" }))],
      ["index.d.ts", buf("export {};")],
    ]);
    expect(resolveTypesEntry(files)).toBe("index.d.ts");
  });

  it("falls back to conventional locations with no manifest at all", () => {
    expect(resolveTypesEntry(new Map([["types/index.d.ts", buf("export {};")]]))).toBe(
      "types/index.d.ts",
    );
  });

  it("survives a manifest that will not parse", () => {
    const files = new Map([
      ["package.json", buf("{ not json")],
      ["index.d.ts", buf("export {};")],
    ]);
    expect(resolveTypesEntry(files)).toBe("index.d.ts");
  });

  it("returns null when there is nothing to point at", () => {
    expect(resolveTypesEntry(new Map([["index.js", buf("")]]))).toBeNull();
  });

  it("does not follow a types field out of the package", () => {
    const files = new Map([
      ["package.json", buf(JSON.stringify({ types: "/etc/passwd" }))],
      ["index.d.ts", buf("export {};")],
    ]);
    expect(resolveTypesEntry(files)).toBe("index.d.ts");
  });
});
