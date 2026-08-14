import { describe, expect, it } from "vitest";
import { extractApiSurface, SurfaceExtractionError } from "../../src/detect/dts-surface.ts";
import { diffSurfaces } from "../../src/detect/api-surface.ts";

/**
 * Surface extraction with the TypeScript compiler.
 *
 * `api-surface.ts` refuses to parse declarations itself because an
 * approximation silently mis-reports on the cases that matter. These tests are
 * mostly those cases — re-exports, declaration merging, overloads — plus the
 * one that is not about correctness at all: a compiler host that cannot be
 * turned into a file reader by a package we do not control.
 */

function surface(files: Record<string, string>, entry = "/index.d.ts") {
  return extractApiSurface({
    packageName: "acme-sdk",
    version: "1.0.0",
    entry,
    files: new Map(Object.entries(files)),
  });
}

function named(files: Record<string, string>, name: string) {
  return surface(files).symbols.find((s) => s.name === name);
}

describe("what it finds", () => {
  it("extracts exported functions, classes, interfaces, types and consts", () => {
    const symbols = surface({
      "/index.d.ts": `
        export declare function createClient(key: string): Client;
        export declare class Client { send(body: string): void; }
        export interface Options { region: string; }
        export type Handler = (event: string) => void;
        export declare const VERSION: string;
      `,
    }).symbols;

    expect(symbols.map((s) => `${s.name}:${s.kind}`).sort()).toEqual([
      "Client:class",
      "Handler:type",
      "Options:interface",
      "VERSION:const",
      "createClient:function",
    ]);
  });

  it("follows re-exports", () => {
    // The case a regex parser sees only the re-export line for. It is also the
    // normal shape of a package with an index barrel, so getting it wrong
    // would mis-report most of the ecosystem.
    const symbols = surface({
      "/index.d.ts": `export { createClient } from "./client";`,
      "/client.d.ts": `export declare function createClient(key: string): void;`,
    }).symbols;

    expect(symbols.map((s) => s.name)).toEqual(["createClient"]);
    expect(symbols[0]?.kind).toBe("function");
  });

  it("follows a renaming re-export under the name consumers use", () => {
    const symbols = surface({
      "/index.d.ts": `export { makeClient as createClient } from "./client";`,
      "/client.d.ts": `export declare function makeClient(key: string): void;`,
    }).symbols;
    expect(symbols.map((s) => s.name)).toEqual(["createClient"]);
  });

  it("sees the whole of a merged interface", () => {
    // Declaration merging means the text of any one declaration is not the
    // type. This is the case that fails silently without a compiler.
    const merged = named(
      {
        "/index.d.ts": `
          export interface Options { region: string; }
          export interface Options { retries: number; }
        `,
      },
      "Options",
    );
    expect(merged?.signature).toContain("region");
    expect(merged?.signature).toContain("retries");
  });

  it("captures every overload of a function", () => {
    const overloaded = named(
      {
        "/index.d.ts": `
          export declare function send(body: string): void;
          export declare function send(body: string, retries: number): void;
        `,
      },
      "send",
    );
    expect(overloaded?.signature).toContain("retries");
  });

  it("marks deprecated symbols", () => {
    const deprecated = named(
      {
        "/index.d.ts": `
          /** @deprecated use createClient */
          export declare function makeClient(key: string): void;
        `,
      },
      "makeClient",
    );
    expect(deprecated?.deprecated).toBe(true);
  });

  it("does not mark undeprecated symbols", () => {
    expect(named({ "/index.d.ts": `export declare const x: string;` }, "x")?.deprecated).toBe(
      undefined,
    );
  });

  it("describes a namespace by what it exports", () => {
    // Rendering the namespace object itself would compare two things that
    // always look identical.
    const ns = named(
      {
        "/index.d.ts": `
          export declare namespace errors {
            class Timeout {}
            class Refused {}
          }
        `,
      },
      "errors",
    );
    expect(ns?.kind).toBe("namespace");
    expect(ns?.signature).toContain("Timeout");
    expect(ns?.signature).toContain("Refused");
  });

  it("treats an unmarked ambient declaration as exported, because TypeScript does", () => {
    // Surprising, and correct. In an ambient external module — which is what a
    // .d.ts containing an export is — the `export` modifier is optional and
    // every top-level declaration is part of the module's exports. A consumer
    // really can `import { internal }`, so removing it really would break
    // them, and reporting it is the honest answer rather than an over-count.
    //
    // This is the sort of rule a regex parser gets wrong in the other
    // direction: it would look for the `export` keyword and miss the symbol.
    const symbols = surface({
      "/index.d.ts": `
        declare function internal(): void;
        export declare function published(): void;
      `,
    }).symbols;
    expect(symbols.map((s) => s.name)).toEqual(["internal", "published"]);
  });

  it("does not report a symbol that is genuinely module-local", () => {
    const symbols = surface({
      "/index.d.ts": `
        import type { Hidden } from "./private";
        export declare function published(h: Hidden): void;
      `,
      "/private.d.ts": `export interface Hidden { x: string; }`,
    }).symbols;
    expect(symbols.map((s) => s.name)).toEqual(["published"]);
  });
});

describe("determinism", () => {
  it("produces byte-identical surfaces for identical declarations", () => {
    // Two extractions are only ever compared with each other, so any
    // instability here becomes a phantom breaking change and a wave of pull
    // requests nobody asked for.
    const files = {
      "/index.d.ts": `
        export declare function b(): void;
        export declare function a(): void;
        export interface C { z: string; a: number; }
      `,
    };
    expect(JSON.stringify(surface(files))).toBe(JSON.stringify(surface(files)));
  });

  it("orders symbols by name regardless of declaration order", () => {
    const forwards = surface({
      "/index.d.ts": `export declare const a: string; export declare const b: string;`,
    });
    const backwards = surface({
      "/index.d.ts": `export declare const b: string; export declare const a: string;`,
    });
    expect(forwards.symbols.map((s) => s.name)).toEqual(backwards.symbols.map((s) => s.name));
  });
});

describe("feeding the diff", () => {
  it("reports a removed export as breaking", () => {
    const before = extractApiSurface({
      packageName: "acme-sdk",
      version: "1.0.0",
      entry: "/index.d.ts",
      files: new Map([
        ["/index.d.ts", `export declare function a(): void; export declare function b(): void;`],
      ]),
    });
    const after = extractApiSurface({
      packageName: "acme-sdk",
      version: "2.0.0",
      entry: "/index.d.ts",
      files: new Map([["/index.d.ts", `export declare function a(): void;`]]),
    });

    const diff = diffSurfaces(before, after);
    expect(diff.removedCount).toBe(1);
    expect(diff.impactedSymbols).toContain("b");
  });

  it("reports a changed signature as breaking", () => {
    const before = extractApiSurface({
      packageName: "acme-sdk",
      version: "1.0.0",
      entry: "/index.d.ts",
      files: new Map([["/index.d.ts", `export declare function send(body: string): void;`]]),
    });
    const after = extractApiSurface({
      packageName: "acme-sdk",
      version: "2.0.0",
      entry: "/index.d.ts",
      files: new Map([
        ["/index.d.ts", `export declare function send(body: string, retries: number): void;`],
      ]),
    });

    const diff = diffSurfaces(before, after);
    expect(diff.impactedSymbols).toContain("send");
  });

  it("does not report an added export as breaking", () => {
    const before = extractApiSurface({
      packageName: "acme-sdk",
      version: "1.0.0",
      entry: "/index.d.ts",
      files: new Map([["/index.d.ts", `export declare function a(): void;`]]),
    });
    const after = extractApiSurface({
      packageName: "acme-sdk",
      version: "1.1.0",
      entry: "/index.d.ts",
      files: new Map([
        ["/index.d.ts", `export declare function a(): void; export declare function b(): void;`],
      ]),
    });
    expect(diffSurfaces(before, after).impactedSymbols).toEqual([]);
  });

  it("survives a reformatted but unchanged declaration", () => {
    // Whitespace churn between releases must not look like a breaking change.
    const before = extractApiSurface({
      packageName: "acme-sdk",
      version: "1.0.0",
      entry: "/index.d.ts",
      files: new Map([["/index.d.ts", `export interface O { a: string; b: number }`]]),
    });
    const after = extractApiSurface({
      packageName: "acme-sdk",
      version: "1.0.1",
      entry: "/index.d.ts",
      files: new Map([
        ["/index.d.ts", `export interface O {\n\n  b: number;\n\n  a: string;\n\n}`],
      ]),
    });
    expect(diffSurfaces(before, after).changes).toEqual([]);
  });
});

describe("the compiler host reads nothing", () => {
  it("cannot be made to read a file off disk through a triple-slash reference", () => {
    // TypeScript resolves these. With a filesystem-backed host, a published
    // package would be handing us a file reader.
    const symbols = surface({
      "/index.d.ts": `
        /// <reference path="../../../../etc/passwd" />
        export declare const x: string;
      `,
    }).symbols;
    expect(symbols.map((s) => s.name)).toEqual(["x"]);
  });

  it("cannot be made to read a file off disk through an import", () => {
    const symbols = surface({
      "/index.d.ts": `
        import type { Secret } from "/etc/shadow";
        export declare const x: string;
      `,
    }).symbols;
    expect(symbols.map((s) => s.name)).toEqual(["x"]);
  });

  it("drops a re-export of a module it was not given", () => {
    // Dropping is right: we cannot describe what we cannot see, and an empty
    // description would compare as a removal.
    const symbols = surface({
      "/index.d.ts": `
        export { hidden } from "./not-supplied";
        export declare const visible: string;
      `,
    }).symbols;
    expect(symbols.map((s) => s.name)).toEqual(["visible"]);
  });
});

describe("bounds and refusals", () => {
  it("refuses an entry that is not among the supplied files", () => {
    expect(() =>
      extractApiSurface({
        packageName: "a",
        version: "1.0.0",
        entry: "/missing.d.ts",
        files: new Map([["/index.d.ts", "export {};"]]),
      }),
    ).toThrow(SurfaceExtractionError);
  });

  it("refuses more declarations than the byte ceiling", () => {
    // Type checking is CPU-bound on input we do not control.
    expect(() =>
      extractApiSurface(
        {
          packageName: "a",
          version: "1.0.0",
          entry: "/index.d.ts",
          files: new Map([["/index.d.ts", "x".repeat(2_000)]]),
        },
        { maxTotalBytes: 1_000 },
      ),
    ).toThrow(/exceeds the ceiling/);
  });

  it("refuses more files than the file ceiling", () => {
    const files = new Map<string, string>();
    for (let i = 0; i < 10; i++) files.set(`/f${i}.d.ts`, "export {};");
    files.set("/index.d.ts", "export {};");
    expect(() =>
      extractApiSurface(
        { packageName: "a", version: "1.0.0", entry: "/index.d.ts", files },
        { maxFiles: 5 },
      ),
    ).toThrow(/exceeds the ceiling/);
  });

  it("truncates rather than returning an unbounded surface", () => {
    const declarations = Array.from(
      { length: 50 },
      (_, i) => `export declare const s${i}: string;`,
    ).join("\n");
    const result = extractApiSurface(
      {
        packageName: "a",
        version: "1.0.0",
        entry: "/index.d.ts",
        files: new Map([["/index.d.ts", declarations]]),
      },
      { maxSymbols: 10 },
    );
    expect(result.symbols).toHaveLength(10);
  });

  it("refuses a declaration file that is not a module", () => {
    // Ambient globals cannot be diffed this way. Reporting an empty surface
    // would read as "everything was removed" and open a pull request against
    // every consumer.
    expect(() => surface({ "/index.d.ts": `declare const x: string;` })).toThrow(
      /not a module/,
    );
  });
});
