/**
 * API surface extraction, using the TypeScript compiler.
 *
 * `api-surface.ts` states why this cannot be regular expressions: an
 * approximation looks right on the examples you tested and silently
 * mis-reports on declaration merging, re-exports, conditional types, and
 * overloads. Since this decides whether thousands of pull requests get opened,
 * a plausible-looking wrong answer is worse than no answer.
 *
 * ── The compiler host reads nothing ─────────────────────────────────────────
 *
 * Declaration files come from a package registry and are written by whoever
 * published the package. Handing them to a compiler with a filesystem-backed
 * host is handing an attacker a file reader:
 *
 *     /// <reference path="../../../../etc/passwd" />
 *
 * TypeScript resolves that, and the contents become part of a program whose
 * output we then act on. The same is true of `import` specifiers reaching into
 * `node_modules`, and of `@types` resolution.
 *
 * So the host here is backed by a map and nothing else. A path that is not in
 * the map does not exist — there is no fallback to disk, and `readFile` cannot
 * escape the map because it never touches `fs`. This is the same posture as
 * the sandbox in ADR-0006, applied to the one place a compiler runs inside the
 * control plane.
 *
 * ── No lib, deliberately ─────────────────────────────────────────────────────
 *
 * `noLib` keeps `lib.d.ts` out of the program. That means `Promise<Foo>`
 * resolves to nothing and renders as the name it was written with, rather than
 * as whatever the installed TypeScript's lib says today.
 *
 * That is the behaviour we want. Two surfaces are only ever compared with each
 * other, both extracted this way, so a systematic omission cancels out — while
 * a lib that changes under us would make a package look like it had changed
 * when only our toolchain did. Stability of the comparison matters more here
 * than completeness of any single extraction.
 */

import ts from "typescript";
import type { ApiSurface, ExportedSymbol, SymbolKind } from "./api-surface.ts";

export class SurfaceExtractionError extends Error {
  override readonly name = "SurfaceExtractionError";
}

export interface ExtractInput {
  readonly packageName: string;
  readonly version: string;
  /** Entry declaration file. Must be a key of `files`. */
  readonly entry: string;
  /** Declaration files, keyed by path. The whole filesystem, as far as tsc is concerned. */
  readonly files: ReadonlyMap<string, string>;
}

export interface ExtractOptions {
  /**
   * Ceiling on total declaration bytes.
   *
   * Type checking is CPU-bound on input we do not control, and a pathological
   * declaration file is a denial-of-service with no network component. Bounding
   * the input is a partial answer; the complete one is running extraction
   * somewhere it can be killed, which is the sandbox (ADR-0006) and is noted as
   * a limitation rather than claimed as solved.
   */
  readonly maxTotalBytes?: number;
  readonly maxFiles?: number;
  /** Ceiling on exported symbols. A surface larger than this is truncated. */
  readonly maxSymbols?: number;
}

// Raised from 4MB after the live registry rejected it as too tight: the
// stripe package publishes 12.6MB of declarations, and a ceiling that refuses
// the largest real SDKs bounds nothing an attacker cares about while making
// the tool useless on exactly the packages worth watching. The bound is still
// here — it is a denial-of-service guard, not a correctness one — just set
// above what legitimate publishers actually ship.
const DEFAULT_MAX_TOTAL_BYTES = 32_000_000;
const DEFAULT_MAX_FILES = 500;
const DEFAULT_MAX_SYMBOLS = 5_000;

export function extractApiSurface(
  input: ExtractInput,
  options: ExtractOptions = {},
): ApiSurface {
  const maxTotalBytes = options.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES;
  const maxFiles = options.maxFiles ?? DEFAULT_MAX_FILES;
  const maxSymbols = options.maxSymbols ?? DEFAULT_MAX_SYMBOLS;

  if (!input.files.has(input.entry)) {
    throw new SurfaceExtractionError(`Entry file ${input.entry} is not among the supplied files`);
  }
  if (input.files.size > maxFiles) {
    throw new SurfaceExtractionError(
      `${input.files.size} declaration files exceeds the ceiling of ${maxFiles}`,
    );
  }

  let total = 0;
  for (const content of input.files.values()) {
    total += Buffer.byteLength(content, "utf8");
  }
  if (total > maxTotalBytes) {
    throw new SurfaceExtractionError(
      `${total} bytes of declarations exceeds the ceiling of ${maxTotalBytes}`,
    );
  }

  const host = createSealedHost(input.files);
  const program = ts.createProgram({
    rootNames: [input.entry],
    options: {
      noLib: true,
      noResolve: false,
      skipLibCheck: true,
      target: ts.ScriptTarget.ESNext,
      moduleResolution: ts.ModuleResolutionKind.Bundler,
      // Errors are expected and ignored: a declaration file torn out of its
      // package will not typecheck, and we are reading its shape rather than
      // validating it.
      noEmit: true,
    },
    host,
  });

  const checker = program.getTypeChecker();
  const source = program.getSourceFile(input.entry);
  if (!source) {
    throw new SurfaceExtractionError(`Entry file ${input.entry} produced no source file`);
  }

  const moduleSymbol = checker.getSymbolAtLocation(source);
  if (!moduleSymbol) {
    // A declaration file with no top-level `export` is a script, not a module.
    // Its declarations are globals, and a package whose public surface is
    // globals is a package we cannot diff this way — better to say so than to
    // report an empty surface, which would read as "everything was removed".
    throw new SurfaceExtractionError(
      `${input.entry} is not a module; a surface cannot be extracted from ambient globals`,
    );
  }

  const exported = checker.getExportsOfModule(moduleSymbol);
  const symbols: ExportedSymbol[] = [];

  for (const symbol of exported) {
    if (symbols.length >= maxSymbols) break;
    const described = describe(checker, symbol);
    if (described) symbols.push(described);
  }

  // Sorted, so two extractions of the same declarations produce byte-identical
  // surfaces regardless of the order the compiler happened to visit them in.
  symbols.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

  return { packageName: input.packageName, version: input.version, symbols };
}

/**
 * A compiler host with no filesystem.
 *
 * Every method that could reach disk answers from the map or answers "no".
 * `fileExists` returning false for anything unknown is what makes triple-slash
 * references and module resolution dead ends rather than a file reader.
 */
function createSealedHost(files: ReadonlyMap<string, string>): ts.CompilerHost {
  const cache = new Map<string, ts.SourceFile>();

  // Module resolution asks whether a directory exists before looking inside
  // it, so answering "no" to everything makes `export … from "./client"`
  // unresolvable. The set is derived from the supplied paths, which keeps the
  // host sealed: a directory exists only because a file we were given is in it.
  const directories = new Set<string>(["/"]);
  for (const path of files.keys()) {
    let index = path.lastIndexOf("/");
    while (index > 0) {
      directories.add(path.slice(0, index));
      index = path.lastIndexOf("/", index - 1);
    }
  }

  return {
    fileExists: (fileName) => files.has(fileName),
    readFile: (fileName) => files.get(fileName),
    directoryExists: (directoryName) => directories.has(directoryName.replace(/\/+$/, "") || "/"),
    getDirectories: () => [],
    getSourceFile(fileName, languageVersion) {
      const cached = cache.get(fileName);
      if (cached) return cached;
      const text = files.get(fileName);
      if (text === undefined) return undefined;
      const created = ts.createSourceFile(fileName, text, languageVersion, true);
      cache.set(fileName, created);
      return created;
    },
    // No lib is loaded, so the name is never resolved to a file. Returning a
    // path that is not in the map keeps that true even if a future option
    // change re-enables lib loading by accident.
    getDefaultLibFileName: () => "<no-lib>",
    writeFile: () => {
      throw new SurfaceExtractionError("Surface extraction must not write files");
    },
    getCurrentDirectory: () => "/",
    getCanonicalFileName: (fileName) => fileName,
    useCaseSensitiveFileNames: () => true,
    getNewLine: () => "\n",
  };
}

function describe(checker: ts.TypeChecker, symbol: ts.Symbol): ExportedSymbol | null {
  // Re-exports arrive as aliases. Following them is the whole reason for using
  // the compiler: `export { createClient } from "./client"` is part of the
  // public surface, and a regex sees only the re-export line.
  const resolved =
    symbol.flags & ts.SymbolFlags.Alias ? safeAliasOf(checker, symbol) : symbol;
  if (!resolved) return null;

  const declaration = resolved.declarations?.[0];
  if (!declaration) return null;

  const kind = kindOf(resolved);
  if (!kind) return null;

  return {
    name: symbol.getName(),
    kind,
    signature: signatureOf(checker, resolved, declaration, kind),
    ...(isDeprecated(resolved, checker) ? { deprecated: true } : {}),
  };
}

function safeAliasOf(checker: ts.TypeChecker, symbol: ts.Symbol): ts.Symbol | null {
  try {
    return checker.getAliasedSymbol(symbol);
  } catch {
    // An alias to something that does not resolve — a re-export of a module we
    // were not given. Dropping it is right: we cannot describe what we cannot
    // see, and inventing an empty description would read as a removal.
    return null;
  }
}

function kindOf(symbol: ts.Symbol): SymbolKind | null {
  const flags = symbol.flags;
  // Order matters: a symbol can carry several flags through declaration
  // merging (a class is also an interface; an enum is also a variable), and
  // the first match here is the one a consumer would name it by.
  if (flags & ts.SymbolFlags.Class) return "class";
  if (flags & ts.SymbolFlags.Enum) return "enum";
  if (flags & ts.SymbolFlags.Interface) return "interface";
  if (flags & ts.SymbolFlags.TypeAlias) return "type";
  if (flags & ts.SymbolFlags.Function) return "function";
  if (flags & ts.SymbolFlags.Module) return "namespace";
  if (flags & (ts.SymbolFlags.Variable | ts.SymbolFlags.Property)) return "const";
  return null;
}

const TYPE_FORMAT =
  ts.TypeFormatFlags.NoTruncation |
  ts.TypeFormatFlags.UseFullyQualifiedType |
  ts.TypeFormatFlags.WriteArrowStyleSignature;

/**
 * A normalised, comparable rendering of the declaration.
 *
 * Compared as an opaque string — `api-surface.ts` decides what a difference
 * means, and deliberately does not attempt to understand type compatibility.
 * The only property required here is that identical declarations render
 * identically and different ones do not.
 */
function signatureOf(
  checker: ts.TypeChecker,
  symbol: ts.Symbol,
  declaration: ts.Declaration,
  kind: SymbolKind,
): string {
  try {
    if (kind === "interface" || kind === "class") {
      // Built from members rather than from the declaration text, because
      // declaration merging means the text of any one declaration is not the
      // type. This is the case a regex parser gets wrong silently.
      const type = checker.getDeclaredTypeOfSymbol(symbol);
      const members = checker
        .getPropertiesOfType(type)
        .map((member) => {
          const memberDeclaration = member.declarations?.[0];
          const memberType = memberDeclaration
            ? checker.typeToString(
                checker.getTypeOfSymbolAtLocation(member, memberDeclaration),
                undefined,
                TYPE_FORMAT,
              )
            : "unknown";
          return `${member.getName()}: ${memberType}`;
        })
        .sort();

      const calls = checker
        .getSignaturesOfType(type, ts.SignatureKind.Call)
        .map((signature) => checker.signatureToString(signature, undefined, TYPE_FORMAT))
        .sort();
      const constructs = checker
        .getSignaturesOfType(type, ts.SignatureKind.Construct)
        .map((signature) => `new ${checker.signatureToString(signature, undefined, TYPE_FORMAT)}`)
        .sort();

      return [...constructs, ...calls, ...members].join("; ");
    }

    if (kind === "namespace") {
      // A namespace's surface is the surface of what it exports. Rendering the
      // namespace itself would compare two objects that always look the same.
      return checker
        .getExportsOfModule(symbol)
        .map((member) => `${member.getName()}: ${kindOf(member) ?? "unknown"}`)
        .sort()
        .join("; ");
    }

    const type = checker.getTypeOfSymbolAtLocation(symbol, declaration);
    return checker.typeToString(type, undefined, TYPE_FORMAT);
  } catch (error) {
    // The compiler can throw on genuinely degenerate declarations. A surface
    // that cannot be rendered is recorded as such rather than as empty — the
    // difference matters, because empty compares equal to empty and would hide
    // a real change behind an extraction failure.
    return `<unrenderable: ${(error as Error).name}>`;
  }
}

function isDeprecated(symbol: ts.Symbol, checker: ts.TypeChecker): boolean {
  return symbol.getJsDocTags(checker).some((tag) => tag.name === "deprecated");
}
