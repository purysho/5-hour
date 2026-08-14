/**
 * Reading a package tarball, in memory, without trusting it.
 *
 * Package tarballs are attacker-authored by definition — anyone can publish to
 * npm — and this code runs inside the control plane, so the posture is the
 * same as everywhere else content crosses that line: assume the input is
 * hostile and give it as little to work with as possible.
 *
 * ── Nothing is written to disk ──────────────────────────────────────────────
 *
 * Not "written carefully to a temporary directory with path checks" — not
 * written at all. Entries are decoded into a map keyed by their normalised
 * path. That is what makes the entire family of extraction attacks
 * inapplicable rather than defended against:
 *
 *   `../../../.ssh/authorized_keys`  — a map key, not a path
 *   a symlink to `/etc/passwd`       — skipped; only regular files are decoded
 *   a 400:1 decompression bomb       — refused at the byte ceiling
 *
 * There is no `mkdir`, no `writeFile`, and no `fs` import in this file, which
 * is a property worth preserving: the moment one appears, every one of those
 * three lines needs a real defence instead of an absence.
 *
 * ── Bounds are refusals, not truncations ────────────────────────────────────
 *
 * A tarball that exceeds a ceiling is refused whole. Truncating would leave a
 * partial file set that looks complete, and a surface extracted from half a
 * package reads as "the other half was removed" — which would open a pull
 * request against every consumer.
 *
 * Dependency-free on purpose: this is a parser for hostile input, so it should
 * be small enough to read in one sitting and should not become a supply-chain
 * surface of its own.
 */

import { gunzipSync } from "node:zlib";

export class TarballError extends Error {
  override readonly name = "TarballError";
}

export interface TarballLimits {
  /** Compressed bytes accepted before gunzip is attempted. */
  readonly maxCompressedBytes?: number;
  /** Uncompressed bytes. The decompression-bomb ceiling. */
  readonly maxUncompressedBytes?: number;
  readonly maxEntries?: number;
  readonly maxEntryBytes?: number;
}

const DEFAULT_LIMITS = {
  maxCompressedBytes: 32 * 1024 * 1024,
  maxUncompressedBytes: 128 * 1024 * 1024,
  maxEntries: 20_000,
  maxEntryBytes: 8 * 1024 * 1024,
} as const;

const BLOCK = 512;

export interface TarEntry {
  /** Normalised, with the leading `package/` directory removed. */
  readonly path: string;
  readonly content: Buffer;
}

/**
 * Decodes a gzipped tarball into its regular files.
 *
 * `filter` is applied before an entry's bytes are copied, so declining a file
 * costs nothing — which is what makes it reasonable to run this over a package
 * whose tarball is mostly source we do not want.
 */
export function readTarball(
  gzipped: Buffer,
  options: { limits?: TarballLimits; filter?: (path: string) => boolean } = {},
): Map<string, Buffer> {
  const limits = { ...DEFAULT_LIMITS, ...options.limits };

  if (gzipped.byteLength > limits.maxCompressedBytes) {
    throw new TarballError(
      `Tarball is ${gzipped.byteLength} bytes, above the ceiling of ${limits.maxCompressedBytes}`,
    );
  }

  let tar: Buffer;
  try {
    // `maxOutputLength` makes the ceiling the decompressor's problem rather
    // than ours. Checking the size after inflating would mean having already
    // allocated whatever the bomb asked for.
    tar = gunzipSync(gzipped, { maxOutputLength: limits.maxUncompressedBytes });
  } catch (error) {
    throw new TarballError(`Tarball could not be decompressed: ${(error as Error).message}`);
  }

  const files = new Map<string, Buffer>();
  let offset = 0;
  let entries = 0;
  /** Set by a GNU long-name entry, consumed by the entry that follows it. */
  let pendingLongName: string | null = null;

  while (offset + BLOCK <= tar.byteLength) {
    const header = tar.subarray(offset, offset + BLOCK);
    if (isZeroBlock(header)) break; // End-of-archive marker.

    const rawName = readString(header, 0, 100);
    const size = readOctal(header, 124, 12);
    const typeFlag = String.fromCharCode(header[156] as number);
    const prefix = readString(header, 345, 155);

    if (size < 0 || !Number.isFinite(size)) {
      throw new TarballError("Tarball entry declares an unreadable size");
    }
    if (size > limits.maxEntryBytes) {
      throw new TarballError(
        `Tarball entry ${rawName} is ${size} bytes, above the ceiling of ${limits.maxEntryBytes}`,
      );
    }

    const dataStart = offset + BLOCK;
    const dataEnd = dataStart + size;
    if (dataEnd > tar.byteLength) {
      throw new TarballError("Tarball entry runs past the end of the archive");
    }

    if (typeFlag === "L") {
      // GNU long name: this entry's *content* is the name of the next entry.
      pendingLongName = tar.subarray(dataStart, dataEnd).toString("utf8").replace(/\0+$/, "");
    } else {
      const name = pendingLongName ?? (prefix ? `${prefix}/${rawName}` : rawName);
      pendingLongName = null;

      // Type flags: "0" and "\0" are regular files. Everything else —
      // directories, symlinks, hardlinks, character and block devices, FIFOs,
      // and the pax/GNU extension records — is skipped. Only regular files
      // have contents we could want, and every one of the others is a way of
      // referring to something outside the archive.
      if (typeFlag === "0" || typeFlag === "\0") {
        if (++entries > limits.maxEntries) {
          throw new TarballError(`Tarball has more than ${limits.maxEntries} entries`);
        }
        const normalised = normalisePath(name);
        if (normalised && (!options.filter || options.filter(normalised))) {
          // Copied rather than sliced: a subarray keeps the whole decompressed
          // archive alive for as long as any one file is referenced.
          files.set(normalised, Buffer.from(tar.subarray(dataStart, dataEnd)));
        }
      }
    }

    offset = dataEnd + padding(size);
  }

  if (files.size === 0) {
    throw new TarballError("Tarball contained no matching regular files");
  }

  return files;
}

/**
 * npm tarballs put everything under a single top-level directory, almost
 * always `package/`. Stripping it makes paths match what `package.json` says,
 * which is the whole point of reading them.
 *
 * Returns null for anything that should not become a key: absolute paths,
 * paths containing `..`, and empty names. None of these can escape anything
 * here — the result is a map — but a path that tried is a signal, and letting
 * it through would make this function unsafe the day someone writes the files
 * out.
 */
function normalisePath(name: string): string | null {
  const cleaned = name.replace(/\0+$/, "").replace(/\/+$/, "");
  if (!cleaned || cleaned.startsWith("/") || cleaned.includes("\0")) return null;
  if (cleaned.split("/").some((segment) => segment === ".." )) return null;

  // An entry with no directory component is dropped rather than kept as-is.
  // npm always nests under one top-level directory, so an unnested entry
  // cannot be the target of any path in `package.json` — and keeping it would
  // let `package.json` at the archive root shadow `package/package.json`,
  // since the later write to the map wins.
  const slash = cleaned.indexOf("/");
  return slash === -1 ? null : cleaned.slice(slash + 1) || null;
}

function isZeroBlock(block: Buffer): boolean {
  for (const byte of block) if (byte !== 0) return false;
  return true;
}

function readString(block: Buffer, start: number, length: number): string {
  const raw = block.subarray(start, start + length);
  const end = raw.indexOf(0);
  return raw.subarray(0, end === -1 ? raw.length : end).toString("utf8");
}

function readOctal(block: Buffer, start: number, length: number): number {
  const text = readString(block, start, length).trim();
  if (text === "") return 0;
  const value = Number.parseInt(text, 8);
  return Number.isNaN(value) ? -1 : value;
}

function padding(size: number): number {
  const remainder = size % BLOCK;
  return remainder === 0 ? 0 : BLOCK - remainder;
}
