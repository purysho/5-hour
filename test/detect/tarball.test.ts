import { describe, expect, it } from "vitest";
import { gzipSync } from "node:zlib";
import { readTarball, TarballError } from "../../src/detect/tarball.ts";

/**
 * Reading a package tarball.
 *
 * Anyone can publish to npm, so this is a parser for hostile input running
 * inside the control plane. Most of these tests are the attacks the design
 * makes inapplicable rather than defends against — the assertion is usually
 * that the dangerous entry simply is not in the result.
 */

const BLOCK = 512;

interface EntryOptions {
  typeFlag?: string;
  /** Overrides the declared size, for the malformed-header cases. */
  declaredSize?: number;
  prefix?: string;
}

function header(name: string, size: number, options: EntryOptions = {}): Buffer {
  const block = Buffer.alloc(BLOCK, 0);
  block.write(name.slice(0, 100), 0, "utf8");
  block.write("0000644\0", 100, "utf8");
  block.write("0000000\0", 108, "utf8");
  block.write("0000000\0", 116, "utf8");
  block.write(`${(options.declaredSize ?? size).toString(8).padStart(11, "0")}\0`, 124, "utf8");
  block.write("00000000000\0", 136, "utf8");
  block.write(options.typeFlag ?? "0", 156, "utf8");
  block.write("ustar\0", 257, "utf8");
  block.write("00", 263, "utf8");
  if (options.prefix) block.write(options.prefix.slice(0, 155), 345, "utf8");

  // Checksum, computed with the checksum field read as spaces.
  block.write("        ", 148, "utf8");
  let sum = 0;
  for (const byte of block) sum += byte;
  block.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "utf8");

  return block;
}

function entry(name: string, content: string | Buffer, options: EntryOptions = {}): Buffer {
  const data = Buffer.isBuffer(content) ? content : Buffer.from(content, "utf8");
  const padding = data.byteLength % BLOCK === 0 ? 0 : BLOCK - (data.byteLength % BLOCK);
  return Buffer.concat([
    header(name, data.byteLength, options),
    data,
    Buffer.alloc(padding, 0),
  ]);
}

function tarball(...entries: Buffer[]): Buffer {
  return gzipSync(Buffer.concat([...entries, Buffer.alloc(BLOCK * 2, 0)]));
}

describe("reading files", () => {
  it("returns regular files with the package prefix stripped", () => {
    // npm puts everything under `package/`, and stripping it is what makes
    // paths match what package.json says.
    const files = readTarball(
      tarball(
        entry("package/package.json", '{"name":"acme-sdk"}'),
        entry("package/dist/index.d.ts", "export declare const x: string;"),
      ),
    );

    expect([...files.keys()].sort()).toEqual(["dist/index.d.ts", "package.json"]);
    expect(files.get("package.json")?.toString("utf8")).toBe('{"name":"acme-sdk"}');
  });

  it("applies the filter before copying an entry's bytes", () => {
    const files = readTarball(
      tarball(
        entry("package/index.d.ts", "declarations"),
        entry("package/src/huge.js", "x".repeat(10_000)),
      ),
      { filter: (path) => path.endsWith(".d.ts") },
    );
    expect([...files.keys()]).toEqual(["index.d.ts"]);
  });

  it("reads a file split across many blocks", () => {
    const content = "y".repeat(BLOCK * 3 + 17);
    const files = readTarball(tarball(entry("package/big.d.ts", content)));
    expect(files.get("big.d.ts")?.toString("utf8")).toBe(content);
  });

  it("handles an empty file", () => {
    const files = readTarball(
      tarball(entry("package/empty.d.ts", ""), entry("package/index.d.ts", "x")),
    );
    expect(files.get("empty.d.ts")?.byteLength).toBe(0);
  });

  it("reads a ustar prefix-split path", () => {
    const files = readTarball(
      tarball(entry("index.d.ts", "x", { prefix: "package/deeply/nested" })),
    );
    expect([...files.keys()]).toEqual(["deeply/nested/index.d.ts"]);
  });

  it("reads a GNU long name", () => {
    const longName = `package/${"a".repeat(120)}.d.ts`;
    const files = readTarball(
      tarball(entry("././@LongLink", `${longName}\0`, { typeFlag: "L" }), entry(longName, "x")),
    );
    expect([...files.keys()]).toEqual([`${"a".repeat(120)}.d.ts`]);
  });
});

describe("entries that are not regular files", () => {
  it("skips a symlink", () => {
    // The classic extraction attack. Here it is not defended against, it is
    // inapplicable: a symlink has no contents to decode.
    const files = readTarball(
      tarball(
        entry("package/evil", "/etc/passwd", { typeFlag: "2" }),
        entry("package/index.d.ts", "x"),
      ),
    );
    expect([...files.keys()]).toEqual(["index.d.ts"]);
  });

  it("skips a hardlink, a directory, and a device node", () => {
    const files = readTarball(
      tarball(
        entry("package/link", "", { typeFlag: "1" }),
        entry("package/dir/", "", { typeFlag: "5" }),
        entry("package/dev", "", { typeFlag: "3" }),
        entry("package/index.d.ts", "x"),
      ),
    );
    expect([...files.keys()]).toEqual(["index.d.ts"]);
  });

  it("skips a pax extended header record", () => {
    const files = readTarball(
      tarball(
        entry("package/PaxHeader", "30 mtime=1700000000.0\n", { typeFlag: "x" }),
        entry("package/index.d.ts", "x"),
      ),
    );
    expect([...files.keys()]).toEqual(["index.d.ts"]);
  });
});

describe("paths that try to escape", () => {
  it("drops a path containing ..", () => {
    const files = readTarball(
      tarball(
        entry("package/../../../.ssh/authorized_keys", "ssh-rsa AAAA"),
        entry("package/index.d.ts", "x"),
      ),
    );
    expect([...files.keys()]).toEqual(["index.d.ts"]);
    expect([...files.keys()].some((k) => k.includes(".."))).toBe(false);
  });

  it("drops an absolute path", () => {
    const files = readTarball(
      tarball(entry("/etc/cron.d/backdoor", "* * * * * root sh"), entry("package/index.d.ts", "x")),
    );
    expect([...files.keys()]).toEqual(["index.d.ts"]);
  });

  it("drops an entry with no top-level directory", () => {
    // Otherwise a `package.json` at the archive root would shadow the real
    // `package/package.json`, since the later write to the map wins.
    const files = readTarball(
      tarball(entry("package/package.json", '{"real":true}'), entry("package.json", '{"fake":true}')),
    );
    expect(files.get("package.json")?.toString("utf8")).toBe('{"real":true}');
  });
});

describe("bounds", () => {
  it("refuses a tarball above the compressed ceiling before decompressing", () => {
    const big = gzipSync(Buffer.alloc(BLOCK * 4, 0));
    expect(() => readTarball(big, { limits: { maxCompressedBytes: 4 } })).toThrow(
      /above the ceiling/,
    );
  });

  it("refuses a decompression bomb at the uncompressed ceiling", () => {
    // Zeroes compress to almost nothing, which is exactly what a bomb relies
    // on. The ceiling is enforced by the decompressor, so the bytes are never
    // allocated.
    const bomb = tarball(entry("package/bomb.txt", "0".repeat(2_000_000)));
    expect(() =>
      readTarball(bomb, { limits: { maxUncompressedBytes: 100_000 } }),
    ).toThrow(TarballError);
  });

  it("refuses an entry above the per-entry ceiling", () => {
    const big = tarball(entry("package/big.d.ts", "z".repeat(100_000)));
    expect(() => readTarball(big, { limits: { maxEntryBytes: 1_000 } })).toThrow(
      /above the ceiling/,
    );
  });

  it("refuses more entries than the entry ceiling", () => {
    const many = tarball(
      ...Array.from({ length: 20 }, (_, i) => entry(`package/f${i}.d.ts`, "x")),
    );
    expect(() => readTarball(many, { limits: { maxEntries: 5 } })).toThrow(/more than 5 entries/);
  });

  it("refuses whole rather than truncating", () => {
    // A partial file set looks complete, and a surface extracted from half a
    // package reads as "the other half was removed".
    const many = tarball(
      ...Array.from({ length: 20 }, (_, i) => entry(`package/f${i}.d.ts`, "x")),
    );
    let caught: unknown;
    try {
      readTarball(many, { limits: { maxEntries: 5 } });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(TarballError);
  });
});

describe("malformed archives", () => {
  it("refuses input that is not gzip", () => {
    expect(() => readTarball(Buffer.from("not a tarball"))).toThrow(/could not be decompressed/);
  });

  it("refuses an entry whose declared size runs past the archive", () => {
    const truncated = gzipSync(
      Buffer.concat([header("package/x.d.ts", 10, { declaredSize: 100_000 }), Buffer.alloc(64, 0)]),
    );
    expect(() => readTarball(truncated)).toThrow(/past the end/);
  });

  it("refuses an entry with an unreadable size", () => {
    const block = header("package/x.d.ts", 0);
    block.write("not-octal!!\0", 124, "utf8");
    expect(() => readTarball(gzipSync(Buffer.concat([block, Buffer.alloc(BLOCK * 2, 0)])))).toThrow(
      /unreadable size/,
    );
  });

  it("refuses an archive with nothing in it", () => {
    // Distinguishing "empty" from "no matching files" would be a false
    // precision: both mean there is no surface to extract.
    expect(() => readTarball(gzipSync(Buffer.alloc(BLOCK * 2, 0)))).toThrow(
      /no matching regular files/,
    );
  });

  it("stops at the end-of-archive marker rather than reading trailing junk", () => {
    const withJunk = gzipSync(
      Buffer.concat([
        entry("package/index.d.ts", "x"),
        Buffer.alloc(BLOCK * 2, 0),
        entry("package/after-the-end.d.ts", "y"),
      ]),
    );
    expect([...readTarball(withJunk).keys()]).toEqual(["index.d.ts"]);
  });
});
