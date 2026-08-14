/**
 * Unified diff generation — the inverse of `src/policy/diff.ts`.
 *
 * ── Why Driftless authors the diff rather than the model ─────────────────────
 *
 * The obvious design is to ask the model for a patch and apply it. That design
 * has a security problem that is easy to miss: the diff would be *both* the
 * artifact the policy engine inspects and the artifact git applies, and those
 * two readings are not guaranteed to agree. `git apply --3way` will relocate a
 * hunk whose line numbers are wrong; a hunk header that lies about its length
 * is tolerated by some appliers and not others. Any gap between "what the
 * policy engine parsed" and "what landed in the branch" is a gap an injection
 * can be aimed at.
 *
 * So the model never writes diff syntax. It proposes anchored replacements
 * (`src/agent/edit-plan.ts`), Driftless applies them to content it already
 * holds, and this module renders the before/after pair. The diff is therefore
 * a *description* of a transformation that has already been performed, not an
 * instruction to perform one — which makes the policy engine's reading of it
 * authoritative by construction.
 *
 * Dependency-free for the same reason the parser is: it sits underneath a
 * security control, so it must stay inspectable and must not become a
 * supply-chain surface of its own.
 */

export interface FileChange {
  readonly path: string;
  readonly before: string;
  readonly after: string;
}

export interface FormatOptions {
  /** Context lines around each hunk. Three is git's default. */
  readonly context?: number;
}

/**
 * Above this many cells the quadratic line-matching is abandoned in favour of
 * replacing the changed region wholesale. The result is a valid, correct diff
 * that is merely less pretty — and a migration that rewrites tens of thousands
 * of lines is going to be escalated by `diff-scale` regardless.
 */
const MAX_MATRIX_CELLS = 4_000_000;

export function formatUnifiedDiff(
  changes: readonly FileChange[],
  options: FormatOptions = {},
): string {
  const context = options.context ?? 3;
  const out: string[] = [];

  for (const change of changes) {
    if (change.before === change.after) continue;
    const body = formatFile(change, context);
    if (body) out.push(body);
  }

  return out.join("");
}

function formatFile(change: FileChange, context: number): string {
  const before = toLines(change.before);
  const after = toLines(change.after);
  const ops = diffLines(before.lines, after.lines);

  // A file can differ only in whether its last line is terminated, which the
  // line-based comparison above cannot see — both sides split to identical
  // arrays. Git represents it by rewriting the final line, so we do too;
  // without this, a real change renders as an empty diff.
  if (before.noEofNewline !== after.noEofNewline) {
    const last = ops[ops.length - 1];
    if (last && last.kind === "equal") {
      ops.splice(
        ops.length - 1,
        1,
        { kind: "delete", text: last.text, oldIndex: last.oldIndex, newIndex: null },
        { kind: "insert", text: last.text, oldIndex: null, newIndex: last.newIndex },
      );
    }
  }

  const hunks = groupIntoHunks(ops, context);
  if (hunks.length === 0) return "";

  const quoted = quotePath(change.path);
  const lines: string[] = [
    `diff --git a/${quoted} b/${quoted}`,
    `--- a/${quoted}`,
    `+++ b/${quoted}`,
  ];

  for (const hunk of hunks) {
    lines.push(
      `@@ -${hunk.oldStart},${hunk.oldLines} +${hunk.newStart},${hunk.newLines} @@`,
    );
    for (const op of hunk.ops) {
      switch (op.kind) {
        case "equal":
          lines.push(` ${op.text}`);
          if (op.oldIndex === before.lines.length - 1 && before.noEofNewline) {
            lines.push(NO_NEWLINE);
          }
          break;
        case "delete":
          lines.push(`-${op.text}`);
          if (op.oldIndex === before.lines.length - 1 && before.noEofNewline) {
            lines.push(NO_NEWLINE);
          }
          break;
        case "insert":
          lines.push(`+${op.text}`);
          if (op.newIndex === after.lines.length - 1 && after.noEofNewline) {
            lines.push(NO_NEWLINE);
          }
          break;
      }
    }
  }

  return `${lines.join("\n")}\n`;
}

const NO_NEWLINE = "\\ No newline at end of file";

interface Split {
  readonly lines: readonly string[];
  /** True when the file's last line is not terminated. */
  readonly noEofNewline: boolean;
}

function toLines(text: string): Split {
  if (text === "") return { lines: [], noEofNewline: false };
  if (text.endsWith("\n")) return { lines: text.slice(0, -1).split("\n"), noEofNewline: false };
  return { lines: text.split("\n"), noEofNewline: true };
}

type Op =
  | { kind: "equal"; text: string; oldIndex: number; newIndex: number }
  | { kind: "delete"; text: string; oldIndex: number; newIndex: null }
  | { kind: "insert"; text: string; oldIndex: null; newIndex: number };

/**
 * Longest-common-subsequence line matching, with the shared head and tail
 * trimmed first.
 *
 * The trimming is what keeps this practical: anchored replacements change a
 * small region of a file, so after trimming the matrix is usually a handful of
 * lines square regardless of how large the file is.
 */
function diffLines(before: readonly string[], after: readonly string[]): Op[] {
  let head = 0;
  while (head < before.length && head < after.length && before[head] === after[head]) head++;

  let tail = 0;
  while (
    tail < before.length - head &&
    tail < after.length - head &&
    before[before.length - 1 - tail] === after[after.length - 1 - tail]
  ) {
    tail++;
  }

  const ops: Op[] = [];
  for (let i = 0; i < head; i++) {
    ops.push({ kind: "equal", text: before[i] as string, oldIndex: i, newIndex: i });
  }

  const oldMiddle = before.slice(head, before.length - tail);
  const newMiddle = after.slice(head, after.length - tail);

  for (const op of diffMiddle(oldMiddle, newMiddle, head)) ops.push(op);

  for (let i = 0; i < tail; i++) {
    const oldIndex = before.length - tail + i;
    ops.push({
      kind: "equal",
      text: before[oldIndex] as string,
      oldIndex,
      newIndex: after.length - tail + i,
    });
  }

  return ops;
}

function diffMiddle(
  before: readonly string[],
  after: readonly string[],
  offset: number,
): Op[] {
  if (before.length === 0 && after.length === 0) return [];

  if (before.length === 0 || after.length === 0) {
    return wholesale(before, after, offset);
  }

  if ((before.length + 1) * (after.length + 1) > MAX_MATRIX_CELLS) {
    return wholesale(before, after, offset);
  }

  const rows = before.length + 1;
  const cols = after.length + 1;
  const table = new Uint32Array(rows * cols);

  for (let i = before.length - 1; i >= 0; i--) {
    for (let j = after.length - 1; j >= 0; j--) {
      table[i * cols + j] =
        before[i] === after[j]
          ? (table[(i + 1) * cols + (j + 1)] as number) + 1
          : Math.max(table[(i + 1) * cols + j] as number, table[i * cols + (j + 1)] as number);
    }
  }

  const ops: Op[] = [];
  let i = 0;
  let j = 0;
  while (i < before.length && j < after.length) {
    if (before[i] === after[j]) {
      ops.push({
        kind: "equal",
        text: before[i] as string,
        oldIndex: offset + i,
        newIndex: offset + j,
      });
      i++;
      j++;
    } else if ((table[(i + 1) * cols + j] as number) >= (table[i * cols + (j + 1)] as number)) {
      ops.push({ kind: "delete", text: before[i] as string, oldIndex: offset + i, newIndex: null });
      i++;
    } else {
      ops.push({ kind: "insert", text: after[j] as string, oldIndex: null, newIndex: offset + j });
      j++;
    }
  }
  while (i < before.length) {
    ops.push({ kind: "delete", text: before[i] as string, oldIndex: offset + i, newIndex: null });
    i++;
  }
  while (j < after.length) {
    ops.push({ kind: "insert", text: after[j] as string, oldIndex: null, newIndex: offset + j });
    j++;
  }
  return ops;
}

/** Every old line removed, every new line added. Correct, just coarse. */
function wholesale(
  before: readonly string[],
  after: readonly string[],
  offset: number,
): Op[] {
  const ops: Op[] = [];
  before.forEach((text, index) =>
    ops.push({ kind: "delete", text, oldIndex: offset + index, newIndex: null }),
  );
  after.forEach((text, index) =>
    ops.push({ kind: "insert", text, oldIndex: null, newIndex: offset + index }),
  );
  return ops;
}

interface Hunk {
  oldStart: number;
  oldLines: number;
  newStart: number;
  newLines: number;
  ops: Op[];
}

/**
 * Collect changed regions with `context` lines either side, merging regions
 * whose contexts would overlap.
 */
function groupIntoHunks(ops: readonly Op[], context: number): Hunk[] {
  const changed: number[] = [];
  ops.forEach((op, index) => {
    if (op.kind !== "equal") changed.push(index);
  });
  if (changed.length === 0) return [];

  const ranges: { start: number; end: number }[] = [];
  for (const index of changed) {
    const start = Math.max(0, index - context);
    const end = Math.min(ops.length - 1, index + context);
    const last = ranges[ranges.length - 1];
    // `<= last.end + 1` merges ranges that touch as well as ranges that
    // overlap, so two adjacent hunks never emit a one-line gap of context.
    if (last && start <= last.end + 1) last.end = Math.max(last.end, end);
    else ranges.push({ start, end });
  }

  return ranges.map((range) => {
    const slice = ops.slice(range.start, range.end + 1);
    let oldStart = 0;
    let newStart = 0;
    let oldLines = 0;
    let newLines = 0;

    for (const op of slice) {
      if (op.kind !== "insert") {
        if (oldLines === 0) oldStart = (op.oldIndex as number) + 1;
        oldLines++;
      }
      if (op.kind !== "delete") {
        if (newLines === 0) newStart = (op.newIndex as number) + 1;
        newLines++;
      }
    }

    // A hunk of pure insertions has no old line to anchor to; git writes the
    // position after which the lines are inserted, with a length of zero.
    if (oldLines === 0) {
      const firstNew = slice.find((op) => op.kind === "insert");
      oldStart = firstNew ? (firstNew.newIndex as number) : 0;
    }
    if (newLines === 0) {
      const firstOld = slice.find((op) => op.kind === "delete");
      newStart = firstOld ? (firstOld.oldIndex as number) : 0;
    }

    return { oldStart, oldLines, newStart, newLines, ops: slice };
  });
}

/**
 * Paths reach a shell-adjacent format, so anything that could break the header
 * is refused rather than escaped. Repository paths are attacker-controlled in
 * the threat model that matters here (§5.1), and a path containing a newline
 * would let a single file header inject an entire second file into the diff —
 * one the policy engine would then attribute to us.
 */
function quotePath(path: string): string {
  if (path.length === 0 || path.length > 4096) {
    throw new UnifiedDiffError(`Refusing to render a diff for a path of length ${path.length}`);
  }
  if (/[\n\r\t\0]/.test(path) || path.includes(" b/")) {
    throw new UnifiedDiffError(
      `Refusing to render a diff for a path containing control characters or a header delimiter`,
    );
  }
  return path;
}

export class UnifiedDiffError extends Error {
  override readonly name = "UnifiedDiffError";
}
