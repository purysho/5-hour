/**
 * Unified diff parsing.
 *
 * Deliberately small and dependency-free: this parser feeds a security control
 * (ADR-0003, layer 3), so its behaviour needs to be fully inspectable and it
 * must not become a supply-chain surface of its own.
 *
 * It parses what git produces. Anything it cannot parse is surfaced as an
 * error rather than skipped — a diff the policy engine cannot read is a diff
 * the policy engine cannot approve.
 */

export interface DiffLine {
  readonly kind: "added" | "removed" | "context";
  readonly text: string;
  /** Line number in the new file for added/context lines. */
  readonly newLineNumber: number | null;
}

export interface DiffFile {
  /** Path in the new tree, or the old path for deletions. */
  readonly path: string;
  readonly oldPath: string | null;
  readonly change: "added" | "modified" | "deleted" | "renamed";
  readonly lines: readonly DiffLine[];
  readonly addedCount: number;
  readonly removedCount: number;
}

export interface ParsedDiff {
  readonly files: readonly DiffFile[];
  readonly addedCount: number;
  readonly removedCount: number;
}

export class DiffParseError extends Error {
  override readonly name = "DiffParseError";
}

const GIT_HEADER = /^diff --git a\/(.+?) b\/(.+)$/;
const HUNK_HEADER = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/;

export function parseUnifiedDiff(text: string): ParsedDiff {
  const files: DiffFile[] = [];
  const lines = text.split("\n");

  let current: {
    path: string;
    oldPath: string | null;
    change: DiffFile["change"];
    lines: DiffLine[];
  } | null = null;
  let newLineCursor = 0;
  let inHunk = false;

  const flush = (): void => {
    if (!current) return;
    files.push({
      path: current.path,
      oldPath: current.oldPath,
      change: current.change,
      lines: current.lines,
      addedCount: current.lines.filter((l) => l.kind === "added").length,
      removedCount: current.lines.filter((l) => l.kind === "removed").length,
    });
    current = null;
  };

  for (const line of lines) {
    const header = GIT_HEADER.exec(line);
    if (header) {
      flush();
      const oldPath = header[1] as string;
      const newPath = header[2] as string;
      current = {
        path: newPath,
        oldPath,
        change: oldPath === newPath ? "modified" : "renamed",
        lines: [],
      };
      inHunk = false;
      continue;
    }

    if (!current) {
      // Preamble before the first file header is ignored; anything else with
      // diff-like structure outside a file is a malformed diff.
      if (line.startsWith("@@") || line.startsWith("+++") || line.startsWith("---")) {
        throw new DiffParseError(`Diff content outside a file header: ${line.slice(0, 80)}`);
      }
      continue;
    }

    if (line.startsWith("new file mode")) {
      current.change = "added";
      current.oldPath = null;
      continue;
    }
    if (line.startsWith("deleted file mode")) {
      current.change = "deleted";
      continue;
    }
    if (
      line.startsWith("index ") ||
      line.startsWith("similarity index") ||
      line.startsWith("rename from") ||
      line.startsWith("rename to") ||
      line.startsWith("old mode") ||
      line.startsWith("new mode")
    ) {
      continue;
    }
    if (line.startsWith("--- ") || line.startsWith("+++ ")) {
      continue;
    }
    if (line.startsWith("Binary files")) {
      continue;
    }

    const hunk = HUNK_HEADER.exec(line);
    if (hunk) {
      newLineCursor = Number.parseInt(hunk[1] as string, 10);
      inHunk = true;
      continue;
    }

    if (!inHunk) continue;

    if (line.startsWith("+")) {
      current.lines.push({
        kind: "added",
        text: line.slice(1),
        newLineNumber: newLineCursor,
      });
      newLineCursor += 1;
    } else if (line.startsWith("-")) {
      current.lines.push({ kind: "removed", text: line.slice(1), newLineNumber: null });
    } else if (line.startsWith(" ")) {
      current.lines.push({
        kind: "context",
        text: line.slice(1),
        newLineNumber: newLineCursor,
      });
      newLineCursor += 1;
    } else if (line.startsWith("\\")) {
      // "\ No newline at end of file"
      continue;
    } else if (line.trim() === "") {
      continue;
    } else {
      throw new DiffParseError(`Unrecognised line in hunk: ${line.slice(0, 80)}`);
    }
  }

  flush();

  return {
    files,
    addedCount: files.reduce((n, f) => n + f.addedCount, 0),
    removedCount: files.reduce((n, f) => n + f.removedCount, 0),
  };
}
