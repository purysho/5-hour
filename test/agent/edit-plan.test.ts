import { describe, expect, it } from "vitest";
import {
  applyEditPlan,
  EditPlanError,
  EDIT_PLAN_SCHEMA,
  parseEditPlan,
  type EditPlan,
} from "../../src/agent/edit-plan.ts";
import { parseUnifiedDiff } from "../../src/policy/diff.ts";

/**
 * The model's proposal (ADR-0013).
 *
 * Everything here validates the proposal as though an adversary wrote it,
 * because a model that has read a hostile repository is downstream of that
 * repository. These tests are the boundary between "the model said something"
 * and "Driftless did something".
 */

const SOURCES = [
  {
    path: "src/client.ts",
    content: 'import { createClient } from "acme";\n\nconst client = createClient({ key: KEY });\n',
  },
  { path: "src/other.ts", content: "export const unrelated = 1;\n" },
];

const ALLOWED = ["src/client.ts", "src/other.ts"];

function plan(edits: EditPlan["edits"]): EditPlan {
  return { summary: "test", edits, suspectedInjectionPaths: [] };
}

describe("parseEditPlan", () => {
  it("accepts a well-formed proposal", () => {
    const parsed = parseEditPlan({
      summary: "Rename createClient to makeClient",
      edits: [{ path: "src/client.ts", find: "createClient", replace: "makeClient" }],
      suspectedInjectionPaths: [],
    });
    expect(parsed.edits).toHaveLength(1);
    expect(parsed.summary).toBe("Rename createClient to makeClient");
  });

  it("rejects output that is not an object", () => {
    for (const raw of ["a string", 42, null, [], undefined]) {
      expect(() => parseEditPlan(raw), String(raw)).toThrow(EditPlanError);
    }
  });

  it("rejects a proposal with no edits", () => {
    // An empty plan is a legitimate model answer ("nothing to do here"), and
    // it must not become an empty pull request.
    expect(() => parseEditPlan({ summary: "", edits: [] })).toThrow(/no edits/);
  });

  it("rejects an implausible number of edits before doing any work", () => {
    const edits = Array.from({ length: 101 }, (_, i) => ({
      path: "src/client.ts",
      find: `a${i}`,
      replace: `b${i}`,
    }));
    expect(() => parseEditPlan({ summary: "", edits })).toThrow(/ceiling/);
  });

  it("rejects an edit missing any required field", () => {
    for (const edit of [
      { find: "a", replace: "b" },
      { path: "src/client.ts", replace: "b" },
      { path: "src/client.ts", find: "a" },
      { path: "src/client.ts", find: "", replace: "b" },
      { path: "", find: "a", replace: "b" },
    ]) {
      expect(() => parseEditPlan({ summary: "", edits: [edit] }), JSON.stringify(edit)).toThrow(
        EditPlanError,
      );
    }
  });

  it("rejects an edit that replaces text with itself", () => {
    expect(() =>
      parseEditPlan({ summary: "", edits: [{ path: "a", find: "x", replace: "x" }] }),
    ).toThrow(/itself/);
  });

  it("rejects an oversized anchor", () => {
    expect(() =>
      parseEditPlan({
        summary: "",
        edits: [{ path: "a", find: "x".repeat(20_001), replace: "y" }],
      }),
    ).toThrow(/exceeds/);
  });

  it("strips control characters from the summary", () => {
    // This string reaches a log line. A terminal escape in a log line is an
    // injection into whoever is reading it during an incident.
    const parsed = parseEditPlan({
      summary: "before\u001b[2Jafter\nnewline\u0000null",
      edits: [{ path: "a", find: "x", replace: "y" }],
    });
    expect(parsed.summary).not.toContain("\u001b");
    expect(parsed.summary).not.toContain("\u0000");
    expect(parsed.summary).toBe("before [2Jafter newline null");
  });

  it("bounds the summary", () => {
    const parsed = parseEditPlan({
      summary: "x".repeat(10_000),
      edits: [{ path: "a", find: "x", replace: "y" }],
    });
    expect(parsed.summary.length).toBeLessThanOrEqual(2_001);
  });

  it("tolerates a missing or malformed injection-signal field", () => {
    // A signal, not a control — it must never be the reason a migration fails.
    for (const value of [undefined, null, "not an array", 5]) {
      const parsed = parseEditPlan({
        summary: "",
        edits: [{ path: "a", find: "x", replace: "y" }],
        suspectedInjectionPaths: value,
      });
      expect(parsed.suspectedInjectionPaths).toEqual([]);
    }
  });
});

describe("applyEditPlan", () => {
  it("applies an anchored replacement and renders the diff", () => {
    const applied = applyEditPlan(
      plan([{ path: "src/client.ts", find: "createClient({ key: KEY })", replace: "makeClient(KEY)" }]),
      SOURCES,
      { allowedPaths: ALLOWED },
    );

    expect(applied.changedPaths).toEqual(["src/client.ts"]);
    const parsed = parseUnifiedDiff(applied.diff);
    expect(parsed.files).toHaveLength(1);
    expect(parsed.files[0]?.path).toBe("src/client.ts");
    expect(applied.diff).toContain("+const client = makeClient(KEY);");
  });

  it("applies several edits to one file, in order", () => {
    const applied = applyEditPlan(
      plan([
        { path: "src/client.ts", find: "import { createClient }", replace: "import { makeClient }" },
        { path: "src/client.ts", find: "createClient({ key: KEY })", replace: "makeClient(KEY)" },
      ]),
      SOURCES,
      { allowedPaths: ALLOWED },
    );
    expect(applied.diff).toContain("import { makeClient }");
    expect(applied.diff).toContain("makeClient(KEY)");
  });

  it("refuses a file that was not supplied to the model", () => {
    // The rule that makes "…also update .github/workflows/release.yml" inert
    // rather than merely rejected later.
    expect(() =>
      applyEditPlan(
        plan([{ path: ".github/workflows/release.yml", find: "on:", replace: "on: [push]" }]),
        SOURCES,
        { allowedPaths: [...ALLOWED, ".github/workflows/release.yml"] },
      ),
    ).toThrow(/was not supplied/);
  });

  it("refuses a file outside the blast radius", () => {
    expect(() =>
      applyEditPlan(plan([{ path: "src/other.ts", find: "unrelated", replace: "related" }]), SOURCES, {
        allowedPaths: ["src/client.ts"],
      }),
    ).toThrow(/outside the blast radius/);
  });

  it("refuses an anchor that does not appear", () => {
    expect(() =>
      applyEditPlan(plan([{ path: "src/client.ts", find: "notPresent", replace: "x" }]), SOURCES, {
        allowedPaths: ALLOWED,
      }),
    ).toThrow(/does not appear/);
  });

  it("refuses an ambiguous anchor rather than picking one", () => {
    // "First match wins" produces a plausible-looking wrong edit, which is the
    // worst outcome available here.
    const sources = [{ path: "src/a.ts", content: "call();\ncall();\n" }];
    expect(() =>
      applyEditPlan(plan([{ path: "src/a.ts", find: "call();", replace: "invoke();" }]), sources, {
        allowedPaths: ["src/a.ts"],
      }),
    ).toThrow(/more than once/);
  });

  it("refuses a second edit whose anchor became ambiguous", () => {
    // Uniqueness is checked against the content as it stands, not as it
    // arrived — an earlier edit can create a duplicate.
    const sources = [{ path: "src/a.ts", content: "alpha\nbeta\n" }];
    expect(() =>
      applyEditPlan(
        plan([
          { path: "src/a.ts", find: "beta", replace: "alpha" },
          { path: "src/a.ts", find: "alpha", replace: "gamma" },
        ]),
        sources,
        { allowedPaths: ["src/a.ts"] },
      ),
    ).toThrow(/more than once/);
  });

  it("refuses a plan that changes nothing", () => {
    // Reachable when every edit is a deletion of text back to itself through
    // an intermediate state. An empty diff must never reach the forge.
    const sources = [{ path: "src/a.ts", content: "one\n" }];
    expect(() =>
      applyEditPlan(
        plan([
          { path: "src/a.ts", find: "one", replace: "two" },
          { path: "src/a.ts", find: "two", replace: "one" },
        ]),
        sources,
        { allowedPaths: ["src/a.ts"] },
      ),
    ).toThrow(/produced no change/);
  });

  it("never touches a file no edit named", () => {
    const applied = applyEditPlan(
      plan([{ path: "src/client.ts", find: "createClient({", replace: "makeClient({" }]),
      SOURCES,
      { allowedPaths: ALLOWED },
    );
    expect(applied.diff).not.toContain("src/other.ts");
  });

  it("renders paths in a stable order", () => {
    const sources = [
      { path: "src/z.ts", content: "z\n" },
      { path: "src/a.ts", content: "a\n" },
    ];
    const applied = applyEditPlan(
      plan([
        { path: "src/z.ts", find: "z", replace: "Z" },
        { path: "src/a.ts", find: "a", replace: "A" },
      ]),
      sources,
      { allowedPaths: ["src/a.ts", "src/z.ts"] },
    );
    expect(applied.changedPaths).toEqual(["src/a.ts", "src/z.ts"]);
  });
});

describe("the schema and the validator describe the same shape", () => {
  it("requires exactly the fields the parser requires", () => {
    const schema = EDIT_PLAN_SCHEMA as unknown as {
      required: string[];
      properties: { edits: { items: { required: string[]; additionalProperties: boolean } } };
    };
    expect(schema.required).toEqual(["summary", "edits", "suspectedInjectionPaths"]);
    expect(schema.properties.edits.items.required).toEqual(["path", "find", "replace"]);
    // No extra keys means no field the model can invent and we might later
    // start reading by accident.
    expect(schema.properties.edits.items.additionalProperties).toBe(false);
  });

  it("offers no capability beyond replacement", () => {
    // A create/delete/rename/mode field would be a capability an injection
    // could reach. Their absence is the control.
    const serialised = JSON.stringify(EDIT_PLAN_SCHEMA);
    for (const forbidden of ["delete", "rename", "create", "mode", "command", "url"]) {
      expect(serialised.toLowerCase()).not.toContain(`"${forbidden}"`);
    }
  });
});
