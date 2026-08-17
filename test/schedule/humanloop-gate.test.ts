import { describe, expect, it, beforeEach, afterEach } from "vitest";
import {
  type HumanLoopInput,
  submitToHumanLayer,
} from "../../src/schedule/humanloop-gate.ts";

const baseInput: HumanLoopInput = {
  diff: "--- a/package.json\n+++ b/package.json\n@@ -1 +1 @@",
  findings: {
    codeReview: { verdict: "pass", issues: [] },
    blastRadius: { affected: 42, high_risk: false },
    testVerification: { outcome: "passed" },
  },
  package: "lodash",
  fromVersion: "4.17.21",
  toVersion: "5.0.0",
  repositoryUrl: "https://github.com/org/repo",
  prUrl: "https://github.com/org/repo/pull/123",
  humanloopApiKey: "sk-hl-test-key",
  timeoutSeconds: 5,
};

/**
 * A stand-in for `fetch`, typed to the real signature.
 *
 * The parameter type matters: `fetch` accepts `string | URL | Request`, and a
 * handler narrowed to `string` is not assignable to it. Writing the mocks as
 * `vi.fn(async (url: string) => …)` typechecked nowhere — it produced five
 * TS2322 errors that only surfaced in CI, because the suite itself runs through
 * vitest's transform rather than tsc.
 */
function mockFetch(handler: (url: string) => Promise<Response>): typeof fetch {
  return async (input: string | URL | Request, _init?: RequestInit): Promise<Response> => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    return handler(url);
  };
}

/** True for the collection endpoint (task creation), false for `/tasks/<id>`. */
function isCreate(url: string): boolean {
  return url.endsWith("/tasks");
}

function created(id: string): Response {
  return { ok: true, json: async () => ({ id }) } as Response;
}

function task(fields: Record<string, unknown>): Response {
  return { ok: true, json: async () => fields } as Response;
}

describe("HumanLayer Gate", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("rejects when API key is missing", async () => {
    await expect(
      submitToHumanLayer({ ...baseInput, humanloopApiKey: "" }),
    ).rejects.toThrow("HUMANLOOP_API_KEY");
  });

  it("returns the approval a reviewer gave", async () => {
    globalThis.fetch = mockFetch(async (url) =>
      isCreate(url)
        ? created("task_123")
        : task({
            id: "task_123",
            status: "approved",
            feedback: "Looks good",
            reviewer_id: "rev_abc123",
            completed_at: "2026-08-17T10:55:00Z",
          }),
    );

    const result = await submitToHumanLayer(baseInput);

    expect(result.approved).toBe(true);
    expect(result.feedback).toBe("Looks good");
    expect(result.reviewerId).toBe("rev_abc123");
    expect(result.decisionTimestamp).toBe(new Date("2026-08-17T10:55:00Z").getTime());
  });

  it("returns the rejection a reviewer gave", async () => {
    globalThis.fetch = mockFetch(async (url) =>
      isCreate(url)
        ? created("task_456")
        : task({
            id: "task_456",
            status: "rejected",
            feedback: "Blast radius too large",
            reviewer_id: "rev_def456",
            completed_at: "2026-08-17T10:55:30Z",
          }),
    );

    const result = await submitToHumanLayer(baseInput);

    expect(result.approved).toBe(false);
    expect(result.feedback).toBe("Blast radius too large");
    expect(result.reviewerId).toBe("rev_def456");
  });

  it("carries the escalation flag through", async () => {
    // Documented in the skill and returned by the API, but previously
    // hard-coded to false in both return paths — an escalation that never
    // left this function was identical to no escalation at all.
    globalThis.fetch = mockFetch(async (url) =>
      isCreate(url)
        ? created("task_esc")
        : task({
            id: "task_esc",
            status: "approved",
            feedback: "Merging, but oncall should look",
            reviewer_id: "rev_esc",
            completed_at: "2026-08-17T10:55:00Z",
            escalated: true,
          }),
    );

    const result = await submitToHumanLayer(baseInput);

    expect(result.approved).toBe(true);
    expect(result.escalated).toBe(true);
  });

  it("defaults escalation to false when the API omits it", async () => {
    globalThis.fetch = mockFetch(async (url) =>
      isCreate(url)
        ? created("task_noesc")
        : task({ id: "task_noesc", status: "approved", reviewer_id: "rev_x" }),
    );

    const result = await submitToHumanLayer(baseInput);

    expect(result.escalated).toBe(false);
  });

  it("substitutes a message when a rejection carries no feedback", async () => {
    globalThis.fetch = mockFetch(async (url) =>
      isCreate(url)
        ? created("task_nofb")
        : task({ id: "task_nofb", status: "rejected", reviewer_id: "rev_y" }),
    );

    const result = await submitToHumanLayer(baseInput);

    expect(result.feedback).toBe("No feedback provided");
    expect(result.reviewerId).toBe("rev_y");
  });

  it("reports an unknown reviewer rather than crashing", async () => {
    globalThis.fetch = mockFetch(async (url) =>
      isCreate(url) ? created("task_anon") : task({ id: "task_anon", status: "approved" }),
    );

    expect((await submitToHumanLayer(baseInput)).reviewerId).toBe("unknown");
  });

  it("throws when task creation fails", async () => {
    globalThis.fetch = mockFetch(
      async () => ({ ok: false, status: 401, text: async () => "Unauthorized" }) as Response,
    );

    await expect(submitToHumanLayer(baseInput)).rejects.toThrow("HumanLayer API error: 401");
  });

  it("throws when polling fails", async () => {
    globalThis.fetch = mockFetch(async (url) =>
      isCreate(url) ? created("task_pollfail") : ({ ok: false, status: 503 } as Response),
    );

    await expect(submitToHumanLayer(baseInput)).rejects.toThrow("HumanLayer API error: 503");
  });

  it("throws when the task expires", async () => {
    globalThis.fetch = mockFetch(async (url) =>
      isCreate(url) ? created("task_exp") : task({ id: "task_exp", status: "expired" }),
    );

    await expect(submitToHumanLayer(baseInput)).rejects.toThrow("expired");
  });

  it("polls until the reviewer decides", async () => {
    let polls = 0;
    globalThis.fetch = mockFetch(async (url) => {
      if (isCreate(url)) return created("task_poll");
      polls += 1;
      return task({
        id: "task_poll",
        status: polls >= 3 ? "approved" : "pending",
        reviewer_id: "rev_slow",
        feedback: "took a while",
      });
    });

    const result = await submitToHumanLayer(baseInput, { pollIntervalMs: 1 });

    expect(result.approved).toBe(true);
    expect(polls).toBe(3);
  });

  it("times out without approving or rejecting", async () => {
    // The safety-critical path. A timeout must not resolve — auto-approval
    // would merge an unreviewed diff into someone else's repository, which is
    // strictly worse than making a human look again.
    //
    // This is now reachable because the poll interval is injectable. It was
    // previously asserted only by a comment and a tautology, since a
    // hard-coded ten-second interval could not be driven from a unit test.
    globalThis.fetch = mockFetch(async (url) =>
      isCreate(url) ? created("task_to") : task({ id: "task_to", status: "pending" }),
    );

    await expect(
      submitToHumanLayer({ ...baseInput, timeoutSeconds: 0.05 }, { pollIntervalMs: 1 }),
    ).rejects.toThrow(/timeout/i);
  });

  it("names the pending task in the timeout error", async () => {
    // An operator reading this needs to know the task is still open, not lost.
    globalThis.fetch = mockFetch(async (url) =>
      isCreate(url) ? created("task_msg") : task({ id: "task_msg", status: "pending" }),
    );

    const error = await submitToHumanLayer(
      { ...baseInput, timeoutSeconds: 0.05 },
      { pollIntervalMs: 1 },
    ).then(
      () => null,
      (e: unknown) => e as Error,
    );

    expect(error).not.toBeNull();
    expect(error!.message).toMatch(/remains pending/i);
    expect(error!.message).toMatch(/do not auto-merge/i);
  });

  it("logs submission and decision", async () => {
    const logs: Array<[string, Record<string, unknown>]> = [];
    globalThis.fetch = mockFetch(async (url) =>
      isCreate(url)
        ? created("task_log")
        : task({
            id: "task_log",
            status: "approved",
            feedback: "OK",
            reviewer_id: "rev_log",
            completed_at: "2026-08-17T10:55:00Z",
          }),
    );

    await submitToHumanLayer(baseInput, { log: (event, detail) => logs.push([event, detail]) });

    expect(logs.map(([event]) => event)).toEqual([
      "humanloop.submit_start",
      "humanloop.task_created",
      "humanloop.approved",
    ]);
  });

  it("logs an expiry before throwing", async () => {
    const logs: Array<[string, Record<string, unknown>]> = [];
    globalThis.fetch = mockFetch(async (url) =>
      isCreate(url) ? created("task_expl") : task({ id: "task_expl", status: "expired" }),
    );

    await submitToHumanLayer(baseInput, {
      log: (event, detail) => logs.push([event, detail]),
    }).catch(() => undefined);

    expect(logs.some(([event]) => event === "humanloop.expired")).toBe(true);
  });

  it("sends the package and version range to the reviewer", async () => {
    let body: unknown;
    globalThis.fetch = (async (
      input: string | URL | Request,
      init?: RequestInit,
    ): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (isCreate(url)) {
        body = JSON.parse(String(init?.body));
        return created("task_body");
      }
      return task({ id: "task_body", status: "approved", reviewer_id: "r" });
    }) as typeof fetch;

    await submitToHumanLayer(baseInput);

    const sent = body as { title: string; description: string; metadata: Record<string, unknown> };
    expect(sent.title).toContain("lodash");
    expect(sent.title).toContain("4.17.21");
    expect(sent.title).toContain("5.0.0");
    expect(sent.metadata["pr_url"]).toBe(baseInput.prUrl);
    expect(sent.metadata["affected_repositories"]).toBe(42);
    // The reviewer must see the PR link and the automated findings, or the
    // approval is uninformed.
    expect(sent.description).toContain(baseInput.prUrl);
    expect(sent.description).toContain("Tests passed");
  });

  it("tells the reviewer when tests were not run", async () => {
    // `not-run` is the current production state (the sandbox is unbuilt), so
    // this is the wording a reviewer will actually see most often.
    let body: unknown;
    globalThis.fetch = (async (
      input: string | URL | Request,
      init?: RequestInit,
    ): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (isCreate(url)) {
        body = JSON.parse(String(init?.body));
        return created("task_nr");
      }
      return task({ id: "task_nr", status: "approved", reviewer_id: "r" });
    }) as typeof fetch;

    await submitToHumanLayer({
      ...baseInput,
      findings: {
        codeReview: { verdict: "fail", issues: ["unchecked null"] },
        blastRadius: { affected: 900, high_risk: true },
        testVerification: { outcome: "not-run" },
      },
    });

    const description = (body as { description: string }).description;
    expect(description).toContain("Tests not run");
    expect(description).toContain("High-risk blast radius");
    expect(description).toContain("unchecked null");
  });
});
