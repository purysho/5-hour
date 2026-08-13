import { describe, expect, it, vi } from "vitest";
import {
  CredentialAccessViolation,
  CredentialBroker,
  type BrokerEvent,
} from "../../src/github/credential-broker.ts";
import { ScopedToken, REQUIRED_PERMISSIONS } from "../../src/github/token.ts";

/**
 * Credential broker phase gating (ADR-0002 §5).
 *
 * The scenario under test is the one the scoped helper alone does not cover:
 * the repository's own test suite is attacker-authored code running inside the
 * sandbox, and it can issue a perfectly in-scope credential request. Scope
 * checks pass, because they were never about who is asking.
 *
 * Phase gating is what answers that.
 */

const SECRET = "ghs_BROKERTESTvalue00000000000000000000";

function broker(options: { grantsPerArm?: number; observe?: (e: BrokerEvent) => void } = {}) {
  const token = new ScopedToken(
    SECRET,
    { repositoryId: "repo-1", installationId: "inst-1", permissions: REQUIRED_PERMISSIONS },
    new Date(Date.now() + 300_000),
    "tok_broker",
  );
  return new CredentialBroker(
    token,
    { host: "github.com", repositoryPath: "acme/widgets" },
    options,
  );
}

const IN_SCOPE = { protocol: "https", host: "github.com", path: "acme/widgets" };

describe("phase gating", () => {
  it("grants during push", () => {
    const b = broker();
    b.enterPhase("push");
    expect(b.handle("get", IN_SCOPE).kind).toBe("credentials");
  });

  it("grants during clone", () => {
    const b = broker();
    b.enterPhase("clone");
    expect(b.handle("get", IN_SCOPE).kind).toBe("credentials");
  });

  it("treats a request during the test phase as compromise, not a refusal", () => {
    // The attack this whole file exists for. Attacker code in the repository's
    // test suite issues an in-scope request — every scope check passes.
    const b = broker();
    b.enterPhase("test");
    expect(() => b.handle("get", IN_SCOPE)).toThrow(CredentialAccessViolation);
  });

  it("treats a request during analysis the same way", () => {
    const b = broker();
    b.enterPhase("analyse");
    expect(() => b.handle("get", IN_SCOPE)).toThrow(CredentialAccessViolation);
  });

  it("starts disarmed", () => {
    // A broker that armed on construction would be open during the clone of a
    // repository whose hooks run before we ever call enterPhase.
    expect(broker().armed).toBe(false);
    expect(() => broker().handle("get", IN_SCOPE)).toThrow(CredentialAccessViolation);
  });

  it("refuses everything once closed", () => {
    const b = broker();
    b.close();
    expect(() => b.handle("get", IN_SCOPE)).toThrow(CredentialAccessViolation);
    expect(() => b.enterPhase("push")).toThrow(/closed/);
  });

  it("reports the violation with non-secret detail only", () => {
    const b = broker();
    b.enterPhase("test");
    try {
      b.handle("get", IN_SCOPE);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(CredentialAccessViolation);
      const violation = error as CredentialAccessViolation;
      expect(violation.message).not.toContain(SECRET);
      expect(violation.event.kind).toBe("refused-disarmed");
      expect(violation.event.phase).toBe("test");
      expect(violation.event.requested).toBe("github.com/acme/widgets");
    }
  });
});

describe("grant budget", () => {
  it("permits one grant per arm by default", () => {
    const b = broker();
    b.enterPhase("push");
    expect(b.handle("get", IN_SCOPE).kind).toBe("credentials");
    const second = b.handle("get", IN_SCOPE);
    expect(second.kind).toBe("refused");
    expect(b.armed).toBe(false);
  });

  it("re-arms on re-entering an armed phase", () => {
    // A push that fails and is retried legitimately needs a second grant.
    const b = broker();
    b.enterPhase("push");
    b.handle("get", IN_SCOPE);
    b.enterPhase("push");
    expect(b.handle("get", IN_SCOPE).kind).toBe("credentials");
  });

  it("honours a larger budget when a phase genuinely needs it", () => {
    const b = broker({ grantsPerArm: 2 });
    b.enterPhase("clone");
    expect(b.handle("get", IN_SCOPE).kind).toBe("credentials");
    expect(b.handle("get", IN_SCOPE).kind).toBe("credentials");
    expect(b.handle("get", IN_SCOPE).kind).toBe("refused");
  });

  it("does not carry budget across a disarmed phase", () => {
    const b = broker({ grantsPerArm: 5 });
    b.enterPhase("push");
    b.enterPhase("test");
    expect(() => b.handle("get", IN_SCOPE)).toThrow(CredentialAccessViolation);
  });
});

describe("withCredentials", () => {
  it("closes the window after the callback resolves", async () => {
    const b = broker();
    b.enterPhase("analyse");
    await b.withCredentials("push", async () => {
      expect(b.handle("get", IN_SCOPE).kind).toBe("credentials");
    });
    expect(b.phase).toBe("analyse");
    expect(() => b.handle("get", IN_SCOPE)).toThrow(CredentialAccessViolation);
  });

  it("closes the window even when the callback throws", async () => {
    // The reason this helper exists. A thrown error between a manual arm and
    // disarm would leave credentials available across the test phase — the one
    // failure the design cannot tolerate.
    const b = broker();
    b.enterPhase("analyse");
    await expect(
      b.withCredentials("push", async () => {
        throw new Error("push failed");
      }),
    ).rejects.toThrow("push failed");
    expect(b.armed).toBe(false);
    expect(() => b.handle("get", IN_SCOPE)).toThrow(CredentialAccessViolation);
  });
});

describe("observability", () => {
  it("reports a grant", () => {
    const observe = vi.fn();
    const b = broker({ observe });
    b.enterPhase("push");
    b.handle("get", IN_SCOPE);
    expect(observe).toHaveBeenCalledWith(
      expect.objectContaining({ kind: "granted", phase: "push" }),
    );
  });

  it("reports an in-phase request for the wrong repository", () => {
    // The submodule redirect, arriving during a legitimately armed phase.
    const observe = vi.fn();
    const b = broker({ observe });
    b.enterPhase("push");
    b.handle("get", { ...IN_SCOPE, path: "attacker/collector" });
    expect(observe).toHaveBeenCalledWith(
      expect.objectContaining({ kind: "refused-by-scope", detail: "path-mismatch" }),
    );
  });

  it("never puts a secret in an event", () => {
    const events: BrokerEvent[] = [];
    const b = broker({ observe: (e) => events.push(e) });
    b.enterPhase("push");
    b.handle("get", IN_SCOPE);
    b.handle("get", IN_SCOPE);
    expect(events.length).toBeGreaterThan(0);
    expect(JSON.stringify(events)).not.toContain(SECRET);
  });
});

describe("store and erase", () => {
  it("stay inert in every phase without raising", () => {
    // git issues these after a successful or failed authentication. They
    // disclose nothing, so they must not be escalated as violations — a false
    // security alarm on a routine git operation would train us to ignore real
    // ones.
    for (const phase of ["analyse", "test", "push"] as const) {
      const b = broker();
      b.enterPhase(phase);
      expect(b.handle("store", IN_SCOPE).kind).toBe("no-output");
      expect(b.handle("erase", IN_SCOPE).kind).toBe("no-output");
    }
  });
});
