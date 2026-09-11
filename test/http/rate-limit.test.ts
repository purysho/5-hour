import { describe, it, expect } from "vitest";
import { RateLimiter, clientKeyFrom } from "../../src/http/rate-limit.ts";

/**
 * Bounding the one endpoint where a stranger decides our bill.
 *
 * The clock is injected throughout. A rate-limit test that waits on real time
 * is either slow or flaky, and usually both.
 */

function limiter(overrides: Partial<ConstructorParameters<typeof RateLimiter>[0]> = {}) {
  let now = 1_000_000;
  const instance = new RateLimiter({
    perClient: 3,
    global: 5,
    windowMs: 60_000,
    now: () => now,
    ...overrides,
  });
  return { instance, advance: (ms: number) => (now += ms) };
}

describe("the per-client limit", () => {
  it("allows up to the bound and then refuses", () => {
    const { instance } = limiter();
    for (let i = 0; i < 3; i += 1) {
      expect(instance.check("1.2.3.4").allowed).toBe(true);
    }
    const refused = instance.check("1.2.3.4");
    expect(refused.allowed).toBe(false);
    expect(refused.scope).toBe("client");
    expect(refused.retryAfterSeconds).toBeGreaterThan(0);
  });

  it("does not penalise a different client", () => {
    const { instance } = limiter();
    for (let i = 0; i < 3; i += 1) instance.check("1.2.3.4");
    expect(instance.check("5.6.7.8").allowed).toBe(true);
  });

  it("recovers when the window rolls over", () => {
    const { instance, advance } = limiter();
    for (let i = 0; i < 3; i += 1) instance.check("1.2.3.4");
    expect(instance.check("1.2.3.4").allowed).toBe(false);

    advance(60_001);
    expect(instance.check("1.2.3.4").allowed).toBe(true);
  });
});

describe("the global ceiling", () => {
  it("holds even when the caller spreads across addresses", () => {
    // The per-client limit is bypassable — addresses are cheap and the header
    // is caller-controlled. This is the bound that actually caps the bill.
    const { instance } = limiter();
    for (let i = 0; i < 5; i += 1) {
      expect(instance.check(`10.0.0.${i}`).allowed).toBe(true);
    }
    const refused = instance.check("10.0.0.99");
    expect(refused.allowed).toBe(false);
    expect(refused.scope).toBe("global");
  });

  it("refuses a brand-new client once the ceiling is reached", () => {
    // The deliberate trade: during an attack, real customers are refused too.
    // A few minutes of refused checkouts is recoverable; an unbounded bill is
    // not.
    const { instance } = limiter();
    for (let i = 0; i < 5; i += 1) instance.check(`10.0.0.${i}`);
    expect(instance.check("a-genuine-customer").allowed).toBe(false);
  });

  it("recovers when its window rolls over", () => {
    const { instance, advance } = limiter();
    for (let i = 0; i < 5; i += 1) instance.check(`10.0.0.${i}`);
    expect(instance.check("10.0.0.99").allowed).toBe(false);
    advance(60_001);
    expect(instance.check("10.0.0.99").allowed).toBe(true);
  });

  it("is not consumed by a request the per-client limit already refused", () => {
    const { instance } = limiter({ perClient: 1, global: 5 });
    instance.check("noisy");
    for (let i = 0; i < 10; i += 1) instance.check("noisy");
    // One consumed. A refused request must not spend the shared allowance, or
    // one blocked caller could exhaust the ceiling for everyone.
    expect(instance.check("quiet").allowed).toBe(true);
  });
});

describe("memory", () => {
  it("does not grow without bound when a caller cycles addresses", () => {
    // Without a ceiling the limiter becomes a memory-exhaustion primitive,
    // which is a worse bug than the one it exists to prevent.
    const { instance } = limiter({ perClient: 1, global: 1_000_000, maxTrackedClients: 50 });
    for (let i = 0; i < 5_000; i += 1) instance.check(`client-${i}`);
    expect(instance.trackedClients).toBeLessThanOrEqual(50);
  });
});

describe("construction", () => {
  it("refuses a per-client bound above the global ceiling", () => {
    // Otherwise the per-client limit can never refuse, and one caller is
    // permitted the entire global allowance.
    expect(() => new RateLimiter({ perClient: 10, global: 5, windowMs: 1000 })).toThrow();
  });

  for (const bad of [
    { perClient: 0, global: 5, windowMs: 1000 },
    { perClient: 1, global: 0, windowMs: 1000 },
    { perClient: 1, global: 5, windowMs: 0 },
  ]) {
    it(`refuses ${JSON.stringify(bad)}`, () => {
      expect(() => new RateLimiter(bad)).toThrow();
    });
  }
});

describe("the client key", () => {
  it("prefers the forwarded address, because the socket is the proxy", () => {
    // Without this every caller shares one key behind a load balancer, and the
    // per-client limit silently becomes a second global one.
    expect(clientKeyFrom({ "x-forwarded-for": "203.0.113.7" }, "10.0.0.1")).toBe("203.0.113.7");
  });

  it("takes the leftmost entry of the chain", () => {
    expect(clientKeyFrom({ "x-forwarded-for": "203.0.113.7, 10.0.0.5, 10.0.0.6" }, "10.0.0.1")).toBe(
      "203.0.113.7",
    );
  });

  it("falls back to the socket address", () => {
    expect(clientKeyFrom({}, "10.0.0.1")).toBe("10.0.0.1");
    expect(clientKeyFrom({ "x-forwarded-for": "" }, "10.0.0.1")).toBe("10.0.0.1");
  });

  it("bounds the key length, since the header is caller-controlled", () => {
    const key = clientKeyFrom({ "x-forwarded-for": "a".repeat(10_000) }, "10.0.0.1");
    expect(key.length).toBeLessThanOrEqual(64);
  });

  it("never returns empty, so distinct callers cannot collapse into one key", () => {
    expect(clientKeyFrom({}, undefined)).toBe("unknown");
  });
});
