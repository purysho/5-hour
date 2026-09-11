/**
 * Bounding what an anonymous caller can make us spend.
 *
 * `/checkout` is unauthenticated by necessity — asking someone to authenticate
 * before they can pay is how you get no customers — and it calls Stripe, which
 * costs money and consumes an API allowance we do not control. That makes it
 * the one route where a stranger decides our spending, and it had nothing
 * bounding it at all.
 *
 * ── Two buckets, because one of them is a lie on its own ────────────────────
 *
 * Per-client, keyed on the caller's address, is the fair limit: it stops one
 * source from monopolising checkout without affecting anyone else. It is also
 * trivially bypassed, because the address comes from a proxy header a caller
 * can set, and because addresses are cheap.
 *
 * So there is also a global ceiling, which cannot be bypassed by spreading
 * traffic across addresses, and which is the only one that genuinely bounds
 * cost. It is set well above any plausible real demand: a business at the
 * revenue this product is aimed at does not see sixty checkouts a minute, so
 * reaching it means something is wrong and refusing is correct.
 *
 * The global ceiling denies checkout to real customers during an attack. That
 * is a deliberate trade and worth stating: a few minutes of refused checkouts
 * is recoverable, and an unbounded bill is not.
 *
 * ── What this is not ────────────────────────────────────────────────────────
 *
 * In-process, so it bounds one instance rather than a fleet. Two instances
 * permit twice this. That is honest for a deployment of one or two containers
 * and stops being sufficient the moment there are many; the fix then is a
 * shared counter, not a smaller number here.
 *
 * It is not a defence against a distributed flood, which arrives at the load
 * balancer rather than here.
 */

export interface RateLimitDecision {
  readonly allowed: boolean;
  /** Which bucket refused, for the log. Null when allowed. */
  readonly scope: "client" | "global" | null;
  readonly retryAfterSeconds: number;
}

export interface RateLimitOptions {
  /** Requests per window from one client address. */
  readonly perClient: number;
  /** Requests per window from everyone, together. */
  readonly global: number;
  readonly windowMs: number;
  /**
   * Distinct client keys held before the oldest are dropped.
   *
   * Bounded because the key comes from the caller: without a ceiling, a caller
   * cycling addresses turns this rate limiter into a memory-exhaustion
   * primitive, which is a worse bug than the one it exists to prevent.
   */
  readonly maxTrackedClients?: number;
  readonly now?: () => number;
}

interface Window {
  count: number;
  resetAt: number;
}

const DEFAULT_MAX_TRACKED_CLIENTS = 10_000;

export class RateLimiter {
  readonly #perClient: number;
  readonly #global: number;
  readonly #windowMs: number;
  readonly #maxTracked: number;
  readonly #now: () => number;
  readonly #clients = new Map<string, Window>();
  #globalWindow: Window;

  constructor(options: RateLimitOptions) {
    if (options.perClient < 1 || options.global < 1 || options.windowMs < 1) {
      throw new Error("rate limit bounds must be positive");
    }
    if (options.perClient > options.global) {
      // Otherwise the per-client limit can never be the one that refuses, and
      // one caller is permitted the entire global allowance.
      throw new Error("perClient must not exceed the global ceiling");
    }
    this.#perClient = options.perClient;
    this.#global = options.global;
    this.#windowMs = options.windowMs;
    this.#maxTracked = options.maxTrackedClients ?? DEFAULT_MAX_TRACKED_CLIENTS;
    this.#now = options.now ?? Date.now;
    this.#globalWindow = { count: 0, resetAt: this.#now() + this.#windowMs };
  }

  check(clientKey: string): RateLimitDecision {
    const now = this.#now();

    // Global first. It is the bound that actually holds, and checking it first
    // means a caller cycling addresses cannot also fill the client map on the
    // way past.
    if (now >= this.#globalWindow.resetAt) {
      this.#globalWindow = { count: 0, resetAt: now + this.#windowMs };
    }
    if (this.#globalWindow.count >= this.#global) {
      return {
        allowed: false,
        scope: "global",
        retryAfterSeconds: secondsUntil(this.#globalWindow.resetAt, now),
      };
    }

    let window = this.#clients.get(clientKey);
    if (window === undefined || now >= window.resetAt) {
      window = { count: 0, resetAt: now + this.#windowMs };
      this.#clients.set(clientKey, window);
    }

    if (window.count >= this.#perClient) {
      return {
        allowed: false,
        scope: "client",
        retryAfterSeconds: secondsUntil(window.resetAt, now),
      };
    }

    window.count += 1;
    this.#globalWindow.count += 1;
    this.#evict(now);
    return { allowed: true, scope: null, retryAfterSeconds: 0 };
  }

  /**
   * Drops expired entries, then oldest-first if still over the ceiling.
   *
   * Map iteration is insertion-ordered, so the first keys are the least
   * recently created. Evicting a live entry resets that caller's allowance,
   * which is the correct way to be wrong here: the global ceiling still holds,
   * so the cost is bounded regardless.
   */
  #evict(now: number): void {
    if (this.#clients.size <= this.#maxTracked) return;
    for (const [key, window] of this.#clients) {
      if (this.#clients.size <= this.#maxTracked) break;
      if (now >= window.resetAt) this.#clients.delete(key);
    }
    for (const key of this.#clients.keys()) {
      if (this.#clients.size <= this.#maxTracked) break;
      this.#clients.delete(key);
    }
  }

  /** Tracked client count. Exposed for tests and for a health metric. */
  get trackedClients(): number {
    return this.#clients.size;
  }
}

function secondsUntil(resetAt: number, now: number): number {
  return Math.max(1, Math.ceil((resetAt - now) / 1000));
}

/**
 * The key a rate limit is applied to.
 *
 * `x-forwarded-for` is used when present because in every real deployment this
 * process sits behind a proxy and the socket address is the proxy's — without
 * it every caller shares one key and the per-client limit becomes a second
 * global one. The header is caller-controllable, which is exactly why the
 * global ceiling exists and why this value is never used for anything but
 * rate limiting.
 *
 * The first entry is taken and trimmed: the header is a comma-separated chain,
 * and the leftmost is the original client as recorded by the first proxy.
 */
export function clientKeyFrom(
  headers: Readonly<Record<string, string | undefined>>,
  socketAddress: string | undefined,
): string {
  const forwarded = headers["x-forwarded-for"];
  if (forwarded !== undefined && forwarded !== "") {
    const first = forwarded.split(",")[0]?.trim();
    // Bounded: an arbitrarily long header value must not become an
    // arbitrarily long map key.
    if (first !== undefined && first !== "") return first.slice(0, 64);
  }
  return socketAddress ?? "unknown";
}
