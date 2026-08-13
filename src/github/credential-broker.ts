/**
 * Credential broker (ADR-0002 §5).
 *
 * ── Why the helper cannot hold the token ─────────────────────────────────────
 *
 * The obvious design is a credential helper binary that holds the token and
 * answers git. It is wrong, and the reason is easy to miss.
 *
 * Validating a migration means running the repository's own test suite
 * (ADR-0006). That is arbitrary attacker-authored code executing inside the
 * sandbox. If the credential helper holds the token, that code does not need
 * to defeat anything — it just runs the helper:
 *
 *     $ echo -e "protocol=https\nhost=github.com\npath=acme/widgets\n" \
 *         | git-credential-driftless get
 *
 * The request is perfectly in scope. Path matching passes. The token is
 * printed to a process the attacker controls. Every check in
 * `credential-helper.ts` is satisfied, because none of them was ever about
 * *who is asking*.
 *
 * ── The design ───────────────────────────────────────────────────────────────
 *
 * The token never enters the sandbox. It lives in the supervisor, outside the
 * isolation boundary. Inside the sandbox the credential helper is a thin
 * client that forwards git's request over a unix socket and copies back the
 * answer.
 *
 * That alone does not fix it — attacker code can talk to the socket too. So
 * the broker is *armed* only during the push, and disarmed while untrusted
 * code runs:
 *
 *     clone      armed      (fetch needs credentials)
 *     analyse    disarmed
 *     test       disarmed   ← attacker code runs here
 *     push       armed      (one grant, then closed)
 *
 * A request arriving while disarmed is not merely refused — it is strong
 * evidence of compromise, since nothing legitimate asks for credentials
 * during test execution. It is logged as a security event and fails the job.
 *
 * Arming is additionally single-use by default: one grant per arm, so code
 * that races the push window gets at most one shot at a token it cannot
 * meaningfully use elsewhere.
 */

import {
  CredentialHelper,
  type CredentialOperation,
  type CredentialRequest,
  type HelperOutcome,
  type HelperScope,
} from "./credential-helper.ts";
import type { ScopedToken } from "./token.ts";

export type BrokerPhase = "clone" | "analyse" | "test" | "push" | "closed";

/** Phases in which credentials may legitimately be requested. */
const ARMED_PHASES: readonly BrokerPhase[] = Object.freeze(["clone", "push"]);

export interface BrokerEvent {
  readonly kind:
    | "granted"
    | "refused-by-scope"
    | "refused-disarmed"
    | "refused-exhausted";
  readonly phase: BrokerPhase;
  readonly operation: CredentialOperation;
  /** Non-secret. Safe for logs and the audit chain. */
  readonly requested: string;
  readonly detail?: string;
}

export interface BrokerObserver {
  (event: BrokerEvent): void;
}

export class CredentialAccessViolation extends Error {
  override readonly name = "CredentialAccessViolation";
  readonly event: BrokerEvent;
  constructor(message: string, event: BrokerEvent) {
    super(message);
    this.event = event;
  }
}

export interface BrokerOptions {
  /** Grants permitted per arm. Defaults to 1. */
  readonly grantsPerArm?: number;
  readonly observe?: BrokerObserver;
}

export class CredentialBroker {
  readonly #helper: CredentialHelper;
  readonly #grantsPerArm: number;
  readonly #observe: BrokerObserver;

  #phase: BrokerPhase = "analyse";
  #grantsRemaining = 0;

  constructor(token: ScopedToken, scope: HelperScope, options: BrokerOptions = {}) {
    this.#helper = new CredentialHelper(token, scope);
    this.#grantsPerArm = options.grantsPerArm ?? 1;
    this.#observe = options.observe ?? (() => {});
  }

  get phase(): BrokerPhase {
    return this.#phase;
  }

  get armed(): boolean {
    return ARMED_PHASES.includes(this.#phase) && this.#grantsRemaining > 0;
  }

  /**
   * Enters a phase. Entering an armed phase resets the grant budget; entering
   * any other phase drops it to zero immediately.
   */
  enterPhase(phase: BrokerPhase): void {
    if (this.#phase === "closed") {
      throw new Error("Broker is closed; a new job requires a new broker.");
    }
    this.#phase = phase;
    this.#grantsRemaining = ARMED_PHASES.includes(phase) ? this.#grantsPerArm : 0;
  }

  /** Irreversible. Called when the job ends, successfully or not. */
  close(): void {
    this.#phase = "closed";
    this.#grantsRemaining = 0;
  }

  /**
   * Runs `fn` with credentials available, and closes the window afterwards
   * whether or not it succeeded.
   *
   * Preferred over manual `enterPhase` calls: an early return or a thrown
   * error between arm and disarm would otherwise leave the window open across
   * the test phase, which is the one thing this design exists to prevent.
   */
  async withCredentials<T>(
    phase: Extract<BrokerPhase, "clone" | "push">,
    fn: () => Promise<T>,
  ): Promise<T> {
    const previous = this.#phase;
    this.enterPhase(phase);
    try {
      return await fn();
    } finally {
      this.enterPhase(previous === "closed" ? "analyse" : previous);
    }
  }

  handle(operation: CredentialOperation, request: CredentialRequest): HelperOutcome {
    const requested = `${request.host ?? "?"}/${request.path ?? "?"}`;

    // store/erase are inert in every phase and are not credential disclosure.
    if (operation === "store" || operation === "erase") {
      return this.#helper.handle(operation, request);
    }

    if (!ARMED_PHASES.includes(this.#phase)) {
      // Nothing legitimate asks for credentials during analysis or test
      // execution. This is the signature of attacker-authored code reaching
      // for the token, so it is escalated rather than quietly declined.
      const event: BrokerEvent = {
        kind: "refused-disarmed",
        phase: this.#phase,
        operation,
        requested,
        detail: "credential requested outside an armed phase",
      };
      this.#observe(event);
      throw new CredentialAccessViolation(
        `Credential requested during "${this.#phase}" for ${requested}. ` +
          `Nothing legitimate does this — treating as compromise (threat-model §5.5).`,
        event,
      );
    }

    if (this.#grantsRemaining <= 0) {
      const event: BrokerEvent = {
        kind: "refused-exhausted",
        phase: this.#phase,
        operation,
        requested,
        detail: "grant budget for this phase is exhausted",
      };
      this.#observe(event);
      return {
        kind: "refused",
        reason: "unsupported-operation",
        detail: "Credential grant budget exhausted for this phase.",
      };
    }

    const outcome = this.#helper.handle(operation, request);

    if (outcome.kind === "credentials") {
      this.#grantsRemaining -= 1;
      this.#observe({ kind: "granted", phase: this.#phase, operation, requested });
    } else if (outcome.kind === "refused") {
      // Scope refusals are also security-relevant: a request for a repository
      // we are not scoped to, arriving even in an armed phase, is the
      // submodule redirect described in credential-helper.ts.
      this.#observe({
        kind: "refused-by-scope",
        phase: this.#phase,
        operation,
        requested,
        detail: outcome.reason,
      });
    }

    return outcome;
  }
}
