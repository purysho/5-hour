/**
 * Forge webhook ingestion.
 *
 * The second unauthenticated surface, and a more dangerous one than the
 * opt-out endpoint. Anyone on the internet can POST here; the only thing
 * separating a real GitHub delivery from a forgery is an HMAC signature.
 *
 * It also carries the customer's revocation path. When someone uninstalls the
 * app, GitHub tells us here and nowhere else. Getting that wrong means we keep
 * acting on an installation the customer believes they revoked, which is the
 * single worst thing this system could do.
 *
 * ── Four rules, each of which is a real vulnerability if broken ──────────────
 *
 * 1. Verify the signature over the RAW body, before parsing.
 *
 *    Parse-then-verify is a classic break: JSON round-tripping is not
 *    byte-preserving (duplicate keys, unicode escapes, number formats), so an
 *    attacker can craft a body that verifies as one thing and parses as
 *    another. This module never sees a parsed object it has not first
 *    authenticated.
 *
 * 2. Compare in constant time.
 *
 *    A byte-by-byte early-exit comparison leaks the expected signature one
 *    byte at a time. It is a slow attack, but the endpoint is public and
 *    unauthenticated, so the attacker has unlimited attempts.
 *
 * 3. A missing signature is a rejection, never a bypass.
 *
 *    The tempting shape — "if a signature is present, check it" — means an
 *    attacker simply omits the header. Absence must fail exactly like a wrong
 *    signature.
 *
 * 4. Deduplicate deliveries.
 *
 *    GitHub retries, so the same event arrives more than once. A replayed
 *    `installation.created` that re-enables a revoked installation would be a
 *    security incident, not a duplicate-processing annoyance.
 */

import { createHmac, timingSafeEqual } from "node:crypto";

export type WebhookOutcome =
  | { readonly kind: "accepted"; readonly event: ForgeEvent }
  | { readonly kind: "ignored"; readonly reason: string }
  | { readonly kind: "duplicate"; readonly deliveryId: string }
  | { readonly kind: "rejected"; readonly reason: RejectionReason };

export type RejectionReason =
  | "missing-signature"
  | "bad-signature"
  | "missing-delivery-id"
  | "oversized"
  | "unparseable"
  | "unexpected-shape";

export interface RawWebhook {
  /** Exactly the bytes received. Never re-serialised from a parsed object. */
  readonly body: string;
  readonly headers: Readonly<Record<string, string | undefined>>;
}

/**
 * Events we act on. Everything else is acknowledged and dropped — GitHub sends
 * a great deal we have no business reacting to, and silently ignoring the rest
 * is safer than a default branch that tries.
 */
export type ForgeEvent =
  | {
      /**
       * A new installation, and the only event that carries the installing
       * account. Kept distinct from `repositories.added` because enrolment
       * needs that account to record who we are acting for — collapsing the
       * two, as this once did, discards it.
       */
      readonly type: "installation.created";
      readonly installationId: number;
      readonly account: string;
      readonly repositories: readonly AddedRepository[];
    }
  | { readonly type: "installation.revoked"; readonly installationId: number }
  | { readonly type: "installation.suspended"; readonly installationId: number }
  | { readonly type: "installation.unsuspended"; readonly installationId: number }
  | {
      readonly type: "repositories.removed";
      readonly installationId: number;
      readonly repositories: readonly RepositoryRef[];
    }
  | {
      readonly type: "repositories.added";
      readonly installationId: number;
      readonly repositories: readonly AddedRepository[];
    }
  | {
      readonly type: "pull_request.closed";
      readonly installationId: number;
      readonly repository: RepositoryRef;
      readonly number: number;
      readonly merged: boolean;
    }
  | {
      readonly type: "push";
      readonly installationId: number;
      readonly repository: RepositoryRef;
      readonly ref: string;
    };

export interface RepositoryRef {
  readonly owner: string;
  readonly name: string;
}

/**
 * A repository we have just been granted access to.
 *
 * Carries the numeric forge id, which is the field that matters: ADR-0002
 * scopes every token by it, so a repository recorded without one is a
 * repository we can name and cannot act on. The payload does not include the
 * default branch or the star count, and this deliberately does not invent
 * them — the worker learns a repository's shape the first time it reads it,
 * with a credential, rather than the webhook guessing.
 */
export interface AddedRepository extends RepositoryRef {
  readonly forgeRepositoryId: number;
  readonly isPrivate: boolean;
}

export interface WebhookDeps {
  /** Per-installation secrets are not available pre-verification; one app secret. */
  readonly secret: string;
  /** Returns true if this delivery id has been seen. Must be atomic. */
  readonly claimDelivery: (deliveryId: string) => Promise<boolean>;
  readonly maxBodyBytes?: number;
}

const MAX_BODY_BYTES = 1024 * 1024;
const DELIVERY_ID = /^[0-9a-fA-F-]{8,64}$/;

export async function handleWebhook(
  raw: RawWebhook,
  deps: WebhookDeps,
): Promise<WebhookOutcome> {
  const maxBytes = deps.maxBodyBytes ?? MAX_BODY_BYTES;

  // Size first: everything below either hashes or parses the body, and both
  // are attacker-controlled work.
  if (Buffer.byteLength(raw.body, "utf8") > maxBytes) {
    return { kind: "rejected", reason: "oversized" };
  }

  const signature = header(raw, "x-hub-signature-256");
  if (!signature) {
    // Rule 3. Absence is not a special case.
    return { kind: "rejected", reason: "missing-signature" };
  }

  // Rule 1 and 2: raw body, constant time, before any parsing.
  if (!verifySignature(raw.body, signature, deps.secret)) {
    return { kind: "rejected", reason: "bad-signature" };
  }

  const deliveryId = header(raw, "x-github-delivery");
  if (!deliveryId || !DELIVERY_ID.test(deliveryId)) {
    // Without a delivery id there is no way to deduplicate, and a webhook we
    // cannot deduplicate is one we cannot safely act on.
    return { kind: "rejected", reason: "missing-delivery-id" };
  }

  // Rule 4. Claimed before the payload is interpreted, so a retry that arrives
  // while the first is still processing does not double-apply.
  const alreadySeen = await deps.claimDelivery(deliveryId);
  if (alreadySeen) return { kind: "duplicate", deliveryId };

  let payload: unknown;
  try {
    payload = JSON.parse(raw.body);
  } catch {
    // Authenticated but unparseable. Odd enough to be worth surfacing rather
    // than ignoring — a valid signature over invalid JSON should not happen.
    return { kind: "rejected", reason: "unparseable" };
  }

  const eventType = header(raw, "x-github-event");
  if (!eventType) return { kind: "ignored", reason: "no event type" };

  return interpret(eventType, payload);
}

function verifySignature(body: string, provided: string, secret: string): boolean {
  const expected =
    "sha256=" + createHmac("sha256", secret).update(body, "utf8").digest("hex");

  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(provided, "utf8");

  // timingSafeEqual throws on length mismatch, which would itself be a timing
  // signal and a crash. Compare lengths first and still run the comparison, so
  // the wrong-length path costs roughly the same as the wrong-value path.
  if (a.length !== b.length) {
    timingSafeEqual(a, a);
    return false;
  }
  return timingSafeEqual(a, b);
}

/**
 * Narrows an authenticated payload into an event we act on.
 *
 * Authenticated is not the same as well-formed: the signature proves GitHub
 * sent it, not that it has the shape this code expects. Every field is checked
 * rather than assumed, and anything unrecognised is ignored rather than
 * guessed at.
 */
function interpret(eventType: string, payload: unknown): WebhookOutcome {
  if (typeof payload !== "object" || payload === null) {
    return { kind: "rejected", reason: "unexpected-shape" };
  }
  const body = payload as Record<string, unknown>;
  const action = typeof body["action"] === "string" ? body["action"] : null;
  const installationId = readInstallationId(body);

  if (eventType === "installation") {
    if (installationId === null) return { kind: "rejected", reason: "unexpected-shape" };

    switch (action) {
      case "deleted":
      case "revoked":
        // The customer's revocation path. Treated as terminal.
        return { kind: "accepted", event: { type: "installation.revoked", installationId } };
      case "suspend":
        return { kind: "accepted", event: { type: "installation.suspended", installationId } };
      case "unsuspend":
        return {
          kind: "accepted",
          event: { type: "installation.unsuspended", installationId },
        };
      case "created": {
        // The first event of a customer's life. Without it there is no
        // installation row and no repository row, and every later stage has
        // nothing to act on.
        const repositories = readAddedRepositories(body["repositories"]);
        const account = readAccountLogin(body["installation"]);
        if (repositories === null || account === null) {
          return { kind: "rejected", reason: "unexpected-shape" };
        }
        return {
          kind: "accepted",
          event: { type: "installation.created", installationId, account, repositories },
        };
      }
      default:
        return { kind: "ignored", reason: `installation.${action ?? "unknown"}` };
    }
  }

  if (eventType === "installation_repositories") {
    if (installationId === null) return { kind: "rejected", reason: "unexpected-shape" };
    if (action === "added") {
      const repositories = readAddedRepositories(body["repositories_added"]);
      if (repositories === null) return { kind: "rejected", reason: "unexpected-shape" };
      return {
        kind: "accepted",
        event: { type: "repositories.added", installationId, repositories },
      };
    }
    if (action !== "removed") {
      return { kind: "ignored", reason: `installation_repositories.${action ?? "unknown"}` };
    }
    const repositories = readRepositoryList(body["repositories_removed"]);
    if (repositories === null) return { kind: "rejected", reason: "unexpected-shape" };
    return {
      kind: "accepted",
      event: { type: "repositories.removed", installationId, repositories },
    };
  }

  if (eventType === "pull_request") {
    if (action !== "closed") {
      return { kind: "ignored", reason: `pull_request.${action ?? "unknown"}` };
    }
    if (installationId === null) return { kind: "rejected", reason: "unexpected-shape" };

    const pr = body["pull_request"];
    const repository = readRepository(body["repository"]);
    if (typeof pr !== "object" || pr === null || repository === null) {
      return { kind: "rejected", reason: "unexpected-shape" };
    }
    const record = pr as Record<string, unknown>;
    const number = typeof record["number"] === "number" ? record["number"] : null;
    if (number === null) return { kind: "rejected", reason: "unexpected-shape" };

    return {
      kind: "accepted",
      event: {
        type: "pull_request.closed",
        installationId,
        repository,
        number,
        // A closed-unmerged pull request is the strongest negative signal we
        // get about migration quality; merged is the metric that matters.
        merged: record["merged"] === true,
      },
    };
  }

  if (eventType === "push") {
    if (installationId === null) return { kind: "rejected", reason: "unexpected-shape" };
    const repository = readRepository(body["repository"]);
    const ref = body["ref"];
    if (repository === null || typeof ref !== "string") {
      return { kind: "rejected", reason: "unexpected-shape" };
    }
    return {
      kind: "accepted",
      event: { type: "push", installationId, repository, ref },
    };
  }

  return { kind: "ignored", reason: eventType };
}

function readInstallationId(body: Record<string, unknown>): number | null {
  const installation = body["installation"];
  if (typeof installation !== "object" || installation === null) return null;
  const id = (installation as Record<string, unknown>)["id"];
  return typeof id === "number" && Number.isSafeInteger(id) && id > 0 ? id : null;
}

/**
 * The account an App was installed on.
 *
 * Lower-cased to match `readRepository`, because the two are compared against
 * the same stored columns and GitHub does not preserve case consistently
 * between payloads.
 */
function readAccountLogin(installation: unknown): string | null {
  if (typeof installation !== "object" || installation === null) return null;
  const account = (installation as Record<string, unknown>)["account"];
  if (typeof account !== "object" || account === null) return null;
  const login = (account as Record<string, unknown>)["login"];
  return typeof login === "string" && login.length > 0 ? login.toLowerCase() : null;
}

function readRepository(value: unknown): RepositoryRef | null {
  if (typeof value !== "object" || value === null) return null;
  const record = value as Record<string, unknown>;

  // full_name is "owner/name". Split rather than trusting a separate owner
  // object, which is not present on every payload shape.
  const fullName = record["full_name"];
  if (typeof fullName === "string") {
    const slash = fullName.indexOf("/");
    if (slash > 0 && slash < fullName.length - 1) {
      return {
        owner: fullName.slice(0, slash).toLowerCase(),
        name: fullName.slice(slash + 1).toLowerCase(),
      };
    }
  }

  const owner = record["owner"];
  const name = record["name"];
  if (
    typeof owner === "object" &&
    owner !== null &&
    typeof (owner as Record<string, unknown>)["login"] === "string" &&
    typeof name === "string"
  ) {
    return {
      owner: ((owner as Record<string, unknown>)["login"] as string).toLowerCase(),
      name: name.toLowerCase(),
    };
  }
  return null;
}

/**
 * Repositories being granted, with their numeric ids.
 *
 * An entry without a usable id is dropped rather than invalidating the batch —
 * the opposite of `readRepositoryList`, and for the opposite reason. There,
 * partially applying a *removal* would leave us acting on repositories the
 * customer withdrew, so all-or-nothing is the safe direction. Here, dropping
 * one entry costs that repository its migrations and grants nothing extra.
 */
function readAddedRepositories(value: unknown): readonly AddedRepository[] | null {
  if (!Array.isArray(value)) return null;
  const added: AddedRepository[] = [];
  for (const entry of value) {
    const ref = readRepository(entry);
    if (!ref) continue;
    const record = entry as Record<string, unknown>;
    const id = record["id"];
    if (typeof id !== "number" || !Number.isSafeInteger(id) || id <= 0) continue;
    added.push({
      ...ref,
      forgeRepositoryId: id,
      // Absent means public on some payload shapes. Defaulting to private is
      // the safe direction: it is only used for our own reporting, and
      // over-reporting privacy leaks nothing.
      isPrivate: record["private"] !== false,
    });
  }
  return added;
}

function readRepositoryList(value: unknown): readonly RepositoryRef[] | null {
  if (!Array.isArray(value)) return null;
  const refs: RepositoryRef[] = [];
  for (const entry of value) {
    const ref = readRepository(entry);
    // One malformed entry invalidates the batch. Partially applying a
    // repository-removal event would leave us acting on repositories the
    // customer has withdrawn.
    if (!ref) return null;
    refs.push(ref);
  }
  return refs;
}

function header(raw: RawWebhook, name: string): string | undefined {
  const value = raw.headers[name] ?? raw.headers[name.toLowerCase()];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

/** Exposed for tests and for signing fixtures. */
export function signBody(body: string, secret: string): string {
  return "sha256=" + createHmac("sha256", secret).update(body, "utf8").digest("hex");
}
