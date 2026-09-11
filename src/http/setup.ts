/**
 * The GitHub App setup callback — where a payment becomes a connection.
 *
 * GitHub sends a customer here after they install the App, with the
 * installation id it just created and the `state` we put on the install link.
 * That `state` is the reference minted at checkout, so this is the one moment
 * both facts exist in the same request: which installation, and which tenant
 * paid for it.
 *
 * ── Why this cannot be guessed anywhere else ────────────────────────────────
 *
 * The `installation.created` webhook knows the GitHub account and not the
 * tenant. Nothing else in the system ever sees both. Before this route existed
 * a paying customer's installation resolved to no tenant and was dropped, or —
 * with DEFAULT_PROVIDER_SLUG set — resolved to whichever single tenant was
 * configured, filing one customer's repositories under another.
 *
 * ── What an attacker can do with a reference, and what they cannot ──────────
 *
 * A reference is a bearer credential: whoever holds one can bind an
 * installation they control to the tenant it names, enrolling their own
 * repositories into somebody else's paid account. So it is compared by hash,
 * it is single-use, and an unknown reference is refused rather than falling
 * back to any default.
 *
 * It cannot be used to read anything. The lookup discloses a provider id and
 * nothing else, and binding an installation grants the *tenant* access to the
 * attacker's repositories rather than the other way round — the damage is a
 * nuisance on the payer's bill, not disclosure of their code.
 */

import { hashToken } from "../outbound/suppression.ts";

export interface PendingInstallation {
  readonly account: string;
  readonly repositories: readonly {
    readonly owner: string;
    readonly name: string;
    readonly forgeRepositoryId: number;
    readonly isPrivate: boolean;
  }[];
}

export interface SetupDeps {
  /** Minimal disclosure: a provider id, or null. Never a tenant listing. */
  readonly providerForEnrolmentRef: (refHash: string) => Promise<string | null>;
  /** The installation the webhook parked, if it arrived first. */
  readonly takePendingInstallation: (
    forgeInstallationId: number,
  ) => Promise<PendingInstallation | null>;
  /** Records the installation against the tenant. Idempotent. */
  readonly enrol: (
    providerId: string,
    forgeInstallationId: number,
    pending: PendingInstallation | null,
  ) => Promise<void>;
  /** Consumes the reference so it cannot bind a second installation. */
  readonly consumeEnrolmentRef: (providerId: string) => Promise<void>;
  readonly log: (message: string, fields?: Record<string, unknown>) => void;
}

export type SetupOutcome =
  | { readonly kind: "enrolled"; readonly providerId: string; readonly installationId: number }
  | { readonly kind: "rejected"; readonly reason: string };

export interface SetupRequest {
  readonly installationId: string | null;
  readonly state: string | null;
}

export async function handleSetup(
  request: SetupRequest,
  deps: SetupDeps,
): Promise<SetupOutcome> {
  if (request.state === null || request.state === "") {
    // No reference, no tenant. Refused rather than defaulted: a default here
    // is the cross-tenant bug this route was written to remove.
    return { kind: "rejected", reason: "missing-state" };
  }

  const installationId = Number(request.installationId);
  if (!Number.isSafeInteger(installationId) || installationId <= 0) {
    return { kind: "rejected", reason: "missing-installation-id" };
  }

  const providerId = await deps.providerForEnrolmentRef(hashToken(request.state));
  if (providerId === null) {
    // Unknown, already consumed, or forged — deliberately indistinguishable to
    // the caller, so the endpoint is not an oracle for which references exist.
    return { kind: "rejected", reason: "unknown-reference" };
  }

  const pending = await deps.takePendingInstallation(installationId);
  await deps.enrol(providerId, installationId, pending);
  await deps.consumeEnrolmentRef(providerId);

  deps.log("installation enrolled via setup callback", {
    installationId,
    // The repository count, not the names: this line goes to a log aggregator.
    repositories: pending?.repositories.length ?? 0,
    parked: pending !== null,
  });

  return { kind: "enrolled", providerId, installationId };
}

const SECURITY_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  "content-type": "text/html; charset=utf-8",
  "content-security-policy":
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  // The URL carries a reference. A cached copy of this page is a cached copy
  // of a bearer credential.
  "cache-control": "no-store",
  "strict-transport-security": "max-age=63072000; includeSubDomains",
});

export function setupResponse(outcome: SetupOutcome): {
  status: number;
  headers: Readonly<Record<string, string>>;
  body: string;
} {
  const enrolled = outcome.kind === "enrolled";
  return {
    status: enrolled ? 200 : 400,
    headers: SECURITY_HEADERS,
    body: page(
      enrolled ? "You are connected" : "We could not complete the connection",
      enrolled
        ? "Driftless can see the repositories you selected. When a package one of " +
            "them depends on ships a breaking change, we will open the fixing pull " +
            "request. Nothing is merged without your review."
        : "This link is not valid, or it has already been used. Open the install " +
            "link from your receipt again, or reply to it and we will connect you " +
            "by hand.",
    ),
  };
}

function page(heading: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(heading)} — Driftless</title>
<style>
  :root { color-scheme: light dark; --fg: #16161a; --muted: #5b5b66; --bg: #fdfdfd; }
  @media (prefers-color-scheme: dark) {
    :root { --fg: #e8e8ea; --muted: #a0a0ac; --bg: #131316; }
  }
  body { margin: 0; background: var(--bg); color: var(--fg);
         font: 16px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif; }
  main { max-width: 42rem; margin: 0 auto; padding: 64px 20px; }
  h1 { font-size: 1.7rem; letter-spacing: -0.02em; margin: 0 0 12px; }
  p { color: var(--muted); max-width: 60ch; }
</style>
</head>
<body>
<main>
  <h1>${escapeHtml(heading)}</h1>
  <p>${escapeHtml(body)}</p>
</main>
</body>
</html>`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
