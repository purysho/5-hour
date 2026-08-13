/**
 * The opt-out endpoint.
 *
 * The link printed in every pull request body lands here. It is the only
 * unauthenticated, publicly reachable surface Driftless exposes, and it exists
 * to be used by someone who is already mildly annoyed with us — so it has to
 * work on the first click, with no account, and without a single question.
 *
 * ── Why a bare GET would be a bug ────────────────────────────────────────────
 *
 * The obvious implementation is `GET /opt-out/:token` → suppress → done. One
 * click, no friction. It is also broken, and the reason catches people out.
 *
 * Links posted to GitHub, Slack, Teams, and most mail providers get *fetched
 * automatically* to build previews, and scanned by security appliances that
 * follow every URL in an inbound message. A state-changing GET therefore fires
 * without anyone clicking:
 *
 *   - our own pull request body renders on GitHub → GitHub fetches the link
 *   - the notification email hits a corporate scanner → it follows the link
 *   - the repository is now opted out, and nobody chose that
 *
 * The failure is silent and looks exactly like a maintainer opting out, so we
 * would simply stop contacting repositories that never asked us to. Losing
 * customers to a link preview is a bad way to discover HTTP semantics.
 *
 * So: GET renders a confirmation page and changes nothing. POST performs the
 * opt-out. Prefetchers issue GETs, humans click the button.
 *
 * That is still one click for the person — the page has a single button — and
 * it is the honest reading of "safe methods" rather than a ceremonial nod to
 * it.
 */

import type { TenantClient } from "../db/client.ts";
import { redeemOptOutToken, type SuppressionTarget } from "../outbound/suppression.ts";

export interface HttpRequest {
  readonly method: string;
  /** Path-extracted token. Never read from a query string — those leak into logs. */
  readonly token: string;
  readonly formFields?: Readonly<Record<string, string>>;
}

export interface HttpResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

/**
 * Applied to every response.
 *
 * The page renders no user-controlled content and loads nothing external, so
 * the policy can be maximally restrictive. `no-store` matters specifically:
 * an opt-out confirmation cached by an intermediary and replayed later would
 * be confusing at best.
 */
const SECURITY_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  "content-type": "text/html; charset=utf-8",
  "content-security-policy":
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "cache-control": "no-store",
  "strict-transport-security": "max-age=63072000; includeSubDomains",
});

/** Bounds the token before it reaches a database query or a log line. */
const TOKEN_SHAPE = /^[A-Za-z0-9_-]{20,128}$/;

export interface OptOutDeps {
  readonly withTenant: <T>(
    providerId: string,
    fn: (client: TenantClient) => Promise<T>,
  ) => Promise<T>;
  /**
   * Resolves a token to its owning tenant.
   *
   * Tokens are looked up across tenants by hash before tenant context exists —
   * there is no authenticated caller to derive it from. This is the one place
   * that legitimately spans tenants, so it is narrow, explicit, and returns
   * nothing but the provider id.
   */
  readonly providerForToken: (tokenHash: string) => Promise<string | null>;
  readonly hashToken: (token: string) => string;
  /** Observability hook. Receives no token and no personal data. */
  readonly observe?: (event: OptOutEvent) => void;
}

export interface OptOutEvent {
  readonly kind: "viewed" | "confirmed" | "unknown-token" | "malformed" | "bad-method";
  readonly target?: SuppressionTarget;
}

export async function handleOptOut(
  request: HttpRequest,
  deps: OptOutDeps,
): Promise<HttpResponse> {
  const observe = deps.observe ?? (() => {});

  if (request.method !== "GET" && request.method !== "POST") {
    observe({ kind: "bad-method" });
    return respond(405, page("Method not allowed", "<p>Use the button on the confirmation page.</p>"), {
      allow: "GET, POST",
    });
  }

  if (!TOKEN_SHAPE.test(request.token)) {
    // Deliberately identical to the unknown-token response below. A distinct
    // "malformed" page would let someone probe the token format.
    observe({ kind: "malformed" });
    return notFound();
  }

  const hash = deps.hashToken(request.token);
  const providerId = await deps.providerForToken(hash);

  if (!providerId) {
    observe({ kind: "unknown-token" });
    return notFound();
  }

  if (request.method === "GET") {
    // Renders. Changes nothing. This is the response every link prefetcher,
    // preview bot, and security scanner will ever see.
    observe({ kind: "viewed" });
    return respond(200, confirmationPage(request.token));
  }

  const result = await deps.withTenant(providerId, (client) =>
    redeemOptOutToken(client, providerId, request.token, readReason(request)),
  );

  if (!result.redeemed) {
    observe({ kind: "unknown-token" });
    return notFound();
  }

  observe({ kind: "confirmed", target: result.target });
  return respond(200, confirmedPage());
}

/**
 * Optional free text from the form.
 *
 * Unauthenticated input, so it is length-bounded here and again at the storage
 * boundary, and it is never rendered back into any page — it exists to be read
 * by us later, not to be echoed.
 */
function readReason(request: HttpRequest): string | undefined {
  const reason = request.formFields?.["reason"];
  if (typeof reason !== "string" || reason.trim() === "") return undefined;
  return reason.slice(0, 500);
}

function notFound(): HttpResponse {
  return respond(
    404,
    page(
      "Link not recognised",
      "<p>This opt-out link is not one we issued, or it has been superseded.</p>" +
        "<p>If you are still receiving pull requests you did not ask for, " +
        "close one with a comment and we will stop.</p>",
    ),
  );
}

function respond(
  status: number,
  body: string,
  extraHeaders: Record<string, string> = {},
): HttpResponse {
  return { status, headers: { ...SECURITY_HEADERS, ...extraHeaders }, body };
}

/**
 * The token is placed in the form action, which is a path we constructed from
 * a value already validated against TOKEN_SHAPE — so it cannot carry markup.
 * No other dynamic content appears on any page here.
 */
function confirmationPage(token: string): string {
  return page(
    "Stop pull requests to this repository?",
    `<p>Driftless will not open any further pull requests in this repository.</p>
     <form method="post" action="/opt-out/${token}">
       <label for="reason">Anything we should know? (optional)</label>
       <textarea id="reason" name="reason" rows="3" maxlength="500"></textarea>
       <button type="submit">Stop pull requests here</button>
     </form>
     <p class="muted">Nothing changes until you press the button.</p>`,
  );
}

function confirmedPage(): string {
  return page(
    "Done — we will not open another pull request here",
    `<p>This repository is opted out. No account, nothing to confirm by email,
        and no expiry.</p>
     <p class="muted">If a pull request from us is already open, you can close
        it — we will not reopen it.</p>`,
  );
}

function page(heading: string, content: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Driftless</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 34rem; margin: 4rem auto; padding: 0 1rem; }
  h1 { font-size: 1.3rem; line-height: 1.3; }
  textarea { width: 100%; font: inherit; padding: .5rem; margin: .5rem 0 1rem; }
  button { font: inherit; padding: .6rem 1rem; cursor: pointer; }
  .muted { opacity: .7; font-size: .9rem; }
</style>
</head>
<body>
<h1>${heading}</h1>
${content}
</body>
</html>`;
}
