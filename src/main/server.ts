/**
 * The HTTP server.
 *
 * Deliberately tiny. Everything it exposes is unauthenticated by necessity:
 * the homepage, a health check, the opt-out page, the forge webhook, and the
 * commercial surface — pricing, checkout, and the Stripe webhook. There is no
 * admin surface here and no API; anything requiring authentication does not
 * belong on this process.
 *
 * The billing routes are absent, not disabled, when billing is unconfigured.
 * A deployment that does not sell should 404 on /checkout rather than expose a
 * route that fails at the Stripe call — an endpoint that exists and breaks is
 * harder to reason about than one that was never mounted.
 *
 * Routing is hand-written rather than framework-driven. At this size a
 * framework is a dependency in the most exposed process we run, in exchange
 * for saving twenty lines.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { handleOptOut, type OptOutDeps } from "../http/opt-out.ts";
import { landingResponse } from "../http/landing.ts";
import { handleWebhook, type WebhookDeps } from "../http/webhook.ts";
import { applyForgeEvent, type ApplyDeps } from "../http/webhook-apply.ts";
import { pricingResponse, startCheckout, welcomeResponse, type CheckoutDeps } from "../http/pricing.ts";
import { handleBillingWebhook, type BillingWebhookDeps } from "../http/billing-webhook.ts";

export interface ServerDeps {
  readonly optOut: OptOutDeps;
  readonly webhook: WebhookDeps;
  readonly apply: ApplyDeps;
  /** Absent when the deployment does not sell; the billing routes are then unmounted. */
  readonly billing?: {
    readonly checkout: CheckoutDeps;
    readonly webhook: BillingWebhookDeps;
    readonly appInstallUrl: string;
    readonly portalUrl: string;
  };
  /** Reports readiness. False makes /health fail so a load balancer drains us. */
  readonly ready: () => boolean;
  readonly log: (message: string, fields?: Record<string, unknown>) => void;
}

/** Bounded so an unauthenticated caller cannot buffer arbitrary memory. */
const MAX_BODY_BYTES = 1024 * 1024;

export function createHttpServer(deps: ServerDeps): Server {
  return createServer((req, res) => {
    handleRequest(req, res, deps).catch((error) => {
      // Never leak internals to an unauthenticated caller. The detail goes to
      // our logs; the caller gets a status code.
      deps.log("unhandled request error", { error: String(error) });
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "text/plain" });
      }
      res.end("Internal error\n");
    });
  });
}

async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  deps: ServerDeps,
): Promise<void> {
  const url = new URL(req.url ?? "/", "http://localhost");
  const path = url.pathname;
  const method = req.method ?? "GET";

  // The public homepage, and the GitHub App's homepage URL. Served here so
  // there is no second host to run — see src/http/landing.ts for why the page
  // says what it says.
  if (path === "/" && (method === "GET" || method === "HEAD")) {
    const page = landingResponse();
    res.writeHead(page.status, page.headers);
    res.end(method === "HEAD" ? undefined : page.body);
    return;
  }

  if (path === "/health") {
    const ready = deps.ready();
    res.writeHead(ready ? 200 : 503, { "content-type": "application/json" });
    res.end(JSON.stringify({ status: ready ? "ok" : "draining" }));
    return;
  }

  // Opt-out: /opt-out/:token
  const optOutMatch = /^\/opt-out\/([^/]+)\/?$/.exec(path);
  if (optOutMatch) {
    const token = decodeURIComponent(optOutMatch[1] as string);
    const body = method === "POST" ? await readBody(req) : "";
    const outcome = await handleOptOut(
      {
        method,
        token,
        ...(method === "POST" ? { formFields: parseForm(body) } : {}),
      },
      deps.optOut,
    );
    res.writeHead(outcome.status, outcome.headers);
    res.end(outcome.body);
    return;
  }

  const billing = deps.billing;

  if (path === "/pricing" && (method === "GET" || method === "HEAD")) {
    if (billing === undefined) {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("Not found\n");
      return;
    }
    const page = pricingResponse(billing.portalUrl);
    res.writeHead(page.status, page.headers);
    res.end(method === "HEAD" ? undefined : page.body);
    return;
  }

  if (path === "/welcome" && (method === "GET" || method === "HEAD")) {
    if (billing === undefined) {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("Not found\n");
      return;
    }
    const page = welcomeResponse(billing.appInstallUrl, billing.portalUrl);
    res.writeHead(page.status, page.headers);
    res.end(method === "HEAD" ? undefined : page.body);
    return;
  }

  if (path === "/checkout") {
    if (billing === undefined) {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("Not found\n");
      return;
    }
    if (method !== "POST") {
      res.writeHead(405, { allow: "POST" });
      res.end();
      return;
    }
    const form = parseForm(await readBody(req));
    const outcome = await startCheckout(form["plan"], billing.checkout);
    if (outcome.kind === "rejected") {
      deps.log("checkout rejected", { reason: outcome.reason });
      // Back to the page they came from rather than an error document. The
      // only way to reach this is a tampered or stale form, and the useful
      // response is the list of things that can actually be bought.
      res.writeHead(303, { location: "/pricing", "cache-control": "no-store" });
      res.end();
      return;
    }
    // 303 so the browser follows with GET. A 302 here leaves the method
    // technically at the browser's discretion, and a POST to Stripe's hosted
    // checkout is not a page.
    res.writeHead(303, { location: outcome.url, "cache-control": "no-store" });
    res.end();
    return;
  }

  if (path === "/webhooks/stripe") {
    if (billing === undefined) {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("Not found\n");
      return;
    }
    if (method !== "POST") {
      res.writeHead(405, { allow: "POST" });
      res.end();
      return;
    }

    // The raw body, unparsed. The signature is over the bytes as sent, so
    // anything that re-serialises the JSON invalidates every delivery.
    const body = await readBody(req);
    const outcome = await handleBillingWebhook(
      { body, headers: normaliseHeaders(req) },
      billing.webhook,
    );

    if (outcome.kind === "rejected") {
      // 400 for the same reason as the forge webhook: telling an
      // unauthenticated caller whether the signature or the body was wrong is
      // free information about how we validate.
      deps.log("billing webhook rejected", { reason: outcome.reason });
      res.writeHead(400);
      res.end();
      return;
    }

    if (outcome.kind === "provisioned") {
      deps.log("billing webhook provisioned tenant", {
        eventId: outcome.eventId,
        created: outcome.created,
      });
    } else if (outcome.kind === "duplicate") {
      deps.log("billing webhook duplicate", { eventId: outcome.eventId });
    } else {
      deps.log("billing webhook ignored", { reason: outcome.reason });
    }

    // 200 on duplicates and ignored events. A non-2xx makes Stripe retry with
    // backoff and eventually disable the endpoint, which would take billing
    // down for events we deliberately do not act on.
    res.writeHead(200);
    res.end();
    return;
  }

  if (path === "/webhooks/github") {
    if (method !== "POST") {
      res.writeHead(405, { allow: "POST" });
      res.end();
      return;
    }

    const body = await readBody(req);
    const outcome = await handleWebhook(
      { body, headers: normaliseHeaders(req) },
      deps.webhook,
    );

    if (outcome.kind === "rejected") {
      // 400 rather than 401/403 deliberately: distinguishing "bad signature"
      // from "malformed" for an unauthenticated caller is free information
      // about how the endpoint validates.
      deps.log("webhook rejected", { reason: outcome.reason });
      res.writeHead(400);
      res.end();
      return;
    }

    if (outcome.kind === "accepted") {
      const result = await applyForgeEvent(outcome.event, deps.apply);
      deps.log("webhook applied", {
        event: outcome.event.type,
        applied: result.applied,
        detail: result.detail,
      });
    } else if (outcome.kind === "ignored") {
      deps.log("webhook ignored", { reason: outcome.reason });
    } else if (outcome.kind === "duplicate") {
      deps.log("webhook duplicate", { deliveryId: outcome.deliveryId });
    }

    // Acknowledge duplicates and ignored events with 200. A non-2xx makes
    // GitHub retry, and retrying something we deliberately ignored produces a
    // delivery-failure alert on the customer's side for no reason.
    res.writeHead(200);
    res.end();
    return;
  }

  res.writeHead(404, { "content-type": "text/plain" });
  res.end("Not found\n");
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;

  for await (const chunk of req) {
    const buffer = chunk as Buffer;
    size += buffer.length;
    if (size > MAX_BODY_BYTES) {
      // Stop reading rather than accumulating. An unauthenticated caller must
      // not be able to decide how much memory we allocate.
      req.destroy();
      throw new Error("request body too large");
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function parseForm(body: string): Record<string, string> {
  const fields: Record<string, string> = {};
  const params = new URLSearchParams(body);
  for (const [key, value] of params) {
    // First value wins; a repeated field is either a bug or an attempt to
    // confuse whichever layer reads it.
    if (!(key in fields)) fields[key] = value;
  }
  return fields;
}

function normaliseHeaders(req: IncomingMessage): Record<string, string | undefined> {
  const headers: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(req.headers)) {
    // Node lower-cases header names already; arrays only occur for set-cookie
    // and duplicated headers, neither of which we authorise on.
    headers[key] = Array.isArray(value) ? value[0] : value;
  }
  return headers;
}
