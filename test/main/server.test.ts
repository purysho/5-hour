import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createHttpServer, type ServerDeps } from "../../src/main/server.ts";
import { signBody } from "../../src/http/webhook.ts";
import { hashToken } from "../../src/outbound/suppression.ts";

/**
 * The HTTP server, exercised over a real socket.
 *
 * Every route here is unauthenticated by necessity, so the tests are about
 * what an anonymous caller can make the process do — including how much memory
 * it can make us allocate.
 */

const SECRET = "server-test-webhook-secret-0000000000";

let server: Server;
let origin: string;
let ready = true;
const applied: string[] = [];
const suppressed: string[] = [];

const deps: ServerDeps = {
  ready: () => ready,
  log: () => {},
  optOut: {
    withTenant: async (_id, fn) => fn({ query: async () => ({ rows: [] }) } as never),
    hashToken,
    providerForToken: async (hash) =>
      hash === hashToken("valid-token-aaaaaaaaaaaaaaaaaaaaaa")
        ? "11111111-1111-4111-8111-111111111111"
        : null,
  },
  webhook: {
    secret: SECRET,
    claimDelivery: async () => false,
  },
  apply: {
    withTenant: async (_id, fn) => fn({ query: async () => ({ rows: [], rowCount: 0 }) } as never),
    providerForInstallation: async () => null,
  },
};

// The opt-out handler calls redeemOptOutToken, which needs a client; the stub
// above returns no rows, so redemption reports an unknown token. That is the
// correct behaviour to assert at this layer — routing and I/O, not persistence.

beforeAll(async () => {
  server = createHttpServer({
    ...deps,
    apply: {
      ...deps.apply,
      providerForInstallation: async (id) => {
        applied.push(String(id));
        return null;
      },
    },
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  origin = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

async function request(
  path: string,
  init: RequestInit = {},
): Promise<{ status: number; body: string; headers: Headers }> {
  const response = await fetch(`${origin}${path}`, init);
  return { status: response.status, body: await response.text(), headers: response.headers };
}

describe("health", () => {
  it("reports ok when ready", async () => {
    ready = true;
    const response = await request("/health");
    expect(response.status).toBe(200);
    expect(JSON.parse(response.body)).toEqual({ status: "ok" });
  });

  it("fails the check while draining, so a load balancer stops sending work", async () => {
    ready = false;
    const response = await request("/health");
    expect(response.status).toBe(503);
    ready = true;
  });
});

describe("routing", () => {
  it("returns 404 for unknown paths", async () => {
    expect((await request("/admin")).status).toBe(404);
    expect((await request("/")).status).toBe(404);
  });

  it("exposes no admin or API surface", async () => {
    // Anything needing authentication does not belong on this process.
    for (const path of ["/api", "/admin", "/metrics", "/jobs", "/providers"]) {
      expect((await request(path)).status, path).toBe(404);
    }
  });

  it("serves the opt-out page over GET", async () => {
    const response = await request("/opt-out/valid-token-aaaaaaaaaaaaaaaaaaaaaa");
    expect(response.status).toBe(200);
    expect(response.body).toContain("Stop pull requests");
    expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
  });

  it("returns 404 for an unknown opt-out token", async () => {
    const response = await request("/opt-out/unknown-token-bbbbbbbbbbbbbbbbbb");
    expect(response.status).toBe(404);
  });

  it("does not confuse a path traversal with a token", async () => {
    const response = await request("/opt-out/..%2f..%2fetc%2fpasswd");
    expect(response.status).toBe(404);
  });
});

describe("webhooks", () => {
  function deliver(body: string, headers: Record<string, string> = {}): RequestInit {
    return {
      method: "POST",
      body,
      headers: {
        "content-type": "application/json",
        "x-github-event": "installation",
        "x-github-delivery": "aaaaaaaa-1111-2222-3333-444444444444",
        "x-hub-signature-256": signBody(body, SECRET),
        ...headers,
      },
    };
  }

  it("accepts a correctly signed delivery", async () => {
    const body = JSON.stringify({ action: "deleted", installation: { id: 4242 } });
    const response = await request("/webhooks/github", deliver(body));
    expect(response.status).toBe(200);
    expect(applied).toContain("4242");
  });

  it("rejects an unsigned delivery with 400", async () => {
    const body = JSON.stringify({ action: "deleted", installation: { id: 1 } });
    const response = await request("/webhooks/github", {
      method: "POST",
      body,
      headers: { "x-github-event": "installation" },
    });
    expect(response.status).toBe(400);
  });

  it("does not reveal why a delivery was rejected", async () => {
    // Distinguishing "bad signature" from "malformed" for an unauthenticated
    // caller is free information about how validation works.
    const badSignature = await request(
      "/webhooks/github",
      deliver(JSON.stringify({ a: 1 }), { "x-hub-signature-256": "sha256=00" }),
    );
    const noDelivery = await request("/webhooks/github", {
      method: "POST",
      body: "{}",
      headers: { "x-hub-signature-256": signBody("{}", SECRET) },
    });

    expect(badSignature.status).toBe(400);
    expect(noDelivery.status).toBe(400);
    expect(badSignature.body).toBe(noDelivery.body);
  });

  it("acknowledges ignored events with 200 so GitHub does not retry", async () => {
    // A non-2xx makes GitHub retry, and retrying something we deliberately
    // ignored produces a delivery-failure alert on the customer's side for no
    // reason.
    const body = JSON.stringify({ action: "created", repository: {} });
    const response = await request(
      "/webhooks/github",
      deliver(body, { "x-github-event": "star" }),
    );
    expect(response.status).toBe(200);
  });

  it("rejects methods other than POST", async () => {
    const response = await request("/webhooks/github", { method: "GET" });
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("POST");
  });
});

describe("resource bounds", () => {
  it("refuses an oversized body rather than buffering it", async () => {
    // An anonymous caller must not decide how much memory we allocate.
    const response = await fetch(`${origin}/webhooks/github`, {
      method: "POST",
      body: "x".repeat(2 * 1024 * 1024),
      headers: { "x-github-event": "installation" },
    }).catch(() => null);

    // Either a 500 from the size guard or a connection reset — both mean we
    // stopped reading. What must not happen is a 200.
    expect(response === null || response.status >= 400).toBe(true);
  });

  it("does not leak internals when a handler throws", async () => {
    const failing = createHttpServer({
      ...deps,
      ready: () => {
        throw new Error("secret internal detail: postgres://user:pw@host");
      },
    });
    await new Promise<void>((resolve) => failing.listen(0, "127.0.0.1", resolve));
    const port = (failing.address() as AddressInfo).port;

    const response = await fetch(`http://127.0.0.1:${port}/health`);
    const body = await response.text();

    expect(response.status).toBe(500);
    expect(body).not.toContain("postgres://");
    expect(body).not.toContain("secret internal detail");

    await new Promise<void>((resolve) => failing.close(() => resolve()));
  });
});
