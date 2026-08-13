import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { prepareDatabase, seedProvider, workerDatabase, type Fixture } from "../db/setup.ts";
import type { Database } from "../../src/db/client.ts";
import { handleOptOut, type OptOutDeps, type OptOutEvent } from "../../src/http/opt-out.ts";
import {
  checkSuppression,
  hashToken,
  issueOptOutToken,
  recordOptOutToken,
} from "../../src/outbound/suppression.ts";

/**
 * The opt-out endpoint.
 *
 * The only unauthenticated, publicly reachable surface in the system, used by
 * someone who is already mildly annoyed with us. It has to work on the first
 * click — and, more subtly, must NOT work when nobody clicked.
 */

let db: Database;
let tenant: Fixture;

const TARGET = { forge: "github", owner: "acme", name: "widgets" };

beforeAll(async () => {
  await prepareDatabase();
  db = workerDatabase();
  tenant = await seedProvider("optout-http");
});

afterAll(async () => {
  await db?.close();
});

function deps(
  events: OptOutEvent[] = [],
  providerId: string = tenant.providerId,
): OptOutDeps {
  return {
    withTenant: (id, fn) => db.withTenant(id, fn),
    hashToken,
    async providerForToken(tokenHash) {
      // Via the minimal-disclosure function, not a table read — the platform
      // role deliberately holds no SELECT on opt_out_token.
      const rows = await db.withPlatformContext("opt-out token lookup", (client) =>
        client
          .query<{ provider_id: string | null }>(
            "SELECT provider_for_opt_out_token($1) AS provider_id",
            [tokenHash],
          )
          .then((r) => r.rows),
      );
      return rows[0]?.provider_id ?? null;
    },
    observe: (event) => events.push(event),
  };
}

async function issueFor(fixture: Fixture): Promise<string> {
  const issued = issueOptOutToken();
  await db.withTenant(fixture.providerId, (client) =>
    recordOptOutToken(client, fixture.providerId, issued.hash, TARGET),
  );
  return issued.token;
}

describe("GET changes nothing", () => {
  /**
   * The important behaviour in this file.
   *
   * GitHub, Slack, mail providers and security appliances all fetch links
   * automatically to build previews or scan them. A state-changing GET fires
   * without anyone clicking — including when GitHub renders our own pull
   * request body. The failure is silent and indistinguishable from a genuine
   * opt-out, so we would quietly stop contacting repositories that never asked.
   */

  it("renders a confirmation page without suppressing", async () => {
    const fixture = await seedProvider("optout-get");
    const token = await issueFor(fixture);

    const response = await handleOptOut(
      { method: "GET", token },
      deps([], fixture.providerId),
    );

    expect(response.status).toBe(200);
    expect(response.body).toContain("Stop pull requests");

    const check = await db.withTenant(fixture.providerId, (client) =>
      checkSuppression(client, TARGET),
    );
    expect(check.suppressed, "a link preview must not opt anyone out").toBe(false);
  });

  it("survives repeated prefetches without side effects", async () => {
    const fixture = await seedProvider("optout-prefetch");
    const token = await issueFor(fixture);
    const d = deps([], fixture.providerId);

    for (let i = 0; i < 5; i++) {
      await handleOptOut({ method: "GET", token }, d);
    }

    const check = await db.withTenant(fixture.providerId, (client) =>
      checkSuppression(client, TARGET),
    );
    expect(check.suppressed).toBe(false);
  });

  it("offers a form that posts back to the same token", async () => {
    const fixture = await seedProvider("optout-form");
    const token = await issueFor(fixture);
    const response = await handleOptOut(
      { method: "GET", token },
      deps([], fixture.providerId),
    );
    expect(response.body).toContain('method="post"');
    expect(response.body).toContain(`action="/opt-out/${token}"`);
  });
});

describe("POST performs the opt-out", () => {
  it("suppresses the repository", async () => {
    const fixture = await seedProvider("optout-post");
    const token = await issueFor(fixture);

    const response = await handleOptOut(
      { method: "POST", token },
      deps([], fixture.providerId),
    );

    expect(response.status).toBe(200);
    expect(response.body).toContain("we will not open another pull request");

    const check = await db.withTenant(fixture.providerId, (client) =>
      checkSuppression(client, TARGET),
    );
    expect(check.suppressed).toBe(true);
  });

  it("records an optional reason without echoing it back", async () => {
    // Unauthenticated free text. It exists to be read by us later, never to be
    // rendered into a page.
    const fixture = await seedProvider("optout-reason");
    const token = await issueFor(fixture);

    const response = await handleOptOut(
      {
        method: "POST",
        token,
        formFields: { reason: "<script>alert(1)</script> too noisy" },
      },
      deps([], fixture.providerId),
    );

    expect(response.body).not.toContain("<script>");
    expect(response.body).not.toContain("too noisy");

    const { rows } = await db.withTenant(fixture.providerId, (client) =>
      client.query<{ reason: string }>("SELECT reason FROM suppression"),
    );
    expect(rows[0]?.reason).toContain("too noisy");
  });

  it("is idempotent — a second submission still confirms", async () => {
    const fixture = await seedProvider("optout-twice");
    const token = await issueFor(fixture);
    const d = deps([], fixture.providerId);

    await handleOptOut({ method: "POST", token }, d);
    const second = await handleOptOut({ method: "POST", token }, d);
    expect(second.status).toBe(200);
    expect(second.body).toContain("opted out");
  });
});

describe("unrecognised tokens", () => {
  it("returns the same response for malformed and unknown tokens", async () => {
    // A distinct "malformed" page would let someone probe the token format.
    const fixture = await seedProvider("optout-probe");
    const unknown = await handleOptOut(
      { method: "GET", token: "A".repeat(43) },
      { ...deps([], fixture.providerId), providerForToken: async () => null },
    );
    const malformed = await handleOptOut(
      { method: "GET", token: "../../etc/passwd" },
      deps([], fixture.providerId),
    );

    expect(unknown.status).toBe(404);
    expect(malformed.status).toBe(404);
    expect(malformed.body).toBe(unknown.body);
  });

  it("rejects a malformed token before it reaches the database", async () => {
    let looked = 0;
    const response = await handleOptOut(
      { method: "POST", token: "'; DROP TABLE suppression; --" },
      {
        ...deps(),
        providerForToken: async () => {
          looked += 1;
          return tenant.providerId;
        },
      },
    );
    expect(response.status).toBe(404);
    expect(looked).toBe(0);
  });

  it("tells someone what to do instead", async () => {
    // The person reading this is already annoyed. A bare 404 earns a public
    // complaint; a route to a human does not.
    const response = await handleOptOut(
      { method: "GET", token: "A".repeat(43) },
      { ...deps(), providerForToken: async () => null },
    );
    expect(response.body).toContain("close one with a comment");
  });
});

describe("method handling", () => {
  it("rejects methods other than GET and POST", async () => {
    for (const method of ["PUT", "DELETE", "PATCH", "HEAD"]) {
      const response = await handleOptOut({ method, token: "A".repeat(43) }, deps());
      expect(response.status, method).toBe(405);
      expect(response.headers["allow"]).toBe("GET, POST");
    }
  });
});

describe("response hardening", () => {
  it("sets a restrictive content security policy", async () => {
    const fixture = await seedProvider("optout-csp");
    const token = await issueFor(fixture);
    const response = await handleOptOut(
      { method: "GET", token },
      deps([], fixture.providerId),
    );

    expect(response.headers["content-security-policy"]).toContain("default-src 'none'");
    expect(response.headers["content-security-policy"]).toContain("frame-ancestors 'none'");
    expect(response.headers["x-frame-options"]).toBe("DENY");
    expect(response.headers["x-content-type-options"]).toBe("nosniff");
  });

  it("never caches, so a confirmation cannot be replayed by an intermediary", async () => {
    const fixture = await seedProvider("optout-cache");
    const token = await issueFor(fixture);
    const response = await handleOptOut(
      { method: "POST", token },
      deps([], fixture.providerId),
    );
    expect(response.headers["cache-control"]).toBe("no-store");
  });

  it("sends no referrer, so the token does not leak to third parties", async () => {
    const fixture = await seedProvider("optout-referrer");
    const token = await issueFor(fixture);
    const response = await handleOptOut(
      { method: "GET", token },
      deps([], fixture.providerId),
    );
    expect(response.headers["referrer-policy"]).toBe("no-referrer");
    expect(response.body).toContain('name="robots" content="noindex');
  });
});

describe("observability", () => {
  it("distinguishes a view from a confirmation", async () => {
    // The difference between "a bot looked at the link" and "a human opted
    // out" is the whole point of the split, so the events must not blur it.
    const fixture = await seedProvider("optout-events");
    const token = await issueFor(fixture);
    const events: OptOutEvent[] = [];
    const d = deps(events, fixture.providerId);

    await handleOptOut({ method: "GET", token }, d);
    await handleOptOut({ method: "POST", token }, d);

    expect(events.map((e) => e.kind)).toEqual(["viewed", "confirmed"]);
    expect(events[1]?.target).toMatchObject({ owner: "acme", name: "widgets" });
  });

  it("puts no token in any event", async () => {
    const fixture = await seedProvider("optout-noleak");
    const token = await issueFor(fixture);
    const events: OptOutEvent[] = [];
    await handleOptOut({ method: "POST", token }, deps(events, fixture.providerId));
    expect(JSON.stringify(events)).not.toContain(token);
  });
});

describe("tenant resolution discloses the minimum", () => {
  /**
   * The unauthenticated endpoint has to resolve a token to a tenant before
   * tenant context can exist. The obvious implementation — grant the platform
   * role SELECT on opt_out_token — was rejected by the RLS coverage test, and
   * correctly: that table records which repositories each provider has
   * contacted, and providers are frequently competitors.
   *
   * These tests pin the narrower mechanism that replaced it.
   */

  it("does not let the platform role read the token table", async () => {
    await expect(
      db.withPlatformContext("attempted direct read", (client) =>
        client.query("SELECT * FROM opt_out_token"),
      ),
    ).rejects.toThrow(/permission denied/i);
  });

  it("returns only a provider id, never the target", async () => {
    const fixture = await seedProvider("optout-disclosure");
    const token = await issueFor(fixture);

    const { rows } = await db.withPlatformContext("token lookup", (client) =>
      client.query<Record<string, unknown>>(
        "SELECT provider_for_opt_out_token($1) AS provider_id",
        [hashToken(token)],
      ),
    );

    expect(rows[0]?.["provider_id"]).toBe(fixture.providerId);
    // Owner and repository name are what a competitor would want. They are
    // not in the result at all, rather than being present and ignored.
    expect(Object.keys(rows[0] ?? {})).toEqual(["provider_id"]);
    expect(JSON.stringify(rows[0])).not.toContain("acme");
    expect(JSON.stringify(rows[0])).not.toContain("widgets");
  });

  it("reveals nothing for a hash the caller does not already hold", async () => {
    // The capability is "confirm the tenant of a token you have", not
    // "enumerate tenants". Matching on the primary key means there is no scan.
    const { rows } = await db.withPlatformContext("unknown lookup", (client) =>
      client.query<{ provider_id: string | null }>(
        "SELECT provider_for_opt_out_token($1) AS provider_id",
        ["0".repeat(64)],
      ),
    );
    expect(rows[0]?.provider_id).toBeNull();
  });

  it("is not executable by the tenant-scoped role", async () => {
    await expect(
      db.withTenant(tenant.providerId, (client) =>
        client.query("SELECT provider_for_opt_out_token($1)", ["0".repeat(64)]),
      ),
    ).rejects.toThrow(/permission denied/i);
  });
});
