import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { prepareDatabase, seedProvider, workerDatabase, type Fixture } from "./setup.ts";
import type { Database } from "../../src/db/client.ts";
import {
  checkSuppression,
  hashToken,
  issueOptOutToken,
  recordOptOutToken,
  redeemOptOutToken,
  suppress,
  tokensEqual,
} from "../../src/outbound/suppression.ts";

/**
 * Suppression.
 *
 * Every pull request body promises "one click, no account, and we will not
 * open another pull request here." A promise printed on a trusted artifact and
 * not enforced is worse than no promise — it converts goodwill into a public
 * grievance the moment we open a second pull request after someone clicked.
 *
 * So these tests are about whether the promise actually holds.
 */

let db: Database;
let tenant: Fixture;

beforeAll(async () => {
  await prepareDatabase();
  db = workerDatabase();
  tenant = await seedProvider("suppress");
});

afterAll(async () => {
  await db?.close();
});

const TARGET = { forge: "github", owner: "acme", name: "widgets" };

describe("honouring an opt-out", () => {
  it("reports no suppression for an untouched repository", async () => {
    const result = await db.withTenant(tenant.providerId, (client) =>
      checkSuppression(client, TARGET),
    );
    expect(result.suppressed).toBe(false);
  });

  it("suppresses a repository after opt-out", async () => {
    const fixture = await seedProvider("suppress-repo");
    await db.withTenant(fixture.providerId, (client) =>
      suppress(client, fixture.providerId, { ...TARGET, scope: "repository" }),
    );

    const result = await db.withTenant(fixture.providerId, (client) =>
      checkSuppression(client, TARGET),
    );
    expect(result.suppressed).toBe(true);
    if (!result.suppressed) return;
    expect(result.scope).toBe("repository");
  });

  it("does not suppress a sibling repository under a repository-scoped opt-out", async () => {
    const fixture = await seedProvider("suppress-sibling");
    await db.withTenant(fixture.providerId, (client) =>
      suppress(client, fixture.providerId, { ...TARGET, scope: "repository" }),
    );

    const sibling = await db.withTenant(fixture.providerId, (client) =>
      checkSuppression(client, { ...TARGET, name: "gadgets" }),
    );
    expect(sibling.suppressed).toBe(false);
  });

  it("suppresses every repository under an owner-scoped opt-out", async () => {
    // A maintainer with forty repositories should not have to click forty
    // times to be left alone.
    const fixture = await seedProvider("suppress-owner");
    await db.withTenant(fixture.providerId, (client) =>
      suppress(client, fixture.providerId, { ...TARGET, scope: "owner" }),
    );

    for (const name of ["widgets", "gadgets", "anything-at-all"]) {
      const result = await db.withTenant(fixture.providerId, (client) =>
        checkSuppression(client, { ...TARGET, name }),
      );
      expect(result.suppressed, name).toBe(true);
    }
  });

  it("matches case-insensitively", async () => {
    // Forge identifiers are case-insensitive. A case-sensitive comparison
    // would silently fail to suppress, which is the worst possible bug here:
    // no error, just a broken promise.
    const fixture = await seedProvider("suppress-case");
    await db.withTenant(fixture.providerId, (client) =>
      suppress(client, fixture.providerId, {
        forge: "github",
        owner: "AcMe",
        name: "WiDgEtS",
        scope: "repository",
      }),
    );

    const result = await db.withTenant(fixture.providerId, (client) =>
      checkSuppression(client, { forge: "github", owner: "ACME", name: "widgets" }),
    );
    expect(result.suppressed).toBe(true);
  });

  it("is permanent by default", async () => {
    // Someone who opted out last year has not consented to being contacted
    // again this year.
    const fixture = await seedProvider("suppress-permanent");
    await db.withTenant(fixture.providerId, (client) =>
      suppress(client, fixture.providerId, { ...TARGET, scope: "repository" }),
    );

    const { rows } = await db.withTenant(fixture.providerId, (client) =>
      client.query<{ expires_at: string | null }>("SELECT expires_at FROM suppression"),
    );
    expect(rows[0]?.expires_at).toBeNull();
  });

  it("ignores an expired suppression", async () => {
    const fixture = await seedProvider("suppress-expired");
    await db.withTenant(fixture.providerId, (client) =>
      suppress(client, fixture.providerId, {
        ...TARGET,
        scope: "repository",
        expiresAt: new Date(Date.now() - 1000),
      }),
    );

    const result = await db.withTenant(fixture.providerId, (client) =>
      checkSuppression(client, TARGET),
    );
    expect(result.suppressed).toBe(false);
  });

  it("is idempotent — clicking twice is not an error", async () => {
    const fixture = await seedProvider("suppress-twice");
    await db.withTenant(fixture.providerId, async (client) => {
      await suppress(client, fixture.providerId, { ...TARGET, scope: "repository" });
      await suppress(client, fixture.providerId, { ...TARGET, scope: "repository" });
    });

    const { rows } = await db.withTenant(fixture.providerId, (client) =>
      client.query<{ count: string }>("SELECT count(*) FROM suppression"),
    );
    expect(Number(rows[0]!.count)).toBe(1);
  });

  it("does not leak suppression across tenants", async () => {
    const a = await seedProvider("suppress-tenant-a");
    const b = await seedProvider("suppress-tenant-b");
    await db.withTenant(a.providerId, (client) =>
      suppress(client, a.providerId, { ...TARGET, scope: "repository" }),
    );

    const other = await db.withTenant(b.providerId, (client) =>
      checkSuppression(client, TARGET),
    );
    expect(other.suppressed).toBe(false);
  });

  it("truncates an oversized reason from an unauthenticated endpoint", async () => {
    const fixture = await seedProvider("suppress-reason");
    await db.withTenant(fixture.providerId, (client) =>
      suppress(client, fixture.providerId, {
        ...TARGET,
        scope: "repository",
        reason: "x".repeat(10_000),
      }),
    );

    const { rows } = await db.withTenant(fixture.providerId, (client) =>
      client.query<{ reason: string }>("SELECT reason FROM suppression"),
    );
    expect(rows[0]!.reason.length).toBe(500);
  });
});

describe("opt-out tokens", () => {
  it("mints an unguessable token and stores only its hash", async () => {
    // A database read must not yield working opt-out links for every
    // repository we have ever contacted — that would be a tidy
    // denial-of-service list against our own customers.
    const fixture = await seedProvider("token-hash");
    const issued = issueOptOutToken();
    await db.withTenant(fixture.providerId, (client) =>
      recordOptOutToken(client, fixture.providerId, issued.hash, TARGET),
    );

    const { rows } = await db.withTenant(fixture.providerId, (client) =>
      client.query<{ token_hash: string }>("SELECT token_hash FROM opt_out_token"),
    );
    expect(rows[0]!.token_hash).toBe(hashToken(issued.token));
    expect(rows[0]!.token_hash).not.toBe(issued.token);
    expect(issued.token.length).toBeGreaterThanOrEqual(40);
  });

  it("suppresses the repository when redeemed", async () => {
    const fixture = await seedProvider("token-redeem");
    const issued = issueOptOutToken();

    const result = await db.withTenant(fixture.providerId, async (client) => {
      await recordOptOutToken(client, fixture.providerId, issued.hash, TARGET);
      return redeemOptOutToken(client, fixture.providerId, issued.token, "too noisy");
    });

    expect(result.redeemed).toBe(true);
    const check = await db.withTenant(fixture.providerId, (client) =>
      checkSuppression(client, TARGET),
    );
    expect(check.suppressed).toBe(true);
  });

  it("rejects an unknown token", async () => {
    const fixture = await seedProvider("token-unknown");
    const result = await db.withTenant(fixture.providerId, (client) =>
      redeemOptOutToken(client, fixture.providerId, "not-a-real-token"),
    );
    expect(result.redeemed).toBe(false);
  });

  it("stays valid after use, so a second click still works", async () => {
    // Someone who clicks again because nothing visibly happened should land on
    // "you are opted out", not an error page.
    const fixture = await seedProvider("token-reuse");
    const issued = issueOptOutToken();

    const second = await db.withTenant(fixture.providerId, async (client) => {
      await recordOptOutToken(client, fixture.providerId, issued.hash, TARGET);
      await redeemOptOutToken(client, fixture.providerId, issued.token);
      return redeemOptOutToken(client, fixture.providerId, issued.token);
    });
    expect(second.redeemed).toBe(true);
  });

  it("does not move the original redemption timestamp on re-use", async () => {
    const fixture = await seedProvider("token-timestamp");
    const issued = issueOptOutToken();

    const [first, second] = await db.withTenant(fixture.providerId, async (client) => {
      await recordOptOutToken(client, fixture.providerId, issued.hash, TARGET);
      await redeemOptOutToken(client, fixture.providerId, issued.token);
      const a = await client.query<{ redeemed_at: string }>(
        "SELECT redeemed_at FROM opt_out_token",
      );
      await redeemOptOutToken(client, fixture.providerId, issued.token);
      const b = await client.query<{ redeemed_at: string }>(
        "SELECT redeemed_at FROM opt_out_token",
      );
      // pg returns Date objects, so compare by value rather than identity.
      return [
        new Date(a.rows[0]!.redeemed_at).toISOString(),
        new Date(b.rows[0]!.redeemed_at).toISOString(),
      ];
    });
    expect(first).toBe(second);
  });

  it("mints a distinct token every time", async () => {
    const tokens = new Set(Array.from({ length: 50 }, () => issueOptOutToken().token));
    expect(tokens.size).toBe(50);
  });

  it("compares tokens in constant time", () => {
    const a = issueOptOutToken().token;
    expect(tokensEqual(a, a)).toBe(true);
    expect(tokensEqual(a, issueOptOutToken().token)).toBe(false);
    // Different lengths must not throw — timingSafeEqual does on mismatch.
    expect(tokensEqual(a, "short")).toBe(false);
  });
});
