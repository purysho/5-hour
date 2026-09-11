import { beforeAll, afterAll, describe, expect, it } from "vitest";
import {
  appDatabase,
  prepareDatabase,
  seedProvider,
  setSubscriptionStatus,
  removeSubscription,
  SHA_A,
  type Fixture,
} from "./setup.ts";
import type { Database } from "../../src/db/client.ts";
import { authoriseOutboundWrite } from "../../src/outbound/guard.ts";
import { entitlementFor } from "../../src/billing/entitlement.ts";
import { DUNNING_GRACE_MS } from "../../src/billing/entitlement.ts";

/**
 * Entitlement, enforced where the product is actually delivered.
 *
 * Driftless creates value by opening a pull request and by no other means, so
 * `authoriseOutboundWrite` is the only place the product can be withheld. A
 * tenant that gets past this line gets everything, for free, silently.
 *
 * The second property under test is the one that is easy to get wrong and
 * expensive to discover: refusing an unentitled tenant must consume no
 * idempotency claim. A claim consumed here would mean that when the customer
 * pays, the work is already marked done and is never performed — a silent
 * failure that looks exactly like the product not working.
 */

const TARGET = { forge: "github", owner: "acme", name: "widgets" };

let db: Database;

beforeAll(async () => {
  await prepareDatabase();
  db = appDatabase();
});

afterAll(async () => {
  await db?.close();
});

function request(fixture: Fixture) {
  return {
    providerId: fixture.providerId,
    installationId: fixture.installationId,
    repositoryId: fixture.repositoryId,
    changeId: fixture.changeId,
    baseSha: SHA_A,
    target: TARGET,
  };
}

describe("a tenant who has never paid", () => {
  it("cannot have a pull request opened for them", async () => {
    const fixture = await seedProvider(`ent-never-${Date.now()}`);
    await removeSubscription(fixture.providerId);

    const decision = await db.withTenant(fixture.providerId, (client) =>
      authoriseOutboundWrite(client, request(fixture)),
    );

    expect(decision.allowed).toBe(false);
    if (!decision.allowed && decision.reason === "not-entitled") {
      expect(decision.detail).toContain("no-subscription");
    }
  });

  it("consumes no idempotency claim, so the work is still doable once they pay", async () => {
    const fixture = await seedProvider(`ent-claim-${Date.now()}`);
    await removeSubscription(fixture.providerId);

    const refused = await db.withTenant(fixture.providerId, (client) =>
      authoriseOutboundWrite(client, request(fixture)),
    );
    expect(refused.allowed).toBe(false);

    // They pay. The same work must now be authorised — if the refusal had
    // consumed the claim, this would come back "already-written" and the
    // customer would wait forever for a pull request that was silently
    // skipped.
    await setSubscriptionStatus(fixture.providerId, "active");

    const allowed = await db.withTenant(fixture.providerId, (client) =>
      authoriseOutboundWrite(client, request(fixture)),
    );
    expect(allowed.allowed).toBe(true);
  });
});

describe("a tenant whose subscription lapsed", () => {
  it("is refused once the subscription is cancelled", async () => {
    const fixture = await seedProvider(`ent-cancel-${Date.now()}`);
    await setSubscriptionStatus(fixture.providerId, "canceled");

    const decision = await db.withTenant(fixture.providerId, (client) =>
      authoriseOutboundWrite(client, request(fixture)),
    );
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.reason).toBe("not-entitled");
  });

  it("keeps working while a failed payment is still being retried", async () => {
    const fixture = await seedProvider(`ent-dunning-${Date.now()}`);
    // Period ended yesterday: inside the dunning window.
    await setSubscriptionStatus(
      fixture.providerId,
      "past_due",
      new Date(Date.now() - 24 * 60 * 60 * 1000),
    );

    const decision = await db.withTenant(fixture.providerId, (client) =>
      authoriseOutboundWrite(client, request(fixture)),
    );
    expect(decision.allowed).toBe(true);
  });

  it("stops once the dunning window has closed", async () => {
    const fixture = await seedProvider(`ent-dunned-${Date.now()}`);
    await setSubscriptionStatus(
      fixture.providerId,
      "past_due",
      new Date(Date.now() - DUNNING_GRACE_MS - 60_000),
    );

    const decision = await db.withTenant(fixture.providerId, (client) =>
      authoriseOutboundWrite(client, request(fixture)),
    );
    expect(decision.allowed).toBe(false);
    if (!decision.allowed && decision.reason === "not-entitled") {
      expect(decision.detail).toContain("grace-expired");
    }
  });
});

describe("reading entitlement through a tenant connection", () => {
  it("sees only this tenant's subscription, without a predicate in the query", async () => {
    const mine = await seedProvider(`ent-mine-${Date.now()}`);
    const theirs = await seedProvider(`ent-theirs-${Date.now()}`);
    await setSubscriptionStatus(theirs.providerId, "canceled");

    // The query in loadSubscription has no WHERE clause: isolation is RLS, not
    // application logic. If that were reversed, this would read the other
    // tenant's cancelled row.
    const entitlement = await db.withTenant(mine.providerId, (client) => entitlementFor(client));
    expect(entitlement.entitled).toBe(true);
  });
});
