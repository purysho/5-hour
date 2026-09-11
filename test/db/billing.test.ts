import { beforeAll, afterAll, describe, expect, it } from "vitest";
import pg from "pg";
import {
  ADMIN_URL,
  APP_URL,
  BILLING_URL,
  adminClient,
  appDatabase,
  prepareDatabase,
  seedProvider,
} from "./setup.ts";
import type { Database } from "../../src/db/client.ts";
import { createBillingStore, slugFor, type BillingStore } from "../../src/billing/provisioning.ts";
import { PLANS } from "../../src/billing/plans.ts";
import { Secret } from "../../src/config.ts";

/**
 * The narrow door that creates a tenant (migration 012).
 *
 * Two properties are under test and neither is visible in application code:
 * the billing role can create a tenant and read nothing about one, and the
 * application role can read its own entitlement and write none. Both are
 * enforced by grants and RLS, so both are tested against a live database
 * through the same login roles production uses. Testing them through a
 * superuser connection would make every assertion pass vacuously.
 */

let db: Database;
let store: BillingStore;

beforeAll(async () => {
  await prepareDatabase();
  db = appDatabase();
  store = createBillingStore(new Secret(BILLING_URL, "BILLING_DATABASE_URL"));
});

afterAll(async () => {
  await db?.close();
  await store?.close();
});

function provisionRequest(slug: string, overrides: Record<string, unknown> = {}) {
  return {
    slug,
    displayName: `${slug}@example.com`,
    stripeCustomerId: `cus_${slug}`,
    stripeSubscriptionId: `sub_${slug}`,
    status: "active",
    plan: PLANS.team,
    currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    cancelAtPeriodEnd: false,
    ...overrides,
  };
}

describe("provisioning a paid checkout", () => {
  it("creates the tenant and its subscription in one call", async () => {
    const slug = `bill-new-${Date.now()}`;
    const result = await store.provision(provisionRequest(slug));

    expect(result.created).toBe(true);
    expect(result.providerId).toMatch(/^[0-9a-f-]{36}$/);

    const entitlement = await db.withTenant(result.providerId, (client) =>
      client.query<{ status: string; plan: string; repository_limit: number }>(
        "SELECT status, plan, repository_limit FROM subscription",
      ),
    );
    expect(entitlement.rows[0]).toMatchObject({
      status: "active",
      plan: "team",
      repository_limit: 50,
    });
  });

  it("converges on redelivery instead of creating a second tenant", async () => {
    // Stripe redelivers. A non-idempotent handler splits one customer's
    // repositories across two tenants that cannot see each other, and nothing
    // surfaces it until they ask why half their repos are ignored.
    const slug = `bill-dup-${Date.now()}`;
    const first = await store.provision(provisionRequest(slug));
    const second = await store.provision(provisionRequest(slug));

    expect(second.providerId).toBe(first.providerId);
    expect(second.created).toBe(false);

    const admin = await adminClient();
    try {
      const { rows } = await admin.query<{ count: string }>(
        "SELECT count(*)::text FROM subscription WHERE provider_id = $1",
        [first.providerId],
      );
      expect(rows[0]!.count).toBe("1");
    } finally {
      await admin.end();
    }
  });

  it("upgrades a plan in place, keeping the tenant and its repositories", async () => {
    const slug = `bill-upgrade-${Date.now()}`;
    const created = await store.provision(provisionRequest(slug));
    const upgraded = await store.provision(provisionRequest(slug, { plan: PLANS.scale }));

    expect(upgraded.providerId).toBe(created.providerId);

    const { rows } = await db.withTenant(created.providerId, (client) =>
      client.query<{ plan: string; repository_limit: number }>(
        "SELECT plan, repository_limit FROM subscription",
      ),
    );
    expect(rows[0]).toMatchObject({ plan: "scale", repository_limit: 200 });
  });

  it("re-subscribes a returning customer onto their existing tenant", async () => {
    // Cancel, then come back weeks later: a new Stripe subscription id, the
    // same email, and therefore the same slug. Keying the upsert on the
    // subscription id instead of the tenant made this violate the
    // one-subscription-per-tenant index — the webhook 500s, Stripe retries
    // until it disables the endpoint, and a customer who has paid is never
    // provisioned. Found by this test.
    const slug = `bill-return-${Date.now()}`;
    const first = await store.provision(provisionRequest(slug));
    await store.provision(provisionRequest(slug, { status: "canceled" }));

    const renewed = `sub_renewed_${Date.now()}`;
    const returning = await store.provision(
      provisionRequest(slug, { stripeSubscriptionId: renewed, status: "active" }),
    );

    expect(returning.providerId).toBe(first.providerId);

    const { rows } = await db.withTenant(first.providerId, (client) =>
      client.query<{ status: string; stripe_subscription_id: string }>(
        "SELECT status, stripe_subscription_id FROM subscription",
      ),
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ status: "active", stripe_subscription_id: renewed });
  });

  it("records a cancellation so entitlement can see it", async () => {
    const slug = `bill-cancel-${Date.now()}`;
    const created = await store.provision(provisionRequest(slug));
    await store.provision(provisionRequest(slug, { status: "canceled" }));

    const { rows } = await db.withTenant(created.providerId, (client) =>
      client.query<{ status: string }>("SELECT status FROM subscription"),
    );
    expect(rows[0]!.status).toBe("canceled");
  });
});

describe("the event claim", () => {
  it("is held by the first caller only", async () => {
    const eventId = `evt_${Date.now()}`;
    expect(await store.claimEvent(eventId, "customer.subscription.created")).toBe(true);
    expect(await store.claimEvent(eventId, "customer.subscription.created")).toBe(false);
  });

  it("resolves a race in the database rather than in application code", async () => {
    const eventId = `evt_race_${Date.now()}`;
    const results = await Promise.all(
      Array.from({ length: 8 }, () => store.claimEvent(eventId, "customer.subscription.updated")),
    );
    expect(results.filter(Boolean)).toHaveLength(1);
  });
});

describe("the application role", () => {
  it("can read its own entitlement", async () => {
    const fixture = await seedProvider(`bill-read-${Date.now()}`);
    const { rows } = await db.withTenant(fixture.providerId, (client) =>
      client.query("SELECT status FROM subscription"),
    );
    expect(rows).toHaveLength(1);
  });

  it("cannot see another tenant's subscription", async () => {
    const mine = await seedProvider(`bill-mine-${Date.now()}`);
    const theirs = await seedProvider(`bill-theirs-${Date.now()}`);

    const { rows } = await db.withTenant(mine.providerId, (client) =>
      client.query("SELECT provider_id FROM subscription WHERE provider_id = $1", [
        theirs.providerId,
      ]),
    );
    expect(rows).toHaveLength(0);
  });

  it("cannot grant itself a subscription", async () => {
    // The whole enforcement story rests on this. If the application role could
    // write here, entitlement would be advisory.
    const fixture = await seedProvider(`bill-selfgrant-${Date.now()}`);
    const client = new pg.Client({ connectionString: APP_URL });
    await client.connect();
    try {
      await client.query("SELECT set_config('app.current_provider_id', $1, false)", [
        fixture.providerId,
      ]);
      await expect(
        client.query(
          `INSERT INTO subscription (provider_id, stripe_customer_id, stripe_subscription_id,
                                     status, plan, repository_limit)
           VALUES ($1, 'cus_x', 'sub_x', 'active', 'scale', 200)`,
          [fixture.providerId],
        ),
      ).rejects.toThrow(/permission denied/i);
    } finally {
      await client.end();
    }
  });

  it("cannot upgrade its own plan", async () => {
    const fixture = await seedProvider(`bill-selfupgrade-${Date.now()}`);
    const client = new pg.Client({ connectionString: APP_URL });
    await client.connect();
    try {
      await client.query("SELECT set_config('app.current_provider_id', $1, false)", [
        fixture.providerId,
      ]);
      await expect(
        client.query("UPDATE subscription SET repository_limit = 9999"),
      ).rejects.toThrow(/permission denied/i);
    } finally {
      await client.end();
    }
  });

  it("cannot create a tenant, which is what makes the billing role necessary", async () => {
    const client = new pg.Client({ connectionString: APP_URL });
    await client.connect();
    try {
      await expect(
        client.query("INSERT INTO provider (slug, display_name) VALUES ('smuggled', 'x')"),
      ).rejects.toThrow();
    } finally {
      await client.end();
    }
  });
});

describe("the billing role", () => {
  it("cannot read the repositories of a tenant it created", async () => {
    // It creates customers; it has no business reading their code locations.
    const fixture = await seedProvider(`bill-blind-${Date.now()}`);
    const client = new pg.Client({ connectionString: BILLING_URL });
    await client.connect();
    try {
      await expect(client.query("SELECT * FROM repository")).rejects.toThrow(
        /permission denied/i,
      );
      expect(fixture.repositoryId).toBeTruthy();
    } finally {
      await client.end();
    }
  });

  it("cannot enumerate tenants", async () => {
    const client = new pg.Client({ connectionString: BILLING_URL });
    await client.connect();
    try {
      await expect(client.query("SELECT slug FROM provider")).rejects.toThrow(
        /permission denied/i,
      );
    } finally {
      await client.end();
    }
  });

  it("holds neither the application nor the platform role", async () => {
    // Postgres ORs the policies of every role you hold. Combining these would
    // grant cross-tenant visibility with no error and nothing to see in review
    // — see ADR-0010 and non-negotiable 10.
    const admin = new pg.Client({ connectionString: ADMIN_URL });
    await admin.connect();
    try {
      const { rows } = await admin.query<{ rolname: string }>(
        `SELECT r.rolname
           FROM pg_auth_members m
           JOIN pg_roles r ON r.oid = m.roleid
           JOIN pg_roles g ON g.oid = m.member
          WHERE g.rolname = 'driftless_billing_login'`,
      );
      const held = rows.map((r) => r.rolname);
      expect(held).toContain("driftless_billing");
      expect(held).not.toContain("driftless_app");
      expect(held).not.toContain("driftless_admin");
    } finally {
      await admin.end();
    }
  });
});

describe("slug derivation", () => {
  it("is readable when an email is known", () => {
    expect(slugFor("ops@acme.io", "cus_ABC12345XYZ")).toMatch(/^ops-abc12345$/);
  });

  it("falls back to the customer id when no email was captured", () => {
    expect(slugFor(null, "cus_ABC12345XYZ")).toBe("tenant-abc12345");
  });

  it("does not collide for two customers with the same email local part", () => {
    expect(slugFor("ops@a.io", "cus_11111111")).not.toBe(slugFor("ops@b.io", "cus_22222222"));
  });

  it("strips characters that are not slug-safe", () => {
    expect(slugFor("Ops.Team+billing@acme.io", "cus_99999999")).toBe("ops-team-billing-99999999");
  });
});
