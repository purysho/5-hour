import { beforeAll, afterAll, describe, expect, it } from "vitest";
import {
  prepareDatabase,
  seedProvider,
  adminClient,
  workerDatabase,
  setSubscriptionStatus,
  removeSubscription,
  type Fixture,
} from "./setup.ts";
import type { Database } from "../../src/db/client.ts";
import { applyForgeEvent, type ApplyDeps } from "../../src/http/webhook-apply.ts";
import { applyRepositoryLimit } from "../../src/billing/limits.ts";

/**
 * The repository limit — the thing customers are actually buying tiers of.
 *
 * Enforced at connect time rather than at detection time. The same rule
 * applied at detection would mean a customer's pull requests silently stop
 * arriving for some repositories and they find out weeks later; applied here
 * it is a refusal they see immediately and can act on by upgrading.
 */

let db: Database;

beforeAll(async () => {
  await prepareDatabase();
  db = workerDatabase();
});

afterAll(async () => {
  await db?.close();
});

function deps(): ApplyDeps {
  return {
    withTenant: (id, fn) => db.withTenant(id, fn),
    async providerForInstallation(forgeInstallationId) {
      const rows = await db.withPlatformContext("installation lookup", (client) =>
        client
          .query<{ provider_id: string | null }>(
            "SELECT provider_for_installation($1) AS provider_id",
            [forgeInstallationId],
          )
          .then((r) => r.rows),
      );
      return rows[0]?.provider_id ?? null;
    },
  };
}

async function forgeIdFor(fixture: Fixture): Promise<number> {
  const client = await adminClient();
  try {
    const { rows } = await client.query<{ forge_installation_id: string }>(
      "SELECT forge_installation_id FROM installation WHERE id = $1",
      [fixture.installationId],
    );
    return Number(rows[0]!.forge_installation_id);
  } finally {
    await client.end();
  }
}

async function setLimit(providerId: string, limit: number): Promise<void> {
  const client = await adminClient();
  try {
    await client.query("UPDATE subscription SET repository_limit = $2 WHERE provider_id = $1", [
      providerId,
      limit,
    ]);
  } finally {
    await client.end();
  }
}

async function liveRepositories(providerId: string): Promise<string[]> {
  return db.withTenant(providerId, async (client) => {
    const { rows } = await client.query<{ forge_owner: string; forge_name: string }>(
      "SELECT forge_owner, forge_name FROM repository WHERE archived_at IS NULL ORDER BY forge_name",
    );
    return rows.map((row) => `${row.forge_owner}/${row.forge_name}`);
  });
}

/**
 * A grant of repositories.
 *
 * Forge repository ids are unique across the whole table, not per tenant, so
 * they are derived from the owner rather than from a fixed base — two tests
 * using the same literal id collide globally and fail for a reason that has
 * nothing to do with plan limits.
 */
function grant(owner: string, names: readonly string[]) {
  return names.map((name) => ({
    owner,
    name,
    forgeRepositoryId: forgeRepositoryId(owner, name),
    isPrivate: false,
  }));
}

function forgeRepositoryId(owner: string, name: string): number {
  let hash = 2_166_136_261;
  for (const character of `${owner}/${name}`.toLowerCase()) {
    hash ^= character.charCodeAt(0);
    hash = Math.imul(hash, 16_777_619) >>> 0;
  }
  return hash;
}

describe("connecting repositories under a plan limit", () => {
  it("records everything when the plan has room", async () => {
    const fixture = await seedProvider(`lim-room-${Date.now()}`);
    await setLimit(fixture.providerId, 10);
    const installationId = await forgeIdFor(fixture);

    const result = await applyForgeEvent(
      {
        type: "repositories.added",
        installationId,
        repositories: grant(`${fixture.slug}-consumer`, ["alpha", "beta"]),
      },
      deps(),
    );

    expect(result.applied).toBe(true);
    expect(result.detail).not.toContain("refused");
    expect(await liveRepositories(fixture.providerId)).toEqual(
      expect.arrayContaining([`${fixture.slug}-consumer/alpha`, `${fixture.slug}-consumer/beta`]),
    );
  });

  it("accepts up to the limit and refuses the remainder", async () => {
    const fixture = await seedProvider(`lim-over-${Date.now()}`);
    // seedProvider already records one repository ("widgets"), so a limit of 3
    // leaves room for two more.
    await setLimit(fixture.providerId, 3);
    const installationId = await forgeIdFor(fixture);

    const result = await applyForgeEvent(
      {
        type: "repositories.added",
        installationId,
        repositories: grant(`${fixture.slug}-consumer`, ["one", "two", "three", "four"]),
      },
      deps(),
    );

    expect(result.applied).toBe(true);
    expect(result.detail).toContain("2 refused");

    const live = await liveRepositories(fixture.providerId);
    expect(live).toHaveLength(3);
  });

  it("refuses the whole grant, and says so, when already at the limit", async () => {
    const fixture = await seedProvider(`lim-full-${Date.now()}`);
    await setLimit(fixture.providerId, 1);
    const installationId = await forgeIdFor(fixture);

    const result = await applyForgeEvent(
      {
        type: "repositories.added",
        installationId,
        repositories: grant(`${fixture.slug}-consumer`, ["extra"]),
      },
      deps(),
    );

    expect(result.applied).toBe(false);
    expect(result.detail).toContain("plan limit reached");
    expect(result.auditAction).toBe("repositories.refused");
    expect(await liveRepositories(fixture.providerId)).toHaveLength(1);
  });

  it("does not consume capacity again for a repository already on record", async () => {
    // GitHub re-sends the whole selection on re-install. Counting those again
    // would report a customer's entire existing selection as refused.
    const fixture = await seedProvider(`lim-resend-${Date.now()}`);
    await setLimit(fixture.providerId, 2);
    const installationId = await forgeIdFor(fixture);

    await applyForgeEvent(
      {
        type: "repositories.added",
        installationId,
        repositories: grant(`${fixture.slug}-consumer`, ["second"]),
      },
      deps(),
    );

    const resend = await applyForgeEvent(
      {
        type: "repositories.added",
        installationId,
        repositories: grant(`${fixture.slug}-consumer`, ["widgets", "second"]),
      },
      deps(),
    );

    expect(resend.applied).toBe(true);
    expect(resend.detail).not.toContain("refused");
    expect(await liveRepositories(fixture.providerId)).toHaveLength(2);
  });
});

describe("the limit calculation", () => {
  it("treats forge coordinates case-insensitively, as GitHub does", async () => {
    const fixture = await seedProvider(`lim-case-${Date.now()}`);
    await setLimit(fixture.providerId, 1);

    const outcome = await db.withTenant(fixture.providerId, (client) =>
      applyRepositoryLimit(client, [
        { owner: `${fixture.slug}-consumer`.toUpperCase(), name: "WIDGETS" },
      ]),
    );

    // Already counted under its lowercase spelling, so it is accepted rather
    // than consuming the one remaining slot a second time.
    expect(outcome.accepted).toHaveLength(1);
    expect(outcome.refused).toHaveLength(0);
  });

  it("fails open when no subscription is visible, because the outbound guard already refused them", async () => {
    // The opposite of entitlement, deliberately. Blocking enrolment here would
    // mean a customer whose install webhook lands a second before their
    // subscription row loses their repositories permanently.
    const fixture = await seedProvider(`lim-nosub-${Date.now()}`);
    await removeSubscription(fixture.providerId);

    const outcome = await db.withTenant(fixture.providerId, (client) =>
      applyRepositoryLimit(client, [{ owner: "acme", name: "anything" }]),
    );

    expect(outcome.accepted).toHaveLength(1);
    expect(outcome.refused).toHaveLength(0);
  });

  it("reports the live count and limit for the dashboard to show", async () => {
    const fixture = await seedProvider(`lim-report-${Date.now()}`);
    await setSubscriptionStatus(fixture.providerId, "active");
    await setLimit(fixture.providerId, 50);

    const outcome = await db.withTenant(fixture.providerId, (client) =>
      applyRepositoryLimit(client, []),
    );

    expect(outcome.limit).toBe(50);
    expect(outcome.liveCount).toBe(1);
  });
});
