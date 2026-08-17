import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { prepareDatabase, seedProvider, adminClient, workerDatabase, type Fixture } from "../db/setup.ts";
import type { Database } from "../../src/db/client.ts";
import { applyForgeEvent, type ApplyDeps } from "../../src/http/webhook-apply.ts";
import type { ForgeEvent } from "../../src/http/webhook.ts";

/**
 * Applying webhook events.
 *
 * Parsing an event is not honouring it. These tests are about whether
 * revocation actually reaches the database — continuing to act on an
 * installation a customer believes they revoked is the single worst thing this
 * system can do.
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

async function suspendedAt(fixture: Fixture): Promise<string | null> {
  return db.withTenant(fixture.providerId, async (client) => {
    const { rows } = await client.query<{ suspended_at: string | null }>(
      "SELECT suspended_at FROM installation WHERE id = $1",
      [fixture.installationId],
    );
    return rows[0]?.suspended_at ?? null;
  });
}

describe("revocation", () => {
  it("suspends the installation immediately", async () => {
    const fixture = await seedProvider("wh-revoke");
    const installationId = await forgeIdFor(fixture);

    const result = await applyForgeEvent(
      { type: "installation.revoked", installationId },
      deps(),
    );

    expect(result.applied).toBe(true);
    expect(await suspendedAt(fixture)).not.toBeNull();
  });

  it("cancels queued jobs rather than letting them discover the revocation", async () => {
    // A queued job would otherwise run, try to mint a token, and only then
    // stop. "Only then" is after it has already acted.
    const fixture = await seedProvider("wh-revoke-jobs");
    const installationId = await forgeIdFor(fixture);

    await db.withTenant(fixture.providerId, (client) =>
      client.query(
        `INSERT INTO job (provider_id, workflow, input, status)
         VALUES ($1, 'migrate-repository', $2, 'pending')`,
        [
          fixture.providerId,
          JSON.stringify({ installationId: fixture.installationId, repositoryId: fixture.repositoryId }),
        ],
      ),
    );

    const result = await applyForgeEvent(
      { type: "installation.revoked", installationId },
      deps(),
    );

    expect(result.detail).toContain("1 queued job(s) cancelled");

    const { rows } = await db.withTenant(fixture.providerId, (client) =>
      client.query<{ status: string }>("SELECT status FROM job"),
    );
    expect(rows[0]?.status).toBe("cancelled");
  });

  it("does not cancel jobs that already finished", async () => {
    const fixture = await seedProvider("wh-revoke-finished");
    const installationId = await forgeIdFor(fixture);

    await db.withTenant(fixture.providerId, (client) =>
      client.query(
        `INSERT INTO job (provider_id, workflow, input, status, finished_at)
         VALUES ($1, 'migrate-repository', $2, 'succeeded', now())`,
        [fixture.providerId, JSON.stringify({ installationId: fixture.installationId })],
      ),
    );

    await applyForgeEvent({ type: "installation.revoked", installationId }, deps());

    const { rows } = await db.withTenant(fixture.providerId, (client) =>
      client.query<{ status: string }>("SELECT status FROM job"),
    );
    expect(rows[0]?.status).toBe("succeeded");
  });

  it("is idempotent — a replayed revocation does not move the timestamp", async () => {
    const fixture = await seedProvider("wh-revoke-twice");
    const installationId = await forgeIdFor(fixture);

    await applyForgeEvent({ type: "installation.revoked", installationId }, deps());
    const first = await suspendedAt(fixture);
    await applyForgeEvent({ type: "installation.revoked", installationId }, deps());
    const second = await suspendedAt(fixture);

    expect(new Date(first!).toISOString()).toBe(new Date(second!).toISOString());
  });

  it("ignores an event for an installation we do not know", async () => {
    // Common and benign: a stale delivery after a tenant was deleted.
    const result = await applyForgeEvent(
      { type: "installation.revoked", installationId: 999_999_999 },
      deps(),
    );
    expect(result.applied).toBe(false);
    expect(result.detail).toContain("no installation matching");
  });
});

describe("suspension is reversible", () => {
  it("restores an unsuspended installation", async () => {
    const fixture = await seedProvider("wh-unsuspend");
    const installationId = await forgeIdFor(fixture);

    await applyForgeEvent({ type: "installation.suspended", installationId }, deps());
    expect(await suspendedAt(fixture)).not.toBeNull();

    await applyForgeEvent({ type: "installation.unsuspended", installationId }, deps());
    expect(await suspendedAt(fixture)).toBeNull();
  });
});

describe("repositories granted", () => {
  it("records the repositories a customer just granted", async () => {
    // The row this writes is the only thing that makes a repository visible to
    // the rest of the pipeline. Without it there is nothing to migrate, which
    // is exactly the state the system was in before this event was handled.
    const fixture = await seedProvider(`wh-add-${Date.now()}`);
    const installationId = await forgeIdFor(fixture);

    const event: ForgeEvent = {
      type: "repositories.added",
      installationId,
      repositories: [
        { owner: "acme", name: "new-service", forgeRepositoryId: 987, isPrivate: true },
      ],
    };

    const result = await applyForgeEvent(event, deps());
    expect(result.applied).toBe(true);

    const rows = await db.withTenant(fixture.providerId, async (client) => {
      const { rows } = await client.query<{ forge_repository_id: string; is_private: boolean }>(
        "SELECT forge_repository_id, is_private FROM repository WHERE forge_name = $1",
        ["new-service"],
      );
      return rows;
    });

    expect(rows).toHaveLength(1);
    // ADR-0002 scopes a token by numeric id. A row without one is a repository
    // we can name and cannot act on.
    expect(Number(rows[0]!.forge_repository_id)).toBe(987);
  });

  it("does not create a second row when the grant is replayed", async () => {
    // Webhook deliveries repeat. Two rows for one repository would mean two
    // candidate entries and, downstream, two pull requests.
    const fixture = await seedProvider(`wh-add-replay-${Date.now()}`);
    const installationId = await forgeIdFor(fixture);
    const event: ForgeEvent = {
      type: "repositories.added",
      installationId,
      repositories: [{ owner: "acme", name: "svc", forgeRepositoryId: 1, isPrivate: false }],
    };

    await applyForgeEvent(event, deps());
    await applyForgeEvent(event, deps());

    const count = await db.withTenant(fixture.providerId, async (client) => {
      const { rows } = await client.query<{ count: string }>(
        "SELECT count(*)::text AS count FROM repository WHERE forge_name = $1",
        ["svc"],
      );
      return Number(rows[0]!.count);
    });
    expect(count).toBe(1);
  });

  it("un-archives a repository the customer re-grants", async () => {
    // The customer re-inviting us must not require a support ticket to take
    // effect. The audit trail of the first grant stays where it was.
    const fixture = await seedProvider(`wh-regrant-${Date.now()}`);
    const installationId = await forgeIdFor(fixture);

    await applyForgeEvent(
      {
        type: "repositories.removed",
        installationId,
        repositories: [{ owner: `${fixture.slug}-consumer`, name: "widgets" }],
      },
      deps(),
    );
    await applyForgeEvent(
      {
        type: "repositories.added",
        installationId,
        repositories: [
          {
            owner: `${fixture.slug}-consumer`,
            name: "widgets",
            forgeRepositoryId: 4242,
            isPrivate: true,
          },
        ],
      },
      deps(),
    );

    const archivedAt = await db.withTenant(fixture.providerId, async (client) => {
      const { rows } = await client.query<{ archived_at: string | null }>(
        "SELECT archived_at FROM repository WHERE id = $1",
        [fixture.repositoryId],
      );
      return rows[0]!.archived_at;
    });
    expect(archivedAt).toBeNull();
  });

  it("does not record repositories for an installation belonging to someone else", async () => {
    // The tenant comes from resolving the installation, never from the
    // payload. An event naming another provider's installation must not write
    // into this one.
    const mine = await seedProvider(`wh-add-mine-${Date.now()}`);
    const theirs = await seedProvider(`wh-add-theirs-${Date.now()}`);
    const theirInstallation = await forgeIdFor(theirs);

    await applyForgeEvent(
      {
        type: "repositories.added",
        installationId: theirInstallation,
        repositories: [{ owner: "acme", name: "leaked", forgeRepositoryId: 55, isPrivate: true }],
      },
      deps(),
    );

    const count = await db.withTenant(mine.providerId, async (client) => {
      const { rows } = await client.query<{ count: string }>(
        "SELECT count(*)::text AS count FROM repository WHERE forge_name = $1",
        ["leaked"],
      );
      return Number(rows[0]!.count);
    });
    expect(count).toBe(0);
  });
});

describe("repositories withdrawn", () => {
  it("archives rather than deletes", async () => {
    // Deleting would orphan the outbound_write records that prove what we did
    // there while we had access.
    const fixture = await seedProvider("wh-removed");
    const installationId = await forgeIdFor(fixture);

    const result = await applyForgeEvent(
      {
        type: "repositories.removed",
        installationId,
        repositories: [{ owner: `${fixture.slug}-consumer`, name: "widgets" }],
      },
      deps(),
    );

    expect(result.applied).toBe(true);
    const { rows } = await db.withTenant(fixture.providerId, (client) =>
      client.query<{ archived_at: string | null }>(
        "SELECT archived_at FROM repository WHERE id = $1",
        [fixture.repositoryId],
      ),
    );
    expect(rows[0]?.archived_at).not.toBeNull();
  });

  it("leaves repositories that were not withdrawn alone", async () => {
    const fixture = await seedProvider("wh-removed-other");
    const installationId = await forgeIdFor(fixture);

    await applyForgeEvent(
      {
        type: "repositories.removed",
        installationId,
        repositories: [{ owner: `${fixture.slug}-consumer`, name: "something-else" }],
      },
      deps(),
    );

    const { rows } = await db.withTenant(fixture.providerId, (client) =>
      client.query<{ archived_at: string | null }>(
        "SELECT archived_at FROM repository WHERE id = $1",
        [fixture.repositoryId],
      ),
    );
    expect(rows[0]?.archived_at).toBeNull();
  });
});

describe("pull request outcomes", () => {
  async function seedWrite(fixture: Fixture, prNumber: number): Promise<void> {
    await db.withTenant(fixture.providerId, async (client) => {
      const claim = await client.query<{ write_id: string }>(
        "SELECT * FROM claim_outbound_write($1, $2, $3, $4, $5)",
        [
          fixture.providerId,
          fixture.installationId,
          fixture.repositoryId,
          fixture.changeId,
          "a".repeat(40),
        ],
      );
      await client.query(
        "SELECT resolve_outbound_write($1, 'succeeded', $2, $3, NULL)",
        [claim.rows[0]!.write_id, prNumber, `https://example/pr/${prNumber}`],
      );
    });
  }

  it("records a merge against the write that produced it", async () => {
    const fixture = await seedProvider("wh-merged");
    const installationId = await forgeIdFor(fixture);
    await seedWrite(fixture, 42);

    const result = await applyForgeEvent(
      {
        type: "pull_request.closed",
        installationId,
        repository: { owner: `${fixture.slug}-consumer`, name: "widgets" },
        number: 42,
        merged: true,
      },
      deps(),
    );

    expect(result.applied).toBe(true);
    const { rows } = await db.withTenant(fixture.providerId, (client) =>
      client.query<{ pr_outcome: string }>("SELECT pr_outcome FROM outbound_write"),
    );
    expect(rows[0]?.pr_outcome).toBe("merged");
  });

  it("records a close without merge distinctly from no outcome", async () => {
    // "We have not heard" and "closed without merging" are different facts.
    // Collapsing them would quietly flatter the merge rate.
    const fixture = await seedProvider("wh-closed");
    const installationId = await forgeIdFor(fixture);
    await seedWrite(fixture, 7);

    await applyForgeEvent(
      {
        type: "pull_request.closed",
        installationId,
        repository: { owner: `${fixture.slug}-consumer`, name: "widgets" },
        number: 7,
        merged: false,
      },
      deps(),
    );

    const { rows } = await db.withTenant(fixture.providerId, (client) =>
      client.query<{ pr_outcome: string | null }>("SELECT pr_outcome FROM outbound_write"),
    );
    expect(rows[0]?.pr_outcome).toBe("closed");
  });

  it("ignores an outcome for a pull request we did not open", async () => {
    const fixture = await seedProvider("wh-foreign-pr");
    const installationId = await forgeIdFor(fixture);

    const result = await applyForgeEvent(
      {
        type: "pull_request.closed",
        installationId,
        repository: { owner: `${fixture.slug}-consumer`, name: "widgets" },
        number: 999,
        merged: true,
      },
      deps(),
    );
    expect(result.applied).toBe(false);
  });
});

describe("tenant resolution", () => {
  it("does not let the platform role read the installation table", async () => {
    await expect(
      db.withPlatformContext("attempted direct read", (client) =>
        client.query("SELECT * FROM installation"),
      ),
    ).rejects.toThrow(/permission denied/i);
  });

  it("returns only a provider id", async () => {
    const fixture = await seedProvider("wh-disclosure");
    const installationId = await forgeIdFor(fixture);

    const { rows } = await db.withPlatformContext("lookup", (client) =>
      client.query<Record<string, unknown>>(
        "SELECT provider_for_installation($1) AS provider_id",
        [installationId],
      ),
    );
    expect(rows[0]?.["provider_id"]).toBe(fixture.providerId);
    expect(Object.keys(rows[0] ?? {})).toEqual(["provider_id"]);
  });
});

describe("delivery claims", () => {
  it("claims a delivery exactly once", async () => {
    const id = "aaaaaaaa-1111-2222-3333-444444444444";
    const claim = async (): Promise<boolean> =>
      db.withPlatformContext("claim", async (client) => {
        const { rows } = await client.query<{ claim_webhook_delivery: boolean }>(
          "SELECT claim_webhook_delivery($1, $2)",
          [id, "installation"],
        );
        return rows[0]!.claim_webhook_delivery;
      });

    expect(await claim()).toBe(true);
    expect(await claim()).toBe(false);
  });

  it("resolves concurrent claims to a single winner", async () => {
    // GitHub retries can overlap. A SELECT-then-INSERT would let two
    // concurrent deliveries both conclude they were first.
    const id = "bbbbbbbb-1111-2222-3333-444444444444";
    const results = await Promise.all(
      Array.from({ length: 10 }, () =>
        db.withPlatformContext("claim", async (client) => {
          const { rows } = await client.query<{ claim_webhook_delivery: boolean }>(
            "SELECT claim_webhook_delivery($1, NULL)",
            [id],
          );
          return rows[0]!.claim_webhook_delivery;
        }),
      ),
    );
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it("stores no payload", async () => {
    // A delivery record must never become a copy of customer data.
    const { rows } = await db.withPlatformContext("columns", (client) =>
      client.query<{ column_name: string }>(
        `SELECT column_name FROM information_schema.columns
          WHERE table_name = 'webhook_delivery' ORDER BY column_name`,
      ),
    );
    const columns = rows.map((r) => r.column_name);
    expect(columns).toEqual(["delivery_id", "event_type", "outcome", "received_at"]);
  });
});
