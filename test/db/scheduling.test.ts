import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { adminClient, prepareDatabase, seedProvider, workerDatabase, type Fixture } from "./setup.ts";
import type { Database } from "../../src/db/client.ts";
import { PostgresSweepStore } from "../../src/schedule/sweep-scheduler.ts";

/**
 * Scheduling (migration 007).
 *
 * The claim lives in the database rather than in a scheduler process, so this
 * is where it has to be tested. Two schedulers, or one scheduler either side
 * of a deploy, must not both decide a package is due — and an in-process test
 * double cannot demonstrate that.
 */

let db: Database;
let tenant: Fixture;
let other: Fixture;

beforeAll(async () => {
  await prepareDatabase();
  db = workerDatabase();
  tenant = await seedProvider("sched");
  other = await seedProvider("sched-other");
});

afterAll(async () => {
  await db?.close();
});

async function watch(
  fixture: Fixture,
  packageName: string,
  options: { intervalSeconds?: number; lastSweptAt?: Date | null; enabled?: boolean } = {},
): Promise<void> {
  const client = await adminClient();
  try {
    await client.query(
      `INSERT INTO watched_package
         (provider_id, ecosystem, package_name, baseline_version,
          sweep_interval_seconds, last_swept_at, enabled)
       VALUES ($1, 'npm', $2, '1.0.0', $3, $4, $5)`,
      [
        fixture.providerId,
        packageName,
        options.intervalSeconds ?? 3600,
        options.lastSweptAt ?? null,
        options.enabled ?? true,
      ],
    );
  } finally {
    await client.end();
  }
}

const NOW = new Date("2026-08-14T12:00:00Z");

describe("claiming due sweeps", () => {
  it("claims a package that has never been swept", async () => {
    await watch(tenant, "never-swept");
    const store = new PostgresSweepStore(db);

    const claimed = await store.claimDue(50, NOW);
    expect(claimed.map((c) => c.packageName)).toContain("never-swept");
  });

  it("does not claim the same package twice inside its interval", async () => {
    // The property the whole design exists for: a second scheduler, or the
    // same one after a restart, must see nothing due.
    await watch(tenant, "interval-respected", { intervalSeconds: 3600 });
    const store = new PostgresSweepStore(db);

    const first = await store.claimDue(50, NOW);
    expect(first.map((c) => c.packageName)).toContain("interval-respected");

    const second = await store.claimDue(50, new Date(NOW.getTime() + 60_000));
    expect(second.map((c) => c.packageName)).not.toContain("interval-respected");
  });

  it("claims it again once the interval has elapsed", async () => {
    await watch(tenant, "recurs", { intervalSeconds: 3600 });
    const store = new PostgresSweepStore(db);

    await store.claimDue(50, NOW);
    const later = await store.claimDue(50, new Date(NOW.getTime() + 3_600_001));
    expect(later.map((c) => c.packageName)).toContain("recurs");
  });

  it("never claims a disabled package", async () => {
    // Pausing must not lose the baseline, so it is a flag rather than a
    // delete — and the flag has to actually be honoured.
    await watch(tenant, "paused", { enabled: false });
    const claimed = await new PostgresSweepStore(db).claimDue(50, NOW);
    expect(claimed.map((c) => c.packageName)).not.toContain("paused");
  });

  it("returns the baseline the sweep compares against", async () => {
    await watch(tenant, "with-baseline");
    const claimed = await new PostgresSweepStore(db).claimDue(50, NOW);
    const found = claimed.find((c) => c.packageName === "with-baseline");
    expect(found?.baselineVersion).toBe("1.0.0");
    expect(found?.providerId).toBe(tenant.providerId);
  });

  it("honours the limit", async () => {
    await watch(tenant, "limited-a");
    await watch(tenant, "limited-b");
    await watch(tenant, "limited-c");
    const claimed = await new PostgresSweepStore(db).claimDue(2, NOW);
    expect(claimed.length).toBeLessThanOrEqual(2);
  });

  it("crosses tenants, because the scheduler serves all of them", async () => {
    await watch(tenant, "cross-tenant-a");
    await watch(other, "cross-tenant-b");
    const claimed = await new PostgresSweepStore(db).claimDue(50, NOW);
    const providers = new Set(claimed.map((c) => c.providerId));
    expect(providers.size).toBeGreaterThan(1);
  });
});

describe("tenant isolation", () => {
  it("shows a provider only its own watched packages", async () => {
    await watch(tenant, "mine-only");
    await watch(other, "theirs-only");

    const rows = await db.withTenant(tenant.providerId, (client) =>
      client.query<{ package_name: string }>("SELECT package_name FROM watched_package"),
    );
    const names = rows.rows.map((r) => r.package_name);
    expect(names).toContain("mine-only");
    expect(names).not.toContain("theirs-only");
  });

  it("refuses to write a row into another provider's tenant", async () => {
    // The WITH CHECK half of the policy. Without it, a provider can read only
    // its own rows but write into anyone's.
    await expect(
      db.withTenant(tenant.providerId, (client) =>
        client.query(
          `INSERT INTO watched_package (provider_id, ecosystem, package_name, baseline_version)
           VALUES ($1, 'npm', 'smuggled', '1.0.0')`,
          [other.providerId],
        ),
      ),
    ).rejects.toThrow(/row-level security/i);
  });

  it("does not let the platform role read the table directly", async () => {
    // Which packages a provider watches is competitive information. The
    // scheduler gets a minimal-disclosure function instead of a grant — the
    // same shape as migration 005's opt-out lookup.
    await expect(
      db.withPlatformContext("test: direct read", (client) =>
        client.query("SELECT * FROM watched_package"),
      ),
    ).rejects.toThrow(/permission denied/i);
  });
});

describe("upstream_change.impacted_symbols", () => {
  it("round-trips the symbols the blast radius is derived from", async () => {
    // Dropped on the way to the database, this produces an empty blast radius
    // and a migration that refuses itself for a reason that reads like
    // "nothing references this package".
    const changeKey = `${tenant.slug}-symbols`;
    await db.withTenant(tenant.providerId, (client) =>
      client.query(
        `INSERT INTO upstream_change
           (provider_id, change_key, ecosystem, package_name, summary, impacted_symbols)
         VALUES ($1, $2, 'npm', 'acme-sdk', 'v3', $3)`,
        [tenant.providerId, changeKey, ["createClient", "AcmeOptions"]],
      ),
    );

    const { rows } = await db.withTenant(tenant.providerId, (client) =>
      client.query<{ impacted_symbols: string[] }>(
        "SELECT impacted_symbols FROM upstream_change WHERE change_key = $1",
        [changeKey],
      ),
    );
    expect(rows[0]?.impacted_symbols).toEqual(["createClient", "AcmeOptions"]);
  });

  it("defaults to empty rather than null", async () => {
    // An empty set means "no migration is possible", which is safe. A null
    // would mean "unknown", and the difference would have to be handled at
    // every read site.
    const { rows } = await db.withTenant(tenant.providerId, (client) =>
      client.query<{ impacted_symbols: string[] }>(
        "SELECT impacted_symbols FROM upstream_change WHERE id = $1",
        [tenant.changeId],
      ),
    );
    expect(rows[0]?.impacted_symbols).toEqual([]);
  });
});
