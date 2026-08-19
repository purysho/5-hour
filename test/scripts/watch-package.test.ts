import { beforeAll, describe, expect, it } from "vitest";
import { ADMIN_URL, adminClient, prepareDatabase, seedProvider } from "../db/setup.ts";
import { watchPackage } from "../../scripts/watch-package.ts";

/**
 * Adding a package to the sweep list.
 *
 * The sweep scheduler is the only thing that starts the pipeline, and it reads
 * `watched_package`. Nothing outside the test suite ever wrote a row, so the
 * scheduler swept an empty list forever and no migration could be generated —
 * healthy-looking, and completely inert. These cover the operator path that
 * closes it.
 */

beforeAll(async () => {
  await prepareDatabase();
});

async function rowFor(providerId: string, packageName: string) {
  const client = await adminClient();
  try {
    const { rows } = await client.query<{
      baseline_version: string;
      sweep_interval_seconds: number;
      enabled: boolean;
      last_swept_at: string | null;
    }>(
      `SELECT baseline_version, sweep_interval_seconds, enabled, last_swept_at
         FROM watched_package WHERE provider_id = $1 AND package_name = $2`,
      [providerId, packageName],
    );
    return rows;
  } finally {
    await client.end();
  }
}

describe("watching a package", () => {
  it("records it against the provider, due for its first sweep", async () => {
    // last_swept_at NULL is what makes claim_due_sweeps pick it up on the very
    // next tick, rather than one interval from now.
    const fixture = await seedProvider("watch-new");

    await watchPackage(ADMIN_URL, "watch-new", "react", "18.2.0");

    expect(await rowFor(fixture.providerId, "react")).toEqual([
      {
        baseline_version: "18.2.0",
        sweep_interval_seconds: 3600,
        enabled: true,
        last_swept_at: null,
      },
    ]);
  });

  it("updates the baseline instead of adding a second row", async () => {
    const fixture = await seedProvider("watch-again");

    await watchPackage(ADMIN_URL, "watch-again", "react", "18.2.0");
    await watchPackage(ADMIN_URL, "watch-again", "react", "19.0.0", {
      sweepIntervalSeconds: 600,
    });

    expect(await rowFor(fixture.providerId, "react")).toEqual([
      {
        baseline_version: "19.0.0",
        sweep_interval_seconds: 600,
        enabled: true,
        last_swept_at: null,
      },
    ]);
  });

  it("re-enables a package that had been paused", async () => {
    // Pausing is a flag rather than a delete so the baseline survives it;
    // re-adding must therefore turn it back on.
    const fixture = await seedProvider("watch-paused");
    await watchPackage(ADMIN_URL, "watch-paused", "react", "18.2.0");

    const client = await adminClient();
    try {
      await client.query(
        "UPDATE watched_package SET enabled = false WHERE provider_id = $1",
        [fixture.providerId],
      );
    } finally {
      await client.end();
    }

    await watchPackage(ADMIN_URL, "watch-paused", "react", "18.2.0");

    expect((await rowFor(fixture.providerId, "react"))[0]?.enabled).toBe(true);
  });

  it("refuses a provider that does not exist", async () => {
    // The likely operator mistake is a slug that does not match
    // DEFAULT_PROVIDER_SLUG. Failing here beats a foreign key error.
    await expect(
      watchPackage(ADMIN_URL, "no-such-provider", "react", "18.2.0"),
    ).rejects.toThrow(/no provider with slug/);
  });
});
