import { beforeAll, describe, expect, it } from "vitest";
import { ADMIN_URL, adminClient, prepareDatabase, seedProvider } from "../db/setup.ts";
import { approveChange, listPending } from "../../scripts/approve-change.ts";

/**
 * The approval gate.
 *
 * plan-rollout refuses to fan out a change whose approved_at is null, and
 * migration 010 built the scheduler that watches for approvals — but nothing
 * ever set the column, so every detected change sat at the gate forever.
 * These cover the operator path that opens it, and the attribution that has to
 * survive it.
 */

beforeAll(async () => {
  await prepareDatabase();
});

async function seedChange(slug: string, changeKey: string): Promise<string> {
  const fixture = await seedProvider(slug);
  const client = await adminClient();
  try {
    await client.query(
      `INSERT INTO upstream_change
              (provider_id, change_key, ecosystem, package_name,
               from_version, to_version, summary, corroborations, impacted_symbols)
            VALUES ($1, $2, 'npm', 'react', '18.2.0', '19.0.0', 'removed defaultProps',
                    '[{"source":"changelog"}]'::jsonb, ARRAY['defaultProps'])`,
      [fixture.providerId, changeKey],
    );
  } finally {
    await client.end();
  }
  return fixture.providerId;
}

async function approvalOf(changeKey: string) {
  const client = await adminClient();
  try {
    const { rows } = await client.query<{ approved_at: string | null; approved_by: string | null }>(
      "SELECT approved_at, approved_by FROM upstream_change WHERE change_key = $1",
      [changeKey],
    );
    return rows[0];
  } finally {
    await client.end();
  }
}

describe("approving across tenants", () => {
  it("never approves another provider's change with the same key", async () => {
    // change_key is unique per provider, not globally — two tenants watching
    // react both hold react@19.2.8. Matching on the key alone approved every
    // one of them at once: an operator authorising a fan-out across tenants
    // who never asked for it, recorded against their name.
    await seedChange("tenant-a", "shared@1.0.0");
    await seedChange("tenant-b", "shared@1.0.0");

    await expect(
      approveChange(ADMIN_URL, "shared@1.0.0", "oliver"),
    ).rejects.toThrow(/matches 2 providers/);

    const client = await adminClient();
    try {
      const { rows } = await client.query<{ count: string }>(
        "SELECT count(*) FROM upstream_change WHERE change_key = $1 AND approved_at IS NOT NULL",
        ["shared@1.0.0"],
      );
      // The refusal has to be total. A partial approval would be worse than
      // the bug: one tenant rolled out, and nobody told to look.
      expect(Number(rows[0]!.count)).toBe(0);
    } finally {
      await client.end();
    }
  });

  it("approves exactly the named provider's row when disambiguated", async () => {
    await seedChange("tenant-c", "picked@2.0.0");
    await seedChange("tenant-d", "picked@2.0.0");

    const result = await approveChange(ADMIN_URL, "picked@2.0.0", "oliver", "tenant-c");
    expect(result.providerSlug).toBe("tenant-c");

    const client = await adminClient();
    try {
      const { rows } = await client.query<{ slug: string; approved_by: string | null }>(
        `SELECT p.slug, c.approved_by
           FROM upstream_change c JOIN provider p ON p.id = c.provider_id
          WHERE c.change_key = $1 ORDER BY p.slug`,
        ["picked@2.0.0"],
      );
      expect(rows).toEqual([
        { slug: "tenant-c", approved_by: "oliver" },
        { slug: "tenant-d", approved_by: null },
      ]);
    } finally {
      await client.end();
    }
  });
});

describe("approving a change", () => {
  it("records who approved it, not just that it was approved", async () => {
    // "Who decided to touch a thousand repositories" is the first question
    // asked afterwards.
    await seedChange("approve-basic", "react-19-defaultprops");

    await approveChange(ADMIN_URL, "react-19-defaultprops", "alice");

    const approval = await approvalOf("react-19-defaultprops");
    expect(approval?.approved_at).not.toBeNull();
    expect(approval?.approved_by).toBe("alice");
  });

  it("leaves the original approver in place on a second approval", async () => {
    // A re-run must not quietly relabel who authorised a rollout that has
    // already happened.
    await seedChange("approve-twice", "react-19-twice");
    await approveChange(ADMIN_URL, "react-19-twice", "alice");

    const result = await approveChange(ADMIN_URL, "react-19-twice", "mallory");

    expect(result.alreadyApproved).toBe(true);
    expect((await approvalOf("react-19-twice"))?.approved_by).toBe("alice");
  });

  it("refuses a change key that does not exist", async () => {
    await expect(approveChange(ADMIN_URL, "no-such-change", "alice")).rejects.toThrow(
      /no change with key/,
    );
  });

  it("lists what is waiting, and stops listing it once approved", async () => {
    await seedChange("approve-list", "react-19-listed");

    const before = await listPending(ADMIN_URL);
    expect(before.map((c) => c.changeKey)).toContain("react-19-listed");
    const listed = before.find((c) => c.changeKey === "react-19-listed");
    expect(listed).toMatchObject({
      packageName: "react",
      fromVersion: "18.2.0",
      toVersion: "19.0.0",
      corroborations: 1,
      impactedSymbols: 1,
    });

    await approveChange(ADMIN_URL, "react-19-listed", "alice");

    const after = await listPending(ADMIN_URL);
    expect(after.map((c) => c.changeKey)).not.toContain("react-19-listed");
  });
});
