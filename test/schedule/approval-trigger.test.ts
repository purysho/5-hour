import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  ApprovalTrigger,
  PostgresApprovalStore,
  rolloutDedupeKey,
  type ApprovalQueue,
  type ApprovalStore,
  type ApprovedChange,
} from "../../src/schedule/approval-trigger.ts";
import { adminClient, prepareDatabase, seedProvider, workerDatabase } from "../db/setup.ts";
import type { Database } from "../../src/db/client.ts";

/**
 * The link between a human approving and the system acting.
 *
 * Approval is the only reason fan-out is safe to automate, so the properties
 * that matter here are about restraint: exactly one rollout per approval, and
 * nothing at all for a change nobody approved.
 */

interface Enqueued {
  providerId: string;
  workflow: string;
  input: Record<string, unknown>;
  dedupeKey: string | undefined;
}

function stubQueue(behaviour: { created?: boolean; throws?: boolean } = {}): {
  queue: ApprovalQueue;
  enqueued: Enqueued[];
} {
  const enqueued: Enqueued[] = [];
  const seen = new Set<string>();
  const queue: ApprovalQueue = {
    async enqueue(providerId, workflow, input, options) {
      if (behaviour.throws) throw new Error("queue unavailable");
      enqueued.push({ providerId, workflow, input, dedupeKey: options?.dedupeKey });
      const key = options?.dedupeKey ?? "";
      const created = behaviour.created ?? !seen.has(key);
      seen.add(key);
      return { jobId: "job-1", created };
    },
  };
  return { queue, enqueued };
}

function stubStore(changes: readonly ApprovedChange[]): ApprovalStore {
  return { async awaitingRollout(limit) { return changes.slice(0, limit); } };
}

describe("enqueuing a rollout", () => {
  it("enqueues plan-rollout for an approved change", async () => {
    const { queue, enqueued } = stubQueue();
    const trigger = new ApprovalTrigger({
      store: stubStore([{ providerId: "p1", changeId: "c1" }]),
      queue,
    });

    const result = await trigger.tick();

    expect(result).toMatchObject({ found: 1, enqueued: 1, duplicate: 0 });
    expect(enqueued[0]).toMatchObject({
      workflow: "plan-rollout",
      input: { changeId: "c1" },
      dedupeKey: "rollout:c1",
    });
  });

  it("uses a dedupe key with no time bucket, so one approval means one rollout", async () => {
    // The opposite of the sweep scheduler, deliberately. There, an unbucketed
    // key would make the first sweep of a package the last one forever; here
    // that is exactly the property we want.
    expect(rolloutDedupeKey("c1")).toBe("rollout:c1");
    expect(rolloutDedupeKey("c1")).not.toContain(String(Date.now()).slice(0, 5));
  });

  it("does not enqueue a second rollout on the next tick", async () => {
    const { queue } = stubQueue();
    const trigger = new ApprovalTrigger({
      store: stubStore([{ providerId: "p1", changeId: "c1" }]),
      queue,
    });

    await trigger.tick();
    const second = await trigger.tick();

    expect(second).toMatchObject({ enqueued: 0, duplicate: 1 });
  });

  it("does not let one tenant's failure cost another its rollout", async () => {
    let calls = 0;
    const queue: ApprovalQueue = {
      async enqueue(providerId) {
        calls += 1;
        if (providerId === "p1") throw new Error("queue unavailable");
        return { jobId: "job", created: true };
      },
    };
    const trigger = new ApprovalTrigger({
      store: stubStore([
        { providerId: "p1", changeId: "c1" },
        { providerId: "p2", changeId: "c2" },
      ]),
      queue,
    });

    const result = await trigger.tick();

    expect(calls).toBe(2);
    expect(result).toMatchObject({ found: 2, enqueued: 1, failed: 1 });
  });

  it("bounds the burst a batch approval produces", async () => {
    const changes = Array.from({ length: 100 }, (_, i) => ({
      providerId: "p1",
      changeId: `c${i}`,
    }));
    const { queue, enqueued } = stubQueue();
    const trigger = new ApprovalTrigger({ store: stubStore(changes), queue, batchSize: 5 });

    await trigger.tick();
    expect(enqueued).toHaveLength(5);
  });
});

describe("against the database", () => {
  let db: Database;

  beforeAll(async () => {
    await prepareDatabase();
    db = workerDatabase();
  });

  afterAll(async () => {
    await db?.close();
  });

  async function approve(changeId: string): Promise<void> {
    const client = await adminClient();
    try {
      await client.query("UPDATE upstream_change SET approved_at = now() WHERE id = $1", [changeId]);
    } finally {
      await client.end();
    }
  }

  it("finds nothing for a change nobody approved", async () => {
    // The gate. `detect-changes` never self-approves, so an unapproved change
    // must be invisible to this scan — otherwise a detection bug becomes a
    // fan-out incident with no human in between.
    const fixture = await seedProvider(`approval-none-${Date.now()}`);
    const store = new PostgresApprovalStore(db);

    const found = await store.awaitingRollout(100);
    expect(found.some((change) => change.changeId === fixture.changeId)).toBe(false);
  });

  it("finds an approved change", async () => {
    const fixture = await seedProvider(`approval-yes-${Date.now()}`);
    await approve(fixture.changeId);

    const found = await new PostgresApprovalStore(db).awaitingRollout(100);
    const match = found.find((change) => change.changeId === fixture.changeId);

    expect(match).toBeDefined();
    expect(match?.providerId).toBe(fixture.providerId);
  });

  it("stops finding it once a rollout is queued", async () => {
    // The scan is a predicate, not a cursor: it asks "approved and not yet
    // rolled out". That is what makes a crashed tick recoverable and a
    // completed one final.
    const fixture = await seedProvider(`approval-queued-${Date.now()}`);
    await approve(fixture.changeId);

    const store = new PostgresApprovalStore(db);
    const { queue } = stubQueue();
    const trigger = new ApprovalTrigger({ store, queue });
    await trigger.tick();

    // Real enqueue, so the job row the predicate looks for actually exists.
    await db.withTenant(fixture.providerId, (client) =>
      client.query("SELECT enqueue_job($1, $2, $3::jsonb, $4)", [
        fixture.providerId,
        "plan-rollout",
        JSON.stringify({ changeId: fixture.changeId }),
        rolloutDedupeKey(fixture.changeId),
      ]),
    );

    const found = await store.awaitingRollout(100);
    expect(found.some((change) => change.changeId === fixture.changeId)).toBe(false);
  });

  it("discloses only what enqueueing needs", async () => {
    // A cross-tenant read. The scheduler has no business knowing which package
    // a provider is watching, so the function returns two ids and nothing else.
    const fixture = await seedProvider(`approval-minimal-${Date.now()}`);
    await approve(fixture.changeId);

    const found = await new PostgresApprovalStore(db).awaitingRollout(100);
    const match = found.find((change) => change.changeId === fixture.changeId);

    expect(Object.keys(match ?? {}).sort()).toEqual(["changeId", "providerId"]);
  });
});
