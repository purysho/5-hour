/**
 * Turning a paid checkout into a live tenant.
 *
 * This runs as `driftless_billing`, a role that exists only to call
 * `provision_subscription` and claim webhook deliveries. It is deliberately
 * not the application role and deliberately not the platform role — see
 * migration 012 and non-negotiable 10 in docs/HANDOFF.md. Postgres ORs
 * together the policies of every role you hold, so a connection that carried
 * billing *and* application rights would silently gain cross-tenant
 * visibility, with no error and nothing to notice in review.
 *
 * A separate pool rather than a method on `Database` for the same reason:
 * `Database` exists to make the app/platform split hard to get wrong, and
 * adding a third mode to it would put all three sets of rights behind one
 * object where a mistaken call site is a one-word typo.
 */

import pg from "pg";
import { Secret } from "../config.ts";
import type { Plan } from "./plans.ts";

export interface ProvisionRequest {
  readonly slug: string;
  readonly displayName: string;
  readonly stripeCustomerId: string;
  readonly stripeSubscriptionId: string;
  readonly status: string;
  readonly plan: Plan;
  readonly currentPeriodEnd: Date | null;
  readonly cancelAtPeriodEnd: boolean;
  /**
   * SHA-256 of the checkout reference, or null.
   *
   * Only `checkout.session.completed` carries one — it is the event Stripe
   * echoes `client_reference_id` back on. Subscription events pass null, and
   * the function keeps whichever reference arrived first.
   */
  readonly enrolmentRefHash: string | null;
}

export interface ProvisionResult {
  readonly providerId: string;
  /** True only on the checkout that created the tenant. Gates the welcome path. */
  readonly created: boolean;
}

export interface BillingStore {
  provision(request: ProvisionRequest): Promise<ProvisionResult>;
  /**
   * Claims a Stripe event id. False means another delivery already has it.
   *
   * The claim is the primary key, so concurrency is resolved by Postgres
   * rather than by a read-then-write in application code that two workers can
   * interleave.
   */
  claimEvent(eventId: string, eventType: string): Promise<boolean>;
  /**
   * Releases a claim whose processing failed.
   *
   * Without this, a transient failure during provisioning is permanent: the
   * claim survives, Stripe's retry is dismissed as a duplicate, and a paying
   * customer is never provisioned while Stripe is told the delivery succeeded.
   */
  releaseEvent(eventId: string): Promise<void>;
  close(): Promise<void>;
}

/**
 * A slug derived from the customer's own details.
 *
 * Slugs are visible in operator tooling and in `DEFAULT_PROVIDER_SLUG`, so
 * they need to be readable, and they need to be stable for the same customer.
 * They are not a security boundary — `provision_subscription` resolves an
 * existing tenant by subscription id first, precisely so that a colliding slug
 * cannot adopt another tenant's rows.
 */
export function slugFor(email: string | null, stripeCustomerId: string): string {
  const local = (email ?? "").split("@")[0] ?? "";
  const cleaned = local
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 24);

  // The customer id suffix makes collisions impossible in practice while
  // keeping the readable part readable. Two customers called "ops@" do not
  // fight over one slug.
  const suffix = stripeCustomerId.replace(/^cus_/, "").toLowerCase().slice(0, 8);
  return cleaned === "" ? `tenant-${suffix}` : `${cleaned}-${suffix}`;
}

export function createBillingStore(connectionString: Secret, max = 2): BillingStore {
  const pool = new pg.Pool({
    connectionString: Secret.reveal(connectionString),
    max,
    // Short: this pool serves a webhook handler that must answer Stripe
    // quickly, and a billing connection held open is a connection holding
    // tenant-creation rights.
    idleTimeoutMillis: 10_000,
    connectionTimeoutMillis: 5_000,
  });

  return {
    async provision(request) {
      const client = await pool.connect();
      try {
        const { rows } = await client.query<{ provider_id: string; created: boolean }>(
          `SELECT provisioned_provider_id AS provider_id, was_created AS created
             FROM provision_subscription($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
          [
            request.slug,
            request.displayName,
            request.stripeCustomerId,
            request.stripeSubscriptionId,
            request.status,
            request.plan.id,
            request.plan.repositoryLimit,
            request.currentPeriodEnd,
            request.cancelAtPeriodEnd,
            request.enrolmentRefHash,
          ],
        );
        const row = rows[0];
        if (!row) throw new Error("provision_subscription returned no row");
        return { providerId: row.provider_id, created: row.created };
      } finally {
        client.release();
      }
    },

    async claimEvent(eventId, eventType) {
      const client = await pool.connect();
      try {
        const { rowCount } = await client.query(
          `INSERT INTO billing_event (event_id, event_type)
                VALUES ($1, $2)
           ON CONFLICT (event_id) DO NOTHING`,
          [eventId, eventType],
        );
        return rowCount === 1;
      } finally {
        client.release();
      }
    },

    async releaseEvent(eventId) {
      const client = await pool.connect();
      try {
        await client.query("DELETE FROM billing_event WHERE event_id = $1", [eventId]);
      } finally {
        client.release();
      }
    },

    async close() {
      await pool.end();
    },
  };
}
