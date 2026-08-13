-- 006 — Webhook deliveries
--
-- Two things the webhook endpoint needs that live outside any tenant.
--
-- Deduplication. GitHub retries deliveries, so the same event arrives more
-- than once. A replayed `installation.created` that re-enabled a revoked
-- installation would be a security incident rather than a duplicate-processing
-- annoyance, so the claim has to be atomic and durable rather than an in-memory
-- set that resets on deploy.
--
-- Tenant resolution. A webhook arrives with a forge installation id and
-- nothing else. There is no session to derive tenant context from, so the
-- installation must be resolved to a provider before any tenant-scoped work
-- can happen — the same chicken-and-egg as the opt-out endpoint in 005, and
-- solved the same way: a minimal-disclosure function rather than a grant.

CREATE TABLE webhook_delivery (
  delivery_id   text PRIMARY KEY,
  event_type    text,
  received_at   timestamptz NOT NULL DEFAULT now(),
  -- What we decided. Kept for incident review: "did we receive the uninstall?"
  -- is a question worth being able to answer precisely.
  outcome       text,

  CONSTRAINT webhook_delivery_id_shape CHECK (delivery_id ~ '^[0-9a-fA-F-]{8,64}$')
);

-- Deliveries are platform state, not tenant state: at claim time we do not yet
-- know which tenant an event belongs to. Deliberately NOT tenant-scoped, and
-- deliberately holding no payload — a delivery record should never become a
-- copy of customer data.
COMMENT ON TABLE webhook_delivery IS
  'Delivery dedupe. Platform-scoped by necessity; holds no payload.';

CREATE INDEX webhook_delivery_received_idx ON webhook_delivery (received_at);

/**
 * Atomically claims a delivery.
 *
 * Returns true if this caller now owns it, false if it was already claimed.
 * The uniqueness of the primary key is what makes the claim exclusive — a
 * SELECT-then-INSERT would let two concurrent retries both conclude they were
 * first.
 */
CREATE FUNCTION claim_webhook_delivery(
  p_delivery_id text,
  p_event_type  text DEFAULT NULL
)
RETURNS boolean
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO webhook_delivery (delivery_id, event_type)
  VALUES (p_delivery_id, p_event_type)
  ON CONFLICT (delivery_id) DO NOTHING;

  RETURN FOUND;
END;
$$;

-- ---------------------------------------------------------------------------
-- Resolving an installation to its tenant
--
-- Same reasoning as provider_for_opt_out_token in 005. A table-wide SELECT for
-- the platform role would expose every provider's installation list; a
-- function that takes a forge installation id and returns only a provider id
-- discloses exactly what the requirement needs and nothing else.
-- ---------------------------------------------------------------------------

CREATE FUNCTION provider_for_installation(p_forge_installation_id bigint)
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT provider_id
    FROM installation
   WHERE forge_installation_id = p_forge_installation_id
   LIMIT 1;
$$;

COMMENT ON FUNCTION provider_for_installation IS
  'Minimal-disclosure tenant resolution for webhook ingestion. Returns only a '
  'provider id. See migration 006.';

REVOKE ALL ON FUNCTION provider_for_installation FROM PUBLIC;
GRANT EXECUTE ON FUNCTION provider_for_installation TO driftless_admin;

GRANT SELECT, INSERT ON webhook_delivery TO driftless_admin;
GRANT EXECUTE ON FUNCTION claim_webhook_delivery TO driftless_admin;

-- ---------------------------------------------------------------------------
-- Pull request outcomes
--
-- Merged versus closed-unmerged is the only real quality signal this system
-- receives, and merge rate is the metric the product is judged on. Recorded
-- against the outbound write that produced the pull request, so the evidence
-- sits with the action rather than being reconstructed later.
--
-- Deliberately nullable and deliberately not defaulted: "we have not heard"
-- and "closed without merging" are very different facts, and collapsing them
-- would quietly flatter the numbers.
-- ---------------------------------------------------------------------------

CREATE TYPE pr_outcome AS ENUM ('merged', 'closed');

ALTER TABLE outbound_write
  ADD COLUMN pr_outcome    pr_outcome,
  ADD COLUMN pr_outcome_at timestamptz;

CREATE INDEX outbound_write_outcome_idx
  ON outbound_write (provider_id, pr_outcome)
  WHERE pr_outcome IS NOT NULL;

COMMENT ON COLUMN outbound_write.pr_outcome IS
  'NULL means no outcome observed yet — not the same as closed. See migration 006.';
