-- 012 — Subscriptions, and the narrow door that creates a tenant
--
-- Migration 011 made an installed App able to find its tenant. It did not make
-- a tenant exist. Creating one is still `pnpm db:provider`, run by a human who
-- knows why — which is a correct security posture and an impossible business:
-- every customer who wants to pay has to wait for an operator to notice.
--
-- This migration closes that gap without reopening the boundary 001 exists to
-- defend.
--
-- ── Why the application role still cannot create a tenant ────────────────────
--
-- The policy on `provider` checks `id = app.current_provider_id()`. A row that
-- does not exist yet cannot satisfy it, so the application role cannot insert
-- one. That is not an oversight to work around; it is the property that makes
-- a compromised web process unable to manufacture tenants and read across the
-- boundary (ADR-0005).
--
-- The tempting fix is to grant the application role INSERT on `provider` and
-- move on. That silently converts an RLS-enforced boundary into an
-- application-enforced one — the exact failure mode ADR-0005 rejects, and one
-- with no visible symptom until someone is reading another customer's
-- repositories.
--
-- So provisioning goes through a SECURITY DEFINER function with a fixed
-- search_path, granted to a role that exists only for this purpose. The
-- function is the whole attack surface: it takes billing facts, and it can do
-- exactly one thing with them. It is the same shape as `provider_id_for_slug`
-- in 011, for the same reason.
--
-- ── Why a third role ────────────────────────────────────────────────────────
--
-- `driftless_billing` is neither `driftless_app` nor `driftless_admin`, and no
-- login role may hold it together with either. Non-negotiable 10 in
-- docs/HANDOFF.md explains the mechanism: Postgres ORs together every policy
-- for every role you are a member of, so combining roles grants cross-tenant
-- visibility with no error and nothing to see in review. Billing needs to
-- create tenants; it has no business reading their repositories.
--
-- ── Why redelivery converges ────────────────────────────────────────────────
--
-- Stripe redelivers. A webhook handler that is not idempotent creates a second
-- tenant for a customer who paid once, and the duplicate is invisible until
-- that customer's repositories are split across two tenants that cannot see
-- each other. The tenant is resolved from `stripe_subscription_id` before
-- anything is written, so redelivery lands on the row it already wrote.
--
-- ── Why the subscription upsert keys on the tenant, not the subscription ────
--
-- Because a customer who cancels and comes back is a customer. They arrive
-- with a *new* Stripe subscription id and the same email, so the slug resolves
-- to the tenant they already have — and an upsert keyed on the subscription id
-- would then try to insert a second subscription row for that tenant and hit
-- `subscription_one_per_provider`. The webhook would 500, Stripe would retry
-- until it disabled the endpoint, and someone who had just paid would never be
-- provisioned. Keying on `provider_id` makes the new subscription replace the
-- old one, which is what "one live subscription per tenant" means.

-- ---------------------------------------------------------------------------
-- The billing role
-- ---------------------------------------------------------------------------

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'driftless_billing') THEN
    CREATE ROLE driftless_billing NOLOGIN NOBYPASSRLS;
  END IF;
END
$$;

GRANT USAGE ON SCHEMA app, public TO driftless_billing;

-- ---------------------------------------------------------------------------
-- Subscription
-- ---------------------------------------------------------------------------

CREATE TABLE subscription (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id             uuid NOT NULL REFERENCES provider (id) ON DELETE CASCADE,

  -- Stripe's identifiers. Kept because reconciling a disputed charge against
  -- our own record is otherwise guesswork.
  stripe_customer_id      text NOT NULL,
  stripe_subscription_id  text NOT NULL UNIQUE,

  -- Stripe's own status string, stored verbatim rather than mapped to a local
  -- enum. A mapping has to be updated when Stripe adds a status, and the
  -- failure mode of a stale mapping is treating an unknown status as entitled.
  status                  text NOT NULL,

  plan                    text NOT NULL,
  repository_limit        integer NOT NULL CHECK (repository_limit > 0),

  current_period_end      timestamptz,
  cancel_at_period_end    boolean NOT NULL DEFAULT false,

  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now()
);

-- One live subscription per tenant. Two would make "is this tenant entitled?"
-- a question with two answers, and the entitlement check would have to pick.
CREATE UNIQUE INDEX subscription_one_per_provider ON subscription (provider_id);

CREATE INDEX subscription_customer ON subscription (stripe_customer_id);

ALTER TABLE subscription ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscription FORCE  ROW LEVEL SECURITY;

CREATE POLICY subscription_tenant_isolation ON subscription
  FOR ALL TO driftless_app
  USING (provider_id = app.current_provider_id())
  WITH CHECK (provider_id = app.current_provider_id());

-- SELECT only, deliberately. The application reads entitlement on every
-- outbound write; it must never be able to grant itself one. Writes come from
-- the billing role through the function below, which is reachable only from a
-- verified Stripe webhook.
GRANT SELECT ON subscription TO driftless_app;
GRANT SELECT ON subscription TO driftless_admin;

COMMENT ON TABLE subscription IS
  'Entitlement state, written only by the billing role via provision_subscription. '
  'The application role can read its own row and cannot write any. See migration 012.';

-- ---------------------------------------------------------------------------
-- Webhook delivery dedupe
--
-- Same reasoning as migration 006 for forge webhooks: the claim is a database
-- statement, so two workers processing a redelivered event produce one effect.
-- No provider_id column — the event arrives before the tenant it creates
-- exists, which is the whole point of it.
-- ---------------------------------------------------------------------------

CREATE TABLE billing_event (
  event_id     text PRIMARY KEY,
  event_type   text NOT NULL,
  received_at  timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT ON billing_event TO driftless_billing;

COMMENT ON TABLE billing_event IS
  'Processed Stripe event ids. Insert-only; the primary key is the replay claim.';

-- ---------------------------------------------------------------------------
-- Provisioning
--
-- The only path by which a tenant comes into existence from the internet.
--
-- SECURITY DEFINER with a fixed search_path: without the pinned path, a caller
-- who can create objects in a schema earlier in the search path can shadow a
-- function this body calls and execute it as the owner.
--
-- It discloses a provider id and a created flag, and nothing else. The billing
-- role learns whether it just created a tenant, which it needs in order to
-- decide whether to send a welcome email; it does not learn anything about any
-- other tenant, so a compromised billing process cannot enumerate customers.
-- ---------------------------------------------------------------------------

CREATE FUNCTION provision_subscription(
  p_slug                    text,
  p_display_name            text,
  p_stripe_customer_id      text,
  p_stripe_subscription_id  text,
  p_status                  text,
  p_plan                    text,
  p_repository_limit        integer,
  p_current_period_end      timestamptz,
  p_cancel_at_period_end    boolean
)
-- The output columns are named distinctly from the table columns they carry.
-- A RETURNS TABLE column named `provider_id` shadows `subscription.provider_id`
-- inside the body, and `ON CONFLICT (provider_id)` below then fails to resolve
-- with "column reference is ambiguous" — at runtime, on the first real
-- customer, since nothing catches it at creation time.
RETURNS TABLE (provisioned_provider_id uuid, was_created boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_provider_id uuid;
  v_created     boolean;
BEGIN
  -- An existing subscription wins over the slug. A customer who changes plan
  -- keeps their tenant; resolving by slug alone would let a second checkout
  -- with a colliding slug adopt someone else's tenant.
  SELECT s.provider_id INTO v_provider_id
    FROM subscription s
   WHERE s.stripe_subscription_id = p_stripe_subscription_id;

  IF v_provider_id IS NULL THEN
    INSERT INTO provider (slug, display_name)
         VALUES (p_slug, p_display_name)
    ON CONFLICT (slug) DO UPDATE SET display_name = EXCLUDED.display_name
      RETURNING id, (xmax = 0) INTO v_provider_id, v_created;
  ELSE
    v_created := false;
  END IF;

  INSERT INTO subscription (
    provider_id, stripe_customer_id, stripe_subscription_id, status, plan,
    repository_limit, current_period_end, cancel_at_period_end, updated_at
  ) VALUES (
    v_provider_id, p_stripe_customer_id, p_stripe_subscription_id, p_status,
    p_plan, p_repository_limit, p_current_period_end, p_cancel_at_period_end, now()
  )
  ON CONFLICT (provider_id) DO UPDATE
     SET status                 = EXCLUDED.status,
         plan                   = EXCLUDED.plan,
         repository_limit       = EXCLUDED.repository_limit,
         current_period_end     = EXCLUDED.current_period_end,
         cancel_at_period_end   = EXCLUDED.cancel_at_period_end,
         stripe_customer_id     = EXCLUDED.stripe_customer_id,
         -- Replaced, not preserved: a returning customer's new subscription is
         -- the live one. The unique index on stripe_subscription_id still
         -- holds, and cannot be violated here — a subscription already
         -- attached to another tenant would have been resolved above.
         stripe_subscription_id = EXCLUDED.stripe_subscription_id,
         updated_at             = now();

  RETURN QUERY SELECT v_provider_id, v_created;
END;
$$;

REVOKE ALL ON FUNCTION provision_subscription FROM PUBLIC;
GRANT EXECUTE ON FUNCTION provision_subscription TO driftless_billing;

COMMENT ON FUNCTION provision_subscription IS
  'The only route from a paid checkout to a live tenant. SECURITY DEFINER because '
  'the application role cannot create a provider by construction (ADR-0005). '
  'Idempotent on stripe_subscription_id so Stripe redelivery converges.';
