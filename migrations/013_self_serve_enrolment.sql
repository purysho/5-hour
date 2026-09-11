-- 013 — Connecting a payment to an installation
--
-- Migration 012 made a tenant exist when someone pays. It did not connect that
-- tenant to the GitHub installation the customer then creates, and without
-- that link the product does not function for a paying customer at all:
--
--   * With DEFAULT_PROVIDER_SLUG unset, `installation.created` resolves to no
--     tenant and is dropped. The customer has paid and is connected to
--     nothing, permanently, and the log line saying so is the only symptom.
--
--   * With it set, EVERY installation from EVERY customer enrols into the one
--     configured tenant. That is worse: it files one customer's repositories
--     under another, which is precisely the boundary 001 exists to defend.
--
-- Both were live. This migration closes it.
--
-- ── Why GitHub cannot answer the question ───────────────────────────────────
--
-- An `installation.created` webhook says which *account* installed the App. It
-- cannot say which paying tenant that account belongs to, because GitHub has
-- never heard of our tenants. Guessing from the account name is not available:
-- a wrong guess is a cross-tenant leak with no error.
--
-- So the answer has to be carried from the side that does know — the checkout
-- — through the install flow, and back to us. GitHub App installation supports
-- a `state` parameter which it returns to the App's setup URL. We mint an
-- opaque reference at checkout, Stripe echoes it back on
-- `checkout.session.completed` as `client_reference_id`, and the same value
-- travels through the install as `state`. Matching the two binds the
-- installation to the tenant that paid, and to no other.
--
-- ── Why the reference is stored hashed ──────────────────────────────────────
--
-- It arrives in a URL. URLs reach browser history, referrer headers, corporate
-- proxies, and screenshots in support tickets. Anyone holding one can bind an
-- installation they control to the tenant it names — enrolling their own
-- repositories into someone else's paid account. Storing only the hash means a
-- database disclosure does not hand over working references, exactly as
-- migration 005 treats opt-out tokens.
--
-- ── Why installations are parked rather than dropped ────────────────────────
--
-- The webhook and the browser race, and GitHub wins about as often as not: the
-- `installation.created` delivery frequently lands before the customer's
-- browser reaches the setup URL. Dropping it, as the old path did, loses the
-- repository list the customer just chose — and nothing asks them again, so
-- the account stays empty until they think to reinstall.
--
-- So an unenrolled installation is parked with the repositories it arrived
-- with, and the setup callback drains it. Parked rows carry no provider_id
-- because no tenant owns them yet; that is the whole point of them, and it is
-- why this table is not under RLS. It holds public repository names and an
-- installation id, which is why that is acceptable — see the grants.

-- ---------------------------------------------------------------------------
-- The enrolment reference
-- ---------------------------------------------------------------------------

ALTER TABLE provider ADD COLUMN enrolment_ref_hash text;

-- Partial, because most providers have no reference: one created by an
-- operator through `pnpm db:provider` never goes through checkout. A plain
-- unique index would collapse every one of those NULLs into a conflict.
CREATE UNIQUE INDEX provider_enrolment_ref_hash_idx
  ON provider (enrolment_ref_hash)
  WHERE enrolment_ref_hash IS NOT NULL;

COMMENT ON COLUMN provider.enrolment_ref_hash IS
  'SHA-256 of the checkout reference that may bind an installation to this '
  'tenant. Hashed because the reference travels in a URL. See migration 013.';

-- ---------------------------------------------------------------------------
-- Parked installations
-- ---------------------------------------------------------------------------

CREATE TABLE pending_installation (
  forge_installation_id  bigint PRIMARY KEY,
  forge                  text NOT NULL DEFAULT 'github',
  account                text NOT NULL,
  -- The repository list as the webhook delivered it. Stored so the selection
  -- the customer made survives the race; drained and deleted on enrolment.
  repositories           jsonb NOT NULL,
  received_at            timestamptz NOT NULL DEFAULT now()
);

-- No RLS, deliberately, and the reason is the reason the table exists: a
-- parked installation belongs to no tenant yet, so there is no provider_id to
-- scope it by and no policy that could be written. What it holds is an
-- installation id and public repository coordinates the account owner just
-- chose to share with us — not customer data belonging to anyone else. The
-- control is the grant below: only the platform role can read it, and it is
-- deleted the moment the installation is claimed.
-- UPDATE is required and is easy to omit. The writer upserts — GitHub
-- redelivers `installation.created`, and a customer who changes their
-- repository selection before reaching the setup URL must refresh the parked
-- row rather than conflict with it. Postgres checks the UPDATE privilege for
-- an ON CONFLICT DO UPDATE statement at plan time, whether or not a conflict
-- actually occurs, so a grant of INSERT alone fails every call rather than
-- only the second one. That is how this was found: the plain INSERT passed in
-- isolation and the real statement did not.
GRANT SELECT, INSERT, UPDATE, DELETE ON pending_installation TO driftless_admin;

COMMENT ON TABLE pending_installation IS
  'Installations that arrived before their tenant was known. Drained by the '
  'setup callback; deleted on enrolment. See migration 013.';

-- ---------------------------------------------------------------------------
-- Minimal-disclosure lookup
-- ---------------------------------------------------------------------------

CREATE FUNCTION provider_id_for_enrolment_ref(p_ref_hash text)
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT id
    FROM provider
   WHERE enrolment_ref_hash = p_ref_hash
     AND enrolment_ref_hash IS NOT NULL
     AND deleted_at IS NULL
   LIMIT 1;
$$;

COMMENT ON FUNCTION provider_id_for_enrolment_ref IS
  'Resolves a checkout reference hash to a provider id and nothing else. Same '
  'minimal-disclosure shape as provider_for_installation in 006: the platform '
  'role must not be able to enumerate tenants.';

REVOKE ALL ON FUNCTION provider_id_for_enrolment_ref FROM PUBLIC;
GRANT EXECUTE ON FUNCTION provider_id_for_enrolment_ref TO driftless_admin;

-- ---------------------------------------------------------------------------
-- Provisioning now records the reference
--
-- Dropped and recreated rather than overloaded. Adding a defaulted parameter
-- would leave two callable signatures, and which one runs would be decided by
-- argument types rather than by intent — with the older one silently never
-- recording a reference, which is the failure this migration exists to fix.
-- ---------------------------------------------------------------------------

DROP FUNCTION provision_subscription(
  text, text, text, text, text, text, integer, timestamptz, boolean
);

CREATE FUNCTION provision_subscription(
  p_slug                    text,
  p_display_name            text,
  p_stripe_customer_id      text,
  p_stripe_subscription_id  text,
  p_status                  text,
  p_plan                    text,
  p_repository_limit        integer,
  p_current_period_end      timestamptz,
  p_cancel_at_period_end    boolean,
  p_enrolment_ref_hash      text
)
RETURNS TABLE (provisioned_provider_id uuid, was_created boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_provider_id uuid;
  v_created     boolean;
BEGIN
  SELECT s.provider_id INTO v_provider_id
    FROM subscription s
   WHERE s.stripe_subscription_id = p_stripe_subscription_id;

  IF v_provider_id IS NULL THEN
    INSERT INTO provider (slug, display_name, enrolment_ref_hash)
         VALUES (p_slug, p_display_name, p_enrolment_ref_hash)
    ON CONFLICT (slug) DO UPDATE SET display_name = EXCLUDED.display_name
      RETURNING id, (xmax = 0) INTO v_provider_id, v_created;
  ELSE
    v_created := false;
  END IF;

  -- Set outside the insert as well, so a reference arriving on a later event
  -- still lands. The subscription event fires without one and may win the race
  -- against checkout.session.completed, which is the event that carries it.
  --
  -- COALESCE keeps the first reference rather than the last: a customer who
  -- changes plan later produces a new checkout with a new reference, and
  -- overwriting would silently invalidate an enrolment link they have not used
  -- yet.
  IF p_enrolment_ref_hash IS NOT NULL THEN
    UPDATE provider
       SET enrolment_ref_hash = COALESCE(enrolment_ref_hash, p_enrolment_ref_hash)
     WHERE id = v_provider_id;
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
         stripe_subscription_id = EXCLUDED.stripe_subscription_id,
         updated_at             = now();

  RETURN QUERY SELECT v_provider_id, v_created;
END;
$$;

REVOKE ALL ON FUNCTION provision_subscription FROM PUBLIC;
GRANT EXECUTE ON FUNCTION provision_subscription TO driftless_billing;

COMMENT ON FUNCTION provision_subscription IS
  'The only route from a paid checkout to a live tenant, now also recording the '
  'enrolment reference that binds an installation to it. See migrations 012, 013.';
