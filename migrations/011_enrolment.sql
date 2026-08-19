-- 011 — Enrolling an installation
--
-- Migrations 001 and 006 assume installations already exist: 006 resolves a
-- forge installation id to a provider, and everything downstream reads from
-- there. Nothing ever wrote that row. An installed App therefore produced
-- webhooks that resolved to no tenant, forever, and the product could not
-- onboard anyone.
--
-- The missing question is one GitHub cannot answer: an `installation.created`
-- webhook says which account installed the App, but not which *provider* — the
-- paying tenant — that installation belongs to. Guessing is not available: a
-- wrong guess files another tenant's repositories under our customer, which is
-- precisely the boundary 001 exists to defend.
--
-- So enrolment is explicit. A single-tenant deployment names its provider in
-- configuration (DEFAULT_PROVIDER_SLUG) and installations enrol into it; a
-- multi-tenant deployment leaves it unset and unknown installations stay
-- unenrolled, exactly as before. This function is the lookup that makes the
-- first case possible, and it discloses a provider id and nothing else — the
-- same minimal-disclosure shape as provider_for_installation in 006, for the
-- same reason: the platform role must not be able to enumerate tenants.
--
-- Creating the provider row itself is deliberately NOT here. Provider creation
-- is an operator and billing action (see scripts/create-provider.ts); the RLS
-- policy on `provider` makes it impossible for the application role anyway,
-- since a row that does not exist yet cannot match current_provider_id().

CREATE FUNCTION provider_id_for_slug(p_slug text)
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT id
    FROM provider
   WHERE slug = p_slug
     AND deleted_at IS NULL
   LIMIT 1;
$$;

COMMENT ON FUNCTION provider_id_for_slug IS
  'Minimal-disclosure provider lookup for enrolment. Returns only a provider '
  'id, and only for a live provider. See migration 011.';

REVOKE ALL ON FUNCTION provider_id_for_slug FROM PUBLIC;
GRANT EXECUTE ON FUNCTION provider_id_for_slug TO driftless_admin;
