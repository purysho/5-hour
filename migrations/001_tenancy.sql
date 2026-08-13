-- 001 — Tenancy foundation and row-level security
--
-- Implements ADR-0005. Tenant isolation is enforced by the database, not by
-- application predicates, so that a forgotten WHERE clause returns zero rows
-- rather than another tenant's.
--
-- The tenancy structure is two-level (threat-model §5.3):
--   provider  — the paying tenant, and the RLS boundary
--   consumer  — a party whose repositories we act on, scoped under a provider
--
-- A repository reachable through two providers produces two distinct rows with
-- no shared state. Providers are frequently competitors; they must not be able
-- to infer each other's consumer lists.

-- ---------------------------------------------------------------------------
-- Roles
-- ---------------------------------------------------------------------------

-- The application role. Deliberately NOT a superuser and NOT BYPASSRLS.
-- Superusers and table owners bypass RLS unless FORCE is set, so every
-- tenant-scoped table below sets FORCE ROW LEVEL SECURITY.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'driftless_app') THEN
    CREATE ROLE driftless_app NOLOGIN NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'driftless_admin') THEN
    -- Narrow, audited, cross-tenant role (ADR-0005 §6). Every use is written
    -- to the audit chain. Not used by request-serving code paths.
    CREATE ROLE driftless_admin NOLOGIN NOBYPASSRLS;
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- Tenant context
--
-- Set per transaction from a server-derived session identity. Never from a
-- client-supplied parameter (threat-model §5.3).
--
-- current_provider_id() returns NULL when unset, and every policy below
-- compares against it with `=`, which yields NULL — not TRUE — for every row.
-- A query issued without tenant context therefore returns nothing. Failing
-- closed is the entire point of this file.
-- ---------------------------------------------------------------------------

CREATE SCHEMA IF NOT EXISTS app;

CREATE OR REPLACE FUNCTION app.current_provider_id()
RETURNS uuid
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('app.current_provider_id', true), '')::uuid;
$$;

-- ---------------------------------------------------------------------------
-- Tables
-- ---------------------------------------------------------------------------

CREATE TABLE provider (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug          text NOT NULL UNIQUE,
  display_name  text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  deleted_at    timestamptz
);

COMMENT ON TABLE provider IS
  'The paying tenant: an API provider. This is the RLS boundary (ADR-0005).';

CREATE TABLE consumer (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id   uuid NOT NULL REFERENCES provider(id) ON DELETE CASCADE,
  -- Forge-side identity of the consuming organisation or user.
  forge         text NOT NULL DEFAULT 'github',
  forge_owner   text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider_id, forge, forge_owner)
);

COMMENT ON TABLE consumer IS
  'A party whose repositories we act on, scoped beneath one provider. The same '
  'organisation under two providers is two rows (ADR-0005 §3).';

-- A GitHub App installation. Ownership of a repository is proven by the
-- existence of an installation, never asserted by the tenant
-- (threat-model §5.3).
CREATE TABLE installation (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id           uuid NOT NULL REFERENCES provider(id) ON DELETE CASCADE,
  consumer_id           uuid NOT NULL REFERENCES consumer(id) ON DELETE CASCADE,
  forge_installation_id bigint NOT NULL,
  -- Recorded so that a widening of our permission manifest is detectable.
  -- ADR-0002 §4: changes to the manifest require an ADR.
  granted_permissions   jsonb NOT NULL DEFAULT '{}'::jsonb,
  suspended_at          timestamptz,
  created_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider_id, forge_installation_id)
);

CREATE TABLE repository (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id     uuid NOT NULL REFERENCES provider(id) ON DELETE CASCADE,
  installation_id uuid NOT NULL REFERENCES installation(id) ON DELETE CASCADE,
  forge           text NOT NULL DEFAULT 'github',
  forge_owner     text NOT NULL,
  forge_name      text NOT NULL,
  default_branch  text NOT NULL DEFAULT 'main',
  is_private      boolean NOT NULL DEFAULT true,
  archived_at     timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider_id, forge, forge_owner, forge_name)
);

CREATE INDEX repository_installation_idx ON repository (installation_id);
CREATE INDEX consumer_provider_idx ON consumer (provider_id);

-- An upstream breaking change we have detected and corroborated.
CREATE TABLE upstream_change (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id      uuid NOT NULL REFERENCES provider(id) ON DELETE CASCADE,
  -- Stable identifier for the change, used in the idempotency key (ADR-0004).
  change_key       text NOT NULL,
  ecosystem        text NOT NULL,
  package_name     text NOT NULL,
  from_version     text,
  to_version       text,
  summary          text NOT NULL,
  -- Sources that corroborated this change (threat-model §5.2). A change with
  -- fewer than the configured minimum is not eligible for fan-out.
  corroborations   jsonb NOT NULL DEFAULT '[]'::jsonb,
  -- Migrations introducing dependencies, network destinations, or credential
  -- usage are never auto-generated; they wait for human approval on our side.
  approved_at      timestamptz,
  approved_by      text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider_id, change_key)
);

-- ---------------------------------------------------------------------------
-- Row-level security
--
-- Enabled AND forced on every tenant-scoped table. FORCE matters: without it
-- the table owner bypasses the policy, which silently defeats the control in
-- exactly the environment where it is least likely to be noticed.
-- ---------------------------------------------------------------------------

ALTER TABLE provider        ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider        FORCE  ROW LEVEL SECURITY;
ALTER TABLE consumer        ENABLE ROW LEVEL SECURITY;
ALTER TABLE consumer        FORCE  ROW LEVEL SECURITY;
ALTER TABLE installation    ENABLE ROW LEVEL SECURITY;
ALTER TABLE installation    FORCE  ROW LEVEL SECURITY;
ALTER TABLE repository      ENABLE ROW LEVEL SECURITY;
ALTER TABLE repository      FORCE  ROW LEVEL SECURITY;
ALTER TABLE upstream_change ENABLE ROW LEVEL SECURITY;
ALTER TABLE upstream_change FORCE  ROW LEVEL SECURITY;

CREATE POLICY provider_tenant_isolation ON provider
  FOR ALL TO driftless_app
  USING (id = app.current_provider_id())
  WITH CHECK (id = app.current_provider_id());

CREATE POLICY consumer_tenant_isolation ON consumer
  FOR ALL TO driftless_app
  USING (provider_id = app.current_provider_id())
  WITH CHECK (provider_id = app.current_provider_id());

CREATE POLICY installation_tenant_isolation ON installation
  FOR ALL TO driftless_app
  USING (provider_id = app.current_provider_id())
  WITH CHECK (provider_id = app.current_provider_id());

CREATE POLICY repository_tenant_isolation ON repository
  FOR ALL TO driftless_app
  USING (provider_id = app.current_provider_id())
  WITH CHECK (provider_id = app.current_provider_id());

CREATE POLICY upstream_change_tenant_isolation ON upstream_change
  FOR ALL TO driftless_app
  USING (provider_id = app.current_provider_id())
  WITH CHECK (provider_id = app.current_provider_id());

-- WITH CHECK on every policy, not just USING. USING governs which rows are
-- visible; WITH CHECK governs which rows may be written. A policy with only
-- USING permits a tenant to INSERT rows attributed to another tenant, which
-- is the more damaging half of the problem.

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------

GRANT USAGE ON SCHEMA app, public TO driftless_app, driftless_admin;
GRANT EXECUTE ON FUNCTION app.current_provider_id() TO driftless_app, driftless_admin;

GRANT SELECT, INSERT, UPDATE, DELETE ON
  provider, consumer, installation, repository, upstream_change
  TO driftless_app;
