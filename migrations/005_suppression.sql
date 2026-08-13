-- 005 — Suppression (opt-out)
--
-- Every pull request Driftless opens carries the line:
--
--   "Not useful? <link> — one click, no account, and we will not open another
--    pull request here."
--
-- This is the table that makes that true. Without it the promise is a lie
-- printed on a trusted artifact, which is worse than not offering an opt-out
-- at all.
--
-- The opt-out is not politeness. In the open-source cold-start motion we open
-- pull requests nobody asked for, and a bot with no working off switch earns a
-- block, a public complaint, and a reputation that is expensive to undo. This
-- is the control that makes the motion survivable.
--
-- Three design commitments:
--
--   No account. The link works on one click, from a signed token, with no
--   sign-up and no email. Anything more friction-heavy is not an opt-out — it
--   is a retention funnel, and maintainers recognise the difference.
--
--   Permanent by default. Suppression has no expiry unless someone explicitly
--   sets one. A person who opted out last year has not consented to being
--   contacted again this year.
--
--   Scoped upward. Opting out a repository suppresses that repository; opting
--   out an owner suppresses everything they have. A maintainer with forty
--   repositories should not have to click forty times.

CREATE TYPE suppression_scope AS ENUM ('repository', 'owner', 'installation');

CREATE TABLE suppression (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id   uuid NOT NULL REFERENCES provider(id) ON DELETE CASCADE,

  scope         suppression_scope NOT NULL,
  forge         text NOT NULL DEFAULT 'github',
  -- Lower-cased at write time. Forge identifiers are case-insensitive, and a
  -- case-sensitive comparison here would silently fail to suppress.
  forge_owner   text NOT NULL,
  -- NULL for owner- and installation-scoped suppression.
  forge_name    text,

  -- Free-text reason supplied by whoever opted out. Never rendered into a
  -- prompt, a pull request body, or any other trusted surface — it is
  -- untrusted input from an unauthenticated endpoint.
  reason        text,
  source        text NOT NULL DEFAULT 'opt-out-link',

  created_at    timestamptz NOT NULL DEFAULT now(),
  -- NULL means permanent, which is the default and the intended case.
  expires_at    timestamptz,

  CONSTRAINT suppression_name_matches_scope CHECK (
    (scope = 'repository' AND forge_name IS NOT NULL) OR
    (scope <> 'repository' AND forge_name IS NULL)
  ),
  CONSTRAINT suppression_lowercase CHECK (
    forge_owner = lower(forge_owner)
    AND (forge_name IS NULL OR forge_name = lower(forge_name))
  )
);

-- One suppression per target. Re-opting-out is idempotent rather than
-- accumulating rows.
CREATE UNIQUE INDEX suppression_repository_key
  ON suppression (provider_id, forge, forge_owner, forge_name)
  WHERE scope = 'repository';

CREATE UNIQUE INDEX suppression_owner_key
  ON suppression (provider_id, forge, forge_owner, scope)
  WHERE scope <> 'repository';

CREATE INDEX suppression_lookup_idx
  ON suppression (provider_id, forge, forge_owner);

COMMENT ON TABLE suppression IS
  'Opt-out list. Checked before every outbound write; see src/outbound/suppression.ts.';

-- ---------------------------------------------------------------------------
-- Opt-out tokens
--
-- The link in a pull request body must work with one click and no account, so
-- the URL itself carries the authorisation. Storing a hash rather than the
-- token means a database read does not yield working opt-out links for every
-- repository we have ever contacted — which would otherwise be a tidy
-- denial-of-service list.
--
-- Tokens do not expire. A maintainer who finds an old pull request in their
-- inbox two years from now should still be able to opt out from it.
-- ---------------------------------------------------------------------------

CREATE TABLE opt_out_token (
  token_hash    text PRIMARY KEY,
  provider_id   uuid NOT NULL REFERENCES provider(id) ON DELETE CASCADE,
  forge         text NOT NULL DEFAULT 'github',
  forge_owner   text NOT NULL,
  forge_name    text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  redeemed_at   timestamptz,

  CONSTRAINT opt_out_token_hash_shape CHECK (token_hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX opt_out_token_target_idx
  ON opt_out_token (provider_id, forge, forge_owner, forge_name);

ALTER TABLE suppression   ENABLE ROW LEVEL SECURITY;
ALTER TABLE suppression   FORCE  ROW LEVEL SECURITY;
ALTER TABLE opt_out_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE opt_out_token FORCE  ROW LEVEL SECURITY;

CREATE POLICY suppression_tenant_isolation ON suppression
  FOR ALL TO driftless_app
  USING (provider_id = app.current_provider_id())
  WITH CHECK (provider_id = app.current_provider_id());

CREATE POLICY opt_out_token_tenant_isolation ON opt_out_token
  FOR ALL TO driftless_app
  USING (provider_id = app.current_provider_id())
  WITH CHECK (provider_id = app.current_provider_id());

GRANT SELECT, INSERT, UPDATE ON suppression TO driftless_app;
GRANT SELECT, INSERT, UPDATE ON opt_out_token TO driftless_app;

-- ---------------------------------------------------------------------------
-- Resolving a token to its tenant
--
-- The opt-out endpoint is unauthenticated: someone arrives holding a token and
-- nothing else. There is no session to derive tenant context from, so the
-- token must be resolved to a provider BEFORE tenant context can exist. A
-- genuine chicken-and-egg, not a shortcut.
--
-- The obvious fix — grant the platform role SELECT on this table — is wrong,
-- and the RLS coverage test in test/db/rls.test.ts correctly rejects it. This
-- table is tenant data: it records which repositories each provider has
-- contacted, and providers are frequently competitors. A table-wide read would
-- hand the platform role every provider's target list, which is exactly the
-- disclosure ADR-0005 exists to prevent.
--
-- So the escape hatch is a function rather than a grant, and it is shaped to
-- disclose the minimum the requirement needs:
--
--   * it takes a token HASH, so the caller must already hold the token;
--   * it matches on the primary key, so there is no scanning or enumeration;
--   * it returns ONLY the provider id — not the owner, not the repository,
--     not the timestamps.
--
-- Learning "this token belongs to provider X" is the entire capability. It
-- reveals nothing about any provider whose token you do not already have.
-- Everything after the lookup runs inside the resolved tenant's context under
-- ordinary RLS.
-- ---------------------------------------------------------------------------

CREATE FUNCTION provider_for_opt_out_token(p_token_hash text)
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT provider_id FROM opt_out_token WHERE token_hash = p_token_hash;
$$;

COMMENT ON FUNCTION provider_for_opt_out_token IS
  'Minimal-disclosure tenant resolution for the unauthenticated opt-out endpoint. '
  'Returns only a provider id, only for an exact token hash. See migration 005.';

REVOKE ALL ON FUNCTION provider_for_opt_out_token FROM PUBLIC;
GRANT EXECUTE ON FUNCTION provider_for_opt_out_token TO driftless_admin;
