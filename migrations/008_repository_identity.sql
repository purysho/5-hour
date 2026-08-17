-- 008 — Forge repository identity
--
-- ADR-0002 scopes every installation token to exactly one repository, and
-- GitHub's API expresses that as `repository_ids: [<numeric id>]` — not as an
-- owner/name pair. Until now the schema stored only the coordinates, which
-- meant the worker could name a repository it could not mint a token for.
--
-- Nullable, deliberately. Rows written before this migration have no numeric
-- id, and backfilling one would mean guessing. The loader refuses a repository
-- whose id is missing rather than minting a token scoped to nothing: an
-- unscoped token is the standing privilege ADR-0002 exists to eliminate, and a
-- guessed id is worse — it is a token for somebody else's repository.
--
-- `stars` is separate and much less serious. Fan-out ordering sends the first
-- wave to the smallest repositories (`prioritise`), so its absence costs
-- ordering quality, not safety. NULL means "unknown", which orders last.

ALTER TABLE repository
  ADD COLUMN forge_repository_id bigint,
  ADD COLUMN stars               integer;

COMMENT ON COLUMN repository.forge_repository_id IS
  'GitHub''s numeric repository id. Required to scope an installation token to '
  'this repository alone (ADR-0002). NULL means we cannot act on the row.';

COMMENT ON COLUMN repository.stars IS
  'Popularity, used only to order the canary smallest-first. NULL orders last.';

-- Unique per tenant rather than globally: the same repository reached through
-- two providers is two rows with no shared state (ADR-0005 §3).
CREATE UNIQUE INDEX repository_forge_id_idx
  ON repository (provider_id, forge, forge_repository_id)
  WHERE forge_repository_id IS NOT NULL;

-- The fan-out candidate scan: every live repository under one installation.
-- Partial, because archived repositories are never candidates and the index
-- should not grow with them.
CREATE INDEX repository_live_idx
  ON repository (provider_id, installation_id)
  WHERE archived_at IS NULL;
