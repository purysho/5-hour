-- 009 — What the forge says about a repository
--
-- The installation webhook carries a repository's id, name and visibility and
-- nothing else. It does not say which branch is the default, how many people
-- watch it, or whether it is a fork — and all three change what we do:
--
--   default_branch  read the wrong one and the repository looks like it has no
--                   manifest, which is a skip nobody investigates
--   stars           orders the canary smallest-first
--   is_fork         `decideTarget` skips forks, because the upstream is the
--                   meaningful target
--
-- So they are learned from the forge, with a credential, the first time a
-- rollout looks at the repository — and cached here. `is_fork` defaults to
-- false rather than NULL because the column is a filter: a NULL would have to
-- mean "maybe", and the only safe reading of "maybe a fork" is to treat it as
-- one, which would silently exclude every repository we have not yet described.
-- Defaulting to false and correcting on first read fails in the direction that
-- is visible.

ALTER TABLE repository
  ADD COLUMN is_fork      boolean NOT NULL DEFAULT false,
  ADD COLUMN described_at timestamptz;

COMMENT ON COLUMN repository.is_fork IS
  'From the forge, not the webhook. Forks are skipped: the upstream is the '
  'meaningful target for a migration.';

COMMENT ON COLUMN repository.described_at IS
  'When default_branch, stars and is_fork were last refreshed from the forge. '
  'NULL means they are still webhook defaults and have not been confirmed.';
