-- 007 — Impacted symbols, and the packages we watch
--
-- Two gaps that only become visible once migration generation exists.
--
-- ── Impacted symbols had nowhere to live ────────────────────────────────────
--
-- `detect-changes` computes the set of symbols an upstream change impacts, and
-- the migration workflow derives the blast radius from it (ADR-0013). Between
-- those two points the value was being dropped: `RecordedChange` carried it,
-- `upstream_change` had no column for it, and the recorder silently discarded
-- it. The consequence is quiet and total — an empty symbol set produces an
-- empty blast radius, which means every migration is refused for a reason that
-- looks like "nothing references this package".
--
-- `approved_at` had the same shape of problem: the column existed and nothing
-- ever wrote it.
--
-- ── Nothing decided when to sweep ───────────────────────────────────────────
--
-- The sweep workflow exists and is tested, but jobs only ever appeared because
-- something enqueued them by hand. Detection that runs when someone remembers
-- is not detection.
--
-- The claim is in the database rather than in a scheduler process for the same
-- reason the job lease is: two schedulers, or one scheduler across a deploy,
-- must not both decide a package is due. `FOR UPDATE SKIP LOCKED` makes the
-- claim exclusive without either instance waiting on the other.

ALTER TABLE upstream_change
  ADD COLUMN impacted_symbols text[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN upstream_change.impacted_symbols IS
  'Symbols the change impacts. The migration blast radius is derived from '
  'these before any inference runs (ADR-0013), so an empty set means no '
  'migration is possible — not that any file may be edited.';

-- ---------------------------------------------------------------------------
-- Watched packages
-- ---------------------------------------------------------------------------

CREATE TABLE watched_package (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id    uuid NOT NULL REFERENCES provider(id) ON DELETE CASCADE,
  ecosystem      text NOT NULL,
  package_name   text NOT NULL,
  -- The version consumers are assumed to be on; the baseline every comparison
  -- is made against. Advanced deliberately, by a human or by an approved
  -- change, never by the sweep itself — a sweep that moved its own baseline
  -- would forget the change it had just found the moment it ran again.
  baseline_version text NOT NULL,
  -- How often to sweep. Per-package because a package that ships weekly and
  -- one that ships hourly do not deserve the same registry load.
  sweep_interval_seconds integer NOT NULL DEFAULT 3600,
  last_swept_at  timestamptz,
  -- Pausing a package must not lose its baseline, so this is a flag rather
  -- than a delete.
  enabled        boolean NOT NULL DEFAULT true,
  created_at     timestamptz NOT NULL DEFAULT now(),

  UNIQUE (provider_id, ecosystem, package_name),
  CONSTRAINT watched_package_interval_sane
    CHECK (sweep_interval_seconds BETWEEN 60 AND 604800),
  CONSTRAINT watched_package_ecosystem_known CHECK (ecosystem IN ('npm'))
);

CREATE INDEX watched_package_due_idx
  ON watched_package (last_swept_at)
  WHERE enabled;

ALTER TABLE watched_package ENABLE ROW LEVEL SECURITY;
ALTER TABLE watched_package FORCE  ROW LEVEL SECURITY;

CREATE POLICY watched_package_tenant_isolation ON watched_package
  FOR ALL TO driftless_app
  USING (provider_id = app.current_provider_id())
  WITH CHECK (provider_id = app.current_provider_id());

GRANT SELECT, INSERT, UPDATE ON watched_package TO driftless_app;

-- ---------------------------------------------------------------------------
-- Claiming due sweeps
--
-- The scheduler runs as the platform role and must see every provider's
-- packages, which is the same tension migration 005 hit with opt-out tokens
-- and is resolved the same way: a function shaped to disclose the minimum,
-- rather than a table-wide grant the RLS coverage test would rightly reject.
--
-- What this discloses is a package name and a version — both public facts
-- about a published package — plus the provider that watches it, which the
-- caller needs in order to enqueue into the right tenant. It does not expose
-- intervals, history, or which packages a provider has paused.
--
-- The UPDATE is the claim. Returning a row and advancing `last_swept_at` in
-- one statement is what makes a second scheduler see nothing due, rather than
-- both of them enqueueing the same sweep and relying on the job dedupe key to
-- clean up after them. The dedupe key is still set — this is the first of two
-- defences, not the only one.
-- ---------------------------------------------------------------------------

CREATE FUNCTION claim_due_sweeps(p_limit integer DEFAULT 50, p_now timestamptz DEFAULT now())
RETURNS TABLE (
  provider_id      uuid,
  ecosystem        text,
  package_name     text,
  baseline_version text
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  WITH due AS (
    SELECT w.id
    FROM watched_package w
    WHERE w.enabled
      AND (
        w.last_swept_at IS NULL
        OR w.last_swept_at <= p_now - make_interval(secs => w.sweep_interval_seconds)
      )
    ORDER BY w.last_swept_at NULLS FIRST
    LIMIT p_limit
    FOR UPDATE SKIP LOCKED
  )
  UPDATE watched_package w
  SET last_swept_at = p_now
  FROM due
  WHERE w.id = due.id
  RETURNING w.provider_id, w.ecosystem, w.package_name, w.baseline_version;
$$;

COMMENT ON FUNCTION claim_due_sweeps IS
  'Claims packages due for a detection sweep and advances their clock in the '
  'same statement, so two schedulers cannot claim the same package. Discloses '
  'only what enqueueing requires. See migration 007.';

REVOKE ALL ON FUNCTION claim_due_sweeps FROM PUBLIC;
GRANT EXECUTE ON FUNCTION claim_due_sweeps TO driftless_admin;
