-- 010 — Finding changes a human has approved
--
-- The approval gate only works if something is watching the gate. A human sets
-- `approved_at` and, until now, nothing happened: `plan-rollout` existed, was
-- registered, and had no way of ever being enqueued. Approval was a column
-- nobody read.
--
-- ── Why this discloses so little ─────────────────────────────────────────────
--
-- SECURITY DEFINER, like `claim_due_sweeps`, because the scheduler runs as
-- `driftless_admin` and has to see across tenants to do its job at all. That
-- makes it a cross-tenant read, so it returns the two fields enqueueing needs —
-- the provider and the change — and nothing describing what the change is.
-- A scheduler does not need to know that a provider is watching a competitor's
-- package, and the narrower the return, the less a bug in the caller can leak.
--
-- ── Why it does not claim ────────────────────────────────────────────────────
--
-- `claim_due_sweeps` advances a clock as it returns rows, because a sweep is
-- recurring and two schedulers must not both decide the same package is due.
-- A rollout is not recurring: one approved change earns exactly one rollout,
-- ever. That is already guaranteed by `job_dedupe_key_idx` on
-- `rollout:<change id>`, which is unique across every status — so a second
-- scheduler, or the same one after a restart, enqueues nothing.
--
-- Relying on the dedupe key rather than a second mechanism keeps "how many
-- rollouts can one approval cause" answerable by looking at one index.

CREATE FUNCTION approved_changes_awaiting_rollout(p_limit integer DEFAULT 50)
RETURNS TABLE (
  provider_id uuid,
  change_id   uuid
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT c.provider_id, c.id
  FROM upstream_change c
  WHERE c.approved_at IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM job j
      WHERE j.workflow = 'plan-rollout'
        AND j.dedupe_key = 'rollout:' || c.id::text
    )
  ORDER BY c.approved_at
  LIMIT p_limit;
$$;

COMMENT ON FUNCTION approved_changes_awaiting_rollout IS
  'Approved changes with no rollout job yet. Returns only what enqueueing '
  'requires — never what the change is about. See migration 010.';

REVOKE ALL ON FUNCTION approved_changes_awaiting_rollout FROM PUBLIC;
GRANT EXECUTE ON FUNCTION approved_changes_awaiting_rollout TO driftless_admin;

-- Keeps the scan above off a sequential read of every change ever recorded.
CREATE INDEX upstream_change_approved_idx
  ON upstream_change (approved_at)
  WHERE approved_at IS NOT NULL;
