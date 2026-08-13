-- 002 — Outbound writes and the exactly-once invariant
--
-- Implements ADR-0004. The guarantee that a retry storm cannot open a second
-- pull request lives in a unique index, not in application logic.
--
-- The naive implementation — check whether a PR exists, then create it — is
-- not atomic. A crash or a concurrent worker between the check and the write
-- produces exactly the duplicate the check exists to prevent. Threat-model
-- §5.6 rates that failure as more probable than any attack in this system,
-- and unrecoverable in the way that matters: the customer's trust.
--
-- So the row is claimed BEFORE the side effect is attempted. The unique
-- constraint is what makes the claim exclusive; everything else is bookkeeping.

CREATE TYPE outbound_write_status AS ENUM (
  'claimed',    -- row inserted, side effect not yet attempted
  'succeeded',  -- side effect completed, result recorded
  'failed',     -- side effect failed terminally; will not be retried
  'abandoned'   -- claim expired without resolution; see reclaim rules below
);

CREATE TABLE outbound_write (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id      uuid NOT NULL REFERENCES provider(id) ON DELETE CASCADE,

  -- ── The idempotency key (ADR-0004) ───────────────────────────────────────
  -- base_sha is part of the key deliberately. If the repository has moved on,
  -- this is a genuinely different migration and should produce a new pull
  -- request, not be suppressed as a duplicate. Keying on
  -- (repository, change) alone silently skips repositories that still need
  -- the fix, which fails invisibly — the worst failure mode available.
  installation_id  uuid NOT NULL REFERENCES installation(id) ON DELETE CASCADE,
  repository_id    uuid NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
  change_id        uuid NOT NULL REFERENCES upstream_change(id) ON DELETE CASCADE,
  base_sha         text NOT NULL,
  -- ─────────────────────────────────────────────────────────────────────────

  status           outbound_write_status NOT NULL DEFAULT 'claimed',

  -- Result of the side effect. Populated on success.
  pr_number        integer,
  pr_url           text,

  -- Diagnostics. `attempts` counts claim acquisitions, not retries within a
  -- single attempt.
  attempts         integer NOT NULL DEFAULT 1,
  last_error       text,

  claimed_at       timestamptz NOT NULL DEFAULT now(),
  claim_expires_at timestamptz NOT NULL,
  resolved_at      timestamptz,

  CONSTRAINT outbound_write_base_sha_is_sha
    CHECK (base_sha ~ '^[0-9a-f]{40}$'),

  -- A resolved row must record when, and a succeeded row must record what.
  CONSTRAINT outbound_write_resolution_coherent CHECK (
    (status = 'claimed'   AND resolved_at IS NULL) OR
    (status = 'succeeded' AND resolved_at IS NOT NULL AND pr_number IS NOT NULL) OR
    (status IN ('failed', 'abandoned') AND resolved_at IS NOT NULL)
  )
);

-- ═══════════════════════════════════════════════════════════════════════════
-- THE INVARIANT
--
-- Everything else in this schema is convenience. This index is the guarantee.
-- It holds regardless of application bugs, concurrent workers, duplicate
-- webhook deliveries, or a worker that died between claiming and writing.
--
-- Do not add a partial predicate to this index. Excluding failed rows so they
-- can be "retried cleanly" reintroduces the duplicate this exists to prevent:
-- a write that failed to report success may still have succeeded remotely.
-- Reclaim is handled by the function below, which reuses the row rather than
-- permitting a second one.
-- ═══════════════════════════════════════════════════════════════════════════
CREATE UNIQUE INDEX outbound_write_idempotency_key
  ON outbound_write (installation_id, repository_id, change_id, base_sha);

CREATE INDEX outbound_write_provider_status_idx
  ON outbound_write (provider_id, status);

CREATE INDEX outbound_write_reclaimable_idx
  ON outbound_write (claim_expires_at)
  WHERE status = 'claimed';

COMMENT ON INDEX outbound_write_idempotency_key IS
  'ADR-0004: exactly-once outbound writes. Do not make this partial.';

-- ---------------------------------------------------------------------------
-- Claim acquisition
--
-- Returns the row and whether this caller now owns the side effect.
--
--   is_owner = true   caller must attempt the write, then resolve the row
--   is_owner = false  a prior claim exists; caller must NOT write. If that
--                     claim succeeded, its result is returned.
--
-- Reclaim: a claim whose expiry has passed while still in 'claimed' state is
-- assumed to belong to a dead worker. It is reclaimed rather than duplicated,
-- and attempts is incremented so runaway reclaim is visible rather than
-- silent. The row identity — and therefore the guarantee — is preserved.
-- ---------------------------------------------------------------------------

CREATE FUNCTION claim_outbound_write(
  p_provider_id     uuid,
  p_installation_id uuid,
  p_repository_id   uuid,
  p_change_id       uuid,
  p_base_sha        text,
  p_claim_ttl       interval DEFAULT interval '10 minutes'
)
RETURNS TABLE (
  write_id   uuid,
  is_owner   boolean,
  status     outbound_write_status,
  pr_number  integer,
  pr_url     text,
  attempts   integer
)
LANGUAGE plpgsql
AS $$
DECLARE
  v_row outbound_write;
BEGIN
  INSERT INTO outbound_write (
    provider_id, installation_id, repository_id, change_id, base_sha,
    claim_expires_at
  )
  VALUES (
    p_provider_id, p_installation_id, p_repository_id, p_change_id, p_base_sha,
    now() + p_claim_ttl
  )
  ON CONFLICT (installation_id, repository_id, change_id, base_sha)
  DO NOTHING
  RETURNING * INTO v_row;

  IF FOUND THEN
    RETURN QUERY SELECT v_row.id, true, v_row.status, v_row.pr_number,
                        v_row.pr_url, v_row.attempts;
    RETURN;
  END IF;

  -- A row already exists. Lock it so concurrent callers serialise here rather
  -- than both concluding they may reclaim.
  SELECT * INTO v_row
  FROM outbound_write
  WHERE installation_id = p_installation_id
    AND repository_id   = p_repository_id
    AND change_id       = p_change_id
    AND base_sha        = p_base_sha
  FOR UPDATE;

  IF v_row.status = 'claimed' AND v_row.claim_expires_at < now() THEN
    UPDATE outbound_write
       SET attempts         = outbound_write.attempts + 1,
           claimed_at       = now(),
           claim_expires_at = now() + p_claim_ttl
     WHERE id = v_row.id
     RETURNING * INTO v_row;

    RETURN QUERY SELECT v_row.id, true, v_row.status, v_row.pr_number,
                        v_row.pr_url, v_row.attempts;
    RETURN;
  END IF;

  RETURN QUERY SELECT v_row.id, false, v_row.status, v_row.pr_number,
                      v_row.pr_url, v_row.attempts;
END;
$$;

CREATE FUNCTION resolve_outbound_write(
  p_write_id   uuid,
  p_status     outbound_write_status,
  p_pr_number  integer DEFAULT NULL,
  p_pr_url     text    DEFAULT NULL,
  p_error      text    DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  IF p_status = 'claimed' THEN
    RAISE EXCEPTION 'resolve_outbound_write cannot resolve to claimed';
  END IF;

  UPDATE outbound_write
     SET status      = p_status,
         pr_number   = COALESCE(p_pr_number, pr_number),
         pr_url      = COALESCE(p_pr_url, pr_url),
         last_error  = p_error,
         resolved_at = now()
   WHERE id = p_write_id
     AND status = 'claimed';

  IF NOT FOUND THEN
    -- Either the id does not exist, or the row was already resolved. Both are
    -- programming errors: a resolved row must never be resolved again, since
    -- that would overwrite the recorded result of a side effect that happened.
    RAISE EXCEPTION 'outbound_write % is not in claimed state', p_write_id;
  END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Rate ceilings (ADR-0004)
--
-- Hard per-installation limits on outbound writes, enforced centrally. Fan-out
-- is staged: a migration reaching a new installation goes to a canary subset
-- before broad release.
-- ---------------------------------------------------------------------------

CREATE TABLE outbound_rate_limit (
  installation_id   uuid PRIMARY KEY REFERENCES installation(id) ON DELETE CASCADE,
  provider_id       uuid NOT NULL REFERENCES provider(id) ON DELETE CASCADE,
  max_writes_per_hour integer NOT NULL DEFAULT 20,
  max_open_prs        integer NOT NULL DEFAULT 50,
  updated_at          timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT outbound_rate_limit_positive
    CHECK (max_writes_per_hour > 0 AND max_open_prs > 0)
);

-- The global kill switch (ADR-0004). A single row, deliberately trivial to
-- flip, so that halting all outbound writes never requires a deploy. Not
-- tenant-scoped and not subject to RLS: it is platform state, and it must be
-- readable on every write path regardless of tenant context.
CREATE TABLE outbound_kill_switch (
  id          boolean PRIMARY KEY DEFAULT true CHECK (id),
  halted      boolean NOT NULL DEFAULT false,
  reason      text,
  halted_by   text,
  updated_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO outbound_kill_switch (halted) VALUES (false);

ALTER TABLE outbound_write      ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbound_write      FORCE  ROW LEVEL SECURITY;
ALTER TABLE outbound_rate_limit ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbound_rate_limit FORCE  ROW LEVEL SECURITY;

CREATE POLICY outbound_write_tenant_isolation ON outbound_write
  FOR ALL TO driftless_app
  USING (provider_id = app.current_provider_id())
  WITH CHECK (provider_id = app.current_provider_id());

CREATE POLICY outbound_rate_limit_tenant_isolation ON outbound_rate_limit
  FOR ALL TO driftless_app
  USING (provider_id = app.current_provider_id())
  WITH CHECK (provider_id = app.current_provider_id());

GRANT SELECT, INSERT, UPDATE ON outbound_write, outbound_rate_limit TO driftless_app;
GRANT SELECT ON outbound_kill_switch TO driftless_app;
GRANT EXECUTE ON FUNCTION claim_outbound_write TO driftless_app;
GRANT EXECUTE ON FUNCTION resolve_outbound_write TO driftless_app;
