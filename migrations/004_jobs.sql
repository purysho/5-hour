-- 004 — Durable job execution
--
-- Implements ADR-0009, which closes the engine question left open by ADR-0004.
--
-- Three mechanisms:
--   leased dequeue      a dead worker's job returns to the queue, never lost
--   step memoisation    a completed side effect is never re-executed on retry
--   bounded retry       backoff with jitter, then a terminal dead state
--
-- Step memoisation is the load-bearing one. Without it, "retry the job" means
-- "redo the side effects", which is the duplicate-PR failure in
-- threat-model §5.6 arriving by a different route than the one ADR-0004
-- closed.

CREATE TYPE job_status AS ENUM (
  'pending',   -- waiting for run_at
  'running',   -- leased by a worker
  'succeeded',
  'failed',    -- will be retried
  'dead',      -- attempt ceiling reached; terminal
  'cancelled'
);

CREATE TABLE job (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id   uuid NOT NULL REFERENCES provider(id) ON DELETE CASCADE,

  workflow      text NOT NULL,
  input         jsonb NOT NULL DEFAULT '{}'::jsonb,

  status        job_status NOT NULL DEFAULT 'pending',
  priority      integer NOT NULL DEFAULT 100,

  attempts      integer NOT NULL DEFAULT 0,
  max_attempts  integer NOT NULL DEFAULT 5,

  run_at        timestamptz NOT NULL DEFAULT now(),
  leased_by     text,
  lease_expires_at timestamptz,

  result        jsonb,
  last_error    text,

  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  finished_at   timestamptz,

  -- Optional deduplication for enqueue itself. Distinct from the outbound
  -- write idempotency key: this stops two webhooks creating two jobs, while
  -- the other stops two jobs creating two pull requests. Both are needed —
  -- neither subsumes the other.
  dedupe_key    text,

  CONSTRAINT job_attempts_sane CHECK (attempts >= 0 AND max_attempts > 0),
  CONSTRAINT job_lease_coherent CHECK (
    (status = 'running' AND leased_by IS NOT NULL AND lease_expires_at IS NOT NULL)
    OR (status <> 'running')
  ),
  CONSTRAINT job_terminal_finished CHECK (
    (status IN ('succeeded', 'dead', 'cancelled') AND finished_at IS NOT NULL)
    OR (status NOT IN ('succeeded', 'dead', 'cancelled'))
  )
);

CREATE UNIQUE INDEX job_dedupe_key_idx
  ON job (provider_id, workflow, dedupe_key)
  WHERE dedupe_key IS NOT NULL;

-- The dequeue path. Partial so the index stays small as completed jobs
-- accumulate — the queue is scanned constantly and the backlog is not.
CREATE INDEX job_runnable_idx
  ON job (priority, run_at)
  WHERE status IN ('pending', 'failed');

CREATE INDEX job_lease_reclaim_idx
  ON job (lease_expires_at)
  WHERE status = 'running';

CREATE INDEX job_provider_status_idx ON job (provider_id, status);

-- ---------------------------------------------------------------------------
-- Step memoisation
--
-- One row per completed step. The unique constraint is what makes a step
-- exactly-once within a job: a concurrent or repeated attempt to record the
-- same step conflicts rather than producing a second execution record.
--
-- `result` is nullable because a step may legitimately return nothing;
-- `completed_at` is what marks it done.
-- ---------------------------------------------------------------------------

CREATE TABLE job_step (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id       uuid NOT NULL REFERENCES job(id) ON DELETE CASCADE,
  provider_id  uuid NOT NULL REFERENCES provider(id) ON DELETE CASCADE,
  step_key     text NOT NULL,
  result       jsonb,
  attempt      integer NOT NULL,
  completed_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (job_id, step_key)
);

COMMENT ON TABLE job_step IS
  'ADR-0009: completed steps are never re-executed. This is what makes retry safe.';

-- ---------------------------------------------------------------------------
-- Enqueue
-- ---------------------------------------------------------------------------

CREATE FUNCTION enqueue_job(
  p_provider_id  uuid,
  p_workflow     text,
  p_input        jsonb DEFAULT '{}'::jsonb,
  p_dedupe_key   text DEFAULT NULL,
  p_run_at       timestamptz DEFAULT now(),
  p_max_attempts integer DEFAULT 5,
  p_priority     integer DEFAULT 100
)
RETURNS TABLE (job_id uuid, created boolean)
LANGUAGE plpgsql
AS $$
DECLARE
  v_id uuid;
BEGIN
  INSERT INTO job (provider_id, workflow, input, dedupe_key, run_at,
                   max_attempts, priority)
  VALUES (p_provider_id, p_workflow, p_input, p_dedupe_key, p_run_at,
          p_max_attempts, p_priority)
  ON CONFLICT DO NOTHING
  RETURNING id INTO v_id;

  IF v_id IS NOT NULL THEN
    RETURN QUERY SELECT v_id, true;
    RETURN;
  END IF;

  SELECT id INTO v_id
  FROM job
  WHERE provider_id = p_provider_id
    AND workflow = p_workflow
    AND dedupe_key = p_dedupe_key;

  RETURN QUERY SELECT v_id, false;
END;
$$;

-- ---------------------------------------------------------------------------
-- Dequeue
--
-- SKIP LOCKED is what lets many workers poll the same queue without
-- serialising on the head of it.
--
-- Expired leases are reclaimed in the same statement as ordinary pickup: a
-- job whose worker died is, from the queue's point of view, simply runnable
-- again. Treating reclaim as a separate sweeper process is a common design
-- and a needless one — it adds a component that can itself fail.
-- ---------------------------------------------------------------------------

CREATE FUNCTION dequeue_jobs(
  p_worker_id  text,
  p_workflows  text[],
  p_limit      integer DEFAULT 1,
  p_lease      interval DEFAULT interval '5 minutes'
)
RETURNS SETOF job
LANGUAGE sql
AS $$
  WITH claimed AS (
    SELECT id
    FROM job
    WHERE workflow = ANY(p_workflows)
      AND (
        (status IN ('pending', 'failed') AND run_at <= now())
        OR (status = 'running' AND lease_expires_at < now())
      )
    ORDER BY priority, run_at
    FOR UPDATE SKIP LOCKED
    LIMIT p_limit
  )
  UPDATE job
     SET status           = 'running',
         attempts         = job.attempts + 1,
         leased_by        = p_worker_id,
         lease_expires_at = now() + p_lease,
         updated_at       = now()
   WHERE id IN (SELECT id FROM claimed)
  RETURNING job.*;
$$;

-- A worker still working renews its lease. A worker that has died stops,
-- and the job becomes runnable again without anyone having to notice.
CREATE FUNCTION heartbeat_job(
  p_job_id    uuid,
  p_worker_id text,
  p_lease     interval DEFAULT interval '5 minutes'
)
RETURNS boolean
LANGUAGE sql
AS $$
  UPDATE job
     SET lease_expires_at = now() + p_lease, updated_at = now()
   WHERE id = p_job_id
     AND leased_by = p_worker_id
     AND status = 'running'
  RETURNING true;
$$;

-- ---------------------------------------------------------------------------
-- Completion
--
-- Both paths check `leased_by`, so a worker whose lease expired and was
-- reclaimed by someone else cannot report an outcome for a job it no longer
-- owns. Without that check, a slow worker returning from the dead overwrites
-- the result of the worker that actually finished the job.
-- ---------------------------------------------------------------------------

CREATE FUNCTION complete_job(
  p_job_id    uuid,
  p_worker_id text,
  p_result    jsonb DEFAULT NULL
)
RETURNS boolean
LANGUAGE sql
AS $$
  UPDATE job
     SET status = 'succeeded', result = p_result, finished_at = now(),
         leased_by = NULL, lease_expires_at = NULL, updated_at = now()
   WHERE id = p_job_id AND leased_by = p_worker_id AND status = 'running'
  RETURNING true;
$$;

-- Backoff is computed here rather than by the caller so every worker, in every
-- language, retries on the same schedule.
--
-- Jitter is not decoration. Without it a provider outage produces synchronised
-- retries from every worker at once, and the recovery attempt becomes a second
-- outage.
CREATE FUNCTION fail_job(
  p_job_id    uuid,
  p_worker_id text,
  p_error     text,
  p_base_delay interval DEFAULT interval '10 seconds'
)
RETURNS job_status
LANGUAGE plpgsql
AS $$
DECLARE
  v_job    job;
  v_status job_status;
  v_delay  interval;
BEGIN
  SELECT * INTO v_job
  FROM job
  WHERE id = p_job_id AND leased_by = p_worker_id AND status = 'running'
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  IF v_job.attempts >= v_job.max_attempts THEN
    UPDATE job
       SET status = 'dead', last_error = p_error, finished_at = now(),
           leased_by = NULL, lease_expires_at = NULL, updated_at = now()
     WHERE id = p_job_id;
    RETURN 'dead';
  END IF;

  -- Exponential, capped at one hour, with up to 25% jitter.
  v_delay := LEAST(
    p_base_delay * power(2, v_job.attempts)::double precision,
    interval '1 hour'
  );
  v_delay := v_delay * (1 + random() * 0.25);

  UPDATE job
     SET status = 'failed', last_error = p_error, run_at = now() + v_delay,
         leased_by = NULL, lease_expires_at = NULL, updated_at = now()
   WHERE id = p_job_id;

  v_status := 'failed';
  RETURN v_status;
END;
$$;

CREATE FUNCTION record_job_step(
  p_job_id      uuid,
  p_provider_id uuid,
  p_step_key    text,
  p_result      jsonb,
  p_attempt     integer
)
RETURNS TABLE (recorded boolean, result jsonb)
LANGUAGE plpgsql
AS $$
DECLARE
  v_existing jsonb;
  v_found    boolean;
BEGIN
  INSERT INTO job_step (job_id, provider_id, step_key, result, attempt)
  VALUES (p_job_id, p_provider_id, p_step_key, p_result, p_attempt)
  ON CONFLICT (job_id, step_key) DO NOTHING;

  IF FOUND THEN
    RETURN QUERY SELECT true, p_result;
    RETURN;
  END IF;

  -- Lost the race, or this is a retry. Either way the recorded result wins:
  -- it corresponds to a side effect that actually happened.
  SELECT js.result INTO v_existing
  FROM job_step js
  WHERE js.job_id = p_job_id AND js.step_key = p_step_key;

  v_found := false;
  RETURN QUERY SELECT v_found, v_existing;
END;
$$;

ALTER TABLE job      ENABLE ROW LEVEL SECURITY;
ALTER TABLE job      FORCE  ROW LEVEL SECURITY;
ALTER TABLE job_step ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_step FORCE  ROW LEVEL SECURITY;

CREATE POLICY job_tenant_isolation ON job
  FOR ALL TO driftless_app
  USING (provider_id = app.current_provider_id())
  WITH CHECK (provider_id = app.current_provider_id());

CREATE POLICY job_step_tenant_isolation ON job_step
  FOR ALL TO driftless_app
  USING (provider_id = app.current_provider_id())
  WITH CHECK (provider_id = app.current_provider_id());

-- The platform role's cross-tenant access is granted by an explicit policy,
-- not by BYPASSRLS. The distinction matters: BYPASSRLS is invisible in the
-- schema and applies to every table forever, whereas a policy names the two
-- tables it covers and shows up in the same place a reviewer already looks.
--
-- driftless_admin still holds no policy on provider, consumer, repository,
-- installation, upstream_change, outbound_write or audit_entry — so even the
-- platform role cannot read tenant data through this path. It can move jobs
-- through the queue and nothing more.
CREATE POLICY job_platform_access ON job
  FOR ALL TO driftless_admin
  USING (true)
  WITH CHECK (true);

CREATE POLICY job_step_platform_access ON job_step
  FOR ALL TO driftless_admin
  USING (true)
  WITH CHECK (true);

-- ---------------------------------------------------------------------------
-- Grants
--
-- Dequeue is the one genuinely cross-tenant operation in the system: a worker
-- polls a shared queue and cannot know which tenant's job it will receive, so
-- it cannot have tenant context set beforehand.
--
-- Rather than weaken the RLS policies to accommodate that, dequeue is confined
-- to the platform role (ADR-0005 §6). The worker's shape is therefore:
--
--   withPlatformContext  → dequeue, learn the job's provider_id
--   withTenant(that id)  → execute every step under tenant isolation
--
-- Execution — where untrusted input is handled and outbound writes are
-- claimed — is fully tenant-scoped. Only the act of picking a job off the
-- queue is not, and that is the narrowest cross-tenant surface available.
-- ---------------------------------------------------------------------------

GRANT SELECT, INSERT, UPDATE ON job, job_step TO driftless_app;
GRANT SELECT, INSERT, UPDATE ON job, job_step TO driftless_admin;

GRANT EXECUTE ON FUNCTION enqueue_job, heartbeat_job, complete_job, fail_job,
  record_job_step TO driftless_app;

-- Platform-only. A worker holding driftless_app cannot drain other tenants'
-- queues even if a bug tried to.
GRANT EXECUTE ON FUNCTION dequeue_jobs TO driftless_admin;
GRANT EXECUTE ON FUNCTION heartbeat_job, complete_job, fail_job TO driftless_admin;
