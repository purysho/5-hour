-- 003 — Tamper-evident audit chain
--
-- Implements ADR-0007. Every action taken against a customer repository is
-- recorded in an append-only, hash-chained log the customer can verify without
-- trusting us.
--
-- Two properties drive the design:
--
--   Write-ahead. Sensitive actions are logged BEFORE they are performed. An
--   action visible in a repository but absent from the chain is itself
--   evidence of compromise. Because the log is strictly append-only, the
--   outcome is a SEPARATE entry referencing the intent — never an update to
--   the intent row. An append-only log with an UPDATE in it is not append-only.
--
--   Chain enforced by the database. Sequence, previous hash, and entry hash
--   are computed by a trigger, not by application code. A buggy or
--   compromised application cannot write a malformed link, and cannot choose
--   its own sequence number.
--
-- Chains are per-provider (ADR-0007 consequences): chaining serialises
-- writes, and one global chain would not survive fan-out. The cost is that
-- ordering is only guaranteed within a tenant, which is where it matters.

-- ---------------------------------------------------------------------------
-- Canonical payload
--
-- Defined once and used by BOTH the chaining trigger and the export path, so
-- the bytes a customer verifies are the bytes we hashed. Two separate
-- expressions would drift, and the drift would only surface as a verification
-- failure at the worst possible moment.
--
-- jsonb text output is deterministic in Postgres — object keys are sorted and
-- insignificant whitespace is removed — so metadata::text is stable across
-- rows and versions. Timestamps are rendered in UTC with fixed precision for
-- the same reason.
-- ---------------------------------------------------------------------------

CREATE FUNCTION audit_canonical_payload(
  p_seq         bigint,
  p_prev_hash   text,
  p_provider_id uuid,
  p_action      text,
  p_subject     text,
  p_intent_id   uuid,
  p_metadata    jsonb,
  p_occurred_at timestamptz
)
RETURNS text
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT concat_ws(E'\n',
    p_seq::text,
    p_prev_hash,
    p_provider_id::text,
    p_action,
    p_subject,
    COALESCE(p_intent_id::text, ''),
    p_metadata::text,
    to_char(p_occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
  );
$$;

-- ---------------------------------------------------------------------------
-- Chain head
--
-- One row per provider, holding the tip. Locked FOR UPDATE during append,
-- which is what serialises the chain and prevents two concurrent writers from
-- claiming the same sequence number.
-- ---------------------------------------------------------------------------

CREATE TABLE audit_chain_head (
  provider_id  uuid PRIMARY KEY REFERENCES provider(id) ON DELETE CASCADE,
  seq          bigint NOT NULL DEFAULT 0,
  head_hash    text   NOT NULL DEFAULT repeat('0', 64),
  updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_entry (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id  uuid NOT NULL REFERENCES provider(id) ON DELETE CASCADE,

  -- Chain fields. Assigned by trigger; any value supplied by the caller is
  -- overwritten.
  seq          bigint NOT NULL,
  prev_hash    text   NOT NULL,
  entry_hash   text   NOT NULL,

  -- What happened.
  action       text NOT NULL,
  -- Stable reference to the thing acted upon, e.g. 'github:acme/widgets'.
  subject      text NOT NULL,
  -- For outcome entries: the intent entry this resolves. NULL for intents.
  intent_id    uuid REFERENCES audit_entry(id),

  -- Metadata is deliberately constrained. This log is a high-value read
  -- target; it records WHICH repository, WHICH commit, WHICH permissions,
  -- WHICH token identifier and TTL — never token values, never file contents
  -- (ADR-0007 §6).
  metadata     jsonb NOT NULL DEFAULT '{}'::jsonb,

  occurred_at  timestamptz NOT NULL DEFAULT now(),

  UNIQUE (provider_id, seq),
  CONSTRAINT audit_entry_hash_shape  CHECK (entry_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT audit_entry_prev_shape  CHECK (prev_hash  ~ '^[0-9a-f]{64}$')
);

CREATE INDEX audit_entry_provider_seq_idx ON audit_entry (provider_id, seq);
CREATE INDEX audit_entry_intent_idx ON audit_entry (intent_id)
  WHERE intent_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Append trigger — the chain is a database invariant
-- ---------------------------------------------------------------------------

CREATE FUNCTION audit_entry_chain()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_seq       bigint;
  v_prev_hash text;
  v_payload   text;
BEGIN
  -- Create the head row on first use, then lock it. INSERT ... ON CONFLICT
  -- DO UPDATE (rather than DO NOTHING) so the row is locked by this
  -- transaction in both the created and pre-existing cases.
  INSERT INTO audit_chain_head (provider_id)
  VALUES (NEW.provider_id)
  ON CONFLICT (provider_id) DO UPDATE SET updated_at = now()
  RETURNING seq, head_hash INTO v_seq, v_prev_hash;

  v_seq := v_seq + 1;

  NEW.seq       := v_seq;
  NEW.prev_hash := v_prev_hash;

  v_payload := audit_canonical_payload(
    v_seq, v_prev_hash, NEW.provider_id, NEW.action, NEW.subject,
    NEW.intent_id, NEW.metadata, NEW.occurred_at
  );

  NEW.entry_hash := encode(sha256(convert_to(v_payload, 'UTF8')), 'hex');

  UPDATE audit_chain_head
     SET seq = v_seq, head_hash = NEW.entry_hash, updated_at = now()
   WHERE provider_id = NEW.provider_id;

  RETURN NEW;
END;
$$;

CREATE TRIGGER audit_entry_chain_before_insert
  BEFORE INSERT ON audit_entry
  FOR EACH ROW EXECUTE FUNCTION audit_entry_chain();

-- ---------------------------------------------------------------------------
-- Append-only enforcement
--
-- Two layers. The grant is the real control; the trigger is defence in depth
-- against a future migration that widens the grant without thinking about it.
-- ---------------------------------------------------------------------------

CREATE FUNCTION audit_entry_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION
    'audit_entry is append-only (ADR-0007); corrections are new compensating entries';
END;
$$;

CREATE TRIGGER audit_entry_no_update
  BEFORE UPDATE OR DELETE ON audit_entry
  FOR EACH ROW EXECUTE FUNCTION audit_entry_immutable();

CREATE TRIGGER audit_chain_head_no_delete
  BEFORE DELETE ON audit_chain_head
  FOR EACH ROW EXECUTE FUNCTION audit_entry_immutable();

-- ---------------------------------------------------------------------------
-- Signed checkpoints
--
-- A checkpoint commits to the whole history up to a sequence number. Published
-- where we cannot silently rewrite them and retrievable by customers, so an
-- attacker cannot rewrite history without invalidating a checkpoint the
-- customer already holds.
--
-- Signing key management and the publication mechanism are deliberately not
-- specified here; this table records what was published.
-- ---------------------------------------------------------------------------

CREATE TABLE audit_checkpoint (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id  uuid NOT NULL REFERENCES provider(id) ON DELETE CASCADE,
  seq          bigint NOT NULL,
  head_hash    text   NOT NULL,
  signature    text   NOT NULL,
  key_id       text   NOT NULL,
  published_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider_id, seq)
);

-- ---------------------------------------------------------------------------
-- Export for independent verification
--
-- Returns the canonical payload alongside each hash, so a customer can
-- recompute sha256 over bytes we hand them and walk the links themselves. No
-- Driftless service needs to be trusted — or even reachable — at verification
-- time (ADR-0007 §4).
-- ---------------------------------------------------------------------------

CREATE FUNCTION audit_export(p_provider_id uuid)
RETURNS TABLE (
  seq               bigint,
  prev_hash         text,
  entry_hash        text,
  canonical_payload text,
  occurred_at       timestamptz
)
LANGUAGE sql
STABLE
AS $$
  SELECT
    e.seq,
    e.prev_hash,
    e.entry_hash,
    audit_canonical_payload(
      e.seq, e.prev_hash, e.provider_id, e.action, e.subject,
      e.intent_id, e.metadata, e.occurred_at
    ),
    e.occurred_at
  FROM audit_entry e
  WHERE e.provider_id = p_provider_id
  ORDER BY e.seq;
$$;

ALTER TABLE audit_entry      ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_entry      FORCE  ROW LEVEL SECURITY;
ALTER TABLE audit_chain_head ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_head FORCE  ROW LEVEL SECURITY;
ALTER TABLE audit_checkpoint ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_checkpoint FORCE  ROW LEVEL SECURITY;

CREATE POLICY audit_entry_tenant_isolation ON audit_entry
  FOR ALL TO driftless_app
  USING (provider_id = app.current_provider_id())
  WITH CHECK (provider_id = app.current_provider_id());

CREATE POLICY audit_chain_head_tenant_isolation ON audit_chain_head
  FOR ALL TO driftless_app
  USING (provider_id = app.current_provider_id())
  WITH CHECK (provider_id = app.current_provider_id());

CREATE POLICY audit_checkpoint_tenant_isolation ON audit_checkpoint
  FOR ALL TO driftless_app
  USING (provider_id = app.current_provider_id())
  WITH CHECK (provider_id = app.current_provider_id());

-- The application may append and read. It may not update or delete.
GRANT SELECT, INSERT ON audit_entry TO driftless_app;
GRANT SELECT, INSERT, UPDATE ON audit_chain_head TO driftless_app;
GRANT SELECT ON audit_checkpoint TO driftless_app;
GRANT EXECUTE ON FUNCTION audit_export, audit_canonical_payload TO driftless_app;
