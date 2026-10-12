-- Tamper-evident audit chain for approval decisions and case audit logs (W1.10).
--
-- agent_events already carries its own hash chain (31_agent_ledger_hash_chain.sql).
-- approval_actions and case_audit_logs are ordinary, mutable tables, so their
-- history is copied here: one append-only row per insert / update / delete,
-- written by an AFTER trigger on the source table, chained per tenant:
--
--   event_hash = sha256(prev_hash || CAST(jsonb_build_object(
--       'created_at', <created_at in UTC, ISO 8601, microseconds, 'Z'>,
--       'event', event, 'payload', payload, 'seq', seq,
--       'source_id', source_id, 'source_table', source_table,
--       'tenant_id', tenant_id) AS text))
--
-- prev_hash is '' at seq 1. seq, prev_hash, event_hash and created_at are
-- assigned by the BEFORE INSERT trigger whatever the writer supplied. Writers
-- of one tenant are serialized by a transaction-scoped advisory lock, so two
-- concurrent writers never fork the chain (under REPEATABLE READ the loser
-- fails on the primary key instead of forking).
--
-- Append-only: vigil_app may only SELECT audit_chain (the capture trigger
-- inserts as the function owner), and a trigger refuses UPDATE, DELETE and
-- TRUNCATE for every role. A superuser or the table owner can still disable
-- triggers; that is what the signed checkpoints in audit_checkpoints and
-- `python -m core.audit.verify` detect.
--
-- Where the triggers come from: approval_actions exists when init SQL runs
-- (13_approval_actions.sql), so this file attaches it. case_audit_logs is
-- ORM-owned and only exists once create_all has run, which on a first Compose
-- boot and on Helm's db-init Job is after this file. So this file attaches it
-- only if it is already there and the role running the SQL may; otherwise
-- core/storage/audit_chain.py does it from init_database() after create_all,
-- and scripts/migrate_schema.py on an existing bare-metal database. Every path
-- calls audit_chain_attach(), which is a no-op when the triggers are in place.

CREATE TABLE IF NOT EXISTS audit_chain (
    tenant_id     text        NOT NULL DEFAULT 'default',
    seq           bigint      NOT NULL,
    source_table  text        NOT NULL,
    source_id     text        NOT NULL,
    event         text        NOT NULL,
    payload       jsonb       NOT NULL,
    prev_hash     text        NOT NULL,
    event_hash    text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, seq),
    CONSTRAINT audit_chain_seq_positive CHECK (seq > 0)
);

-- Coverage check in the verifier: latest chain row per source row.
CREATE INDEX IF NOT EXISTS idx_audit_chain_source
    ON audit_chain (source_table, source_id, tenant_id, seq);

COMMENT ON TABLE audit_chain IS
    'Append-only, per-tenant hash chain of approval_actions and case_audit_logs changes. Written only by triggers; verified by python -m core.audit.verify.';
COMMENT ON COLUMN audit_chain.event IS
    'insert / update / delete for a source row change; truncate for a TRUNCATE of the table; snapshot for a row that existed when the table was attached; install / reinstall when the capture triggers were (re)created.';
COMMENT ON COLUMN audit_chain.payload IS
    '{"row": <source row as jsonb>} and, on update, "old": <the changed columns before the update>.';
COMMENT ON COLUMN audit_chain.event_hash IS
    'sha256(prev_hash || canonical row text), assigned on INSERT and never by the caller.';

CREATE TABLE IF NOT EXISTS audit_checkpoints (
    id              bigserial   PRIMARY KEY,
    created_at      timestamptz NOT NULL DEFAULT now(),
    key_id          text        NOT NULL,
    public_key      text        NOT NULL,
    body            text        NOT NULL,
    body_hash       text        NOT NULL,
    prev_body_hash  text        NOT NULL,
    signature       text        NOT NULL,
    tsa_token       text
);

COMMENT ON TABLE audit_checkpoints IS
    'Ed25519-signed chain heads of agent_events and audit_chain, each linked to the previous checkpoint by body_hash. Append-only.';
COMMENT ON COLUMN audit_checkpoints.body IS
    'The exact UTF-8 JSON text that was signed.';
COMMENT ON COLUMN audit_checkpoints.tsa_token IS
    'Base64 RFC 3161 TimeStampResp over sha256(body), when AUDIT_TSA_URL is set. Stored, not validated.';

CREATE OR REPLACE FUNCTION audit_chain_hash(
    prev_hash text,
    tenant_id text,
    seq bigint,
    source_table text,
    source_id text,
    event text,
    payload jsonb,
    created_at timestamptz
)
RETURNS text
LANGUAGE sql
STABLE
SET search_path = public, pg_temp
AS $$
  SELECT encode(
    sha256(convert_to(
      coalesce(prev_hash, '') || CAST(jsonb_build_object(
        'created_at', to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'event', event,
        'payload', payload,
        'seq', seq,
        'source_id', source_id,
        'source_table', source_table,
        'tenant_id', tenant_id
      ) AS text),
      'UTF8'
    )),
    'hex'
  );
$$;

CREATE OR REPLACE FUNCTION audit_chain_assign()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
  head_seq bigint;
  head_hash text;
BEGIN
  NEW.tenant_id := coalesce(NEW.tenant_id, 'default');
  -- One writer per tenant at a time, until commit. The SELECT below is a new
  -- statement, so under READ COMMITTED it sees the head the previous holder
  -- committed.
  PERFORM pg_advisory_xact_lock(hashtextextended('audit_chain:' || NEW.tenant_id, 0));
  SELECT seq, event_hash INTO head_seq, head_hash
    FROM audit_chain
   WHERE tenant_id = NEW.tenant_id
   ORDER BY seq DESC
   LIMIT 1;
  NEW.seq := coalesce(head_seq, 0) + 1;
  NEW.prev_hash := coalesce(head_hash, '');
  NEW.created_at := now();
  NEW.event_hash := audit_chain_hash(
    NEW.prev_hash, NEW.tenant_id, NEW.seq, NEW.source_table, NEW.source_id,
    NEW.event, NEW.payload, NEW.created_at
  );
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS audit_chain_assign ON audit_chain;
CREATE TRIGGER audit_chain_assign
  BEFORE INSERT ON audit_chain
  FOR EACH ROW
  EXECUTE FUNCTION audit_chain_assign();

-- Refuses every change but INSERT, for every role, owner included.
CREATE OR REPLACE FUNCTION audit_chain_forbid_change()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: % is not allowed', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS audit_chain_forbid_change ON audit_chain;
CREATE TRIGGER audit_chain_forbid_change
  BEFORE UPDATE OR DELETE ON audit_chain
  FOR EACH ROW
  EXECUTE FUNCTION audit_chain_forbid_change();

DROP TRIGGER IF EXISTS audit_chain_forbid_truncate ON audit_chain;
CREATE TRIGGER audit_chain_forbid_truncate
  BEFORE TRUNCATE ON audit_chain
  FOR EACH STATEMENT
  EXECUTE FUNCTION audit_chain_forbid_change();

DROP TRIGGER IF EXISTS audit_checkpoints_forbid_change ON audit_checkpoints;
CREATE TRIGGER audit_checkpoints_forbid_change
  BEFORE UPDATE OR DELETE ON audit_checkpoints
  FOR EACH ROW
  EXECUTE FUNCTION audit_chain_forbid_change();

DROP TRIGGER IF EXISTS audit_checkpoints_forbid_truncate ON audit_checkpoints;
CREATE TRIGGER audit_checkpoints_forbid_truncate
  BEFORE TRUNCATE ON audit_checkpoints
  FOR EACH STATEMENT
  EXECUTE FUNCTION audit_chain_forbid_change();

-- The capture trigger on a source table. SECURITY DEFINER so it can insert
-- into audit_chain, which vigil_app may not. TG_ARGV[0] is the key column.
CREATE OR REPLACE FUNCTION audit_chain_capture()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  row_now jsonb;
  row_old jsonb;
  changed jsonb;
  body jsonb;
BEGIN
  -- Only the audited tables: anyone with CREATE on the schema could otherwise
  -- point this trigger at a table of their own and write chain rows at will.
  IF TG_TABLE_SCHEMA <> 'public'
     OR TG_TABLE_NAME NOT IN ('approval_actions', 'case_audit_logs') THEN
    RAISE EXCEPTION 'audit_chain_capture: %.% is not an audited table',
      TG_TABLE_SCHEMA, TG_TABLE_NAME;
  END IF;
  IF TG_OP = 'DELETE' THEN
    row_now := to_jsonb(OLD);
  ELSE
    row_now := to_jsonb(NEW);
  END IF;
  body := jsonb_build_object('row', row_now);
  IF TG_OP = 'UPDATE' THEN
    row_old := to_jsonb(OLD);
    SELECT coalesce(jsonb_object_agg(o.key, o.value), '{}'::jsonb) INTO changed
      FROM jsonb_each(row_old) AS o
     WHERE row_now -> o.key IS DISTINCT FROM o.value;
    body := body || jsonb_build_object('old', changed);
  END IF;
  INSERT INTO audit_chain (tenant_id, source_table, source_id, event, payload,
                           seq, prev_hash, event_hash)
  VALUES (coalesce(row_now ->> 'tenant_id', 'default'), TG_TABLE_NAME,
          coalesce(row_now ->> TG_ARGV[0], ''), lower(TG_OP), body,
          0, '', '');
  RETURN NULL;
END;
$$;

-- TRUNCATE fires no row triggers, so it is chained as one 'truncate' marker:
-- every row of the table chained before it counts as deleted. The marker goes
-- to the default tenant, which is every row's tenant while the audited tables
-- carry no tenant_id column.
CREATE OR REPLACE FUNCTION audit_chain_capture_truncate()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  IF TG_TABLE_SCHEMA <> 'public'
     OR TG_TABLE_NAME NOT IN ('approval_actions', 'case_audit_logs') THEN
    RAISE EXCEPTION 'audit_chain_capture_truncate: %.% is not an audited table',
      TG_TABLE_SCHEMA, TG_TABLE_NAME;
  END IF;
  INSERT INTO audit_chain (source_table, source_id, event, payload, seq, prev_hash, event_hash)
  VALUES (TG_TABLE_NAME, '', 'truncate', '{}'::jsonb, 0, '', '');
  RETURN NULL;
END;
$$;

-- Records that the capture triggers on p_table were just (re)created. On the
-- table's first attach it also chains every existing row as a snapshot, from
-- p_rows, which the caller (the table's owner) read under a lock: the definer
-- may not be able to read a table vigil_app owns. Once a table has any chain
-- row, later calls write only a 'reinstall' marker and ignore p_rows, so rows
-- written while the triggers were missing are never laundered into the chain.
CREATE OR REPLACE FUNCTION audit_chain_record_install(p_table text, p_key text, p_rows jsonb)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  r jsonb;
  n integer := 0;
BEGIN
  IF p_table NOT IN ('approval_actions', 'case_audit_logs') THEN
    RAISE EXCEPTION 'audit_chain_record_install: % is not an audited table', p_table;
  END IF;
  IF (SELECT count(*) FROM pg_trigger
       WHERE tgrelid = to_regclass(p_table)
         AND tgname IN ('audit_chain_capture', 'audit_chain_capture_update',
                        'audit_chain_capture_truncate')
         AND tgenabled <> 'D') <> 3 THEN
    RAISE EXCEPTION 'audit_chain_record_install: capture triggers are not on %', p_table;
  END IF;
  IF EXISTS (SELECT 1 FROM audit_chain WHERE source_table = p_table) THEN
    INSERT INTO audit_chain (source_table, source_id, event, payload, seq, prev_hash, event_hash)
    VALUES (p_table, '', 'reinstall', jsonb_build_object('key', p_key), 0, '', '');
    RETURN 'reinstall';
  END IF;
  n := coalesce(jsonb_array_length(p_rows), 0);
  INSERT INTO audit_chain (source_table, source_id, event, payload, seq, prev_hash, event_hash)
  VALUES (p_table, '', 'install', jsonb_build_object('key', p_key, 'rows', n), 0, '', '');
  FOR r IN SELECT value FROM jsonb_array_elements(coalesce(p_rows, '[]'::jsonb)) LOOP
    INSERT INTO audit_chain (tenant_id, source_table, source_id, event, payload,
                             seq, prev_hash, event_hash)
    VALUES (coalesce(r ->> 'tenant_id', 'default'), p_table, coalesce(r ->> p_key, ''),
            'snapshot', jsonb_build_object('row', r), 0, '', '');
  END LOOP;
  RETURN 'install';
END;
$$;

-- Puts the capture triggers on p_table unless all three are already there and
-- enabled. Runs as the caller, who must own the table. Returns NULL when
-- nothing was needed, else what audit_chain_record_install recorded.
CREATE OR REPLACE FUNCTION audit_chain_attach(p_table regclass, p_key text)
RETURNS text
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
DECLARE
  v_name text;
  v_rows jsonb := '[]'::jsonb;
BEGIN
  SELECT relname INTO v_name FROM pg_class WHERE oid = p_table;
  IF (SELECT count(*) FROM pg_trigger
       WHERE tgrelid = p_table
         AND tgname IN ('audit_chain_capture', 'audit_chain_capture_update',
                        'audit_chain_capture_truncate')
         AND tgenabled <> 'D') = 3 THEN
    RETURN NULL;
  END IF;
  -- No writes to the table between reading its rows and the triggers taking
  -- over, and one attach at a time.
  EXECUTE format('LOCK TABLE %s IN SHARE ROW EXCLUSIVE MODE', p_table);
  EXECUTE format('DROP TRIGGER IF EXISTS audit_chain_capture ON %s', p_table);
  EXECUTE format('DROP TRIGGER IF EXISTS audit_chain_capture_update ON %s', p_table);
  EXECUTE format('DROP TRIGGER IF EXISTS audit_chain_capture_truncate ON %s', p_table);
  EXECUTE format(
    'CREATE TRIGGER audit_chain_capture AFTER INSERT OR DELETE ON %s '
    'FOR EACH ROW EXECUTE FUNCTION audit_chain_capture(%L)', p_table, p_key);
  EXECUTE format(
    'CREATE TRIGGER audit_chain_capture_update AFTER UPDATE ON %s '
    'FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) '
    'EXECUTE FUNCTION audit_chain_capture(%L)', p_table, p_key);
  EXECUTE format(
    'CREATE TRIGGER audit_chain_capture_truncate AFTER TRUNCATE ON %s '
    'FOR EACH STATEMENT EXECUTE FUNCTION audit_chain_capture_truncate()', p_table);
  IF NOT EXISTS (SELECT 1 FROM audit_chain WHERE source_table = v_name) THEN
    EXECUTE format(
      'SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.%I), ''[]''::jsonb) FROM %s AS t',
      p_key, p_table) INTO v_rows;
  END IF;
  RETURN audit_chain_record_install(v_name, p_key, v_rows);
END;
$$;

-- Privileges. Default privileges from 30_vigil_app_role.sql granted vigil_app
-- SELECT, INSERT, UPDATE, DELETE on these new tables, and Compose re-runs 30's
-- GRANT ... ON ALL TABLES on every up; this file runs after it each time and
-- takes back all but what vigil_app needs. The forbid triggers above hold
-- whatever the grants say.
REVOKE ALL ON TABLE audit_chain FROM PUBLIC;
REVOKE ALL ON TABLE audit_checkpoints FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION audit_chain_record_install(text, text, jsonb) FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vigil_app') THEN
    REVOKE ALL ON TABLE audit_chain FROM vigil_app;
    GRANT SELECT ON TABLE audit_chain TO vigil_app;
    REVOKE ALL ON TABLE audit_checkpoints FROM vigil_app;
    GRANT SELECT, INSERT ON TABLE audit_checkpoints TO vigil_app;
    GRANT USAGE, SELECT ON SEQUENCE audit_checkpoints_id_seq TO vigil_app;
    GRANT EXECUTE ON FUNCTION audit_chain_record_install(text, text, jsonb) TO vigil_app;
  END IF;
END
$$;

-- Attach what is here and ours to attach. A table this role does not own
-- (case_audit_logs built by create_all as vigil_app on Helm) is left to
-- core/storage/audit_chain.py, which runs as that owner.
DO $$
DECLARE
  src record;
BEGIN
  FOR src IN SELECT * FROM (VALUES ('approval_actions', 'action_id'),
                                   ('case_audit_logs', 'audit_id')) AS s (tbl, key)
  LOOP
    IF to_regclass(src.tbl) IS NOT NULL THEN
      BEGIN
        PERFORM audit_chain_attach(to_regclass(src.tbl), src.key);
      EXCEPTION WHEN insufficient_privilege THEN
        RAISE NOTICE 'audit_chain: % left for the schema setup to attach: %', src.tbl, SQLERRM;
      END;
    END IF;
  END LOOP;
END
$$;
