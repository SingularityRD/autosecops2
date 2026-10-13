-- W0.10: two follow-ups on merged work packages. Rerunnable.
--
-- 1. One broadcast row per case event (W1.8).
--    The SLA monitor and the stale-case detector raise an event once: they
--    read "already raised?" and then insert the broadcast row. Two passes
--    racing past that read both inserted. This unique index makes the second
--    insert conflict; core/cases/case_notification_service.py catches it in a
--    savepoint and drops the duplicate.
--
--    case_notifications is created by SQLAlchemy (the model declares the same
--    index), and create_all adds no index to a table that already exists. On
--    a first install the table is not there yet when this file runs and the
--    block below does nothing; create_all then builds the table with the
--    index. scripts/migrate_schema.py covers a database this file never
--    reached, or one where this file's role does not own the table.
--
-- 2. Chain head for regulatory clock events (W3.8).
--    regulatory_clock_events is hash-chained per case, but deleting the last
--    row(s) leaves a shorter chain that still verifies. regulatory_clock_heads
--    keeps the last seq and row hash per case, written only by the insert
--    trigger on regulatory_clock_events (and removed only with the case), so
--    core/compliance/regulatory_service.verify_chain can tell a truncated
--    chain from a short one. An append that does not extend the head (wrong
--    seq or prev_hash, e.g. a row forged after deleting the tail) is
--    remembered in broken_at and never cleared.

DO $$
BEGIN
  IF to_regclass('case_notifications') IS NOT NULL
     AND to_regclass('uq_case_notification_broadcast_event') IS NULL THEN
    -- Rows the race already duplicated: keep the first of each event.
    DELETE FROM case_notifications a
      USING case_notifications b
      WHERE a.user_id = 'system:broadcast'
        AND b.user_id = 'system:broadcast'
        AND a.notification_metadata ->> 'event_key' = b.notification_metadata ->> 'event_key'
        AND a.notification_id > b.notification_id;
    CREATE UNIQUE INDEX uq_case_notification_broadcast_event
      ON case_notifications ((notification_metadata ->> 'event_key'))
      WHERE user_id = 'system:broadcast';
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS regulatory_clock_heads (
    tenant_id   TEXT         NOT NULL DEFAULT 'default',
    case_id     VARCHAR(50)  NOT NULL REFERENCES cases (case_id) ON DELETE CASCADE,
    seq         INTEGER      NOT NULL,
    row_hash    TEXT         NOT NULL,
    broken_at   INTEGER,     -- first seq appended out of sequence; never cleared
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, case_id)
);

-- Advance the head on every appended event.
CREATE OR REPLACE FUNCTION regulatory_clock_heads_advance()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
DECLARE
  head regulatory_clock_heads%ROWTYPE;
BEGIN
  SELECT * INTO head FROM regulatory_clock_heads
    WHERE tenant_id = NEW.tenant_id AND case_id = NEW.case_id
    FOR UPDATE;
  IF NOT FOUND THEN
    INSERT INTO regulatory_clock_heads (tenant_id, case_id, seq, row_hash, broken_at)
    VALUES (
      NEW.tenant_id, NEW.case_id, NEW.seq, NEW.row_hash,
      CASE WHEN NEW.seq = 1 AND NEW.prev_hash = '' THEN NULL ELSE NEW.seq END
    );
  ELSE
    UPDATE regulatory_clock_heads SET
      seq = NEW.seq,
      row_hash = NEW.row_hash,
      broken_at = COALESCE(
        head.broken_at,
        CASE WHEN NEW.seq = head.seq + 1 AND NEW.prev_hash = head.row_hash
             THEN NULL ELSE NEW.seq END
      ),
      updated_at = now()
    WHERE tenant_id = NEW.tenant_id AND case_id = NEW.case_id;
  END IF;
  RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS regulatory_clock_heads_advance ON regulatory_clock_events;
CREATE TRIGGER regulatory_clock_heads_advance
  AFTER INSERT ON regulatory_clock_events
  FOR EACH ROW
  EXECUTE FUNCTION regulatory_clock_heads_advance();

-- Only the trigger above (nested, so pg_trigger_depth() > 1) may move a head,
-- and only the cascade from cases (also nested) may delete one. A direct
-- INSERT is accepted only when it names the case's real last event: that is
-- the backfill below, and harmless otherwise.
CREATE OR REPLACE FUNCTION regulatory_clock_heads_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  IF pg_trigger_depth() > 1 THEN
    RETURN COALESCE(NEW, OLD);
  END IF;
  IF TG_OP = 'INSERT' AND NEW.broken_at IS NULL AND EXISTS (
       SELECT 1 FROM regulatory_clock_events e
        WHERE e.tenant_id = NEW.tenant_id AND e.case_id = NEW.case_id
          AND e.seq = NEW.seq AND e.row_hash = NEW.row_hash
          AND e.seq = (SELECT max(seq) FROM regulatory_clock_events m
                        WHERE m.tenant_id = NEW.tenant_id AND m.case_id = NEW.case_id)) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'regulatory_clock_heads is written only by the regulatory_clock_events trigger';
END;
$$;

DROP TRIGGER IF EXISTS regulatory_clock_heads_guard ON regulatory_clock_heads;
CREATE TRIGGER regulatory_clock_heads_guard
  BEFORE INSERT OR UPDATE OR DELETE ON regulatory_clock_heads
  FOR EACH ROW
  EXECUTE FUNCTION regulatory_clock_heads_guard();

-- Cases that already had events before this file: anchor their current last row.
INSERT INTO regulatory_clock_heads (tenant_id, case_id, seq, row_hash)
SELECT DISTINCT ON (e.tenant_id, e.case_id) e.tenant_id, e.case_id, e.seq, e.row_hash
  FROM regulatory_clock_events e
 WHERE NOT EXISTS (
       SELECT 1 FROM regulatory_clock_heads h
        WHERE h.tenant_id = e.tenant_id AND h.case_id = e.case_id)
 ORDER BY e.tenant_id, e.case_id, e.seq DESC;

COMMENT ON TABLE regulatory_clock_heads IS
    'Last seq and row hash of each case''s regulatory_clock_events chain, kept by trigger, so a deleted tail shows (W0.10).';
