-- Lessons: scope, expiry, provenance, replay gate, rollback and audit (W3.11).
--
-- Extends the W0.5 skeleton in 48_autonomy_lessons_suppression_retention.sql.
-- Rerunnable: columns use ADD COLUMN IF NOT EXISTS; the CHECK constraints are
-- dropped and re-added NOT VALID on every run (rows written before this file
-- are not rechecked; every new or updated row is), so a database that ran an
-- earlier draft of this file gets the current definitions.
--
-- A lesson may be 'active' only when a replay over labelled historical alerts
-- passed and its report is kept, its provenance is 'analyst' (not traced to
-- alert text the adversary controls, not written by automation), it has an
-- effect and an expiry at most 90 days after creation, a person other than
-- its proposer approved it, and its scope has a sensor-authored anchor: a
-- non-empty string data_source. (core.lessons.model.anchored also accepts a
-- rule_name or mitre_technique that the W1.2 field-provenance maps mark
-- sensor for every source; none do: rule names are adversary, webhook MITRE
-- ids third-party. tests/unit/lessons/test_apply.py pins that.) No lesson may
-- name critical as its max_severity, in any letter case. A retired lesson is
-- final: lessons_status_transition refuses any later write to it. The
-- application enforces the same rules (core/lessons); these are the backstop.
--
-- The per-row value checks (effect, provenance, never critical, source_id)
-- do not hold a retired row: a row written by an earlier draft that breaks a
-- rule added since must still be retirable (rolled back), and a retired row
-- never applies.
--
-- Tenancy: rows carry tenant_id (default 'default'). The API runs single
-- tenant today and SqlLessonStore scopes every read and write to one tenant;
-- the constraints and triggers below hold per row whatever the tenant.

ALTER TABLE lessons ADD COLUMN IF NOT EXISTS effect            TEXT;
ALTER TABLE lessons ADD COLUMN IF NOT EXISTS expires_at        TIMESTAMPTZ;
-- 'system' by default: a row written without saying who wrote it never applies.
ALTER TABLE lessons ADD COLUMN IF NOT EXISTS provenance        TEXT        NOT NULL DEFAULT 'system';
ALTER TABLE lessons ADD COLUMN IF NOT EXISTS provenance_detail JSONB       NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE lessons ADD COLUMN IF NOT EXISTS replay            JSONB;
ALTER TABLE lessons ADD COLUMN IF NOT EXISTS replay_passed     BOOLEAN     NOT NULL DEFAULT FALSE;
ALTER TABLE lessons ADD COLUMN IF NOT EXISTS replayed_at       TIMESTAMPTZ;
ALTER TABLE lessons ADD COLUMN IF NOT EXISTS retired_by        TEXT;
ALTER TABLE lessons ADD COLUMN IF NOT EXISTS retire_reason     TEXT;
-- Optimistic lock: every application write names the version it read.
ALTER TABLE lessons ADD COLUMN IF NOT EXISTS version           INTEGER     NOT NULL DEFAULT 0;

ALTER TABLE lessons DROP CONSTRAINT IF EXISTS lessons_effect_check;
ALTER TABLE lessons ADD CONSTRAINT lessons_effect_check
    CHECK (status = 'retired' OR effect IS NULL OR effect IN ('benign_hint', 'escalate')) NOT VALID;

ALTER TABLE lessons DROP CONSTRAINT IF EXISTS lessons_provenance_check;
ALTER TABLE lessons ADD CONSTRAINT lessons_provenance_check
    CHECK (status = 'retired' OR provenance IN ('analyst', 'adversary_text', 'system')) NOT VALID;

ALTER TABLE lessons DROP CONSTRAINT IF EXISTS lessons_active_gate;
ALTER TABLE lessons ADD CONSTRAINT lessons_active_gate
    CHECK (status <> 'active' OR (
        replay_passed
        AND replay IS NOT NULL
        AND provenance = 'analyst'
        AND effect IS NOT NULL
        AND expires_at IS NOT NULL
        AND expires_at <= created_at + INTERVAL '90 days'
        AND approved_by IS NOT NULL
        AND btrim(approved_by) <> ''
        AND lower(btrim(approved_by)) <> lower(btrim(created_by))
        -- COALESCE: a missing key is NULL, and a NULL CHECK passes.
        AND COALESCE(jsonb_typeof(applies_to->'data_source') = 'string'
                     AND btrim(applies_to->>'data_source') <> '', FALSE)
    )) NOT VALID;

ALTER TABLE lessons DROP CONSTRAINT IF EXISTS lessons_never_critical;
ALTER TABLE lessons ADD CONSTRAINT lessons_never_critical
    CHECK (status = 'retired'
           OR lower(btrim(COALESCE(applies_to->>'max_severity', ''))) <> 'critical') NOT VALID;

ALTER TABLE lessons DROP CONSTRAINT IF EXISTS lessons_retired_has_reason;
ALTER TABLE lessons ADD CONSTRAINT lessons_retired_has_reason
    CHECK (status <> 'retired' OR retire_reason IS NULL OR btrim(retire_reason) <> '') NOT VALID;

-- Every lesson but a manual one names what it came from (a finding, a QA
-- review, an eval case, a canary run).
ALTER TABLE lessons DROP CONSTRAINT IF EXISTS lessons_source_id_required;
ALTER TABLE lessons ADD CONSTRAINT lessons_source_id_required
    CHECK (status = 'retired' OR source_kind = 'manual'
           OR (source_id IS NOT NULL AND btrim(source_id) <> '')) NOT VALID;

-- proposed -> proposed | active | retired; active -> active | retired;
-- retired -> nothing. Once out of 'proposed', what the replay measured
-- (scope, effect, text, expiry, provenance, proposer) and the evidence of
-- its promotion (approver, replay report, provenance detail, source,
-- creation time) are frozen.
CREATE OR REPLACE FUNCTION lessons_status_transition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  IF OLD.status = 'retired' THEN
    RAISE EXCEPTION 'lesson % is retired and cannot change', OLD.id;
  END IF;
  IF OLD.status = 'active' AND NEW.status NOT IN ('active', 'retired') THEN
    RAISE EXCEPTION 'lesson % cannot go from active to %', OLD.id, NEW.status;
  END IF;
  IF OLD.status <> 'proposed' AND (
       NEW.applies_to IS DISTINCT FROM OLD.applies_to
    OR NEW.effect IS DISTINCT FROM OLD.effect
    OR NEW.lesson IS DISTINCT FROM OLD.lesson
    OR NEW.category IS DISTINCT FROM OLD.category
    OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
    OR NEW.provenance IS DISTINCT FROM OLD.provenance
    OR NEW.created_by IS DISTINCT FROM OLD.created_by
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.approved_by IS DISTINCT FROM OLD.approved_by
    OR NEW.approved_at IS DISTINCT FROM OLD.approved_at
    OR NEW.replay IS DISTINCT FROM OLD.replay
    OR NEW.replay_passed IS DISTINCT FROM OLD.replay_passed
    OR NEW.replayed_at IS DISTINCT FROM OLD.replayed_at
    OR NEW.provenance_detail IS DISTINCT FROM OLD.provenance_detail
    OR NEW.source_kind IS DISTINCT FROM OLD.source_kind
    OR NEW.source_id IS DISTINCT FROM OLD.source_id
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
  ) THEN
    RAISE EXCEPTION 'lesson % is %: its definition is frozen', OLD.id, OLD.status;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS lessons_status_transition ON lessons;
CREATE TRIGGER lessons_status_transition
  BEFORE UPDATE ON lessons
  FOR EACH ROW
  EXECUTE FUNCTION lessons_status_transition();

-- Every proposal, replay, promotion (and refused promotion) and rollback.
CREATE TABLE IF NOT EXISTS lesson_events (
    id          BIGSERIAL    PRIMARY KEY,
    tenant_id   TEXT         NOT NULL DEFAULT 'default',
    lesson_id   UUID         NOT NULL REFERENCES lessons (id),
    action      TEXT         NOT NULL
        CONSTRAINT lesson_events_action_check
        CHECK (action IN ('proposed', 'replayed', 'promoted', 'promotion_refused', 'rolled_back')),
    actor       TEXT         NOT NULL
        CONSTRAINT lesson_events_actor_check CHECK (btrim(actor) <> ''),
    at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    detail      JSONB        NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_lesson_events_lesson
    ON lesson_events (tenant_id, lesson_id, id);

CREATE OR REPLACE FUNCTION lesson_events_append_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  RAISE EXCEPTION 'lesson_events is append-only';
END;
$$;

DROP TRIGGER IF EXISTS lesson_events_append_only ON lesson_events;
CREATE TRIGGER lesson_events_append_only
  BEFORE UPDATE OR DELETE ON lesson_events
  FOR EACH ROW
  EXECUTE FUNCTION lesson_events_append_only();

DROP TRIGGER IF EXISTS lesson_events_no_truncate ON lesson_events;
CREATE TRIGGER lesson_events_no_truncate
  BEFORE TRUNCATE ON lesson_events
  FOR EACH STATEMENT
  EXECUTE FUNCTION lesson_events_append_only();

CREATE INDEX IF NOT EXISTS idx_lessons_tenant_status
    ON lessons (tenant_id, status, created_at DESC);

COMMENT ON TABLE lesson_events IS
    'Append-only audit of lesson proposals, replays, promotions and rollbacks (W3.11).';
