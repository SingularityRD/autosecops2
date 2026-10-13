-- Lessons: scope, expiry, provenance, replay gate, rollback and audit (W3.11).
--
-- Extends the W0.5 skeleton in 48_autonomy_lessons_suppression_retention.sql.
-- Rerunnable: columns use ADD COLUMN IF NOT EXISTS, constraints are added only
-- when missing and NOT VALID (rows written before this file are not rechecked;
-- every new or updated row is).
--
-- A lesson may be 'active' only when its replay over labelled historical
-- alerts passed, its provenance is 'analyst' (not traced to alert text the
-- adversary controls, not written by automation), and it has an effect and an
-- expiry. No lesson may name critical as its max_severity. The application
-- enforces the same rules (core/lessons); these constraints are the backstop.

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

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'lessons_effect_check') THEN
        ALTER TABLE lessons ADD CONSTRAINT lessons_effect_check
            CHECK (effect IS NULL OR effect IN ('benign_hint', 'escalate')) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'lessons_provenance_check') THEN
        ALTER TABLE lessons ADD CONSTRAINT lessons_provenance_check
            CHECK (provenance IN ('analyst', 'adversary_text', 'system')) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'lessons_active_gate') THEN
        ALTER TABLE lessons ADD CONSTRAINT lessons_active_gate
            CHECK (status <> 'active' OR (
                replay_passed
                AND provenance = 'analyst'
                AND effect IS NOT NULL
                AND expires_at IS NOT NULL
            )) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'lessons_never_critical') THEN
        ALTER TABLE lessons ADD CONSTRAINT lessons_never_critical
            CHECK (COALESCE(applies_to->>'max_severity', '') <> 'critical') NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'lessons_retired_has_reason') THEN
        ALTER TABLE lessons ADD CONSTRAINT lessons_retired_has_reason
            CHECK (status <> 'retired' OR retire_reason IS NULL OR btrim(retire_reason) <> '') NOT VALID;
    END IF;
END
$$;

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

CREATE INDEX IF NOT EXISTS idx_lessons_tenant_status
    ON lessons (tenant_id, status, created_at DESC);

COMMENT ON TABLE lesson_events IS
    'Append-only audit of lesson proposals, replays, promotions and rollbacks (W3.11).';
