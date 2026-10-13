-- Regulatory notification clocks (DORA, NIS2) and report drafts per case (W3.8).
--
-- SQL-owned like 46_eval_qa_canary.sql and 48_*.sql: no ORM model, so
-- create_all and the startup drift check leave these tables alone, and every
-- install gets them from this file (Compose re-applies the directory, Helm's
-- db-init Job runs the mirror under infra/helm/vigil/files/database-init/,
-- bare metal runs it through scripts/seed_reference_data.py). Rerunnable.
--
-- Read and written by core/compliance/regulatory_service.py; the clock
-- arithmetic is core/compliance/clocks.py.

-- Per-tenant settings. durations holds only overrides of the defaults in
-- clocks.DEFAULT_DURATIONS, as {"dora.initial_after_classification": {"hours": 4, "months": 0}, ...}.
-- No row: the defaults and Europe/Istanbul.
CREATE TABLE IF NOT EXISTS regulatory_clock_config (
    tenant_id   TEXT         PRIMARY KEY DEFAULT 'default',
    timezone    TEXT         NOT NULL DEFAULT 'Europe/Istanbul',
    durations   JSONB        NOT NULL DEFAULT '{}'::jsonb
        CONSTRAINT regulatory_clock_config_durations_object
        CHECK (jsonb_typeof(durations) = 'object'),
    updated_by  TEXT         NOT NULL,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Every set, change or clear of a start instant, appended, never updated.
--   value           the instant from now on; NULL clears it
--   previous_value  what it replaced; a change or clear of a recorded value
--                   must carry a reason
--   prev_hash,      sha256 chain over the case's rows in seq order, computed by
--   row_hash        regulatory_service.event_hash; prev_hash is '' at seq 1
-- Rows go with their case (ON DELETE CASCADE) so case deletion and retention
-- keep working; UPDATE is refused by the trigger below.
CREATE TABLE IF NOT EXISTS regulatory_clock_events (
    id              BIGSERIAL    PRIMARY KEY,
    tenant_id       TEXT         NOT NULL DEFAULT 'default',
    case_id         VARCHAR(50)  NOT NULL REFERENCES cases (case_id) ON DELETE CASCADE,
    seq             INTEGER      NOT NULL CONSTRAINT regulatory_clock_events_seq_check CHECK (seq > 0),
    regime          TEXT         NOT NULL,
    instant         TEXT         NOT NULL,
    value           TIMESTAMPTZ,
    previous_value  TIMESTAMPTZ,
    actor           TEXT         NOT NULL CONSTRAINT regulatory_clock_events_actor_check CHECK (btrim(actor) <> ''),
    reason          TEXT,
    recorded_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    prev_hash       TEXT         NOT NULL,
    row_hash        TEXT         NOT NULL,
    CONSTRAINT regulatory_clock_events_case_seq UNIQUE (tenant_id, case_id, seq),
    CONSTRAINT regulatory_clock_events_instant_check CHECK (
        (regime = 'dora' AND instant IN
            ('aware_at', 'classification_at', 'notified_at', 'last_intermediate_at', 'final_at'))
        OR (regime = 'nis2' AND instant IN
            ('aware_at', 'early_warning_at', 'notified_at', 'final_at'))
    ),
    CONSTRAINT regulatory_clock_events_change_needs_reason CHECK (
        previous_value IS NULL OR (reason IS NOT NULL AND btrim(reason) <> '')
    )
);

CREATE INDEX IF NOT EXISTS idx_regulatory_clock_events_case
    ON regulatory_clock_events (tenant_id, case_id, seq);

CREATE OR REPLACE FUNCTION regulatory_clock_events_no_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  RAISE EXCEPTION 'regulatory_clock_events is append-only: record a new event instead';
END;
$$;

DROP TRIGGER IF EXISTS regulatory_clock_events_no_update ON regulatory_clock_events;
CREATE TRIGGER regulatory_clock_events_no_update
  BEFORE UPDATE ON regulatory_clock_events
  FOR EACH ROW
  EXECUTE FUNCTION regulatory_clock_events_no_update();

-- Generated report drafts. body is the whole draft (sections, cites, markdown);
-- cited_ids are the evidence pack ids it cites, pack_digest the pack's sha256.
CREATE TABLE IF NOT EXISTS regulatory_report_drafts (
    draft_id     UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    TEXT         NOT NULL DEFAULT 'default',
    case_id      VARCHAR(50)  NOT NULL REFERENCES cases (case_id) ON DELETE CASCADE,
    regime       TEXT         NOT NULL,
    kind         TEXT         NOT NULL,
    generator    TEXT         NOT NULL
        CONSTRAINT regulatory_report_drafts_generator_check CHECK (generator IN ('template', 'llm')),
    body         JSONB        NOT NULL,
    cited_ids    JSONB        NOT NULL DEFAULT '[]'::jsonb,
    pack_digest  TEXT         NOT NULL,
    created_by   TEXT         NOT NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT regulatory_report_drafts_kind_check CHECK (
        (regime = 'dora' AND kind IN ('initial', 'intermediate', 'final'))
        OR (regime = 'nis2' AND kind IN ('early_warning', 'notification', 'intermediate', 'final'))
    )
);

CREATE INDEX IF NOT EXISTS idx_regulatory_report_drafts_case
    ON regulatory_report_drafts (tenant_id, case_id, created_at DESC);

COMMENT ON TABLE regulatory_clock_events IS
    'Append-only, hash-chained history of DORA/NIS2 start instants per case (W3.8).';
COMMENT ON TABLE regulatory_report_drafts IS
    'DORA/NIS2 report drafts generated from a case evidence pack; every line cites pack ids.';
