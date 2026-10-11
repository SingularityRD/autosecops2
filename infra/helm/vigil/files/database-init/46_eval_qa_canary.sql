-- Verdict quality: offline evals, QA sampling of live verdicts, canaries (W0.5).
--
-- Skeleton tables frozen so the work packages that fill them can be written in
-- parallel. Every table carries tenant_id TEXT NOT NULL DEFAULT 'default' so a
-- single-tenant install never names one and a multi-tenant one filters on it.
--
-- Verdicts stored here are core/contracts/verdict.schema.json documents
-- (JSONB). verdict / category columns repeat the document's values so they can
-- be counted without unpacking it; the CHECKs list the schema's enums.
--
-- Tenant isolation: a row that points at another table's row points at it by
-- (tenant_id, id), so a child can never reference a parent in another tenant.
-- Each referenced table carries UNIQUE (tenant_id, id) for that FK to target.
--
-- SQL-owned: no ORM model declares these tables, so create_all never builds
-- them and the drift check never inspects them (the agent_* tables work the
-- same way). Compose and Helm apply this file; scripts/seed_reference_data.py
-- applies it on bare-metal installs.

-- One run of the eval suite against one model and prompt version.
CREATE TABLE IF NOT EXISTS eval_runs (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT         NOT NULL DEFAULT 'default',
    suite           TEXT         NOT NULL,
    model           TEXT         NOT NULL,
    prompt_version  TEXT         NOT NULL,
    git_sha         TEXT,
    status          TEXT         NOT NULL DEFAULT 'running'
        CONSTRAINT eval_runs_status_check
        CHECK (status IN ('running', 'completed', 'failed', 'cancelled')),
    config          JSONB        NOT NULL DEFAULT '{}'::jsonb,
    metrics         JSONB        NOT NULL DEFAULT '{}'::jsonb,   -- precision/recall/etc., written at completion
    triggered_by    TEXT,
    started_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ,
    -- Target of eval_results' (tenant_id, run_id) FK.
    CONSTRAINT uq_eval_runs_tenant_id UNIQUE (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_eval_runs_tenant_started
    ON eval_runs (tenant_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_eval_runs_suite_version
    ON eval_runs (suite, model, prompt_version);

-- One labelled case in one eval run.
CREATE TABLE IF NOT EXISTS eval_results (
    id                 BIGSERIAL     PRIMARY KEY,
    run_id             UUID          NOT NULL,
    tenant_id          TEXT          NOT NULL DEFAULT 'default',
    case_id            TEXT          NOT NULL,
    expected_verdict   TEXT          NOT NULL
        CONSTRAINT eval_results_expected_verdict_check
        CHECK (expected_verdict IN ('malicious', 'benign', 'inconclusive')),
    expected_category  TEXT
        CONSTRAINT eval_results_expected_category_check
        CHECK (expected_category IN ('phishing', 'malware', 'identity', 'network', 'cloud', 'other')),
    actual_verdict     TEXT
        CONSTRAINT eval_results_actual_verdict_check
        CHECK (actual_verdict IN ('malicious', 'benign', 'inconclusive')),
    actual_category    TEXT
        CONSTRAINT eval_results_actual_category_check
        CHECK (actual_category IN ('phishing', 'malware', 'identity', 'network', 'cloud', 'other')),
    confidence         NUMERIC(4, 3)
        CONSTRAINT eval_results_confidence_check CHECK (confidence BETWEEN 0 AND 1),
    passed             BOOLEAN,                 -- NULL until scored, or when the case errored
    verdict            JSONB,                   -- the full verdict document, NULL on error
    latency_ms         INTEGER,
    cost_usd           NUMERIC(12, 6),          -- NULL when unpriced, never 0 for unknown
    error              TEXT,
    created_at         TIMESTAMPTZ   NOT NULL DEFAULT now(),
    CONSTRAINT uq_eval_results_run_case UNIQUE (run_id, case_id),
    -- Composite: a result belongs to a run of its own tenant.
    CONSTRAINT eval_results_run_fkey FOREIGN KEY (tenant_id, run_id)
        REFERENCES eval_runs (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_eval_results_tenant_case
    ON eval_results (tenant_id, case_id);

-- A live verdict drawn for human review. simple_random gives an unbiased
-- error-rate estimate; risk_weighted over-samples the verdicts that matter
-- (benign on high-severity, auto-actioned) and records each draw's inclusion
-- probability so estimates can be re-weighted (Horvitz-Thompson).
CREATE TABLE IF NOT EXISTS qa_samples (
    id                      BIGSERIAL     PRIMARY KEY,
    tenant_id               TEXT          NOT NULL DEFAULT 'default',
    sampling_kind           TEXT          NOT NULL
        CONSTRAINT qa_samples_sampling_kind_check
        CHECK (sampling_kind IN ('simple_random', 'risk_weighted')),
    inclusion_probability   DOUBLE PRECISION NOT NULL
        CONSTRAINT qa_samples_inclusion_probability_check
        CHECK (inclusion_probability > 0 AND inclusion_probability <= 1),
    subject_kind            TEXT          NOT NULL,      -- 'finding', 'case', 'approval_action', ...
    subject_id              TEXT          NOT NULL,
    verdict                 JSONB         NOT NULL,      -- the verdict as issued
    sampled_at              TIMESTAMPTZ   NOT NULL DEFAULT now(),
    reviewer                TEXT,
    reviewed_at             TIMESTAMPTZ,
    review_verdict          TEXT
        CONSTRAINT qa_samples_review_verdict_check
        CHECK (review_verdict IN ('malicious', 'benign', 'inconclusive')),
    agrees                  BOOLEAN,                     -- NULL until reviewed
    notes                   TEXT,
    CONSTRAINT uq_qa_samples_subject UNIQUE (tenant_id, sampling_kind, subject_kind, subject_id)
);

CREATE INDEX IF NOT EXISTS idx_qa_samples_unreviewed
    ON qa_samples (tenant_id, sampled_at)
    WHERE reviewed_at IS NULL;

-- A synthetic event with a known answer pushed through the live pipeline.
-- marker is the token embedded in the event so the pipeline's output can be
-- matched back and so response executors can refuse to act on it.
CREATE TABLE IF NOT EXISTS canary_injections (
    id                  UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           TEXT          NOT NULL DEFAULT 'default',
    marker              TEXT          NOT NULL,
    canary_kind         TEXT          NOT NULL,
    expected_verdict    TEXT          NOT NULL
        CONSTRAINT canary_injections_expected_verdict_check
        CHECK (expected_verdict IN ('malicious', 'benign', 'inconclusive')),
    expected_category   TEXT
        CONSTRAINT canary_injections_expected_category_check
        CHECK (expected_category IN ('phishing', 'malware', 'identity', 'network', 'cloud', 'other')),
    payload             JSONB         NOT NULL DEFAULT '{}'::jsonb,
    injected_at         TIMESTAMPTZ   NOT NULL DEFAULT now(),
    finding_id          TEXT,                       -- the finding the pipeline made of it
    observed_verdict    TEXT
        CONSTRAINT canary_injections_observed_verdict_check
        CHECK (observed_verdict IN ('malicious', 'benign', 'inconclusive')),
    observed_at         TIMESTAMPTZ,
    outcome             TEXT          NOT NULL DEFAULT 'pending'
        CONSTRAINT canary_injections_outcome_check
        CHECK (outcome IN ('pending', 'caught', 'missed', 'error')),
    error               TEXT,
    CONSTRAINT uq_canary_injections_marker UNIQUE (marker)
);

CREATE INDEX IF NOT EXISTS idx_canary_injections_pending
    ON canary_injections (tenant_id, injected_at)
    WHERE outcome = 'pending';

COMMENT ON TABLE eval_runs IS 'One offline eval run of the verdict pipeline (W0.5 skeleton).';
COMMENT ON TABLE eval_results IS 'One labelled case in an eval run; verdict is a verdict.schema.json document.';
COMMENT ON TABLE qa_samples IS 'Live verdicts drawn for human review; inclusion_probability allows re-weighting risk_weighted draws.';
COMMENT ON TABLE canary_injections IS 'Known-answer synthetic events injected into the live pipeline; marker matches output back and keeps executors off it.';
