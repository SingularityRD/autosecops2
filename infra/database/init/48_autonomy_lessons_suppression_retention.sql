-- Autonomy tiers, lessons, suppression rules, retention policies (W0.5 skeleton).
--
-- tenant_id TEXT NOT NULL DEFAULT 'default' on every table. SQL-owned like
-- 46_eval_qa_canary.sql: no ORM model, so create_all and the drift check
-- leave these tables alone.

-- How far the system may act on its own, per action type and verdict category.
--   off         never proposed
--   recommend   shown to the analyst, never queued
--   approve     queued, one approver
--   two_person  queued, approver and a different second_approver
--   autonomous  executed without a human when confidence >= min_confidence
--               and the action is reversible. Irreversible actions never run
--               autonomously whatever this row says (approval_service gates
--               them before any tier is consulted).
-- category '*' is the row for every category the tenant has not named.
CREATE TABLE IF NOT EXISTS autonomy_tiers (
    tenant_id        TEXT          NOT NULL DEFAULT 'default',
    action_type      VARCHAR(40)   NOT NULL,                    -- approval_actions.action_type
    category         TEXT          NOT NULL DEFAULT '*'
        CONSTRAINT autonomy_tiers_category_check
        CHECK (category IN ('*', 'phishing', 'malware', 'identity', 'network', 'cloud', 'other')),
    tier             TEXT          NOT NULL DEFAULT 'approve'
        CONSTRAINT autonomy_tiers_tier_check
        CHECK (tier IN ('off', 'recommend', 'approve', 'two_person', 'autonomous')),
    min_confidence   NUMERIC(4, 3)
        CONSTRAINT autonomy_tiers_min_confidence_check CHECK (min_confidence BETWEEN 0 AND 1),
    max_ttl_seconds  INTEGER
        CONSTRAINT autonomy_tiers_max_ttl_check CHECK (max_ttl_seconds > 0),
    updated_by       TEXT,
    updated_at       TIMESTAMPTZ   NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, action_type, category),
    CONSTRAINT autonomy_tiers_autonomous_needs_floor
        CHECK (tier <> 'autonomous' OR min_confidence IS NOT NULL)
);

-- A lesson learned from a QA disagreement, eval failure, analyst override or
-- missed canary, for later prompts to carry. Lesson text can echo adversary
-- content, so a lesson is 'proposed' until a human approves it and only
-- 'active' lessons may reach a prompt.
CREATE TABLE IF NOT EXISTS lessons (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     TEXT         NOT NULL DEFAULT 'default',
    source_kind   TEXT         NOT NULL
        CONSTRAINT lessons_source_kind_check
        CHECK (source_kind IN ('qa_review', 'eval_failure', 'analyst_override', 'canary_miss', 'manual')),
    source_id     TEXT,
    category      TEXT
        CONSTRAINT lessons_category_check
        CHECK (category IN ('phishing', 'malware', 'identity', 'network', 'cloud', 'other')),
    lesson        TEXT         NOT NULL,
    applies_to    JSONB        NOT NULL DEFAULT '{}'::jsonb,
    status        TEXT         NOT NULL DEFAULT 'proposed'
        CONSTRAINT lessons_status_check
        CHECK (status IN ('proposed', 'active', 'retired')),
    created_by    TEXT         NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    approved_by   TEXT,
    approved_at   TIMESTAMPTZ,
    retired_at    TIMESTAMPTZ,
    CONSTRAINT lessons_active_was_approved
        CHECK (status <> 'active' OR approved_by IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_lessons_tenant_active
    ON lessons (tenant_id, category)
    WHERE status = 'active';

-- Alerts an analyst has said to stop raising. match is a predicate document
-- over the alert. expires_at is nullable but the console should always ask
-- for one: a suppression nobody revisits is a blind spot.
CREATE TABLE IF NOT EXISTS suppression_rules (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     TEXT         NOT NULL DEFAULT 'default',
    name          TEXT         NOT NULL,
    match         JSONB        NOT NULL,
    reason        TEXT         NOT NULL,
    enabled       BOOLEAN      NOT NULL DEFAULT TRUE,
    created_by    TEXT         NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ,
    hit_count     BIGINT       NOT NULL DEFAULT 0,
    last_hit_at   TIMESTAMPTZ,
    CONSTRAINT uq_suppression_rules_tenant_name UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_suppression_rules_tenant_enabled
    ON suppression_rules (tenant_id)
    WHERE enabled;

-- How long each class of data is kept. legal_hold stops the pruner for that
-- class whatever retain_days says.
CREATE TABLE IF NOT EXISTS retention_policies (
    tenant_id     TEXT         NOT NULL DEFAULT 'default',
    data_class    TEXT         NOT NULL,      -- e.g. findings, agent_events, webhook_deliveries, eval_results
    retain_days   INTEGER      NOT NULL
        CONSTRAINT retention_policies_retain_days_check CHECK (retain_days > 0),
    legal_hold    BOOLEAN      NOT NULL DEFAULT FALSE,
    updated_by    TEXT,
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, data_class)
);

COMMENT ON TABLE autonomy_tiers IS 'Per tenant, action type and verdict category: off / recommend / approve / two_person / autonomous. Irreversible actions never run autonomously.';
COMMENT ON TABLE lessons IS 'Lessons for later prompts. Only status=active (human-approved) lessons may reach a prompt.';
COMMENT ON TABLE suppression_rules IS 'Analyst-declared alert suppressions; match is a predicate document over the alert.';
COMMENT ON TABLE retention_policies IS 'Retention per data class; legal_hold overrides retain_days.';
