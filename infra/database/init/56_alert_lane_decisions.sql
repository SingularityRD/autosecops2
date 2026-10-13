-- Alert lane decisions (W2.2): one row per lane decision the daemon makes for
-- a finding before any model call (core/lanes/alert_lanes.py).
--
-- tenant_id TEXT NOT NULL DEFAULT 'default' like every W0.5 table. SQL-owned
-- like 46_eval_qa_canary.sql: no ORM model, so create_all and the drift check
-- leave this table alone.
--
-- alert_routes (47_*.sql) is where an alert is *sent* (webhook / slack /
-- email); this is which *lane* settled it (rules / small_model / verdict).
-- Append-only: a finding the backfill re-routes gets a second row.

CREATE TABLE IF NOT EXISTS alert_lane_decisions (
    id                BIGSERIAL     PRIMARY KEY,
    tenant_id         TEXT          NOT NULL DEFAULT 'default',
    finding_id        TEXT          NOT NULL,
    lane              TEXT          NOT NULL
        CONSTRAINT alert_lane_decisions_lane_check
        CHECK (lane IN ('rules', 'small_model', 'verdict')),
    reason            TEXT          NOT NULL,
    risk              NUMERIC(4, 3) NOT NULL
        CONSTRAINT alert_lane_decisions_risk_check CHECK (risk BETWEEN 0 AND 1),
    factors           JSONB         NOT NULL DEFAULT '[]'::jsonb,
    rule_kind         TEXT
        CONSTRAINT alert_lane_decisions_rule_kind_check
        CHECK (rule_kind IN ('suppression', 'playbook')),
    rule_id           TEXT,          -- suppression_rules.id or playbook name
    outcome           JSONB,
    deferred_verdict  BOOLEAN       NOT NULL DEFAULT FALSE,
    degraded_from     TEXT,
    verdict_run_id    TEXT,
    model             TEXT,
    decided_at        TIMESTAMPTZ   NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alert_lane_decisions_tenant_finding
    ON alert_lane_decisions (tenant_id, finding_id, decided_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_lane_decisions_tenant_decided
    ON alert_lane_decisions (tenant_id, decided_at DESC);
-- Deferred verdicts still owed a run, for whatever drains them after a restart.
CREATE INDEX IF NOT EXISTS idx_alert_lane_decisions_deferred
    ON alert_lane_decisions (tenant_id, decided_at)
    WHERE deferred_verdict;

COMMENT ON TABLE alert_lane_decisions IS 'Per-finding alert lane decision (rules / small_model / verdict), append-only; written by the daemon when ALERT_LANES_ENABLED.';
