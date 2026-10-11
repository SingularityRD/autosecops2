-- Outbound webhooks and alert routing (W0.5 skeleton).
--
-- tenant_id TEXT NOT NULL DEFAULT 'default' on every table. SQL-owned like
-- 46_eval_qa_canary.sql: no ORM model, so create_all and the drift check
-- leave these tables alone.
--
-- Signing secrets are never stored here. secret_ref names the secret in the
-- secrets manager (core/secrets_manager.py), the way integrations do.

CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     TEXT         NOT NULL DEFAULT 'default',
    name          TEXT         NOT NULL,
    url           TEXT         NOT NULL,
    secret_ref    TEXT,                                  -- secrets-manager key for the HMAC secret
    event_types   TEXT[]       NOT NULL DEFAULT '{}',    -- empty: every event type
    enabled       BOOLEAN      NOT NULL DEFAULT TRUE,
    created_by    TEXT,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_webhook_endpoints_tenant_name UNIQUE (tenant_id, name)
);

-- One event owed to one endpoint. (endpoint_id, event_id) is unique so a
-- re-emitted event is one delivery, retried, not two.
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id                BIGSERIAL    PRIMARY KEY,
    tenant_id         TEXT         NOT NULL DEFAULT 'default',
    endpoint_id       UUID         NOT NULL REFERENCES webhook_endpoints (id) ON DELETE CASCADE,
    event_type        TEXT         NOT NULL,
    event_id          TEXT         NOT NULL,
    payload           JSONB        NOT NULL,
    status            TEXT         NOT NULL DEFAULT 'pending'
        CONSTRAINT webhook_deliveries_status_check
        CHECK (status IN ('pending', 'delivered', 'failed', 'dead')),
    attempts          INTEGER      NOT NULL DEFAULT 0,
    next_attempt_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_attempt_at   TIMESTAMPTZ,
    response_status   INTEGER,
    last_error        TEXT,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    delivered_at      TIMESTAMPTZ,
    CONSTRAINT uq_webhook_deliveries_endpoint_event UNIQUE (endpoint_id, event_id)
);

-- The sender's one query: what is due.
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_due
    ON webhook_deliveries (next_attempt_at)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_tenant_created
    ON webhook_deliveries (tenant_id, created_at DESC);

-- Where an alert goes. Routes are evaluated in ascending priority; match is a
-- predicate document over the alert (severity, category, source, ...).
CREATE TABLE IF NOT EXISTS alert_routes (
    id                    UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             TEXT         NOT NULL DEFAULT 'default',
    name                  TEXT         NOT NULL,
    priority              INTEGER      NOT NULL DEFAULT 100,
    match                 JSONB        NOT NULL DEFAULT '{}'::jsonb,
    destination_kind      TEXT         NOT NULL
        CONSTRAINT alert_routes_destination_kind_check
        CHECK (destination_kind IN ('webhook', 'slack', 'email')),
    -- RESTRICT: an endpoint a route sends to cannot be deleted out from under it.
    webhook_endpoint_id   UUID         REFERENCES webhook_endpoints (id) ON DELETE RESTRICT,
    destination           JSONB        NOT NULL DEFAULT '{}'::jsonb,   -- channel / address for slack, email
    stop_processing       BOOLEAN      NOT NULL DEFAULT TRUE,          -- first match wins unless false
    enabled               BOOLEAN      NOT NULL DEFAULT TRUE,
    created_by            TEXT,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_alert_routes_tenant_name UNIQUE (tenant_id, name),
    CONSTRAINT alert_routes_webhook_has_endpoint
        CHECK (destination_kind <> 'webhook' OR webhook_endpoint_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_alert_routes_tenant_priority
    ON alert_routes (tenant_id, priority)
    WHERE enabled;

COMMENT ON TABLE webhook_endpoints IS 'Outbound webhook targets (W0.5 skeleton). secret_ref names a secrets-manager entry, never the secret.';
COMMENT ON TABLE webhook_deliveries IS 'One event owed to one endpoint; unique (endpoint_id, event_id) makes a re-emit a retry, not a second delivery.';
COMMENT ON TABLE alert_routes IS 'Alert routing rules evaluated by ascending priority; match is a predicate document over the alert.';
