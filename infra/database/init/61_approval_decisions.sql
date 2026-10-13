-- Who decided each approval action, in which role, when (W3.2).
--
-- approval_actions keeps the names (created_by, approved_by, second_approver)
-- but not the role each person held when they decided. The two-person rule's
-- "distinct role" condition and the segregation-of-duties report need it:
-- a role changed after the fact must not rewrite who approved in what
-- capacity. One row per decision, appended by ApprovalService in the same
-- transaction as the decision (a savepoint, so an install without this table
-- still decides; the report then falls back to current roles and says so).
--
-- SQL-owned like 46_eval_qa_canary.sql and 48_*: no ORM model, so create_all
-- and the drift check leave it alone. Append-only for the application role.

CREATE TABLE IF NOT EXISTS approval_decisions (
    id            BIGSERIAL     PRIMARY KEY,
    tenant_id     TEXT          NOT NULL DEFAULT 'default',
    action_id     VARCHAR(80)   NOT NULL,
    step          TEXT          NOT NULL
        CONSTRAINT approval_decisions_step_check
        CHECK (step IN ('approve', 'first_approval', 'second_approval', 'reject')),
    actor         VARCHAR(100)  NOT NULL,
    actor_role_id VARCHAR(50),
    actor_role    VARCHAR(100),
    decided_at    TIMESTAMP     NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);

CREATE INDEX IF NOT EXISTS idx_approval_decisions_action
    ON approval_decisions (action_id);

CREATE INDEX IF NOT EXISTS idx_approval_decisions_decided_at
    ON approval_decisions (decided_at);

COMMENT ON TABLE approval_decisions IS
    'One row per approval decision with the decider''s role at that moment (W3.2). Append-only.';

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vigil_app') THEN
    GRANT SELECT, INSERT ON TABLE approval_decisions TO vigil_app;
    GRANT USAGE, SELECT ON SEQUENCE approval_decisions_id_seq TO vigil_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON TABLE approval_decisions FROM vigil_app;
  END IF;
END
$$;
