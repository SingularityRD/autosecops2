-- Execution lifecycle on approval_actions: expiry, verification, reversal,
-- before/after state, two-person approval (W0.5).
--
-- approval_actions is created by this directory (13_approval_actions.sql)
-- and mirrored by the ORM model (core/storage/models/workflow.py
-- ApprovalAction), the same arrangement 30_approval_action_reversibility.sql
-- extends. So, unlike findings in 15_federation.sql, the table exists when
-- init SQL runs and an init-time ALTER is safe. The columns reach each kind of
-- install by its own path, all three carrying the same definitions:
--   * fresh or upgraded Compose / Helm: this file (Compose re-applies the
--     directory on every up, Helm's db-init Job applies new files by name)
--   * fresh bare-metal: create_all from the ORM model, then this file again
--     via scripts/seed_reference_data.py for the constraints
--   * existing bare-metal: scripts/migrate_schema.py
--     "Add approval_actions lifecycle columns", which the startup drift check
--     names once the model has the columns and the table does not.
-- The ORM declares the columns and indexes but, as in 30, not the CHECKs:
-- those come from here.
--
-- Column meanings (core/response/executors/base.py):
--   expires_at       executed_at + ttl; the sweeper reverses the action then.
--                    NULL: permanent until someone reverses it.
--   verified_at,     when the executor last checked the effect is in place,
--   verify_status    and what it found: verified / failed / unknown
--                    (unknown = could not look, which is not failed).
--   reversed_at      when this action was undone.
--   reverse_of       on the row that undoes another: that row's action_id.
--   before_state,    what the executor observed before and after the change.
--   after_state      reverse restores before_state.
--   second_approver  the two-person rule's second approver, never approved_by.
-- Timestamps are TIMESTAMP (no zone) like the table's other timestamps.

ALTER TABLE approval_actions ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP;
ALTER TABLE approval_actions ADD COLUMN IF NOT EXISTS verified_at TIMESTAMP;
ALTER TABLE approval_actions ADD COLUMN IF NOT EXISTS verify_status VARCHAR(16);
ALTER TABLE approval_actions ADD COLUMN IF NOT EXISTS reversed_at TIMESTAMP;
ALTER TABLE approval_actions ADD COLUMN IF NOT EXISTS reverse_of VARCHAR(80);
ALTER TABLE approval_actions ADD COLUMN IF NOT EXISTS before_state JSONB;
ALTER TABLE approval_actions ADD COLUMN IF NOT EXISTS after_state JSONB;
ALTER TABLE approval_actions ADD COLUMN IF NOT EXISTS second_approver VARCHAR(100);

ALTER TABLE approval_actions
    DROP CONSTRAINT IF EXISTS approval_actions_verify_status_check;
ALTER TABLE approval_actions
    ADD CONSTRAINT approval_actions_verify_status_check
        CHECK (verify_status IN ('verified', 'failed', 'unknown'));

ALTER TABLE approval_actions
    DROP CONSTRAINT IF EXISTS approval_actions_second_approver_distinct;
ALTER TABLE approval_actions
    ADD CONSTRAINT approval_actions_second_approver_distinct
        CHECK (second_approver IS NULL OR second_approver IS DISTINCT FROM approved_by);

ALTER TABLE approval_actions
    DROP CONSTRAINT IF EXISTS approval_actions_reverse_of_fkey;
ALTER TABLE approval_actions
    ADD CONSTRAINT approval_actions_reverse_of_fkey
        FOREIGN KEY (reverse_of) REFERENCES approval_actions (action_id) ON DELETE SET NULL;

-- The expiry sweeper's one query: executed, not yet reversed, due.
CREATE INDEX IF NOT EXISTS idx_approval_actions_expiry
    ON approval_actions (expires_at)
    WHERE status = 'executed' AND reversed_at IS NULL AND expires_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_approval_actions_reverse_of
    ON approval_actions (reverse_of)
    WHERE reverse_of IS NOT NULL;

COMMENT ON COLUMN approval_actions.expires_at IS
    'executed_at + ttl. The sweeper reverses the action when it passes. NULL: permanent until reversed.';
COMMENT ON COLUMN approval_actions.verify_status IS
    'Last verify() outcome: verified, failed, or unknown (could not check; not a failure).';
COMMENT ON COLUMN approval_actions.reverse_of IS
    'On a row that undoes another action: the undone action_id.';
COMMENT ON COLUMN approval_actions.before_state IS
    'Target state the executor observed before acting; reverse restores it.';
COMMENT ON COLUMN approval_actions.second_approver IS
    'Second approver under the two-person rule; must differ from approved_by.';
