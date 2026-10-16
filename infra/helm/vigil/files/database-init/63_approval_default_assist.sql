-- Human approval is the default response mode (W0.32).
--
-- 04_config_tables.sql (a frozen 0.7.1 file) seeds approval.force_manual_approval
-- as Act ({"enabled": false}), so every install read Act without anyone choosing
-- it. This file moves that row to Assist while it is still the untouched seed:
-- never written by a person (updated_by is set on every console write) and with
-- no config_audit_log entry for the key. That covers a new database (04, then
-- this file) and an upgraded one alike. A row a person set, to Act or to Assist,
-- is left exactly as it is, and DAEMON_FORCE_APPROVAL is read as before.
--
-- The move is audited under system:w0.32-default on both new and upgraded
-- databases, so a new install's config_audit_log starts with that one row.
-- A later run (compose re-applies every file on `up`) finds the audit row and
-- does nothing.
--
-- A file of its own, not an edit to 04: 04 is frozen (test_upgrade_database.py)
-- and the Helm init job records each file once it has run.

WITH flipped AS (
    UPDATE system_config
       SET value = '{"enabled": true}'::jsonb
     WHERE key = 'approval.force_manual_approval'
       AND value = '{"enabled": false}'::jsonb
       AND updated_by IS NULL
       AND NOT EXISTS (
           SELECT 1 FROM config_audit_log
            WHERE config_key = 'approval.force_manual_approval'
       )
    RETURNING key
)
INSERT INTO config_audit_log
    (config_type, config_key, action, old_value, new_value, changed_by, change_reason)
SELECT 'approval', key, 'update', '{"enabled": false}'::jsonb,
       '{"enabled": true}'::jsonb, 'system:w0.32-default',
       'GA default: a person approves every response action (Assist). '
       'Nobody had chosen the Act seed; choose Act in Settings to use it.'
  FROM flipped;
