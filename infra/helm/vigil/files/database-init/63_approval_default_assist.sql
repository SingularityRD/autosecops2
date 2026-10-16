-- Human approval is the default response mode (W0.32).
--
-- 04_config_tables.sql seeded approval.force_manual_approval as Act
-- ({"enabled": false}) before 2.0.0, so every install read Act without anyone
-- choosing it. 04 now seeds Assist for a new database; this file moves an
-- existing one to Assist only while the row is still that untouched seed:
-- never written by a person (updated_by is set on every console write) and
-- with no config_audit_log entry for the key. A row a person set, to Act or
-- to Assist, is left exactly as it is, and DAEMON_FORCE_APPROVAL is read as
-- before. The change is audited under system:w0.32-upgrade, so a later run
-- (compose re-applies every file on `up`) finds the audit row and does
-- nothing.
--
-- A file of its own, not an edit to 04: the Helm init job records each file once
-- it has run, so an edit to 04 would never reach an existing Helm install.

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
       '{"enabled": true}'::jsonb, 'system:w0.32-upgrade',
       'GA default: a person approves every response action (Assist). '
       'The Act seed was never chosen by a person; choose Act again in '
       'Settings to keep it.'
  FROM flipped;
