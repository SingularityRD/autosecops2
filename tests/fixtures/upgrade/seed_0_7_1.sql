-- Representative rows for the Vigil 0.7.1 upgrade fixture (W4.5).
--
-- Applied by scripts/build_upgrade_fixture.py to a database provisioned from the
-- upstream 0.7.1 tree, before pg_dump. Every value is synthetic: example.com
-- addresses, RFC 5737 documentation IPs, and a password_hash that is not a hash
-- of anything (no bcrypt prefix, so it can never verify).
--
-- tests/integration/test_upgrade_from_071.py asserts on these exact rows after
-- the upgrade; change both together.

BEGIN;

INSERT INTO users (user_id, username, email, password_hash, full_name, role_id,
                   is_active, is_verified, mfa_enabled, login_count, created_at, updated_at)
VALUES
  ('user-upg-analyst', 'upg.analyst', 'upg.analyst@example.com',
   'not-a-hash-upgrade-fixture', 'Upgrade Analyst', 'role-analyst',
   true, true, false, 7, '2026-09-01 08:00:00', '2026-09-01 08:00:00'),
  ('user-upg-admin', 'upg.admin', 'upg.admin@example.com',
   'not-a-hash-upgrade-fixture', 'Upgrade Admin', 'role-admin',
   true, true, false, 3, '2026-09-01 08:00:00', '2026-09-01 08:00:00');

INSERT INTO findings (finding_id, anomaly_score, title, description, entity_context,
                      evidence_links, "timestamp", data_source, external_id, severity,
                      status, created_at, updated_at)
VALUES
  ('f-upg-0001', 0.91, 'Brute force against VPN gateway',
   'Repeated failed logins from one source.', '{"src_ip": "192.0.2.10", "user": "upg.analyst"}',
   '[]', '2026-10-01 10:00:00', 'splunk', 'ext-1', 'high', 'new',
   '2026-10-01 10:00:05', '2026-10-01 10:00:05'),
  ('f-upg-0002', 0.42, 'Unusual PowerShell child process',
   NULL, '{"host": "ws-upg-01.example.com"}',
   '[]', '2026-10-01 11:00:00', 'crowdstrike', 'ext-2', 'medium', 'in_review',
   '2026-10-01 11:00:05', '2026-10-01 11:00:05'),
  ('f-upg-0003', NULL, 'Imported historical alert',
   NULL, '{}', '[]', NULL, 'splunk', 'ext-3', NULL, 'new',
   '2026-09-15 09:00:00', '2026-09-15 09:00:00'),
  ('f-upg-0004', 0.10, 'Benign scanner',
   'Internal vulnerability scanner.', '{"src_ip": "198.51.100.7"}', '[]',
   '2026-10-02 12:00:00', 'splunk', 'ext-4', 'low', 'closed',
   '2026-10-02 12:00:05', '2026-10-02 12:00:05');

INSERT INTO cases (case_id, title, description, status, priority, assignee, tags,
                   notes, timeline, activities, resolution_steps, mitre_techniques,
                   created_at, updated_at)
VALUES
  ('case-upg-0001', 'VPN brute force', 'Opened from f-upg-0001.', 'in_progress', 'high',
   'upg.analyst', ARRAY['vpn','bruteforce'], '[]',
   '[{"ts": "2026-10-01T10:05:00", "event": "created"}]', '[]', '[]',
   ARRAY['T1110'], '2026-10-01 10:05:00', '2026-10-01 10:30:00'),
  ('case-upg-0002', 'Scanner noise', NULL, 'closed', 'low',
   NULL, NULL, NULL, '[]', NULL, NULL, NULL,
   '2026-10-02 12:10:00', '2026-10-02 12:20:00');

INSERT INTO case_findings (case_id, finding_id, added_at) VALUES
  ('case-upg-0001', 'f-upg-0001', '2026-10-01 10:05:00'),
  ('case-upg-0001', 'f-upg-0002', '2026-10-01 11:05:00'),
  ('case-upg-0002', 'f-upg-0004', '2026-10-02 12:10:00');

INSERT INTO case_comments (case_id, author, content, is_edited, is_deleted, created_at, updated_at)
VALUES ('case-upg-0001', 'upg.analyst', 'Source IP blocked at the edge; watching for retries.',
        false, false, '2026-10-01 10:20:00', '2026-10-01 10:20:00');

INSERT INTO case_iocs (case_id, ioc_type, value, threat_level, confidence, source,
                       is_active, is_false_positive, created_at, updated_at)
VALUES ('case-upg-0001', 'ip', '192.0.2.10', 'high', 0.9, 'analyst',
        true, false, '2026-10-01 10:21:00', '2026-10-01 10:21:00');

-- One ordinary executed block and one isolation the pre-#1276 stub "executed":
-- migrate_schema.py marks the latter failed (its host was never contained).
INSERT INTO approval_actions (action_id, action_type, title, description, target, confidence,
                              reason, evidence, created_at, created_by, requires_approval,
                              status, approved_at, approved_by, executed_at, execution_result,
                              parameters, reversibility, idempotency_key)
VALUES
  ('act-upg-0001', 'block_ip', 'Block 192.0.2.10', 'Edge block', '192.0.2.10', 0.9,
   'Brute force', '["f-upg-0001"]', '2026-10-01 10:10:00', 'agent', true,
   'executed', '2026-10-01 10:12:00', 'upg.admin', '2026-10-01 10:12:05',
   '{"message": "blocked"}', '{}', 'reversible', 'block_ip:192.0.2.10'),
  ('act-upg-0002', 'isolate_host', 'Isolate ws-upg-01', 'Containment', 'ws-upg-01.example.com', 0.7,
   'Suspicious PowerShell', '["f-upg-0002"]', '2026-10-01 11:10:00', 'agent', true,
   'executed', '2026-10-01 11:12:00', 'upg.admin', '2026-10-01 11:12:05',
   '{"message": "Host isolated (MOCK)"}', '{}', 'reversible', 'isolate_host:ws-upg-01.example.com'),
  ('act-upg-0003', 'disable_user', 'Disable upg.analyst', 'Pending review', 'upg.analyst', 0.4,
   'Low confidence', '[]', '2026-10-01 12:00:00', 'agent', true,
   'pending', NULL, NULL, NULL, NULL, '{}', 'reversible', NULL);

-- The agent ledger: the 0.7.1 trigger (31_agent_ledger_hash_chain.sql) assigns
-- prev_hash / event_hash; the upgrade test re-verifies the chain afterwards.
INSERT INTO agent_events (run_id, seq, ts, run_kind, kind, payload, snapshot, schema_version,
                          prev_hash, event_hash)
VALUES
  ('5f0c4a52-6d2e-4f43-9a63-0a0000000001', 1, '2026-10-01 10:06:00+00', 'triage', 'run_started',
   '{"finding_id": "f-upg-0001"}', NULL, 1, '', ''),
  ('5f0c4a52-6d2e-4f43-9a63-0a0000000001', 2, '2026-10-01 10:06:30+00', 'triage', 'tool_call',
   '{"tool": "lookup_ip", "args": {"ip": "192.0.2.10"}}', NULL, 1, '', ''),
  ('5f0c4a52-6d2e-4f43-9a63-0a0000000001', 3, '2026-10-01 10:07:00+00', 'triage', 'run_finished',
   '{"verdict": "malicious"}', '{"verdict": "malicious"}', 1, '', '');

INSERT INTO workflow_runs (run_id, workflow_id, workflow_version, workflow_source, workflow_name,
                           status, triggered_by, trigger_context, started_at, finished_at,
                           duration_ms, total_cost_usd, result_summary, outcome)
VALUES ('wfr-upg-0001', 'incident-response', 1, 'file', 'Incident response', 'completed',
        'upg.analyst', '{"case_id": "case-upg-0001"}', '2026-10-01 10:08:00',
        '2026-10-01 10:09:00', 60000, 0.0123, 'Contained', 'completed');

INSERT INTO custom_agents (id, name, description, role, extra_principles, methodology,
                           recommended_tools, max_tokens, enable_thinking, model, created_by,
                           created_at, updated_at, component_category)
VALUES ('agent-upg-vpn', 'VPN triage', 'Triage VPN alerts', 'triage', '', '',
        '["lookup_ip"]', 4096, false, NULL, 'upg.admin',
        '2026-09-20 09:00:00', '2026-09-20 09:00:00', 'investigation');

INSERT INTO llm_interaction_logs (interaction_id, session_id, agent_id, created_at, model,
                                  request_messages, thinking_enabled, tool_calls, tool_results,
                                  input_tokens, output_tokens, cache_read_tokens,
                                  cache_creation_tokens, cost_usd, duration_ms)
VALUES ('llm-upg-0001', 'sess-upg', 'agent-upg-vpn', '2026-10-01 10:06:10', 'claude-sonnet',
        '[{"role": "user", "content": "triage f-upg-0001"}]', false, '[]', '[]',
        1200, 300, 0, 0, 0.0081, 2100);

INSERT INTO conversations (id, user_id, title, case_id, archived, message_count,
                           created_at, updated_at, last_message_at)
VALUES ('conv-upg-0001', 'user-upg-analyst', 'About case-upg-0001', 'case-upg-0001', false, 2,
        '2026-10-01 10:30:00', '2026-10-01 10:31:00', '2026-10-01 10:31:00');

INSERT INTO chat_messages (conversation_id, seq, role, content, tool_calls, complete,
                           input_tokens, output_tokens, cost_usd, created_at)
VALUES
  ('conv-upg-0001', 1, 'user', 'Summarise the case.', '[]', true, 0, 0, 0, '2026-10-01 10:30:00'),
  ('conv-upg-0001', 2, 'assistant', 'One VPN brute force, source blocked.', '[]', true,
   50, 12, 0.0004, '2026-10-01 10:31:00');

INSERT INTO federation_sources (source_id, enabled, interval_seconds, max_items, cursor,
                                consecutive_errors, dropped_total)
VALUES ('splunk', true, 300, 100, '{"last_time": "2026-10-02T12:00:00Z"}', 0, 0);

INSERT INTO threat_indicators (indicator_type, indicator_value, source, confidence, threat_level,
                               labels, first_seen, last_seen)
VALUES ('ipv4-addr', '192.0.2.10', 'taxii-upgrade-fixture', 80, 'high',
        ARRAY['bruteforce'], '2026-10-01 10:00:00', '2026-10-01 10:00:00');

INSERT INTO ip_exclusions (exclusion_id, ip, reason, origin, created_by, created_at)
VALUES ('excl-upg-0001', '198.51.100.7', 'Internal scanner', 'ad_hoc', 'upg.admin',
        '2026-10-02 12:15:00');

INSERT INTO system_config (key, value, description, config_type)
VALUES ('upgrade_fixture.marker', '{"from": "0.7.1"}', 'Upgrade fixture marker row', 'system')
ON CONFLICT (key) DO NOTHING;

COMMIT;
