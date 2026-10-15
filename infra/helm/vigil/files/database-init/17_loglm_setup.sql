-- Retired (W0.29): the third-party LogLM connector this file served is gone.
--
-- The statement below is left exactly as shipped and is harmless: it adds a
-- `loglm.view` key to the analyst-and-above roles, and since W0.29 nothing reads
-- that permission (no route, no screen, no extension checks it). It is kept,
-- rather than emptied, because this file is part of the frozen 0.7.1 init set
-- (tests/unit/test_upgrade_database.py): a 0.7.1 database already ran it, so an
-- edit would only split fresh installs from upgraded ones. The file also keeps
-- its name and number because installs record it in `_vigil_schema_versions`.
-- No migration drops the inert key. Idempotent: safe to re-run.
--
-- History: this file once also provisioned a pgvector embedding column/index
-- on findings; 23_drop_finding_embedding.sql drops them.
UPDATE roles
SET permissions = permissions || '{"loglm.view": true}'::jsonb,
    updated_at = NOW()
WHERE role_id IN ('role-analyst', 'role-senior-analyst', 'role-manager', 'role-admin')
  AND COALESCE((permissions->>'loglm.view')::boolean, false) = false;
