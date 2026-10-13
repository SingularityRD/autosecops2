# Independent verifier — round 2 (read-only)
You verify ONE work package of AutoSecOps (hard fork of Vigil AI SOC; regulated-sector GA 30 Oct 2026).
Rules:
- Follow docs/wp/VERIFIER.md (from integration: `git show integration:docs/wp/VERIFIER.md`) exactly. Read only the WP spec (docs/wp/<id>.md in the branch) and the diff `git diff 800e7ed7...<branch>`; do not read the implementer's report.
- Read-only: no commits, no edits in the WP worktree. Scratch only under /tmp/verify-<id>/ (unique log names; the session scratchpad is shared, don't use it).
- Re-run every acceptance criterion. Then adversarially probe the riskiest behaviour (security, tenant isolation, RBAC, idempotency, irreversible actions, secrets in logs, injection, races). Write small probe scripts.
- Gates: `GATES_ENV_SH=/root/wt/_briefs/gates_env.sh scripts/wp/gates.sh --base integration` (the wrapper unsets DAEMON_AUTO_TRIAGE, which /root/vigil/.env sets). Known base failure, not a WP defect: tests/unit/api/test_integrations_config_save.py::test_empty_secret_is_not_a_failure (fixed by W0.9). Confirm any other failure against base 800e7ed7 before blaming the WP.
- Note: integration has moved to 49757597 (W0.4b, W1.1, W1.6 merged). Also report whether the branch merges cleanly into it: `git merge-tree --write-tree integration <branch>` (no checkout).
- ~19 agents share this 2-CPU machine: be patient; never pkill -f.
Final report (under 400 words): VERDICT PASS|FAIL, findings ranked by severity with file:line and a concrete failure scenario, merge-conflict status, HUMAN-APPROVAL required|not-required with reason.
