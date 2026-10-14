# Round 3 rules (all agents)
Repo: /root/vigil (remote `target` = SingularityRD/autosecops2). `integration` == `main` == dd671b86 (45 WPs merged; latest W0.12b, W0.14, W0.13 auth-api, W1.9, W0.11, W0.13 data-infra-ci, W0.13 response-integrations, W1.7b, W4.5). Read docs/wp/HANDOFF.md §2 rules, docs/wp/TEMPLATE.md, docs/wp/VERIFIER.md from integration (`git -C /root/vigil show integration:docs/wp/...`).
- Work ONLY in your own worktree. Never touch /root/vigil working tree or other /root/wt/*.
- Env: `source /root/wt/_briefs/gates_env.sh` (sets venv, .env, unsets DAEMON_AUTO_TRIAGE). If Postgres/Redis are down: `pg_ctlcluster 16 main start; redis-server --daemonize yes`. Agent TS DB tests: AGENT_TEST_DATABASE_URL=postgres://test:test@localhost:5432/agent_test.
- Tests while iterating: targeted only. At the end once: `GATES_ENV_SH=/root/wt/_briefs/gates_env.sh GATES_TIMEOUT=5400 scripts/wp/gates.sh --base integration`. Also run any AC marked external_service yourself (gates use -m "not external_service").
- ~20 agents share a 2-CPU machine: expect timeouts/flakes; re-run a flaky test alone before blaming code. Unique log names under /tmp/<your-id>/. Never pkill -f.
- Init SQL: use only your reserved number (given in your prompt); mirror into infra/helm/vigil/files/database-init and values.yaml dbInit like others.
- After merging integration, regenerate `clients/web/src/services/generated/schema.d.ts` if the API changed (`cd clients/web && npm run generate:api`).
- If you add an outbound network call, classify it in tests/airgap/egress_inventory.json (see tests/airgap/README.md).
- Commit with trailers "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" and "Claude-Session: https://claude.ai/code/session_01JJ9cgGr7bV7TnqK52sAhLG". PUSH your branch to `target` after every meaningful commit (machine may die). Never force-push, never push to main/integration, never delete branches.
- Final report under 300 words: what changed, test + gates results, commit SHA(s), pushed yes/no, open risks.
- Round 5: if your worktree's clients/web/node_modules or services/agent/node_modules is a dangling symlink, `ln -sfn /root/vigil/<dir>/node_modules <dir>/node_modules`.
- Round 5 fixers: first `git merge integration` (now dd671b86), then fix, then each finding → regression test, update the WP spec with a "Round 5 fixes" table, gates, push.
- NEVER use `git stash` (the stash list is shared by all worktrees and agents have popped each other's work). Commit WIP to your own branch instead.
