# Independent verifier — round 2 (read-only)
You verify ONE work package of AutoSecOps (hard fork of Vigil AI SOC; regulated-sector GA 30 Oct 2026).
Rules:
- Follow docs/wp/VERIFIER.md exactly (`git -C /root/vigil show integration:docs/wp/VERIFIER.md`). Read only the WP spec (docs/wp/<id>.md in the branch) and the diff `git diff 800e7ed7...<branch>`; do not read the implementer's report.
- Read-only: no commits, no edits in the WP worktree. Scratch only under /tmp/verify-<id>/ (unique log names; the session scratchpad is shared, don't use it).
- Re-run every acceptance criterion. Then adversarially probe the riskiest behaviour (security, tenant isolation, RBAC, idempotency, irreversible actions, secrets in logs, injection, races). Write small probe scripts.
- Gates: `GATES_ENV_SH=/root/wt/_briefs/gates_env.sh scripts/wp/gates.sh --base integration` (the wrapper unsets DAEMON_AUTO_TRIAGE, which /root/vigil/.env sets). Confirm any other failure against integration before blaming the WP.
- Note: integration (== main) is dd671b86. Also report whether the branch merges cleanly into it: `git merge-tree --write-tree integration <branch>` (no checkout).
- ~19 agents share this 2-CPU machine: be patient; never pkill -f.
Final report (under 400 words): VERDICT PASS|FAIL, findings ranked by severity with file:line and a concrete failure scenario, merge-conflict status, HUMAN-APPROVAL required|not-required with reason.
Round 4 additions:
- The diff to review is `git diff $(git merge-base integration <branch>)...<branch>` (branches have merged integration). If this is a re-verification, the previous FAIL findings are in `git show integration:docs/wp/FIXES.md` (section for your WP): confirm each is fixed with your own probe, then hunt for NEW problems introduced by the fixes.
- Also run every AC marked external_service (gates skip them) and the evalkit tests (`pytest tests/unit/evalkit`) since gates don't cover them.
- If node_modules links in the worktree are broken (pointing to removed /root/wt/w01), repoint to /root/vigil's clients/web and services/agent node_modules (git-ignored, not a code change).
- Read-only: no commits, no pushes.
