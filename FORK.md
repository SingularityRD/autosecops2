# autosecops2 — Vigil fork notes

This repository (`SingularityRD/autosecops2`) is a private copy of
[Vigil-SOC/vigil](https://github.com/Vigil-SOC/vigil), imported on 2026-10-11
from upstream `main` at `8813f24a` (Vigil 0.7.0). It is a separate repository,
not a GitHub fork, so GitHub's "Sync fork" button does not exist here: upstream
changes are pulled in by hand (or by the weekly sync task) as described below.

Read this file before resolving a sync conflict. It lists every place where this
repository deliberately differs from upstream.

## Syncing with upstream

```bash
git remote add upstream https://github.com/Vigil-SOC/vigil.git   # once
git fetch upstream
git checkout -b sync/upstream-YYYY-MM-DD origin/main
git merge upstream/main          # merge, never rebase: main's history is never rewritten
# resolve conflicts (see below), run the test suites, push, open a PR into main
```

Sync often (weekly). Conflicts grow much faster than the gap between syncs.

## Where this repository differs from upstream

### 1. Database init file numbers 41–49

Upstream `main` ended at `40_drop_custom_workflow_graph_layout.sql`. Nine files
were added here, in this order:

| File | Came from |
|---|---|
| `41_users_service_account.sql` | Medic series (upstream PRs #1947–#1995, open upstream) |
| `42_medic_last_seen.sql` | Medic series |
| `43_medic_permissions.sql` | Medic series |
| `44_findings_bulk_imported.sql` | Federation epic (upstream PR #1372, closed upstream) |
| `45_skill_reads.sql` | Skill usage (upstream PRs #1843/#1997, open upstream) |
| `46_eval_qa_canary.sql` | AutoSecOps W0.5 contracts (not upstream) |
| `47_webhooks_alert_routes.sql` | AutoSecOps W0.5 contracts |
| `48_autonomy_lessons_suppression_retention.sql` | AutoSecOps W0.5 contracts |
| `49_approval_action_lifecycle.sql` | AutoSecOps W0.5 contracts |

When upstream adds its own `41_…` or later, the numbers collide. Renumber so the
order stays correct, and change all of these together:

- `infra/database/init/` and its mirror `infra/helm/vigil/files/database-init/`
  (CI diffs the two directories; they must stay identical);
- `dbInit.sqlFiles` in `infra/helm/vigil/values.yaml`;
- references in `scripts/migrate_schema.py`, the code that names the file, and the tests.

Then regenerate `core/storage/schema.snapshot.json` with
`python scripts/generate_schema_snapshot.py` (needs a local Postgres).

### 2. Upstream PRs merged here before upstream merged them

These were still open upstream on 2026-10-11. When upstream lands them, it will
squash-merge them as new commits, so git will not recognise them as already
present. Expect conflicts whose two sides are mostly identical; keep the newer
upstream wording unless it drops something listed here.

- Medic (System Watcher) series: upstream #1947, #1948, #1949, #1950, #1951,
  #1952, #1953, #1987, #1989, #1990, #1991, #1992, #1993, #1994, #1995.
  - Local fix not upstream: `tests/medic_compose/test_enable_flow.py` sorts the
    `stdin.N` files by call number instead of by name (the name sort put
    `stdin.18` before `stdin.7`).
- Skill usage tracking: upstream #1843 and its review fixes #1997.
- Release 0.7.1: upstream release-please PR #2048 (`VERSION` is 0.7.1 here).

### 3. Work upstream closed but this repository kept

- **Federation epic** (upstream #1372, closed unmerged): oldest-first fetch with
  per-source cursor lag, Federation as the only polling path (legacy Splunk /
  CrowdStrike loops removed, one-time default-on switch), unrated-findings
  tracking (`findings.bulk_imported`), batched intake tick. On first boot,
  Federation switches itself and every configured source on, once;
  `DAEMON_SPLUNK_POLL_INTERVAL` and `DAEMON_CROWDSTRIKE_POLL_INTERVAL` are only
  read by that switch.
- **Setup screens** (upstream #1871, #1873, #1877, closed unmerged while issues
  #1810, #1812, #1813 stayed open): Agents and workflows step, Limits and alerts
  step (spending ceiling, Slack route), "Vigil is ready" step. The workflow
  trigger label "Nightly" is "On a schedule" here.
- **Auth-on-by-default remainder** (upstream #955, closed): `core/auth/dev_mode.py`
  start-up banner and `security.dev_mode_enabled` event (escalates when bound to
  a non-loopback address), `Settings.bind_host`, and token sign-in for
  `scripts/reset-setup.sh` and `scripts/generate_sample_data.py --api`.
- **INTENT.md confidence bands** (upstream #1128, closed): `review_threshold`,
  `monitor_threshold`, `critical_action_floor`, `high_action_floor`.
- Extra regression tests carried from otherwise-superseded branches (backup
  restore with a key held outside the install, root-cause projection, timeline
  date range, MeterBar).

### 4. CI

`.github/workflows/ci-cd.yml` gates its jobs on
`github.repository == 'Vigil-SOC/vigil'`, so they are skipped here. Only the
Helm and Medic workflows run. To run the full pipeline in this repository,
change that condition (costs GitHub Actions minutes on a private repository).
