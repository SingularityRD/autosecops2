# autosecops2 — fork notes

This repository (`SingularityRD/autosecops2`, the AutoSecOps product) is a hard
fork of [Vigil-SOC/vigil](https://github.com/Vigil-SOC/vigil). It was imported
on 2026-10-11 from upstream `main` at `8813f24a` (Vigil 0.7.0) and synced with
upstream one last time on 2026-10-12, from upstream `main` at `58736836`. The
merge commit of that last sync is tagged **`fork-point-2026-10`**.

From the fork point on, upstream is not merged again. Its history and ours have
diverged on purpose (branding, database init numbering, Federation, Medic,
setup screens), and a full merge would cost more than it returns. Upstream work
reaches this repository only as individual cherry-picks, under the rules below.

Read this file before taking anything from upstream. It lists every place where
this repository deliberately differs from upstream.

## Taking changes from upstream

### What may come in

Only fixes for:

- **security** problems (authentication, authorization, secrets handling,
  injection, unsafe defaults, anything a CVE or GHSA would cover), and
- **data loss** or data corruption (database migrations, backup/restore,
  writes that drop or overwrite records).

Features, refactors, dead-code removals, copy changes and dependency bumps do
not come in from upstream. If one of them is wanted, it is planned as our own
work and written against this repository.

### How

```bash
git remote add upstream https://github.com/Vigil-SOC/vigil.git   # once
git fetch upstream
git checkout -b fix/upstream-<short-name> origin/main
git cherry-pick -x <upstream-sha>     # -x records "(cherry picked from commit …)"
# resolve conflicts (see "Where this repository differs" below),
# run the test suites, push, open a PR into main
```

- Always `git cherry-pick -x`, one upstream commit per pick, so
  `git log --grep "cherry picked from"` lists everything taken from upstream.
- Never `git merge upstream/main`, and never rebase `main`.
- The PR description names the upstream PR or advisory and says why it
  qualifies (security or data loss).
- User-visible text in a pick is rebranded: it says AutoSecOps, never Vigil.

### Monthly upstream radar

Once a month (first working week), someone reviews what upstream merged since
the last radar:

```bash
git fetch upstream
git log --oneline --no-merges <last-reviewed-sha>..upstream/main
# first radar: start from 58736836, the upstream parent of fork-point-2026-10
```

Also check upstream's security advisories (GitHub Security tab) and releases.
For each security or data-loss fix, open an issue here (label `upstream-radar`)
and cherry-pick it as above, or note why it does not apply. Record the upstream
SHA reviewed up to in that month's radar issue, so the next radar starts there.

## Where this repository differs from upstream

### 1. Database init file numbers 41–49

Upstream `main` ended at `40_drop_custom_workflow_graph_layout.sql` when this
repository was imported. Nine files were added here, in this order:

| File | Came from |
|---|---|
| `41_users_service_account.sql` | Medic series (upstream PRs #1947–#1995) |
| `42_medic_last_seen.sql` | Medic series |
| `43_medic_permissions.sql` | Medic series |
| `44_findings_bulk_imported.sql` | Federation epic (upstream PR #1372, closed upstream) |
| `45_skill_reads.sql` | Skill usage (upstream PRs #1843/#1997) |
| `46_eval_qa_canary.sql` | AutoSecOps W0.5 contracts (not upstream) |
| `47_webhooks_alert_routes.sql` | AutoSecOps W0.5 contracts |
| `48_autonomy_lessons_suppression_retention.sql` | AutoSecOps W0.5 contracts |
| `49_approval_action_lifecycle.sql` | AutoSecOps W0.5 contracts |

Upstream later merged #1997 with the same table as `40_skill_reads.sql`. That
file was dropped in the final sync: `45_skill_reads.sql` is the only copy here.
Upstream's numbering beyond 40 means nothing for this repository; an upstream
fix that adds an init file is renumbered to the next free number here.

Whenever an init file is added or renumbered, change all of these together:

- `infra/database/init/` and its mirror `infra/helm/vigil/files/database-init/`
  (CI diffs the two directories; they must stay identical);
- `dbInit.sqlFiles` in `infra/helm/vigil/values.yaml`;
- references in `scripts/migrate_schema.py`, the code that names the file, and the tests.

Then regenerate `core/storage/schema.snapshot.json` with
`python scripts/generate_schema_snapshot.py` (needs a local Postgres).

### 2. Branding

The product is AutoSecOps. Every user-visible string (web console, setup,
notifications, emails, operator-facing CLI output) says AutoSecOps. Code
identifiers, package and image names, environment variables (`VIGIL_*`), the
Helm chart name and code comments may still say Vigil; renaming those is
separate work, not something to do inside a cherry-pick.

### 3. Upstream PRs merged here before upstream merged them

These were merged here while still open upstream. Upstream later squash-merged
some of them as new commits; the final sync reconciled those (upstream wording
kept where it did not drop a local fix).

- Medic (System Watcher) series: upstream #1947, #1948, #1949, #1950, #1951,
  #1952, #1953, #1987, #1989, #1990, #1991, #1992, #1993, #1994, #1995.
  Upstream merged the gateway part (#1947) as #2167. Kept from this side: the
  gateway's Compose aliases (`medic-gateway-out` on `medic-private`,
  `medic-gateway-in`) and the `gap` event kind in its policy. Taken from
  upstream: the listener refusing any address that resolves to 0.0.0.0, and the
  log-redaction canary test.
  - Local fix not upstream: `tests/medic_compose/test_enable_flow.py` sorts the
    `stdin.N` files by call number instead of by name (the name sort put
    `stdin.18` before `stdin.7`).
- Skill usage tracking: upstream #1843 and its review fixes #1997 (see §1 for
  the init file).
- Release 0.7.1: upstream release-please PR #2048 (`VERSION` is 0.7.1 here).

### 4. Work upstream closed but this repository kept

- **Federation epic** (upstream #1372, closed unmerged): oldest-first fetch with
  per-source cursor lag, Federation as the only polling path (legacy Splunk /
  CrowdStrike loops removed, one-time default-on switch), unrated-findings
  tracking (`findings.bulk_imported`), batched intake tick. On first boot,
  Federation switches itself and every configured source on, once;
  `DAEMON_SPLUNK_POLL_INTERVAL` and `DAEMON_CROWDSTRIKE_POLL_INTERVAL` are only
  read by that switch (`DaemonConfig.splunk_interval` and
  `crowdstrike_interval`, still in upstream, do not exist here).
- **Setup screens** (upstream #1871, #1873, #1877, closed unmerged while issues
  #1810, #1812, #1813 stayed open): Agents and workflows step, Limits and alerts
  step (spending ceiling, Slack route), "AutoSecOps is ready" step with its own
  summary page ("Go to Home"). The workflow trigger label "Nightly" is
  "On a schedule" here. Upstream's later rail marks (#2158: step 1 follows the
  latest system checks, "!" when they need you) were merged on top.
- **Auth-on-by-default remainder** (upstream #955, closed): `core/auth/dev_mode.py`
  start-up banner and `security.dev_mode_enabled` event (escalates when bound to
  a non-loopback address), `Settings.bind_host`, and token sign-in for
  `scripts/reset-setup.sh` and `scripts/generate_sample_data.py --api`.
- **INTENT.md confidence bands** (upstream #1128, closed): `review_threshold`,
  `monitor_threshold`, `critical_action_floor`, `high_action_floor`.
- Extra regression tests carried from otherwise-superseded branches (backup
  restore with a key held outside the install, root-cause projection, timeline
  date range, MeterBar), and the `/api/orchestrator/status` and
  `POST /api/orchestrator/investigations` tests in
  `tests/unit/api/test_orchestrator_intake_api.py`, which upstream deleted
  together with the unused `GET /intake` route (#2161).

### 5. Users and roles

Upstream #2153 (sign a user out when their role changes) is in:
`PUT /api/users/{id}` revokes the user's tokens on an email or role change, and
the unused `PUT /api/users/{id}/role` route is gone. The Medic service-account
guard (`_refuse_service_account_role`: a service account can only hold the
Viewer role) stays on the remaining route.

### 6. CI

`.github/workflows/ci-cd.yml` gates its jobs on
`github.repository == 'Vigil-SOC/vigil'`, so they are skipped here. Only the
Helm and Medic workflows run. To run the full pipeline in this repository,
change that condition (costs GitHub Actions minutes on a private repository).
`.oss-scanner/` (upstream #2180) is upstream's configuration for an external
scanner and describes upstream's project; no workflow here runs it.
