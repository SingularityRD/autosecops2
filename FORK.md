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

Policy since **15 October 2026** (decision of the product owner): every
upstream change made after the fork point that this product lacks comes in,
features, fixes and UX alike, **except**:

- **LogLM** (DeepTempo's paid connector): this product builds its own, so
  anything that only serves LogLM is skipped, and LogLM code paths are
  candidates for removal, not for updates;
- items the radar marks **ERTELE** (deferred) in the log below, each with its
  reason; they are re-examined at every radar, not taken silently.

A change still comes in only as an adaptation that keeps this product's
guarantees: human approval by default, four-eyes, models cannot approve
(W1.7b), approval argument digest and bounds (W0.16/W0.18), the audit chain,
autonomy tiers, response policy, zero egress / air-gap (every new outbound call
classified in `tests/airgap/egress_inventory.json`), FIPS, branding
("AutoSecOps" in user-visible text) and image names
(`ghcr.io/singularityrd/autosecops-*`). A change that cannot keep them is
adapted (UYARLA) or deferred (ERTELE), never taken as is.

Before 15 October 2026 only security and data-loss fixes came in; features
were planned as our own work. Picks made under that rule stay as they are.

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
- When a pick conflicts too much to apply, port it by hand and still add the
  `(cherry picked from commit <sha>)` line, saying "manual port" in the message.
  Adaptations go in separate commits on top, titled
  `adapt(upstream <sha>): …`, each behaviour change with a test.
- The PR description names the upstream PR or advisory and the radar decision
  (AL / UYARLA, and the work package that takes it).
- User-visible text in a pick is rebranded: it says AutoSecOps, never Vigil.

### Monthly upstream radar

Once a month (first working week), someone reviews what upstream merged since
the last radar:

```bash
git fetch upstream
git log --oneline --no-merges <last-reviewed-sha>..upstream/main
# next radar: start from 7eea6a18 (the last commit of the 15 Oct 2026 radar)
```

Also check upstream's security advisories (GitHub Security tab) and releases.
Give every commit one decision and record it in the log below:

- **AL** (take): picks cleanly and is wanted; name the work package;
- **UYARLA** (adapt): wanted, but needs changes to keep the guarantees above;
  name the work package and what changes;
- **ERTELE** (defer): wanted, but too large or risky now; say what it would
  take;
- **ATLA** (skip): LogLM-only, already here, or against this product's
  direction; say why.

Security and data-loss fixes go first. Record the upstream SHA reviewed up to,
so the next radar starts there.

### Upstream radar log

Radar of 15 October 2026: upstream `58736836..7eea6a18`, 46 commits (triage
notes in `docs/wp/w0.25.md`). Work packages: **W0.25** core and data fixes,
**W0.26** hunt / case / console UI (search/entity chain deferred), **W0.27** password reset, **W0.28**
connectors, **W0.30** agent guards and OTel. Next radar starts from
**`7eea6a18`**.

| Upstream | PR | Subject | Decision | Taken by / reason |
|---|---|---|---|---|
| `98ca1152` | #2197 | Experimental label for connectors never run live | UYARLA | W0.28 (pending): README text rebranded, support channel ours |
| `596850b6` | #2198 | Weekly live connector runs; Okta MCP env fix | UYARLA | W0.28 (pending): Okta `OKTA_CLIENT_ORGURL` fix and Experimental entries only; `tests/live` and the workflow ERTELE (CI secrets, runner egress) |
| `ceb46864` | #2199 | Forgot / reset password screens | UYARLA | W0.27 (taken): on top of the W1.9 SSO login, AutoSecOps branding, token removed from the URL, air-gap (no SMTP) wording |
| `ac147719` | #2205 | Ask gets the run's live state; bounded `replay_hunt` | AL | W0.26 (taken) |
| `2ecfbb2c` | #2206 | /hunt preview names the real state; one Approve path | AL | W0.26 (taken) (client only; four-eyes stays server side) |
| `29bb968c` | #2207 | A failed query is a blind spot, not evidence against | AL | W0.26 (taken) |
| `6eaeec5c` | #2208 | Evidence tab totals every row | AL | W0.26 (taken) |
| `d79131cb` | #2209 | Run-only case shows step, cap, entities | UYARLA | W0.26 (taken): init file renumbered to **62** (`62_workflow_runs_progress.sql`) with Helm, migrate and snapshots |
| `de30c4b4` | #2223 | change-password returns 400 on password reuse | AL | W0.25 (taken) |
| `cae2414a` | #2229 | Case activities in the Record tab | AL | W0.26 (taken) (rows marked unchained; audit chain unchanged) |
| `d2e5f2b6` | #2228 | Approval times stamped as UTC | UYARLA | W0.25 (taken): also the fork's `expires_at` / `verified_at` / `reversed_at` and the `-rev` reversal id |
| `92c8da6d` | #2248 | Orchestrator reads findings from Postgres, not the demo service | UYARLA | W0.25 (taken): kept the Federation bulk hydrate (one read per tick) |
| `a37010f8` | #2249 | Triage queue scrolls inside its card | AL | W0.26 (taken) |
| `b36a232c` | #2250 | Auto-investigate off: say alerts wait, no case opens | AL | W0.26 (taken) |
| `5d6d2d5f` | #2251 | LogLM session secret help text | ATLA | LogLM only |
| `0b42a5d4` | #2252 | Re-queued finding merges into its open case | UYARLA | W0.25 (taken): one batched open-case query per intake tick |
| `e96f0bf3` | #2271 | Proposed actions collapse under the paused-run decision | UYARLA | W0.26 (taken): the collapsed row gets a Review button that reads the full action (target, arguments, W0.16) before Approve |
| `a8fe22df` | #2264 | Agent kernel: one plugin-driven loop | ERTELE | Only useful with the whole kernel series; kernel re-base vs. own agent layer decided in 2027 Q1 |
| `5dc40ab3` | #2265 | Root cause, chat, tally, compose as kernel plugins | ERTELE | Kernel series; compose `idOf()` drops the W1.7b `tool`/`args` binding, tally loses its `read_only` effect |
| `6f7d7e12` | #2266 | Hunt and adjudicate as plugins; controller retired | ERTELE | Kernel series; breaks the W2.1 verdict run (acceptConclude, on_budget, provenance) |
| `02f6d21f` | #2267 | Kernel trust: frames, ledger-only replay | ERTELE | Kernel series; recall content copied to the ledger needs a W3.5 / KVKK review first |
| `2ea100f1` | #2268 | One skill library; workflows/ and arch/ folded into plugins | ERTELE | Kernel series; moves break path-based ratchets and inventories (W1.7, FIPS, egress) |
| `05e50665` | #2276 | OTel traces for the agent layer | UYARLA | W0.30 (taken): keep `approval` in `remote.ts`, tracing only with an OTLP endpoint, egress inventory entry, content capture off in air-gap |
| `6d34c7cd` | #2298 | Hunt guards: subject-written text kept out of the verdict | UYARLA | W0.30 (taken, manual port): `core/guards.ts` on our hunt loop; handles resolved before the approval gate (args digest) |
| `4494721c` | #2299 | Case page side panel, citation chips, composer room | ERTELE | Client-only UX, taken in the post-GA UX batch after W0.26's case-page changes |
| `5674c0d4` | #2300 | Eval estate SQL; reviewer upholds benign dismissals | ATLA | Needs the kernel's reviewer and live-model eval; lowering the benign-closure bar runs against human approval by default |
| `dd88dd4b` | #2301 | Hunt case in words; waits on a person with controls | ERTELE | Needs the kernel (`book.ts` park reasons); the idea can move to our controller |
| `59703064` | #2296 | /hunt proposes a PDF's own hypothesis; Ask keeps grounding | UYARLA (Python half), TS half ERTELE | W0.26 (taken, manual port): `hunt_claim.py` and `router.py` only; the Ask `exchange` grounding (TS) needs the kernel |
| `c441a3fa` | #2297 | Hunt rules on the named host; evidence names its system | ERTELE | Search/entity chain (with e08ea09e, 265078af); deferred by W0.26's Non-goals, needs a hunt `linkFindings` port and keeps W1.7 `is_gated` / `effect_of` |
| `2f8fdf42` | #2302 | Evidence store under the State Directory; OpenRouter; setup gate | UYARLA | W0.26 (taken, manual port): evidence path only (data loss); OpenRouter `*` allow-list ATLA; setup gate ERTELE with the MCP runner |
| `5f132b81` | #2329 | Okta MCP as a pinned uv tool | UYARLA | W0.28 (pending): pin a commit SHA, egress `exec:uvx` + `UV_OFFLINE`, drop `tests/live` hunks |
| `6c8533f6` | #2331 | Chat session ids fall back to `getRandomValues` | AL | W0.25 (taken) |
| `9f2a4e52` | #2332 | Reset without mail; operator-issued link | UYARLA | W0.27 (taken): e-mail-bound token (W1.9), refuse SSO-only and service accounts, audit + SIEM event, TTL setting, branding |
| `5a4bb2f1` | #2333 | Vertex API-key keys carry project and region | ATLA | Cloud Vertex only, no air-gap use; take cleanly if a customer runs Vertex |
| `66ea4005` | #2328 | MCP runner supervisor | ERTELE | New image and architecture; one MCP runner WP with release/Trivy/SBOM/cosign, non-root mode, offline env |
| `2cea176b` | #2334 | On-demand analysis: 8192-token cap for cloud | UYARLA | W0.25 (taken): any local endpoint (on-prem vLLM, LM Studio) keeps 1400, not only Ollama |
| `2d28c92e` | #2335 | Built-ins that list findings can search them | AL | W0.26 (taken; read-only grant) |
| `e08ea09e` | #2336 | search_findings counts every match | ERTELE | Search/entity chain: needs c441a3fa's entity extraction; `cluster_id` / `min_anomaly_score` are LogLM filters |
| `3df928f3` | #2338 | Daemon triage asks for 8192 output tokens | AL | W0.25 (taken), plus `DAEMON_TRIAGE_MAX_TOKENS` (default 8192) |
| `265078af` | #2337 | Findings search matches every term | ERTELE | Search/entity chain (textually after e08ea09e); not taken by W0.26; when taken, at most 10 terms |
| `4bb6037a` | #2339 | Helm: MCP runner component | ERTELE | MCP runner WP: release matrix entry, `existingSecret` for air-gap, PSS `restricted` |
| `89dcca09` | #2343 | Backend and daemon reach MCP servers through the runner | ERTELE | MCP runner WP: `is_integration_enabled` gates, offline env for children, mTLS, egress and FIPS notes |
| `dcc79f66` | #2356 | AI analysis progress text no longer says local | AL | W0.25 (taken) |
| `2acef19f` | #2357 | connectors-live probes through a runner | ATLA | CI-only, needs `tests/live`; the Cloudflare gate removal belongs to the MCP runner WP |
| `c5f49d69` | #2358 | Only a generated analysis counts as cached enrichment | AL | W0.25 (taken) (also fixes the popup for `alert_lane`-only rows) |
| `7eea6a18` | #2359 | Triage and AI analysis replace only their own keys | UYARLA | W0.25 (taken): `alert_lane` is a daemon key, `_persist_settled` writes as the daemon, the backfill predicate (`UNRATED_WHERE` + partial index) counts `alert_lane` as triaged |

## Where this repository differs from upstream

### 1. Database init file numbers 41–51

Upstream `main` ended at `40_drop_custom_workflow_graph_layout.sql` when this
repository was imported. These files were added here, in this order:

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
| `50_regulatory_clocks.sql` | AutoSecOps W3.8 regulatory clocks |
| `51_audit_chain.sql` | AutoSecOps W1.10 tamper-evident audit chain |

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
