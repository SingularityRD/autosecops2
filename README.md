# AutoSecOps

AutoSecOps is an agentic AI Security Operations Center with a human in charge. Agents triage, investigate, hunt and propose responses; every action they take is proposed as an approval request, released by an analyst (or, for a reversible action class an analyst has explicitly made autonomous, under a measured false-negative bound), and recorded in a tamper-evident audit chain. Playbooks are plain-text Markdown files, agent logic is readable code, and integrations use an open standard ([MCP](https://modelcontextprotocol.io/)).

AutoSecOps runs on your own infrastructure: a local clone, Docker Compose, Kubernetes (Helm), or a fully air-gapped install, with any supported LLM provider (a local Ollama model works, so no data has to leave your network).

AutoSecOps is developed by SingularityRD. It is based on [Vigil](https://github.com/Vigil-SOC/vigil) (Apache-2.0); see [NOTICE](NOTICE) and [Credits](#credits).

Documentation for operators and administrators is in [`docs/guide/`](docs/guide/README.md) (Turkish): scope, installation (also air-gapped), the administrator guide, the security technical document, the threat model and the regulatory mapping.

---

## Agents

AutoSecOps ships a set of built-in specialist agents covering the core SOC roles — triage, investigation, threat hunting, correlation, response, reporting, ATT&CK mapping, forensics, threat intel, compliance, malware and network analysis — and you can add your own from the console. The set grows and changes with the project; the built-in definitions live in [`core/agents/builtins.py`](core/agents/builtins.py) and the administrator guide describes them.

Every agent can call AutoSecOps's backend tools (findings, cases, approvals, detections, ATT&CK, threat intel, memory, skills) and the tools of whichever MCP integrations you have connected. Each agent's tool list, prompt, model, and extended-thinking budget are visible in its definition.

Response actions are proposed as approval requests. A request from the Response agent always waits for an analyst. The daemon's auto-responder routes by confidence: 0.85–0.90 gets a quick review, 0.70–0.85 needs analyst review, and below 0.70 escalates (configurable). **High confidence no longer auto-approves on its own.** Every (alert category × action class) has an autonomy tier (Settings → Limits & autonomy), and the default is *Approve*: an analyst releases the action whatever its confidence. An action runs without a person only at the *Autonomous* tier, which an analyst sets per category with an https evidence link, only for reversible, TTL-bounded classes (`isolate_host`, `block_ip`, `block_domain`, `waf_block`, `gateway_block`), and only while that category's sampled false-negative bound holds (≤1% at 95% confidence, n ≥ 299). The `other` category (unknown or unmapped alerts) is never autonomous; force-manual approval stops autonomous actions even after they were released. Deployments that relied on the 0.90 band for hands-off response must set Autonomous tiers explicitly after upgrading. The approval pipeline records `isolate_host` actions but does not execute them; host isolation or quarantine happens only when an agent calls an EDR integration's tool directly.

## Workflows

A workflow is a `WORKFLOW.md` file: YAML frontmatter that says what runs, and a Markdown body that explains it. Built-in workflows live under [`core/workflows/definitions/`](core/workflows/definitions/); edit them there, build your own from the Workflows screen, or disable the ones you don't use.

A workflow's `run_kind` decides how it executes:

| `run_kind` | How it runs | Built-in examples |
|---|---|---|
| `compose` (default) | Walks the declared `phases` in order, each phase handled by the named agent with the listed tools | Your custom workflows |
| `investigate` | A single lead agent works the objectives and narrative; no phases | Incident Response, Full Investigation, Forensic Analysis, Cloud Incident |
| `root_cause` | A single agent traces a confirmed compromise backward, step by step | Root Cause Analysis |
| `hunt` / `adjudicate` | A lead runs a hypothesis loop, dispatching worker agents and deciding each next move from the evidence | Threat Hunt, Shadow Adjudication |

Start one from chat, for example `"Run incident response on finding f-20260215-abc123"`, or from the Workflows screen.

### Create your own workflow

```markdown
---
name: phishing-triage
description: "Triage and investigate phishing reports from user submissions."
use_case: "A user reports a suspicious email and the SOC needs to assess, investigate, and contain."
trigger_examples:
  - "Run phishing triage on finding f-20260401-abc123"
objectives:
  - "Decide whether the reported mail is malicious"
  - "Contain it without waiting on a second report"
phases:
  - id: assess
    agent: triage
    name: "Assess the Report"
    tools: [get_finding, list_findings]
    instructions: |
      Fetch the finding, extract sender/domain/URLs, score severity, check for
      known-bad indicators. Hand on the verdict and the indicators you found.

  - id: investigate
    agent: investigator
    name: "Investigate"
    tools: [get_finding, search_detections]
    instructions: |
      Correlate with detection rules. Build an evidence timeline. Hand on the
      timeline and related findings.

  - id: contain
    agent: responder
    name: "Contain"
    tools: [get_case, update_case]
    approval_required: true
    instructions: |
      If confirmed malicious: block the sender domain, quarantine matching emails,
      and plan remediation with confidence scores.
---

# Phishing Triage Workflow

An overview for whoever reads this file. The `phases` above are what actually
runs, in the order written.
```

`approval_required: true` holds a phase for a human before it acts. Scaffold a new file with:

```bash
python scripts/create_workflow.py phishing-triage --agents triage,investigator,responder
# creates core/workflows/definitions/phishing-triage/WORKFLOW.md
```

---

## Integrations

AutoSecOps connects agents to your existing tools through [MCP](https://modelcontextprotocol.io/). Integrations span SIEM and log search, EDR/XDR, cloud security (AWS, Azure, GCP), identity, threat intel, sandboxes, detection engineering, ticketing, chat and paging, network security, and data pipelines. The catalogue changes as vendors ship official MCP servers and contributors add new ones; [`mcp-config.json`](mcp-config.json) is the current list, and the [administrator guide](docs/guide/yonetici-kilavuzu.md) describes each one.

An integration is one of two things:

- **An upstream MCP server**: a vendor's or community's own server, pinned to a version in `mcp-config.json` (npx, uvx, Docker, or a remote endpoint).
- **A vendor slice**: a server AutoSecOps maintains at `core/integrations/<vendor>/tool.py`, used where no suitable upstream server exists.

What an integration can do depends on its server: some are read-only lookups, others can act (for example, Microsoft Defender isolation or Carbon Black quarantine). The integrations docs list each one's tools.

Some integrations are marked **Experimental** in Settings: CrowdStrike Falcon, SentinelOne, Microsoft Sentinel, the official Splunk MCP server, Google SecOps, Google Threat Intelligence, Joe Sandbox, vStrike, Atomic Red Team and CAPE Sandbox. AutoSecOps has not run these against a live instance of the product (Atomic Red Team runs an operator's own runner; CAPE needs a KVM host), so they may not work. The label shows on every screen that turns one on and cannot be dismissed; a connector loses it only when it gains a live test. If you run one, tell AutoSecOps support whether it worked and attach a [support bundle](#getting-help-the-support-bundle).

Enable and configure integrations under **Settings → Integrations**, or generate one from API docs with the **Custom Integration Builder**. If you build an integration you find useful, someone else will too. Please contribute it.

**AutoSecOps's own MCP server.** AutoSecOps serves its SOC operations (findings, cases, approvals, hunts) at `/mcp`, the same tools its agents use. The finding, case, and approval tools that mirror frozen `/api/v1` operations are frozen: their names and input schemas are pinned in [`tools/mcp/frozen_tools.snapshot.json`](tools/mcp/frozen_tools.snapshot.json). The rest may change in any minor ([`VERSIONING.md`](VERSIONING.md)).

**Detection rules.** The detection-engineering integration ([security-detections-mcp](https://www.npmjs.com/package/security-detections-mcp)) indexes community rule sets (Sigma, Splunk ESCU, Elastic, KQL) for search, coverage analysis, and gap identification. AutoSecOps does not ship the rules in its images; fetch them with `./scripts/setup_detection_repos.sh` (or `SETUP_DETECTION_REPOS=1 ./setup_dev.sh`). The air-gap bundle can carry snapshots of them; each rule set keeps its own licence (Sigma: DRL 1.1, Elastic: Elastic License 2.0), shipped next to it ([NOTICE](NOTICE)).

---

## Quick Start

```bash
git clone https://github.com/SingularityRD/autosecops2.git
cd autosecops2
cp env.example .env   # set AGENT_INTERNAL_TOKEN (see below)
./start.sh
```

Then open http://localhost:6988 and create the admin account on the bootstrap screen.

`start.sh` provisions the pinned Python with [uv](https://docs.astral.sh/uv/), installs dependencies, starts PostgreSQL, Redis, and the Bifrost LLM gateway in Docker, starts a host Ollama if one is installed (optional), initializes the schema and reference data, and launches the API, the agent layer, and the frontend. No cloud API key is needed to reach a running UI.

- **`AGENT_INTERNAL_TOKEN`** lets the agent layer talk to the API. Generate one with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Without it the stack still starts, but workflow runs stay queued.
- **Authentication is on by default.** No account or default password ships; the first visit creates the admin. `start.sh` creates the JWT signing secret at `~/.vigil/jwt_secret`. For an unauthenticated instance on your own machine, set `DEV_MODE=true` in `.env`; the backend announces the bypass on every startup, naming each gate it opens, and says so separately when it is bound to anything but loopback (`BIND_HOST`). `scripts/reset-setup.sh` and `scripts/generate_sample_data.py --api` sign in with `VIGIL_TOKEN`, or `VIGIL_USERNAME` and `VIGIL_PASSWORD`.

> **Stable vs. development build:** `main` is the active development branch. For a tested build, check out a release tag (`git checkout v<version>`) or pull a published image (`docker pull ghcr.io/singularityrd/autosecops-backend:<version>`). Releases are listed on the [releases page](https://github.com/SingularityRD/autosecops2/releases/latest).
>
> Released images are signed keyless by [`.github/workflows/release.yml`](.github/workflows/release.yml). To verify (the image tag drops the leading `v`; the certificate identity uses the git tag):
>
> ```bash
> cosign verify \
>   --certificate-identity https://github.com/SingularityRD/autosecops2/.github/workflows/release.yml@refs/tags/v<version> \
>   --certificate-oidc-issuer https://token.actions.githubusercontent.com \
>   ghcr.io/singularityrd/autosecops-backend:<version>
> ```

### Prerequisites

- **Docker** (running): PostgreSQL, Redis, and Bifrost run in containers.
- **Node.js 22 (LTS)**: runs the agent layer and the frontend (Node 20 reached end of life in April 2026; `start.sh` still accepts it). Without Node, neither starts and workflows cannot run.
- **Git**.
- **No system Python needed**: `start.sh` provisions the version pinned in `.python-version` with uv, independent of any Python you already have.
- **An LLM provider** (optional to reach the UI): Anthropic (default), OpenAI, Google Vertex, or Ollama (local, no key). Configure it under **Settings → AI models → Providers & Keys**. With no provider key, `scripts/local_model.sh` serves a small local model Bifrost can reach and prints the model id to use.

### Run

```bash
./start.sh              # interactive; Ctrl+C to stop
./start.sh -d           # background: logs/ + pidfiles, also starts the SOC daemon
./start.sh --with splunk   # add a profiled service (splunk, kafka, pgadmin, jaeger,
./start.sh --all           #   prometheus, grafana, otel-collector), or all of them
```

Core services come from `.vigil-autostart` (or `$AUTOSTART_SERVICES`), defaulting to `postgres redis bifrost ollama`.

| | URL |
|---|---|
| Frontend | http://localhost:6988 |
| API | http://localhost:6987 |
| API docs | http://localhost:6987/docs |

### Shutdown

```bash
./shutdown_all.sh            # stop native processes; containers keep running
./shutdown_all.sh -d         # stop everything; data is kept
./shutdown_all.sh -d --full  # stop everything and PERMANENTLY DELETE all data volumes
```

`-d --full` runs `docker compose down -v`, which deletes every named volume in the compose file: `postgres_data` (database), `bifrost_data` (Bifrost config and keys), `vigil_home` (the Compose State Directory, including `master.key`), `vigil_investigations`, `redis_data`, `backup_repo` (the default on-box backup repository), and any optional-profile volumes. Keep backups outside the compose volumes (`VIGIL_BACKUP_REPO`) first. See `./shutdown_all.sh --help`.

<details>
<summary>Manual install (separate terminals)</summary>

```bash
# Python environment (uv fetches the interpreter in .python-version)
uv python install
uv venv --python "$(cat .python-version)" --python-preference only-managed venv
source venv/bin/activate
uv pip install -r requirements.lock
cp env.example .env   # set AGENT_INTERNAL_TOKEN
export PYTHONPATH="${PWD}:${PYTHONPATH}"

# 1. Containers
docker compose -f infra/docker/docker-compose.yml up -d postgres redis bifrost

# 2. Schema and reference data (no admin is seeded)
python scripts/init_schema.py
python scripts/seed_reference_data.py

# 3. API
uvicorn services.api.main:app --host 127.0.0.1 --port 6987 --reload

# 4. Agent layer (drains the queue workflow runs are enqueued to)
scripts/agent_up.sh
# optional: python -m services.worker   (ARQ LLM worker)

# 5. Frontend
cd clients/web && npm install && npm run dev
```

</details>

### Run with Docker (full stack)

```bash
docker compose --env-file .env -f infra/docker/docker-compose.yml up -d
```

Pass the repo-root `.env` explicitly, or `AGENT_INTERNAL_TOKEN` reaches the containers empty. The `backend` container refuses to start without `JWT_SECRET_KEY`. Set it in `.env`, for example `export JWT_SECRET_KEY="$(cat ~/.vigil/jwt_secret)"` if `start.sh` has run before, or `openssl rand -base64 48`.

The default set runs the database, cache, gateway, backup, API, and agent layer: everything a chat-driven workflow needs. Opt-in profiles add more: `daemon` (the SOC daemon plus the ARQ worker, for headless 24/7 monitoring), `dev`, `observability`, `splunk`, `kafka`, `elastic`, and `misp`:

```bash
docker compose --env-file .env -f infra/docker/docker-compose.yml --profile daemon up -d
```

On the host, `./start.sh -d` also runs the daemon (`services/daemon/main.py`), or run it alone against a running stack with `python services/daemon/main.py`.

### Install on Kubernetes

```bash
helm install autosecops ./infra/helm/vigil \
  --namespace autosecops --create-namespace \
  --set secrets.anthropicApiKey="$ANTHROPIC_API_KEY" \
  --set secrets.postgresPassword="$(openssl rand -hex 24)" \
  --set secrets.jwtSecretKey="$(python -c 'import secrets; print(secrets.token_urlsafe(64))')"
```

The chart directory keeps its upstream name, `vigil`, so existing releases upgrade in place. See the [chart README](infra/helm/vigil/README.md) and the [administrator guide](docs/guide/yonetici-kilavuzu.md) for values, external Postgres/Redis, ingress, and troubleshooting; for a network without internet access, [infra/airgap/README.md](infra/airgap/README.md).

### Desktop app

The desktop app (`clients/desktop`, Electron) puts a native window in front of the local stack: PostgreSQL, Redis, the Bifrost gateway, the backend and the agent layer, all running as Docker containers from the published `ghcr.io/singularityrd/autosecops-*` images. It needs no source tree, but **Docker must be installed and running** (Docker Desktop on macOS and Windows, Docker Engine with the Compose v2 plugin on Linux). The console listens on `127.0.0.1:6987` only. Bifrost reaches a host Ollama through `host.docker.internal`.

Each release ships signed installers next to the other release files: `autosecops-<V>-desktop-mac-{arm64,x64}.dmg`, `autosecops-<V>-desktop-linux-x86_64.AppImage` and `autosecops-<V>-desktop-win-x64.exe` (Windows is a preview). Files named `*-unsigned.*` carry no Apple Developer ID / Authenticode signature; every installer carries a cosign signature and is listed in `SHA256SUMS`. Install, first run, data and log locations, update, uninstall and verification steps (Turkish): [administrator guide, "Masaüstü uygulaması"](docs/guide/yonetici-kilavuzu.md#masaüstü-uygulaması).

To build locally (Node 22.12+):

```bash
cd clients/desktop && npm ci && npm test   # type-check and unit tests
npm run dist                                # installers for this OS into release/ (needs Docker for the schema SQL)
# optional, for a machine without registry access (arch-specific):
bash scripts/bundle-image.sh linux/arm64 && npm run dist
```

Local builds are ad-hoc signed, not notarized, so macOS reports the app as "damaged". After checking where the file came from, clear the quarantine with `xattr -dr com.apple.quarantine /Applications/AutoSecOps.app`, or use **System Settings → Privacy & Security → Open Anyway**. The app has no auto-updater; its only network traffic is Docker pulling the five images it runs (backend, agent, `postgres:16-alpine`, `redis:7.2.16-alpine` (pinned by digest), `maximhq/bifrost:v2.2.1`) when they are not already loaded.

### Tests

```bash
source venv/bin/activate
pytest tests/unit tests/security -m "not external_service"   # same invocation as CI; no LLM key needed
```

---

## Getting help: the support bundle

`vigil-support.sh` writes one redacted `tar.gz` you can attach to a support request. It is POSIX `sh`, runs on Linux and macOS, and uploads nothing.

```bash
sh scripts/vigil-support/vigil-support.sh   # from a checkout
```

Without a checkout, download `autosecops-support-<version>.tar.gz` and its `.sha256` from the [release](https://github.com/SingularityRD/autosecops2/releases/latest), verify it, extract it, and run `sh autosecops-support/vigil-support.sh` (the script keeps its internal file name). The bundle it writes is `autosecops-support-<install|host>-<version>-<UTC time>.tar.gz`. The AutoSecOps desktop app shows the exact command under **Help → Support Bundle Command…** (also in the tray menu). For a Helm install, run it from your own machine with your current `kubectl` context: `--mode helm [--release NAME --namespace NS]`.

Re-run with `sudo` to include system logs that need elevation; the bundle still examines, and belongs to, the invoking user's install. `sudo` resets `VIGIL_DIR`, so pass `--state-dir` for a non-default State Directory.

> **DATA NOTICE:** the bundle holds host information: hostname, the full process list with command lines, system logs, and disk usage. Known credential formats are redacted, but secrets in free log text cannot be guaranteed caught. Review it before you share it.

When it finds an AutoSecOps install, the bundle also collects its configuration, health output, container status, and logs. Secrets, keys, and database contents are never included; `SUMMARY.txt` lists what was left out. See [`scripts/vigil-support/README.md`](scripts/vigil-support/README.md).

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Web console (React)  ·  Chat  ·  Desktop app  ·  /mcp clients    │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│  API (Python / FastAPI)                                           │
│  Findings · Cases · Approvals · Detections · ATT&CK · Workflows   │
└──────────────────────────────────────────────────────────────────┘
                │ enqueue runs (BullMQ / Redis)      ▲ backend tools
                ▼                                    │
┌──────────────────────────────────────────────────────────────────┐
│  Agent layer (TypeScript)                                         │
│  Workflow runtimes: compose · investigate · root cause · hunt     │
│  Agents call backend tools and MCP integration tools              │
└──────────────────────────────────────────────────────────────────┘
        │ model calls                       │ tool calls
        ▼                                   ▼
┌──────────────────────────┐  ┌────────────────────────────────────┐
│  Bifrost LLM gateway     │  │  MCP integrations                  │
│  Anthropic · OpenAI ·    │  │  SIEM · EDR · cloud · identity ·   │
│  Vertex · Ollama         │  │  intel · sandbox · ticketing · …   │
└──────────────────────────┘  └────────────────────────────────────┘

  PostgreSQL: findings, cases, approvals, runs, settings
  SOC daemon (optional): alert polling and auto-enrichment
```

## Project structure

```
autosecops2/
├── core/              # Shared Python library: domains (findings, cases, llm,
│   │                  #   integrations, …) over a storage/platform tier
│   ├── agents/        # Built-in agent definitions
│   ├── integrations/  # Vendor slices and the MCP registry
│   └── workflows/definitions/   # Built-in WORKFLOW.md files
├── services/
│   ├── api/           # FastAPI backend
│   ├── agent/         # TypeScript agent layer (workflow runtimes, worker + serve)
│   ├── daemon/        # Headless autonomous SOC
│   └── worker/        # ARQ LLM worker
├── clients/
│   ├── web/           # React + Tailwind frontend
│   └── desktop/       # Desktop app
├── tools/mcp/         # AutoSecOps's own MCP server and frozen tool snapshot
├── mcp-config.json    # MCP integration catalogue
└── infra/             # Docker Compose, Helm chart, DB init
```

## Documentation

| Doc | Contents |
|-----|----------|
| [docs/guide/](docs/guide/README.md) | Operator and administrator documentation (Turkish): scope, installation, administration, security, threat model, regulatory mapping |
| [infra/airgap/README.md](infra/airgap/README.md) | Air-gapped installation bundle: build, verify, install |
| [infra/helm/vigil/README.md](infra/helm/vigil/README.md) | Helm chart notes |
| [docs/release/dogrulama.md](docs/release/dogrulama.md) | Verifying release signatures, SBOMs and provenance |
| [docs/security/vex.md](docs/security/vex.md) | Unfixed image CVEs: VEX and risk acceptance |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting, supported versions, disclosure |
| [VERSIONING.md](VERSIONING.md) | What is frozen, what is not, and how the contract changes |
| [FORK.md](FORK.md) | How this repository relates to upstream Vigil |

## Contributing

Contributions go through pull requests on [SingularityRD/autosecops2](https://github.com/SingularityRD/autosecops2), signed off under the [DCO](DCO). Security issues are not reported in public issues: see [SECURITY.md](SECURITY.md).

## License

Apache 2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE) and [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES) (every Python and Node package with its licence, regenerated at each release). Every image carries these files under `/licenses`.

## Credits

AutoSecOps is based on Vigil (Apache-2.0), the open source agentic AI SOC by the Vigil-SOC project. Upstream attribution and the list of what changed are in [NOTICE](NOTICE) and [FORK.md](FORK.md).

- [Vigil](https://github.com/Vigil-SOC/vigil): the upstream project
- [DeepTempo](https://deeptempo.ai): sponsor of the upstream Vigil project
- [Model Context Protocol](https://modelcontextprotocol.io/): MCP specification
- [SOCBench](https://socbench.org): open benchmark for AI in cybersecurity operations
