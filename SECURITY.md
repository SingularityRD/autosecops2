# Security Policy

AutoSecOps is a security product, and we hold it to the standard we ask of the
tools it integrates with: report vulnerabilities privately, get a human response
quickly, and coordinate disclosure so operators can patch before details are
public.

This policy covers AutoSecOps 2.x, developed by SingularityRD
(<https://github.com/SingularityRD/autosecops2>). AutoSecOps is based on Vigil
(Apache-2.0), but vulnerabilities in AutoSecOps are reported to us, not to the
upstream Vigil project. If you find that an issue also affects upstream Vigil,
tell us and we will coordinate with upstream.

---

## Supported Versions

| Version | Supported | Security fixes |
|---------|-----------|----------------|
| Latest `2.x` minor (currently `2.0.x`) | ✅ | Every fix ships in a patch release of this minor. |
| Previous `2.x` minor | ✅ for 6 months after the next minor is released | Critical and high fixes are backported as a patch release. |
| Older `2.x` minors | ❌ | Upgrade to a supported minor; [VERSIONING.md](VERSIONING.md) says what may change between releases. |
| `0.x` (Vigil-based releases before 2.0) | ❌ | Upgrade with [docs/upgrade-0.7-to-2.0.md](docs/upgrade-0.7-to-2.0.md). |
| `main` (unreleased) | Reports welcome | Note the commit SHA. |

**End of life.** When a minor reaches the end of its window it gets no further
fixes; the release notes of the minor that starts the window give the exact
end date. A new major (`3.0`) will be announced at least 6 months before the
last `2.x` minor leaves support. What may change between releases is in
[VERSIONING.md](VERSIONING.md).

Container images (`ghcr.io/singularityrd/autosecops-backend`, `autosecops-daemon`,
`autosecops-agent`), the Helm chart at `infra/helm/vigil/`, the air-gap bundle and
the desktop app follow the same window. Chart `version` and `appVersion` move in
lockstep, so the chart version identifies the app release it deploys.

**Base-image and OS packages.** Every image is scanned (Trivy). Operating-system
CVEs that have no fixed package yet, or that are not reachable from AutoSecOps,
are recorded with their exploitability assessment in
[docs/security/vex.md](docs/security/vex.md) and the OpenVEX file next to it, so
a scanner can tell "not affected" from "not fixed".

Release images are signed keyless by `.github/workflows/release.yml` (GitHub
OIDC → Fulcio, Rekor). Confirm an image came from that workflow (the identity
is pinned to this file and issuer, not any Actions run in the repo). Image tags
drop the leading `v`; the certificate identity uses the git tag:

```bash
cosign verify \
  --certificate-identity https://github.com/SingularityRD/autosecops2/.github/workflows/release.yml@refs/tags/v<version> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/singularityrd/autosecops-backend:<version>
```

The same invocation works for `autosecops-daemon` and `autosecops-agent`. Offline
verification of every release file: [docs/release/dogrulama.md](docs/release/dogrulama.md).

---

## Reporting a Vulnerability

**Do not open a public GitHub issue, pull request, or discussion for a security
vulnerability.** Do not disclose it on social media, a blog, or a conference
talk before the coordination window below has closed.

### 1. GitHub private vulnerability reporting (preferred)

**<https://github.com/SingularityRD/autosecops2/security/advisories/new>**

This is the fastest path. It gives us a private fork to develop and review the
fix in, keeps the whole thread with the eventual advisory, and lets us request a
CVE and credit you in one step. You need a GitHub account; nothing else.

### 2. Email

**`security@singularityrd.invalid`** is a placeholder. The address is an owner
decision that has not been made yet; the `.invalid` domain delivers nowhere on
purpose. Until a real address replaces it here, use the GitHub channel above.
Customers with a support contract can also report through their support
channel.

If you need to encrypt, say so in a first message with no technical detail and
we will reply with a key. Please do not send unsolicited encrypted mail.

### What to include

A report we can reproduce is a report we can fix in days instead of weeks:

- **Impact**: what an attacker gains (auth bypass, RCE, secret disclosure,
  privilege escalation, SSRF via an integration, prompt injection into an agent
  with tool access, bypass of the approval or four-eyes gate, audit-chain
  tampering, etc.).
- **Affected component**: path and, ideally, line: `services/api/`,
  `services/agent/`, `core/llm/`, an MCP server under `core/integrations/<vendor>/`,
  `clients/web/`, an `infra/database/init/` migration, the Helm chart, the
  air-gap bundle.
- **Version**: release tag, commit SHA, or image digest.
- **Reproduction**: minimal steps, a request/response pair, a curl invocation,
  a proof-of-concept, or a failing test. Include your `DEV_MODE` setting: with
  `DEV_MODE=true` authentication is bypassed by design, and findings that
  depend on it are not vulnerabilities (see [Out of scope](#out-of-scope)).
- **Deployment shape**: Compose, Helm, air-gap bundle, desktop app, or a
  native checkout.
- **Attribution**: how you want to be credited, or that you prefer to stay
  anonymous.

Please keep your testing to your own deployment. Do not test against another
organization's AutoSecOps instance or any third-party service an integration
talks to.

---

## What Happens Next

| Stage | Target |
|-------|--------|
| Acknowledgment that a human has your report | **3 business days** |
| Triage: confirmed or rejected, with severity | **7 business days** |
| Fix or documented mitigation, critical | **14 days** from triage |
| Fix or documented mitigation, high | **30 days** from triage |
| Fix or documented mitigation, medium | **90 days** from triage |
| Fix, low | Next scheduled release |
| Public advisory | Coordinated with you, see below |

We will tell you when something is going to slip rather than let the thread go
quiet. Throughout, we will confirm receipt, tell you whether we accept the
report and at what severity, keep you updated as the fix moves, and let you
review the advisory text and your credit line before it is published.

We ask you to give us a reasonable window before disclosing, not to access or
modify data that isn't yours, and to tell us if you believe the issue is being
exploited in the wild: that changes our timeline immediately.

We use [CVSS v3.1](https://www.first.org/cvss/calculator/3.1) to set severity.
Our rating drives our timeline, and we will explain it if it differs from yours.

---

## Coordinated Disclosure

Our default window is **90 days** from triage to public disclosure, or the day
the fix ships, whichever comes first. We publish sooner when a fix is ready
sooner.

We will ask to extend past 90 days only when a fix is genuinely hard (a schema
migration, a breaking interface change, an upstream dependency we don't
control), and we will say why. If we go quiet for 90 days with no fix and no
explanation, disclose: that is our failure, not yours.

Fixes are published as
[GitHub Security Advisories](https://github.com/SingularityRD/autosecops2/security/advisories)
on this repository. For anything of medium severity or above we request a CVE
through GitHub, note the advisory in [CHANGELOG.md](CHANGELOG.md) and the
release notes, and name the affected and fixed versions so operators can tell
whether they need to act. Customers with a support contract are notified
before the advisory is public, with the fixed version or the mitigation.

---

## Safe Harbor

If you make a good-faith effort to follow this policy, we will not pursue or
support legal action against you, and we consider your research authorized. If
a third party brings action against you for research that followed this policy,
we will say that it was authorized.

Good faith means: you test only against deployments you own or have written
permission to test, you stay within the scope below, you avoid privacy
violations (personal data in a SOC is data of real people), data destruction and
any degradation of service, you access only the minimum data needed to
demonstrate the issue, you delete any retained data once the report is closed,
and you report promptly and give us the coordination window.

There is no paid bug bounty. We credit you in the advisory and in the
[acknowledgments](#acknowledgments--hall-of-fame).

---

## Scope

### In scope

Anything in this repository that a deployment actually runs:

- **Authentication and authorization**: JWT handling in `core/`, the
  middleware under `services/api/middleware/`, RBAC, SSO, MFA, session and
  cookie handling, token revocation, CSRF.
- **API surface**: every router discovered by `services/api/discovery.py`:
  injection, SSRF, path traversal, IDOR, missing authorization, mass
  assignment, unsafe deserialization.
- **The agent and LLM layer**: `services/agent/`, `core/llm/`, `core/agents/`.
  Prompt injection that escalates into real capability (unapproved tool
  execution, exfiltration of secrets or case data, bypass of the approval,
  four-eyes or autonomy-tier gate) is in scope. Getting an agent to produce
  impolite or wrong text is not.
- **MCP integrations**: `core/integrations/<vendor>/`, `tools/mcp/`,
  `mcp-config.json`, and `core/integrations/mcp/service.py`: credential
  leakage into logs or agent context, command injection into a spawned
  server, TLS verification that can be silently disabled, and bypass of the
  approval workflow for actions that change the world (host isolation,
  firewall rules).
- **Secret handling**: the encrypted store in the State Directory,
  `core.secrets`, Helm secret plumbing, and anything that writes a credential
  to a log, an error response, a support bundle or the database in cleartext.
- **Audit and evidence**: the tamper-evident audit chain, audit export, and
  case evidence integrity.
- **Data layer**: SQL injection, the `infra/database/init/` migrations, and
  case isolation failures.
- **Web client**: `clients/web/`: XSS, CSRF, token storage, and anything that
  leaks one user's data to another.
- **Deployment artifacts**: the Dockerfiles and Compose file under
  `infra/docker/`, the Helm chart, the air-gap bundle and its installer, the
  desktop app, and `scripts/`: privilege escalation inside a container, a chart
  default that exposes an unauthenticated service, a secret baked into an image
  layer, a bundle verification bypass.
- **Supply chain**: a dependency with a known exploitable CVE reachable from
  AutoSecOps's own code paths, or a compromised build or release step.

### Out of scope

Not vulnerabilities. Reports on these will be closed with a pointer back here:

- **`DEV_MODE=true` bypassing authentication.** That is its documented purpose.
  It defaults to `false` in `core/config.py` and in `env.example`; a developer
  opts into it for a local instance, and the backend announces the bypass on
  every startup.
- **Default credentials in development material**: the default PostgreSQL
  password in `infra/docker/docker-compose.yml`, documented as
  must-change-before-production. No default admin login ships; the first
  account is created through `/api/auth/bootstrap`.
- **Placeholder values in `env.example`.** They are a template, not a
  configuration.
- **Findings that require a misconfiguration we already document as unsafe**,
  for example exposing port 6987 to the internet with `DEV_MODE=true`. If you
  find a case the [administrator guide](docs/guide/yonetici-kilavuzu.md) does
  *not* cover, that gap is worth reporting.
- **Vulnerabilities in a product AutoSecOps integrates with** (Splunk,
  CrowdStrike, VirusTotal, and the rest). Report those to that vendor. If
  AutoSecOps's *client* for one is what mishandles the credential or the
  response, that is in scope.
- **Scanner output with no demonstrated impact**: OS-package CVEs already
  assessed in [docs/security/vex.md](docs/security/vex.md), missing hardening
  headers with no exploit path, outdated dependencies with no reachable
  vulnerability, and self-XSS or clickjacking on pages with no sensitive action.
- **Denial of service through resource exhaustion or volumetric traffic**, and
  social engineering of staff or users. LLM cost amplification that defeats the
  spending ceilings *is* in scope: it costs operators real money.

---

## Hardening Your Deployment

Most incidents we would expect to see are configuration, not code. Before you
run AutoSecOps anywhere real, read the
[administrator guide](docs/guide/yonetici-kilavuzu.md) and the
[security technical document](docs/guide/guvenlik-teknik-belgesi.md) (Turkish).

Non-negotiables: set `DEV_MODE=false`, generate a real `JWT_SECRET_KEY`, change
the default database password, terminate TLS in front of the API, keep the
approval defaults, and never commit a credential.

---

## Security in Development

Contributions are held to the same bar, enforced in CI (`ci-cd.yml`, plus the
nightly audit in `nightly.yml`):

- `bandit` for Python and `npm audit` for the Node packages.
- Trivy scans of every image, and CycloneDX SBOMs, signatures and SLSA
  provenance on every release.
- Dependabot for dependency updates (`.github/dependabot.yml`).
- Ratchet tests under `tests/unit/_ratchets/` (no ambient environment reads, no
  disabled TLS verification, pinned third-party images, and more).
- `lint-imports` enforcing the layering in `.importlinter`.

If you are fixing a reported vulnerability, coordinate with the maintainers
**before** opening a public pull request: a PR that describes the bug discloses
it. We will work with you in the private advisory fork instead.

---

## Acknowledgments & Hall of Fame

Researchers who have reported valid vulnerabilities to AutoSecOps and
coordinated disclosure with us. We add you here when the advisory publishes,
with the name or handle you asked for, or not at all if you would rather stay
anonymous.

<!-- Add entries newest first: - **Name / handle**: short description of the issue (advisory GHSA-xxxx, YYYY-MM) -->

_No entries yet._
