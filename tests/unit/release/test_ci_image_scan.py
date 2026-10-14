"""Backend and daemon images are scanned in ci-cd.yml before any tag (WP W0.22).

W0.23: every Trivy step in ci-cd.yml (Agent Image included) runs the same
SHA-pinned action and Trivy version, and the gates fail on secrets too, with no
allow-list or skip that could hide one.

release.yml builds and signs backend, daemon and agent on a tag. Until W0.22
only the agent image was built and scanned on PRs; this pins the job that does
the same for backend and daemon, and the rule that ci-cd.yml never pushes an
image anywhere (publishing is release.yml's job).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]
CI_PATH = REPO / ".github" / "workflows" / "ci-cd.yml"
RELEASE_PATH = REPO / ".github" / "workflows" / "release.yml"
CANONICAL = "github.repository == 'SingularityRD/autosecops2'"
SHA_PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
JOB = "build-service-images"


def _load(path: Path) -> dict:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if True in doc:  # YAML 1.1 reads the bare key `on` as boolean True
        doc["on"] = doc.pop(True)
    return doc


@pytest.fixture(scope="module")
def raw() -> str:
    return CI_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def ci() -> dict:
    return _load(CI_PATH)


@pytest.fixture(scope="module")
def job(ci: dict) -> dict:
    assert JOB in ci["jobs"], f"ci-cd.yml has no {JOB} job"
    return ci["jobs"][JOB]


def _step(job: dict, prefix: str) -> list[dict]:
    return [s for s in job["steps"] if s.get("name", "").startswith(prefix)]


def _job_text(raw: str, name: str) -> str:
    """The job's block of ci-cd.yml, comments included."""
    m = re.search(rf"^  {re.escape(name)}:\n(.*?)(?=^  [\w-]+:\n|\Z)", raw, re.M | re.S)
    assert m, name
    return m.group(1)


def test_actionlint_clean_when_available() -> None:
    exe = os.environ.get("ACTIONLINT") or shutil.which("actionlint")
    if not exe:
        pytest.skip("actionlint not installed; the Lint Backend job runs it in CI")
    proc = subprocess.run(
        [exe, "-no-color", str(CI_PATH)], capture_output=True, text=True, cwd=REPO
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_runs_on_push_to_main_and_on_prs(ci: dict) -> None:
    on = ci["on"]
    assert "main" in on["push"]["branches"]
    assert "main" in on["pull_request"]["branches"]
    assert "workflow_dispatch" in on


def test_builds_backend_and_daemon_from_the_release_dockerfiles(job: dict) -> None:
    matrix = {
        e["component"]: e["dockerfile"] for e in job["strategy"]["matrix"]["include"]
    }
    assert matrix == {
        "backend": "infra/docker/Dockerfile.backend",
        "daemon": "infra/docker/Dockerfile.daemon",
    }
    release = _load(RELEASE_PATH)["jobs"]["build-images"]["strategy"]["matrix"][
        "include"
    ]
    released = {e["component"]: e["dockerfile"] for e in release}
    for component, dockerfile in matrix.items():
        assert released[component] == dockerfile, component
    assert job["strategy"].get("fail-fast") is False


def test_guarded_least_privilege_no_secrets(raw: str, job: dict) -> None:
    assert job["if"] == CANONICAL
    assert job["permissions"] == {"contents": "read"}
    assert "secrets." not in _job_text(raw, JOB)


def test_actions_pinned_by_sha_and_match_release(raw: str, job: dict) -> None:
    release_refs = set(
        re.findall(r"uses: (\S+@[0-9a-f]{40})", RELEASE_PATH.read_text())
    )
    uses = [s["uses"] for s in job["steps"] if "uses" in s]
    assert uses
    for ref in uses:
        assert SHA_PIN.match(ref), f"not pinned by commit SHA: {ref}"
    for prefix in (
        "actions/checkout@",
        "docker/setup-buildx-action@",
        "docker/build-push-action@",
    ):
        mine = {r for r in uses if r.startswith(prefix)}
        assert (
            mine and mine <= release_refs
        ), f"{prefix} differs from release.yml: {mine}"
    for line in _job_text(raw, JOB).splitlines():
        if re.match(r"^\s*(-\s+)?uses:", line):
            assert re.search(r"@[0-9a-f]{40} # v\d+(\.\d+)*$", line), line
    checkout = [
        s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout@")
    ]
    assert all(s["with"]["persist-credentials"] is False for s in checkout)


def test_builds_locally_never_pushes(job: dict) -> None:
    (build,) = [
        s
        for s in job["steps"]
        if s.get("uses", "").startswith("docker/build-push-action@")
    ]
    w = build["with"]
    assert w["push"] is False and w["load"] is True
    assert w["file"] == "${{ matrix.dockerfile }}"
    assert "PYTHON_VERSION=" in w["build-args"]


def test_trivy_reports_high_critical_and_fails_on_fixable_critical(job: dict) -> None:
    (report,) = _step(job, "Trivy — report")
    (gate,) = _step(job, "Trivy — fail")
    for s in (report, gate):
        assert s["uses"].startswith("aquasecurity/trivy-action@")
        assert re.match(
            r"^v\d+\.\d+\.\d+$", s["with"]["version"]
        ), "pin the Trivy version"
        assert s["with"]["image-ref"] == "${{ env.IMAGE }}"
        assert "continue-on-error" not in s
    assert report["uses"] == gate["uses"]
    assert report["with"]["version"] == gate["with"]["version"]
    assert report["with"]["severity"] == "HIGH,CRITICAL"
    assert gate["with"]["severity"] == "CRITICAL"
    assert gate["with"]["ignore-unfixed"] is True
    # W0.23: the gate fails on secrets as well as vulnerabilities
    assert gate["with"]["scanners"] == "vuln,secret"
    assert "scanners" not in report["with"]
    assert str(gate["with"]["exit-code"]) == "1"
    names = [s.get("name", "") for s in job["steps"]]
    assert names.index(report["name"]) < names.index(gate["name"])


def test_smoke_test_runs_the_image(job: dict) -> None:
    (smoke,) = _step(job, "Smoke test")
    assert '"$IMAGE"' in smoke["run"] and "docker run --rm" in smoke["run"]
    # matrix values reach the shell through env, not ${{ }} in the script
    assert "${{" not in smoke["run"]
    smokes = {e["component"]: e["smoke"] for e in job["strategy"]["matrix"]["include"]}
    assert "services.api.main" in smokes["backend"]
    assert "services.daemon.main" in smokes["daemon"]


def test_ci_cd_never_pushes_or_logs_in_to_a_registry(raw: str, ci: dict) -> None:
    for name, j in ci["jobs"].items():
        perms = j.get("permissions") or {}
        assert perms != "write-all", name
        assert "packages" not in perms, f"{name}: ci-cd.yml does not publish packages"
        for step in j.get("steps", []):
            uses = step.get("uses", "")
            assert not uses.startswith("docker/login-action"), name
            if uses.startswith("docker/build-push-action"):
                assert (
                    step.get("with", {}).get("push") is False
                ), f"{name}: push must be false"
            assert not re.search(
                r"\bdocker\s+(push|login)\b", step.get("run", "")
            ), name
    assert not re.search(r"^\s*push:\s*true\b", raw, re.M)


# --- W0.23: one pinned Trivy everywhere, secrets gated, nothing waived --------

TRIVY_STEP_INPUTS_THAT_HIDE_FINDINGS = (
    "trivyignores",
    "skip-dirs",
    "skip-files",
    "secret-config",
    "trivy-config",
)
SECRET_CONFIG = REPO / "trivy-secret.yaml"
# The text Trivy's gcp-service-account rule matches, spelled loosely so this
# file does not match it itself.
KEY_FILE_SHAPE = re.compile(r'"type"\s*:\s*"service_account"')


def _trivy_steps(ci: dict) -> list[tuple[str, dict]]:
    return [
        (name, step)
        for name, j in ci["jobs"].items()
        for step in j.get("steps", [])
        if "trivy" in step.get("uses", "").lower()
    ]


def test_no_unpinned_trivy_anywhere(raw: str, ci: dict) -> None:
    steps = _trivy_steps(ci)
    assert len(steps) >= 4, "Agent Image and Service Image each report and gate"
    assert {name for name, _ in steps} >= {"build-agent-image", JOB}
    refs = {s["uses"] for _, s in steps}
    versions = {s.get("with", {}).get("version") for _, s in steps}
    assert len(refs) == 1, f"one trivy-action pin for every step: {refs}"
    assert len(versions) == 1, f"one Trivy version for every step: {versions}"
    (ref,) = refs
    (version,) = versions
    assert SHA_PIN.match(ref), ref
    assert version and re.match(r"^v\d+\.\d+\.\d+$", version), version
    # no floating ref in any spelling, in steps or comments
    assert not re.search(r"trivy[\w/-]*@(master|main|latest)\b", raw, re.I)
    assert not re.search(r"^\s*version:\s*['\"]?latest", raw, re.M | re.I)
    for line in raw.splitlines():
        if "uses:" in line and "trivy" in line.lower():
            assert re.search(r"@[0-9a-f]{40} # v\d+\.\d+\.\d+$", line), line


def test_agent_image_gate_matches_service_image_gate(ci: dict) -> None:
    agent = ci["jobs"]["build-agent-image"]
    (a_report,) = _step(agent, "Trivy — report")
    (a_gate,) = _step(agent, "Trivy — fail")
    (s_gate,) = _step(ci["jobs"][JOB], "Trivy — fail")
    assert a_report["with"]["severity"] == "HIGH,CRITICAL"
    for key in ("scanners", "severity", "ignore-unfixed", "exit-code", "version"):
        assert a_gate["with"][key] == s_gate["with"][key], key
    names = [s.get("name", "") for s in agent["steps"]]
    assert names.index(a_report["name"]) < names.index(a_gate["name"])


def test_every_gate_fails_on_secrets_and_waives_nothing(ci: dict) -> None:
    gates = [
        (n, s) for n, s in _trivy_steps(ci) if s["name"].startswith("Trivy — fail")
    ]
    assert len(gates) == 2
    for name, step in gates:
        w = step["with"]
        assert set(w["scanners"].split(",")) == {"vuln", "secret"}, name
        assert str(w["exit-code"]) == "1", name
        assert "continue-on-error" not in step, name
    for name, step in _trivy_steps(ci):
        w = step.get("with", {})
        for key in TRIVY_STEP_INPUTS_THAT_HIDE_FINDINGS:
            assert key not in w, f"{name}/{step['name']}: {key} would hide findings"


def test_no_secret_allow_list_exists() -> None:
    """W0.23 fixed the one finding at the source instead of allow-listing it.

    A trivy-secret.yaml at the repo root is read by Trivy by default, so one
    added later would waive findings without touching ci-cd.yml. If one is ever
    needed it must be narrow: every allow-rule names a single file by an
    anchored path and a regex, nothing disables a rule or a whole directory.
    """
    for name in (".trivyignore", ".trivyignore.yaml", "trivy.yaml"):
        assert not (
            REPO / name
        ).exists(), f"{name} is read by default and waives findings"
    if not SECRET_CONFIG.exists():
        return
    doc = yaml.safe_load(SECRET_CONFIG.read_text(encoding="utf-8")) or {}
    assert not doc.get("disable-rules"), "disabling a rule waives it everywhere"
    assert not doc.get("disable-allow-rules")
    for rule in doc.get("allow-rules") or []:
        assert rule.get("id") and rule.get("description"), rule
        assert rule.get("regex"), f"{rule['id']}: allow a string, not a whole file"
        path = rule.get("path")
        assert path, f"{rule['id']}: scope the allow-rule to one file"
        assert path.startswith("^") and path.endswith("$"), path
        assert ".*" not in path and ".+" not in path, f"{rule['id']}: no path wildcards"


def test_web_ui_ships_no_key_file_shaped_text() -> None:
    """The SPA is in the backend image; key-shaped placeholders trip the gate."""
    src = REPO / "clients" / "web" / "src"
    hits = [
        str(p.relative_to(REPO))
        for p in src.rglob("*")
        if p.suffix in {".ts", ".tsx", ".js", ".jsx", ".json", ".html"}
        and "generated" not in p.parts
        and KEY_FILE_SHAPE.search(p.read_text(encoding="utf-8", errors="replace"))
    ]
    assert hits == [], hits
