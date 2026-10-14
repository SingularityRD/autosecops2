"""Backend and daemon images are scanned in ci-cd.yml before any tag (WP W0.22).

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
    matrix = {e["component"]: e["dockerfile"] for e in job["strategy"]["matrix"]["include"]}
    assert matrix == {
        "backend": "infra/docker/Dockerfile.backend",
        "daemon": "infra/docker/Dockerfile.daemon",
    }
    release = _load(RELEASE_PATH)["jobs"]["build-images"]["strategy"]["matrix"]["include"]
    released = {e["component"]: e["dockerfile"] for e in release}
    for component, dockerfile in matrix.items():
        assert released[component] == dockerfile, component
    assert job["strategy"].get("fail-fast") is False


def test_guarded_least_privilege_no_secrets(raw: str, job: dict) -> None:
    assert job["if"] == CANONICAL
    assert job["permissions"] == {"contents": "read"}
    assert "secrets." not in _job_text(raw, JOB)


def test_actions_pinned_by_sha_and_match_release(raw: str, job: dict) -> None:
    release_refs = set(re.findall(r"uses: (\S+@[0-9a-f]{40})", RELEASE_PATH.read_text()))
    uses = [s["uses"] for s in job["steps"] if "uses" in s]
    assert uses
    for ref in uses:
        assert SHA_PIN.match(ref), f"not pinned by commit SHA: {ref}"
    for prefix in ("actions/checkout@", "docker/setup-buildx-action@", "docker/build-push-action@"):
        mine = {r for r in uses if r.startswith(prefix)}
        assert mine and mine <= release_refs, f"{prefix} differs from release.yml: {mine}"
    for line in _job_text(raw, JOB).splitlines():
        if re.match(r"^\s*(-\s+)?uses:", line):
            assert re.search(r"@[0-9a-f]{40} # v\d+(\.\d+)*$", line), line
    checkout = [s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout@")]
    assert all(s["with"]["persist-credentials"] is False for s in checkout)


def test_builds_locally_never_pushes(job: dict) -> None:
    (build,) = [s for s in job["steps"] if s.get("uses", "").startswith("docker/build-push-action@")]
    w = build["with"]
    assert w["push"] is False and w["load"] is True
    assert w["file"] == "${{ matrix.dockerfile }}"
    assert "PYTHON_VERSION=" in w["build-args"]


def test_trivy_reports_high_critical_and_fails_on_fixable_critical(job: dict) -> None:
    (report,) = _step(job, "Trivy — report")
    (gate,) = _step(job, "Trivy — fail")
    for s in (report, gate):
        assert s["uses"].startswith("aquasecurity/trivy-action@")
        assert re.match(r"^v\d+\.\d+\.\d+$", s["with"]["version"]), "pin the Trivy version"
        assert s["with"]["image-ref"] == "${{ env.IMAGE }}"
        assert "continue-on-error" not in s
    assert report["uses"] == gate["uses"]
    assert report["with"]["version"] == gate["with"]["version"]
    assert report["with"]["severity"] == "HIGH,CRITICAL"
    assert gate["with"]["severity"] == "CRITICAL"
    assert gate["with"]["ignore-unfixed"] is True
    # the gate is about vulnerabilities; secrets are reported, not gated
    assert gate["with"]["scanners"] == "vuln"
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
                assert step.get("with", {}).get("push") is False, f"{name}: push must be false"
            assert not re.search(r"\bdocker\s+(push|login)\b", step.get("run", "")), name
    assert not re.search(r"^\s*push:\s*true\b", raw, re.M)
