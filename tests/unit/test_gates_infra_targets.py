"""scripts/wp/gates.sh: a non-Python infra change runs the tests that read it.

Before W0.13 an infra/ change that was not a .py file pulled in only
tests/unit/_ratchets, so a change to infra/staging/*.sh, infra/airgap/*.sh or
a Helm template passed gates without tests/unit/staging, tests/unit/airgap or
tests/unit/platform (test_helm_daemon_ha.py, the backup CronJob) ever running.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
GATES = REPO / "scripts" / "wp" / "gates.sh"

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "scripts" / "wp").mkdir(parents=True)
    shutil.copy2(GATES, repo / "scripts" / "wp" / "gates.sh")
    for d in ("_ratchets", "staging", "airgap", "platform"):
        (repo / "tests" / "unit" / d).mkdir(parents=True)
        (repo / "tests" / "unit" / d / "test_x.py").write_text("def test_x(): pass\n")
    for f in (
        "infra/staging/nightly.sh",
        "infra/airgap/install.sh",
        "infra/helm/vigil/templates/job.yaml",
    ):
        (repo / f).parent.mkdir(parents=True, exist_ok=True)
        (repo / f).write_text("x\n")
    _git(repo, "init", "-q", "-b", "base")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")
    _git(repo, "checkout", "-qb", "work")
    return repo


def _targets(repo: Path, path: str) -> str:
    (repo / path).write_text("y\n")
    _git(repo, "commit", "-qam", "change")
    proc = subprocess.run(
        ["bash", "scripts/wp/gates.sh", "--base", "base", "--dry-run"],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=120,
    )
    out = proc.stdout + proc.stderr
    line = next((ln for ln in out.splitlines() if "pytest targets:" in ln), "")
    assert line, out
    return line


@pytest.mark.parametrize(
    "path, expected, absent",
    [
        ("infra/staging/nightly.sh", ["tests/unit/staging"], ["tests/unit/airgap"]),
        ("infra/airgap/install.sh", ["tests/unit/airgap"], ["tests/unit/staging"]),
        (
            "infra/helm/vigil/templates/job.yaml",
            ["tests/unit/platform"],
            ["tests/unit/staging"],
        ),
    ],
)
def test_infra_change_runs_its_area_tests(tmp_path, path, expected, absent):
    line = _targets(_repo(tmp_path), path)
    assert "tests/unit/_ratchets" in line
    for t in expected:
        assert t in line, line
    for t in absent:
        assert t not in line, line


def test_an_infra_change_also_runs_the_upgrade_ratchet(tmp_path):
    """W0.44: the frozen init SQL ratchet lives outside _ratchets."""
    repo = _repo(tmp_path)
    (repo / "tests" / "unit" / "test_upgrade_database.py").write_text(
        "def test_x(): pass\n"
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "ratchet")
    line = _targets(repo, "infra/helm/vigil/templates/job.yaml")
    assert "tests/unit/test_upgrade_database.py" in line
