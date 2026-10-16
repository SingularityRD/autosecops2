"""The case evidence store sits on a persistent, app-owned volume (W0.26, upstream #2280).

``./evidence`` resolved against the working directory, which in the images is
root-owned ``/app`` and on no volume: an attach failed, or wrote evidence into
the container layer that the next recreate threw away. The store is now
``<State Directory>/evidence``. On Compose that is the ``vigil_home`` named volume
the image pre-creates for uid 1000; on Helm, whose State Directory defaults to an
emptyDir, a persistent claim of its own is mounted at that path.

These run as root too (the upstream read-only-cwd test skips there).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from core.cases.case_evidence_service import CaseEvidenceService

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]
COMPOSE = REPO / "infra" / "docker" / "docker-compose.yml"
HELM = REPO / "infra" / "helm" / "vigil"
STATE_DIR = "/home/vigil/.vigil"
# Every pod that writes evidence (backend: attach), deletes it (daemon:
# retention) or records it (llm-worker: the MCP tool).
WRITERS_COMPOSE = ("backend", "soc-daemon", "llm-worker")
WRITERS_HELM = (
    "backend-deployment.yaml",
    "daemon-statefulset.yaml",
    "llm-worker-deployment.yaml",
)


def test_default_store_is_under_the_state_directory(tmp_path, monkeypatch):
    workdir = tmp_path / "app"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    monkeypatch.setenv("VIGIL_DIR", str(tmp_path / "state"))

    store = CaseEvidenceService()

    assert store.storage_path == tmp_path / "state" / "evidence"
    # Constructing the service (every evidence read does) touches no disk.
    assert not (tmp_path / "state").exists()
    assert list(workdir.iterdir()) == []


def test_an_explicit_store_path_still_wins(tmp_path):
    assert CaseEvidenceService(str(tmp_path / "x")).storage_path == tmp_path / "x"


def test_retention_deletes_from_the_same_store(tmp_path, monkeypatch):
    from core.compliance import retention

    monkeypatch.setenv("VIGIL_DIR", str(tmp_path / "state"))
    source = Path(retention.__file__).read_text(encoding="utf-8")
    # Retention resolves the root through the service, not its own path.
    assert "CaseEvidenceService().storage_path" in source
    assert os.path.realpath(CaseEvidenceService().storage_path) == os.path.realpath(
        tmp_path / "state" / "evidence"
    )


def _named_state_volume(compose: dict, service: str) -> str | None:
    for entry in compose["services"][service].get("volumes") or []:
        if isinstance(entry, str) and entry.rsplit(":", 1)[-1] == STATE_DIR:
            source = entry.rsplit(":", 1)[0]
            if source.startswith("${") and ":-" in source:
                source = source.split(":-", 1)[1][:-1]
            return source if source in (compose.get("volumes") or {}) else None
    return None


def test_compose_writers_share_the_named_state_volume():
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    sources = {s: _named_state_volume(compose, s) for s in WRITERS_COMPOSE}
    assert all(sources.values()), f"no named volume at {STATE_DIR}: {sources}"
    assert len(set(sources.values())) == 1, sources
    # The backup service carries the State Directory, so evidence is in backups.
    assert _named_state_volume(compose, "backup") == sources["backend"]


@pytest.mark.parametrize("dockerfile", ["Dockerfile.backend", "Dockerfile.daemon"])
def test_images_precreate_the_store_owned_by_the_app(dockerfile):
    text = (REPO / "infra" / "docker" / dockerfile).read_text(encoding="utf-8")
    run = re.search(
        r"RUN mkdir -p ([^\n\\]*)\\\n\s*&& chown -R vigil:vigil ([^\n]*)", text
    )
    assert run, f"{dockerfile}: no mkdir/chown of the runtime dirs"
    assert f"{STATE_DIR}/evidence" in run.group(1).split()
    assert "/home/vigil" in run.group(2).split()


# Main before W0.26: the default chart's pods must render exactly as they did.
BASE = "fa6e7229"
PODS = (
    "backend-deployment.yaml",
    "daemon-statefulset.yaml",
    "llm-worker-deployment.yaml",
)


def test_helm_evidence_claim_is_off_by_default_and_warned_about():
    values = yaml.safe_load((HELM / "values.yaml").read_text(encoding="utf-8"))
    persistence = values["evidence"]["persistence"]
    assert persistence["enabled"] is False
    assert persistence["accessModes"] == []  # required when enabled
    assert "NOT persistent" in (HELM / "values.yaml").read_text(encoding="utf-8")
    # fsGroup gives a mounted claim to the app's group.
    assert values["podSecurityContext"]["fsGroup"] == 1000

    env = (HELM / "templates" / "_env.tpl").read_text(encoding="utf-8")
    assert (
        'mountPath: {{ printf "%s/evidence" (trimSuffix "/" '
        ".Values.stateDirectory.mountPath) }}" in env
    )
    for name in WRITERS_HELM:
        text = (HELM / "templates" / name).read_text(encoding="utf-8")
        assert 'include "vigil.evidenceVolumeMount"' in text, name
        assert 'include "vigil.evidenceVolume"' in text, name

    pvc = (HELM / "templates" / "evidence-pvc.yaml").read_text(encoding="utf-8")
    assert 'include "vigil.evidence.validate"' in pvc
    assert "helm.sh/resource-policy: keep" in pvc
    notes = (HELM / "templates" / "NOTES.txt").read_text(encoding="utf-8")
    assert "EVIDENCE IS NOT PERSISTENT" in notes
    guide = (REPO / "docs" / "guide" / "yonetici-kilavuzu.md").read_text(
        encoding="utf-8"
    )
    assert "kalıcı değildir" in guide


def test_airgap_profile_leaves_the_claim_off():
    airgap = yaml.safe_load(
        (REPO / "infra" / "airgap" / "values-airgap.yaml").read_text(encoding="utf-8")
    )
    assert airgap["evidence"]["persistence"]["enabled"] is False


# --- rendered with helm, where a helm binary is available ----------------------


def _helm() -> str | None:
    return os.environ.get("VIGIL_TEST_HELM") or shutil.which("helm")


def _strip_dependencies(dest: Path) -> None:
    """Subchart dependencies need a network fetch; nothing here uses them."""
    meta = yaml.safe_load((dest / "Chart.yaml").read_text(encoding="utf-8"))
    meta.pop("dependencies", None)
    (dest / "Chart.yaml").write_text(yaml.safe_dump(meta), encoding="utf-8")
    (dest / "Chart.lock").unlink(missing_ok=True)


@pytest.fixture(scope="module")
def chart(tmp_path_factory):
    if not _helm():
        pytest.skip("no helm binary (set VIGIL_TEST_HELM to run)")
    dest = tmp_path_factory.mktemp("chart") / "vigil"
    shutil.copytree(HELM, dest, ignore=shutil.ignore_patterns("charts", "Chart.lock"))
    _strip_dependencies(dest)
    # NOTES.txt is not rendered by `helm template`: render it through tpl.
    shutil.copy(dest / "templates" / "NOTES.txt", dest / "files" / "zz-notes.txt")
    (dest / "templates" / "zz-notes.yaml").write_text(
        'notes: |\n{{ tpl (.Files.Get "files/zz-notes.txt") . | indent 2 }}\n',
        encoding="utf-8",
    )
    return dest


def _helm_template(chart: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            _helm(),
            "template",
            "rc",
            str(chart),
            "--set",
            "secrets.postgresPassword=x",
            *args,
        ],
        capture_output=True,
        text=True,
    )


def _render(chart: Path, template: str, *args: str) -> str:
    out = _helm_template(chart, "--show-only", f"templates/{template}", *args)
    assert out.returncode == 0, out.stderr
    return out.stdout


ON = ("--set", "evidence.persistence.enabled=true")
RWX = ON + ("--set", "evidence.persistence.accessModes={ReadWriteMany}")
RWO = ON + ("--set", "evidence.persistence.accessModes={ReadWriteOnce}")
AIRGAP = ("-f", str(REPO / "infra" / "airgap" / "values-airgap.yaml"))


def test_default_chart_renders_no_evidence_claim_or_mount(chart):
    out = _helm_template(chart)
    assert out.returncode == 0, out.stderr
    assert "vigil-evidence" not in out.stdout
    assert "component: evidence" not in out.stdout


def test_default_pods_match_main_before_w026(chart, tmp_path):
    has_base = subprocess.run(
        ["git", "-C", str(REPO), "cat-file", "-e", f"{BASE}^{{commit}}"],
        capture_output=True,
    )
    if has_base.returncode != 0:
        pytest.skip(f"{BASE} is not in this clone")
    archive = subprocess.run(
        ["git", "-C", str(REPO), "archive", BASE, "infra/helm/vigil"],
        capture_output=True,
        check=True,
    )
    subprocess.run(["tar", "-x", "-C", str(tmp_path)], input=archive.stdout, check=True)
    base = tmp_path / "infra" / "helm" / "vigil"
    _strip_dependencies(base)
    for name in PODS:
        for extra in ((), ("--set", "backup.enabled=true")):
            assert _without_later_changes(
                _render(chart, name, *extra)
            ) == _without_later_changes(_render(base, name, *extra)), name


# W0.36 later gave the backend and the daemon one signing-key envFrom source each.
_SIGNING_KEY_ENV = re.compile(
    r"^( +)- secretRef:\n\1    name: rc-vigil-signing-key-\w+\n\1    optional: true\n",
    re.MULTILINE,
)


# The ConfigMap gained keys after the base (W0.30's AUTOSECOPS_GUARDS and others),
# which changes every pod's checksum/config annotation and nothing else here.
_CONFIG_CHECKSUM = re.compile(r"^ +checksum/config: [0-9a-f]+\n", re.MULTILINE)


def _without_later_changes(rendered: str) -> str:
    return _CONFIG_CHECKSUM.sub("", _SIGNING_KEY_ENV.sub("", rendered))


def test_enabled_rwx_renders_an_rwx_claim_and_mounts_it(chart):
    pvc = yaml.safe_load(_render(chart, "evidence-pvc.yaml", *RWX))
    assert pvc["spec"]["accessModes"] == ["ReadWriteMany"]
    for name in PODS:
        assert "claimName: rc-vigil-evidence" in _render(chart, name, *RWX), name
    notes = _render(chart, "zz-notes.yaml", *RWX)
    assert "DEFAULT" in notes and "NOT PERSISTENT" not in notes
    quiet = _render(
        chart,
        "zz-notes.yaml",
        *RWX,
        "--set",
        "evidence.persistence.storageClassName=nfs",
    )
    assert "EVIDENCE" not in quiet


def test_enabled_without_access_modes_fails(chart):
    out = _helm_template(chart, *ON)
    assert out.returncode != 0
    assert "needs an explicit evidence.persistence.accessModes" in out.stderr


@pytest.mark.parametrize(
    "extra",
    [
        (),  # defaults: two backends, daemon standby, two llm-workers
        ("--set", "backend.replicaCount=1"),
        ("--set", "evidence.persistence.existingClaim=mine"),
    ],
)
def test_enabled_rwo_with_several_mounters_fails(chart, extra):
    out = _helm_template(chart, *RWO, *extra)
    assert out.returncode != 0
    assert (
        "ReadWriteOnce but" in out.stderr
        and "pods mount the evidence claim" in out.stderr
    )


def test_enabled_rwo_with_a_single_mounter_renders(chart):
    single = (
        "--set",
        "backend.replicaCount=1",
        "--set",
        "daemon.enabled=false",
        "--set",
        "llmWorker.enabled=false",
    )
    pvc = yaml.safe_load(_render(chart, "evidence-pvc.yaml", *RWO, *single))
    assert pvc["spec"]["accessModes"] == ["ReadWriteOnce"]
    # The backup job is one more node-independent mounter.
    out = _helm_template(chart, *RWO, *single, "--set", "backup.enabled=true")
    assert out.returncode != 0


def test_airgap_profile_is_consistent(chart):
    out = _helm_template(chart, *AIRGAP)
    assert out.returncode == 0, out.stderr
    assert "vigil-evidence" not in out.stdout
    assert "EVIDENCE IS NOT PERSISTENT" in _render(chart, "zz-notes.yaml", *AIRGAP)


def test_default_notes_say_evidence_is_not_persistent(chart):
    assert "EVIDENCE IS NOT PERSISTENT" in _render(chart, "zz-notes.yaml")


def test_the_backup_job_archives_the_claim_only_when_enabled(chart):
    on = ("--set", "backup.enabled=true")
    off = _render(chart, "backup-cronjob.yaml", *on)
    assert "vigil-evidence" not in off and "value: /evidence" not in off
    cron = next(
        d
        for d in yaml.safe_load_all(_render(chart, "backup-cronjob.yaml", *on, *RWX))
        if d and d["kind"] == "CronJob"
    )
    pod = cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    claims = {v["name"]: v.get("persistentVolumeClaim", {}) for v in pod["volumes"]}
    assert claims["vigil-evidence"] == {
        "claimName": "rc-vigil-evidence",
        "readOnly": True,
    }
    dump = pod["containers"][0]
    assert {"name": "EVIDENCE_DIR", "value": "/evidence"} in dump["env"]
    mount = next(m for m in dump["volumeMounts"] if m["name"] == "vigil-evidence")
    assert mount == {
        "name": "vigil-evidence",
        "mountPath": "/evidence",
        "readOnly": True,
    }
    assert pod["securityContext"]["fsGroup"] == 1000
    excluded = _render(
        chart, "backup-cronjob.yaml", *on, *RWX, "--set", "backup.includeEvidence=false"
    )
    assert "claimName: rc-vigil-evidence" not in excluded
