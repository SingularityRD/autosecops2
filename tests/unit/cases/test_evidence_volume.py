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


def test_helm_mounts_a_persistent_evidence_claim_by_default():
    values = yaml.safe_load((HELM / "values.yaml").read_text(encoding="utf-8"))
    persistence = values["evidence"]["persistence"]
    assert persistence["enabled"] is True
    # Empty: derived from how many pods mount it (see vigil.evidence.accessModes).
    assert persistence["accessModes"] == []
    # fsGroup gives the mounted claim to the app's group.
    assert values["podSecurityContext"]["fsGroup"] == 1000
    assert values["backup"]["includeEvidence"] is True

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
    assert "kind: PersistentVolumeClaim" in pvc
    assert "helm.sh/resource-policy: keep" in pvc
    assert "not .Values.evidence.persistence.existingClaim" in pvc
    assert 'include "vigil.evidence.accessModes"' in pvc


def test_airgap_values_choose_the_access_mode_explicitly():
    airgap = yaml.safe_load(
        (REPO / "infra" / "airgap" / "values-airgap.yaml").read_text(encoding="utf-8")
    )
    assert airgap["evidence"]["persistence"]["accessModes"] == ["ReadWriteOnce"]


# --- rendered with helm, where a helm binary is available ----------------------


def _helm() -> str | None:
    return os.environ.get("VIGIL_TEST_HELM") or shutil.which("helm")


@pytest.fixture(scope="module")
def chart(tmp_path_factory):
    """The chart without its subchart dependencies, which need a network fetch."""
    if not _helm():
        pytest.skip("no helm binary (set VIGIL_TEST_HELM to run)")
    dest = tmp_path_factory.mktemp("chart") / "vigil"
    shutil.copytree(HELM, dest, ignore=shutil.ignore_patterns("charts", "Chart.lock"))
    meta = yaml.safe_load((dest / "Chart.yaml").read_text(encoding="utf-8"))
    meta.pop("dependencies", None)
    (dest / "Chart.yaml").write_text(yaml.safe_dump(meta), encoding="utf-8")
    # NOTES.txt is not rendered by `helm template`: render it through tpl.
    shutil.copy(dest / "templates" / "NOTES.txt", dest / "files" / "zz-notes.txt")
    (dest / "templates" / "zz-notes.yaml").write_text(
        'notes: |\n{{ tpl (.Files.Get "files/zz-notes.txt") . | indent 2 }}\n',
        encoding="utf-8",
    )
    return dest


def _render(chart: Path, template: str, *args: str) -> str:
    out = subprocess.run(
        [
            _helm(),
            "template",
            "rc",
            str(chart),
            "--set",
            "secrets.postgresPassword=x",
            "--show-only",
            f"templates/{template}",
            *args,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout


def _modes(chart: Path, *args: str) -> list:
    pvc = yaml.safe_load(_render(chart, "evidence-pvc.yaml", *args))
    return pvc["spec"]["accessModes"]


SINGLE = (
    "--set",
    "backend.replicaCount=1",
    "--set",
    "daemon.leaderElection.enabled=false",
    "--set",
    "llmWorker.replicaCount=1",
)


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ((), ["ReadWriteMany"]),  # two backend replicas, daemon standby
        (SINGLE, ["ReadWriteOnce"]),  # one pod mounts it
        (("--set", "backend.replicaCount=1"), ["ReadWriteMany"]),  # daemon standby
        (SINGLE + ("--set", "backend.autoscaling.enabled=true"), ["ReadWriteMany"]),
        (SINGLE + ("--set", "llmWorker.replicaCount=2"), ["ReadWriteMany"]),
        (
            ("--set", "evidence.persistence.accessModes={ReadWriteOnce}"),
            ["ReadWriteOnce"],
        ),
        (
            ("-f", str(REPO / "infra" / "airgap" / "values-airgap.yaml")),
            ["ReadWriteOnce"],
        ),
    ],
)
def test_the_access_mode_follows_how_many_pods_mount_the_claim(chart, args, expected):
    assert _modes(chart, *args) == expected


@pytest.mark.parametrize(
    ("args", "warned"),
    [
        ((), True),
        (("--set", "evidence.persistence.storageClassName=nfs"), False),
        (("--set", "evidence.persistence.existingClaim=mine"), False),
        (SINGLE, False),
        (("-f", str(REPO / "infra" / "airgap" / "values-airgap.yaml")), False),
        (("--set", "evidence.persistence.enabled=false"), False),
    ],
)
def test_notes_warn_about_rwx_on_the_default_class(chart, args, warned):
    notes = _render(chart, "zz-notes.yaml", *args)
    assert ("EVIDENCE STORE" in notes) is warned


def test_the_backup_job_archives_the_evidence_claim(chart):
    on = ("--set", "backup.enabled=true")
    job = yaml.safe_load_all(_render(chart, "backup-cronjob.yaml", *on))
    cron = next(d for d in job if d and d["kind"] == "CronJob")
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
    # The app's group, so uid 70 reads the evidence without a re-grouping.
    assert pod["securityContext"]["fsGroup"] == 1000

    off = _render(
        chart, "backup-cronjob.yaml", *on, "--set", "backup.includeEvidence=false"
    )
    assert "vigil-evidence" not in off
