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
    run = re.search(r"RUN mkdir -p ([^\n\\]*)\\\n\s*&& chown -R vigil:vigil ([^\n]*)", text)
    assert run, f"{dockerfile}: no mkdir/chown of the runtime dirs"
    assert f"{STATE_DIR}/evidence" in run.group(1).split()
    assert "/home/vigil" in run.group(2).split()


def test_helm_mounts_a_persistent_evidence_claim_by_default():
    values = yaml.safe_load((HELM / "values.yaml").read_text(encoding="utf-8"))
    persistence = values["evidence"]["persistence"]
    assert persistence["enabled"] is True
    # backend.replicaCount > 1 shares the claim across pods.
    assert values["backend"]["replicaCount"] <= 1 or persistence["accessModes"] == [
        "ReadWriteMany"
    ]
    # fsGroup gives the mounted claim to the app's group.
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
    assert "kind: PersistentVolumeClaim" in pvc
    assert "helm.sh/resource-policy: keep" in pvc
    assert "not .Values.evidence.persistence.existingClaim" in pvc
