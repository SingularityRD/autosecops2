"""Helm: OpenShift's restricted-v2 SCC picks the uid, the chart must not (W0.54).

With ``openshift.enabled`` no pod or container may ask for a fixed uid, gid or
fsGroup; the SCC assigns them from the namespace range. A Route can front the
backend. Off by default, the chart renders as before.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[3]
HELM = ROOT / "infra" / "helm" / "vigil"
FIXED = ("runAsUser", "runAsGroup", "fsGroup", "fsGroupChangePolicy")
EVERYTHING = [
    "daemon.enabled=true",
    "llmWorker.enabled=true",
    "medic.enabled=true",
    "medic.gateway.viewer.username=viewer",
    "medic.gateway.viewer.passwordSecret.name=medic-viewer",
    "medic.kubeApi.cidrs[0]=10.0.0.1/32",
    "pgadmin.enabled=true",
    "dbInit.enabled=true",
    "backup.enabled=true",
    "backup.persistence.enabled=true",
]


def _helm():
    return os.environ.get("VIGIL_TEST_HELM") or shutil.which("helm")


@pytest.fixture(scope="module")
def chart(tmp_path_factory):
    if not _helm():
        pytest.skip("no helm binary (set VIGIL_TEST_HELM to run)")
    dest = tmp_path_factory.mktemp("chart") / "vigil"
    shutil.copytree(HELM, dest, ignore=shutil.ignore_patterns("charts", "Chart.lock"))
    meta = yaml.safe_load((dest / "Chart.yaml").read_text(encoding="utf-8"))
    meta.pop("dependencies", None)
    (dest / "Chart.yaml").write_text(yaml.safe_dump(meta), encoding="utf-8")
    return dest


def _render(chart, *sets):
    args = [
        _helm(),
        "template",
        "rc",
        str(chart),
        "--set",
        "secrets.postgresPassword=x",
    ]
    for s in sets:
        args += ["--set", s]
    out = subprocess.run(args, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return [d for d in yaml.safe_load_all(out.stdout) if d]


def _pod_specs(docs):
    for d in docs:
        spec = d.get("spec") or {}
        if d["kind"] == "CronJob":
            spec = spec["jobTemplate"]["spec"]
        tpl = (spec.get("template") or {}).get("spec")
        if tpl:
            yield d["kind"], d["metadata"]["name"], tpl


def _fixed_ids(pod):
    found = [k for k in FIXED if k in (pod.get("securityContext") or {})]
    for c in pod.get("containers", []) + pod.get("initContainers", []):
        found += [
            f"{c['name']}.{k}" for k in FIXED if k in (c.get("securityContext") or {})
        ]
    return found


def test_default_keeps_fixed_ids_and_no_route(chart):
    docs = _render(chart, *EVERYTHING)
    assert "Route" not in {d["kind"] for d in docs}
    backend = next(
        p for k, n, p in _pod_specs(docs) if k == "Deployment" and n.endswith("backend")
    )
    assert backend["securityContext"]["runAsUser"] == 1000


def test_openshift_leaves_every_uid_to_the_scc(chart):
    docs = _render(chart, "openshift.enabled=true", *EVERYTHING)
    pods = list(_pod_specs(docs))
    assert len(pods) >= 8
    offenders = {f"{k}/{n}": ids for k, n, p in pods if (ids := _fixed_ids(p))}
    assert offenders == {}
    for _, _, pod in pods:
        assert (pod.get("securityContext") or {}).get("runAsNonRoot") in (True, None)


def test_openshift_route_fronts_the_backend(chart):
    docs = _render(
        chart,
        "openshift.enabled=true",
        "openshift.route.enabled=true",
        "openshift.route.host=soc.example.com",
    )
    route = next(d for d in docs if d["kind"] == "Route")
    assert route["apiVersion"] == "route.openshift.io/v1"
    assert route["spec"]["host"] == "soc.example.com"
    assert route["spec"]["to"]["name"].endswith("backend")
    assert route["spec"]["port"]["targetPort"] == "http"
    assert route["spec"]["tls"]["termination"] == "edge"


def test_route_needs_openshift_enabled(chart):
    docs = _render(chart, "openshift.route.enabled=true")
    assert "Route" not in {d["kind"] for d in docs}


@pytest.mark.parametrize("dockerfile", ["Dockerfile.backend", "Dockerfile.daemon"])
def test_images_keep_writable_paths_group_zero_writable(dockerfile):
    text = (ROOT / "infra" / "docker" / dockerfile).read_text(encoding="utf-8")
    assert "chgrp -R 0" in text and "g=u" in text
