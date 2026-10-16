"""Signing keys are part of installation (W0.36, U-13): Compose and Helm.

Compose runs ``signing-keys`` (provision into the encrypted store on the State
Directory volume) before the backend and daemon. Helm mints both keys into a
Secret kept across upgrades and uninstall, and hands each workload only the
key it signs with. The air-gap installer installs that chart (its install
test checks the public-key export step).
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from core.audit.checkpoint import load_private_key

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]
COMPOSE = REPO / "infra" / "docker" / "docker-compose.yml"
HELM = REPO / "infra" / "helm" / "vigil"
AIRGAP = REPO / "infra" / "airgap" / "values-airgap.yaml"
STATE = "vigil_home:/home/vigil/.vigil"


def _compose():
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def test_compose_provisions_before_backend_and_daemon():
    services = _compose()["services"]
    svc = services["signing-keys"]
    assert svc["entrypoint"] == ["python", "-m", "core.audit.signing_keys"]
    assert svc["command"][0] == "provision"
    assert "profiles" not in svc, "must run on the default `up`"
    assert svc["restart"] == "no"
    # Offline: it only writes the store, so it gets no network at all.
    assert svc["network_mode"] == "none"
    # The same State Directory (secrets.enc + master.key) the signers read.
    assert STATE in svc["volumes"]
    for name in ("backend", "soc-daemon"):
        assert STATE in services[name]["volumes"], name
        dep = services[name]["depends_on"]["signing-keys"]
        assert dep == {"condition": "service_completed_successfully"}, name
    # No key value is ever passed in through the environment.
    assert not any("SIGNING_KEY" in k for k in (svc.get("environment") or {}))


# --- Helm ---------------------------------------------------------------------


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


def _render(chart, *args):
    out = subprocess.run(
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
    assert out.returncode == 0, out.stderr
    return [d for d in yaml.safe_load_all(out.stdout) if d]


def _find(docs, kind, name):
    return next(
        (d for d in docs if d["kind"] == kind and d["metadata"]["name"] == name), None
    )


def _signing_sources(doc):
    """The envFrom Secrets of a pod that carry signing keys, in order."""
    spec = doc["spec"]["template"]["spec"]
    out = []
    for c in spec["containers"]:
        for i, src in enumerate(c.get("envFrom") or []):
            ref = src.get("secretRef")
            if ref and ("signing" in ref["name"] or ref["name"] == "my-keys"):
                out.append((i, ref))
        for e in c.get("env") or []:
            assert "SIGNING_KEY" not in e["name"], "signing keys come through envFrom"
    return out


def _main_secret_index(doc):
    c = doc["spec"]["template"]["spec"]["containers"][0]
    return next(
        i
        for i, src in enumerate(c["envFrom"])
        if (src.get("secretRef") or {}).get("name") == "rc-vigil-secrets"
    )


def test_helm_mints_each_key_into_its_own_kept_secret(chart):
    docs = _render(chart)
    names = {
        "rc-vigil-signing-key-checkpoint": "AUDIT_CHECKPOINT_SIGNING_KEY",
        "rc-vigil-signing-key-evidence": "EVIDENCE_PACK_SIGNING_KEY",
    }
    seeds = set()
    for name, key in names.items():
        secret = _find(docs, "Secret", name)
        assert secret is not None, name
        assert secret["metadata"]["annotations"]["helm.sh/resource-policy"] == "keep"
        assert set(secret["data"]) == {key}
        seed = base64.b64decode(secret["data"][key]).decode("ascii")
        load_private_key(seed)  # an Ed25519 seed the signers read
        seeds.add(seed)
    assert len(seeds) == 2


def test_helm_gives_each_workload_only_its_own_key(chart):
    docs = _render(chart)
    for kind, pod, secret in (
        ("StatefulSet", "rc-vigil-daemon", "rc-vigil-signing-key-checkpoint"),
        ("Deployment", "rc-vigil-backend", "rc-vigil-signing-key-evidence"),
    ):
        doc = _find(docs, kind, pod)
        [(index, ref)] = _signing_sources(doc)
        assert ref == {"name": secret, "optional": True}, pod
        # Before the main Secret: a key the operator supplies there wins.
        assert index < _main_secret_index(doc), pod
    for kind, name in (("Deployment", "rc-vigil-llm-worker"),):
        doc = _find(docs, kind, name)
        if doc is not None:
            assert _signing_sources(doc) == []


def test_helm_existing_secret_and_opt_out(chart):
    docs = _render(chart, "--set", "signingKeys.existingSecret=my-keys")
    assert not [d for d in docs if "signing-key-" in d["metadata"]["name"]]
    [(_, ref)] = _signing_sources(_find(docs, "Deployment", "rc-vigil-backend"))
    assert ref["name"] == "my-keys"

    docs = _render(chart, "--set", "signingKeys.generate=false")
    assert not [d for d in docs if "signing-key-" in d["metadata"]["name"]]
    assert _signing_sources(_find(docs, "Deployment", "rc-vigil-backend")) == []
    assert _signing_sources(_find(docs, "StatefulSet", "rc-vigil-daemon")) == []


def test_airgap_profile_provisions_the_keys(chart):
    docs = _render(chart, "-f", str(AIRGAP))
    assert _find(docs, "Secret", "rc-vigil-signing-key-checkpoint") is not None
    assert _find(docs, "Secret", "rc-vigil-signing-key-evidence") is not None
