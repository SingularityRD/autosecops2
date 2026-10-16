"""Helm mints the data-encryption key at install (W0.34).

With SECRETS_BACKEND=database and DEV_MODE=false the backend refuses to start
without VIGIL_DATA_KEY. A default ``helm install`` (and the air-gap installer,
which installs this chart) must therefore start without anyone setting
secrets.dataEncryptionKey: the chart mints one into ``<fullname>-data-key``,
keeps it (resource policy), and every workload reads it before the main Secret,
so a key the operator supplies still wins.
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

HELM = Path(__file__).resolve().parents[3] / "infra" / "helm" / "vigil"
WORKLOADS = ("rc-vigil-backend", "rc-vigil-daemon", "rc-vigil-llm-worker")


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
    return [d for d in yaml.safe_load_all(out.stdout) if d], out.stdout


def _envfrom(doc):
    return doc["spec"]["template"]["spec"]["containers"][0]["envFrom"]


def _index(sources, name):
    return next(
        i
        for i, s in enumerate(sources)
        if (s.get("secretRef") or {}).get("name") == name
    )


def test_default_install_mints_a_kept_data_key(chart):
    docs, _ = _render(chart)
    secret = next(
        d
        for d in docs
        if d["kind"] == "Secret" and d["metadata"]["name"] == "rc-vigil-data-key"
    )
    assert secret["metadata"]["annotations"]["helm.sh/resource-policy"] == "keep"
    key = base64.b64decode(secret["data"]["VIGIL_DATA_KEY"]).decode()
    assert len(key) >= 32  # core/crypto/data_key.py needs 32+ characters


def test_every_workload_reads_it_before_the_main_secret(chart):
    docs, _ = _render(chart)
    found = 0
    for d in docs:
        if (
            d["kind"] in ("Deployment", "StatefulSet")
            and d["metadata"]["name"] in WORKLOADS
        ):
            src = _envfrom(d)
            data_key = _index(src, "rc-vigil-data-key")
            assert src[data_key]["secretRef"]["optional"] is True
            # Kubernetes lets the last envFrom source win: an operator's key wins.
            assert data_key < _index(src, "rc-vigil-secrets")
            found += 1
    assert found >= 2


def test_two_renders_mint_different_keys_without_lookup(chart):
    # Documented: helm template / GitOps cannot read the old Secret back.
    first = _render(chart)[0]
    second = _render(chart)[0]

    def key(docs):
        return next(d for d in docs if d["metadata"]["name"] == "rc-vigil-data-key")[
            "data"
        ]

    assert key(first) != key(second)


def test_existing_secret_or_generate_off_mints_nothing(chart):
    docs, _ = _render(chart, "--set", "dataKey.existingSecret=my-data-key")
    assert not any(d["metadata"]["name"] == "rc-vigil-data-key" for d in docs)
    backend = next(
        d
        for d in docs
        if d["kind"] == "Deployment" and d["metadata"]["name"] == "rc-vigil-backend"
    )
    assert _index(_envfrom(backend), "my-data-key") < _index(
        _envfrom(backend), "rc-vigil-secrets"
    )

    docs, _ = _render(chart, "--set", "dataKey.generate=false")
    assert not any(d["metadata"]["name"] == "rc-vigil-data-key" for d in docs)
    backend = next(
        d
        for d in docs
        if d["kind"] == "Deployment" and d["metadata"]["name"] == "rc-vigil-backend"
    )
    assert not any("data-key" in str(s) for s in _envfrom(backend))
