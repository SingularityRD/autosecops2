"""Helm: the chart can run its own Bifrost and Ollama (W0.55, O4).

Off by default, the chart expects Services "bifrost" and "ollama" (the air-gap
installer's k8s/llm-stack.yaml). Turned on, it runs them, points BIFROST_URL
and OLLAMA_URL at its own Services, and lets only the model callers reach them.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[3]
HELM = ROOT / "infra" / "helm" / "vigil"
ON = ["llmStack.bifrost.enabled=true", "llmStack.ollama.enabled=true"]


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
    args = [_helm(), "template", "rc", str(chart)]
    for s in ("secrets.postgresPassword=x", *sets):
        args += ["--set", s]
    out = subprocess.run(args, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return [d for d in yaml.safe_load_all(out.stdout) if d]


def _get(docs, kind, name):
    return next(d for d in docs if d["kind"] == kind and d["metadata"]["name"] == name)


def _config(docs):
    return _get(docs, "ConfigMap", "rc-vigil-config")["data"]


def _seed(docs):
    return json.loads(
        _get(docs, "ConfigMap", "rc-vigil-bifrost-seed")["data"]["config.json"]
    )


def test_off_by_default_keeps_the_external_service_names(chart):
    docs = _render(chart)
    names = {d["metadata"]["name"] for d in docs}
    assert not {"rc-vigil-bifrost", "rc-vigil-ollama"} & names
    assert _config(docs)["BIFROST_URL"] == "http://bifrost:8080"
    assert _config(docs)["OLLAMA_URL"] == "http://ollama:11434"


def test_on_points_the_app_at_its_own_services(chart):
    docs = _render(chart, *ON)
    cfg = _config(docs)
    assert cfg["BIFROST_URL"] == "http://rc-vigil-bifrost:8080"
    assert cfg["OLLAMA_URL"] == "http://rc-vigil-ollama:11434"
    for name, port in (("rc-vigil-bifrost", 8080), ("rc-vigil-ollama", 11434)):
        assert _get(docs, "Service", name)["spec"]["ports"][0]["port"] == port
        dep = _get(docs, "Deployment", name)
        pod = dep["spec"]["template"]["spec"]
        assert pod["automountServiceAccountToken"] is False
        assert pod["securityContext"]["runAsNonRoot"] is True
        c = pod["containers"][0]
        assert c["securityContext"]["allowPrivilegeEscalation"] is False
    bifrost = _get(docs, "Deployment", "rc-vigil-bifrost")["spec"]["template"]["spec"]
    env = {e["name"]: e["value"] for e in bifrost["containers"][0]["env"]}
    assert env["OLLAMA_URL"] == "http://rc-vigil-ollama:11434"
    ollama = _get(docs, "Deployment", "rc-vigil-ollama")["spec"]["template"]["spec"]
    env = {e["name"]: e["value"] for e in ollama["containers"][0]["env"]}
    assert env["HOME"] == "/models" and env["OLLAMA_NOPRUNE"] == "1"


def test_seed_has_cloud_providers_only_with_a_key_secret(chart):
    seed = _seed(_render(chart, *ON))
    assert set(seed["providers"]) == {"ollama"}
    docs = _render(chart, *ON, "llmStack.bifrost.providerKeysSecret=llm-keys")
    seed = _seed(docs)
    assert set(seed["providers"]) == {"ollama", "anthropic", "openai", "gemini"}
    assert seed["providers"]["anthropic"]["keys"][0]["value"] == "env.ANTHROPIC_API_KEY"
    # The keys come from the Secret, never from values or the ConfigMap.
    assert "sk-" not in json.dumps(seed)
    pod = _get(docs, "Deployment", "rc-vigil-bifrost")["spec"]["template"]["spec"]
    assert pod["containers"][0]["envFrom"] == [
        {"secretRef": {"name": "llm-keys", "optional": True}}
    ]


def test_only_model_callers_reach_bifrost(chart):
    docs = _render(chart, *ON, "networkPolicies.enabled=true")
    pol = _get(docs, "NetworkPolicy", "rc-vigil-bifrost")
    rule = pol["spec"]["ingress"][0]
    comps = {
        p["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
        for p in rule["from"]
    }
    assert "medic" not in comps and "bifrost" not in comps
    assert {"backend", "daemon", "llm-worker"} <= comps
    assert all("namespaceSelector" not in p for p in rule["from"])
    assert rule["ports"] == [{"protocol": "TCP", "port": 8080}]
    ollama = _get(docs, "NetworkPolicy", "rc-vigil-ollama")["spec"]["ingress"][0]
    comps = {
        p["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
        for p in ollama["from"]
    }
    assert "bifrost" in comps and "medic" not in comps


def test_openshift_leaves_the_uid_to_the_scc(chart):
    docs = _render(chart, *ON, "openshift.enabled=true")
    for name in ("rc-vigil-bifrost", "rc-vigil-ollama"):
        sc = _get(docs, "Deployment", name)["spec"]["template"]["spec"][
            "securityContext"
        ]
        assert not {"runAsUser", "runAsGroup", "fsGroup"} & set(sc)


def test_image_tags_match_compose_and_the_airgap_manifest():
    values = yaml.safe_load((HELM / "values.yaml").read_text(encoding="utf-8"))
    stack = values["llmStack"]
    compose = (ROOT / "infra" / "docker" / "docker-compose.yml").read_text(
        encoding="utf-8"
    )
    tag = re.search(r"BIFROST_IMAGE_TAG:-([^}]+)\}", compose).group(1)
    assert stack["bifrost"]["image"]["tag"] == tag
    manifest = (ROOT / "infra" / "airgap" / "k8s" / "llm-stack.yaml").read_text(
        encoding="utf-8"
    )
    images = set(re.findall(r"image:\s*(\S+)", manifest))
    for part in ("bifrost", "ollama"):
        img = stack[part]["image"]
        assert f"{img['repository']}:{img['tag']}" in images


def test_airgap_profile_leaves_the_stack_to_the_installer():
    airgap = yaml.safe_load(
        (ROOT / "infra" / "airgap" / "values-airgap.yaml").read_text(encoding="utf-8")
    )
    stack = airgap.get("llmStack") or {}
    assert not (stack.get("bifrost") or {}).get("enabled")
    assert not (stack.get("ollama") or {}).get("enabled")


# --- W0.61: Bifrost starts offline -------------------------------------------


def _bifrost_volume_mounts(docs):
    pod = _get(docs, "Deployment", "rc-vigil-bifrost")["spec"]["template"]["spec"]
    return {m["mountPath"] for m in pod["containers"][0]["volumeMounts"]}


@pytest.mark.parametrize(
    "switch",
    [
        "llmStack.bifrost.offlineCatalog=true",
        "networkPolicies.egress.inClusterOnly=true",
    ],
)
def test_offline_bifrost_reads_its_catalogs_from_the_seed(chart, switch):
    docs = _render(chart, *ON, switch)
    seed = _get(docs, "ConfigMap", "rc-vigil-bifrost-seed")["data"]
    pricing = json.loads(seed["config.json"])["framework"]["pricing"]
    assert pricing["pricing_url"] == "file:///app/seed/pricing.json"
    assert pricing["model_parameters_url"] == "file:///app/seed/model-parameters.json"
    assert (
        json.loads(seed["pricing.json"]) == {}
        and json.loads(seed["model-parameters.json"]) == {}
    )
    assert "/app/seed" in _bifrost_volume_mounts(docs)


def test_connected_bifrost_keeps_the_live_catalogs(chart):
    docs = _render(chart, *ON)
    seed = _get(docs, "ConfigMap", "rc-vigil-bifrost-seed")["data"]
    assert "framework" not in json.loads(seed["config.json"])
    assert "pricing.json" not in seed
    assert "/app/seed" not in _bifrost_volume_mounts(docs)


def test_airgap_manifest_points_bifrost_at_local_catalogs():
    manifest = (ROOT / "infra" / "airgap" / "k8s" / "llm-stack.yaml").read_text(
        encoding="utf-8"
    )
    docs = [d for d in yaml.safe_load_all(manifest) if d]
    cm = next(d for d in docs if d["kind"] == "ConfigMap")
    pricing = json.loads(cm["data"]["config.json"])["framework"]["pricing"]
    assert pricing["pricing_url"].startswith("file:///app/seed/")
    assert pricing["model_parameters_url"].startswith("file:///app/seed/")
    dep = next(
        d
        for d in docs
        if d["kind"] == "Deployment" and d["metadata"]["name"] == "bifrost"
    )
    mounts = {
        m["mountPath"]
        for m in dep["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
    }
    assert "/app/seed" in mounts
    assert "getbifrost.ai" not in cm["data"]["config.json"]
