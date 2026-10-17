"""Helm: the daemon's syslog listener (W0.41).

Off by default: no port, Service, env or NetworkPolicy rule. Enabled: the
container ports, a separate Service (so it can be a LoadBalancer without the
webhook), the DAEMON_SYSLOG_* env, the TLS Secret mount, and a NetworkPolicy
rule for the same CIDRs the listener accepts.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

HELM = Path(__file__).resolve().parents[3] / "infra" / "helm" / "vigil"


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


def _render(chart, *args, ok=True):
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
    if not ok:
        return out
    assert out.returncode == 0, out.stderr
    return [d for d in yaml.safe_load_all(out.stdout) if d]


def _daemon(docs):
    sts = next(
        d
        for d in docs
        if d["kind"] == "StatefulSet" and d["metadata"]["name"] == "rc-vigil-daemon"
    )
    return sts["spec"]["template"]["spec"]


def _env(spec):
    return {e["name"]: e.get("value") for e in spec["containers"][0]["env"]}


ON = (
    "--set",
    "daemon.syslog.enabled=true",
    "--set",
    "daemon.syslog.allowedSources={10.0.0.0/8,192.0.2.7/32}",
)


def test_off_by_default(chart):
    docs = _render(chart, "--set", "networkPolicies.enabled=true")
    spec = _daemon(docs)
    assert not [
        p for p in spec["containers"][0]["ports"] if p["name"].startswith("syslog")
    ]
    assert not [k for k in _env(spec) if k.startswith("DAEMON_SYSLOG")]
    assert not [d for d in docs if d["metadata"]["name"] == "rc-vigil-daemon-syslog"]
    policy = next(
        d
        for d in docs
        if d["kind"] == "NetworkPolicy" and d["metadata"]["name"] == "rc-vigil-daemon"
    )
    ports = {p["port"] for rule in policy["spec"]["ingress"] for p in rule["ports"]}
    assert 5514 not in ports


def test_enabled_tcp(chart):
    docs = _render(chart, *ON, "--set", "networkPolicies.enabled=true")
    spec = _daemon(docs)
    ports = {p["name"]: p for p in spec["containers"][0]["ports"]}
    assert ports["syslog-tcp"]["containerPort"] == 5514
    assert "syslog-udp" not in ports
    env = _env(spec)
    assert env["DAEMON_SYSLOG_ENABLED"] == "true"
    assert env["DAEMON_SYSLOG_TCP_PORT"] == "5514"
    assert env["DAEMON_SYSLOG_UDP_PORT"] == "0"
    assert env["DAEMON_SYSLOG_ALLOWED_SOURCES"] == "10.0.0.0/8,192.0.2.7/32"
    assert "DAEMON_SYSLOG_TLS_CERT" not in env
    svc = next(d for d in docs if d["metadata"]["name"] == "rc-vigil-daemon-syslog")
    assert [(p["name"], p["port"], p["protocol"]) for p in svc["spec"]["ports"]] == [
        ("syslog-tcp", 5514, "TCP")
    ]
    assert svc["spec"]["type"] == "ClusterIP"
    policy = next(
        d
        for d in docs
        if d["kind"] == "NetworkPolicy" and d["metadata"]["name"] == "rc-vigil-daemon"
    )
    syslog_rules = [
        r
        for r in policy["spec"]["ingress"]
        if any(p["port"] == 5514 for p in r["ports"])
    ]
    assert len(syslog_rules) == 1
    assert [b["ipBlock"]["cidr"] for b in syslog_rules[0]["from"]] == [
        "10.0.0.0/8",
        "192.0.2.7/32",
    ]


def test_tls_udp_and_load_balancer(chart):
    docs = _render(
        chart,
        *ON,
        "--set",
        "daemon.syslog.tls.existingSecret=syslog-tls",
        "--set",
        "daemon.syslog.tls.clientCA=true",
        "--set",
        "daemon.syslog.udpPort=5515",
        "--set",
        "daemon.syslog.service.type=LoadBalancer",
    )
    spec = _daemon(docs)
    env = _env(spec)
    assert env["DAEMON_SYSLOG_TLS_CERT"] == "/etc/autosecops/syslog-tls/tls.crt"
    assert env["DAEMON_SYSLOG_TLS_KEY"] == "/etc/autosecops/syslog-tls/tls.key"
    assert env["DAEMON_SYSLOG_TLS_CLIENT_CA"] == "/etc/autosecops/syslog-tls/ca.crt"
    mounts = {m["name"]: m for m in spec["containers"][0]["volumeMounts"]}
    assert mounts["syslog-tls"]["readOnly"] is True
    volumes = {v["name"]: v for v in spec["volumes"]}
    assert volumes["syslog-tls"]["secret"]["secretName"] == "syslog-tls"
    svc = next(d for d in docs if d["metadata"]["name"] == "rc-vigil-daemon-syslog")
    assert svc["spec"]["type"] == "LoadBalancer"
    assert {(p["name"], p["protocol"]) for p in svc["spec"]["ports"]} == {
        ("syslog-tcp", "TCP"),
        ("syslog-udp", "UDP"),
    }


def test_no_port_at_all_fails(chart):
    out = _render(chart, *ON, "--set", "daemon.syslog.tcpPort=0", ok=False)
    assert out.returncode != 0
    assert "needs tcpPort or udpPort" in out.stderr


def test_the_daemon_service_is_unchanged(chart):
    docs = _render(chart, *ON)
    svc = next(
        d
        for d in docs
        if d["kind"] == "Service" and d["metadata"]["name"] == "rc-vigil-daemon"
    )
    assert [p["name"] for p in svc["spec"]["ports"]] == ["webhook", "metrics", "health"]
