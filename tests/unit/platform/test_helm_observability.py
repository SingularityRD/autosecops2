"""Helm: alert rules, a backend ServiceMonitor and a Grafana dashboard (W0.51)."""

from __future__ import annotations

import json
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


def test_off_by_default(chart):
    kinds = {d["kind"] for d in _render(chart)}
    assert "PrometheusRule" not in kinds and "ServiceMonitor" not in kinds
    assert not [
        d for d in _render(chart) if d["metadata"]["name"].endswith("grafana-dashboard")
    ]


def test_service_monitors_for_daemon_and_backend(chart):
    docs = _render(chart, "--set", "observability.serviceMonitor.enabled=true")
    monitors = {d["metadata"]["name"]: d for d in docs if d["kind"] == "ServiceMonitor"}
    assert set(monitors) == {"rc-vigil-daemon", "rc-vigil-backend"}
    assert monitors["rc-vigil-backend"]["spec"]["endpoints"][0]["port"] == "http"
    docs = _render(
        chart,
        "--set",
        "observability.serviceMonitor.enabled=true",
        "--set",
        "observability.serviceMonitor.backend=false",
    )
    assert [d["metadata"]["name"] for d in docs if d["kind"] == "ServiceMonitor"] == [
        "rc-vigil-daemon"
    ]


def test_rules_name_the_scrape_jobs_and_real_metrics(chart):
    docs = _render(chart, "--set", "observability.prometheusRule.enabled=true")
    [rule] = [d for d in docs if d["kind"] == "PrometheusRule"]
    exprs = {r["alert"]: r["expr"] for g in rule["spec"]["groups"] for r in g["rules"]}
    assert 'job="rc-vigil-daemon"' in exprs["AutoSecOpsDaemonDown"]
    assert 'job="rc-vigil-backend"' in exprs["AutoSecOpsBackendDown"]
    assert (
        "vigil_backup_last_success_timestamp_seconds" in exprs["AutoSecOpsBackupStale"]
    )
    assert (
        "autosecops_audit_export_delivery_failures_total"
        in exprs["AutoSecOpsAuditExportFailing"]
    )


def test_the_dashboard_is_valid_json_with_the_jobs_filled_in(chart):
    docs = _render(chart, "--set", "observability.grafanaDashboard.enabled=true")
    [cm] = [d for d in docs if d["metadata"]["name"] == "rc-vigil-grafana-dashboard"]
    assert cm["metadata"]["labels"]["grafana_dashboard"] == "1"
    dash = json.loads(cm["data"]["autosecops.json"])
    consts = {
        v["name"]: v["query"]
        for v in dash["templating"]["list"]
        if v["type"] == "constant"
    }
    assert consts == {"daemon": "rc-vigil-daemon", "backend": "rc-vigil-backend"}
    assert len(dash["panels"]) >= 8
