"""Helm: the backend reads ``medic.enabled`` as VIGIL_MEDIC_ENABLED (Off ≠ Down, C8).

Rendered on a copy of the chart without its subcharts (the db-init and Medic
render tests do the same), so it needs the helm binary but no network.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(shutil.which("helm") is None, reason="needs helm"),
]

CHART = Path(__file__).resolve().parents[3] / "infra" / "helm" / "vigil"
USER = "medic-a1b2c3d4e5f6"
# What any Medic-on render needs since S7 (the chart refuses without them).
MEDIC_ON = (
    "medic.enabled=true",
    "medic.kubeApi.cidrs[0]=10.0.0.1/32",
    f"medic.gateway.viewer.username={USER}",
    "medic.gateway.viewer.passwordSecret.name=medic-viewer",
)


@pytest.fixture(scope="module")
def chart(tmp_path_factory) -> Path:
    dest = tmp_path_factory.mktemp("chart") / "vigil"
    shutil.copytree(CHART, dest, ignore=shutil.ignore_patterns("medic-tests"))
    meta = yaml.safe_load((dest / "Chart.yaml").read_text())
    meta.pop("dependencies", None)
    (dest / "Chart.yaml").write_text(yaml.safe_dump(meta))
    (dest / "Chart.lock").unlink(missing_ok=True)
    return dest


def _helm(chart: Path, *args: str) -> str:
    done = subprocess.run(
        ["helm", *args, str(chart), "--set", "secrets.jwtSecretKey=x"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    return done.stdout


def _backend_env(chart: Path, *sets: str) -> dict:
    out = _helm(
        chart,
        "template",
        "t",
        "--show-only",
        "templates/backend-deployment.yaml",
        *[a for s in sets for a in ("--set", s)],
    )
    doc = yaml.safe_load(out)
    env = doc["spec"]["template"]["spec"]["containers"][0]["env"]
    return {e["name"]: e.get("value") for e in env}


@pytest.mark.parametrize(
    "sets, expected",
    [
        ((), "false"),
        (("medic.enabled=false",), "false"),
        (MEDIC_ON, "true"),
    ],
)
def test_backend_flag_follows_medic_enabled(chart, sets, expected) -> None:
    assert _backend_env(chart, *sets)["VIGIL_MEDIC_ENABLED"] == expected


NOTES_PROBE = "templates/zz-notes-probe.yaml"


@pytest.fixture(scope="module")
def notes_chart(chart, tmp_path_factory) -> Path:
    """The chart copy, with NOTES.txt also rendered by ``helm template``.

    ``helm install --dry-run=client`` dials the cluster on Helm 3 (only
    ``template`` is client-only there; Helm 4 changed that), and ``template``
    leaves NOTES.txt out. So NOTES.txt goes, verbatim, into a define that a
    ConfigMap renders: same text, same values, no cluster on any Helm.
    """
    dest = tmp_path_factory.mktemp("notes-chart") / "vigil"
    shutil.copytree(chart, dest)
    notes = (dest / "templates" / "NOTES.txt").read_text()
    (dest / "templates" / "_zz_notes_probe.tpl").write_text(
        '{{- define "zz.notesProbe" -}}\n' + notes + "\n{{- end -}}\n"
    )
    (dest / NOTES_PROBE).write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: notes-probe\n"
        'data:\n  notes: |-\n{{ include "zz.notesProbe" . | indent 4 }}\n'
    )
    return dest


def _notes(chart: Path, *sets: str) -> str:
    out = _helm(
        chart,
        "template",
        "t",
        "--namespace",
        "ns",
        "--show-only",
        NOTES_PROBE,
        *[a for s in sets for a in ("--set", s)],
    )
    return yaml.safe_load(out)["data"]["notes"]


def test_notes_give_the_account_step_only_when_medic_is_on(notes_chart) -> None:
    assert "core.auth.service_account" not in _notes(notes_chart)
    notes = _notes(
        notes_chart, *MEDIC_ON, "medic.gateway.viewer.passwordSecret.key=password"
    )
    assert f"ensure {USER}" in notes
    assert "get secret medic-viewer -o jsonpath='{.data.password}'" in notes
    # The password travels on a pipe: no --from-literal, no value on a command line.
    assert "exec -i" in notes and "--from-literal" not in notes
