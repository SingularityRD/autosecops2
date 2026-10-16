"""Helm tells the installer how to get the first-admin setup token (W0.33).

The NOTES name the two ways to read it on a cluster -- the backend log
(``kubectl logs``) and ``kubectl exec ... setup_token regenerate`` -- and an
operator-chosen ``secrets.setupToken`` reaches the backend as
``VIGIL_SETUP_TOKEN``. Needs a helm binary (``VIGIL_TEST_HELM`` or ``helm`` on
PATH); NOTES.txt is rendered through ``tpl``, as tests/unit/cases does.
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


def _helm() -> str | None:
    return os.environ.get("VIGIL_TEST_HELM") or shutil.which("helm")


@pytest.fixture(scope="module")
def chart(tmp_path_factory):
    if not _helm():
        pytest.skip("no helm binary (set VIGIL_TEST_HELM to run)")
    dest = tmp_path_factory.mktemp("chart") / "vigil"
    shutil.copytree(HELM, dest, ignore=shutil.ignore_patterns("charts", "Chart.lock"))
    meta = yaml.safe_load((dest / "Chart.yaml").read_text(encoding="utf-8"))
    meta.pop("dependencies", None)  # subcharts need a network fetch
    (dest / "Chart.yaml").write_text(yaml.safe_dump(meta), encoding="utf-8")
    shutil.copy(dest / "templates" / "NOTES.txt", dest / "files" / "zz-notes.txt")
    (dest / "templates" / "zz-notes.yaml").write_text(
        'notes: |\n{{ tpl (.Files.Get "files/zz-notes.txt") . | indent 2 }}\n',
        encoding="utf-8",
    )
    return dest


def _render(chart: Path, template: str, *args: str) -> str:
    out = subprocess.run(
        [_helm(), "template", "rc", str(chart), "-n", "soc",
         "--set", "secrets.postgresPassword=x",
         "--show-only", f"templates/{template}", *args],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0, out.stderr
    return out.stdout


def test_notes_say_how_to_read_and_regenerate_the_token(chart):
    notes = _render(chart, "zz-notes.yaml")
    assert "one-time setup token" in notes
    assert "kubectl logs -n soc" in notes and 'grep "setup token"' in notes
    assert "app.kubernetes.io/component=backend" in notes
    assert (
        "kubectl exec -n soc deploy/rc-vigil-backend -c backend -- "
        "python -m core.auth.setup_token regenerate"
    ) in notes


def test_an_operator_chosen_token_is_named_and_reaches_the_backend(chart):
    token = "operator-chosen-token-0123456789"
    notes = _render(chart, "zz-notes.yaml", "--set", f"secrets.setupToken={token}")
    assert "secrets.setupToken" in notes and token not in notes
    secret = yaml.safe_load(
        _render(chart, "secret.yaml", "--set", f"secrets.setupToken={token}")
    )
    assert secret["stringData"]["VIGIL_SETUP_TOKEN"] == token


def test_no_token_in_the_secret_unless_one_is_chosen(chart):
    secret = yaml.safe_load(_render(chart, "secret.yaml"))
    assert "VIGIL_SETUP_TOKEN" not in secret["stringData"]
