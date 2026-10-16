"""Helm: a default install has a person approve every response action (W0.32, KS-20).

``DAEMON_FORCE_APPROVAL`` is a lock, not the mode; unlocked, the console's
``approval.force_manual_approval`` row decides, and the db-init Job seeds it as
Assist (and moves an untouched pre-2.0 Act seed). The static tests read the
chart; the render tests need a helm binary (``VIGIL_TEST_HELM`` or ``helm`` on
PATH, skipped otherwise) and render a copy of the chart without its subcharts.
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

from core.config import Settings
from core.response.approval_service import stored_force_manual

pytestmark = pytest.mark.unit

CHART = Path(__file__).resolve().parents[3] / "infra" / "helm" / "vigil"
SEED = re.compile(r"'approval\.force_manual_approval',\s*'(\{[^']*\})'")
MIGRATION = "63_approval_default_assist.sql"


def _effective_force(config: dict, sql_files: dict) -> bool:
    """env OR the seeded row, as ApprovalService decides it."""
    lock = Settings(daemon_force_approval=config.get("DAEMON_FORCE_APPROVAL", "false"))
    seed = SEED.search(sql_files["04_config_tables.sql"])
    assert seed, "04_config_tables.sql seeds no approval row"
    return bool(lock.daemon_force_approval) or stored_force_manual(json.loads(seed.group(1)))


# -- static -------------------------------------------------------------------------


def test_default_values_and_bundled_sql_hold_every_action_for_a_person():
    values = yaml.safe_load((CHART / "values.yaml").read_text(encoding="utf-8"))
    sql = {
        p.name: p.read_text(encoding="utf-8")
        for p in (CHART / "files" / "database-init").glob("*.sql")
    }
    assert _effective_force(values["config"], sql) is True
    assert MIGRATION in values["dbInit"]["sqlFiles"]


# -- rendered -----------------------------------------------------------------------


def _helm() -> str | None:
    return os.environ.get("VIGIL_TEST_HELM") or shutil.which("helm")


@pytest.fixture(scope="module")
def chart(tmp_path_factory):
    if not _helm():
        pytest.skip("no helm binary (set VIGIL_TEST_HELM to run)")
    dest = tmp_path_factory.mktemp("chart") / "vigil"
    shutil.copytree(CHART, dest, ignore=shutil.ignore_patterns("charts", "Chart.lock"))
    meta = yaml.safe_load((dest / "Chart.yaml").read_text(encoding="utf-8"))
    meta.pop("dependencies", None)
    (dest / "Chart.yaml").write_text(yaml.safe_dump(meta), encoding="utf-8")
    return dest


def _render(chart: Path, template: str, *args: str) -> dict:
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
    )
    assert out.returncode == 0, out.stderr
    return yaml.safe_load(out.stdout)


def test_rendered_default_is_human_approval(chart):
    config = _render(chart, "configmap.yaml")["data"]
    sql = _render(chart, "db-init-configmap.yaml")["data"]
    assert _effective_force(config, sql) is True
    assert MIGRATION in sql


def test_the_lock_renders_when_set(chart):
    config = _render(chart, "configmap.yaml", "--set", "config.DAEMON_FORCE_APPROVAL=true")[
        "data"
    ]
    assert config["DAEMON_FORCE_APPROVAL"] == "true"
