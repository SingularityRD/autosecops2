"""Helm keeps console-entered secrets encrypted in Postgres, not in a pod's file (PY-19/20).

Static reads of the chart; no helm binary. The behaviour itself (two replicas,
one database, nothing on disk) is tests/integration/test_secrets_database_replicas.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]
CHART = REPO / "infra" / "helm" / "vigil"
SQL = "64_platform_secrets.sql"


def _values(name: str = "values.yaml") -> dict:
    return yaml.safe_load((CHART / name).read_text(encoding="utf-8")) or {}


def test_chart_default_is_the_database_store_with_a_data_key_value():
    values = _values()
    assert values["config"]["SECRETS_BACKEND"] == "database"
    assert values["secrets"]["dataEncryptionKey"] == ""  # operator-supplied
    secret = (CHART / "templates" / "secret.yaml").read_text(encoding="utf-8")
    assert "VIGIL_DATA_KEY: {{ . | quote }}" in secret
    assert ".Values.secrets.dataEncryptionKey" in secret


@pytest.mark.parametrize(
    "overlay",
    [
        CHART / "values-dev.yaml",
        REPO / "infra" / "airgap" / "values-airgap.yaml",
        REPO / "infra" / "staging" / "values-staging.yaml",
    ],
)
def test_no_profile_switches_back_to_a_file_store(overlay):
    values = yaml.safe_load(overlay.read_text(encoding="utf-8")) or {}
    backend = (values.get("config") or {}).get("SECRETS_BACKEND", "database")
    assert backend == "database", overlay


def test_platform_secrets_table_ships_with_the_chart():
    assert SQL in _values()["dbInit"]["sqlFiles"]
    mirror = CHART / "files" / "database-init" / SQL
    source = REPO / "infra" / "database" / "init" / SQL
    assert mirror.read_bytes() == source.read_bytes()


def test_install_notes_warn_when_the_data_key_is_missing():
    notes = (CHART / "templates" / "NOTES.txt").read_text(encoding="utf-8")
    assert "secrets.dataEncryptionKey is empty" in notes
