"""The storage settings messages name the product AutoSecOps, not Vigil (W0.10)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from services.api.routers import storage_status

pytestmark = pytest.mark.unit


def test_the_empty_schema_message_names_autosecops():
    message = storage_status._schema_message({"state": "empty"})
    assert "AutoSecOps tables" in message
    assert "Vigil" not in message


def test_the_drifted_refusal_names_autosecops(monkeypatch):
    report = {"state": "drifted", "missing_columns": {"cases": ["x"]}}
    monkeypatch.setattr(storage_status, "require_settings_admin", lambda user: None)
    monkeypatch.setattr(
        storage_status,
        "get_db_manager",
        lambda: SimpleNamespace(schema_report=lambda: report),
    )
    with pytest.raises(HTTPException) as refused:
        storage_status.init_schema(current_user=SimpleNamespace(username="admin"))
    assert refused.value.status_code == 409
    assert "out-of-date AutoSecOps schema" in refused.value.detail
    assert "Vigil" not in refused.value.detail
