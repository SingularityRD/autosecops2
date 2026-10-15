"""W0.27: an operator-issued password reset link lands in the audit chain and
the SIEM export, in a real Postgres, without the token."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.compliance.audit_export import CaseAuditSource

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

_spec = importlib.util.spec_from_file_location(
    "reset_password_script_w027_db",
    Path(__file__).resolve().parents[3] / "scripts" / "reset_password.py",
)
script = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(script)


class _OneUser:
    """The script's user lookup, without a users row (roles FK)."""

    def __init__(self, session, user):
        self.session, self.user = session, user

    def query(self, model):
        if model is script.User:
            return SimpleNamespace(
                filter=lambda *_: SimpleNamespace(first=lambda: self.user)
            )
        return self.session.query(model)

    def add(self, row):
        self.session.add(row)

    def flush(self):
        self.session.flush()


def test_issued_link_is_chained_and_exported_without_the_token(audit_db):
    user = SimpleNamespace(
        user_id="u-reset-db",
        username="ana",
        email="ana@example.com",
        is_active=True,
        password_hash="pbkdf2$x",
        service_account=False,
    )
    with Session(audit_db.engine) as session:
        code, issued = script.issue_link(
            _OneUser(session, user), "ana", "https://soc.example", "alice"
        )
        session.commit()
    assert code == 0
    token = parse_qs(urlparse(issued[2]).query)["token"][0]

    with audit_db.engine.connect() as conn:
        row = (
            conn.execute(
                text(
                    "SELECT * FROM case_audit_logs WHERE entity_id = 'u-reset-db' "
                    "AND action = :a"
                ),
                {"a": script.AUDIT_ACTION},
            )
            .mappings()
            .one()
        )
        chained = conn.execute(
            text(
                "SELECT event, payload FROM audit_chain WHERE "
                "source_table = 'case_audit_logs' AND source_id = :s"
            ),
            {"s": str(row["audit_id"])},
        ).all()
    assert [c.event for c in chained] == ["insert"]
    payload = chained[0].payload
    assert payload["row"]["changed_by"] == "cli:alice"
    assert payload["row"]["action"] == "reset_link_issued"
    assert token not in json.dumps(payload)

    event = CaseAuditSource.event(SimpleNamespace(name="case_audit"), dict(row))
    assert event.action == script.SIEM_ACTION == "case.user.reset_link_issued"
    assert event.actor == "cli:alice"
    assert event.target_id == "u-reset-db"
    assert "alice" in event.message and "ana" in event.message
    assert token not in json.dumps(event.details) + event.message
