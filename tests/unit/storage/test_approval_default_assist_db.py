"""Human approval is the default response mode, new and upgraded (W0.32), DB-backed.

04_config_tables.sql (frozen since 0.7.1) still seeds Act. 63_approval_default_assist.sql
moves that seed to Assist, on a new database and an upgraded one alike, only while
nobody has touched the row; it audits the move and is a no-op on every later run
(compose re-applies every init file on `up`). A row a person wrote is never changed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from sqlalchemy import text

from core.response.approval_service import APPROVAL_CONFIG_KEY, ApprovalService

pytestmark = pytest.mark.external_service

REPO = Path(__file__).resolve().parents[3]
INIT = REPO / "infra" / "database" / "init"
HELM_INIT = REPO / "infra" / "helm" / "vigil" / "files" / "database-init"
MIGRATION = "63_approval_default_assist.sql"
UPGRADE_ACTOR = "system:w0.32-default"


def _engine():
    from core.storage.connection import get_db_manager

    return get_db_manager().engine


@pytest.fixture
def clean():
    with _engine().begin() as conn:
        conn.execute(
            text("DELETE FROM system_config WHERE key = :k"), {"k": APPROVAL_CONFIG_KEY}
        )
        conn.execute(
            text("DELETE FROM config_audit_log WHERE config_key = :k"),
            {"k": APPROVAL_CONFIG_KEY},
        )
    yield


def _row(value: dict, updated_by=None) -> None:
    with _engine().begin() as conn:
        conn.execute(
            text(
                "INSERT INTO system_config (key, value, description, config_type, updated_by) "
                "VALUES (:k, CAST(:v AS jsonb), 'seed', 'approval', :u)"
            ),
            {"k": APPROVAL_CONFIG_KEY, "v": json.dumps(value), "u": updated_by},
        )


def _audit(changed_by: str) -> None:
    with _engine().begin() as conn:
        conn.execute(
            text(
                "INSERT INTO config_audit_log "
                "(config_type, config_key, action, old_value, new_value, changed_by) "
                "VALUES ('approval', :k, 'update', CAST('{\"enabled\": true}' AS jsonb), "
                "CAST('{\"enabled\": false}' AS jsonb), :by)"
            ),
            {"k": APPROVAL_CONFIG_KEY, "by": changed_by},
        )


def _migrate() -> None:
    with _engine().begin() as conn:
        conn.exec_driver_sql((INIT / MIGRATION).read_text(encoding="utf-8"))


def _state():
    with _engine().connect() as conn:
        value = conn.execute(
            text("SELECT value FROM system_config WHERE key = :k"),
            {"k": APPROVAL_CONFIG_KEY},
        ).scalar()
        audit = conn.execute(
            text(
                "SELECT changed_by FROM config_audit_log WHERE config_key = :k ORDER BY id"
            ),
            {"k": APPROVAL_CONFIG_KEY},
        ).scalars().all()
    return value, list(audit)


def _seed_04() -> dict:
    sql = (INIT / "04_config_tables.sql").read_text(encoding="utf-8")
    seed = re.search(r"'approval\.force_manual_approval',\s*'(\{[^']*\})'", sql)
    assert seed
    return json.loads(seed.group(1))


def test_the_bundled_copies_match():
    assert (HELM_INIT / MIGRATION).read_text(encoding="utf-8") == (
        INIT / MIGRATION
    ).read_text(encoding="utf-8")


def test_a_new_database_ends_in_assist(clean):
    # 04 (frozen) seeds Act; 63 runs after it in the same init pass.
    assert _seed_04() == {"enabled": False}
    _row(_seed_04())
    _migrate()
    assert _state() == ({"enabled": True}, [UPGRADE_ACTOR])
    assert ApprovalService()._stored_force_manual_approval() is True


def test_no_row_holds_every_action_for_a_person(clean):
    assert ApprovalService()._stored_force_manual_approval() is True


def test_an_untouched_act_seed_moves_to_assist_once_and_is_audited(clean):
    _row({"enabled": False})
    _migrate()
    assert _state() == ({"enabled": True}, [UPGRADE_ACTOR])
    _migrate()  # compose re-applies the file on every `up`
    assert _state() == ({"enabled": True}, [UPGRADE_ACTOR])
    assert ApprovalService()._stored_force_manual_approval() is True


def test_act_a_person_chose_is_kept(clean):
    _row({"enabled": False}, updated_by="7")
    _audit("7")
    _migrate()
    assert _state() == ({"enabled": False}, ["7"])
    assert ApprovalService()._stored_force_manual_approval() is False


def test_a_row_with_any_history_is_kept(clean):
    # Changed by a person before (say Assist, then back to Act through an
    # older build that left updated_by empty): the audit row is the evidence.
    _row({"enabled": False})
    _audit("alice")
    _migrate()
    assert _state() == ({"enabled": False}, ["alice"])


def test_an_assist_row_is_left_alone(clean):
    _row({"enabled": True})
    _migrate()
    assert _state() == ({"enabled": True}, [])


def test_no_row_is_not_created(clean):
    _migrate()
    assert _state() == (None, [])
