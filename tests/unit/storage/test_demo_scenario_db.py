"""The scripted demo scenario against a real Postgres (W0.50).

Seeded in a rolled-back transaction, then read back the way the console reads
it: verdicts on the findings, a pending approval and a reversed block on the
case's action timeline, running DORA and KVKK clocks, a buildable evidence pack.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.contracts.verdict import validate_verdict
from core.platform import demo_scenario
from core.storage.connection import get_db_manager

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

INIT = Path(__file__).resolve().parents[3] / "infra" / "database" / "init"


@pytest.fixture()
def session():
    manager = get_db_manager()
    if manager.engine is None:
        manager.initialize()
    with manager.engine.connect() as conn:
        tx = conn.begin()
        try:
            names = ["65_regulatory_tr_regimes.sql"]
            if (
                conn.execute(
                    text("SELECT to_regclass('regulatory_clock_events')")
                ).scalar()
                is None
            ):
                names[:0] = [
                    "50_regulatory_clocks.sql",
                    "58_broadcast_unique_and_clock_heads.sql",
                ]
            # 65 always: a table left by an earlier test can predate the KVKK
            # regime, and the file is rerunnable (all rolled back below).
            for name in names:
                conn.execute(text((INIT / name).read_text(encoding="utf-8")))
            with Session(bind=conn, join_transaction_mode="create_savepoint") as s:
                yield s
        finally:
            tx.rollback()


def test_every_stored_verdict_is_a_valid_contract_document():
    for f in demo_scenario.findings(demo_scenario.utcnow()):
        validate_verdict(f["verdict"])
        assert f["finding_id"].startswith(demo_scenario.PREFIX)


def test_seed_shows_the_claim_and_is_idempotent(session):
    result = demo_scenario.seed(session)
    assert result["seeded"] is True and result["clocks"] == "dora, kvkk"
    assert demo_scenario.seed(session)["seeded"] is False

    from core.response.action_timeline import case_action_timeline

    timeline = case_action_timeline(session, demo_scenario.CASE_ID)
    flat = repr(timeline)
    assert (
        "demo-sc-isolate" in flat
        and "demo-sc-block" in flat
        and "demo-sc-unblock" in flat
    )
    status = dict(
        session.execute(
            text(
                "SELECT action_id, status FROM approval_actions WHERE action_id LIKE 'demo-sc-%'"
            )
        ).all()
    )
    assert status == {
        "demo-sc-isolate": "pending",
        "demo-sc-block": "executed",
        "demo-sc-unblock": "executed",
    }

    from core.compliance.regulatory_service import RegulatoryService, SqlClockStore

    clocks = RegulatoryService(SqlClockStore(session)).status(demo_scenario.CASE_ID)[
        "clocks"
    ]
    states = {c["key"]: c["state"] for c in clocks}
    assert states["kvkk.board_notification"] in ("running", "overdue")
    assert states["dora.initial"] in ("running", "overdue")

    from core.compliance.evidence import collect_case_record

    record = collect_case_record(session, demo_scenario.CASE_ID)
    assert record is not None

    from services.api.triage_read import _verdict

    row = session.execute(
        text("SELECT ai_enrichment FROM findings WHERE finding_id = 'demo-sc-c2'")
    ).scalar()
    assert _verdict({"ai_enrichment": row})["verdict"] == "malicious"


def test_remove_deletes_exactly_the_scenario(session):
    demo_scenario.seed(session)
    session.execute(
        text(
            "INSERT INTO cases (case_id, title, description, status, priority, timeline,"
            " created_at, updated_at) VALUES ('w050-keep', 'keep', '', 'open', 'low',"
            " '[]'::jsonb, now(), now())"
        )
    )
    counts = demo_scenario.remove(session)
    assert counts == {
        "approval_actions": 3,
        "case_findings": 2,
        "findings": 3,
        "cases": 1,
    }
    assert (
        session.execute(
            text("SELECT count(*) FROM cases WHERE case_id = 'w050-keep'")
        ).scalar()
        == 1
    )
    assert demo_scenario.seed(session)["seeded"] is True  # can be seeded again
