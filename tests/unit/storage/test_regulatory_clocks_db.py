"""``50_regulatory_clocks.sql`` and the SQL clock store in a real Postgres (W3.8).

The file is applied twice (it must be rerunnable) inside a transaction that is
rolled back. The store writes instants, audit rows, config and drafts; the
table refuses UPDATE and a change without a reason.
"""

from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from core.compliance.clocks import ClockConfig, evaluate
from core.compliance.regulatory_drafts import build_evidence_pack, generate_draft
from core.compliance.regulatory_service import (
    RegulatoryService,
    SqlClockStore,
    fold_instants,
)
from core.storage.connection import get_db_manager

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

SQL = (
    Path(__file__).resolve().parents[3]
    / "infra"
    / "database"
    / "init"
    / "50_regulatory_clocks.sql"
)
HEADS_SQL = SQL.with_name("58_broadcast_unique_and_clock_heads.sql")
NOW = datetime(2026, 3, 2, 12, 0, tzinfo=timezone.utc)
CASE = "W38-TEST-CASE"


@pytest.fixture()
def session():
    with get_db_manager().engine.connect() as conn:
        tx = conn.begin()
        try:
            sql = SQL.read_text(encoding="utf-8")
            conn.execute(text(sql))
            conn.execute(text(sql))
            heads = HEADS_SQL.read_text(encoding="utf-8")
            conn.execute(text(heads))
            conn.execute(text(heads))
            conn.execute(
                text(
                    "INSERT INTO cases (case_id, title, status, priority, timeline, created_at, updated_at) "
                    "VALUES (:c, 'Outage', 'open', 'high', '[]'::jsonb, now(), now())"
                ),
                {"c": CASE},
            )
            with Session(bind=conn, join_transaction_mode="create_savepoint") as s:
                yield s
        finally:
            tx.rollback()


def _refused(session, sql, params, exc=IntegrityError):
    sp = session.connection().begin_nested()
    with pytest.raises(exc):
        session.connection().execute(text(sql), params)
    sp.rollback()


def test_instants_round_trip_with_chain_and_audit(session):
    service = RegulatoryService(SqlClockStore(session), now=lambda: NOW)
    service.record_instant(
        CASE, "dora", "aware_at", datetime(2026, 3, 2, 8, tzinfo=timezone.utc), "ayse"
    )
    service.record_instant(
        CASE,
        "dora",
        "classification_at",
        datetime(2026, 3, 2, 9, tzinfo=timezone.utc),
        "ayse",
    )
    service.record_instant(
        CASE,
        "dora",
        "aware_at",
        datetime(2026, 3, 2, 7, tzinfo=timezone.utc),
        "mehmet",
        "earlier alert",
    )
    events = service.events(CASE)
    assert [(e.seq, e.instant, e.actor) for e in events] == [
        (1, "aware_at", "ayse"),
        (2, "classification_at", "ayse"),
        (3, "aware_at", "mehmet"),
    ]
    assert events[2].previous_value == datetime(2026, 3, 2, 8, tzinfo=timezone.utc)
    assert service.verify_chain(CASE)["ok"] is True
    initial = next(
        c for c in service.status(CASE)["clocks"] if c["key"] == "dora.initial"
    )
    assert initial["due_at"] == "2026-03-02T13:00:00+00:00"

    audits = session.execute(
        text(
            "SELECT field_name, old_value, new_value, changed_by, change_summary FROM case_audit_logs "
            "WHERE entity_type = 'case' AND entity_id = :c ORDER BY audit_id"
        ),
        {"c": CASE},
    ).all()
    assert [a[0] for a in audits] == [
        "regulatory.dora.aware_at",
        "regulatory.dora.classification_at",
        "regulatory.dora.aware_at",
    ]
    assert audits[2][1:] == (
        "2026-03-02T08:00:00+00:00",
        "2026-03-02T07:00:00+00:00",
        "mehmet",
        "Changed DORA aware_at: earlier alert",
    )


def test_rows_cannot_be_updated(session):
    service = RegulatoryService(SqlClockStore(session), now=lambda: NOW)
    service.record_instant(
        CASE, "nis2", "aware_at", datetime(2026, 3, 2, 8, tzinfo=timezone.utc), "ayse"
    )
    _refused(
        session,
        "UPDATE regulatory_clock_events SET value = now() WHERE case_id = :c",
        {"c": CASE},
        exc=DBAPIError,
    )


@pytest.mark.parametrize(
    "regime,instant,previous,reason",
    [
        ("nis2", "classification_at", None, None),  # not a NIS2 instant
        ("gdpr", "aware_at", None, None),
        (
            "nis2",
            "aware_at",
            "2026-03-02T08:00:00+00:00",
            None,
        ),  # change without reason
        ("nis2", "aware_at", "2026-03-02T08:00:00+00:00", "  "),
    ],
)
def test_the_table_refuses_what_the_service_refuses(
    session, regime, instant, previous, reason
):
    _refused(
        session,
        "INSERT INTO regulatory_clock_events (case_id, seq, regime, instant, value, previous_value, "
        "actor, reason, prev_hash, row_hash) VALUES (:c, 1, :r, :i, now(), :p, 'a', :reason, '', 'x')",
        {"c": CASE, "r": regime, "i": instant, "p": previous, "reason": reason},
    )


def test_seq_is_unique_per_case(session):
    sql = (
        "INSERT INTO regulatory_clock_events (case_id, seq, regime, instant, value, actor, "
        "prev_hash, row_hash) VALUES (:c, 1, 'dora', 'aware_at', now(), 'a', '', 'x')"
    )
    session.execute(text(sql), {"c": CASE})
    _refused(session, sql, {"c": CASE})


def test_config_and_drafts_persist(session):
    store = SqlClockStore(session)
    service = RegulatoryService(store, now=lambda: NOW)
    assert service.config() == ClockConfig()
    service.set_config(
        "Europe/Berlin", {"dora.initial_after_classification": {"hours": 2}}, "admin"
    )
    service.set_config(
        "Europe/Berlin", {"dora.initial_after_classification": {"hours": 3}}, "root"
    )
    assert service.config().durations["dora.initial_after_classification"].hours == 3
    audit = session.execute(
        text(
            "SELECT action, changed_by, old_value FROM config_audit_log "
            "WHERE config_type = 'regulatory_clocks' ORDER BY id DESC LIMIT 1"
        )
    ).one()
    assert audit[0] == "update" and audit[1] == "root"
    assert audit[2]["durations"] == {
        "dora.initial_after_classification": {"hours": 2, "months": 0}
    }

    events = service.events(CASE)
    pack = build_evidence_pack(
        {"case_id": CASE, "title": "Outage"}, clock_events=events
    )
    clocks = evaluate(fold_instants(events), service.config(), NOW)
    draft = generate_draft(pack, "dora", "initial", clocks, events, "ayse", NOW)
    store.add_draft(draft)
    listed = store.drafts(CASE)
    assert [d["draft_id"] for d in listed] == [draft["draft_id"]]
    assert listed[0]["cited_ids"] == draft["cited_ids"]


def test_case_deletion_takes_its_clock_rows(session):
    service = RegulatoryService(SqlClockStore(session), now=lambda: NOW)
    service.record_instant(
        CASE, "nis2", "aware_at", datetime(2026, 3, 2, 8, tzinfo=timezone.utc), "ayse"
    )
    session.execute(text("DELETE FROM cases WHERE case_id = :c"), {"c": CASE})
    left = session.execute(
        text("SELECT count(*) FROM regulatory_clock_events WHERE case_id = :c"),
        {"c": CASE},
    ).scalar()
    assert left == 0


# --- chain head (W0.10, 58_broadcast_unique_and_clock_heads.sql) ---------------


def _three_events(service):
    for hour in (5, 6, 7):
        service.record_instant(
            CASE,
            "dora",
            "aware_at",
            datetime(2026, 3, 2, hour, tzinfo=timezone.utc),
            "ayse",
            "fix",
        )


def test_the_trigger_keeps_the_chain_head(session):
    service = RegulatoryService(SqlClockStore(session), now=lambda: NOW)
    _three_events(service)
    head = SqlClockStore(session).head(CASE)
    last = service.events(CASE)[-1]
    assert head == {"seq": 3, "row_hash": last.row_hash, "broken_at": None}
    assert service.verify_chain(CASE)["ok"] is True
    assert service.verify_chain(CASE)["anchored"] is True


def test_deleting_the_last_event_is_detected(session):
    service = RegulatoryService(SqlClockStore(session), now=lambda: NOW)
    _three_events(service)
    session.execute(
        text("DELETE FROM regulatory_clock_events WHERE case_id = :c AND seq = 3"),
        {"c": CASE},
    )
    assert service.verify_chain(CASE) == {
        "ok": False,
        "broken_at": 3,
        "why": "missing row",
    }


def test_deleting_every_event_is_detected(session):
    service = RegulatoryService(SqlClockStore(session), now=lambda: NOW)
    _three_events(service)
    session.execute(
        text("DELETE FROM regulatory_clock_events WHERE case_id = :c"), {"c": CASE}
    )
    assert service.verify_chain(CASE)["ok"] is False


def test_a_forged_append_after_a_deletion_is_remembered(session):
    service = RegulatoryService(SqlClockStore(session), now=lambda: NOW)
    _three_events(service)
    session.execute(
        text("DELETE FROM regulatory_clock_events WHERE case_id = :c AND seq = 3"),
        {"c": CASE},
    )
    service.record_instant(
        CASE,
        "dora",
        "aware_at",
        datetime(2026, 3, 2, 4, tzinfo=timezone.utc),
        "mallory",
        "forged",
    )
    assert service.verify_chain(CASE)["why"] == "append out of sequence"


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE regulatory_clock_heads SET seq = 1 WHERE case_id = :c",
        "UPDATE regulatory_clock_heads SET broken_at = NULL WHERE case_id = :c",
        "DELETE FROM regulatory_clock_heads WHERE case_id = :c",
        "INSERT INTO regulatory_clock_heads (case_id, seq, row_hash) VALUES (:c, 9, 'x')",
    ],
)
def test_the_head_is_written_only_by_the_trigger(session, sql):
    service = RegulatoryService(SqlClockStore(session), now=lambda: NOW)
    _three_events(service)
    _refused(session, sql, {"c": CASE}, exc=DBAPIError)


@pytest.mark.parametrize(
    "sql",
    [
        "TRUNCATE regulatory_clock_heads",
        "TRUNCATE regulatory_clock_events",
        "TRUNCATE regulatory_clock_events, regulatory_clock_heads",
        "TRUNCATE cases CASCADE",
    ],
)
def test_truncate_is_refused(session, sql):
    """W0.11: TRUNCATE skips row triggers, so a statement trigger refuses it."""
    service = RegulatoryService(SqlClockStore(session), now=lambda: NOW)
    _three_events(service)
    _refused(session, sql, {}, exc=DBAPIError)
    assert service.verify_chain(CASE)["ok"] is True


def test_a_dropped_head_table_breaks_the_chain(session):
    """W0.11: without the head table a deleted tail would not show: fail."""
    service = RegulatoryService(SqlClockStore(session), now=lambda: NOW)
    _three_events(service)
    session.execute(text("DROP TABLE regulatory_clock_heads CASCADE"))
    assert service.verify_chain(CASE) == {
        "ok": False,
        "broken_at": None,
        "why": "chain head unavailable",
    }


def test_case_deletion_takes_its_head(session):
    service = RegulatoryService(SqlClockStore(session), now=lambda: NOW)
    _three_events(service)
    session.execute(text("DELETE FROM cases WHERE case_id = :c"), {"c": CASE})
    left = session.execute(
        text("SELECT count(*) FROM regulatory_clock_heads WHERE case_id = :c"),
        {"c": CASE},
    ).scalar()
    assert left == 0


def test_existing_chains_are_anchored_by_the_backfill(session):
    service = RegulatoryService(SqlClockStore(session), now=lambda: NOW)
    _three_events(service)
    # As if the events predated the head table: drop it and re-apply the file.
    session.execute(text("DROP TABLE regulatory_clock_heads CASCADE"))
    session.execute(text(HEADS_SQL.read_text(encoding="utf-8")))
    head = SqlClockStore(session).head(CASE)
    assert head["seq"] == 3 and head["broken_at"] is None
    assert service.verify_chain(CASE)["ok"] is True
