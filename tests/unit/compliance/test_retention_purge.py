"""Retention purge against a real Postgres (W3.5).

DB-backed on purpose: legal holds, open-case protection, anonymise markers and
batch limits all live in the ``WHERE`` clauses, which a fake session would not
exercise. ``external_service`` hands each run a throwaway database built from
the ORM models; the SQL-owned tables this needs (``retention_policies``, the
hash-chained ``agent_events``) are applied from the init files here.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

from core.compliance import retention
from core.storage.connection import get_db_manager, get_db_session
from core.storage.models import (
    Case,
    CaseAttachment,
    CaseAuditLog,
    CaseComment,
    CaseEvidence,
    ChatMessage,
    ConfigAuditLog,
    Conversation,
    Finding,
    LLMInteractionLog,
    SystemConfig,
    case_findings,
)
from core.time import utcnow

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

INIT = Path(__file__).resolve().parents[3] / "infra" / "database" / "init"
OLD = timedelta(days=100)


@pytest.fixture(scope="module")
def sql_owned_tables(throwaway_database):
    engine = get_db_manager().engine
    with engine.begin() as conn:
        for name in (
            "19_agent_ledger.sql",
            "31_agent_ledger_hash_chain.sql",
            "48_autonomy_lessons_suppression_retention.sql",
            "50_regulatory_clocks.sql",
        ):
            conn.exec_driver_sql((INIT / name).read_text())
    return throwaway_database


@pytest.fixture
def db(sql_owned_tables):
    session = get_db_session()
    for stmt in (
        "DELETE FROM agent_events",
        "DELETE FROM retention_policies",
        "DELETE FROM chat_messages",
        "DELETE FROM conversations",
        "DELETE FROM llm_interaction_logs",
        "DELETE FROM case_audit_logs",
        "DELETE FROM ai_decision_logs",
        "DELETE FROM sketch_mappings",
        "DELETE FROM case_relationships",
        "DELETE FROM regulatory_clock_events",
        "DELETE FROM regulatory_report_drafts",
        "DELETE FROM investigations",
        "DELETE FROM config_audit_log",
        "DELETE FROM case_findings",
        "DELETE FROM case_comments",
        "DELETE FROM case_evidence",
        "DELETE FROM case_attachments",
        "DELETE FROM cases",
        "DELETE FROM findings",
    ):
        session.execute(text(stmt))
    session.query(SystemConfig).filter(SystemConfig.key.like("retention.%")).delete(
        synchronize_session=False
    )
    session.commit()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def store(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    return root


# --- builders ----------------------------------------------------------------


def _finding(db, fid, *, age=OLD, raw=False, **extra):
    when = utcnow() - age
    context = {"user": "alice@example.com"}
    if raw:
        context["source_evidence"] = {"records": [{"user": "alice"}]}
    db.add(
        Finding(
            finding_id=fid,
            title=f"title {fid}",
            description="alice logged in from 10.0.0.1",
            entity_context=context,
            evidence_links=[{"url": "x"}],
            data_source="test",
            external_id=f"ext-{fid}",
            ai_enrichment={"ai_triage": {"verdict": "benign"}},
            created_at=when,
            updated_at=when,
            **extra,
        )
    )
    db.flush()


def _case(db, cid, *, status="closed", age=OLD, findings=()):
    when = utcnow() - age
    db.add(
        Case(
            case_id=cid,
            title=f"case {cid} for alice",
            description="alice did something",
            status=status,
            priority="medium",
            assignee="bob",
            tags=["x"],
            notes=[{"text": "alice"}],
            timeline=[{"event": "x"}],
            created_at=when,
            updated_at=when,
        )
    )
    db.flush()
    for fid in findings:
        db.execute(case_findings.insert().values(case_id=cid, finding_id=fid))
    db.flush()


def _evidence(db, store, cid, name, *, age=OLD):
    rel = f"{cid}/{name}"
    path = store / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("secret evidence")
    when = utcnow() - age
    ev = CaseEvidence(
        case_id=cid,
        evidence_type="file",
        name=name,
        description="alice's laptop dump",
        file_path=rel,
        file_hash_sha256="ab" * 32,
        collected_by="bob",
        collected_at=when,
        chain_of_custody=[{"action": "collected"}],
        created_at=when,
        updated_at=when,
    )
    db.add(ev)
    db.flush()
    return ev.evidence_id, path


def _policy(db, data_class, days=30, method=None, legal_hold=False):
    retention.set_policy(
        db,
        data_class,
        retain_days=days,
        method=method,
        legal_hold=legal_hold,
        actor="admin",
    )
    db.commit()


def _purge(store, **kw):
    kw.setdefault("dry_run", False)
    return retention.run_purge(evidence_root=store, **kw)


def _result(report, name):
    return next(c for c in report["classes"] if c["data_class"] == name)


def _count(db, table):
    return db.execute(text(f"SELECT count(*) FROM {table}")).scalar()


# --- tests -------------------------------------------------------------------


def test_a_class_without_a_policy_is_never_touched(db, store):
    _finding(db, "f-1")
    db.commit()

    report = _purge(store)

    assert _result(report, "findings")["status"] == "no_policy"
    assert _count(db, "findings") == 1


def test_legal_hold_keeps_the_case_its_findings_and_its_evidence(db, store):
    _finding(db, "f-held")
    _finding(db, "f-free")
    _case(db, "c-held", findings=["f-held"])
    _case(db, "c-free", findings=["f-free"])
    _, held_file = _evidence(db, store, "c-held", "held.bin")
    _, free_file = _evidence(db, store, "c-free", "free.bin")
    db.commit()
    retention.set_legal_hold(db, "c-held", reason="litigation 2026/1", actor="legal")
    db.commit()
    for cls in ("findings", "cases", "case_evidence"):
        _policy(db, cls)

    report = _purge(store)

    db.expire_all()
    assert db.get(Case, "c-held") is not None
    assert db.get(Finding, "f-held") is not None
    assert held_file.exists()
    assert db.query(CaseEvidence).filter_by(case_id="c-held").count() == 1
    assert db.get(Case, "c-free") is None
    assert db.get(Finding, "f-free") is None
    assert not free_file.exists()
    assert _result(report, "findings")["processed"] == 1
    assert _result(report, "cases")["processed"] == 1
    assert report["legal_hold_cases"] == 1

    # Releasing the hold lets the next run take them.
    assert retention.release_legal_hold(db, "c-held", actor="legal")
    db.commit()
    _purge(store)
    db.expire_all()
    assert db.get(Case, "c-held") is None
    assert not held_file.exists()


def test_an_open_case_protects_its_findings_and_evidence(db, store):
    _finding(db, "f-open")
    _case(db, "c-open", status="investigating", findings=["f-open"])
    _, path = _evidence(db, store, "c-open", "e.bin")
    db.commit()
    for cls in ("findings", "cases", "case_evidence"):
        _policy(db, cls)

    report = _purge(store)

    assert report["total_processed"] == 0
    assert _count(db, "findings") == 1 and _count(db, "cases") == 1
    assert path.exists()


def test_class_level_legal_hold_stops_the_class(db, store):
    _finding(db, "f-1")
    db.commit()
    _policy(db, "findings", legal_hold=True)

    report = _purge(store)

    assert _result(report, "findings")["status"] == "legal_hold"
    assert _count(db, "findings") == 1


def test_recent_rows_are_kept(db, store):
    _finding(db, "f-new", age=timedelta(days=1))
    _finding(db, "f-old")
    db.commit()
    _policy(db, "findings", days=30)

    _purge(store)

    assert [r[0] for r in db.execute(text("SELECT finding_id FROM findings"))] == [
        "f-new"
    ]


def test_anonymise_findings_strips_personal_data_and_keeps_the_row(db, store):
    _finding(db, "f-1")
    db.commit()
    _policy(db, "findings", method="anonymise")

    report = _purge(store)

    db.expire_all()
    f = db.get(Finding, "f-1")
    assert f.title == retention.ANON
    assert f.description is None and f.evidence_links is None
    assert f.external_id is None
    assert set(f.entity_context) == {"retention_anonymised_at"}
    assert "alice" not in json.dumps(f.entity_context)
    # Non-NULL, without a triage error: the unrated sweep must not re-triage it.
    assert f.ai_enrichment == {"retention_anonymised": True}
    assert f.data_source == "test"
    assert _result(report, "findings")["processed"] == 1
    # Already anonymised rows are not selected again.
    assert _result(_purge(store), "findings")["processed"] == 0


def test_anonymise_cases_chats_llm_logs_and_evidence(db, store):
    _case(db, "c-1")
    db.add(CaseComment(case_id="c-1", author="bob", content="alice is guilty"))
    ev_id, path = _evidence(db, store, "c-1", "dump.bin")
    old = utcnow() - OLD
    db.add(
        Conversation(
            id="conv-1", user_id="u-alice", title="about alice", last_message_at=old
        )
    )
    db.flush()
    db.add(
        ChatMessage(
            conversation_id="conv-1",
            seq=0,
            role="user",
            content="alice's password is hunter2",
            thinking="t",
            tool_calls=[{"x": 1}],
        )
    )
    db.add(
        LLMInteractionLog(
            interaction_id="i-1",
            model="m",
            request_messages=[{"content": "alice"}],
            system_prompt="sys",
            response_content="alice",
            tool_calls=[],
            tool_results=[],
            input_tokens=11,
            output_tokens=7,
            created_at=old,
        )
    )
    db.commit()
    for cls in ("cases", "case_evidence", "chat_conversations", "llm_logs"):
        _policy(db, cls, method="anonymise")

    _purge(store)

    db.expire_all()
    case = db.get(Case, "c-1")
    assert case.title == retention.ANON
    assert case.assignee is None and case.notes == [] and case.timeline == []
    assert case.tags == [retention.ANON_TAG]
    comment = db.query(CaseComment).filter_by(case_id="c-1").one()
    assert comment.content == retention.ANON and comment.author == retention.ANON

    ev = db.get(CaseEvidence, ev_id)
    assert ev.file_path is None and ev.description is None
    assert ev.file_hash_sha256 == "ab" * 32  # proof it existed survives
    assert ev.chain_of_custody[-1]["action"] == "retention_anonymised"
    assert not path.exists()

    conv = db.get(Conversation, "conv-1")
    assert conv.title == retention.ANON and conv.user_id is None
    msg = db.query(ChatMessage).filter_by(conversation_id="conv-1").one()
    assert msg.content == retention.ANON and msg.thinking is None
    assert msg.tool_calls == []

    log = db.query(LLMInteractionLog).filter_by(interaction_id="i-1").one()
    assert log.request_messages == [] and log.system_prompt is None
    assert log.response_content == retention.ANON
    assert (log.input_tokens, log.output_tokens) == (11, 7)

    report = _purge(store)
    assert report["total_processed"] == 0


def test_raw_events_strip_the_embedded_source_record_only(db, store):
    _finding(db, "f-raw", raw=True)
    _finding(db, "f-plain")
    db.commit()
    _policy(db, "raw_events")

    report = _purge(store)

    db.expire_all()
    assert "source_evidence" not in db.get(Finding, "f-raw").entity_context
    assert db.get(Finding, "f-raw").entity_context["user"] == "alice@example.com"
    assert _result(report, "raw_events")["processed"] == 1
    assert _count(db, "findings") == 2


def test_dry_run_makes_no_changes(db, store):
    for i in range(5):
        _finding(db, f"f-{i}", raw=True)
    _case(db, "c-1")
    _, path = _evidence(db, store, "c-1", "e.bin")
    orphan = store / "orphan.bin"
    orphan.write_text("x")
    old = (utcnow() - OLD).timestamp() - 7200
    os.utime(orphan, (old, old))
    db.commit()
    for cls in ("findings", "raw_events", "cases", "case_evidence", "uploads"):
        _policy(db, cls)
    audit_before = _count(db, "config_audit_log")
    snapshot = db.execute(
        text("SELECT finding_id, CAST(entity_context AS text) FROM findings")
    ).all()

    report = _purge(store, dry_run=True, batch_size=2, max_batches=2)

    assert report["dry_run"] is True
    assert _result(report, "findings")["processed"] == 4
    assert _result(report, "findings")["more_remaining"] is True
    assert _result(report, "cases")["processed"] == 1
    assert _result(report, "uploads")["processed"] == 1
    db.expire_all()
    assert (
        db.execute(
            text("SELECT finding_id, CAST(entity_context AS text) FROM findings")
        ).all()
        == snapshot
    )
    assert _count(db, "cases") == 1 and _count(db, "case_evidence") == 1
    assert path.exists() and orphan.exists()
    assert _count(db, "config_audit_log") == audit_before


def test_batches_are_bounded_and_the_rest_waits_for_the_next_run(db, store):
    for i in range(7):
        _finding(db, f"f-{i}")
    db.commit()
    _policy(db, "findings")

    first = _result(_purge(store, batch_size=3, max_batches=2), "findings")

    assert (first["processed"], first["batches"]) == (6, 2)
    assert first["more_remaining"] is True
    assert _count(db, "findings") == 1
    second = _result(_purge(store, batch_size=3, max_batches=2), "findings")
    assert (second["processed"], second["more_remaining"]) == (1, False)
    assert _count(db, "findings") == 0


def test_every_real_run_writes_an_audit_record(db, store):
    _finding(db, "f-1")
    db.commit()
    _policy(db, "findings")

    report = retention.run_purge(dry_run=False, evidence_root=store)

    row = (
        db.query(ConfigAuditLog)
        .filter_by(config_type="retention", action="purge")
        .one()
    )
    assert row.changed_by == "system"
    assert row.config_key == f"purge:{report['run_id']}"
    findings = next(
        c for c in row.new_value["classes"] if c["data_class"] == "findings"
    )
    assert findings["processed"] == 1
    assert (findings["method"], findings["retain_days"]) == ("delete", 30)
    # The policy change was audited too.
    assert (
        db.query(ConfigAuditLog)
        .filter_by(config_type="retention", action="policy_set")
        .count()
        == 1
    )


def test_audit_log_purge_never_destroys_the_destruction_records(db, store):
    old = utcnow() - OLD
    db.add(
        ConfigAuditLog(
            config_type="retention",
            config_key="purge:old",
            action="purge",
            changed_by="system",
            timestamp=old,
        )
    )
    db.add(
        ConfigAuditLog(
            config_type="general",
            config_key="k",
            action="update",
            changed_by="alice",
            timestamp=old,
        )
    )
    db.add(
        CaseAuditLog(
            entity_type="case",
            entity_id="c-x",
            action="update",
            changed_by="alice",
            ip_address="10.0.0.1",
            timestamp=old,
        )
    )
    db.commit()
    _policy(db, "audit_logs")

    report = _purge(store)

    assert _result(report, "audit_logs")["processed"] == 2
    remaining = db.query(ConfigAuditLog).filter_by(config_key="purge:old").count()
    assert remaining == 1
    assert db.query(ConfigAuditLog).filter_by(config_type="general").count() == 0
    assert _count(db, "case_audit_logs") == 0


def test_audit_log_anonymise_removes_the_actor(db, store):
    db.add(
        CaseAuditLog(
            entity_type="case",
            entity_id="c-x",
            action="update",
            changed_by="alice",
            ip_address="10.0.0.1",
            user_agent="ua",
            timestamp=utcnow() - OLD,
        )
    )
    db.commit()
    _policy(db, "audit_logs", method="anonymise")

    _purge(store)

    db.expire_all()
    row = db.query(CaseAuditLog).one()
    assert row.changed_by == retention.ANON
    assert row.ip_address is None and row.user_agent is None


def _ledger(db, run_id, n, ts):
    for seq in range(n):
        db.execute(
            text(
                "INSERT INTO agent_events "
                "(run_id, seq, ts, run_kind, kind, payload, schema_version) "
                "VALUES (:r, :s, :ts, 'hunt', 'note', CAST(:p AS jsonb), 1)"
            ),
            {"r": run_id, "s": seq, "ts": ts, "p": json.dumps({"n": seq})},
        )
    db.commit()


def _ledger_rows(db):
    return db.execute(
        text(
            "SELECT run_id, seq, ts, CAST(payload AS text), prev_hash, event_hash "
            "FROM agent_events ORDER BY run_id, seq"
        )
    ).all()


def test_chained_ledger_is_never_purged_only_reported(db, store):
    old_run, new_run = str(uuid.uuid4()), str(uuid.uuid4())
    _ledger(db, old_run, 3, utcnow() - OLD)
    _ledger(db, new_run, 2, utcnow())
    _finding(db, "f-1")
    db.commit()
    for cls in retention.DATA_CLASSES:
        _policy(db, cls, days=1)
    before = _ledger_rows(db)

    report = _purge(store)

    ledger = _result(report, "agent_ledger")
    assert ledger["status"] == "excluded_hash_chained"
    assert ledger["archive_candidates"] == 1
    assert ledger["processed"] == 0
    assert _ledger_rows(db) == before
    assert _count(db, "findings") == 0  # the other classes did run


def test_ledger_policy_cannot_ask_for_delete(db):
    with pytest.raises(retention.RetentionError):
        retention.set_policy(
            db,
            "agent_ledger",
            retain_days=30,
            method="delete",
            legal_hold=False,
            actor="admin",
        )


def test_ledger_archive_verifies_each_chain_and_is_read_only(db):
    old_run = str(uuid.uuid4())
    _ledger(db, old_run, 3, utcnow() - OLD)
    _ledger(db, str(uuid.uuid4()), 1, utcnow())
    before = _ledger_rows(db)

    archive = retention.export_agent_ledger_archive(
        db, before=utcnow() - timedelta(days=30), limit_runs=10, actor="dba"
    )
    db.commit()

    manifest = archive["manifest"]
    assert manifest["run_ids"] == [old_run]
    assert (manifest["events"], manifest["all_verified"]) == (3, True)
    assert _ledger_rows(db) == before
    audit = (
        db.query(ConfigAuditLog).filter_by(action=retention.LEDGER_ARCHIVE_ACTION).one()
    )
    assert audit.new_value["sha256"] == manifest["sha256"]
    assert audit.changed_by == "dba"

    # The verifier catches a tampered row.
    rows = [dict(r) for r in archive["runs"][0]["rows"]]
    rows[1]["payload_text"] = '{"n": 99}'
    assert retention.verify_chain(rows) == (False, 1)


def test_uploads_removes_only_old_unreferenced_files_outside_held_cases(db, store):
    _case(db, "c-held")
    _case(db, "c-ref")
    _, referenced = _evidence(db, store, "c-ref", "keep.bin", age=timedelta(0))
    db.commit()
    retention.set_legal_hold(db, "c-held", reason="hold", actor="legal")
    db.commit()
    old = (utcnow() - OLD).timestamp() - 7200
    orphan = store / "c-gone" / "orphan.bin"
    held = store / "c-held" / "orphan.bin"
    fresh = store / "fresh.bin"
    for path in (orphan, held, fresh):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x")
    for path in (orphan, held, referenced):
        os.utime(path, (old, old))
    _policy(db, "uploads")

    report = _purge(store)

    assert _result(report, "uploads")["processed"] == 1
    assert not orphan.exists()
    assert held.exists() and fresh.exists() and referenced.exists()


def test_attachments_are_deleted_with_their_files(db, store):
    _case(db, "c-1")
    path = store / "c-1" / "a.pdf"
    path.parent.mkdir(parents=True)
    path.write_text("x")
    db.add(
        CaseAttachment(
            case_id="c-1",
            filename="a.pdf",
            file_path="c-1/a.pdf",
            file_size=1,
            uploaded_by="bob",
            created_at=utcnow() - OLD,
        )
    )
    db.commit()
    _policy(db, "case_evidence")

    report = _purge(store)

    assert _result(report, "case_evidence")["files_removed"] == 1
    assert not path.exists()
    assert _count(db, "case_attachments") == 0
    assert _count(db, "cases") == 1  # no cases policy


def test_destruction_report_aggregates_runs_in_turkish_markdown(db, store):
    for i in range(3):
        _finding(db, f"f-{i}")
    _case(db, "c-1")
    db.commit()
    retention.set_legal_hold(db, "c-1", reason="dava", actor="legal")
    db.commit()
    _policy(db, "findings")
    _policy(db, "chat_conversations", method="anonymise")
    _purge(store)

    report = retention.build_destruction_report(
        db, since=utcnow() - timedelta(days=1), until=utcnow() + timedelta(days=1)
    )

    assert report["totals"] == [
        {
            "data_class": "findings",
            "label": "Bulgular",
            "deleted": 3,
            "anonymised": 0,
            "files_removed": 0,
        }
    ]
    assert len(report["runs"]) == 1
    assert report["legal_holds"][0]["case_id"] == "c-1"
    assert {c["action"] for c in report["changes"]} == {
        "policy_set",
        "legal_hold_set",
    }
    md = retention.render_markdown(report)
    assert md.startswith("# AutoSecOps periyodik imha tutanağı")
    assert "| Bulgular | 3 | 0 | 0 |" in md
    assert "Hukuki görüş değildir" in md
    assert "Vigil" not in md
    json.dumps(report)  # exportable as JSON


def test_legal_hold_needs_an_existing_case(db):
    with pytest.raises(LookupError):
        retention.set_legal_hold(db, "c-missing", reason="x", actor="legal")
    assert retention.release_legal_hold(db, "c-missing", actor="legal") is False


def test_a_second_concurrent_run_is_refused(db, store):
    conn = get_db_manager().engine.connect()
    try:
        conn.execute(
            text("SELECT pg_advisory_lock(:k)"), {"k": retention._RUN_LOCK_KEY}
        )
        with pytest.raises(retention.RetentionBusy):
            _purge(store)
    finally:
        conn.execute(
            text("SELECT pg_advisory_unlock(:k)"), {"k": retention._RUN_LOCK_KEY}
        )
        conn.close()


def test_scheduled_run_is_off_by_default_and_a_dry_run_when_on(db, store, monkeypatch):
    _finding(db, "f-1")
    db.commit()
    _policy(db, "findings")

    assert retention.run_scheduled_purge() is None

    from core.config import get_settings

    monkeypatch.setenv("RETENTION_PURGE_ENABLED", "true")
    get_settings.cache_clear()
    try:
        report = retention.run_scheduled_purge()
    finally:
        # Do not leave a cached Settings with the purge switched on.
        monkeypatch.delenv("RETENTION_PURGE_ENABLED")
        get_settings.cache_clear()

    assert report["dry_run"] is True and report["actor"] == "system"
    assert _count(db, "findings") == 1


# --- regressions: legal-hold / open-case bypasses (verifier round 2) ----------


def _conversation(db, cid, *, case_id=None, age=OLD):
    db.add(
        Conversation(
            id=cid, title=f"chat {cid}", case_id=case_id, last_message_at=utcnow() - age
        )
    )
    db.flush()


def _llm_log(db, iid, *, session_id=None, investigation_id=None, age=OLD):
    db.add(
        LLMInteractionLog(
            interaction_id=iid,
            session_id=session_id,
            investigation_id=investigation_id,
            model="m",
            request_messages=[{"content": "alice"}],
            response_content="alice",
            tool_calls=[],
            tool_results=[],
            created_at=utcnow() - age,
        )
    )
    db.flush()


def _hold(db, cid):
    retention.set_legal_hold(db, cid, reason="litigation", actor="legal")
    db.commit()


def test_hold_set_between_batches_is_honoured(db, store, monkeypatch):
    # Two old closed cases; the purge takes one per batch. A hold placed on the
    # second after the first batch commits must stop the second batch.
    _case(db, "c-a", age=timedelta(days=200))
    _case(db, "c-b", age=timedelta(days=150))
    db.commit()
    _policy(db, "cases")

    real_unlink = retention._unlink_all
    calls = {"n": 0}

    def unlink_then_hold(root, files):
        calls["n"] += 1
        if calls["n"] == 1:
            other = get_db_session()
            try:
                _hold(other, "c-b")
            finally:
                other.close()
        return real_unlink(root, files)

    monkeypatch.setattr(retention, "_unlink_all", unlink_then_hold)
    report = _purge(store, batch_size=1, max_batches=5)

    db.expire_all()
    assert db.get(Case, "c-a") is None
    assert db.get(Case, "c-b") is not None
    assert _result(report, "cases")["processed"] == 1


def test_hold_set_between_classes_is_honoured(db, store, monkeypatch):
    # The hold is placed after the run started (after the findings class), so a
    # held-case list read once at the start of the run would miss it.
    _finding(db, "f-1")
    _case(db, "c-1", findings=["f-1"])
    db.commit()
    _policy(db, "findings", method="anonymise")
    _policy(db, "cases")

    real_run_class = retention._run_class

    def run_class(dc, **kw):
        out = real_run_class(dc, **kw)
        if dc.name == "findings":
            other = get_db_session()
            try:
                _hold(other, "c-1")
            finally:
                other.close()
        return out

    monkeypatch.setattr(retention, "_run_class", run_class)
    _purge(store)

    db.expire_all()
    assert db.get(Case, "c-1") is not None


def test_set_legal_hold_waits_for_a_purge_batch_in_flight(db):
    _case(db, "c-1")
    db.commit()
    batch = get_db_manager().engine.connect()
    try:
        batch.execute(
            text("SELECT pg_advisory_xact_lock_shared(:k)"),
            {"k": retention._HOLD_LOCK_KEY},
        )
        db.execute(text("SET LOCAL lock_timeout = '300ms'"))
        with pytest.raises(Exception, match="lock timeout"):
            retention.set_legal_hold(db, "c-1", reason="x", actor="legal")
        db.rollback()
    finally:
        batch.rollback()
        batch.close()
    # Once the batch is done the hold goes through.
    _hold(db, "c-1")
    assert "c-1" in retention.held_case_ids(db)


def test_chat_llm_logs_of_a_held_case_are_kept(db, store):
    _case(db, "c-held")
    _case(db, "c-gone-free")
    _conversation(db, "conv-held", case_id="c-held")
    _conversation(db, "conv-free", case_id="c-gone-free")
    _llm_log(db, "i-held", session_id="conv-held")
    _llm_log(db, "i-free", session_id="conv-free")
    db.commit()
    _hold(db, "c-held")
    for cls in ("llm_logs", "chat_conversations"):
        _policy(db, cls)

    _purge(store)

    db.expire_all()
    left = {r.interaction_id for r in db.query(LLMInteractionLog)}
    assert left == {"i-held"}
    assert db.get(Conversation, "conv-held") is not None
    assert db.get(Conversation, "conv-free") is None


def test_chats_and_llm_logs_of_an_open_case_are_kept(db, store):
    from core.storage.models import Investigation

    _case(db, "c-open", status="investigating")
    _case(db, "c-closed")
    _conversation(db, "conv-open", case_id="c-open")
    _conversation(db, "conv-closed", case_id="c-closed")
    _conversation(db, "conv-orphan", case_id="c-deleted-long-ago")
    db.add(
        Investigation(
            investigation_id="inv-open",
            case_id="c-open",
            workflow_id="w",
            trigger_type="manual",
            workdir="/tmp/x",
        )
    )
    db.flush()
    _llm_log(db, "i-chat-open", session_id="conv-open")
    _llm_log(db, "i-inv-open", investigation_id="inv-open")
    _llm_log(db, "i-chat-closed", session_id="conv-closed")
    db.commit()
    for cls in ("llm_logs", "chat_conversations"):
        _policy(db, cls)

    _purge(store)

    db.expire_all()
    left = {r.interaction_id for r in db.query(LLMInteractionLog)}
    assert left == {"i-chat-open", "i-inv-open"}
    assert {c.id for c in db.query(Conversation)} == {"conv-open"}


def test_anonymise_also_skips_chats_and_llm_logs_of_held_cases(db, store):
    _case(db, "c-held")
    _conversation(db, "conv-held", case_id="c-held")
    _llm_log(db, "i-held", session_id="conv-held")
    db.commit()
    _hold(db, "c-held")
    for cls in ("llm_logs", "chat_conversations"):
        _policy(db, cls, method="anonymise")

    report = _purge(store)

    assert report["total_processed"] == 0
    db.expire_all()
    assert db.get(Conversation, "conv-held").title == "chat conv-held"


def _decision(db, did, finding_id, case_id):
    db.execute(
        text(
            "INSERT INTO ai_decision_logs (decision_id, agent_id, finding_id, case_id, "
            "decision_type, confidence_score, reasoning, recommended_action) "
            "VALUES (:d, 'triage', :f, :c, 'triage', 0.9, 'r', 'a')"
        ),
        {"d": did, "f": finding_id, "c": case_id},
    )


def _sketch(db, finding_id, case_id):
    db.execute(
        text(
            "INSERT INTO sketch_mappings (case_id, finding_id, sketch_id, sketch_name) "
            "VALUES (:c, :f, 1, 's')"
        ),
        {"f": finding_id, "c": case_id},
    )


def test_findings_whose_cascade_children_reach_a_held_or_open_case_are_kept(db, store):
    # None of these findings is in case_findings: the only tie to the case is a
    # row the finding's DELETE would cascade into.
    for fid in ("f-dec-held", "f-sketch-open", "f-dec-closed", "f-free"):
        _finding(db, fid)
    _case(db, "c-held")
    _case(db, "c-open", status="investigating")
    _case(db, "c-closed")
    _decision(db, "d-1", "f-dec-held", "c-held")
    _sketch(db, "f-sketch-open", "c-open")
    _decision(db, "d-2", "f-dec-closed", "c-closed")
    db.commit()
    _hold(db, "c-held")
    _policy(db, "findings")

    report = _purge(store)

    db.expire_all()
    left = {f.finding_id for f in db.query(Finding)}
    assert left == {"f-dec-held", "f-sketch-open"}
    assert _count(db, "ai_decision_logs") == 1
    assert _count(db, "sketch_mappings") == 1
    assert _result(report, "findings")["processed"] == 2


def test_every_cascade_from_findings_and_cases_is_vetted(db):
    # The schema under test must not cascade a DELETE anywhere the purge has
    # not been taught about; a new FK has to be added to these lists first.
    assert (
        retention._unknown_cascades(db, "findings", retention.FINDING_CASCADE_CHILDREN)
        == []
    )
    assert (
        retention._unknown_cascades(db, "cases", retention.CASE_CASCADE_CHILDREN) == []
    )
    children = {
        r[0]
        for r in db.execute(
            text(
                "SELECT conrelid::regclass::text FROM pg_constraint WHERE contype = 'f' "
                "AND confdeltype = 'c' AND confrelid = 'findings'::regclass"
            )
        )
    }
    assert children == set(retention.FINDING_CASCADE_CHILDREN)


def test_an_unvetted_cascade_makes_the_delete_refuse(db, store):
    _finding(db, "f-1")
    db.commit()
    _policy(db, "findings")
    db.execute(
        text(
            "CREATE TABLE w35_new_child (finding_id VARCHAR(50) "
            "REFERENCES findings(finding_id) ON DELETE CASCADE)"
        )
    )
    db.commit()
    try:
        report = _purge(store)
    finally:
        db.execute(text("DROP TABLE w35_new_child"))
        db.commit()

    result = _result(report, "findings")
    assert result["status"] == "error"
    assert result["unvetted_cascades"] == ["w35_new_child"]
    assert _count(db, "findings") == 1


def test_cases_with_regulatory_records_are_never_deleted(db, store):
    _case(db, "c-dora")
    _case(db, "c-nis2")
    _case(db, "c-plain")
    db.execute(
        text(
            "INSERT INTO regulatory_clock_events (case_id, seq, regime, instant, value, "
            "actor, prev_hash, row_hash) VALUES ('c-dora', 1, 'dora', 'aware_at', "
            "now(), 'analyst', '', 'h')"
        )
    )
    db.execute(
        text(
            "INSERT INTO regulatory_report_drafts (case_id, regime, kind, generator, "
            "body, pack_digest, created_by) VALUES ('c-nis2', 'nis2', 'final', "
            "'template', CAST('{}' AS jsonb), 'd', 'analyst')"
        )
    )
    db.commit()
    _policy(db, "cases")

    _purge(store)

    db.expire_all()
    assert {c.case_id for c in db.query(Case)} == {"c-dora", "c-nis2"}
    assert _count(db, "regulatory_clock_events") == 1
    assert _count(db, "regulatory_report_drafts") == 1


def test_a_closed_case_related_to_a_held_or_open_case_is_kept(db, store):
    _case(db, "c-held", age=timedelta(days=1))
    _case(db, "c-open", status="investigating", age=timedelta(days=1))
    _case(db, "c-old-a")
    _case(db, "c-old-b")
    _case(db, "c-old-c")
    for a, b in (("c-held", "c-old-a"), ("c-old-b", "c-open"), ("c-old-c", "c-old-a")):
        db.execute(
            text(
                "INSERT INTO case_relationships (case_id, related_case_id, "
                "relationship_type, created_by) VALUES (:a, :b, 'related', 'x')"
            ),
            {"a": a, "b": b},
        )
    db.commit()
    _hold(db, "c-held")
    _policy(db, "cases")

    _purge(store)

    db.expire_all()
    # c-old-c is only related to c-old-a, which is closed: it goes.
    assert {c.case_id for c in db.query(Case)} == {
        "c-held",
        "c-open",
        "c-old-a",
        "c-old-b",
    }
    assert _count(db, "case_relationships") == 2


def test_audit_logs_of_an_open_case_are_kept(db, store):
    _case(db, "c-open", status="investigating")
    for entity in ("c-open", "c-gone"):
        db.add(
            CaseAuditLog(
                entity_type="case",
                entity_id=entity,
                action="update",
                changed_by="bob",
                timestamp=utcnow() - OLD,
            )
        )
    db.commit()
    _policy(db, "audit_logs")

    _purge(store, data_classes=["audit_logs"])

    db.expire_all()
    assert {a.entity_id for a in db.query(CaseAuditLog)} == {"c-open"}


def test_an_empty_class_list_is_refused_not_all(db, store):
    _finding(db, "f-1")
    db.commit()
    _policy(db, "findings")

    with pytest.raises(retention.RetentionError):
        _purge(store, data_classes=[])

    assert _count(db, "findings") == 1


def test_ledger_archive_export_is_audited(db):
    out = retention.export_agent_ledger_archive(
        db, before=utcnow(), limit_runs=5, actor="dba"
    )
    db.commit()
    row = (
        db.query(ConfigAuditLog).filter_by(action=retention.LEDGER_ARCHIVE_ACTION).one()
    )
    assert row.new_value["sha256"] == out["manifest"]["sha256"]


# --- regressions: shared evidence files (verifier round 3) --------------------


def _shared_ref(db, cid, file_path, *, age=OLD):
    """An evidence row of ``cid`` pointing at an existing file, as spelled."""
    when = utcnow() - age
    db.add(
        CaseEvidence(
            case_id=cid,
            evidence_type="file",
            name="ref",
            file_path=file_path,
            collected_by="bob",
            collected_at=when,
            chain_of_custody=[],
            created_at=when,
            updated_at=when,
        )
    )
    db.flush()


@pytest.mark.parametrize("spelling", ["c-held/shared.bin", "./c-held/shared.bin"])
def test_evidence_purge_keeps_a_file_a_held_case_still_references(db, store, spelling):
    # P7a: a purgeable case's row points at the held case's file.
    _case(db, "c-held")
    _case(db, "c-other")
    _, held_file = _evidence(db, store, "c-held", "shared.bin")
    _shared_ref(db, "c-other", spelling)
    db.commit()
    _hold(db, "c-held")
    _policy(db, "case_evidence")

    report = _purge(store)

    assert _result(report, "case_evidence")["processed"] == 1
    assert _result(report, "case_evidence")["files_removed"] == 0
    assert held_file.exists()
    db.expire_all()
    assert {e.case_id for e in db.query(CaseEvidence)} == {"c-held"}


def test_case_purge_keeps_a_file_a_held_case_still_references(db, store):
    # P7b: deleting the whole case must not take the held case's file along,
    # even when the two rows spell the path differently.
    _case(db, "c-held")
    _case(db, "c-other")
    _, held_file = _evidence(db, store, "c-held", "shared.bin")
    _shared_ref(
        db, "c-other", os.path.join(os.path.realpath(store), "c-held/shared.bin")
    )
    db.commit()
    _hold(db, "c-held")
    _policy(db, "cases")

    _purge(store)

    db.expire_all()
    assert db.get(Case, "c-other") is None
    assert held_file.exists()


def test_case_purge_still_removes_files_nobody_else_references(db, store):
    _case(db, "c-a")
    _case(db, "c-b")
    _, a_file = _evidence(db, store, "c-a", "a.bin")
    _, b_file = _evidence(db, store, "c-b", "b.bin")
    _shared_ref(db, "c-b", "./c-a/a.bin")  # both purged: a.bin goes too
    db.commit()
    _policy(db, "cases")

    report = _purge(store)

    assert _result(report, "cases")["files_removed"] == 2
    assert not a_file.exists() and not b_file.exists()


def test_uploads_treat_absolute_and_dotted_references_as_referenced(db, store):
    # P7c: rows spelling an in-store path absolutely or with ./ still protect it.
    _case(db, "c-open", status="investigating")
    _, abs_file = _evidence(db, store, "c-open", "abs.bin")
    _, dot_file = _evidence(db, store, "c-open", "dot.bin")
    db.execute(
        text("UPDATE case_evidence SET file_path = :p WHERE name = 'abs.bin'"),
        {"p": os.path.join(os.path.realpath(store), "c-open", "abs.bin")},
    )
    db.execute(
        text(
            "UPDATE case_evidence SET file_path = './c-open/dot.bin' "
            "WHERE name = 'dot.bin'"
        )
    )
    db.commit()
    orphan = store / "c-gone" / "orphan.bin"
    orphan.parent.mkdir()
    orphan.write_text("x")
    old = (utcnow() - OLD).timestamp() - 7200
    for path in (abs_file, dot_file, orphan):
        os.utime(path, (old, old))
    _policy(db, "uploads")

    report = _purge(store)

    assert _result(report, "uploads")["processed"] == 1
    assert abs_file.exists() and dot_file.exists()
    assert not orphan.exists()


def test_llm_logs_of_a_caseless_investigation_triggered_by_a_held_finding_are_kept(
    db, store
):
    # P6: case_id is NULL, but the trigger finding belongs to a held case.
    from core.storage.models import Investigation

    _finding(db, "f-held")
    _finding(db, "f-free")
    _case(db, "c-held", findings=["f-held"])
    _case(db, "c-open", status="investigating")
    for iid, triggers in (
        ("inv-held", ["f-held"]),
        ("inv-case", ["c-open"]),
        ("inv-free", ["f-free"]),
    ):
        db.add(
            Investigation(
                investigation_id=iid,
                case_id=None,
                workflow_id="w",
                trigger_type="finding",
                trigger_ids=triggers,
                workdir="/tmp/x",
            )
        )
    db.flush()
    _llm_log(db, "i-held", investigation_id="inv-held")
    _llm_log(db, "i-case", investigation_id="inv-case")
    _llm_log(db, "i-free", investigation_id="inv-free")
    db.commit()
    _hold(db, "c-held")
    _policy(db, "llm_logs")

    _purge(store)

    db.expire_all()
    left = {r.interaction_id for r in db.query(LLMInteractionLog)}
    assert left == {"i-held", "i-case"}


def test_evidence_may_not_point_into_another_cases_directory(db, store):
    from core.cases.case_evidence_service import CaseEvidenceService

    _case(db, "c-held")
    _case(db, "c-other")
    _evidence(db, store, "c-held", "shared.bin")
    db.commit()
    service = CaseEvidenceService(storage_path=str(store))

    for spelling in (
        "c-held/shared.bin",
        "./c-held/shared.bin",
        os.path.join(os.path.realpath(store), "c-held/shared.bin"),
    ):
        with pytest.raises(ValueError):
            service.add_evidence(
                "c-other", "file", "x", "bob", file_path=spelling, session=db
            )
    db.rollback()
    (store / "c-other").mkdir()
    (store / "c-other" / "own.bin").write_text("x")
    (store / "loose.bin").write_text("x")
    assert service.add_evidence(
        "c-other", "file", "x", "bob", file_path="c-other/own.bin", session=db
    )
    assert service.add_evidence(
        "c-held", "file", "x", "bob", file_path="./c-held/shared.bin", session=db
    )
    assert service.add_evidence(
        "c-other", "file", "x", "bob", file_path="loose.bin", session=db
    )
    db.rollback()
