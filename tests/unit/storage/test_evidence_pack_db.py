"""The evidence pack's reader against a real Postgres (W3.7).

Builds a case with a finding, evidence, an audit row, a response action with
before/after state, an investigation whose run has chained ``agent_events``
(19 + 31 init SQL) and regulatory clock events (50 init SQL), all in one
transaction that is rolled back. The pack must verify offline; a ledger row
altered in the database must show as broken at export and be rejected.
"""

from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.agents.projections import run_id_for
from core.compliance import verify_bundle
from core.compliance.evidence import collect_case_record, read_citable
from core.compliance.evidence_bundle import build_bundle, public_bytes
from core.compliance.regulatory_service import RegulatoryService, SqlClockStore
from core.storage.connection import get_db_manager
from core.storage.models import (
    AIDecisionLog,
    ApprovalAction,
    Case,
    CaseAuditLog,
    CaseEvidence,
    Finding,
    Investigation,
)

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

INIT = Path(__file__).resolve().parents[3] / "infra" / "database" / "init"
CASE = "W37-TEST-CASE"
INV = "inv-w37-1"
NOW = datetime(2026, 3, 2, 12, 0, tzinfo=timezone.utc)
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


@pytest.fixture()
def session():
    with get_db_manager().engine.connect() as conn:
        tx = conn.begin()
        try:
            for name in (
                "19_agent_ledger.sql",
                "31_agent_ledger_hash_chain.sql",
                "50_regulatory_clocks.sql",
            ):
                conn.execute(text((INIT / name).read_text(encoding="utf-8")))
            with Session(bind=conn, join_transaction_mode="create_savepoint") as s:
                _seed(s)
                yield s
        finally:
            tx.rollback()


def _seed(s: Session) -> None:
    case = Case(
        case_id=CASE, title="Beacon", status="open", priority="high", timeline=[]
    )
    finding = Finding(
        finding_id="f-w37",
        title="C2 beacon",
        data_source="edr",
        severity="high",
        ai_enrichment={
            "ai_triage": {
                "timestamp": "2026-03-01T08:00:00",
                "result": {"confidence": 0.9},
            }
        },
    )
    case.findings.append(finding)
    s.add(case)
    s.flush()
    s.add(
        CaseEvidence(
            case_id=CASE,
            evidence_type="file",
            name="pcap",
            collected_by="ayse",
            collected_at=datetime(2026, 3, 1, 10, 0),
        )
    )
    s.add(
        CaseAuditLog(
            entity_type="case",
            entity_id=CASE,
            action="update",
            field_name="status",
            old_value="new",
            new_value="open",
            changed_by="ayse",
        )
    )
    s.add(
        ApprovalAction(
            action_id="act-w37",
            action_type="isolate_host",
            title="Isolate build-01",
            description="isolate",
            target="build-01",
            reason="beacon",
            created_by="agent",
            status="executed",
            approved_by="ayse",
            second_approver="mehmet",
            parameters={"case_id": CASE},
            before_state={"isolated": False, "vlan": 12},
            after_state={"isolated": True, "vlan": 999},
            verify_status="verified",
            verified_at=datetime(2026, 3, 1, 11, 0),
            executed_at=datetime(2026, 3, 1, 10, 0),
            approved_at=datetime(2026, 3, 1, 9, 50),
        )
    )
    s.add(
        Investigation(
            investigation_id=INV,
            case_id=CASE,
            workflow_id="triage",
            trigger_type="finding",
            trigger_ids=["f-w37"],
            workdir="/tmp/w37",
        )
    )
    s.add(
        AIDecisionLog(
            decision_id="dec-w37",
            agent_id="triage",
            finding_id="f-w37",
            case_id=CASE,
            decision_type="verdict",
            confidence_score=0.9,
            reasoning="beacon to known C2",
            recommended_action="isolate",
        )
    )
    s.flush()
    run = run_id_for(INV)
    for seq, payload in enumerate(
        [
            {"kind": "dispatch", "agent_id": "triage"},
            {"kind": "finding", "answer": "malicious", "nested": {"b": 1, "a": [1, 2]}},
            {"kind": "terminal", "outcome": "done"},
        ]
    ):
        s.execute(
            text(
                "INSERT INTO agent_events (run_id, seq, run_kind, kind, payload, schema_version) "
                "VALUES (CAST(:r AS uuid), :seq, 'investigation', :kind, CAST(:p AS jsonb), 1)"
            ),
            {"r": run, "seq": seq, "kind": payload["kind"], "p": json.dumps(payload)},
        )
    service = RegulatoryService(SqlClockStore(s), now=lambda: NOW)
    service.record_instant(
        CASE, "nis2", "aware_at", datetime(2026, 3, 2, 8, tzinfo=timezone.utc), "ayse"
    )
    s.flush()


def _files(data):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return {i.filename: z.read(i) for i in z.infolist()}


def _bundle(s):
    record = collect_case_record(s, CASE)
    return record, build_bundle(record, "ayse", NOW, KEY, "configured")


def test_the_case_record_is_collected_and_verifies(session):
    record, bundle = _bundle(session)
    assert record.notes == []
    assert [f.finding_id for f in record.findings] == ["f-w37"]
    files = _files(bundle.data)
    checks = verify_bundle.verify_files(files, public_bytes(KEY))
    assert all(c.ok for c in checks), [(c.name, c.detail) for c in checks]

    actions = json.loads(files["data/actions.json"])["actions"]
    [action] = actions
    assert action["before_state"] == {"isolated": False, "vlan": 12}
    assert action["after_state"] == {"isolated": True, "vlan": 999}
    assert action["verify_status"] == "verified"
    runs = json.loads(files["data/ledger.json"])["runs"]
    assert runs[0]["run_id"] == run_id_for(INV) and runs[0]["status"] == "read"
    assert len(runs[0]["events"]) == 3
    ai = json.loads(files["data/ai_provenance.json"])
    assert ai["decisions"][0]["decision_id"] == "dec-w37"
    assert ai["finding_verdicts"][0]["ai_triage"]["result"]["confidence"] == 0.9
    clocks = json.loads(files["data/regulatory_clock_events.json"])
    assert clocks["status"] == "read" and len(clocks["events"]) == 1
    manifest = json.loads(files["manifest.json"])
    assert manifest["counts"]["ledger_events"] == 3


def test_drafts_and_the_pack_cite_the_same_digest(session):
    record, bundle = _bundle(session)
    events = SqlClockStore(session).events(CASE)
    assert (
        read_citable(session, CASE, events).digest == bundle.manifest["citable_digest"]
    )
    assert read_citable(session, "no-such-case") is None
    assert collect_case_record(session, "no-such-case") is None


def test_a_ledger_row_altered_in_the_database_is_caught(session):
    session.execute(
        text(
            "UPDATE agent_events SET payload = CAST(:p AS jsonb) "
            "WHERE run_id = CAST(:r AS uuid) AND seq = 1"
        ),
        {
            "p": json.dumps({"kind": "finding", "answer": "benign"}),
            "r": run_id_for(INV),
        },
    )
    _, bundle = _bundle(session)
    files = _files(bundle.data)
    verification = json.loads(files["data/verification.json"])
    assert verification["ledger"][0]["ok"] is False
    checks = {c.name: c for c in verify_bundle.verify_files(files, public_bytes(KEY))}
    assert checks["files"].ok and checks["signature"].ok
    assert checks["ledger"].ok is False


def test_canary_findings_are_left_out_of_the_pack(session):
    """W1.5's helper is installed: a canary finding on the case is dropped."""
    from core.storage import canary_exclusion

    session.execute(text((INIT / "46_eval_qa_canary.sql").read_text(encoding="utf-8")))
    canary = Finding(
        finding_id="f-w37-canary", title="Canary", data_source="edr", severity="high"
    )
    session.get(Case, CASE).findings.append(canary)
    session.execute(
        text(
            "INSERT INTO canary_injections "
            "(marker, canary_kind, expected_verdict, finding_id) "
            "VALUES ('m-w37', 'replay', 'malicious', 'f-w37-canary')"
        )
    )
    session.flush()
    canary_exclusion.forget_table_presence()
    try:
        record, bundle = _bundle(session)
        assert [f.finding_id for f in record.findings] == ["f-w37"]
        assert record.canary_exclusion == "applied"
        assert record.excluded_canaries == 1
        files = _files(bundle.data)
        dumped = files["data/findings.json"].decode()
        assert "f-w37-canary" not in dumped
        manifest = json.loads(files["manifest.json"])
        assert manifest["excluded"] == {"canary_findings": 1}
        assert manifest["sources"]["canary_exclusion"] == "applied"
        events = SqlClockStore(session).events(CASE)
        citable = read_citable(session, CASE, events)
        assert citable.digest == bundle.manifest["citable_digest"]
        checks = verify_bundle.verify_files(files, public_bytes(KEY))
        assert all(c.ok for c in checks), [(c.name, c.detail) for c in checks]
    finally:
        # The table goes with the rollback; do not leave it cached as present.
        canary_exclusion.forget_table_presence()
