"""Hidden canary alerts (W1.5) against Postgres.

Injection is off until an admin enables it (and that change is audited); an
injected canary reaches the hand-off looking like any other alert; scoring
reads the AI verdict, cases and analyst feedback; and every metrics and export
path leaves canaries out.

Runs on the throwaway database tests/unit/conftest.py provisions per process,
with ``46_eval_qa_canary.sql`` applied to it (the table is SQL-owned, so
``create_all`` does not build it).
"""

from __future__ import annotations

import asyncio
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import delete, insert, select, text

from core.cases.case_ioc_service import CaseIOCService
from core.cases.case_metrics_service import CaseMetricsService
from core.quality import canary as cq
from core.reporting.analytics_service import (
    calculate_metrics,
    get_severity_distribution,
    get_time_series_data,
    get_top_alert_sources,
)
from core.storage.canary_exclusion import (
    canary_finding_ids,
    canary_injections,
    forget_table_presence,
    is_canary_finding,
)
from core.storage.connection import get_db_manager
from core.storage.database_data_service import DatabaseDataService
from core.storage.models import (
    AIDecisionLog,
    Case,
    CaseIOC,
    ConfigAuditLog,
    Finding,
    SystemConfig,
    case_findings,
)
from core.storage.service import DatabaseService
from core.storage.unit_of_work import unit_of_work

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

INIT_SQL = (
    Path(__file__).resolve().parents[3]
    / "infra"
    / "database"
    / "init"
    / "46_eval_qa_canary.sql"
)
# A window no other module's rows land in.
CREATED = datetime(2003, 5, 6, 12, 0, 0)
START = CREATED - timedelta(hours=1)
END = CREATED + timedelta(hours=1)
PREFIX = "cnq-"
AGENT = "canary-test-agent"


@pytest.fixture(scope="module")
def canary_table(throwaway_database):
    with get_db_manager().engine.begin() as conn:
        conn.execute(text(INIT_SQL.read_text(encoding="utf-8")))
    forget_table_presence()
    return True


def _purge():
    with unit_of_work() as s:
        s.execute(delete(canary_injections))
        s.query(CaseIOC).filter(CaseIOC.case_id.like(f"{PREFIX}%")).delete(
            synchronize_session=False
        )
        s.execute(
            delete(case_findings).where(case_findings.c.case_id.like(f"{PREFIX}%"))
        )
        s.query(Case).filter(Case.case_id.like(f"{PREFIX}%")).delete(
            synchronize_session=False
        )
        s.query(AIDecisionLog).filter(AIDecisionLog.agent_id == AGENT).delete(
            synchronize_session=False
        )
        s.query(Finding).filter(Finding.finding_id.like(f"{PREFIX}%")).delete(
            synchronize_session=False
        )
        s.query(SystemConfig).filter(SystemConfig.key == cq.SETTINGS_KEY).delete()
        s.query(ConfigAuditLog).filter(
            ConfigAuditLog.config_key == cq.SETTINGS_KEY
        ).delete()


@pytest.fixture(autouse=True)
def _clean(canary_table):
    cq._injected.clear()
    _purge()
    yield
    cq._injected.clear()
    _purge()


def _finding(fid, *, source="splunk", severity="high", host="web-01", **kw):
    return Finding(
        finding_id=fid,
        created_at=CREATED,
        timestamp=CREATED,
        data_source=source,
        severity=severity,
        entity_context={"hostnames": [host], "src_ips": ["198.51.100.7"]},
        **kw,
    )


def _canary_row(fid, *, injected_at=None, host="canary-host", category="malware"):
    """A canary_injections row for ``fid`` as record_injection would write it."""
    with unit_of_work() as s:
        s.execute(
            insert(canary_injections).values(
                marker=f"m-{fid}",
                canary_kind=cq.CANARY_KIND,
                expected_verdict="malicious",
                expected_category=category,
                payload={
                    "data_source": "crowdstrike",
                    "alert": {
                        "finding_id": fid,
                        "entity_context": {
                            "hostnames": [host],
                            "src_ips": ["192.0.2.66"],
                        },
                    },
                },
                injected_at=injected_at or datetime.now(timezone.utc),
                finding_id=fid,
            )
        )


def _decision(fid, outcome=None, n=0):
    return AIDecisionLog(
        decision_id=f"{PREFIX}d-{fid}-{n}",
        agent_id=AGENT,
        finding_id=fid,
        decision_type="triage",
        confidence_score=0.9,
        reasoning="r",
        recommended_action="investigate",
        human_decision="agree",
        actual_outcome=outcome,
    )


def _enable(**kw):
    assert cq.write_canary_settings(
        cq.CanarySettings(enabled=True, **kw), user_id="admin-1", reason="test"
    )


# ---------------------------------------------------------------------------
# Off by default, admin-enabled, audited; what an injection looks like
# ---------------------------------------------------------------------------


async def test_nothing_is_injected_until_an_admin_enables_it():
    queue: asyncio.Queue = asyncio.Queue()

    assert cq.read_canary_settings().enabled is False
    assert await cq.inject_canary(queue) is None
    assert queue.empty()
    with unit_of_work() as s:
        assert s.execute(select(canary_injections.c.id)).first() is None


def test_enabling_is_written_to_the_config_audit_log_under_the_admin():
    _enable(per_day=2)

    with unit_of_work() as s:
        rows = (
            s.query(ConfigAuditLog)
            .filter(ConfigAuditLog.config_key == cq.SETTINGS_KEY)
            .all()
        )
        assert len(rows) == 1
        assert rows[0].changed_by == "admin-1"
        assert rows[0].new_value["enabled"] is True
        assert rows[0].config_type == "quality"
    assert cq.read_canary_settings() == cq.CanarySettings(enabled=True, per_day=2)


async def test_an_injected_canary_looks_like_any_other_alert_and_is_recorded():
    _enable()
    queue: asyncio.Queue = asyncio.Queue()
    now = datetime.now(timezone.utc)

    fid = await cq.inject_canary(queue, now=now, rng=random.Random(3))

    assert fid
    item = queue.get_nowait()
    finding = item["data"]
    # The normal hand-off, under the record's realistic source.
    assert item["type"] == "finding"
    assert item["source"] == finding["data_source"] != "probe"
    assert finding["finding_id"] == fid
    blob = json.dumps(finding).lower()
    for tell in ("canary", "probe", "synthetic", "eval"):
        assert tell not in blob

    with unit_of_work() as s:
        row = s.execute(select(canary_injections)).mappings().one()
    assert row["finding_id"] == fid
    assert row["outcome"] == "pending"
    assert row["expected_verdict"] == "malicious"
    assert row["expected_category"] in cq.CATEGORIES
    assert row["marker"] and row["marker"] not in json.dumps(finding)
    # A replay, not a copy: fresh ids.
    assert row["payload"]["source_finding_id"] != fid
    assert finding["external_id"] in fid

    # One per 24h / per_day: the next sweep injects nothing.
    assert await cq.inject_canary(queue, now=now + timedelta(hours=1)) is None
    assert queue.empty()
    # The responder guard knows it without the database.
    assert await cq.withhold_response(fid) is True


async def test_a_full_hand_off_records_an_error_and_queues_nothing():
    _enable()
    queue: asyncio.Queue = asyncio.Queue(maxsize=1)
    queue.put_nowait({"type": "other"})

    assert await cq.inject_canary(queue) is None

    with unit_of_work() as s:
        row = s.execute(select(canary_injections)).mappings().one()
    assert row["outcome"] == "error"
    assert "full" in row["error"]


# ---------------------------------------------------------------------------
# Scoring and the report card
# ---------------------------------------------------------------------------


def test_scoring_reads_ai_verdict_case_and_analyst_feedback():
    old = datetime.now(timezone.utc) - timedelta(hours=30)
    with unit_of_work() as s:
        s.add_all(
            [
                _finding(
                    f"{PREFIX}ai",
                    ai_enrichment={"ai_triage": {"result": {"verdict": "malicious"}}},
                ),
                _finding(f"{PREFIX}case"),
                _finding(f"{PREFIX}analyst"),
                _finding(
                    f"{PREFIX}missed",
                    ai_enrichment={"verdict": {"verdict": "benign"}},
                ),
                _finding(f"{PREFIX}recent"),
                Case(case_id=f"{PREFIX}c1", title="t", status="open", priority="high"),
            ]
        )
        s.flush()
        s.execute(
            insert(case_findings).values(
                case_id=f"{PREFIX}c1", finding_id=f"{PREFIX}case"
            )
        )
        s.add(_decision(f"{PREFIX}analyst", "true_positive"))
    for name in ("ai", "case", "analyst", "missed", "gone"):
        _canary_row(f"{PREFIX}{name}", injected_at=old, category="network")
    _canary_row(f"{PREFIX}recent", category="network")

    assert cq.score_due_canaries(settings=cq.CanarySettings(score_after_hours=24)) == 5

    with unit_of_work() as s:
        rows = {
            r["finding_id"]: r
            for r in s.execute(select(canary_injections)).mappings().all()
        }
    assert rows[f"{PREFIX}ai"]["outcome"] == "caught"
    assert rows[f"{PREFIX}ai"]["payload"]["score"]["ai_verdict"] == "malicious"
    assert rows[f"{PREFIX}case"]["outcome"] == "caught"
    assert rows[f"{PREFIX}case"]["payload"]["score"]["case_opened"] is True
    assert rows[f"{PREFIX}analyst"]["outcome"] == "caught"
    assert rows[f"{PREFIX}analyst"]["observed_verdict"] == "malicious"
    assert rows[f"{PREFIX}missed"]["outcome"] == "missed"
    assert rows[f"{PREFIX}missed"]["observed_verdict"] == "benign"
    assert rows[f"{PREFIX}gone"]["outcome"] == "error"
    assert rows[f"{PREFIX}recent"]["outcome"] == "pending"

    # Never rescored.
    assert cq.score_due_canaries(settings=cq.CanarySettings(score_after_hours=24)) == 0

    summary = cq.canary_summary()
    assert summary["totals"] == {"pending": 1, "caught": 3, "missed": 1, "error": 1}
    assert summary["catch_rate"] == 0.75
    assert summary["by_category"]["network"]["catch_rate"] == 0.75
    assert summary["caught_by"] == {
        "ai_verdict": 1,
        "case_opened": 1,
        "analyst_marked_malicious": 1,
    }
    assert len(summary["canaries"]) == 6
    assert all("marker" not in c for c in summary["canaries"])


def test_the_admin_api_reports_and_sets_with_the_admins_name(monkeypatch):
    from core.auth.current_user import get_current_user
    from core.quality.canary_router import ROUTER_META, router

    app = FastAPI()
    app.include_router(
        router,
        prefix=ROUTER_META.prefix,
        dependencies=list(ROUTER_META.extra_dependencies),
    )
    admin = MagicMock(user_id="admin-7", role_id="role-admin")
    manager = MagicMock(user_id="manager-3", role_id="role-manager")
    signed_in = {"user": admin}
    app.dependency_overrides[get_current_user] = lambda: signed_in["user"]
    client = TestClient(app)
    # The test env runs with DEV_MODE on, which waives role checks.
    monkeypatch.setattr("core.quality.canary_router._dev_mode", lambda: False)

    with patch(
        "core.auth.auth_service.AuthService.check_permission",
        side_effect=lambda uid, perm, session=None: perm == "settings.write",
    ):
        assert client.get("/api/quality/canaries/settings").json()["enabled"] is False
        put = client.put(
            "/api/quality/canaries/settings",
            json={"enabled": True, "per_day": 3, "reason": "pilot"},
        )
        assert put.status_code == 200, put.text
        summary = client.get("/api/quality/canaries").json()
        assert summary["settings"]["enabled"] is True
        assert summary["table_present"] is True

    with patch(
        "core.auth.auth_service.AuthService.check_permission", return_value=False
    ):
        assert client.get("/api/quality/canaries").status_code == 403
        assert (
            client.put(
                "/api/quality/canaries/settings", json={"enabled": False}
            ).status_code
            == 403
        )

    # settings.write alone (a Manager holds it too) is not enough: Admin only.
    signed_in["user"] = manager
    with patch(
        "core.auth.auth_service.AuthService.check_permission",
        side_effect=lambda uid, perm, session=None: perm == "settings.write",
    ):
        denied = client.put("/api/quality/canaries/settings", json={"enabled": False})
        assert denied.status_code == 403
        assert "Admin role" in denied.json()["detail"]
        assert client.get("/api/quality/canaries").status_code == 403
        assert client.get("/api/quality/canaries/settings").status_code == 403
    assert cq.read_canary_settings().enabled is True  # the manager changed nothing

    with unit_of_work() as s:
        audit = (
            s.query(ConfigAuditLog)
            .filter(ConfigAuditLog.config_key == cq.SETTINGS_KEY)
            .one()
        )
        assert audit.changed_by == "admin-7"
        assert audit.change_reason == "pilot"


# ---------------------------------------------------------------------------
# Exclusion from metrics and exports
# ---------------------------------------------------------------------------


@pytest.fixture
def estate():
    """One real finding, one canary, and cases of each kind, in CREATED's window."""
    real, can = f"{PREFIX}real", f"{PREFIX}can"
    with unit_of_work() as s:
        s.add_all(
            [
                _finding(real, source="splunk", severity="high", host="web-01"),
                _finding(
                    can, source="crowdstrike", severity="critical", host="canary-host"
                ),
            ]
        )
        for cid in ("only", "mixed", "plain"):
            s.add(
                Case(
                    case_id=f"{PREFIX}{cid}",
                    title=cid,
                    status="open",
                    priority="high",
                    created_at=CREATED,
                    updated_at=CREATED,
                )
            )
        s.flush()
        s.execute(
            insert(case_findings),
            [
                {"case_id": f"{PREFIX}only", "finding_id": can},
                {"case_id": f"{PREFIX}mixed", "finding_id": can},
                {"case_id": f"{PREFIX}mixed", "finding_id": real},
                {"case_id": f"{PREFIX}plain", "finding_id": real},
            ],
        )
        s.add_all(
            [
                CaseIOC(
                    case_id=f"{PREFIX}only", ioc_type="hostname", value="canary-host"
                ),
                CaseIOC(
                    case_id=f"{PREFIX}mixed", ioc_type="hostname", value="CANARY-HOST"
                ),
                CaseIOC(case_id=f"{PREFIX}mixed", ioc_type="ip", value="192.0.2.66"),
                CaseIOC(case_id=f"{PREFIX}mixed", ioc_type="hostname", value="web-01"),
            ]
        )
        s.add_all([_decision(real, "true_positive"), _decision(can, "true_positive")])
    _canary_row(can, host="canary-host")
    return real, can


def test_the_lookup_helpers_know_the_canary(estate):
    real, can = estate
    assert canary_finding_ids() == {can}
    assert is_canary_finding(can) is True
    assert is_canary_finding(real) is False


async def test_withhold_response_reads_the_database_for_a_canary_it_did_not_inject(
    estate,
):
    real, can = estate
    assert await cq.withhold_response(can) is True
    assert await cq.withhold_response(real) is False


async def test_analytics_leave_canaries_and_canary_only_cases_out(estate):
    with unit_of_work() as db:
        metrics = await calculate_metrics(
            db, START, END, START - timedelta(days=1), START
        )
        assert metrics["totalFindings"] == 1
        assert metrics["totalCases"] == 2  # mixed + plain

        sources = {r["name"] for r in await get_top_alert_sources(db, START, END)}
        assert sources == {"splunk"}

        severities = await get_severity_distribution(db, START, END)
        assert {r["name"]: r["value"] for r in severities} == {"High": 1}

        # Off the hour: bucket edges are inclusive on both sides.
        series = await get_time_series_data(
            db, CREATED - timedelta(minutes=30), END, "24h"
        )
        assert sum(b["findings"] for b in series) == 1
        assert sum(b["cases"] for b in series) == 2


def test_case_dashboard_leaves_canary_only_cases_out(estate):
    metrics = CaseMetricsService().get_dashboard_metrics(start_date=START, end_date=END)
    assert metrics["total_cases"] == 2


def test_ai_decision_stats_leave_canary_decisions_out(estate):
    stats = DatabaseService().get_ai_decision_stats(agent_id=AGENT, days=30)
    assert stats["total_decisions"] == 1
    assert stats["outcomes"] == {"true_positive": 1}


def test_findings_export_leaves_canaries_out(estate, tmp_path):
    real, can = estate
    out = tmp_path / "findings.json"

    assert DatabaseDataService().export_findings(out, fmt="json")

    exported = {f["finding_id"] for f in json.loads(out.read_text())["findings"]}
    assert real in exported
    assert can not in exported


def test_ioc_exports_leave_canary_indicators_out(estate):
    svc = CaseIOCService()

    assert json.loads(svc.export_iocs_json(f"{PREFIX}only")) == []
    assert svc.export_iocs_csv(f"{PREFIX}only").splitlines()[1:] == []
    assert svc.export_iocs_stix(f"{PREFIX}only")["objects"] == []

    mixed = [i["value"] for i in json.loads(svc.export_iocs_json(f"{PREFIX}mixed"))]
    assert mixed == ["web-01"]
    csv_rows = svc.export_iocs_csv(f"{PREFIX}mixed").splitlines()[1:]
    assert [r.split(",")[1] for r in csv_rows] == ["web-01"]
    stix = svc.export_iocs_stix(f"{PREFIX}mixed")["objects"]
    assert [o["pattern"] for o in stix] == ["[x-custom-observable:value = 'web-01']"]


def test_jira_export_refuses_a_canary_only_case_without_calling_jira(estate):
    from services.api.routers import jira_export

    user = MagicMock(user_id="u", username="u", full_name="U", email="u@x")
    with patch.object(
        jira_export,
        "resolve",
        return_value={"url": "https://jira.test", "username": "u", "api_token": "t"},
    ), patch.object(
        jira_export.AuthService, "check_permission", return_value=True
    ), patch.object(
        jira_export.httpx, "post"
    ) as post, unit_of_work() as session:
        result = jira_export.export_case_to_jira(
            f"{PREFIX}only",
            jira_export.JiraExportRequest(project_key="SEC"),
            user,
            session,
        )
    assert result.success is False
    post.assert_not_called()


def test_jira_findings_list_drops_canaries_from_a_mixed_case(estate):
    from core.storage.canary_exclusion import drop_canaries

    real, can = estate
    with unit_of_work() as s:
        case = s.get(Case, f"{PREFIX}mixed")
        kept = [f.finding_id for f in drop_canaries(case.findings, session=s)]
    assert kept == [real]


def test_case_metrics_api_leaves_canary_only_cases_out(estate):
    from core.api.v1 import case_metrics_router as cm

    with unit_of_work() as s:
        by_status = cm.get_by_status(s, start_date=START, end_date=END)
        by_priority = cm.get_by_priority(s, start_date=START, end_date=END)
        mttd = cm.get_mttd(s, start_date=START, end_date=END)
        analysts = cm.get_all_analyst_performance(s, start_date=START, end_date=END)
    assert by_status["status_breakdown"] == [{"status": "open", "count": 2}]
    assert by_priority["priority_breakdown"][0]["count"] == 2
    assert mttd["total_cases"] == 2
    assert sum(a["cases_assigned"] for a in analysts["analyst_performance"]) == 2


async def test_siem_write_back_skips_canaries(estate):
    """Closing a mixed case writes the real finding's status upstream only."""
    from core.api.v1 import cases_router

    real, can = estate
    findings = {
        fid: {
            "finding_id": fid,
            "data_source": "elastic",
            "metadata": {"elastic_alert_id": f"es-{fid}"},
        }
        for fid in (real, can)
    }
    svc = MagicMock()
    svc.update_upstream_alert_status = AsyncMock(return_value=True)
    data = MagicMock()
    data.get_case.return_value = {"finding_ids": [can, real]}
    data.get_finding.side_effect = findings.get
    with patch.object(cases_router, "data_service", data), patch.object(
        cases_router, "_get_ingestion_service", return_value=svc
    ):
        await cases_router._sync_upstream_status(f"{PREFIX}mixed", "closed")
    svc.update_upstream_alert_status.assert_awaited_once_with(f"es-{real}", "closed")


async def test_siem_write_back_fails_closed_when_the_canary_lookup_fails(estate):
    from core.api.v1 import cases_router

    real, _can = estate
    svc = MagicMock()
    svc.update_upstream_alert_status = AsyncMock(return_value=True)
    data = MagicMock()
    data.get_case.return_value = {"finding_ids": [real]}
    data.get_finding.return_value = {
        "finding_id": real,
        "data_source": "elastic",
        "metadata": {"elastic_alert_id": "es-1"},
    }
    with patch.object(cases_router, "data_service", data), patch.object(
        cases_router, "_get_ingestion_service", return_value=svc
    ), patch.object(
        cases_router, "canary_finding_ids", side_effect=RuntimeError("db down")
    ):
        await cases_router._sync_upstream_status(f"{PREFIX}mixed", "closed")
    svc.update_upstream_alert_status.assert_not_called()
