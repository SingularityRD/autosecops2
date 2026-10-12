"""Hidden canary alerts (W1.5) without a database: the setting, the replayed
finding, the AI-verdict reader, the response guard and the daemon hooks."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from core.quality import canary as cq

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]


@pytest.fixture(autouse=True)
def _registry():
    cq._injected.clear()
    yield
    cq._injected.clear()


# --- the setting -------------------------------------------------------------


def test_absent_or_malformed_setting_is_off():
    assert cq.CanarySettings.from_value(None).enabled is False
    assert cq.CanarySettings.from_value({"enabled": "true"}).enabled is False
    assert cq.CanarySettings.from_value({"enabled": 1}).enabled is False
    assert cq.CanarySettings.from_value({"enabled": True}).enabled is True


def test_setting_values_are_clamped():
    s = cq.CanarySettings.from_value(
        {"enabled": True, "per_day": 1000, "score_after_hours": 0}
    )
    assert s.per_day == cq.MAX_PER_DAY
    assert s.score_after_hours == cq.MIN_SCORE_AFTER_H
    assert cq.CanarySettings.from_value({"per_day": "x"}).per_day == 1


def test_an_unreadable_setting_is_off():
    with patch("core.quality.canary.get_config_service") as svc:
        svc.return_value.read_system_config.side_effect = RuntimeError("db down")
        assert cq.read_canary_settings().enabled is False


async def test_a_disabled_sweep_touches_neither_the_queue_nor_the_table():
    queue: asyncio.Queue = asyncio.Queue()
    with patch.object(
        cq, "read_canary_settings", return_value=cq.CanarySettings()
    ), patch.object(cq, "unit_of_work", side_effect=AssertionError("no DB")):
        assert await cq.inject_canary(queue) is None
    assert queue.empty()


# --- the replayed finding ----------------------------------------------------


def test_the_corpus_gives_only_malicious_test_split_records():
    records = cq.load_corpus_records()
    assert len(records) > 100
    assert {r["labels"]["verdict"] for r in records} == {"malicious"}
    assert {r["meta"]["split"] for r in records} == {"test"}


def test_a_replay_has_fresh_ids_the_current_time_and_no_test_markings():
    record = cq.load_corpus_records()[0]
    before = json.dumps(record, sort_keys=True)
    now = datetime(2026, 10, 12, 8, 30, tzinfo=timezone.utc)

    a = cq.build_canary_finding(record, now)
    b = cq.build_canary_finding(record, now)

    assert json.dumps(record, sort_keys=True) == before  # source left alone
    prefix = record["alert"]["finding_id"].split("-", 1)[0]
    assert a["finding_id"].startswith(prefix + "-")
    assert a["finding_id"] != record["alert"]["finding_id"]
    assert a["finding_id"] != b["finding_id"]
    assert a["external_id"] == a["finding_id"].split("-", 1)[1]
    assert len(a["finding_id"]) <= 50  # findings.finding_id is String(50)
    assert a["timestamp"] == "2026-10-12T08:30:00Z"
    assert a["data_source"] == record["alert"]["data_source"] != "probe"
    assert "synthetic" not in a["raw_event"]
    assert "canary" not in json.dumps(a).lower()


def test_every_corpus_id_fits_the_finding_id_column():
    now = datetime.now(timezone.utc)
    for record in cq.load_corpus_records():
        assert len(cq.build_canary_finding(record, now)["finding_id"]) <= 50


def test_the_daemon_image_ships_the_corpus_it_replays():
    dockerfile = (REPO / "infra" / "docker" / "Dockerfile.daemon").read_text()
    rel = cq.CORPUS_PATH.relative_to(REPO).as_posix()
    assert f"COPY --chown=vigil:vigil {rel} ./{rel}" in dockerfile


# --- reading the AI's call ---------------------------------------------------


@pytest.mark.parametrize(
    "enrichment,expected",
    [
        (None, None),
        ({}, None),
        ({"ai_triage": {"result": {"verdict": "malicious"}}}, "malicious"),
        ({"ai_triage": {"verdict": {"verdict": "benign"}}}, "benign"),
        ({"verdict": {"verdict": "inconclusive", "confidence": 0.4}}, "inconclusive"),
        ({"ai_triage": {"result": {"verdict": "MALICIOUS"}}}, "malicious"),
        ({"ai_triage": {"result": {"verdict": "nonsense"}}}, None),
        # Triage that predates the verdict contract.
        ({"ai_triage": {"result": {"recommended_action": "isolate"}}}, "malicious"),
        ({"ai_triage": {"result": {"recommended_action": "block"}}}, "malicious"),
        ({"ai_triage": {"result": {"recommended_action": "dismiss"}}}, "benign"),
        ({"ai_triage": {"result": {"recommended_action": "monitor"}}}, "inconclusive"),
        (
            {"ai_triage": {"result": {"recommended_action": {"type": "isolate"}}}},
            "malicious",
        ),
    ],
)
def test_ai_verdict(enrichment, expected):
    assert cq.ai_verdict(enrichment) == expected


# --- the response guard ------------------------------------------------------


async def test_a_canary_this_process_injected_is_withheld_without_a_lookup():
    cq._injected.add("cs-abc")
    with patch.object(cq, "is_canary_finding", side_effect=AssertionError):
        assert await cq.withhold_response("cs-abc") is True


async def test_a_failed_lookup_withholds_once_canaries_are_live_here():
    with patch.object(cq, "is_canary_finding", side_effect=RuntimeError("db down")):
        # Nothing injected by this process: nothing to hide, act normally.
        assert await cq.withhold_response("f-1") is False
        cq._injected.add("cs-other")
        assert await cq.withhold_response("f-1") is True


async def test_the_lookup_decides_otherwise():
    with patch.object(cq, "is_canary_finding", side_effect=lambda fid: fid == "c"):
        assert await cq.withhold_response("c") is True
        assert await cq.withhold_response("r") is False


async def test_the_processor_never_hands_a_canary_to_the_responder():
    from services.daemon.config import ProcessingConfig
    from services.daemon.processor import FindingProcessor

    processor = FindingProcessor(
        ProcessingConfig(auto_triage_enabled=False, auto_enrich_enabled=False)
    )
    processor._evaluate_for_response = AsyncMock()

    with patch.object(cq, "is_canary_finding", side_effect=lambda fid: fid == "c"):
        await processor._enrich_in_background(
            {"finding_id": "c", "severity": "critical"}, "crowdstrike"
        )
        processor._evaluate_for_response.assert_not_awaited()
        await processor._enrich_in_background(
            {"finding_id": "r", "severity": "critical"}, "crowdstrike"
        )
        processor._evaluate_for_response.assert_awaited_once()


# --- the daemon schedule -----------------------------------------------------


def _task_names(**overrides):
    from services.daemon.config import SchedulerConfig
    from services.daemon.scheduler import TaskScheduler

    return {t.name for t in TaskScheduler(SchedulerConfig(**overrides))._tasks}


def test_the_sweep_is_scheduled_unless_the_kill_switch_is_off():
    assert "canary_sweep" in _task_names()
    assert "canary_sweep" not in _task_names(canaries_enabled=False)


async def test_the_scheduler_sweep_scores_then_injects_onto_the_processor_queue():
    from services.daemon.config import SchedulerConfig
    from services.daemon.scheduler import TaskScheduler

    scheduler = TaskScheduler(SchedulerConfig())
    queue: asyncio.Queue = asyncio.Queue()
    scheduler.set_processor_queue(queue)
    calls = []

    def score():
        calls.append("score")
        return 2

    async def inject(q):
        calls.append(("inject", q is queue))
        return "cs-1"

    with patch.object(cq, "score_due_canaries", side_effect=score), patch.object(
        cq, "inject_canary", side_effect=inject
    ):
        result = await scheduler._run_canary_sweep()

    assert calls == ["score", ("inject", True)]
    assert result == {"scored": 2, "injected": 1}
    assert scheduler.stats["canaries_scored"] == 2
    assert scheduler.stats["canaries_injected"] == 1


def test_the_settings_feed_the_daemon_kill_switch(monkeypatch):
    from core.config import Settings
    from services.daemon.config import DaemonConfig

    monkeypatch.setenv("DAEMON_CANARIES_ENABLED", "false")
    monkeypatch.setenv("DAEMON_CANARY_INTERVAL", "1800")
    settings = Settings()
    # Not get_settings.cache_clear(): other tests' cached Settings must survive.
    monkeypatch.setattr("services.daemon.config.get_settings", lambda: settings)

    config = DaemonConfig.from_env()

    assert config.scheduler.canaries_enabled is False
    assert config.scheduler.canary_interval == 1800
    assert Settings.model_fields["daemon_canaries_enabled"].default is True


# --- egress inventory ----------------------------------------------------------
# The exclusions are tested against Postgres in test_canary_db.py. These pin the
# inventory they were written against, so a new egress path fails here until it
# is given (or deliberately denied) a canary exclusion.


def _py_sources():
    for top in ("core", "services", "tools"):
        for path in (REPO / top).rglob("*.py"):
            if "tests" not in path.parts:
                yield path


def test_siem_write_back_has_one_caller_and_it_skips_canaries():
    callers = sorted(
        p.relative_to(REPO).as_posix()
        for p in _py_sources()
        if ".update_upstream_alert_status(" in p.read_text(encoding="utf-8")
    )
    assert callers == ["core/api/v1/cases_router.py"]
    src = (REPO / callers[0]).read_text(encoding="utf-8")
    assert "canaries = canary_finding_ids()" in src


def test_outbound_webhooks_deliver_nothing_yet():
    """Case-event webhooks are management stubs: no request leaves the install.
    When delivery lands it must drop canaries (core.storage.canary_exclusion)."""
    src = (REPO / "core" / "integrations" / "webhooks_router.py").read_text(
        encoding="utf-8"
    )
    for client in ("httpx", "requests", "aiohttp", "urllib"):
        assert client not in src


def test_every_ioc_export_format_goes_through_the_canary_filter():
    src = (REPO / "core" / "cases" / "case_ioc_service.py").read_text(
        encoding="utf-8"
    )
    for fn in ("export_iocs_json", "export_iocs_csv", "export_iocs_stix"):
        body = src.split(f"def {fn}(", 1)[1].split("\n    def ", 1)[0]
        assert "self._exportable_iocs(" in body, fn
        assert "self.get_case_iocs(" not in body, fn


# --- the daemon's scheduled report ---------------------------------------------


def test_the_scheduled_report_counts_neither_canaries_nor_canary_only_cases():
    findings = [{"finding_id": "r"}, {"finding_id": "c"}]
    cases = [
        {"case_id": "only", "finding_ids": ["c"]},
        {"case_id": "mixed", "finding_ids": ["c", "r"]},
        {"case_id": "empty", "finding_ids": []},
    ]
    with patch.object(cq, "canary_finding_ids", return_value={"c"}):
        kept_f, kept_c = cq.without_canaries(findings, cases)
    assert [f["finding_id"] for f in kept_f] == ["r"]
    assert [c["case_id"] for c in kept_c] == ["mixed", "empty"]

    # The report is only logged: a failed lookup keeps everything.
    with patch.object(cq, "canary_finding_ids", side_effect=RuntimeError("db")):
        assert cq.without_canaries(findings, cases) == (findings, cases)


async def test_the_scheduler_report_goes_through_the_canary_filter():
    from unittest.mock import MagicMock

    from services.daemon.config import SchedulerConfig
    from services.daemon.scheduler import TaskScheduler

    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    scheduler = TaskScheduler(SchedulerConfig())
    data = MagicMock()
    data.get_findings.return_value = [
        {"finding_id": "r", "timestamp": now, "severity": "high"},
        {"finding_id": "c", "timestamp": now, "severity": "critical"},
    ]
    data.get_cases.return_value = [{"case_id": "only", "finding_ids": ["c"]}]
    scheduler._data_service = data
    with patch.object(cq, "canary_finding_ids", return_value={"c"}):
        report = await scheduler._generate_report()
    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["critical_findings"] == 0
    assert report["summary"]["total_cases"] == 0
