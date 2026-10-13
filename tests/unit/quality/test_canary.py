"""Hidden canary alerts (W1.5) without a database: the setting, the replayed
finding, the AI-verdict reader, the response guard and the daemon hooks."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

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
    with (
        patch.object(cq, "read_canary_settings", return_value=cq.CanarySettings()),
        patch.object(cq, "unit_of_work", side_effect=AssertionError("no DB")),
    ):
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


_TEST_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")


def test_a_replay_carries_no_documentation_addresses_or_corpus_hashes():
    now = datetime(2026, 10, 12, 8, 30, tzinfo=timezone.utc)
    pool = cq.address_pool("10.20.0.0/16")
    for record in cq.load_corpus_records():
        source = json.dumps(record["alert"])
        alert = cq.build_canary_finding(record, now, pool=pool)
        text = json.dumps(alert)
        assert not any(net in text for net in _TEST_NETS), record["meta"]
        for h in re.findall(r"[0-9a-f]{64}", source):
            assert h not in text
        ctx = alert["entity_context"]
        for ip in ctx["src_ips"] + ctx["dest_ips"]:
            assert ipaddress.ip_address(ip) in pool[0]


def test_rewrites_are_consistent_between_entities_and_text():
    record = next(
        r
        for r in cq.load_corpus_records()
        if r["alert"]["entity_context"]["file_hashes"]
        and r["alert"]["entity_context"]["dest_ips"]
        and r["alert"]["entity_context"]["dest_ips"][0] in r["alert"]["description"]
    )
    alert = cq.build_canary_finding(record, datetime.now(timezone.utc))
    ctx = alert["entity_context"]
    assert ctx["dest_ips"][0] in alert["description"]
    assert ctx["file_hashes"][0] in alert["description"]


def test_a_replay_carries_its_vendors_per_alert_fields():
    now = datetime.now(timezone.utc)
    seen = {}
    for record in cq.load_corpus_records():
        raw = cq.build_canary_finding(record, now)["raw_event"]
        seen.setdefault(record["alert"]["data_source"], raw)
    assert len(seen) >= 5
    for source, raw in seen.items():
        assert len(raw) > 4, source  # more than vendor/rule_name/event_count
    assert seen["crowdstrike"]["detection_id"].startswith("ldt:")
    assert "SystemAlertId" in seen["sentinel"]
    # Two replays of one record differ in every per-alert id.
    record = cq.load_corpus_records()[0]
    a = cq.build_canary_finding(record, now)["raw_event"]
    b = cq.build_canary_finding(record, now)["raw_event"]
    assert a["detection_id"] != b["detection_id"]


def test_the_address_pool_refuses_routable_ranges():
    nets = cq.address_pool("8.8.8.0/24, 10.9.0.0/16, junk, 2001:db8::/32")
    assert [str(n) for n in nets] == ["10.9.0.0/16"]
    # Nothing usable left: the private default, never a public range.
    assert all(not n.is_global for n in cq.address_pool("1.1.1.0/24"))


def test_reserved_domains_move_under_the_operators_suffix_only_when_set():
    record = next(
        r for r in cq.load_corpus_records() if ".test" in r["alert"]["description"]
    )
    now = datetime.now(timezone.utc)
    kept = cq.build_canary_finding(record, now, domain_suffix="")
    assert ".test" in kept["description"]
    moved = cq.build_canary_finding(record, now, domain_suffix="lab.acme.net")
    assert ".test" not in moved["description"]
    assert ".lab.acme.net" in moved["description"]


async def test_an_injection_leaves_no_info_line_in_the_log(caplog):
    record = cq.load_corpus_records()[0]
    finding = cq.build_canary_finding(record, datetime.now(timezone.utc))
    queue: asyncio.Queue = asyncio.Queue()
    with (
        patch.object(cq, "_prepare", return_value=finding),
        caplog.at_level(logging.INFO, logger="core.quality.canary"),
    ):
        assert await cq.inject_canary(queue) == finding["finding_id"]
    assert queue.qsize() == 1
    assert [r for r in caplog.records if r.levelno >= logging.INFO] == []


def test_table_absence_is_cached_so_metrics_do_not_pay_a_lookup_per_call():
    from core.storage import canary_exclusion as ce

    ce.forget_table_presence()
    session = MagicMock()
    session.get_bind.return_value.url = "postgresql://x/absent-test"
    session.execute.return_value.scalar.return_value = None
    try:
        assert ce.canary_table_present(session) is False
        assert ce.canary_table_present(session) is False
        assert session.execute.call_count == 1
        # Expired: asked again, and a table that appeared is seen.
        with patch.object(ce.time, "monotonic", return_value=1e12):
            session.execute.return_value.scalar.return_value = "canary_injections"
            assert ce.canary_table_present(session) is True
        assert session.execute.call_count == 2
    finally:
        ce.forget_table_presence()


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


async def test_no_canary_indicator_reaches_threat_intel_or_a_sandbox():
    from services.daemon.config import ProcessingConfig
    from services.daemon.processor import FindingProcessor

    processor = FindingProcessor(
        ProcessingConfig(auto_triage_enabled=False, auto_enrich_enabled=True)
    )
    processor._data_service = None
    processor._evaluate_for_response = AsyncMock()
    processor._enrich_ip = AsyncMock(return_value=None)
    processor._enrich_hash = AsyncMock(return_value=None)
    processor._sandbox_submitter = MagicMock()
    processor._sandbox_submitter.submit_hash = AsyncMock(return_value=None)
    ctx = {"src_ips": ["10.1.2.3"], "file_hashes": ["ab" * 32]}

    with patch.object(cq, "is_canary_finding", side_effect=lambda fid: fid == "c"):
        await processor._enrich_in_background(
            {"finding_id": "c", "severity": "high", "entity_context": ctx},
            "crowdstrike",
        )
        processor._enrich_ip.assert_not_awaited()
        processor._enrich_hash.assert_not_awaited()
        processor._sandbox_submitter.submit_hash.assert_not_awaited()

        await processor._enrich_in_background(
            {"finding_id": "r", "severity": "high", "entity_context": ctx},
            "crowdstrike",
        )
        processor._enrich_ip.assert_awaited_once_with("10.1.2.3")
        processor._enrich_hash.assert_awaited_once()
        processor._sandbox_submitter.submit_hash.assert_awaited_once()


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

    with (
        patch.object(cq, "score_due_canaries", side_effect=score),
        patch.object(cq, "inject_canary", side_effect=inject),
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


def test_outbound_case_events_are_queued_only_by_the_canary_aware_dispatcher():
    """Case-event webhooks, Slack and email leave through one dispatcher, which
    skips a case made of hidden canaries (canary_injections, not only a flag)."""
    callers = sorted(
        p.relative_to(REPO).as_posix()
        for p in _py_sources()
        if "outbound_webhooks.enqueue_event" in p.read_text(encoding="utf-8")
    )
    assert callers == ["core/cases/notification_dispatcher.py"]
    src = (REPO / callers[0]).read_text(encoding="utf-8")
    body = src.split("def _dispatch_one(", 1)[1].split("\n    def ", 1)[0]
    assert "if is_canary(case):" in body
    assert "case_canary_profile(" in src and "is_canary_finding(" in src


def test_every_ioc_export_format_goes_through_the_canary_filter():
    src = (REPO / "core" / "cases" / "case_ioc_service.py").read_text(encoding="utf-8")
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
