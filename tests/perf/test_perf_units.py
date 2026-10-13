"""Unit tests for the load/chaos tooling: no stack, no database, run in gates."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from tests.perf import chaos, loadgen, measure
from tests.perf.faulty_llm import FaultyLLM


def _row(fid, created, *, lane=None, decided=None, triage=None, verdict=None, **kw):
    return measure.FindingRow(
        finding_id=fid,
        external_id=kw.get("external_id", fid),
        created_epoch=created,
        lane=lane,
        decided_epoch=decided,
        degraded_from=kw.get("degraded_from"),
        deferred_verdict=kw.get("deferred_verdict", False),
        triage_epoch=triage,
        triage_error=kw.get("triage_error"),
        verdict_finished_epoch=verdict,
        decisions=kw.get("decisions", 1 if lane else 0),
        has_enrichment=kw.get("has_enrichment", True),
        rules_epoch=kw.get("rules_epoch"),
    )


# -- measure ----------------------------------------------------------------


def test_percentile_matches_linear_interpolation():
    assert measure.percentile([], 95) is None
    assert measure.percentile([7], 99) == 7.0
    data = list(range(1, 101))  # 1..100
    assert measure.percentile(data, 50) == pytest.approx(50.5)
    assert measure.percentile(data, 95) == pytest.approx(95.05)
    assert measure.percentile(data, 100) == 100.0
    with pytest.raises(ValueError):
        measure.percentile(data, 101)


def test_verdict_time_depends_on_lane():
    rules = _row("a", 100.0, lane="rules", decided=101.0, triage=None)
    small = _row("b", 100.0, lane="small_model", decided=100.5, triage=130.0)
    small_pending = _row("c", 100.0, lane="small_model", decided=100.5)
    verdict = _row("d", 100.0, lane="verdict", decided=100.2, verdict=400.0)
    verdict_pending = _row("e", 100.0, lane="verdict", decided=100.2, triage=110.0)
    unrouted = _row("f", 100.0, triage=104.0)
    assert measure.verdict_epoch(rules) == 101.0
    assert measure.verdict_epoch(small) == 130.0
    assert not measure.is_settled(small_pending)
    assert measure.verdict_epoch(verdict) == 400.0
    # A verdict-lane finding is settled by its run, not by a triage.
    assert not measure.is_settled(verdict_pending)
    assert measure.lane_of(unrouted) == "unrouted"
    assert measure.verdict_epoch(unrouted) == 104.0
    # First routed to the model, re-routed to a rule by the backfill before any
    # triage answered: settled by the rule, counted in the rules lane.
    rerouted = _row("g", 100.0, lane="small_model", decided=100.1, rules_epoch=150.0)
    assert measure.settlement(rerouted) == (150.0, "rules")
    # A triage that answered first wins over a later rule.
    triaged = _row(
        "h", 100.0, lane="small_model", decided=100.1, triage=120, rules_epoch=150.0
    )
    assert measure.settlement(triaged) == (120, "small_model")
    assert measure.settlement(small_pending) == (None, "small_model")


def test_lane_stats_and_slo_comparison():
    rows = [_row(f"r{i}", 0.0, lane="rules", decided=1.0 + i * 0.01) for i in range(30)]
    rows += [
        _row(f"s{i}", 0.0, lane="small_model", decided=0.1, triage=70.0)
        for i in range(25)
    ]
    rows.append(_row("s-pending", 0.0, lane="small_model", decided=0.1))
    stats = measure.lane_stats(rows)
    assert stats["rules"].count == 30 and stats["rules"].settled == 30
    assert stats["rules"].p95 < 5
    assert stats["small_model"].count == 26 and stats["small_model"].settled == 25
    checks = {c.name: c for c in measure.compare_slo(stats, lost=0)}
    assert checks["Ingest->verdict, rules lane"].status == "PASS"
    small = checks["Ingest->verdict, small model lane"]
    assert small.status == "FAIL" and "1 unsettled" in small.measured
    assert checks["Ingest->verdict, verdict run"].status == "n/a"
    assert checks["Alert loss"].status == "PASS"
    assert measure.compare_slo(stats, lost=1)[-1].status == "FAIL"


def test_slo_needs_enough_samples():
    rows = [_row(f"r{i}", 0.0, lane="rules", decided=9.0) for i in range(5)]
    check = measure.compare_slo(measure.lane_stats(rows), 0, min_samples=20)[0]
    assert check.status == "n/a" and "samples" in check.measured


def test_accounting_lost_duplicates_unsettled():
    rows = [
        _row("lt-x-1", 0, lane="rules", decided=1),
        _row("lt-x-2", 0, lane="small_model", decided=1, decisions=2),
        _row("lt-x-9", 0, lane="small_model", decided=1, external_id="lt-x-2"),
    ]
    acc = measure.account(
        accepted_ids=["lt-x-1", "lt-x-2", "lt-x-3"],
        sent_ids=["lt-x-1", "lt-x-2", "lt-x-3", "lt-x-4"],
        rows=rows,
    )
    assert acc.lost == ["lt-x-3"]
    assert acc.unexpected == ["lt-x-9"]
    assert acc.duplicate_rows == 1
    assert set(acc.unsettled) == {"lt-x-2", "lt-x-9"}
    assert acc.re_decided == 1


def test_wait_settled_polls_until_done_and_tolerates_db_errors():
    calls = {"n": 0}

    def fetch(_engine, _prefix):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("database restarting")
        if calls["n"] == 2:
            return [_row("a", 0, lane="small_model", decided=1)]
        return [_row("a", 0, lane="small_model", decided=1, triage=5)]

    rows = measure.wait_settled(None, "p", ["a"], timeout=5, poll=0.01, fetch=fetch)
    assert measure.is_settled(rows[0]) and calls["n"] == 3


def test_report_renders_and_serialises():
    rows = [_row("a", 0, lane="rules", decided=1)]
    stats = measure.lane_stats(rows)
    acc = measure.account(["a"], ["a"], rows)
    rep = measure.Report(
        run_id="abc",
        label="unit",
        profile={"rate": 1},
        client={"requests": 1},
        lanes=stats,
        accounting=acc,
        slo=measure.compare_slo(stats, 0),
        notes=["smoke"],
        by_path={"api": stats},
    )
    md = measure.render_markdown(rep)
    assert "| rules | 1 | 1 |" in md and "Alert loss" in md and "smoke" in md
    assert "| api | rules | 1 | 1 |" in md
    d = json.loads(json.dumps(rep.to_dict(), default=str))
    assert d["accounting"]["lost_count"] == 0


# -- loadgen ----------------------------------------------------------------


def test_schedule_sustained_plus_bursts():
    p = loadgen.Profile(
        rate=2, duration=60, burst_rate=10, burst_duration=5, burst_every=30
    )
    times = loadgen.schedule(p)
    assert len(times) == 120 + 2 * 50
    assert times == sorted(times) and 0 <= times[0] and times[-1] < 60
    in_burst = [t for t in times if 30 <= t < 35]
    assert len(in_burst) == 10 + 50


def test_schedule_rejects_bad_profiles():
    for bad in (
        loadgen.Profile(rate=-1),
        loadgen.Profile(duration=0),
        loadgen.Profile(api_fraction=1.5),
        loadgen.Profile(batch_size=0),
        loadgen.Profile(burst_rate=5),
    ):
        with pytest.raises(ValueError):
            loadgen.schedule(bad)


def test_make_finding_ids_are_unique_bounded_and_label_free():
    alerts = loadgen.load_corpus(loadgen.DEFAULT_CORPUS, limit=3)
    a = loadgen.make_finding(alerts[0], "deadbeef", 1)
    b = loadgen.make_finding(alerts[0], "deadbeef", 2)
    assert a["finding_id"] != b["finding_id"]
    assert a["external_id"] == a["finding_id"]  # (data_source, external_id) dedup key
    assert (
        len(loadgen.make_finding(alerts[0], "deadbeef", 9_999_999)["finding_id"]) <= 50
    )
    assert a["finding_id"].startswith(loadgen.run_prefix("deadbeef"))
    assert "labels" not in a and "meta" not in a
    assert a["raw_event"]["loadtest_run"] == "deadbeef"
    assert alerts[0]["finding_id"] != a["finding_id"]  # the corpus copy is untouched
    crit = dict(alerts[0], severity="critical")
    r = loadgen.make_finding(crit, "deadbeef", 3, rules=True)
    assert r["data_source"] == loadgen.RULES_SOURCE and r["severity"] == "high"


class _Webhook(BaseHTTPRequestHandler):
    """503 with Retry-After for the first ``busy`` requests, then 200."""

    def log_message(self, *a):
        pass

    def do_POST(self):
        srv = self.server
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        srv.bodies.append(body)
        if self.headers.get("Authorization") != "Bearer tok":
            code, payload = 401, {"error": "unauthorized"}
        elif len(srv.bodies) <= srv.busy:
            code, payload = 503, {"error": "busy", "ingested": 0}
        else:
            n = len(body) if isinstance(body, list) else 1
            code, payload = 200, {"status": "ok", "ingested": n}
        data = json.dumps(payload).encode()
        self.send_response(code)
        if code == 503:
            self.send_header("Retry-After", "0")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def webhook():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Webhook)
    srv.bodies, srv.busy = [], 2
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def test_run_load_retries_busy_and_accounts(webhook):
    url = f"http://127.0.0.1:{webhook.server_address[1]}/webhook"
    alerts = loadgen.load_corpus(loadgen.DEFAULT_CORPUS, limit=4)
    profile = loadgen.Profile(rate=20, duration=0.5, batch_size=2)
    log = asyncio.run(
        loadgen.run_load(
            profile, loadgen.Target(webhooks=[url], webhook_token="tok"), alerts, "u1"
        )
    )
    assert len(log.sent_ids()) == 10
    assert sorted(log.accepted_ids()) == sorted(log.sent_ids())
    assert any(s.attempts > 1 for s in log.sends)  # the 503s were retried
    assert all(isinstance(b, list) and len(b) == 2 for b in webhook.bodies)
    summary = log.summary()
    assert summary["findings_accepted"] == 10 and summary["retried_requests"] >= 1


def test_run_load_fails_over_to_next_webhook(webhook):
    dead = "http://127.0.0.1:9/webhook"  # discard port: connection refused
    live = f"http://127.0.0.1:{webhook.server_address[1]}/webhook"
    webhook.busy = 0
    log = asyncio.run(
        loadgen.run_load(
            loadgen.Profile(rate=4, duration=0.5),
            loadgen.Target(webhooks=[dead, live], webhook_token="tok"),
            loadgen.load_corpus(loadgen.DEFAULT_CORPUS, limit=2),
            "u2",
            max_retry=10,
        )
    )
    assert len(log.accepted_ids()) == 2


def test_run_load_gives_up_on_client_errors(webhook):
    url = f"http://127.0.0.1:{webhook.server_address[1]}/webhook"
    log = asyncio.run(
        loadgen.run_load(
            loadgen.Profile(rate=2, duration=0.5),
            loadgen.Target(webhooks=[url], webhook_token="wrong"),
            loadgen.load_corpus(loadgen.DEFAULT_CORPUS, limit=1),
            "u3",
        )
    )
    assert log.accepted_ids() == [] and log.sends[0].status == 401


def test_run_load_requires_api_credentials_for_api_sends():
    with pytest.raises(ValueError):
        asyncio.run(
            loadgen.run_load(
                loadgen.Profile(rate=1, duration=1, api_fraction=0.5),
                loadgen.Target(webhooks=["http://127.0.0.1:9/w"]),
                [{}],
                "u4",
            )
        )


# -- faulty model stub -------------------------------------------------------


def test_faulty_llm_modes():
    llm = FaultyLLM().start()
    try:
        url = f"{llm.url}/v1/chat/completions"
        body = {"model": "m", "messages": [{"role": "user", "content": "x"}]}
        assert httpx.post(url, json=body, timeout=5).status_code == 200
        llm.set_mode("error")
        assert httpx.post(url, json=body, timeout=5).status_code == 503
        assert httpx.get(f"{llm.url}/health", timeout=5).status_code == 200
        llm.set_mode("hang", hang_seconds=2)
        with pytest.raises(httpx.TimeoutException):
            httpx.post(url, json=body, timeout=0.5)
        llm.set_mode("slow", delay_seconds=0.3)
        t0 = time.monotonic()
        assert httpx.post(url, json=body, timeout=5).status_code == 200
        assert time.monotonic() - t0 >= 0.3
        assert llm.counts["error"] == 1 and llm.counts["slow"] == 1
        with pytest.raises(ValueError):
            llm.set_mode("broken")
    finally:
        llm.set_mode("ok")
        llm.stop()


# -- chaos plumbing ----------------------------------------------------------


def test_catalogue_names_and_actions():
    cat = chaos.scenarios()
    assert set(cat) == {
        "llm_outage",
        "llm_timeout",
        "pg_restart",
        "redis_restart",
        "daemon_kill",
        "daemon_kill_standby",
        "slow_vendor",
    }
    for s in cat.values():
        assert set(s.needs()) <= set(chaos.ACTIONS), s.name
        assert s.recovery_bound > 0


def test_recovery_bound_override(monkeypatch):
    monkeypatch.setenv("CHAOS_RECOVERY_PG_RESTART", "42")
    assert chaos.scenarios()["pg_restart"].recovery_bound == 42


def test_staging_target_runs_commands_and_skips_unset(tmp_path):
    marker = tmp_path / "ran"
    t = chaos.StagingTarget(
        env={
            "PATH": "/usr/bin:/bin",
            "LOADTEST_WEBHOOK_URLS": "http://a/webhook, http://b/webhook",
            "DAEMON_WEBHOOK_TOKEN": "t",
            "LOADTEST_DB_URL": "postgresql://x",
            "CHAOS_CMD_PG_STOP": f"touch {marker}",
            "CHAOS_CMD_PG_START": "exit 3",
        }
    )
    assert t.missing() == []
    assert t.info.webhooks == ["http://a/webhook", "http://b/webhook"]
    assert t.supports("pg_stop") is None
    assert "CHAOS_CMD_REDIS_STOP" in t.supports("redis_stop")
    t.do("pg_stop")
    assert marker.exists()
    with pytest.raises(RuntimeError, match="exited 3"):
        t.do("pg_start")
    with pytest.raises(chaos.Unsupported):
        t.do("redis_stop")
    assert set(chaos.StagingTarget(env={}).missing()) == {
        "LOADTEST_WEBHOOK_URLS",
        "DAEMON_WEBHOOK_TOKEN",
        "LOADTEST_DB_URL",
    }


def test_unsupported_scenario_is_skipped_not_faked():
    t = chaos.StagingTarget(
        env={
            "LOADTEST_WEBHOOK_URLS": "http://a",
            "DAEMON_WEBHOOK_TOKEN": "t",
            "LOADTEST_DB_URL": "postgresql://x",
        }
    )
    res = chaos.run_scenario(t, chaos.scenarios()["redis_restart"])
    assert res.status == "SKIP"
    assert any("CHAOS_CMD_REDIS_STOP" in r for r in res.reasons)


def _obs(rows, sends, samples, inject=10.0, heal=20.0):
    log = loadgen.ClientLog(sends=sends)
    return chaos.Observation(
        rows=rows, log=log, window=chaos.Window(inject, heal), samples=samples
    )


def test_rules_lane_check():
    send = loadgen.SendRecord(ids=["a", "b"], path="webhook", scheduled=0, first_try=12)
    ok = [
        _row("a", 12, lane="rules", decided=12.5),
        _row("b", 12, lane="small_model", decided=12.5),
    ]
    assert chaos.check_rules_lane_survives(_obs(ok, [send], [])) is None
    late = [_row("a", 12, lane="rules", decided=40)]
    assert "waited" in chaos.check_rules_lane_survives(_obs(late, [send], []))
    none = [_row("b", 12, lane="small_model", decided=12.5)]
    assert "no rules-lane" in chaos.check_rules_lane_survives(_obs(none, [send], []))


def test_backlog_check():
    grow = [measure.Backlog(5, 3, 3), measure.Backlog(15, 10, 4)]
    flat = [measure.Backlog(5, 3, 1), measure.Backlog(15, 5, 3)]
    assert chaos.check_backlog_grows(_obs([], [], grow)) is None
    assert "did not grow" in chaos.check_backlog_grows(_obs([], [], flat))


def test_ingest_not_blocked_check():
    fast = loadgen.SendRecord(ids=["a"], path="webhook", scheduled=0, first_try=11)
    fast.accepted_at = 11.1
    slow = loadgen.SendRecord(ids=["b"], path="webhook", scheduled=0, first_try=12)
    slow.accepted_at = 19.0
    assert chaos.check_ingest_not_blocked(_obs([], [fast], [])) is None
    assert "accept p95" in chaos.check_ingest_not_blocked(_obs([], [fast, slow], []))


def test_render_table():
    r = chaos.ScenarioResult("pg_restart", "local", "PASS", recovery_bound=240)
    r.accounting = {"sent": 3, "accepted": 3, "stored": 3, "lost": 0}
    assert "| pg_restart | local | PASS | 3/3/3 | 0 |" in chaos.render([r])
