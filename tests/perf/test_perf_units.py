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


# -- Round 5 fixes (verifier findings) ---------------------------------------


def test_double_processing_is_a_decision_after_the_verdict():
    # Settled by triage at 120, routed again at 150: processed twice.
    twice = _row("a", 100, lane="small_model", decided=101, triage=120, decisions=2)
    twice.last_decided_epoch = 150.0
    # Re-routed while the first triage was in flight (at-least-once): not double.
    inflight = _row("b", 100, lane="small_model", decided=101, triage=120, decisions=2)
    inflight.last_decided_epoch = 110.0
    # A rules finding decided by a rule twice, 30 s apart.
    rules = _row("c", 100, lane="rules", decided=101, decisions=2)
    rules.last_decided_epoch = 131.0
    # Within the clock slack.
    close = _row("d", 100, lane="rules", decided=101, decisions=2)
    close.last_decided_epoch = 102.0
    acc = measure.account(
        ["a", "b", "c", "d"], ["a", "b", "c", "d"], [twice, inflight, rules, close]
    )
    assert acc.double_processed == ["a", "c"]
    assert acc.re_decided == 4
    assert acc.duplicate_rows == 0  # the PK check alone cannot see this


def test_first_triage_time_survives_a_retriage():
    ft = measure.FirstTriage()
    first = ft.apply([_row("a", 100, lane="small_model", decided=101, triage=120)])
    assert first[0].triage_epoch == 120 and not first[0].retriaged
    # The backfill re-triaged it: the stored timestamp moved to 300.
    later = ft.apply([_row("a", 100, lane="small_model", decided=101, triage=300)])
    assert later[0].triage_epoch == 120 and later[0].retriaged
    assert measure.verdict_epoch(later[0]) == 120
    acc = measure.account(["a"], ["a"], later)
    assert acc.retriaged == 1


def test_wait_settled_keeps_first_triage_across_polls():
    seq = iter([120.0, 300.0])

    def fetch(_engine, _prefix):
        return [_row("a", 100, lane="small_model", decided=101, triage=next(seq))]

    ft = measure.FirstTriage()
    rows = measure.wait_settled(
        None, "p", ["x"], timeout=0.05, poll=0.01, fetch=fetch, first_triage=ft
    )
    assert rows[0].triage_epoch == 120.0 and rows[0].retriaged


class _Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, d):
        self.t += d


def test_wait_takeover_measures_the_change_of_holder():
    clock = _Clock()
    holders = iter(["lock:A", None, None, "lock:B"])
    took, who = chaos.wait_takeover(
        None,
        "lock:A",
        10,
        holder=lambda _e: next(holders),
        poll=0.5,
        clock=clock,
        sleep=clock.sleep,
    )
    assert (took, who) == (1.5, "lock:B")


def test_wait_takeover_times_out_and_needs_health_confirmation():
    clock = _Clock()
    took, who = chaos.wait_takeover(
        None,
        "lock:A",
        2,
        holder=lambda _e: "lock:A",
        poll=0.5,
        clock=clock,
        sleep=clock.sleep,
    )
    assert took is None and who == "lock:A"
    clock = _Clock()
    confirms = iter([None, None, "daemon1"])
    took, who = chaos.wait_takeover(
        None,
        "lock:A",
        10,
        holder=lambda _e: "lock:B",
        confirm=lambda: next(confirms),
        poll=1,
        clock=clock,
        sleep=clock.sleep,
    )
    assert (took, who) == (2.0, "lock:B")


class _FakeEngine:
    def connect(self):
        raise RuntimeError("no database in unit tests")

    def dispose(self):
        pass


class _FakeTarget:
    name = "fake"

    def __init__(self, holders, rows_after_heal=None):
        self.info = chaos.TargetInfo(
            webhooks=["http://x"], webhook_token="t", db_url="x"
        )
        self.calls = []
        self.holders = holders

    def supports(self, action):
        return None

    def do(self, action):
        self.calls.append((action, self.holders.current))
        if action == "leader_kill":
            self.holders.killed = True
        if action == "leader_restart":
            self.holders.restarted = True


class _Holders:
    def __init__(self, new_leader):
        self.new_leader = new_leader
        self.killed = self.restarted = False

    @property
    def current(self):
        if not self.killed:
            return "lock:A"
        return self.new_leader

    def __call__(self, _engine):
        return self.current


def _fake_run(monkeypatch, scenario, target, rows):
    async def fake_load(profile, tgt, alerts, run_id, *, max_retry, log):
        rec = loadgen.SendRecord(
            ids=[r.finding_id for r in rows],
            path="webhook",
            scheduled=0,
            first_try=time.time(),
        )
        rec.accepted_at = rec.first_try
        rec.accepted_ids = list(rec.ids)
        log.sends.append(rec)
        return log

    monkeypatch.setattr(loadgen, "make_engine", lambda url: _FakeEngine())
    monkeypatch.setattr(loadgen, "load_corpus", lambda path: [])
    monkeypatch.setattr(loadgen, "run_load", fake_load)
    monkeypatch.setattr(measure, "wait_settled", lambda *a, **k: rows)
    return chaos.run_scenario(
        target,
        scenario,
        pre=0.0,
        fault=0.05,
        post=0.0,
        seed_rules=False,
        run_id="unit",
        log_event=lambda m: None,
    )


def _settled_rows():
    now = time.time()
    return [_row("lt-unit-1", now, lane="rules", decided=now + 0.1)]


def test_standby_scenario_fails_without_takeover_before_restart(monkeypatch):
    monkeypatch.setenv("CHAOS_TAKEOVER_BOUND", "0.3")
    holders = _Holders(new_leader=None)  # nobody takes the lock
    monkeypatch.setattr(chaos, "leader_holder", holders)
    target = _FakeTarget(holders)
    res = _fake_run(
        monkeypatch, chaos.scenarios()["daemon_kill_standby"], target, _settled_rows()
    )
    assert res.status == "FAIL"
    assert any("no standby took over" in r for r in res.reasons)
    assert res.takeover_seconds is None and res.leader_before == "lock:A"
    # The killed leader was restarted only after the takeover wait gave up.
    assert [a for a, _ in target.calls] == ["leader_kill", "leader_restart"]


def test_standby_scenario_reports_takeover_time(monkeypatch):
    monkeypatch.setenv("CHAOS_TAKEOVER_BOUND", "5")
    holders = _Holders(new_leader="lock:B")
    monkeypatch.setattr(chaos, "leader_holder", holders)
    target = _FakeTarget(holders)
    res = _fake_run(
        monkeypatch, chaos.scenarios()["daemon_kill_standby"], target, _settled_rows()
    )
    assert res.status == "PASS", res.reasons
    assert res.leader_after == "lock:B" and res.takeover_seconds is not None
    assert res.takeover_seconds <= res.takeover_bound == 5
    # The standby held the lock before the old leader came back.
    assert target.calls[-1] == ("leader_restart", "lock:B")
    assert f"{res.takeover_seconds} / 5" in chaos.render([res])


def test_double_processing_fails_the_scenario(monkeypatch):
    now = time.time()
    row = _row("lt-unit-1", now, lane="rules", decided=now + 0.1, decisions=2)
    row.last_decided_epoch = now + 30
    target = _FakeTarget(_Holders("lock:B"))
    res = _fake_run(monkeypatch, chaos.scenarios()["daemon_kill"], target, [row])
    assert res.status == "FAIL"
    assert any("double processing: 1" in r for r in res.reasons)
    assert res.accounting["double_processed"] == 1
    monkeypatch.setenv("CHAOS_MAX_DOUBLE_DAEMON_KILL", "1")
    res = _fake_run(monkeypatch, chaos.scenarios()["daemon_kill"], target, [row])
    assert res.status == "PASS", res.reasons


def test_pg_restart_known_issue_tracks_w012(monkeypatch):
    sc = chaos.scenarios()["pg_restart"]
    assert "W0.12" in sc.known_issue and "lost == 0" in sc.known_issue
    monkeypatch.setattr(chaos, "ingest_durability_merged", lambda: False)
    sc = chaos.scenarios()["pg_restart"]
    assert sc.known_open()
    # The assertion is kept: a loss still FAILs, the result is only labelled.
    now = time.time()
    target = _FakeTarget(_Holders("lock:B"))
    target.info = chaos.TargetInfo(webhooks=["http://x"], webhook_token="t", db_url="x")

    async def lossy(profile, tgt, alerts, run_id, *, max_retry, log):
        rec = loadgen.SendRecord(
            ids=["lt-unit-1", "lt-unit-2"], path="webhook", scheduled=0, first_try=now
        )
        rec.accepted_at, rec.accepted_ids = now, ["lt-unit-1", "lt-unit-2"]
        log.sends.append(rec)

    monkeypatch.setattr(loadgen, "make_engine", lambda url: _FakeEngine())
    monkeypatch.setattr(loadgen, "load_corpus", lambda path: [])
    monkeypatch.setattr(loadgen, "run_load", lossy)
    monkeypatch.setattr(
        measure,
        "wait_settled",
        lambda *a, **k: [_row("lt-unit-1", now, lane="rules", decided=now + 0.1)],
    )
    res = chaos.run_scenario(
        target,
        sc,
        pre=0,
        fault=0.01,
        post=0,
        seed_rules=False,
        log_event=lambda m: None,
    )
    assert res.status == "FAIL" and res.accounting["lost"] == 1
    assert res.known_issue and "KNOWN" in chaos.render([res])
    monkeypatch.setattr(chaos, "ingest_durability_merged", lambda: True)
    assert not chaos.scenarios()["pg_restart"].known_open()


def test_scenario_all_runs_standby_on_its_own_stack_when_supported():
    names = list(chaos.scenarios())
    plan = chaos.plan_local(names, standby=False, no_standby=False, supported=True)
    assert plan == [
        (False, [n for n in names if n != "daemon_kill_standby"]),
        (True, ["daemon_kill_standby"]),
    ]
    assert chaos.plan_local(
        names, standby=False, no_standby=False, supported=False
    ) == [(False, names)]
    assert chaos.plan_local(names, standby=False, no_standby=True, supported=True) == [
        (False, names)
    ]
    assert chaos.plan_local(names, standby=True, no_standby=False, supported=True) == [
        (True, names)
    ]
    assert chaos.plan_local(
        ["pg_restart"], standby=False, no_standby=False, supported=True
    ) == [(False, ["pg_restart"])]
