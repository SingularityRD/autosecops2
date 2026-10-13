"""Verifier findings on W3.6: record forging, egress, dead senders, auth input.

Line breaks in syslog SD and CEF, DNS-rebinding-proof HTTP egress through
``core.platform.url_safety``, a pipeline whose sender died is restarted, the
auth spool's blocking I/O stays off the event loop, and a failed login does
not export what was typed into the username box.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
import socket
import threading
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from core.compliance import audit_export as ae
from core.compliance.audit_export import (
    AuditEvent,
    AuditExportConfig,
    AuditExportService,
    DeliveryError,
    FileCursorStore,
    HttpDestination,
    HttpTransport,
    Pipeline,
    Redactor,
    arecord_auth_event,
    failed_login_fields,
    format_cef,
    format_rfc5424,
    resolve_egress,
)

from .conftest import HttpReceiver
from .test_audit_export_pipeline import FakeTransport, ListSource, _cfg, _until
from .test_audit_export_service import CountingLeader, MemoryConfigStore

pytestmark = pytest.mark.unit

BREAKS = ["\r", "\n", "\r\n", "\u0085", " ", " ", "\x0b", "\x0c"]


def _ev(**kw) -> AuditEvent:
    base = dict(
        id="auth:1",
        source="auth",
        category="authentication",
        action="auth.login",
        outcome="failure",
        severity=5,
        timestamp=datetime(2026, 10, 12, tzinfo=timezone.utc),
        message="login failure",
    )
    base.update(kw)
    return AuditEvent(**base)


def _splits(text: str) -> list[str]:
    """How a receiver that honours every Unicode line break would split it."""
    return text.splitlines()


# -- record forging -----------------------------------------------------------


@pytest.mark.parametrize("brk", BREAKS)
def test_syslog_sd_and_body_hold_no_line_break(brk):
    forged = f"alice{brk}<13>1 2026-01-01T00:00:00Z evil app - - - forged"
    ev = _ev(actor=forged, target_id=forged, message=forged, user_agent=forged)
    for body in ("rfc5424", "cef"):
        msg = format_rfc5424(ev, host="soc", body=body).decode("utf-8")
        assert len(_splits(msg)) == 1, (body, msg)
        sd = msg[msg.index("[autosecops@32473") : msg.index("] ")]
        assert "alice\\" in sd  # escaped, not dropped
    # The JSON body still round-trips to the original value.
    msg = format_rfc5424(ev, host="soc").decode("utf-8")
    assert json.loads(msg.split("﻿", 1)[1])["actor"]["name"] == forged


@pytest.mark.parametrize("brk", BREAKS)
def test_cef_holds_no_line_break(brk):
    ev = _ev(actor=f"a{brk}b", message=f"m{brk}CEF:0|forged|x|1|y|z|10|")
    line = format_cef(ev, "soc")
    assert len(_splits(line)) == 1
    assert "suser=a\\" in line


async def test_http_json_body_holds_no_raw_unicode_line_break():
    tx = HttpTransport(
        HttpDestination(type="http", name="h", url="https://siem.example/"),
        lambda _n: None,
        "soc",
    )
    body, _ = tx.body([_ev(actor="a b c\u0085d")])
    text = body.decode("utf-8")
    assert len(_splits(text)) == 1
    assert json.loads(text)[0]["actor"]["name"] == "a b c\u0085d"


# -- egress -------------------------------------------------------------------


def _fake_dns(monkeypatch, answers, calls=None):
    real = socket.getaddrinfo

    def fake(host, port, *args, **kwargs):
        if calls is not None:
            calls.append(host)
        if host in answers:
            value = answers[host]
            addrs = value.pop(0) if isinstance(value[0], list) else value
            return [
                (
                    socket.AF_INET6 if ":" in a else socket.AF_INET,
                    socket.SOCK_STREAM,
                    6,
                    "",
                    (a, port),
                )
                for a in addrs
            ]
        try:
            socket.inet_pton(socket.AF_INET, host)
        except (OSError, TypeError):
            try:
                socket.inet_pton(socket.AF_INET6, host)
            except (OSError, TypeError):
                raise socket.gaierror(socket.EAI_NONAME, "unknown")
        return real(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake)


@pytest.mark.parametrize(
    "address",
    [
        "169.254.169.254",
        "169.254.170.2",
        "fd00:ec2::254",
        "100.100.100.200",
        "169.254.10.10",
        "fe80::1",
        "224.0.0.1",
        "0.0.0.0",
        "240.0.0.1",
        "::ffff:169.254.169.254",
    ],
)
def test_egress_refuses_metadata_and_reserved_answers(monkeypatch, address):
    _fake_dns(monkeypatch, {"siem.example": [address]})
    with pytest.raises(DeliveryError) as exc:
        resolve_egress("siem.example", 443)
    assert exc.value.reason == "egress_refused"


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.2.3.4", "192.168.1.9", "100.64.1.2", "fd12::5", "93.184.216.34"],
)
def test_egress_allows_where_a_siem_lives(monkeypatch, address):
    _fake_dns(monkeypatch, {"siem.example": [address]})
    assert resolve_egress("siem.example", 443) == [address]


@pytest.mark.parametrize(
    "host", ["100.100.100.200", "[fd00:ec2::254]", "169.254.170.2", "metadata"]
)
def test_metadata_literals_are_refused_at_config_time(host):
    with pytest.raises(ValidationError):
        AuditExportConfig.model_validate(
            {
                "destinations": [
                    {"type": "http", "name": "a", "url": f"https://{host}/x"}
                ]
            }
        )
    with pytest.raises(ValidationError):
        AuditExportConfig.model_validate(
            {
                "destinations": [
                    {"type": "syslog", "name": "a", "host": host.strip("[]")}
                ]
            }
        )


async def test_http_connects_to_the_checked_address_without_resolving_again(
    monkeypatch, pki
):
    """DNS rebinding: the second answer would be the metadata service."""
    rx = HttpReceiver(pki.server_context()).start()
    calls: list[str] = []
    _fake_dns(
        monkeypatch,
        {"localhost": [["127.0.0.1"], ["169.254.169.254"], ["169.254.169.254"]]},
        calls,
    )
    tx = HttpTransport(
        HttpDestination(
            type="http",
            name="h",
            url=f"https://localhost:{rx.port}/ingest?x=1",
            ca_pem=pki.ca_pem,
            timeout_s=5,
        ),
        lambda _n: None,
        "soc",
    )
    try:
        await tx.send([_ev()])
    finally:
        await tx.close()
        rx.stop()
    assert calls.count("localhost") == 1  # resolved once, by the check
    (req,) = rx.requests
    assert req["headers"]["Host"] == f"localhost:{rx.port}"
    assert req["path"] == "/ingest?x=1"


async def test_http_refuses_a_name_that_now_resolves_to_metadata(monkeypatch):
    _fake_dns(monkeypatch, {"siem.example": ["100.100.100.200"]})
    tx = HttpTransport(
        HttpDestination(type="http", name="h", url="https://siem.example/"),
        lambda _n: None,
        "soc",
    )
    try:
        with pytest.raises(DeliveryError) as exc:
            await tx.send([_ev()])
    finally:
        await tx.close()
    assert exc.value.reason == "egress_refused"


# -- a dead sender is noticed and restarted -----------------------------------


class BrokenCursors(FileCursorStore):
    """Commits fail while ``fail`` is set."""

    def __init__(self, path):
        super().__init__(path)
        self.fail = True
        self.failed = 0

    def commit(self, destination, source, cursor):
        if self.fail and cursor.get("id", 0) > 0:
            self.failed += 1
            raise OSError("disk gone")
        super().commit(destination, source, cursor)


def _dying_send_loop(monkeypatch, deaths: list):
    """Every sender dies at once while ``deaths`` is not marked done."""
    real = Pipeline._send_loop

    async def send_loop(self):
        if not deaths or deaths[-1] != "stop":
            deaths.append(1)
            raise RuntimeError("sender bug")
        await real(self)

    monkeypatch.setattr(Pipeline, "_send_loop", send_loop)


async def test_pipeline_running_is_false_when_only_the_sender_died(
    tmp_path, monkeypatch
):
    src = ListSource()
    src.add(3)
    dead: list[bool] = []
    _dying_send_loop(monkeypatch, [])
    p = Pipeline(
        destination="siem",
        transport=FakeTransport(),
        sources=[src],
        cursors=FileCursorStore(tmp_path / "cursors.json"),
        cfg=_cfg(),
        redactor=Redactor(),
        rng=random.Random(1),
        on_dead=lambda: dead.append(True),
    )
    p.start()
    try:
        await _until(lambda: dead)
        reader = [t for t in p._tasks if t.get_name().startswith("audit-read-")][0]
        assert not reader.done()  # the reader alone is still alive...
        assert p.running is False  # ...which is not a running pipeline
        assert p.metrics.last_error == "task_died:send"
    finally:
        await p.stop()


def _svc(tmp_path, monkeypatch, src, tx, **cfg):
    monkeypatch.setattr(ae, "build_transport", lambda dest, secrets, host: tx)
    monkeypatch.setattr(ae, "build_sources", lambda *a, **k: [src])
    store = MemoryConfigStore(
        {
            "enabled": True,
            "start_from": "beginning",
            "poll_interval_s": 0.05,
            "destinations": [
                {"type": "http", "name": "siem", "url": "https://siem.example/"}
            ],
            **cfg,
        }
    )
    return AuditExportService(
        state_dir=tmp_path / "audit_export",
        config_store=store,
        secrets={}.get,
        leader=CountingLeader(),
        host="soc",
        refresh_s=60,  # only the dead-task wake-up can restart it in time
    )


class _RecordingTx(FakeTransport):
    def __init__(self):
        super().__init__()
        self.sent: list[str] = []

    async def send(self, events):
        self.sent.extend(ev.id for ev in events)


async def test_service_restarts_a_pipeline_whose_sender_died(tmp_path, monkeypatch):
    src = ListSource()
    src.add(3)
    deaths: list = []
    _dying_send_loop(monkeypatch, deaths)
    tx = _RecordingTx()
    svc = _svc(tmp_path, monkeypatch, src, tx)
    svc.restart_base_s = 0.05
    await svc.start()
    try:
        await _until(lambda: deaths)
        deaths.append("stop")  # the next start gets a healthy sender
        await _until(lambda: svc.restarts >= 1)
        await _until(lambda: svc.cursors.get("siem", "config") == {"id": 3})
    finally:
        await svc.stop()
    assert set(tx.sent) == {"config:1", "config:2", "config:3"}


async def test_failing_cursor_commit_holds_the_batch_instead_of_resending(
    tmp_path, monkeypatch
):
    """Verifier probe: a cursor commit that always fails used to kill the
    sender, which the supervisor restarted at once, re-reading and re-sending
    the same batch: 1000+ deliveries of 3 events in 3s. Now the sender holds
    and retries only the commit, with backoff, and says so."""
    src = ListSource()
    src.add(3)
    tx = _RecordingTx()
    svc = _svc(tmp_path, monkeypatch, src, tx, max_backoff_s=0.5)
    cursors = BrokenCursors(tmp_path / "audit_export" / "cursors.json")
    svc.cursors = cursors
    await svc.start()
    try:
        await asyncio.sleep(3)
        p = svc.pipelines["siem"]
        assert len(tx.sent) == 3, len(tx.sent)  # delivered exactly once
        assert p.running and svc.restarts == 0
        assert p.metrics.commit_stalled is True
        assert p.metrics.cursor_commit_failures >= 2
        assert p.metrics.last_error == "cursor_commit_failed"
        assert cursors.failed < 30  # backed off, not a tight loop
        status = svc.status()["destinations"][0]["metrics"]
        assert status["commit_stalled"] is True
        cursors.fail = False
        await _until(lambda: cursors.get("siem", "config") == {"id": 3})
        await _until(lambda: not p.metrics.commit_stalled)
    finally:
        await svc.stop()
    assert len(tx.sent) == 3


async def test_a_pipeline_that_dies_on_every_start_is_restarted_with_backoff(
    tmp_path, monkeypatch
):
    src = ListSource()
    src.add(3)
    deaths: list = []
    _dying_send_loop(monkeypatch, deaths)
    svc = _svc(tmp_path, monkeypatch, src, _RecordingTx())
    svc.restart_base_s = 0.1
    await svc.start()
    try:
        await asyncio.sleep(3)
    finally:
        await svc.stop()
    # Unbounded, this was hundreds of restarts. With 0.1s doubling (jittered
    # to half) the gaps sum past 3s within ~7 restarts.
    assert 2 <= svc.restarts <= 8, svc.restarts
    assert len(deaths) == svc.restarts + 1


def test_restart_delay_is_jittered_exponential_and_capped(tmp_path):
    svc = AuditExportService(
        state_dir=tmp_path,
        config_store=MemoryConfigStore(None),
        secrets={}.get,
    )
    svc._rng = random.Random(7)
    cfg = AuditExportConfig(max_backoff_s=30)
    delays = [svc.restart_delay(n, cfg) for n in range(1, 12)]
    for n, d in enumerate(delays, start=1):
        ceiling = min(30.0, 1.0 * 2 ** (n - 1))
        assert ceiling / 2 <= d <= ceiling
    assert max(delays) <= 30


# -- export horizon held by an idle-in-transaction session --------------------


def test_horizon_flags_an_idle_in_transaction_holder(tmp_path):
    svc = AuditExportService(
        state_dir=tmp_path, config_store=MemoryConfigStore(None), secrets={}.get
    )
    holder = {
        "pid": 42,
        "database": "vigil",
        "state": "idle in transaction",
        "xact_age_s": 30.0,
        "state_age_s": 29.0,
    }
    probe = {"xmin": 100, "xmax": 150, "holder": holder}
    h = svc.assess_horizon(probe, 600, now=1000.0)
    assert h["stalled"] is False and h["idle_in_transaction"] is True
    # Same xmin 11 minutes later; the holder is still idle.
    holder = dict(holder, xact_age_s=690.0, state_age_s=689.0)
    h = svc.assess_horizon(dict(probe, holder=holder), 600, now=1660.0)
    assert h["stalled"] is True
    assert h["reason"] == "idle_in_transaction"
    assert h["held_s"] >= 660
    # Without visibility into pg_stat_activity, the stuck xmin alone flags it.
    svc2 = AuditExportService(
        state_dir=tmp_path, config_store=MemoryConfigStore(None), secrets={}.get
    )
    svc2.assess_horizon({"xmin": 5, "xmax": 9, "holder": None}, 600, now=0.0)
    h = svc2.assess_horizon({"xmin": 5, "xmax": 9, "holder": None}, 600, now=601.0)
    assert h["stalled"] is True and h["reason"] == "long_running_transaction"
    # The horizon moves: no longer held.
    h = svc2.assess_horizon({"xmin": 9, "xmax": 9, "holder": None}, 600, now=700.0)
    assert h["stalled"] is False and h["held_s"] == 0


def test_horizon_metrics_are_exported(tmp_path):
    svc = AuditExportService(
        state_dir=tmp_path, config_store=MemoryConfigStore(None), secrets={}.get
    )
    svc.horizon = {"held_s": 700.0, "stalled": True, "reason": "idle_in_transaction"}
    svc.restarts = 3
    metrics = {m.name: m for m in ae._Collector(svc).collect()}
    held = metrics["autosecops_audit_export_xid_horizon_held_seconds"]
    assert held.samples[0].value == 700.0
    stalled = metrics["autosecops_audit_export_xid_horizon_stalled"]
    assert stalled.samples[0].value == 1.0
    assert stalled.samples[0].labels == {"reason": "idle_in_transaction"}
    assert metrics["autosecops_audit_export_pipeline_restarts"].samples[0].value == 3


# -- auth hooks ---------------------------------------------------------------


def _request(service):
    return SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(audit_export=service)),
        client=SimpleNamespace(host="198.51.100.4"),
        headers={"user-agent": "pytest"},
    )


async def test_async_handlers_spool_off_the_event_loop(tmp_path):
    svc = AuditExportService(
        state_dir=tmp_path / "ae",
        config_store=MemoryConfigStore(None),
        secrets={}.get,
    )
    svc._spool_enabled = True
    seen: list[int] = []
    real = svc.spool.append

    def append(record):
        seen.append(threading.get_ident())
        return real(record)

    svc.spool.append = append
    await arecord_auth_event(_request(svc), "logout", actor="alice")
    assert seen and seen[0] != threading.get_ident()
    ((record, _),) = svc.spool.read({"segment": 1, "offset": 0}, 10)
    assert record["action"] == "logout" and record["actor"] == "alice"


async def test_async_hook_is_a_noop_while_export_is_off(tmp_path):
    svc = AuditExportService(
        state_dir=tmp_path / "ae",
        config_store=MemoryConfigStore(None),
        secrets={}.get,
    )
    await arecord_auth_event(_request(svc), "logout", actor="alice")
    await arecord_auth_event(None, "logout")
    assert not (tmp_path / "ae").exists()


class _Query:
    def __init__(self, user):
        self.user = user

    def filter(self, *_a):
        return self

    def first(self):
        return self.user


class _Session:
    def __init__(self, user=None):
        self.user = user

    def query(self, _model):
        return _Query(self.user)


def test_failed_login_for_an_unknown_identifier_exports_only_a_digest(tmp_path):
    svc = AuditExportService(
        state_dir=tmp_path / "ae",
        config_store=MemoryConfigStore(None),
        secrets={}.get,
    )
    typed = "MyP@ssw0rd-typed-in-the-wrong-box"
    fields = failed_login_fields(_request(svc), typed, _Session(None))
    record = ae.auth_record("login", outcome="failure", **fields)
    assert typed not in json.dumps(record)
    assert record["actor"] is None
    details = record["details"]
    assert details["unknown_identifier"] is True
    assert details["identifier_length"] == len(typed)
    # Stable per installation (correlates repeated attempts), keyed (not a
    # bare sha256 anyone can brute-force), and the key is private.
    again = failed_login_fields(_request(svc), typed, _Session(None))
    assert again["details"]["identifier_digest"] == details["identifier_digest"]
    assert hashlib.sha256(typed.encode()).hexdigest()[:24] != (
        details["identifier_digest"]
    )
    assert (tmp_path / "ae" / "identifier.key").stat().st_mode & 0o077 == 0


def test_failed_login_for_a_real_account_names_the_account(tmp_path):
    user = SimpleNamespace(username="alice", user_id="u-1")
    fields = failed_login_fields(_request(None), "alice@example.com", _Session(user))
    assert fields == {"actor": "alice", "actor_id": "u-1"}


def test_failed_login_lookup_errors_fall_back_to_the_digest():
    class Broken:
        def query(self, _m):
            raise RuntimeError("db down")

    fields = failed_login_fields(_request(None), "secret-ish", Broken())
    assert fields["actor"] is None
    assert "secret-ish" not in json.dumps(fields)
