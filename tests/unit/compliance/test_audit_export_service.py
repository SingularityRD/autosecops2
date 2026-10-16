"""The export service: off by default, auth events, lifecycle, admin API (WP w3.6)."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Optional

import contextlib

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from core.compliance import audit_export
from core.compliance import audit_export_router as api
from core.compliance.audit_export import (
    AuditExportConfig,
    AuditExportService,
    ConfigStore,
    record_auth_event,
    secret_name,
)
from core.storage.models import CaseAuditLog

from .conftest import HttpReceiver

pytestmark = pytest.mark.unit


class MemoryConfigStore(ConfigStore):
    def __init__(self, value: Optional[dict] = None) -> None:
        self.value = value
        self.saved_by: list[str] = []

    def load(self):
        return self.value

    def save(self, value, actor):
        self.value = value
        self.saved_by.append(actor)


class CountingLeader:
    def __init__(self) -> None:
        self.held = False
        self.acquires = 0

    def acquire(self):
        self.acquires += 1
        self.held = True
        return True

    def alive(self):
        return self.held

    def release(self):
        self.held = False


@pytest.fixture
def recorded(monkeypatch):
    """Auth records handed to the database writer (no database here)."""
    seen: list[dict] = []

    def persist(record, session=None):
        seen.append(record)
        return True

    monkeypatch.setattr(audit_export, "persist_auth_record", persist)
    return seen


def _sqlite_scope():
    engine = create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )
    CaseAuditLog.__table__.create(engine)

    @contextlib.contextmanager
    def scope():
        with Session(engine) as session:
            yield session
            session.commit()

    return scope


def _service(
    tmp_path, store, secrets=None, leader=None, session_scope=None
) -> AuditExportService:
    return AuditExportService(
        state_dir=tmp_path / "audit_export",
        config_store=store,
        secrets=(secrets or {}).get,
        session_scope=session_scope,
        leader=leader or CountingLeader(),
        host="soc-test",
        refresh_s=0.05,
    )


def _request(service, ip="198.51.100.4", ua="pytest-agent"):
    return SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(audit_export=service)),
        client=SimpleNamespace(host=ip),
        headers={"user-agent": ua},
    )


async def _until(pred, timeout=10.0):
    async def loop():
        while not pred():
            await asyncio.sleep(0.02)

    await asyncio.wait_for(loop(), timeout)


async def test_disabled_by_default_has_no_side_effects(tmp_path, recorded):
    leader = CountingLeader()
    svc = _service(tmp_path, MemoryConfigStore(None), leader=leader)
    await svc.start()
    try:
        await svc.tick()
        await asyncio.sleep(0.15)  # a few supervisor rounds
        assert svc.config.enabled is False
        assert record_auth_event(_request(svc), "login", actor="alice") is True
        status = svc.status()
    finally:
        await svc.stop()
    assert not (tmp_path / "audit_export").exists()
    assert leader.acquires == 0
    assert svc.pipelines == {}
    assert status["enabled"] is False and status["destinations"] == []
    assert "spool" not in status
    assert AuditExportConfig().enabled is False
    # Export off, the event is still recorded (W0.35, K1): in the database.
    (record,) = recorded
    assert record["action"] == "login" and record["actor"] == "alice"
    assert record["src_ip"] == "198.51.100.4"


def test_record_auth_event_is_recorded_without_a_request_or_service(recorded):
    record_auth_event(None, "login")
    record_auth_event(
        SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace()), client=None, headers={}
        ),
        "logout",
    )
    assert [r["action"] for r in recorded] == ["login", "logout"]
    assert recorded[0]["src_ip"] is None


def test_record_auth_event_never_raises(recorded):
    # A request object it cannot read is logged, not raised.
    assert record_auth_event(object(), "login") is False
    assert recorded == []


async def test_enabled_auth_events_reach_an_http_receiver(tmp_path):
    rx = HttpReceiver().start()
    store = MemoryConfigStore(
        {
            "enabled": True,
            "start_from": "beginning",
            "poll_interval_s": 0.05,
            "sources": {
                "agent_events": False,
                "approvals": False,
                "config": False,
                "case_audit": False,
                "auth": True,
            },
            "destinations": [
                {
                    "type": "http",
                    "name": "hec",
                    "url": f"http://127.0.0.1:{rx.port}/in",
                    "allow_plaintext": True,
                }
            ],
        }
    )
    leader = CountingLeader()
    scope = _sqlite_scope()
    svc = _service(
        tmp_path,
        store,
        secrets={secret_name("hec", "TOKEN"): "t0k"},
        leader=leader,
        session_scope=scope,
    )
    store.value["settle_s"] = 0
    await svc.start()
    try:
        await svc.tick()
        assert svc.is_leader and "hec" in svc.pipelines
        with scope() as session:
            assert record_auth_event(
                _request(svc),
                "login",
                outcome="failure",
                actor="mallory@example.com",
                details={"password": "guess1"},
                session=session,
            )
        await _until(lambda: rx.requests)
        await _until(lambda: svc.pipelines["hec"].metrics.events_sent == 1)
        status = svc.status()
    finally:
        await svc.stop()
        rx.stop()
    body = json.loads(rx.requests[0]["body"])
    assert rx.requests[0]["headers"]["Authorization"] == "Bearer t0k"
    (event,) = body
    assert event["action"] == "auth.login" and event["outcome"] == "failure"
    assert event["src_ip"] == "198.51.100.4"
    assert event["user_agent"] == "pytest-agent"
    assert event["severity"] == 5
    # The actor is the audit trail's subject and is exported as-is, even with
    # redact_pii on (AUDIT_EXPORT.md, "Redaction policy").
    assert event["actor"]["name"] == "mallory@example.com"
    assert event["details"]["password"] == "[REDACTED]"
    assert event["id"].startswith("auth:")
    dest = status["destinations"][0]
    assert dest["running"] and dest["insecure"] == ["plaintext_http"]
    assert dest["metrics"]["events_sent"] == 1
    assert not (tmp_path / "audit_export" / "auth_spool").exists()
    assert not leader.held  # released on stop


async def test_disabling_stops_pipelines_and_releases_leadership(tmp_path):
    rx = HttpReceiver().start()
    cfg = {
        "enabled": True,
        "sources": {
            "agent_events": False,
            "approvals": False,
            "config": False,
            "case_audit": False,
        },
        "destinations": [
            {
                "type": "http",
                "name": "hec",
                "url": f"http://127.0.0.1:{rx.port}/",
                "allow_plaintext": True,
            }
        ],
    }
    store = MemoryConfigStore(cfg)
    leader = CountingLeader()
    svc = _service(tmp_path, store, leader=leader)
    try:
        await svc.tick()
        assert svc.pipelines and leader.held
        store.value = dict(cfg, enabled=False)
        await svc.tick()
        assert svc.pipelines == {} and not leader.held
    finally:
        await svc.stop()
        rx.stop()


async def test_a_config_change_restarts_pipelines(tmp_path):
    base = {
        "enabled": True,
        "sources": {
            "agent_events": False,
            "approvals": False,
            "config": False,
            "case_audit": False,
        },
        "destinations": [
            {
                "type": "syslog",
                "name": "a",
                "host": "127.0.0.1",
                "port": 9,
                "protocol": "udp",
            }
        ],
    }
    store = MemoryConfigStore(base)
    svc = _service(tmp_path, store)
    try:
        await svc.tick()
        first = svc.pipelines["a"]
        await svc.tick()
        assert svc.pipelines["a"] is first  # unchanged config: kept
        store.value = dict(base, batch_size=7)
        await svc.tick()
        assert svc.pipelines["a"] is not first
        assert not first.running
    finally:
        await svc.stop()


async def test_test_destination_reports_without_raising(tmp_path):
    rx = HttpReceiver(statuses=[500]).start()
    store = MemoryConfigStore()
    svc = _service(tmp_path, store)
    svc.save_config(
        AuditExportConfig.model_validate(
            {
                "destinations": [
                    {
                        "type": "http",
                        "name": "hec",
                        "url": f"http://127.0.0.1:{rx.port}/",
                        "allow_plaintext": True,
                    }
                ]
            }
        ),
        actor="admin",
    )
    try:
        assert await svc.test_destination("nope") == {
            "ok": False,
            "error": "unknown_destination",
        }
        failed = await svc.test_destination("hec")
        ok = await svc.test_destination("hec")
    finally:
        rx.stop()
    assert failed == {"ok": False, "error": "http_500"}
    assert ok["ok"] is True
    assert json.loads(rx.requests[0]["body"])[0]["action"] == "audit_export.test"
    assert not (tmp_path / "audit_export").exists()  # a test send writes no state


# -- admin router (permission gating is covered in tests/security) ---------


@pytest.fixture
def secret_box(monkeypatch):
    box: dict[str, str] = {}
    monkeypatch.setattr(api, "get_secret", lambda k, d=None: box.get(k, d))
    monkeypatch.setattr(api, "set_secret", lambda k, v: box.__setitem__(k, v) or True)
    monkeypatch.setattr(api, "delete_secret", lambda k: box.pop(k, None) is not None)
    return box


def _admin():
    return SimpleNamespace(username="admin", user_id="u-admin")


def test_put_config_stores_secrets_write_only(tmp_path, secret_box):
    store = MemoryConfigStore()
    svc = _service(tmp_path, store)
    req = _request(svc)
    body = api.ConfigUpdate(
        config={
            "enabled": True,
            "destinations": [
                {"type": "http", "name": "splunk", "url": "https://siem.example/"}
            ],
        },
        secrets={"splunk": api.DestinationSecrets(token="s3cret")},
    )
    view = api.put_config(body, req, _admin())
    assert secret_box == {"AUDIT_EXPORT_SPLUNK_TOKEN": "s3cret"}
    assert store.saved_by == ["admin"]
    assert "s3cret" not in json.dumps(view) and "s3cret" not in json.dumps(store.value)
    assert view["destinations"][0]["has_token"] is True
    assert view["destinations"][0]["has_client_key"] is False
    assert api.get_config(req)["enabled"] is True

    clear = api.ConfigUpdate(
        config=store.value, secrets={"splunk": api.DestinationSecrets(clear_token=True)}
    )
    api.put_config(clear, req, _admin())
    assert secret_box == {}


def test_put_config_refuses_invalid_config_and_unknown_secret_targets(
    tmp_path, secret_box
):
    svc = _service(tmp_path, MemoryConfigStore())
    req = _request(svc)
    with pytest.raises(HTTPException) as exc:
        api.put_config(
            api.ConfigUpdate(config={"enabled": True, "surprise": 1}), req, _admin()
        )
    assert exc.value.status_code == 422
    with pytest.raises(HTTPException) as exc:
        api.put_config(
            api.ConfigUpdate(
                config={},
                secrets={"llm": api.DestinationSecrets(token="steal-me")},
            ),
            req,
            _admin(),
        )
    assert exc.value.status_code == 422
    assert secret_box == {}


def test_service_absent_is_503():
    req = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))
    with pytest.raises(HTTPException) as exc:
        api.get_status(req)
    assert exc.value.status_code == 503
