"""FortiGate block_ip / unblock_ip executor against an in-memory FortiOS (W0.57)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Optional
from urllib.parse import unquote

import pytest

from core.integrations.fortinet import client as fclient
from core.integrations.fortinet.client import FortiApiError, FortiConnection
from core.integrations.fortinet.executor import (
    BLOCK_IP,
    UNBLOCK_IP,
    FortiGateExecutor,
    build_executor,
)
from core.response.executors.base import ExecResult, TypedAction

pytestmark = pytest.mark.unit

TOKEN = "tok-secret-123"


class FakeFortiGate:
    """Just enough of FortiOS CMDB: addresses, address groups, member tables."""

    def __init__(self, groups=("autosecops-block", "autosecops-block6")):
        self.addresses: dict[str, dict[str, Any]] = {}
        self.groups: dict[str, list[str]] = {g: ["placeholder"] for g in groups}
        self.calls: list[tuple[str, str]] = []
        self.fail_next: Optional[FortiApiError] = None

    def call(self, method, path, body=None, **_):
        self.calls.append((method, path))
        if self.fail_next is not None:
            err, self.fail_next = self.fail_next, None
            raise err
        parts = [unquote(p) for p in path.split("/")]
        table = "/".join(parts[:3])
        if table in ("cmdb/firewall/address", "cmdb/firewall/address6"):
            if method == "POST":
                if body["name"] in self.addresses:
                    raise FortiApiError("exists", status_code=500, code=-5)
                self.addresses[body["name"]] = dict(body)
                return {"status": "success"}
            name = parts[3]
            if name not in self.addresses:
                raise FortiApiError("not found", status_code=404, code=-3)
            if method == "DELETE":
                del self.addresses[name]
            return {"status": "success", "results": [self.addresses.get(name, {})]}
        if table in ("cmdb/firewall/addrgrp", "cmdb/firewall/addrgrp6"):
            group = parts[3]
            if group not in self.groups:
                raise FortiApiError("not found", status_code=404, code=-3)
            members = self.groups[group]
            if len(parts) == 4 and method == "GET":
                return {
                    "status": "success",
                    "results": [
                        {"name": group, "member": [{"name": m} for m in members]}
                    ],
                }
            if parts[4] == "member" and method == "POST":
                if body["name"] in members:
                    raise FortiApiError("exists", status_code=500, code=-5)
                if body["name"] not in self.addresses:
                    raise FortiApiError("no such address", status_code=500, code=-3)
                members.append(body["name"])
                return {"status": "success"}
            if parts[4] == "member" and method == "DELETE":
                if parts[5] not in members:
                    raise FortiApiError("not found", status_code=404, code=-3)
                members.remove(parts[5])
                return {"status": "success"}
        raise AssertionError(f"unexpected call {method} {path}")


@pytest.fixture()
def fgt():
    return FakeFortiGate()


@pytest.fixture()
def executor(fgt, monkeypatch):
    conn = FortiConnection(base_url="https://192.0.2.10", api_token=TOKEN)
    monkeypatch.setattr(
        FortiConnection, "call", lambda self, *a, **k: fgt.call(*a, **k)
    )
    return FortiGateExecutor(conn, protected_cidrs=())


def act(kind=BLOCK_IP, target="8.8.4.4", **kw):
    return TypedAction(action_type=kind, target=target, **kw)


def test_block_adds_the_address_to_the_group_and_verifies(executor, fgt):
    result = executor.execute(act())
    assert result.status == "executed"
    assert "autosecops-8.8.4.4" in fgt.groups["autosecops-block"]
    assert fgt.addresses["autosecops-8.8.4.4"]["subnet"] == "8.8.4.4/32"
    assert result.before_state["member"] is False
    assert result.after_state["member"] is True
    assert executor.verify(act(), result).status == "verified"
    # placeholder member an operator put there is never touched
    assert "placeholder" in fgt.groups["autosecops-block"]


def test_block_twice_is_a_noop_without_writes(executor, fgt):
    executor.execute(act())
    writes = len([c for c in fgt.calls if c[0] != "GET"])
    result = executor.execute(act())
    assert result.status == "noop"
    assert len([c for c in fgt.calls if c[0] != "GET"]) == writes


def test_reverse_of_a_block_removes_member_and_object(executor, fgt):
    result = executor.execute(act())
    undo = executor.reverse(act(), result)
    assert undo.status == "executed"
    assert "autosecops-8.8.4.4" not in fgt.groups["autosecops-block"]
    assert "autosecops-8.8.4.4" not in fgt.addresses
    assert executor.verify(act(reverse_of="a1"), undo).status == "verified"


def test_reverse_of_a_noop_changes_nothing(executor, fgt):
    executor.execute(act())
    noop = executor.execute(act())
    assert executor.reverse(act(), noop).status == "noop"
    assert "autosecops-8.8.4.4" in fgt.groups["autosecops-block"]


def test_unblock_and_its_reverse(executor, fgt):
    executor.execute(act())
    result = executor.execute(act(UNBLOCK_IP))
    assert result.status == "executed"
    assert "autosecops-8.8.4.4" not in fgt.groups["autosecops-block"]
    again = executor.reverse(act(UNBLOCK_IP), result)
    assert again.status == "executed"
    assert "autosecops-8.8.4.4" in fgt.groups["autosecops-block"]


def test_ipv6_uses_the_v6_tables(executor, fgt):
    result = executor.execute(act(target="2001:4860::8888"))
    assert result.status == "executed"
    name = "autosecops-2001-4860--8888"
    assert name in fgt.groups["autosecops-block6"]
    assert fgt.addresses[name]["ip6"] == "2001:4860::8888/128"


@pytest.mark.parametrize(
    "target, reason",
    [
        ("10.0.0.0/24", "range"),
        ("127.0.0.1", "loopback"),
        ("10.1.2.3", "private"),
        ("192.0.2.10", "protected"),
        ("not-an-ip", "not an IP"),
        ("::ffff:8.8.4.5", "IPv4-mapped"),
    ],
)
def test_validate_refuses_without_calling_the_firewall(executor, fgt, target, reason):
    policy = executor.validate(act(target=target))
    assert not policy.allowed
    assert reason in " ".join(policy.reasons)
    assert executor.execute(act(target=target)).status == "failed"
    assert fgt.calls == []


def test_ttl_over_thirty_days_is_refused(executor):
    assert not executor.validate(act(ttl=timedelta(days=31))).allowed


def test_allowed_internal_range_needs_a_human(fgt, monkeypatch):
    import ipaddress

    conn = FortiConnection(base_url="https://fw.example", api_token=TOKEN)
    monkeypatch.setattr(
        FortiConnection, "call", lambda self, *a, **k: fgt.call(*a, **k)
    )
    ex = FortiGateExecutor(
        conn, allowed_internal_cidrs=[ipaddress.ip_network("10.9.0.0/16")]
    )
    policy = ex.validate(act(target="10.9.1.1"))
    assert policy.allowed and policy.requires_approval


def test_missing_group_fails_with_a_setup_hint(fgt, executor):
    del fgt.groups["autosecops-block"]
    result = executor.execute(act())
    assert result.status == "failed"
    assert "create address group autosecops-block" in result.message


def test_refused_change_reports_failed_with_before_state(executor, fgt):
    real = fgt.call

    def refuse(method, path, body=None, **k):
        if method == "POST" and path.endswith("/member"):
            raise FortiApiError("HTTP 403: permission denied", status_code=403)
        return real(method, path, body, **k)

    fgt.call = refuse
    result = executor.execute(act())
    assert result.status == "failed" and result.before_state["member"] is False


def test_reverse_of_a_failed_read_is_a_noop(executor):
    failed = ExecResult(status="failed", message="x", error="y")
    assert executor.reverse(act(), failed).status == "noop"


def test_build_executor_needs_host_and_token():
    with pytest.raises(fclient.FortiConfigError):
        build_executor({"hostname": "fw"})
    ex = build_executor({"hostname": "fw.example", "api_token": TOKEN, "vdom": "dmz"})
    assert ex.connection.vdom == "dmz"
    assert TOKEN not in repr(ex) and TOKEN not in repr(ex.connection)


# --- the HTTP client ---------------------------------------------------------


class _Resp:
    def __init__(self, code, payload):
        self.status_code = code
        self._payload = payload
        self.text = str(payload)

    def json(self):
        return self._payload


def test_client_sends_the_token_as_a_header_and_redacts_errors(monkeypatch):
    seen = {}

    def request(method, url, **kw):
        seen.update(kw, url=url, method=method)
        return _Resp(500, {"status": "error", "error": -5, "cli_error": f"bad {TOKEN}"})

    monkeypatch.setattr(fclient.httpx, "request", request)
    conn = FortiConnection(base_url="https://fw.example", api_token=TOKEN, vdom="v1")
    with pytest.raises(FortiApiError) as err:
        conn.call("POST", "cmdb/firewall/address", {"name": "x"})
    assert err.value.exists and TOKEN not in err.value.message
    assert seen["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert seen["params"] == {"vdom": "v1"}
    assert TOKEN not in seen["url"]


def test_client_retries_only_retryable_answers(monkeypatch):
    answers = [_Resp(503, {}), _Resp(200, {"status": "success", "results": []})]
    monkeypatch.setattr(fclient.httpx, "request", lambda *a, **k: answers.pop(0))
    conn = FortiConnection(base_url="https://fw.example", api_token=TOKEN)
    assert conn.call("GET", "monitor/system/status", attempts=3, sleep=lambda s: None)
    answers = [_Resp(500, {"error": -1}), _Resp(200, {})]
    monkeypatch.setattr(fclient.httpx, "request", lambda *a, **k: answers.pop(0))
    with pytest.raises(FortiApiError):
        conn.call("GET", "monitor/system/status", attempts=3, sleep=lambda s: None)
    assert len(answers) == 1


# --- the registry ------------------------------------------------------------


def test_registry_builds_fortigate_and_palo_alto_wins_a_conflict():
    from core.response.executors.wiring import EXECUTOR_SOURCES, build_executor_registry

    sources = [
        s for s in EXECUTOR_SOURCES if s.integration_id in ("palo-alto", "fortigate")
    ]
    configs = {
        "fortigate": {"hostname": "fgt.example", "api_token": TOKEN},
        "palo-alto": {"hostname": "pan.example", "api_key": "k"},
    }
    only_fgt = build_executor_registry(
        sources, enabled=lambda i: i == "fortigate", config_for=lambda i: configs[i]
    )
    assert type(only_fgt.get(BLOCK_IP)).__name__ == "FortiGateExecutor"
    both = build_executor_registry(
        sources, enabled=lambda i: True, config_for=lambda i: configs[i]
    )
    assert type(both.get(BLOCK_IP)).__name__ == "PaloAltoExecutor"
