"""Cloudflare executor (W2.4) against mocked Cloudflare REST."""

from __future__ import annotations

import logging

import httpx
import pytest
import respx

from core.integrations.cloudflare import client as cf
from core.integrations.cloudflare.executor import CloudflareExecutor, build_executor
from core.response.executors.base import Executor, ExecutorRegistry, TypedAction

pytestmark = pytest.mark.unit

TOKEN = "cf-secret-token-123"
RULES = f"{cf.CF_API_BASE}/accounts/acct/firewall/access_rules/rules"
GATEWAY = f"{cf.CF_API_BASE}/accounts/acct/gateway/rules"


def _executor(enabled=True, cfg=None):
    return CloudflareExecutor(
        settings=lambda: (
            enabled,
            cfg if cfg is not None else {"api_token": TOKEN, "account_id": "acct"},
        )
    )


def _waf(**kw):
    return TypedAction(action_type="waf_block", target="203.0.113.5", **kw)


def test_it_implements_the_protocol_and_declares_its_reversibility():
    ex = build_executor({})
    assert isinstance(ex, Executor)
    registry = ExecutorRegistry()
    registry.register(ex)
    assert registry.reversibility_of("waf_block") == "reversible"
    assert registry.reversibility_of("gateway_block") == "reversible"
    assert registry.reversibility_of("access_revoke") == "irreversible"
    assert ex.default_ttl.total_seconds() == 24 * 3600


@pytest.mark.parametrize(
    "action_type,target",
    [
        ("waf_block", "not-an-ip"),
        ("gateway_block", "bad domain"),
        ("access_revoke", "nobody"),
    ],
)
def test_validate_refuses_a_malformed_target(action_type, target):
    verdict = _executor().validate(
        TypedAction(
            action_type=action_type, target=target, reversibility="irreversible"
        )
    )
    assert not verdict.allowed


def test_access_revoke_always_requires_approval():
    verdict = _executor().validate(
        TypedAction(
            action_type="access_revoke",
            target="eve@example.com",
            reversibility="irreversible",
        )
    )
    assert verdict.allowed and verdict.requires_approval


def test_a_disabled_integration_fails_the_action_as_before():
    out = _executor(enabled=False).execute(_waf())
    assert out.status == "failed"
    assert out.error == "cloudflare_integration_disabled"


def test_a_missing_token_fails_the_action():
    out = _executor(cfg={"account_id": "acct"}).execute(_waf())
    assert out.status == "failed"
    assert "api_token" in out.error


@respx.mock
def test_waf_block_executes_verifies_reverses_and_verifies_the_reverse():
    ex = _executor()
    respx.post(RULES).mock(
        return_value=httpx.Response(
            200, json={"success": True, "result": {"id": "r-1"}}
        )
    )
    get = respx.get(f"{RULES}/r-1")
    get.mock(
        return_value=httpx.Response(
            200, json={"success": True, "result": {"id": "r-1"}}
        )
    )
    delete = respx.delete(f"{RULES}/r-1").mock(return_value=httpx.Response(204))

    action = _waf(action_id="a-1", parameters={"reason": "c2"})
    result = ex.execute(action)
    assert result.status == "executed"
    assert result.external_ref == "r-1"
    assert result.before_state == {"rule_present": False, "rule_id": None}
    assert result.after_state == {"rule_present": True, "rule_id": "r-1"}
    assert ex.verify(action, result).status == "verified"

    undo = _waf(action_id="a-1-rev", reverse_of="a-1", parameters={"reason": "c2"})
    reversed_ = ex.reverse(undo, result)
    assert reversed_.status == "executed"
    assert delete.called

    get.mock(return_value=httpx.Response(404, json={"success": False}))
    assert ex.verify(undo, reversed_).status == "verified"


@respx.mock
def test_a_rule_still_present_after_reverse_fails_verify():
    ex = _executor()
    respx.get(f"{RULES}/r-1").mock(
        return_value=httpx.Response(
            200, json={"success": True, "result": {"id": "r-1"}}
        )
    )
    undo = _waf(reverse_of="a-1")
    from core.response.executors.base import ExecResult

    assert (
        ex.verify(undo, ExecResult(status="executed", external_ref="r-1")).status
        == "failed"
    )


@respx.mock
def test_a_duplicate_waf_rule_is_a_noop_and_its_reverse_touches_nothing():
    ex = _executor()
    respx.post(RULES).mock(
        return_value=httpx.Response(
            400,
            json={
                "success": False,
                "errors": [{"code": 10009, "message": "duplicate_of_existing"}],
            },
        )
    )
    delete = respx.delete(url__startswith=RULES)
    result = ex.execute(_waf())
    assert result.status == "noop"
    undo = ex.reverse(_waf(reverse_of="a-1"), result)
    assert undo.status == "noop"
    assert not delete.called


@respx.mock
def test_gateway_block_reverse_deletes_the_rule():
    ex = _executor()
    respx.post(GATEWAY).mock(
        return_value=httpx.Response(
            200, json={"success": True, "result": {"id": "g-1"}}
        )
    )
    delete = respx.delete(f"{GATEWAY}/g-1").mock(
        return_value=httpx.Response(200, json={"success": True})
    )
    action = TypedAction(action_type="gateway_block", target="evil.example")
    result = ex.execute(action)
    assert result.external_ref == "g-1"
    assert ex.reverse(action.model_copy(update={"reverse_of": "a-1"}), result).ok
    assert delete.called


@respx.mock
def test_access_revoke_is_irreversible_and_unverifiable():
    ex = _executor()
    respx.post(f"{cf.CF_API_BASE}/accounts/acct/access/organizations/revoke_user").mock(
        return_value=httpx.Response(200, json={"success": True})
    )
    action = TypedAction(
        action_type="access_revoke",
        target="eve@example.com",
        reversibility="irreversible",
    )
    result = ex.execute(action)
    assert result.status == "executed"
    assert ex.verify(action, result).status == "unknown"
    assert ex.reverse(action, result).status == "failed"


@respx.mock
def test_an_http_error_fails_without_leaking_the_token(caplog):
    ex = _executor()
    respx.post(RULES).mock(side_effect=httpx.ConnectError("boom"))
    with caplog.at_level(logging.DEBUG):
        result = ex.execute(_waf())
    assert result.status == "failed"
    assert TOKEN not in (result.error or "")
    assert TOKEN not in caplog.text


@respx.mock
def test_a_cloudflare_error_status_is_a_failure_with_the_reason():
    ex = _executor()
    respx.post(RULES).mock(
        return_value=httpx.Response(
            403,
            json={
                "success": False,
                "errors": [{"code": 10000, "message": "Authentication error"}],
            },
        )
    )
    result = ex.execute(_waf())
    assert result.status == "failed"
    assert "403" in result.error and "Authentication error" in result.error
