"""Entra ID executor (core/integrations/azure_ad/executor.py) over a mocked Graph."""

from __future__ import annotations

import json
import logging
from datetime import timedelta

import httpx
import pytest
import respx

import core.integrations.azure_ad.tool as aad_tool
from core.integrations.azure_ad import executor as ex
from core.integrations.azure_ad.client import GraphClient, GraphError
from core.response.executors.base import (
    ExecResult,
    Executor,
    ExecutorRegistry,
    TypedAction,
)

pytestmark = pytest.mark.unit

GRAPH = "https://graph.microsoft.com/v1.0"
TOKEN_URL = "https://login.microsoftonline.com/tid/oauth2/v2.0/token"
TOKEN = "eyJ-very-secret-access-token"
SECRET = "s3cret-client-value"
UID = "11111111-2222-3333-4444-555555555555"
UPN = "alice@contoso.test"
CONFIG = {
    "tenant_id": "tid",
    "client_id": "cid",
    "client_secret": SECRET,
    "protected_users": ["breakglass1@contoso.test"],
    "protected_patterns": ["svc-*@contoso.test"],
}
ROLES_URL = f"{GRAPH}/users/{UID}/transitiveMemberOf/microsoft.graph.directoryRole"


def _user(**over):
    user = {
        "id": UID,
        "userPrincipalName": UPN,
        "displayName": "Alice",
        "mail": UPN,
        "userType": "Member",
        "accountEnabled": True,
        "signInSessionsValidFromDateTime": "2026-10-01T00:00:00Z",
        "onPremisesSyncEnabled": None,
    }
    user.update(over)
    return user


def _action(action_type="disable_user", target=UPN, **kw):
    if action_type == "revoke_sessions":
        kw.setdefault("reversibility", "irreversible")
    return TypedAction(action_type=action_type, target=target, **kw)


@pytest.fixture
def sleeps():
    return []


@pytest.fixture
def executor(sleeps):
    return ex.build_executor(CONFIG, sleep=sleeps.append)


@pytest.fixture
def graph():
    """respx router with the token endpoint and an empty role list."""
    with respx.mock(assert_all_called=False) as router:
        router.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": TOKEN})
        )
        router.get(ROLES_URL).mock(return_value=httpx.Response(200, json={"value": []}))
        yield router


def _lookup(graph, *users):
    return graph.get(f"{GRAPH}/users").mock(
        return_value=httpx.Response(200, json={"value": list(users)})
    )


class _UserStore:
    """A tiny stateful stand-in for one Graph user: GET and PATCH by id."""

    def __init__(self, graph, user):
        self.user = dict(user)
        self.patches = []
        graph.get(f"{GRAPH}/users/{UID}").mock(side_effect=self._get)
        graph.patch(f"{GRAPH}/users/{UID}").mock(side_effect=self._patch)
        self.revoke = graph.post(f"{GRAPH}/users/{UID}/revokeSignInSessions").mock(
            side_effect=self._revoke
        )

    def _get(self, request):
        return httpx.Response(200, json=self.user)

    def _patch(self, request):
        body = json.loads(request.content)
        self.patches.append(body)
        self.user.update(body)
        return httpx.Response(204)

    def _revoke(self, request):
        self.user["signInSessionsValidFromDateTime"] = "2026-10-12T09:00:00Z"
        return httpx.Response(200, json={"value": True})


# ------------------------------------------------------------------ protocol


def test_protocol_conformance_and_registry_reversibility(executor):
    assert isinstance(executor, Executor)
    assert executor.action_types == {"disable_user", "enable_user", "revoke_sessions"}
    assert executor.reversible_types == {"disable_user", "enable_user"}
    assert executor.default_ttl is None
    reg = ExecutorRegistry()
    reg.register(executor)
    assert reg.reversibility_of("disable_user") == "reversible"
    assert reg.reversibility_of("revoke_sessions") == "irreversible"


def test_revoke_irreversible_not_reversible(executor, graph):
    assert "revoke_sessions" not in executor.reversible_types
    # Calling it reversible is refused by the executor (and the registry).
    verdict = executor.validate(_action("revoke_sessions", reversibility="reversible"))
    assert not verdict.allowed and "irreversible" in verdict.reasons[0]
    reg = ExecutorRegistry()
    reg.register(executor)
    assert not reg.validate(
        _action("revoke_sessions", reversibility="reversible")
    ).allowed
    # And reverse refuses to undo it.
    out = executor.reverse(
        _action("revoke_sessions"),
        ExecResult(status="executed", before_state=_user(), external_ref=UID),
    )
    assert out.status == "failed" and "irreversible" in out.error


def test_irreversible_revoke_requires_approval(executor, graph):
    _lookup(graph, _user())
    verdict = executor.validate(_action("revoke_sessions"))
    assert verdict.allowed and verdict.requires_approval


def test_build_executor_reports_missing_credentials_without_values():
    with pytest.raises(ex.ExecutorConfigError) as info:
        ex.build_executor({"tenant_id": "tid", "client_secret": SECRET})
    assert "client_id" in str(info.value) and SECRET not in str(info.value)


def test_build_executor_accepts_comma_separated_lists():
    e = ex.build_executor(
        {
            "token_provider": lambda: TOKEN,
            "protected_users": "a@x.test, B@x.test",
            "protected_roles": "Security Administrator",
            "default_ttl_seconds": 3600,
        }
    )
    assert e.protected_users == {"a@x.test", "b@x.test"}
    assert e.protected_roles == {"security administrator"}
    assert e.default_ttl == timedelta(hours=1)


# ------------------------------------------------------------------ validate


def test_validate_allows_a_single_member(executor, graph):
    route = _lookup(graph, _user())
    verdict = executor.validate(_action())
    assert verdict.allowed, verdict.reasons
    params = route.calls.last.request.url.params
    assert params["$filter"] == f"userPrincipalName eq '{UPN}' or mail eq '{UPN}'"
    assert route.calls.last.request.headers["ConsistencyLevel"] == "eventual"


def test_validate_escapes_quotes_in_the_filter(executor, graph):
    route = _lookup(graph, _user(userPrincipalName="o'brien@contoso.test"))
    executor.validate(_action(target="o'brien@contoso.test"))
    assert "'o''brien@contoso.test'" in route.calls.last.request.url.params["$filter"]


def test_validate_by_object_id_reads_the_user(executor, graph):
    graph.get(f"{GRAPH}/users/{UID}").mock(return_value=httpx.Response(200, json=_user()))
    assert executor.validate(_action(target=UID)).allowed


def test_validate_does_not_change_the_target(executor, graph):
    _lookup(graph, _user())
    patch = graph.patch(url__startswith=f"{GRAPH}/users").mock(
        return_value=httpx.Response(204)
    )
    post = graph.post(url__startswith=f"{GRAPH}/users").mock(
        return_value=httpx.Response(200)
    )
    executor.validate(_action())
    executor.validate(_action("revoke_sessions"))
    assert not patch.called and not post.called


@pytest.mark.parametrize(
    "user",
    [
        _user(userPrincipalName="breakglass1@contoso.test", mail=None),
        _user(userPrincipalName="svc-backup@contoso.test", mail=None),
        _user(id="AAAA", userPrincipalName="x@contoso.test", mail="BreakGlass1@contoso.test"),
    ],
    ids=["listed", "pattern", "listed-by-mail"],
)
def test_protected_identity_refused(executor, graph, user):
    _lookup(graph, user)
    verdict = executor.validate(_action(target=user["userPrincipalName"]))
    assert not verdict.allowed
    assert "protected" in verdict.reasons[0]


def test_protected_role_holder_refused(executor, graph):
    _lookup(graph, _user())
    graph.get(ROLES_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "r1",
                        "displayName": "Global Administrator",
                        "roleTemplateId": "62e90394-69f5-4237-9190-012177145e10",
                    }
                ]
            },
        )
    )
    verdict = executor.validate(_action())
    assert not verdict.allowed and "Global Administrator" in verdict.reasons[0]


def test_protected_role_refused_on_a_later_page(executor, graph):
    _lookup(graph, _user())
    graph.get(ROLES_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "value": [{"displayName": "Reports Reader", "roleTemplateId": "x"}],
                "@odata.nextLink": f"{GRAPH}/next-roles-page",
            },
        )
    )
    graph.get(f"{GRAPH}/next-roles-page").mock(
        return_value=httpx.Response(
            200, json={"value": [{"displayName": "privileged role administrator"}]}
        )
    )
    assert not executor.validate(_action()).allowed


@pytest.mark.parametrize(
    "stub",
    [
        {"id": "r-unreadable"},
        {"id": "r-unreadable", "displayName": None, "roleTemplateId": ""},
        {"id": "r-unreadable", "displayName": "  ", "roleTemplateId": None},
    ],
)
def test_a_role_without_name_or_template_fails_closed(executor, graph, stub):
    """An id-only role entry could be a protected role; it is not waved through."""
    _lookup(graph, _user())
    graph.get(ROLES_URL).mock(
        return_value=httpx.Response(
            200,
            json={"value": [{"displayName": "Reports Reader", "roleTemplateId": "x"}, stub]},
        )
    )
    verdict = executor.validate(_action())
    assert not verdict.allowed
    assert "r-unreadable" in verdict.reasons[0]
    assert "cannot be ruled out" in verdict.reasons[0]


def test_role_lookup_failure_fails_closed(executor, graph, sleeps):
    _lookup(graph, _user())
    graph.get(ROLES_URL).mock(return_value=httpx.Response(403, json={"error": {"code": "Authorization_RequestDenied"}}))
    verdict = executor.validate(_action())
    assert not verdict.allowed and "Authorization_RequestDenied" in verdict.reasons[0]


def test_ambiguous_user_refused(executor, graph):
    _lookup(
        graph,
        _user(),
        _user(id="other", userPrincipalName="alice_contoso.test#EXT#@t.test", userType="Guest"),
    )
    verdict = executor.validate(_action())
    assert not verdict.allowed
    assert "ambiguous" in verdict.reasons[0] and "a guest and a member" in verdict.reasons[0]


def test_unknown_user_refused(executor, graph):
    _lookup(graph)
    verdict = executor.validate(_action())
    assert not verdict.allowed and "no Entra ID user" in verdict.reasons[0]


def test_unknown_object_id_refused(executor, graph):
    graph.get(f"{GRAPH}/users/{UID}").mock(
        return_value=httpx.Response(404, json={"error": {"code": "Request_ResourceNotFound"}})
    )
    assert "no Entra ID user" in executor.validate(_action(target=UID)).reasons[0]


def test_guest_refused_unless_confirmed(executor, graph):
    _lookup(graph, _user(userType="Guest"))
    verdict = executor.validate(_action())
    assert not verdict.allowed and "guest" in verdict.reasons[0]
    assert executor.validate(_action(parameters={"user_type": "Guest"})).allowed


def test_guest_member_mismatch_refused(executor, graph):
    _lookup(graph, _user(userType="Member"))
    verdict = executor.validate(_action(parameters={"user_type": "Guest"}))
    assert not verdict.allowed and "Member account" in verdict.reasons[0]


def test_on_prem_synced_disable_refused_but_revoke_allowed(executor, graph):
    _lookup(graph, _user(onPremisesSyncEnabled=True))
    assert "on-premises" in executor.validate(_action()).reasons[0]
    assert executor.validate(_action("revoke_sessions")).allowed


@pytest.mark.parametrize("target", ["not an id", "alice", "a b@c.test"])
def test_malformed_target_refused_without_calling_graph(executor, graph, target):
    route = graph.get(url__startswith=f"{GRAPH}/users")
    assert not executor.validate(_action(target=target)).allowed
    assert not route.called


# -------------------------------------------------------- execute / verify


def test_disable_success_verify_and_reverse(executor, graph):
    _lookup(graph, _user())
    store = _UserStore(graph, _user())
    action = _action()

    result = executor.execute(action)
    assert result.status == "executed", result.error
    assert result.before_state["accountEnabled"] is True
    assert result.after_state["accountEnabled"] is False
    assert result.external_ref == UID
    assert store.patches == [{"accountEnabled": False}]

    verdict = executor.verify(action, result)
    assert verdict.status == "verified"
    assert verdict.observed["accountEnabled"] is False

    undo = executor.reverse(action, result)
    assert undo.status == "executed"
    assert store.patches[-1] == {"accountEnabled": True}
    assert undo.after_state["accountEnabled"] is True


def test_enable_is_the_reversible_twin(executor, graph):
    _lookup(graph, _user(accountEnabled=False))
    store = _UserStore(graph, _user(accountEnabled=False))
    result = executor.execute(_action("enable_user"))
    assert result.status == "executed" and store.user["accountEnabled"] is True
    assert executor.verify(_action("enable_user"), result).verified
    executor.reverse(_action("enable_user"), result)
    assert store.user["accountEnabled"] is False


def test_noop_when_already_disabled(executor, graph):
    _lookup(graph, _user(accountEnabled=False))
    store = _UserStore(graph, _user(accountEnabled=False))
    result = executor.execute(_action())
    assert result.status == "noop" and result.ok
    assert store.patches == []
    assert executor.verify(_action(), result).verified
    # Reversing a noop restores before_state: the account stays disabled.
    undo = executor.reverse(_action(), result)
    assert undo.status == "noop" and store.patches == []


def test_execute_rechecks_protection(executor, graph):
    """A role granted between approval and execution still stops the action."""
    _lookup(graph, _user())
    store = _UserStore(graph, _user())
    graph.get(ROLES_URL).mock(
        return_value=httpx.Response(200, json={"value": [{"displayName": "Global Administrator"}]})
    )
    result = executor.execute(_action())
    assert result.status == "failed" and result.error.startswith("refused:")
    assert store.patches == []


def test_verify_mismatch_is_failed(executor, graph):
    _lookup(graph, _user())
    store = _UserStore(graph, _user())
    result = executor.execute(_action())
    store.user["accountEnabled"] = True  # someone re-enabled it
    verdict = executor.verify(_action(), result)
    assert verdict.status == "failed" and "expected False" in verdict.message


def test_verify_unknown_when_graph_unreachable(executor, graph, sleeps):
    graph.get(f"{GRAPH}/users/{UID}").mock(side_effect=httpx.ConnectError("down"))
    result = ExecResult(status="executed", before_state=_user(), external_ref=UID)
    assert executor.verify(_action(), result).status == "unknown"


def test_verify_of_a_failed_execution_is_unknown(executor):
    assert (
        executor.verify(_action(), ExecResult(status="failed", error="x")).status
        == "unknown"
    )


def test_revoke_sessions_executes_and_verifies(executor, graph):
    _lookup(graph, _user())
    store = _UserStore(graph, _user())
    action = _action("revoke_sessions")
    result = executor.execute(action)
    assert result.status == "executed"
    assert store.revoke.call_count == 1
    assert result.after_state["signInSessionsValidFromDateTime"] == "2026-10-12T09:00:00Z"
    assert executor.verify(action, result).verified
    # Same idempotency key again: noop, no second revoke.
    again = executor.execute(action)
    assert again.status == "noop" and store.revoke.call_count == 1


def test_revoke_noop_when_already_revoked_since_request(executor, graph):
    _lookup(graph, _user(signInSessionsValidFromDateTime="2026-10-12T10:00:00Z"))
    store = _UserStore(graph, _user())
    action = _action("revoke_sessions", parameters={"requested_at": "2026-10-12T09:30:00Z"})
    assert executor.execute(action).status == "noop"
    assert store.revoke.call_count == 0


def test_revoke_verify_mismatch(executor, graph):
    _lookup(graph, _user())
    store = _UserStore(graph, _user())
    store.revoke.mock(return_value=httpx.Response(200, json={"value": True}))  # no effect
    action = _action("revoke_sessions")
    result = executor.execute(action)
    verdict = executor.verify(action, result)
    assert verdict.status == "failed" and "did not advance" in verdict.message


# ------------------------------------------------------- errors and backoff


def test_retry_on_429_honours_retry_after(executor, graph, sleeps):
    _lookup(graph, _user())
    _UserStore(graph, _user())
    graph.patch(f"{GRAPH}/users/{UID}").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "7"}, json={"error": {"code": "TooManyRequests"}}),
            httpx.Response(204),
        ]
    )
    result = executor.execute(_action())
    assert result.status == "executed"
    assert sleeps == [7.0]


def test_retry_on_5xx_backs_off_then_gives_up(executor, graph, sleeps):
    _lookup(graph, _user())
    _UserStore(graph, _user())
    route = graph.patch(f"{GRAPH}/users/{UID}").mock(
        return_value=httpx.Response(503, json={"error": {"code": "ServiceUnavailable"}})
    )
    result = executor.execute(_action())
    assert result.status == "failed"
    assert "HTTP 503" in result.error and "ServiceUnavailable" in result.error
    assert route.call_count == 4  # 1 + max_retries(3)
    assert sleeps == [1.0, 2.0, 4.0]


def test_retry_after_is_capped(graph, sleeps):
    client = GraphClient(lambda: TOKEN, max_backoff=5, max_retries=1, sleep=sleeps.append)
    graph.get(f"{GRAPH}/x").mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "600"}), httpx.Response(200, json={})]
    )
    client.get_json("/x")
    assert sleeps == [5]


def test_4xx_is_not_retried(executor, graph, sleeps):
    _lookup(graph, _user())
    _UserStore(graph, _user())
    route = graph.patch(f"{GRAPH}/users/{UID}").mock(
        return_value=httpx.Response(
            403,
            json={"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}},
        )
    )
    result = executor.execute(_action())
    assert result.status == "failed"
    assert "HTTP 403" in result.error and "Authorization_RequestDenied" in result.error
    assert route.call_count == 1 and sleeps == []


def test_401_refreshes_the_token_once(graph, sleeps):
    tokens = iter(["old", "new"])
    client = GraphClient(lambda: next(tokens), sleep=sleeps.append)
    route = graph.get(f"{GRAPH}/x").mock(
        side_effect=[httpx.Response(401), httpx.Response(200, json={"ok": 1})]
    )
    assert client.get_json("/x") == {"ok": 1}
    assert route.calls[1].request.headers["Authorization"] == "Bearer new"


def test_token_failure_is_a_refusal_not_a_crash(graph):
    graph.post(TOKEN_URL).mock(
        return_value=httpx.Response(401, json={"error_description": "AADSTS7000215: bad secret"})
    )
    e = ex.build_executor(CONFIG)
    verdict = e.validate(_action())
    assert not verdict.allowed and "AADSTS7000215" in verdict.reasons[0]
    assert e.execute(_action()).status == "failed"


def test_no_token_logging(graph, sleeps, caplog):
    """Neither the access token nor the client secret reaches logs or results."""
    e = ex.build_executor(CONFIG, sleep=sleeps.append)
    _lookup(graph, _user())
    _UserStore(graph, _user())
    graph.patch(f"{GRAPH}/users/{UID}").mock(
        side_effect=[httpx.Response(429), httpx.Response(500), httpx.Response(204)]
    )
    with caplog.at_level(logging.DEBUG):
        action = _action()
        result = e.execute(action)
        verdict = e.verify(action, result)
        e.reverse(action, result)
        graph.patch(f"{GRAPH}/users/{UID}").mock(return_value=httpx.Response(400, json={"error": {"code": "BadRequest"}}))
        failed = e.execute(_action("enable_user"))
    assert result.status == "executed"
    blob = " ".join(
        [caplog.text, repr(e), repr(e._client), result.model_dump_json(),
         verdict.model_dump_json(), failed.model_dump_json()]
    )
    assert TOKEN not in blob and SECRET not in blob
    # The token did go out, in the header and nowhere else.
    assert graph.calls.last.request.headers["Authorization"] == f"Bearer {TOKEN}"


def test_graph_error_text_is_safe(graph):
    client = GraphClient(lambda: TOKEN, max_retries=0)
    graph.get(f"{GRAPH}/x").mock(return_value=httpx.Response(400, json={"error": {"code": "BadRequest", "message": "nope"}}))
    with pytest.raises(GraphError) as info:
        client.get_json("/x")
    assert info.value.status == 400 and TOKEN not in str(info.value)


# -------------------------------------------- the MCP tool shares the client


@respx.mock
async def test_mcp_disable_tool_uses_the_shared_client(monkeypatch):
    monkeypatch.setattr(aad_tool, "resolve", lambda *a, **kw: CONFIG)
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": TOKEN}))
    guest = "bob_x.test#EXT#@contoso.test"
    route = respx.patch(f"{GRAPH}/users/bob_x.test%23EXT%23@contoso.test").mock(
        return_value=httpx.Response(204)
    )
    out = await aad_tool.handle_call_tool("aad_disable_user", {"user_id": guest, "reason": "r"})
    body = json.loads(out[0].text)
    assert body == {"success": True, "user_id": guest, "action": "disabled"}
    assert json.loads(route.calls.last.request.content) == {"accountEnabled": False}
    assert route.calls.last.request.headers["Authorization"] == f"Bearer {TOKEN}"


@respx.mock
async def test_mcp_disable_tool_reports_graph_errors(monkeypatch):
    monkeypatch.setattr(aad_tool, "resolve", lambda *a, **kw: CONFIG)
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": TOKEN}))
    respx.patch(f"{GRAPH}/users/u1").mock(
        return_value=httpx.Response(404, json={"error": {"code": "Request_ResourceNotFound"}})
    )
    body = json.loads((await aad_tool.handle_call_tool("aad_disable_user", {"user_id": "u1", "reason": "r"}))[0].text)
    assert "HTTP 404" in body["error"] and TOKEN not in body["error"]
