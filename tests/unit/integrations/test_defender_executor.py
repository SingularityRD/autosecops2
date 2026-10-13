"""Microsoft Defender for Endpoint isolation executor (W2.5), against a
respx-mocked MDE API and Entra ID token endpoint. No real network."""

from __future__ import annotations

import json
import logging
from datetime import timedelta

import httpx
import pytest
import respx

from core.integrations.microsoft_defender import executor as mde_executor
from core.integrations.microsoft_defender.client import MDEApiError, MDEClient
from core.integrations.microsoft_defender.executor import (
    ISOLATE,
    UNISOLATE,
    build_executor,
)
from core.response.executors.base import (
    ExecResult,
    Executor,
    ExecutorRegistry,
    TypedAction,
)

pytestmark = pytest.mark.unit

API = "https://api.securitycenter.microsoft.com/api"
TOKEN_URL = "https://login.microsoftonline.com/tid/oauth2/v2.0/token"
SECRET = "s3cret-value-never-logged"
TOKEN = "eyJ-access-token-never-logged"
CONFIG = {
    "tenant_id": "tid",
    "client_id": "cid",
    "client_secret": SECRET,
    "verify_timeout_seconds": 30,
    "poll_interval_seconds": 5,
    "max_retries": 3,
    "backoff_base_seconds": 1,
}
MID = "a" * 40
MID2 = "b" * 40
MACHINE = {
    "id": MID,
    "computerDnsName": "ws-01.corp.example",
    "healthStatus": "Active",
    "onboardingStatus": "Onboarded",
    "lastSeen": "2026-10-12T08:00:00Z",
    "lastIpAddress": "10.0.0.5",
    "osPlatform": "Windows11",
}


class FakeTime:
    """sleep() advances clock(); every sleep is recorded."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture
def ft():
    return FakeTime()


@pytest.fixture
def mock():
    with respx.mock(assert_all_called=False) as router:
        router.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": TOKEN})
        )
        yield router


def _executor(ft, **overrides):
    return build_executor({**CONFIG, **overrides}, sleep=ft.sleep, clock=ft.clock)


def _action(action_type=ISOLATE, target="ws-01.corp.example", **kw):
    return TypedAction(action_type=action_type, target=target, action_id="act-1", **kw)


def _machines(mock, value):
    return mock.get(f"{API}/machines").mock(
        return_value=httpx.Response(200, json={"value": value})
    )


def _actions(mock, value):
    return mock.get(f"{API}/machineactions").mock(
        return_value=httpx.Response(200, json={"value": value})
    )


def _act(type_, status, when="2026-10-12T07:00:00Z", id_="ma-old"):
    return {"id": id_, "type": type_, "status": status, "creationDateTimeUtc": when}


# ------------------------------------------------------------------ protocol


def test_implements_the_protocol_and_registers(ft):
    ex = _executor(ft)
    assert isinstance(ex, Executor)
    assert ex.action_types == {ISOLATE, UNISOLATE}
    assert ex.reversible_types == ex.action_types
    assert ex.default_ttl is None
    registry = ExecutorRegistry()
    registry.register(ex)
    assert registry.reversibility_of(ISOLATE) == "reversible"


def test_isolation_ttl_is_configurable(ft):
    assert _executor(ft, isolation_ttl=3600).default_ttl == timedelta(hours=1)
    with pytest.raises(ValueError):
        _executor(ft, default_isolation_type="Partial")


# ------------------------------------------------------------------ validate


def test_validate_allows_a_single_match(mock, ft):
    route = _machines(mock, [MACHINE])
    verdict = _executor(ft).validate(_action())
    assert verdict.allowed, verdict.reasons
    assert "computerDnsName eq 'ws-01.corp.example'" in str(
        route.calls.last.request.url.params["$filter"]
    )
    # validate reads only: nothing was posted to MDE
    assert not any(
        c.request.method == "POST" and "/api/" in str(c.request.url) for c in mock.calls
    )


def test_validate_refuses_an_ambiguous_target(mock, ft):
    _machines(mock, [MACHINE, {**MACHINE, "id": MID2}])
    verdict = _executor(ft).validate(_action())
    assert not verdict.allowed
    assert "matches 2 MDE machines" in verdict.reasons[0]
    assert MID in verdict.reasons[0] and MID2 in verdict.reasons[0]


def test_short_name_matches_fqdn_but_not_prefix_siblings(mock, ft):
    _machines(
        mock,
        [
            MACHINE,
            {**MACHINE, "id": MID2, "computerDnsName": "ws-010.corp.example"},
        ],
    )
    assert _executor(ft).validate(_action(target="WS-01")).allowed


def test_validate_refuses_unknown_and_malformed_targets(mock, ft):
    _machines(mock, [])
    ex = _executor(ft)
    assert "no MDE machine" in ex.validate(_action()).reasons[0]
    bad = ex.validate(_action(target="x' or 1 eq 1"))
    assert not bad.allowed and "hostname" in bad.reasons[0]


def test_machine_id_target_404_is_refused(mock, ft):
    mock.get(f"{API}/machines/{MID}").mock(
        return_value=httpx.Response(404, json={"error": {"code": "NotFound"}})
    )
    verdict = _executor(ft).validate(_action(target=MID))
    assert not verdict.allowed and "no MDE machine with id" in verdict.reasons[0]


def test_ip_target_resolves_on_last_ip(mock, ft):
    route = _machines(mock, [MACHINE])
    assert _executor(ft).validate(_action(target="10.0.0.5")).allowed
    assert (
        "lastIpAddress eq '10.0.0.5'" in route.calls.last.request.url.params["$filter"]
    )


def test_validate_refuses_bad_parameters_and_missing_config(ft, monkeypatch):
    ex = _executor(ft)
    assert not ex.validate(_action(parameters={"isolation_type": "Partial"})).allowed
    assert not ex.validate(
        _action(UNISOLATE, parameters={"isolation_type": "Full"})
    ).allowed
    monkeypatch.setattr(
        mde_executor,
        "resolve",
        lambda *_a, **_k: {"tenant_id": None, "client_id": None, "client_secret": None},
    )
    unconfigured = build_executor({}, sleep=ft.sleep, clock=ft.clock)
    verdict = unconfigured.validate(_action())
    assert not verdict.allowed and "not configured" in verdict.reasons[0]


def test_validate_refuses_when_mde_is_unreachable(mock, ft):
    mock.get(f"{API}/machines").mock(return_value=httpx.Response(503))
    verdict = _executor(ft).validate(_action())
    assert not verdict.allowed and "HTTP 503" in verdict.reasons[0]


# ------------------------------------------------------------------- execute


def test_execute_isolates_and_captures_state(mock, ft):
    _machines(mock, [MACHINE])
    _actions(mock, [_act("Unisolate", "Succeeded")])
    post = mock.post(f"{API}/machines/{MID}/isolate").mock(
        return_value=httpx.Response(201, json={"id": "ma-1", "status": "Pending"})
    )
    result = _executor(ft).execute(_action(parameters={"isolation_type": "Selective"}))
    assert result.status == "executed", result.error
    assert result.external_ref == "ma-1"
    body = json.loads(post.calls.last.request.content)
    assert body["IsolationType"] == "Selective"
    assert "AutoSecOps" in body["Comment"] and "act-1" in body["Comment"]
    assert result.before_state["isolated"] is False
    assert result.before_state["health_status"] == "Active"
    assert result.after_state["isolated"] is True
    assert result.after_state["isolation_state"] == "isolating"
    assert result.after_state["isolation_type"] == "Selective"
    assert result.after_state["machine_id"] == MID


def test_already_isolated_is_a_noop(mock, ft):
    _machines(mock, [MACHINE])
    _actions(
        mock,
        [
            _act("Unisolate", "Succeeded", "2026-10-11T00:00:00Z", "ma-a"),
            _act("Isolate", "Succeeded", "2026-10-12T00:00:00Z", "ma-b"),
            # a later failed unisolate does not count
            _act("Unisolate", "Failed", "2026-10-12T01:00:00Z", "ma-c"),
        ],
    )
    post = mock.post(f"{API}/machines/{MID}/isolate")
    result = _executor(ft).execute(_action())
    assert result.status == "noop" and result.ok
    assert "already isolated" in result.message
    assert result.external_ref is None
    assert result.before_state == result.after_state
    assert not post.called


def test_latest_action_is_chosen_by_time_not_by_string(mock, ft):
    """7 fractional digits vs none: '...00.5000000Z' sorts before '...00Z' as text."""
    _machines(mock, [MACHINE])
    _actions(
        mock,
        [
            _act("Unisolate", "Succeeded", "2026-10-12T08:00:00.5000000Z", "ma-new"),
            _act("Isolate", "Succeeded", "2026-10-12T08:00:00Z", "ma-old"),
        ],
    )
    post = mock.post(f"{API}/machines/{MID}/isolate").mock(
        return_value=httpx.Response(201, json={"id": "ma-1", "status": "Pending"})
    )
    result = _executor(ft).execute(_action())
    assert result.before_state["isolated"] is False
    assert result.before_state["last_action_id"] == "ma-new"
    assert result.status == "executed" and post.called


def test_pending_isolation_is_a_noop_that_points_at_it(mock, ft):
    _machines(mock, [MACHINE])
    _actions(mock, [_act("Isolate", "InProgress", id_="ma-p")])
    post = mock.post(f"{API}/machines/{MID}/isolate")
    result = _executor(ft).execute(_action())
    assert result.status == "noop" and result.external_ref == "ma-p"
    assert not post.called


def test_unisolate_when_not_isolated_is_a_noop(mock, ft):
    _machines(mock, [MACHINE])
    _actions(mock, [])
    post = mock.post(f"{API}/machines/{MID}/unisolate")
    result = _executor(ft).execute(_action(UNISOLATE))
    assert result.status == "noop"
    assert not post.called


def test_ambiguous_target_fails_execute_without_acting(mock, ft):
    _machines(mock, [MACHINE, {**MACHINE, "id": MID2}])
    post = mock.post(url__regex=rf"{API}/machines/.*/isolate")
    result = _executor(ft).execute(_action())
    assert result.status == "failed" and "matches 2" in result.error
    assert not post.called


def test_active_request_already_exists_resolves_to_the_pending_action(mock, ft):
    _machines(mock, [MACHINE])
    mock.get(f"{API}/machineactions").mock(
        side_effect=[
            httpx.Response(200, json={"value": []}),
            httpx.Response(
                200, json={"value": [_act("Isolate", "Pending", id_="ma-other")]}
            ),
        ]
    )
    mock.post(f"{API}/machines/{MID}/isolate").mock(
        return_value=httpx.Response(
            400,
            json={"error": {"code": "ActiveRequestAlreadyExists", "message": "dup"}},
        )
    )
    result = _executor(ft).execute(_action())
    assert result.status == "executed" and result.external_ref == "ma-other"


@pytest.mark.parametrize("status", [400, 403, 404])
def test_client_errors_fail_without_retry(mock, ft, status):
    _machines(mock, [MACHINE])
    _actions(mock, [])
    post = mock.post(f"{API}/machines/{MID}/isolate").mock(
        return_value=httpx.Response(
            status, json={"error": {"code": "Forbidden", "message": "nope"}}
        )
    )
    result = _executor(ft).execute(_action())
    assert result.status == "failed"
    assert f"HTTP {status}" in result.error
    assert post.call_count == 1
    assert ft.sleeps == []


def test_429_is_retried_honouring_retry_after(mock, ft):
    _machines(mock, [MACHINE])
    _actions(mock, [])
    post = mock.post(f"{API}/machines/{MID}/isolate").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "7"}),
            httpx.Response(201, json={"id": "ma-1", "status": "Pending"}),
        ]
    )
    result = _executor(ft).execute(_action())
    assert result.status == "executed"
    assert post.call_count == 2
    assert ft.sleeps == [7.0]


def test_5xx_backs_off_exponentially_then_gives_up(mock, ft):
    _machines(mock, [MACHINE])
    _actions(mock, [])
    post = mock.post(f"{API}/machines/{MID}/isolate").mock(
        return_value=httpx.Response(503, text="busy")
    )
    result = _executor(ft).execute(_action())
    assert result.status == "failed" and "HTTP 503" in result.error
    assert post.call_count == 4  # first try + max_retries=3
    assert ft.sleeps == [1.0, 2.0, 4.0]


def test_transport_errors_are_retried(mock, ft):
    _machines(mock, [MACHINE])
    _actions(mock, [])
    mock.post(f"{API}/machines/{MID}/isolate").mock(
        side_effect=[
            httpx.ConnectError("refused"),
            httpx.Response(201, json={"id": "ma-1", "status": "Pending"}),
        ]
    )
    assert _executor(ft).execute(_action()).status == "executed"
    assert ft.sleeps == [1.0]


def test_401_refreshes_the_token_once(mock, ft):
    tokens = mock.post(TOKEN_URL).mock(
        side_effect=[
            httpx.Response(200, json={"access_token": "old"}),
            httpx.Response(200, json={"access_token": "new"}),
        ]
    )
    route = mock.get(f"{API}/machines").mock(
        side_effect=[
            httpx.Response(401),
            httpx.Response(200, json={"value": [MACHINE]}),
        ]
    )
    assert _executor(ft).validate(_action()).allowed
    assert tokens.call_count == 2
    assert route.calls.last.request.headers["Authorization"] == "Bearer new"


# -------------------------------------------------------------------- verify


def _executed(after_isolated=True, ref="ma-1"):
    state = {"machine_id": MID, "isolated": not after_isolated}
    return ExecResult(
        status="executed",
        before_state=state,
        after_state={**state, "isolated": after_isolated},
        external_ref=ref,
    )


def test_verify_polls_until_succeeded(mock, ft):
    route = mock.get(f"{API}/machineactions/ma-1").mock(
        side_effect=[
            httpx.Response(200, json={"id": "ma-1", "status": "Pending"}),
            httpx.Response(200, json={"id": "ma-1", "status": "InProgress"}),
            httpx.Response(200, json={"id": "ma-1", "status": "Succeeded"}),
        ]
    )
    vr = _executor(ft).verify(_action(), _executed())
    assert vr.status == "verified"
    assert vr.observed["machine_action_status"] == "Succeeded"
    assert route.call_count == 3
    assert ft.sleeps == [5.0, 5.0]


def test_verify_reports_a_failed_machine_action(mock, ft):
    mock.get(f"{API}/machineactions/ma-1").mock(
        return_value=httpx.Response(200, json={"id": "ma-1", "status": "Failed"})
    )
    assert _executor(ft).verify(_action(), _executed()).status == "failed"


def test_verify_timeout_is_unknown(mock, ft):
    route = mock.get(f"{API}/machineactions/ma-1").mock(
        return_value=httpx.Response(200, json={"id": "ma-1", "status": "Pending"})
    )
    vr = _executor(ft).verify(_action(), _executed())
    assert vr.status == "unknown"
    assert "still Pending" in vr.message
    assert sum(ft.sleeps) == 30.0
    assert route.call_count == 7


def test_verify_with_api_down_is_unknown_not_failed(mock, ft):
    mock.get(f"{API}/machineactions/ma-1").mock(return_value=httpx.Response(500))
    vr = _executor(ft, max_retries=0).verify(_action(), _executed())
    assert vr.status == "unknown" and "HTTP 500" in vr.message


def test_verify_noop_rechecks_state(mock, ft):
    _actions(mock, [_act("Isolate", "Succeeded")])
    noop = ExecResult(
        status="noop",
        before_state={"machine_id": MID, "isolated": True},
        after_state={"machine_id": MID, "isolated": True},
    )
    assert _executor(ft).verify(_action(), noop).status == "verified"


def test_verify_of_a_failed_execution_is_failed(ft):
    failed = ExecResult(status="failed", error="x")
    assert _executor(ft).verify(_action(), failed).status == "failed"


# ------------------------------------------------------------------- reverse


def test_reverse_unisolates_by_recorded_machine_id(mock, ft):
    mock.get(f"{API}/machines/{MID}").mock(
        return_value=httpx.Response(200, json=MACHINE)
    )
    _actions(mock, [_act("Isolate", "Succeeded", id_="ma-1")])
    post = mock.post(f"{API}/machines/{MID}/unisolate").mock(
        return_value=httpx.Response(201, json={"id": "ma-2", "status": "Pending"})
    )
    original = _executed()
    undo = _executor(ft).reverse(_action(), original)
    assert undo.status == "executed" and undo.external_ref == "ma-2"
    assert "reverse" in json.loads(post.calls.last.request.content)["Comment"]
    assert undo.before_state["isolated"] is True
    assert undo.after_state["isolated"] is False


def test_reverse_of_unisolate_reisolates_with_the_prior_type(mock, ft):
    mock.get(f"{API}/machines/{MID}").mock(
        return_value=httpx.Response(200, json=MACHINE)
    )
    _actions(mock, [_act("Unisolate", "Succeeded")])
    post = mock.post(f"{API}/machines/{MID}/isolate").mock(
        return_value=httpx.Response(201, json={"id": "ma-3", "status": "Pending"})
    )
    original = ExecResult(
        status="executed",
        before_state={
            "machine_id": MID,
            "isolated": True,
            "isolation_type": "Selective",
        },
        after_state={"machine_id": MID, "isolated": False},
        external_ref="ma-2",
    )
    undo = _executor(ft).reverse(_action(UNISOLATE), original)
    assert undo.status == "executed"
    assert json.loads(post.calls.last.request.content)["IsolationType"] == "Selective"


def test_reverse_of_a_noop_leaves_a_preexisting_isolation_alone(mock, ft):
    post = mock.post(url__regex=rf"{API}/machines/.*")
    noop = ExecResult(
        status="noop",
        before_state={"machine_id": MID, "isolated": True},
        after_state={"machine_id": MID, "isolated": True},
    )
    assert _executor(ft).reverse(_action(), noop).status == "noop"
    assert not post.called


def test_reverse_when_already_restored_is_a_noop(mock, ft):
    mock.get(f"{API}/machines/{MID}").mock(
        return_value=httpx.Response(200, json=MACHINE)
    )
    _actions(mock, [_act("Unisolate", "Succeeded", id_="ma-x")])
    post = mock.post(f"{API}/machines/{MID}/unisolate")
    assert _executor(ft).reverse(_action(), _executed()).status == "noop"
    assert not post.called


def test_reverse_without_before_state_fails(ft):
    bare = ExecResult(status="executed", external_ref="ma-1")
    undo = _executor(ft).reverse(_action(), bare)
    assert undo.status == "failed" and "before_state" in undo.error


# ------------------------------------------------------------------- secrets


def test_secrets_never_reach_logs_results_or_repr(mock, ft, caplog):
    _machines(mock, [MACHINE])
    _actions(mock, [])
    mock.post(f"{API}/machines/{MID}/isolate").mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(
                403, json={"error": {"code": "Forbidden", "message": "denied"}}
            ),
        ]
    )
    ex = _executor(ft)
    with caplog.at_level(logging.DEBUG):
        ex.validate(_action())
        result = ex.execute(_action())
        ex.verify(_action(), result)
    assert result.status == "failed"
    dumped = json.dumps(result.model_dump(), default=str)
    for needle in (SECRET, TOKEN):
        assert needle not in caplog.text
        assert needle not in dumped
        assert needle not in repr(ex)
        assert needle not in repr(ex._client)


def test_token_rejection_is_reported_without_the_secret(ft, caplog):
    with respx.mock(assert_all_called=False) as router:
        router.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                401,
                json={"error": "invalid_client", "error_description": "AADSTS7000215"},
            )
        )
        with caplog.at_level(logging.DEBUG):
            verdict = _executor(ft).validate(_action())
    assert not verdict.allowed and "rejected" in verdict.reasons[0]
    assert SECRET not in caplog.text and SECRET not in verdict.reasons[0]


def test_client_error_carries_status_and_code(ft):
    with respx.mock() as router:
        router.get(f"{API}/alerts").mock(
            return_value=httpx.Response(
                400, json={"error": {"code": "BadRequest", "message": "bad $top"}}
            )
        )
        client = MDEClient(lambda: "t", sleep=ft.sleep, clock=ft.clock)
        with pytest.raises(MDEApiError) as err:
            client.list_alerts()
    assert err.value.status == 400 and err.value.code == "BadRequest"
    assert "Bearer" not in str(err.value)


# ------------------------------------------------- verifier regressions (R3)


def test_short_name_filter_is_exact_first_label_not_startswith(mock, ft):
    """FIXES W2.5 #1: 'web' must not be resolved through startswith('web')."""
    route = _machines(
        mock,
        [
            {**MACHINE, "computerDnsName": "web.corp.example"},
            {**MACHINE, "id": MID2, "computerDnsName": "web2.corp.example"},
        ],
    )
    verdict = _executor(ft).validate(_action(target="web"))
    assert verdict.allowed, verdict.reasons
    odata = route.calls.last.request.url.params["$filter"]
    assert odata == "computerDnsName eq 'web' or startswith(computerDnsName,'web.')"


@pytest.mark.parametrize(
    "body",
    [
        # nextLink: a second page exists that may hold a second match
        {"value": [MACHINE], "@odata.nextLink": f"{API}/machines?$skip=50"},
        # a full page without nextLink: cannot tell it is complete either
        {"value": [MACHINE] + [{"id": "c" * 40}] * 49},
    ],
    ids=["next-link", "full-page"],
)
def test_truncated_machine_lookup_is_refused(mock, ft, body):
    """FIXES W2.5 #1: one match on page 1 is not 'exactly one machine'."""
    route = mock.get(f"{API}/machines").mock(
        return_value=httpx.Response(200, json=body)
    )
    post = mock.post(url__regex=rf"{API}/machines/.*/isolate")
    ex = _executor(ft)
    verdict = ex.validate(_action(target="ws-01"))
    assert not verdict.allowed and "more MDE machines" in verdict.reasons[0]
    assert not ex.validate(_action(target="10.0.0.5")).allowed
    result = ex.execute(_action(target="ws-01"))
    assert result.status == "failed" and "machine id" in result.error
    assert not post.called
    # the nextLink is never followed
    assert all("$skip" not in str(c.request.url) for c in route.calls)


def test_isolation_history_is_read_newest_first(mock, ft):
    """FIXES W2.5 #2: $top without $orderby can omit the latest action."""
    _machines(mock, [MACHINE])
    route = _actions(mock, [_act("Isolate", "Succeeded")])
    _executor(ft).execute(_action())
    params = route.calls.last.request.url.params
    assert params["$orderby"] == "creationDateTimeUtc desc"
    assert "$top" in params


def _post_isolate(mock, **kw):
    return mock.post(f"{API}/machines/{MID}/isolate").mock(**kw)


@pytest.mark.parametrize(
    "post_kw",
    [
        {"return_value": httpx.Response(503, text="busy")},
        {"side_effect": httpx.ReadTimeout("slow")},
        {
            "return_value": httpx.Response(
                400, json={"error": {"code": "BadRequest", "message": "odd"}}
            )
        },
    ],
    ids=["5xx", "timeout", "unexpected-400"],
)
def test_ambiguous_post_that_landed_is_executed(mock, ft, post_kw):
    """FIXES W2.5 #3: an isolation MDE accepted despite the error is reported
    executed, pointing at the machine action, so verify/reverse/TTL follow it."""
    _machines(mock, [MACHINE])
    mock.get(f"{API}/machineactions").mock(
        side_effect=[
            httpx.Response(200, json={"value": [_act("Unisolate", "Succeeded")]}),
            httpx.Response(
                200,
                json={
                    "value": [
                        _act("Isolate", "Pending", "2026-10-13T00:00:00Z", "ma-new"),
                        _act("Unisolate", "Succeeded"),
                    ]
                },
            ),
        ]
    )
    _post_isolate(mock, **post_kw)
    result = _executor(ft).execute(_action())
    assert result.status == "executed", result.error
    assert result.external_ref == "ma-new"
    assert result.after_state["isolated"] is True
    assert result.before_state["isolated"] is False


def test_ambiguous_post_confirmed_not_landed_is_failed(mock, ft):
    _machines(mock, [MACHINE])
    route = _actions(mock, [_act("Unisolate", "Succeeded")])
    _post_isolate(mock, return_value=httpx.Response(503))
    result = _executor(ft).execute(_action())
    assert result.status == "failed" and "HTTP 503" in result.error
    assert route.call_count == 2  # before + re-read


def test_ambiguous_post_with_unreadable_state_is_unknown_not_failed(mock, ft):
    """Re-read fails too: the isolation may stand, so it must stay undoable."""
    _machines(mock, [MACHINE])
    mock.get(f"{API}/machineactions").mock(
        side_effect=[httpx.Response(200, json={"value": []})]
        + [httpx.Response(503)] * 4
    )
    _post_isolate(mock, side_effect=httpx.ReadTimeout("slow"))
    ex = _executor(ft)
    result = ex.execute(_action())
    assert result.status == "executed"
    assert result.after_state["outcome"] == "unknown"
    assert result.external_ref is None and result.error
    # reverse still works from the recorded machine id
    mock.get(f"{API}/machines/{MID}").mock(
        return_value=httpx.Response(200, json=MACHINE)
    )
    mock.get(f"{API}/machineactions").mock(
        return_value=httpx.Response(
            200, json={"value": [_act("Isolate", "Succeeded", id_="ma-late")]}
        )
    )
    unpost = mock.post(f"{API}/machines/{MID}/unisolate").mock(
        return_value=httpx.Response(201, json={"id": "ma-u", "status": "Pending"})
    )
    assert ex.reverse(_action(), result).status == "executed"
    assert unpost.called


def test_definite_rejection_with_unreadable_state_is_failed(mock, ft):
    _machines(mock, [MACHINE])
    mock.get(f"{API}/machineactions").mock(
        side_effect=[httpx.Response(200, json={"value": []})]
        + [httpx.Response(503)] * 4
    )
    _post_isolate(
        mock, return_value=httpx.Response(403, json={"error": {"code": "Forbidden"}})
    )
    result = _executor(ft).execute(_action())
    assert result.status == "failed" and "HTTP 403" in result.error


@pytest.mark.parametrize(
    "base",
    [
        "https://attacker.example/api",
        "http://api.securitycenter.microsoft.com/api",
        "https://api.securitycenter.microsoft.com.attacker.example/api",
        "https://api.securitycenter.microsoft.com/api/../../x",
    ],
)
def test_api_base_outside_the_mde_allowlist_is_refused(mock, ft, base):
    """FIXES W2.5 #4: integration config cannot send the token to its own host."""
    with pytest.raises(ValueError, match="official Microsoft Defender"):
        _executor(ft, api_base=base)
    with pytest.raises(ValueError):
        MDEClient(lambda: TOKEN, api_base=base)


def test_regional_api_base_is_accepted(mock, ft):
    eu = "https://api-eu.securitycenter.microsoft.com/api"
    route = mock.get(f"{eu}/machines").mock(
        return_value=httpx.Response(200, json={"value": [MACHINE]})
    )
    assert _executor(ft, api_base=eu + "/").validate(_action()).allowed
    assert route.called


def test_validate_of_a_reverse_does_not_re_resolve_the_target(mock, ft):
    """FIXES W2.5 #5 (executor side): the host was renamed since isolation;
    the reverse is still allowed and reverse() uses the recorded machine id."""
    route = _machines(mock, [])
    ex = _executor(ft)
    reverse = _action(reverse_of="act-0")
    verdict = ex.validate(reverse)
    assert verdict.allowed, verdict.reasons
    assert not route.called
    assert not ex.validate(_action()).allowed  # forward still resolves
