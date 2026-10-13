"""The Palo Alto executor against a respx-mocked PAN-OS XML API.

A small fake firewall answers the three calls the executor makes (op
``show object registered-ip``, user-id ``register`` and ``unregister``) and
keeps the registered tags, so execute / verify / reverse are checked as a
round trip rather than call by call.
"""

from __future__ import annotations

import ipaddress
import logging
import xml.etree.ElementTree as ET
from datetime import timedelta
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from core.integrations.palo_alto.client import PanConfigError
from core.integrations.palo_alto.executor import (
    DEFAULT_TAG,
    PaloAltoExecutor,
    build_executor,
)
from core.response.executors.base import (
    ExecResult,
    Executor,
    ExecutorRegistry,
    TypedAction,
)

pytestmark = pytest.mark.unit

API_KEY = "LUFRPT1-super/secret+key=="
PUBLIC_V4 = "185.220.101.1"
PUBLIC_V6 = "2a01:4f8::1"
API_URL = "https://pan.test/api/"


class FakeFirewall:
    """Registered tags per IP, plus scripted failures."""

    def __init__(self) -> None:
        self.tags: dict[str, set[str]] = {}
        self.requests: list[dict[str, str]] = []
        self.headers: list[httpx.Headers] = []
        self.urls: list[str] = []
        # Responses to hand out before behaving normally, keyed by call type.
        self.script: dict[str, list[httpx.Response]] = {}
        self.ignore_writes = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        self.requests.append(form)
        self.headers.append(request.headers)
        self.urls.append(str(request.url))
        kind = form.get("type", "")
        queue = self.script.get(kind)
        if queue:
            scripted = queue.pop(0)
            return scripted(self, form) if callable(scripted) else scripted
        if kind == "op":
            ip = ET.fromstring(form["cmd"]).findtext(".//ip")
            tags = self.tags.get(ip, set())
            entries = (
                f'<entry ip="{ip}" from_agent="0" persistent="1"><tag>'
                + "".join(f"<member>{t}</member>" for t in sorted(tags))
                + "</tag></entry>"
                if tags
                else ""
            )
            return _ok(f"<result>{entries}<count>{1 if tags else 0}</count></result>")
        if kind == "user-id":
            msg = ET.fromstring(form["cmd"])
            if not self.ignore_writes:
                for verb in ("register", "unregister"):
                    for entry in msg.findall(f"./payload/{verb}/entry"):
                        members = {m.text for m in entry.iter("member")}
                        current = self.tags.setdefault(entry.get("ip"), set())
                        if verb == "register":
                            current |= members
                        else:
                            current -= members
            return _ok(
                "<result><uid-response><version>2.0</version></uid-response></result>"
            )
        return httpx.Response(400, text="<response status='error'/>")

    def writes(self) -> list[dict[str, str]]:
        return [r for r in self.requests if r.get("type") == "user-id"]


def _ok(inner: str) -> httpx.Response:
    return httpx.Response(200, text=f'<response status="success">{inner}</response>')


def _err(message: str) -> httpx.Response:
    return httpx.Response(
        200,
        text=f'<response status="error"><msg><line>{message}</line></msg></response>',
    )


@pytest.fixture
def firewall():
    fw = FakeFirewall()
    with respx.mock(assert_all_called=False) as router:
        router.post(API_URL).mock(side_effect=fw)
        yield fw


@pytest.fixture
def sleeps():
    return []


def _executor(sleeps, **overrides) -> PaloAltoExecutor:
    config = {
        "hostname": "pan.test",
        "api_key": API_KEY,
        "verify_ssl": True,
        "ca_cert_path": None,
        **overrides,
    }
    return build_executor(config, sleep=sleeps.append)


def _block(target=PUBLIC_V4, **kw) -> TypedAction:
    return TypedAction(action_type="block_ip", target=target, **kw)


# --------------------------------------------------------------------- #
# protocol / factory
# --------------------------------------------------------------------- #


def test_satisfies_the_executor_protocol_and_registers(sleeps):
    ex = _executor(sleeps)
    assert isinstance(ex, Executor)
    assert ex.action_types == {"block_ip", "unblock_ip"}
    assert ex.reversible_types == ex.action_types
    assert ex.default_ttl == timedelta(hours=24)
    registry = ExecutorRegistry()
    registry.register(ex)
    assert registry.reversibility_of("block_ip") == "reversible"


def test_default_ttl_is_configurable(sleeps):
    assert _executor(sleeps, default_ttl_seconds=3600).default_ttl == timedelta(hours=1)


@pytest.mark.parametrize(
    "overrides",
    [
        {"api_key": None},
        {"hostname": ""},
        {"default_ttl_seconds": 0},
        {"default_ttl_seconds": 31 * 24 * 3600},
        {"default_ttl_seconds": "soon"},
        {"tag": "bad tag<>"},
        {"protected_cidrs": ["not-a-cidr"]},
        {"allowed_internal_cidrs": ["10.0.0.0/7"]},
    ],
)
def test_build_executor_refuses_unusable_config(sleeps, overrides):
    with pytest.raises(PanConfigError):
        _executor(sleeps, **overrides)


# --------------------------------------------------------------------- #
# validate
# --------------------------------------------------------------------- #


def test_validate_allows_a_public_ipv4_without_calling_the_firewall(firewall, sleeps):
    result = _executor(sleeps).validate(_block())
    assert result.allowed and not result.requires_approval
    assert firewall.requests == []


def test_validate_allows_a_public_ipv6_and_a_host_prefix(sleeps):
    ex = _executor(sleeps)
    assert ex.validate(_block(PUBLIC_V6)).allowed
    assert ex.validate(_block(f"{PUBLIC_V6}/128")).allowed
    assert ex.validate(_block(f"{PUBLIC_V4}/32")).allowed


@pytest.mark.parametrize(
    "target",
    [
        "10.1.2.3",
        "192.168.1.10",
        "172.16.0.5",
        "100.64.0.1",  # CGNAT
        "fd00::1",  # ULA
        "127.0.0.1",
        "::1",
        "169.254.10.10",
        "fe80::1",
        "224.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "::ffff:185.220.101.1",
    ],
)
def test_validate_refuses_internal_and_special_addresses(sleeps, target):
    result = _executor(sleeps).validate(_block(target))
    assert not result.allowed
    assert result.reasons


@pytest.mark.parametrize(
    "target", ["0.0.0.0/0", "::/0", "185.220.101.0/24", "2a01:4f8::/64", "1.2.3.4/31"]
)
def test_validate_refuses_ranges(sleeps, target):
    result = _executor(sleeps).validate(_block(target))
    assert not result.allowed
    assert "single host" in result.reasons[0]


@pytest.mark.parametrize("target", ["not-an-ip", "1.2.3.4.5", "example.com", " "])
def test_validate_refuses_non_ip_targets(sleeps, target):
    assert not _executor(sleeps).validate(_block(target)).allowed


def test_validate_refuses_a_protected_cidr_even_when_public(sleeps):
    ex = _executor(sleeps, protected_cidrs="185.220.101.0/24, 2a01:4f8::/32")
    v4 = ex.validate(_block(PUBLIC_V4))
    v6 = ex.validate(_block(PUBLIC_V6))
    assert not v4.allowed and "protected range 185.220.101.0/24" in v4.reasons[0]
    assert not v6.allowed and "protected range 2a01:4f8::/32" in v6.reasons[0]


def test_validate_refuses_a_protected_cidr_even_when_internal_is_allowed(sleeps):
    ex = _executor(
        sleeps,
        allowed_internal_cidrs=["10.0.0.0/8"],
        protected_cidrs=["10.0.0.0/24"],
    )
    assert not ex.validate(_block("10.0.0.7")).allowed


def test_validate_refuses_the_firewall_management_address(sleeps):
    ex = _executor(sleeps, hostname="185.220.101.1")
    result = ex.validate(_block(PUBLIC_V4))
    assert not result.allowed
    assert "protected" in result.reasons[0]


def test_allowed_internal_target_needs_a_human(sleeps):
    ex = _executor(sleeps, allowed_internal_cidrs=["10.20.0.0/16"])
    result = ex.validate(_block("10.20.3.4"))
    assert result.allowed and result.requires_approval
    assert not ex.validate(_block("10.21.3.4")).allowed


def test_validate_refuses_a_ttl_beyond_the_pan_os_maximum(sleeps):
    assert not _executor(sleeps).validate(_block(ttl=timedelta(days=31))).allowed


def test_unblock_of_an_internal_address_is_allowed(sleeps):
    """Removing the tag cannot cut anyone off, so the target rules are looser."""
    ex = _executor(sleeps)
    assert ex.validate(TypedAction(action_type="unblock_ip", target="10.1.2.3")).allowed
    assert not ex.validate(
        TypedAction(action_type="unblock_ip", target="10.0.0.0/8")
    ).allowed


def test_validate_refuses_an_unknown_action_type(sleeps):
    result = _executor(sleeps).validate(
        TypedAction(action_type="isolate_host", target=PUBLIC_V4)
    )
    assert not result.allowed


# --------------------------------------------------------------------- #
# execute / verify / reverse
# --------------------------------------------------------------------- #


def test_block_success_records_before_and_after_and_verifies(firewall, sleeps):
    ex = _executor(sleeps)
    action = _block()
    result = ex.execute(action)

    assert result.status == "executed", result
    assert result.before_state == {
        "ip": PUBLIC_V4,
        "tag": DEFAULT_TAG,
        "registered": False,
        "tags": [],
    }
    assert result.after_state["registered"] is True
    assert result.after_state["tags"] == [DEFAULT_TAG]
    assert result.external_ref == f"palo-alto:pan.test:{DEFAULT_TAG}:{PUBLIC_V4}"
    assert firewall.tags[PUBLIC_V4] == {DEFAULT_TAG}

    verified = ex.verify(action, result)
    assert verified.status == "verified"
    assert verified.observed["registered"] is True


def test_block_sends_the_ttl_as_the_timeout_attribute(firewall, sleeps):
    ex = _executor(sleeps)
    ex.execute(_block())
    ex.execute(_block("185.220.101.2", ttl=timedelta(minutes=90)))

    members = [
        ET.fromstring(w["cmd"]).find("./payload/register/entry/tag/member")
        for w in firewall.writes()
    ]
    assert [m.get("timeout") for m in members] == ["86400", "5400"]
    assert [m.text for m in members] == [DEFAULT_TAG, DEFAULT_TAG]


def test_configured_default_ttl_and_tag_reach_the_wire(firewall, sleeps):
    ex = _executor(sleeps, default_ttl_seconds=600, tag="soc-quarantine", vsys="vsys2")
    ex.execute(_block())
    write = firewall.writes()[0]
    member = ET.fromstring(write["cmd"]).find(".//member")
    assert member.get("timeout") == "600"
    assert member.text == "soc-quarantine"
    assert write["vsys"] == "vsys2"


def test_block_is_a_noop_when_the_tag_is_already_registered(firewall, sleeps):
    firewall.tags[PUBLIC_V4] = {DEFAULT_TAG, "other"}
    result = _executor(sleeps).execute(_block())
    assert result.status == "noop"
    assert result.before_state == result.after_state
    assert result.before_state["tags"] == [DEFAULT_TAG, "other"]
    assert firewall.writes() == []


def test_block_twice_acts_once(firewall, sleeps):
    ex = _executor(sleeps)
    assert ex.execute(_block()).status == "executed"
    assert ex.execute(_block()).status == "noop"
    assert len(firewall.writes()) == 1


def test_ipv6_block_and_reverse(firewall, sleeps):
    ex = _executor(sleeps)
    action = _block("2A01:04F8:0::1")  # normalised before it reaches the wire
    result = ex.execute(action)
    assert result.status == "executed"
    entry = ET.fromstring(firewall.writes()[0]["cmd"]).find(".//entry")
    assert entry.get("ip") == PUBLIC_V6
    assert ex.verify(action, result).status == "verified"

    undone = ex.reverse(action, result)
    assert undone.status == "executed"
    assert undone.after_state["registered"] is False
    assert (
        ET.fromstring(firewall.writes()[1]["cmd"]).find("./payload/unregister")
        is not None
    )
    assert firewall.tags[PUBLIC_V6] == set()


def test_reverse_unregisters_what_the_block_added(firewall, sleeps):
    ex = _executor(sleeps)
    action = _block()
    result = ex.execute(action)
    firewall.tags[PUBLIC_V4].add("someone-else")

    undone = ex.reverse(action, result)
    assert undone.status == "executed"
    assert firewall.tags[PUBLIC_V4] == {"someone-else"}
    unregister = ET.fromstring(firewall.writes()[-1]["cmd"]).find(
        "./payload/unregister"
    )
    assert unregister.find(".//member").get("timeout") is None


def test_reverse_of_a_noop_block_leaves_the_prior_tag(firewall, sleeps):
    firewall.tags[PUBLIC_V4] = {DEFAULT_TAG}
    ex = _executor(sleeps)
    action = _block()
    result = ex.execute(action)
    assert result.status == "noop"

    undone = ex.reverse(action, result)
    assert undone.status == "noop"
    assert firewall.tags[PUBLIC_V4] == {DEFAULT_TAG}
    assert firewall.writes() == []


def test_unblock_and_its_reverse(firewall, sleeps):
    firewall.tags[PUBLIC_V4] = {DEFAULT_TAG}
    ex = _executor(sleeps)
    action = TypedAction(action_type="unblock_ip", target=PUBLIC_V4)
    result = ex.execute(action)
    assert result.status == "executed"
    assert result.before_state["registered"] is True
    assert ex.verify(action, result).status == "verified"

    assert ex.execute(action).status == "noop"

    undone = ex.reverse(action, result)
    assert undone.status == "executed"
    assert firewall.tags[PUBLIC_V4] == {DEFAULT_TAG}


def test_reverse_of_a_failed_execute_without_before_state_is_a_noop(firewall, sleeps):
    failed = ExecResult(status="failed", error="read failed")
    assert _executor(sleeps).reverse(_block(), failed).status == "noop"
    assert firewall.requests == []


def test_reverse_refuses_without_before_state(firewall, sleeps):
    executed = ExecResult(status="executed")
    result = _executor(sleeps).reverse(_block(), executed)
    assert result.status == "failed"
    assert "before_state" in result.error


def test_execute_refuses_what_validate_refuses(firewall, sleeps):
    result = _executor(sleeps).execute(_block("10.0.0.1"))
    assert result.status == "failed"
    assert "private" in result.error
    assert firewall.requests == []


def test_verify_mismatch_when_the_tag_is_missing(firewall, sleeps):
    firewall.ignore_writes = True  # the firewall accepts, but nothing sticks
    ex = _executor(sleeps)
    action = _block()
    result = ex.execute(action)
    assert result.status == "executed"
    assert result.after_state["registered"] is False

    verified = ex.verify(action, result)
    assert verified.status == "failed"
    assert verified.observed["tags"] == []
    assert "expected tag" in verified.message


def test_verify_mismatch_after_unblock_when_tag_remains(firewall, sleeps):
    firewall.tags[PUBLIC_V4] = {DEFAULT_TAG}
    firewall.ignore_writes = True
    ex = _executor(sleeps)
    action = TypedAction(action_type="unblock_ip", target=PUBLIC_V4)
    assert ex.verify(action, ex.execute(action)).status == "failed"


def test_verify_is_unknown_when_the_firewall_cannot_be_read(firewall, sleeps):
    firewall.script["op"] = [httpx.Response(503)] * 3
    verified = _executor(sleeps).verify(_block(), ExecResult(status="executed"))
    assert verified.status == "unknown"


# --------------------------------------------------------------------- #
# errors and backoff
# --------------------------------------------------------------------- #


def test_transient_errors_back_off_and_retry(firewall, sleeps):
    firewall.script["op"] = [httpx.Response(503, text="busy"), httpx.Response(429)]
    result = _executor(sleeps).execute(_block())
    assert result.status == "executed"
    assert sleeps == [0.5, 1.0]


def test_transport_errors_are_retried(sleeps):
    fw = FakeFirewall()
    calls = {"n": 0}

    def flaky(request):
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("connection refused", request=request)
        return fw(request)

    with respx.mock(assert_all_called=False) as router:
        router.post(API_URL).mock(side_effect=flaky)
        result = _executor(sleeps).execute(_block())
    assert result.status == "executed"
    assert sleeps == [0.5]


def test_retries_give_up_after_max_attempts(firewall, sleeps):
    firewall.script["op"] = [httpx.Response(502)] * 5
    result = _executor(sleeps, max_attempts=2, backoff_seconds=0.1).execute(_block())
    assert result.status == "failed"
    assert "HTTP 502" in result.error
    assert result.before_state is None
    assert sleeps == [0.1]
    assert firewall.writes() == []


def test_a_pan_os_error_is_not_retried(firewall, sleeps):
    firewall.script["user-id"] = [_err("Invalid tag name")]
    result = _executor(sleeps).execute(_block())
    assert result.status == "failed"
    assert "Invalid tag name" in result.error
    assert result.before_state["registered"] is False
    assert sleeps == []
    assert len(firewall.writes()) == 1


def test_an_http_4xx_is_not_retried(firewall, sleeps):
    firewall.script["op"] = [
        httpx.Response(
            403,
            text="<response status='error'><msg>Invalid credentials.</msg></response>",
        )
    ]
    result = _executor(sleeps).execute(_block())
    assert result.status == "failed"
    assert "HTTP 403" in result.error and "Invalid credentials" in result.error
    assert sleeps == []


def test_register_already_exists_counts_as_success(firewall, sleeps):
    """A retried register whose first attempt landed answers 'already exists'."""

    def landed_but_errored(fw, form):
        fw.tags.setdefault(PUBLIC_V4, set()).add(DEFAULT_TAG)
        return _err(f"{PUBLIC_V4} already exists, ignore")

    firewall.script["user-id"] = [landed_but_errored]
    result = _executor(sleeps).execute(_block())
    assert result.status == "executed"
    assert result.after_state["registered"] is True


def test_unregister_not_registered_counts_as_success(firewall, sleeps):
    """The TTL may expire between the read and the unregister."""
    firewall.tags[PUBLIC_V4] = {DEFAULT_TAG}

    def expired(fw, form):
        fw.tags[PUBLIC_V4].clear()
        return _err(f"{PUBLIC_V4} does not exist")

    firewall.script["user-id"] = [expired]
    result = _executor(sleeps).execute(
        TypedAction(action_type="unblock_ip", target=PUBLIC_V4)
    )
    assert result.status == "executed"
    assert result.after_state["registered"] is False


def test_a_dtd_in_the_response_is_refused(firewall, sleeps):
    firewall.script["op"] = [
        httpx.Response(
            200,
            text='<!DOCTYPE r [<!ENTITY x "y">]><response status="success">&x;</response>',
        )
    ]
    result = _executor(sleeps).execute(_block())
    assert result.status == "failed"
    assert "DTD" in result.error


# --------------------------------------------------------------------- #
# the API key
# --------------------------------------------------------------------- #


def test_api_key_is_sent_as_a_header_and_never_logged(firewall, sleeps, caplog):
    caplog.set_level(logging.DEBUG)
    firewall.script["op"] = [
        httpx.Response(503, text=f"upstream echoed key={API_KEY}"),
    ]
    firewall.script["user-id"] = [
        _err(f"bad request for key {API_KEY}"),
    ]
    ex = _executor(sleeps)
    result = ex.execute(_block())

    assert result.status == "failed"
    assert all(h["x-pan-key"] == API_KEY for h in firewall.headers)
    assert all("key=" not in url and API_KEY not in url for url in firewall.urls)
    assert all("key" not in form for form in firewall.requests)
    assert caplog.records, "the retry should have logged a warning"
    for text in (caplog.text, result.model_dump_json(), repr(ex), repr(ex.connection)):
        assert API_KEY not in text
    assert "***" in result.error


def test_api_key_is_not_in_transport_error_text(sleeps, caplog):
    caplog.set_level(logging.DEBUG)

    def boom(request):
        raise httpx.ConnectError(f"failed {request.url} {API_KEY}", request=request)

    with respx.mock(assert_all_called=False) as router:
        router.post(API_URL).mock(side_effect=boom)
        result = _executor(sleeps).execute(_block())
    assert result.status == "failed"
    assert API_KEY not in caplog.text
    assert API_KEY not in (result.error or "")


# --------------------------------------------------------------------- #
# verifier findings (round 3)
# --------------------------------------------------------------------- #


def _reverse_row(action: TypedAction) -> TypedAction:
    """The reverse row the response service builds: same type/target, reverse_of set."""
    return action.model_copy(update={"reverse_of": "act-original"})


def test_verify_of_a_block_reverse_wants_the_tag_absent(firewall, sleeps):
    """Finding 1: verify honours reverse_of, so a reversed block verifies."""
    ex = _executor(sleeps)
    action = _block()
    result = ex.execute(action)
    reverse_row = _reverse_row(action)
    undone = ex.reverse(reverse_row, result)
    assert undone.status == "executed"
    assert firewall.tags[PUBLIC_V4] == set()

    verified = ex.verify(reverse_row, undone)
    assert verified.status == "verified", verified
    # ...and a reverse that did not stick is still caught.
    firewall.tags[PUBLIC_V4] = {DEFAULT_TAG}
    assert ex.verify(reverse_row, undone).status == "failed"


def test_verify_of_an_unblock_reverse_wants_the_tag_present(firewall, sleeps):
    firewall.tags[PUBLIC_V4] = {DEFAULT_TAG}
    ex = _executor(sleeps)
    action = TypedAction(action_type="unblock_ip", target=PUBLIC_V4)
    result = ex.execute(action)
    reverse_row = _reverse_row(action)
    undone = ex.reverse(reverse_row, result)
    assert undone.status == "executed"
    assert ex.verify(reverse_row, undone).status == "verified"


@pytest.mark.parametrize(
    "overrides, target",
    [
        ({"hostname": "185.220.101.9"}, "185.220.101.9"),  # management IP
        ({"protected_cidrs": "185.220.101.0/24"}, PUBLIC_V4),
        ({}, "10.1.2.3"),  # private, not allow-listed
    ],
)
def test_reverse_of_unblock_runs_the_block_checks(firewall, sleeps, overrides, target):
    """Finding 2: re-registering on reverse is a block and is refused like one."""
    ex = _executor(sleeps, **overrides)
    action = TypedAction(action_type="unblock_ip", target=target)
    assert ex.validate(action).allowed  # unblocking anything is allowed
    # What execute recorded when it removed the tag.
    state = {
        "ip": target,
        "tag": DEFAULT_TAG,
        "registered": True,
        "tags": [DEFAULT_TAG],
    }
    result = ExecResult(
        status="executed",
        before_state=state,
        after_state={**state, "registered": False, "tags": []},
    )
    writes = 0
    reverse_row = _reverse_row(action)
    assert not ex.validate(reverse_row).allowed
    undone = ex.reverse(reverse_row, result)
    assert undone.status == "failed"
    assert "range" in undone.error or "private" in undone.error
    assert len(firewall.writes()) == writes
    assert firewall.requests == []


def test_reverse_of_a_block_is_allowed_even_for_a_now_protected_ip(firewall, sleeps):
    """Removing a tag is never refused by the block checks."""
    ex = _executor(sleeps)
    action = _block()
    result = ex.execute(action)
    later = _executor(sleeps, protected_cidrs=f"{PUBLIC_V4}/32")
    reverse_row = _reverse_row(action)
    assert later.validate(reverse_row).allowed
    assert later.reverse(reverse_row, result).status == "executed"
    assert firewall.tags[PUBLIC_V4] == set()


def test_reverse_of_a_noop_block_never_registers_after_expiry(firewall, sleeps):
    """Finding 3: the prior tag expired in between; the reverse must not add one."""
    firewall.tags[PUBLIC_V4] = {DEFAULT_TAG}
    ex = _executor(sleeps)
    action = _block()
    result = ex.execute(action)
    assert result.status == "noop"
    firewall.tags[PUBLIC_V4] = set()  # the firewall timed the old tag out

    reverse_row = _reverse_row(action)
    undone = ex.reverse(reverse_row, result)
    assert undone.status == "noop"
    assert firewall.writes() == []
    assert firewall.tags[PUBLIC_V4] == set()
    assert ex.verify(reverse_row, undone).status == "verified"


def test_reverse_of_a_noop_unblock_never_registers(firewall, sleeps):
    ex = _executor(sleeps)
    action = TypedAction(action_type="unblock_ip", target=PUBLIC_V4)
    result = ex.execute(action)
    assert result.status == "noop"
    undone = ex.reverse(_reverse_row(action), result)
    assert undone.status == "noop"
    assert firewall.writes() == []


@pytest.mark.parametrize(
    "target",
    ["fe80::1%eth0", "2a01:4f8::1%1", "2a01:4f8::1%</ip><x>", "fe80::1%25eth0/128"],
)
def test_ipv6_scope_ids_are_refused_everywhere(firewall, sleeps, target):
    """Finding 4: a zone index is refused and never reaches the firewall."""
    ex = _executor(sleeps)
    for action_type in ("block_ip", "unblock_ip"):
        action = TypedAction(action_type=action_type, target=target)
        verdict = ex.validate(action)
        assert not verdict.allowed
        assert "scope id" in verdict.reasons[0]
        assert ex.execute(action).status == "failed"
        assert ex.verify(action, ExecResult(status="executed")).status == "unknown"
        assert ex.reverse(action, ExecResult(status="executed")).status == "failed"
    assert firewall.requests == []


def test_op_and_uid_xml_values_are_escaped(firewall, sleeps):
    """Every value in the op/uid XML is escaped; the commands stay well-formed."""
    ex = _executor(sleeps)
    ex.execute(_block())
    for req in firewall.requests:
        ET.fromstring(req["cmd"])  # parses: nothing leaked markup into it
    op = next(r for r in firewall.requests if r["type"] == "op")
    assert ET.fromstring(op["cmd"]).findtext(".//ip") == PUBLIC_V4
    # The executor's own escaping holds even for a value the tag regex would
    # never let through.
    ex.tag = "a<b&c"
    msg = ex._uid_message("register", ipaddress.ip_address(PUBLIC_V4), 60)
    assert ET.fromstring(msg).findtext(".//member") == "a<b&c"


@pytest.mark.parametrize("value", [True, False, 1.5])
def test_default_ttl_seconds_rejects_bool_and_fractions(sleeps, value):
    with pytest.raises(PanConfigError):
        _executor(sleeps, default_ttl_seconds=value)
