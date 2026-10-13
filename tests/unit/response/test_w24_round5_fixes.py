"""Regressions for the W2.4 round 5 verifier findings (docs/wp/w2.4.md).

1. a subdomain-matching action (gateway_block) on a parent domain of a
   protected name, a public suffix or a single label is refused;
2. names are compared after NFKC and IDNA (``bücher.de`` is
   ``xn--bcher-kva.de``; fullwidth forms are their ASCII);
3. account forms cross-match (``svc-admin``, ``svc-admin@corp.com``,
   ``CORP\\svc-admin``);
4. a row is claimed before the vendor call; a failed claim never executes and
   a failed ``mark_executed`` is reported as a failure and never re-executed;
5. undo-direction types (unblock_ip, unisolate_host, enable_user) never get
   an expiry, so the TTL sweep cannot re-apply what an analyst lifted;
6. end to end through the registry wiring for Microsoft Defender and Palo Alto
   (respx-mocked HTTP; the dispatcher, policy and executor are all real).
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import timedelta
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from core.response.approval_service import PendingAction
from core.response.autonomous_response_service import AutonomousResponseService
from core.response.config import ResponseConfig
from core.response.executors.base import (
    ExecResult,
    ExecutorRegistry,
    PolicyResult,
    TypedAction,
    VerifyResult,
)
from core.response.executors.wiring import build_executor_registry
from core.response.policy import (
    ActionPolicy,
    PolicyConfig,
    identify,
    is_public_suffix,
)
from core.time import utcnow

pytestmark = pytest.mark.unit


# --- fakes ---------------------------------------------------------------------


class _Fake:
    def __init__(self, types_=("waf_block",), ttl=timedelta(hours=1)):
        self.action_types = frozenset(types_)
        self.reversible_types = frozenset(types_)
        self.default_ttl = ttl
        self.executed: list[TypedAction] = []

    def validate(self, action):
        return PolicyResult.allow()

    def execute(self, action):
        self.executed.append(action)
        return ExecResult(
            status="executed", before_state={"on": False}, after_state={"on": True}
        )

    def verify(self, action, result):
        return VerifyResult(status="verified")

    def reverse(self, action, result):
        return ExecResult(status="executed")


def _row(action_id="a-1", **kw):
    base: dict[str, Any] = dict(
        action_id=action_id,
        action_type="waf_block",
        title="t",
        description="d",
        target="203.0.113.7",
        confidence=0.99,
        reason="r",
        evidence=[],
        created_at="",
        created_by="responder",
        requires_approval=True,
        status="approved",
        approved_by="alice",
        parameters={},
    )
    base.update(kw)
    return PendingAction(**base)


class _Approvals:
    """In-memory approvals with the claim semantics of the real service."""

    def __init__(self, rows=(), *, record_fails=False, claim_fails=False):
        self.rows = {r.action_id: r for r in rows}
        self.claimed: set[str] = set()
        self.executed: dict[str, dict] = {}
        self.failed: dict[str, str] = {}
        self.reversals: list[dict] = []
        self.record_fails = record_fails
        self.claim_fails = claim_fails

    def list_actions(self, status=None, **_):
        # The real query re-reads executed_at; a claimed row carries it.
        out = []
        for row in self.rows.values():
            if row.action_id in self.claimed and not row.executed_at:
                row.executed_at = "claimed"
            if row.status == "approved":
                out.append(row)
        return out

    def get_action(self, action_id):
        return self.rows.get(action_id)

    def claim_execution(self, action_id):
        if self.claim_fails or action_id in self.claimed:
            return False
        self.claimed.add(action_id)
        return True

    def mark_executed(self, action_id, result, **lifecycle):
        if self.record_fails:
            return None  # what the real service returns on SQLAlchemyError
        self.executed[action_id] = {"result": result, **lifecycle}
        row = self.rows[action_id]
        row.status = "executed"
        row.execution_result = result
        row.before_state = lifecycle.get("before_state")
        row.after_state = lifecycle.get("after_state")
        row.expires_at = lifecycle.get("expires_at")
        return row

    def mark_failed(self, action_id, error):
        self.failed[action_id] = error
        if action_id in self.rows:
            self.rows[action_id].status = "failed"

    def record_verification(self, action_id, verify_status):
        self.executed[action_id]["verify_status"] = verify_status

    def count_executed_since(self, action_type, since):
        return 0

    def list_expired(self, now):
        return [
            self.rows[i]
            for i, ex in self.executed.items()
            if ex.get("expires_at") is not None and ex["expires_at"] <= now
        ]

    def begin_reversal(self, original_id, actor, reason):
        return _row(f"rev-{original_id}", reverse_of=original_id)

    def finish_reversal(self, reverse_id, **kw):
        self.reversals.append({"reverse_id": reverse_id, **kw})
        return _row(reverse_id)


def _service(approvals, registry, config=None):
    return AutonomousResponseService(
        approvals=approvals,
        config=ResponseConfig(),
        executors=registry,
        policy=ActionPolicy(config or PolicyConfig()),
    )


def _registry(*executors):
    registry = ExecutorRegistry()
    for executor in executors:
        registry.register(executor)
    return registry


def _verdict(config, action_type, target, **params):
    return ActionPolicy(config).evaluate(
        TypedAction(action_type=action_type, target=target, parameters=params),
        registry=None,
    )


# --- 1. parent domains and public suffixes -----------------------------------------

_DC = PolicyConfig.from_mapping(
    {
        "protected_targets": ["dc01.corp.local", "payroll.example.org"],
        "asset_tags": {"vault.secure.example.net": ["tier0"]},
    }
)


class TestParentDomains:
    @pytest.mark.parametrize(
        "target",
        [
            "corp.local",
            "CORP.LOCAL.",
            "*.corp.local",
            "example.org",
            "secure.example.net",  # parent of a tagged asset
            "example.net",
            "dc01.corp.local",  # equal, as before
        ],
    )
    def test_a_parent_of_a_protected_name_is_refused(self, target):
        verdict = _verdict(_DC, "gateway_block", target)
        assert not verdict.allowed, target
        assert "protected asset" in verdict.reasons[0]

    def test_the_domain_parameter_is_checked_too(self):
        verdict = _verdict(_DC, "gateway_block", "evil.test", domain="corp.local")
        assert not verdict.allowed

    @pytest.mark.parametrize(
        "target",
        ["com", "local", "co.uk", "com.au", "gov.br", "github.io", "AMAZONAWS.COM"],
    )
    def test_a_public_suffix_or_single_label_is_refused(self, target):
        verdict = _verdict(PolicyConfig(), "gateway_block", target)
        assert not verdict.allowed, target
        assert "public suffix" in verdict.reasons[0]

    @pytest.mark.parametrize(
        "target", ["evil.example.com", "malware.co.uk", "phish.test", "bad.co"]
    )
    def test_ordinary_domains_still_pass(self, target):
        assert _verdict(_DC, "gateway_block", target).allowed, target

    def test_a_child_of_a_protected_name_is_not_its_parent(self):
        # Blocking a subdomain of a protected name does not block the name.
        assert _verdict(_DC, "gateway_block", "x.dc01.corp.local").allowed

    def test_types_that_match_exactly_are_not_affected(self):
        # disable_user acts on exactly the name it is given.
        assert _verdict(_DC, "disable_user", "corp.local").allowed

    def test_config_can_add_a_subdomain_matching_type(self):
        cfg = PolicyConfig.from_mapping(
            {
                "protected_targets": ["dc01.corp.local"],
                "subdomain_matching_types": ["dns_sinkhole"],
            }
        )
        assert not _verdict(cfg, "dns_sinkhole", "corp.local").allowed
        assert not _verdict(cfg, "gateway_block", "corp.local").allowed

    def test_is_public_suffix(self):
        assert is_public_suffix("uk") and is_public_suffix("co.uk")
        assert not is_public_suffix("bbc.co.uk")
        assert not is_public_suffix("corp.example")


# --- 2. IDNA / NFKC ----------------------------------------------------------------


class TestUnicodeNames:
    def test_idna_spellings_are_one_name(self):
        assert identify("bücher.de").name == "xn--bcher-kva.de"
        assert identify("XN--BCHER-KVA.DE").name == "xn--bcher-kva.de"
        assert identify("BÜCHER.de").name == "xn--bcher-kva.de"

    @pytest.mark.parametrize(
        "protected,target",
        [
            ("bücher.de", "xn--bcher-kva.de"),
            ("xn--bcher-kva.de", "bücher.de"),
            ("dc01.corp.local", "ｄｃ０１.corp.local"),  # fullwidth
            ("dc01.corp.local", "dc01。corp。local"),  # ideographic full stop
            ("dc01.corp.local", "dc01．corp．local"),  # fullwidth full stop
            ("10.0.0.5", "１０.０.０.５"),  # fullwidth digits
        ],
    )
    def test_a_protected_name_in_another_spelling_is_refused(self, protected, target):
        cfg = PolicyConfig.from_mapping({"protected_targets": [protected]})
        for action_type in ("gateway_block", "isolate_host"):
            verdict = _verdict(cfg, action_type, target)
            assert not verdict.allowed, (action_type, target)

    def test_a_parent_in_unicode_of_a_punycode_name_is_refused(self):
        cfg = PolicyConfig.from_mapping(
            {"protected_targets": ["shop.xn--bcher-kva.de"]}
        )
        assert not _verdict(cfg, "gateway_block", "bücher.de").allowed

    def test_a_unicode_mailbox_domain_is_normalised(self):
        cfg = PolicyConfig.from_mapping({"protected_targets": ["ceo@bücher.de"]})
        assert not _verdict(cfg, "access_revoke", "CEO@xn--bcher-kva.de").allowed


# --- 3. account forms ------------------------------------------------------------


class TestAccountForms:
    @pytest.mark.parametrize(
        "protected", ["svc-admin", "svc-admin@corp.com", "CORP\\svc-admin"]
    )
    @pytest.mark.parametrize(
        "target",
        ["svc-admin", "SVC-ADMIN@corp.com", "corp\\Svc-Admin", "svc-admin@CORP.COM"],
    )
    def test_every_form_matches_every_other(self, protected, target):
        cfg = PolicyConfig.from_mapping({"protected_targets": [protected]})
        verdict = _verdict(cfg, "disable_user", target)
        assert not verdict.allowed, (protected, target)

    def test_the_user_parameter_is_matched_too(self):
        cfg = PolicyConfig.from_mapping({"protected_targets": ["svc-admin@corp.com"]})
        assert not _verdict(
            cfg, "revoke_sessions", "someone@corp.com", user="CORP\\svc-admin"
        ).allowed

    def test_other_accounts_pass(self):
        cfg = PolicyConfig.from_mapping({"protected_targets": ["svc-admin@corp.com"]})
        assert _verdict(cfg, "disable_user", "svc-admin2@corp.com").allowed
        assert _verdict(cfg, "disable_user", "CORP\\alice").allowed


# --- 4. claim before execute; a failed record is a failure, never a re-run ----------


class TestExecuteOnce:
    def test_a_failed_mark_executed_is_a_failure_and_never_re_executes(self):
        executor = _Fake()
        approvals = _Approvals([_row()], record_fails=True)
        service = _service(approvals, _registry(executor))

        first = service.execute_approved_actions()
        assert len(executor.executed) == 1
        result = first[0]["result"]
        assert result["success"] is False
        assert result["error"].startswith("executed_unrecorded")

        # The row is still "approved" (recording failed), but it is claimed.
        assert approvals.rows["a-1"].status == "approved"
        service.execute_approved_actions()
        service.execute_approved_actions()
        assert len(executor.executed) == 1

    def test_an_unclaimable_row_never_reaches_the_vendor(self):
        executor = _Fake()
        approvals = _Approvals([_row()], claim_fails=True)
        results = _service(approvals, _registry(executor)).execute_approved_actions()
        assert executor.executed == []
        assert results[0]["result"]["status"] == "skipped"
        assert "a-1" not in approvals.failed

    def test_isolate_host_without_executor_is_claimed_too(self, monkeypatch):
        approvals = _Approvals(
            [_row(action_type="isolate_host", target="10.0.0.9")], claim_fails=True
        )
        service = _service(approvals, ExecutorRegistry())
        calls = []
        monkeypatch.setattr(
            service, "_execute_isolation", lambda **kw: calls.append(kw) or {}
        )
        service.execute_approved_actions()
        assert calls == []


# --- 5. undo types never expire ---------------------------------------------------


class TestUndoTypesDoNotExpire:
    @pytest.mark.parametrize("undo", ["unblock_ip", "unisolate_host", "enable_user"])
    def test_no_expiry_from_the_executor_default(self, undo):
        executor = _Fake(types_=(undo,), ttl=timedelta(hours=1))
        approvals = _Approvals([_row(action_type=undo)])
        _service(approvals, _registry(executor)).execute_approved_actions()
        assert executor.executed
        assert approvals.executed["a-1"]["expires_at"] is None

    def test_an_explicit_ttl_on_an_undo_is_refused(self):
        executor = _Fake(types_=("unblock_ip",))
        approvals = _Approvals(
            [_row(action_type="unblock_ip", parameters={"ttl_seconds": 600})]
        )
        _service(approvals, _registry(executor)).execute_approved_actions()
        assert executor.executed == []
        assert "cannot expire" in approvals.failed["a-1"]

    def test_the_forward_type_still_expires(self):
        executor = _Fake(types_=("block_ip",), ttl=timedelta(hours=1))
        approvals = _Approvals([_row(action_type="block_ip")])
        _service(approvals, _registry(executor)).execute_approved_actions()
        assert approvals.executed["a-1"]["expires_at"] is not None

    def test_config_can_add_an_undo_type(self):
        cfg = PolicyConfig.from_mapping({"undo_types": ["allow_domain"]})
        assert not cfg.takes_ttl("allow_domain") and not cfg.takes_ttl("unblock_ip")
        assert cfg.takes_ttl("block_ip")


# --- 6. end to end through the registry wiring -------------------------------------


def _wire(monkeypatch, stored, secrets):
    import core.config
    import core.integrations._base.config as base_config

    monkeypatch.setattr(
        core.config, "get_integration_config", lambda i: dict(stored.get(i, {}))
    )
    monkeypatch.setattr(
        base_config, "get_integration_config", lambda i: dict(stored.get(i, {}))
    )
    monkeypatch.setattr(base_config, "get_secret", lambda key: secrets.get(key))
    return build_executor_registry(enabled=lambda i: i in stored)


MDE_API = "https://api.securitycenter.microsoft.com/api"
MDE_TOKEN = "https://login.microsoftonline.com/tid/oauth2/v2.0/token"
MID = "a" * 40
MACHINE = {
    "id": MID,
    "computerDnsName": "ws-01.corp.example",
    "healthStatus": "Active",
    "onboardingStatus": "Onboarded",
    "lastSeen": "2026-10-12T08:00:00Z",
    "lastIpAddress": "10.0.0.5",
    "osPlatform": "Windows11",
}


def _defender_registry(monkeypatch, **extra):
    from core.integrations.integration_secrets import secret_fields_for

    key = secret_fields_for("microsoft-defender")["client_secret"]
    return _wire(
        monkeypatch,
        {
            "microsoft-defender": {
                "tenant_id": "tid",
                "client_id": "cid",
                "verify_timeout_seconds": 5,
                "poll_interval_seconds": 0.01,
                **extra,
            }
        },
        {key: "mde-secret"},
    )


@pytest.fixture
def mde():
    with respx.mock(assert_all_called=False) as router:
        router.post(MDE_TOKEN).mock(
            return_value=httpx.Response(200, json={"access_token": "tok"})
        )
        router.get(f"{MDE_API}/machines").mock(
            return_value=httpx.Response(200, json={"value": [MACHINE]})
        )
        router.get(f"{MDE_API}/machines/{MID}").mock(
            return_value=httpx.Response(200, json=MACHINE)
        )
        router.get(f"{MDE_API}/machineactions/ma-1").mock(
            return_value=httpx.Response(
                200, json={"id": "ma-1", "type": "Isolate", "status": "Succeeded"}
            )
        )
        router.get(f"{MDE_API}/machineactions/ma-2").mock(
            return_value=httpx.Response(
                200, json={"id": "ma-2", "type": "Unisolate", "status": "Succeeded"}
            )
        )
        yield router


class TestDefenderEndToEnd:
    def test_wiring_registers_defender_with_its_secret(self, monkeypatch):
        registry = _defender_registry(monkeypatch)
        assert type(registry.get("isolate_host")).__name__ == (
            "DefenderIsolationExecutor"
        )
        assert registry.get("unisolate_host") is registry.get("isolate_host")

    def test_isolate_runs_through_policy_executor_and_verify(self, monkeypatch, mde):
        mde.get(f"{MDE_API}/machineactions").mock(
            return_value=httpx.Response(200, json={"value": []})
        )
        post = mde.post(f"{MDE_API}/machines/{MID}/isolate").mock(
            return_value=httpx.Response(201, json={"id": "ma-1", "status": "Pending"})
        )
        registry = _defender_registry(monkeypatch, isolation_ttl=3600)
        approvals = _Approvals(
            [_row(action_type="isolate_host", target="ws-01.corp.example")]
        )
        results = _service(approvals, registry).execute_approved_actions()

        assert results[0]["result"]["success"] is True, results
        assert post.call_count == 1
        body = json.loads(post.calls.last.request.content)
        assert body["IsolationType"] == "Full"
        assert post.calls.last.request.headers["Authorization"] == "Bearer tok"
        recorded = approvals.executed["a-1"]
        assert recorded["verify_status"] == "verified"
        assert recorded["after_state"]["isolated"] is True
        # The configured isolation ttl becomes the expiry of the forward type.
        assert recorded["expires_at"] == recorded["executed_at"] + timedelta(hours=1)

    def test_unisolate_gets_no_expiry_even_with_an_isolation_ttl(
        self, monkeypatch, mde
    ):
        mde.get(f"{MDE_API}/machineactions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "ma-0",
                            "type": "Isolate",
                            "status": "Succeeded",
                            "creationDateTimeUtc": "2026-10-12T07:00:00Z",
                        }
                    ]
                },
            )
        )
        post = mde.post(f"{MDE_API}/machines/{MID}/unisolate").mock(
            return_value=httpx.Response(201, json={"id": "ma-2", "status": "Pending"})
        )
        registry = _defender_registry(monkeypatch, isolation_ttl=3600)
        approvals = _Approvals(
            [_row(action_type="unisolate_host", target="ws-01.corp.example")]
        )
        service = _service(approvals, registry)
        results = service.execute_approved_actions()
        assert results[0]["result"]["success"] is True, results
        assert post.call_count == 1
        assert approvals.executed["a-1"]["expires_at"] is None
        # Nothing for the sweep to re-isolate.
        assert service.sweep_expired(utcnow() + timedelta(days=60)) == []

    def test_a_protected_host_never_reaches_defender(self, monkeypatch, mde):
        isolate = mde.post(f"{MDE_API}/machines/{MID}/isolate")
        registry = _defender_registry(monkeypatch)
        approvals = _Approvals(
            [_row(action_type="isolate_host", target="ＷＳ-01.corp.example")]
        )
        cfg = PolicyConfig.from_mapping({"protected_targets": ["ws-01"]})
        _service(approvals, registry, cfg).execute_approved_actions()
        assert "protected asset" in approvals.failed["a-1"]
        assert not isolate.called
        assert not any("/machines" in str(c.request.url) for c in mde.calls)


PAN_URL = "https://pan.test/api/"
PUBLIC = "185.220.101.1"


class _Firewall:
    """Registered tags per IP, as PAN-OS keeps them."""

    def __init__(self) -> None:
        self.tags: dict[str, set[str]] = {}
        self.writes: list[dict[str, str]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        if form.get("type") == "op":
            ip = ET.fromstring(form["cmd"]).findtext(".//ip")
            tags = self.tags.get(ip, set())
            entries = (
                f'<entry ip="{ip}" from_agent="0" persistent="1"><tag>'
                + "".join(f"<member>{t}</member>" for t in sorted(tags))
                + "</tag></entry>"
                if tags
                else ""
            )
            return _pan_ok(
                f"<result>{entries}<count>{1 if tags else 0}</count></result>"
            )
        if form.get("type") == "user-id":
            self.writes.append(form)
            msg = ET.fromstring(form["cmd"])
            for verb in ("register", "unregister"):
                for entry in msg.findall(f"./payload/{verb}/entry"):
                    members = {m.text for m in entry.iter("member")}
                    current = self.tags.setdefault(entry.get("ip"), set())
                    if verb == "register":
                        current |= members
                    else:
                        current -= members
            return _pan_ok("<result><uid-response/></result>")
        return httpx.Response(400)


def _pan_ok(inner: str) -> httpx.Response:
    return httpx.Response(200, text=f'<response status="success">{inner}</response>')


@pytest.fixture
def firewall():
    fw = _Firewall()
    with respx.mock(assert_all_called=False) as router:
        router.post(PAN_URL).mock(side_effect=fw)
        yield fw


def _pan_registry(monkeypatch):
    from core.integrations.integration_secrets import secret_fields_for

    key = secret_fields_for("palo-alto")["api_key"]
    return _wire(
        monkeypatch,
        {
            "palo-alto": {
                "hostname": "pan.test",
                "verify_ssl": True,
                "default_ttl_seconds": 7200,
            }
        },
        {key: "pan-key"},
    )


class TestPaloAltoEndToEnd:
    def test_wiring_registers_palo_alto_with_its_secret(self, monkeypatch):
        registry = _pan_registry(monkeypatch)
        assert type(registry.get("block_ip")).__name__ == "PaloAltoExecutor"
        assert registry.get("unblock_ip") is registry.get("block_ip")

    def test_block_expires_and_the_sweep_lifts_it(self, monkeypatch, firewall):
        registry = _pan_registry(monkeypatch)
        approvals = _Approvals([_row(action_type="block_ip", target=PUBLIC)])
        service = _service(approvals, registry)
        results = service.execute_approved_actions()

        assert results[0]["result"]["success"] is True, results
        assert firewall.tags[PUBLIC] == {"autosecops-block"}
        recorded = approvals.executed["a-1"]
        assert recorded["verify_status"] == "verified"
        assert recorded["expires_at"] == recorded["executed_at"] + timedelta(hours=2)

        swept = service.sweep_expired(recorded["expires_at"] + timedelta(seconds=1))
        assert [s["outcome"] for s in swept] == ["reversed"], swept
        assert firewall.tags[PUBLIC] == set()

    def test_an_unblock_does_not_expire_so_the_block_stays_lifted(
        self, monkeypatch, firewall
    ):
        firewall.tags[PUBLIC] = {"autosecops-block"}
        registry = _pan_registry(monkeypatch)
        approvals = _Approvals([_row(action_type="unblock_ip", target=PUBLIC)])
        service = _service(approvals, registry)
        results = service.execute_approved_actions()

        assert results[0]["result"]["success"] is True, results
        assert firewall.tags[PUBLIC] == set()
        assert approvals.executed["a-1"]["expires_at"] is None
        assert service.sweep_expired(utcnow() + timedelta(days=60)) == []
        assert firewall.tags[PUBLIC] == set()

    def test_a_protected_address_never_reaches_the_firewall(
        self, monkeypatch, firewall
    ):
        registry = _pan_registry(monkeypatch)
        approvals = _Approvals(
            [_row(action_type="block_ip", target="::ffff:185.220.101.1")]
        )
        cfg = PolicyConfig.from_mapping({"protected_targets": ["185.220.101.0/28"]})
        _service(approvals, registry, cfg).execute_approved_actions()
        assert "protected asset" in approvals.failed["a-1"]
        assert firewall.writes == []

    def test_a_failed_record_is_not_blocked_twice(self, monkeypatch, firewall):
        registry = _pan_registry(monkeypatch)
        approvals = _Approvals(
            [_row(action_type="block_ip", target=PUBLIC)], record_fails=True
        )
        service = _service(approvals, registry)
        service.execute_approved_actions()
        service.execute_approved_actions()
        assert len(firewall.writes) == 1


# --- 4b. the claim against the real table ----------------------------------------


@pytest.mark.external_service
@pytest.mark.database
class TestClaimInTheDatabase:
    @pytest.fixture
    def approved(self, throwaway_database):
        import uuid

        from core.storage.models import ApprovalAction
        from core.storage.unit_of_work import unit_of_work

        action_id = f"claim-{uuid.uuid4().hex[:12]}"
        with unit_of_work() as session:
            session.add(
                ApprovalAction(
                    action_id=action_id,
                    action_type="waf_block",
                    title="t",
                    description="d",
                    target="203.0.113.7",
                    confidence=0.99,
                    reason="r",
                    evidence=[],
                    created_by="pytest",
                    requires_approval=True,
                    status="approved",
                    approved_by="alice",
                    created_at=utcnow(),
                    parameters={},
                )
            )
        return action_id

    def test_one_claim_wins(self, approved):
        from core.response.approval_service import ApprovalService

        svc = ApprovalService()
        assert svc.claim_execution(approved) is True
        assert svc.claim_execution(approved) is False
        row = svc.get_action(approved)
        assert row.status == "approved" and row.executed_at

    def test_a_failed_record_is_never_dispatched_again(self, approved, monkeypatch):
        from sqlalchemy.exc import OperationalError

        from core.response.approval_service import ApprovalService

        svc = ApprovalService()
        executor = _Fake()
        service = _service(svc, _registry(executor))

        real = ApprovalService.mark_executed

        def broken(self, *a, **kw):
            import core.response.approval_service as mod

            original = mod.get_db_manager

            def explode():
                raise OperationalError("UPDATE", {}, Exception("db went away"))

            monkeypatch.setattr(mod, "get_db_manager", explode)
            try:
                return real(self, *a, **kw)
            finally:
                monkeypatch.setattr(mod, "get_db_manager", original)

        monkeypatch.setattr(ApprovalService, "mark_executed", broken)
        first = service.execute_approved_actions()
        assert first[0]["result"]["error"].startswith("executed_unrecorded")
        service.execute_approved_actions()
        assert len(executor.executed) == 1
        assert svc.get_action(approved).executed_at

    def test_a_row_not_approved_cannot_be_claimed(self, approved):
        from core.response.approval_service import ApprovalService

        svc = ApprovalService()
        svc.mark_failed(approved, "x")
        assert svc.claim_execution(approved) is False
