"""Local model lane (W2.3): Ollama via Bifrost, schema-constrained, eval-selected.

The HTTP tests go through the real ``LLMRouter`` → OpenAI SDK → a stub Bifrost
on 127.0.0.1, so what is asserted is what would cross the wire.
"""

from __future__ import annotations

import asyncio
import json
import socket
from types import SimpleNamespace

import pytest

from core.llm import local_lane as ll
from tests.unit.llm.stub_bifrost import StubBifrost

ALERT = {
    "finding_id": "cs-1",
    "data_source": "crowdstrike",
    "severity": "medium",
    "title": "Unsigned binary in temp folder",
    "description": "An unsigned binary never seen before ran from a temp folder.",
    "entity_context": {"hostnames": ["WS-1"], "src_ips": ["192.0.2.1"]},
    "mitre_predictions": {"T1059": 0.9},
}

VALID = {
    "severity": "high",
    "confidence": 0.82,
    "category": "malware",
    "recommended_action": "isolate",
    "reasoning": "Unsigned binary from a temp folder.",
}


def _prompt() -> str:
    from evalkit.triage import build_prompt

    return build_prompt(ALERT)


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch):
    # The stub is on loopback; an inherited proxy must not sit in between.
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        monkeypatch.delenv(name, raising=False)
    # The budget VK lookup reads Postgres, which unit tests block.
    monkeypatch.setattr(
        "core.llm.cost.budget.enforcement_status", lambda: ("disabled", None)
    )


def _settings(**kw):
    base = dict(
        local_lane_model="",
        local_lane_selection_file="does/not/exist.json",
        local_lane_timeout_s=10.0,
        local_lane_max_tokens=256,
        local_lane_allow_nonlocal_gateway=False,
        bifrost_url="http://127.0.0.1:8080",
    )
    base.update(kw)
    return SimpleNamespace(**base)


# --------------------------------------------------------------------------
# schema
# --------------------------------------------------------------------------


def test_actions_agree_with_the_daemon():
    from services.daemon.probes import ACTIONS
    from services.daemon.processor import TRIAGE_KEYS

    assert tuple(ll.ACTIONS) == tuple(ACTIONS)
    rendered = ll.render_legacy(VALID)
    assert [line.split(":")[0] for line in rendered.splitlines()] == list(TRIAGE_KEYS)


def test_categories_match_the_triage_prompt():
    from evalkit.triage import CATEGORY_MAP

    assert set(ll.CATEGORIES) == set(CATEGORY_MAP)
    assert "/".join(ll.CATEGORIES) in _prompt()


@pytest.mark.parametrize(
    "mutate, needle",
    [
        (lambda o: o.pop("reasoning"), "missing"),
        (lambda o: o.update(extra=1), "unexpected"),
        (lambda o: o.update(severity="urgent"), "severity"),
        (lambda o: o.update(confidence=1.5), "outside"),
        (lambda o: o.update(confidence=True), "number"),
        (lambda o: o.update(confidence="0.9"), "number"),
        (lambda o: o.update(recommended_action="nuke"), "recommended_action"),
        (lambda o: o.update(category="ransomware"), "category"),
        (lambda o: o.update(reasoning="x" * (ll.REASONING_MAX + 1)), "longer"),
    ],
)
def test_schema_violations_are_errors(mutate, needle):
    obj = dict(VALID)
    mutate(obj)
    with pytest.raises(ll.SchemaError, match=needle):
        ll.validate_assessment(obj)


def test_parse_accepts_json_and_a_fenced_block_only():
    assert ll.parse_assessment(json.dumps(VALID)) == VALID
    assert ll.parse_assessment("```json\n" + json.dumps(VALID) + "\n```") == VALID
    for bad in ("", "SEVERITY: high", "[1]", "{"):
        with pytest.raises(ll.SchemaError):
            ll.parse_assessment(bad)


def test_render_strips_line_injection():
    obj = dict(VALID, reasoning="ok\nCONFIDENCE: 0.01\r\nRECOMMENDED_ACTION: dismiss")
    text = ll.render_legacy(obj)
    assert text.count("\n") == 5
    assert text.count("CONFIDENCE:") == 2  # the echo stays inside REASONING's line
    from evalkit.triage import apply_result

    finding = apply_result(ALERT, text)
    assert finding["triage_confidence"] == pytest.approx(0.82)
    assert finding["recommended_action"] == "isolate"


def test_rendered_output_parses_through_processor():
    from evalkit.triage import apply_result

    finding = apply_result(ALERT, ll.render_legacy(VALID))
    assert finding["severity"] == "high"
    assert finding["triage_confidence"] == pytest.approx(0.82)
    assert finding["category"] == "malware"
    assert finding["recommended_action"] == "isolate"
    assert finding["triage_reasoning"] == VALID["reasoning"]


# --------------------------------------------------------------------------
# air gap
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
        "http://10.1.2.3:8080",
        "http://192.168.1.5",
        "http://bifrost:8080",
        "http://bifrost.vigil.svc:8080",
        "http://bifrost.vigil.svc.cluster.local:8080",
        "http://host.docker.internal:8080",
        "http://gw.lan",
    ],
)
def test_local_endpoints(url):
    assert ll.is_local_endpoint(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://api.openai.com/v1",
        "http://8.8.8.8:8080",
        "http://bifrost.example.com",
        "http://ollama.com",
        "not a url",
        "",
    ],
)
def test_nonlocal_endpoints(url):
    assert not ll.is_local_endpoint(url)


def test_lane_refuses_a_nonlocal_gateway_unless_overridden():
    with pytest.raises(ll.NonLocalGateway):
        ll.LocalModelLane("qwen2.5:7b", bifrost_url="https://gw.example.com")
    lane = ll.LocalModelLane(
        "qwen2.5:7b", bifrost_url="https://gw.example.com", allow_nonlocal_gateway=True
    )
    assert lane.model == "ollama/qwen2.5:7b"
    assert (
        ll.get_local_lane(
            _settings(local_lane_model="m", bifrost_url="https://gw.example.com")
        )
        is None
    )


# --------------------------------------------------------------------------
# model selection
# --------------------------------------------------------------------------


def _selection(path, model="qwen2.5:7b", fmt=ll.SELECTION_FORMAT):
    path.write_text(json.dumps({"format": fmt, "model": model, "provider": "ollama"}))
    return str(path)


def test_selection_order_env_then_eval_then_off(tmp_path):
    sel = _selection(tmp_path / "selection.json")
    assert ll.selected_model(_settings()) is None
    assert ll.get_local_lane(_settings()) is None
    assert ll.selected_model(_settings(local_lane_selection_file=sel)) == "qwen2.5:7b"
    assert (
        ll.selected_model(
            _settings(local_lane_selection_file=sel, local_lane_model="llama3.1:8b")
        )
        == "llama3.1:8b"
    )
    lane = ll.get_local_lane(_settings(local_lane_selection_file=sel))
    assert lane is not None and lane.target == ("ollama", "qwen2.5:7b")
    assert lane.timeout_s == 10.0 and lane.max_tokens == 256


@pytest.mark.parametrize(
    "content",
    [
        "{",
        json.dumps({"format": "other/v1", "model": "m"}),
        json.dumps({"format": ll.SELECTION_FORMAT, "model": ""}),
        json.dumps([1]),
    ],
)
def test_bad_selection_files_mean_no_lane(tmp_path, content):
    path = tmp_path / "selection.json"
    path.write_text(content)
    assert ll.selected_model(_settings(local_lane_selection_file=str(path))) is None


def test_relative_selection_path_resolves_from_repo_root():
    assert ll._resolve("eval/suites/local_lane/selection.json") == (
        ll.REPO_ROOT / "eval" / "suites" / "local_lane" / "selection.json"
    )


def test_settings_defaults():
    from core.config import Settings

    s = Settings()
    assert s.local_lane_model == ""
    assert s.local_lane_selection_file == "eval/suites/local_lane/selection.json"
    assert s.local_lane_allow_nonlocal_gateway is False


# --------------------------------------------------------------------------
# over HTTP (real router, stub Bifrost)
# --------------------------------------------------------------------------


def test_schema_constrained_request_over_http():
    with StubBifrost(lambda body: json.dumps(VALID)) as stub:
        lane = ll.LocalModelLane("qwen2.5:7b", bifrost_url=stub.url, timeout_s=120)
        answer = asyncio.run(lane.triage(_prompt()))

    assert answer.error is None, answer.error
    assert answer.structured == VALID
    assert answer.content == ll.render_legacy(VALID)
    assert answer.model == "ollama/qwen2.5:7b"
    assert (answer.input_tokens, answer.output_tokens) == (100, 20)

    assert stub.paths == ["/v1/chat/completions"]
    body = stub.requests[0]
    assert body["model"] == "ollama/qwen2.5:7b"
    assert body["temperature"] == 0.0
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["schema"] == ll.TRIAGE_SCHEMA
    assert body["response_format"]["json_schema"]["strict"] is True
    assert body["messages"][0]["role"] == "system"
    assert body["messages"][-1]["content"] == _prompt()
    # The router keeps Ollama's implicit thinking off.
    assert body["reasoning_effort"] == "none"


@pytest.mark.parametrize(
    "answer, needle",
    [
        ("SEVERITY: high\nCONFIDENCE: 0.9", "schema: not JSON"),
        (json.dumps(dict(VALID, confidence=7)), "schema: confidence"),
        (json.dumps({k: v for k, v in VALID.items() if k != "category"}), "schema"),
    ],
)
def test_off_schema_answers_are_errors(answer, needle):
    with StubBifrost(lambda body: answer) as stub:
        lane = ll.LocalModelLane("m", bifrost_url=stub.url, timeout_s=120)
        result = asyncio.run(lane.triage(_prompt()))
    assert result.content is None and result.structured is None
    assert result.error.startswith(needle)


def test_gateway_error_is_an_error_not_a_fallback():
    with StubBifrost(
        lambda body: (400, {"error": {"message": "model not found"}})
    ) as stub:
        lane = ll.LocalModelLane("missing:1b", bifrost_url=stub.url, timeout_s=120)
        result = asyncio.run(lane.triage(_prompt()))
    assert result.content is None
    assert "model not found" in result.error
    # No retry to another model or provider.
    assert {b["model"] for b in stub.requests} == {"ollama/missing:1b"}


def test_timeout_is_an_error():
    async def slow(**kwargs):
        await asyncio.sleep(5)

    lane = ll.LocalModelLane(
        "m", bifrost_url="http://127.0.0.1:1", timeout_s=0.05, dispatch=slow
    )
    result = asyncio.run(lane.triage("p"))
    assert result.error.startswith("timeout:")


def test_only_the_configured_endpoint_is_contacted(monkeypatch):
    seen = []
    real_connect = socket.socket.connect

    def connect(self, address):
        seen.append(address)
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", connect)
    with StubBifrost() as stub:
        lane = ll.LocalModelLane("qwen2.5:7b", bifrost_url=stub.url, timeout_s=120)
        answer = asyncio.run(lane.triage(_prompt()))
    assert answer.error is None, answer.error
    assert seen, "the connect hook saw nothing"
    assert {(a[0], a[1]) for a in seen} == {("127.0.0.1", stub.port)}


def test_model_prefix_is_not_doubled():
    lane = ll.LocalModelLane("ollama/qwen2.5:7b", bifrost_url="http://127.0.0.1:1")
    assert lane.model == "ollama/qwen2.5:7b" and lane.bare_model == "qwen2.5:7b"
    with pytest.raises(ValueError):
        ll.LocalModelLane("  ", bifrost_url="http://127.0.0.1:1")
