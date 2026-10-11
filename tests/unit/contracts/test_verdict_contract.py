"""The Python verdict contract agrees with verdict.schema.json.

Every case in core/contracts/verdict.cases.json is run through the JSON
Schema (jsonschema, Draft 2020-12) and through ``validate_verdict``; both
must give the answer the case states. The agent layer's
services/agent/tests/core/verdict-contract.test.ts runs the same cases.
"""

from __future__ import annotations

import copy
import json

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from core.contracts.verdict import (
    AUTHORED,
    CASES_PATH,
    CATEGORIES,
    NO_SENSOR_CITATION_GAP,
    UNKNOWN_FIELD_AUTHOR,
    VERDICTS,
    CitedField,
    attach_provenance,
    enforce_provenance,
    load_schema,
    resolve_authored,
    validate_verdict,
    verdict_from_model_output,
)

pytestmark = pytest.mark.unit

SCHEMA = load_schema()
CASES = json.loads(CASES_PATH.read_text(encoding="utf-8"))


def _document(case: dict) -> dict:
    doc = copy.deepcopy(CASES["base"])
    doc.update(copy.deepcopy(case.get("patch", {})))
    for key in case.get("drop", []):
        doc.pop(key)
    return doc


def _pydantic_accepts(doc: dict) -> bool:
    try:
        validate_verdict(doc)
    except ValidationError:
        return False
    return True


def test_the_schema_is_a_valid_2020_12_schema():
    Draft202012Validator.check_schema(SCHEMA)
    assert SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_there_are_cases_both_ways():
    # A vacuous pass is the one way an agreement test fails silently.
    valid = [c for c in CASES["cases"] if c["valid"]]
    assert len(valid) >= 5 and len(CASES["cases"]) - len(valid) >= 5


@pytest.mark.parametrize("case", CASES["cases"], ids=lambda c: c["name"])
def test_schema_and_pydantic_agree(case):
    doc = _document(case)
    schema_accepts = Draft202012Validator(SCHEMA).is_valid(doc)
    assert schema_accepts is case["valid"], "the case file disagrees with the schema"
    assert _pydantic_accepts(doc) is case["valid"]


def test_enums_match_the_schema():
    props = SCHEMA["properties"]
    assert tuple(props["verdict"]["enum"]) == VERDICTS
    assert tuple(props["category"]["enum"]) == CATEGORIES
    assert (
        tuple(SCHEMA["$defs"]["citedField"]["properties"]["authored"]["enum"])
        == AUTHORED
    )
    assert set(SCHEMA["required"]) == {
        name
        for name, field in validate_verdict(CASES["base"]).model_fields.items()
        if field.is_required()
    }


def test_round_trip_is_schema_valid():
    doc = _document(
        {"patch": {"recommended_action": {"type": "block_ip", "target": "x"}}}
    )
    out = validate_verdict(doc).to_json_dict()
    assert out == doc
    assert Draft202012Validator(SCHEMA).is_valid(out)
    bare = validate_verdict(CASES["base"]).to_json_dict()
    assert "recommended_action" not in bare and Draft202012Validator(SCHEMA).is_valid(
        bare
    )


# --- provenance -------------------------------------------------------------

PROVENANCE = CASES["provenance"]["map"]


@pytest.mark.parametrize("case", CASES["provenance"]["cases"], ids=lambda c: c["name"])
def test_shared_provenance_cases(case):
    assert resolve_authored(case["field"], PROVENANCE) == case["authored"]


def test_provenance_cases_cover_the_traps():
    # Made-up children, trailing dots and empty segments must be in the file,
    # or a lenient resolver could pass it.
    fields = {c["field"] for c in CASES["provenance"]["cases"]}
    assert {"email.sender_ip.country", "email.sender_ip.", "edr..pid"} <= fields
    assert any(c["authored"] == "sensor" for c in CASES["provenance"]["cases"])


def test_authored_resolves_exact_then_longest_declared_prefix():
    assert resolve_authored("email.sender_ip", PROVENANCE) == "sensor"
    assert resolve_authored("email.headers.subject", PROVENANCE) == "adversary"
    assert resolve_authored("intel.reputation", PROVENANCE) == "third_party"
    # "email.headersX" is not under "email.headers.*".
    assert resolve_authored("email.headersX", PROVENANCE) == UNKNOWN_FIELD_AUTHOR
    # A plain key covers no children: only a ".*" key does.
    assert resolve_authored("a.b", {"a": "sensor"}) == UNKNOWN_FIELD_AUTHOR
    assert resolve_authored("a.b", {"a.*": "sensor"}) == "sensor"


def test_unknown_field_is_least_trusted():
    assert UNKNOWN_FIELD_AUTHOR == "adversary"
    assert resolve_authored("made.up", PROVENANCE) == "adversary"


def test_a_bad_provenance_map_is_refused():
    with pytest.raises(ValueError):
        resolve_authored("x", {"x": "model"})
    with pytest.raises(ValueError):
        resolve_authored("x.y", {"x.*": "model"})


ASSEMBLY = CASES["assembly"]


@pytest.mark.parametrize("case", ASSEMBLY["cases"], ids=lambda c: c["name"])
def test_shared_assembly_cases(case):
    def run():
        return verdict_from_model_output(
            copy.deepcopy(case["raw"]), ASSEMBLY["provenance"], **ASSEMBLY["stamp"]
        )

    if not case["ok"]:
        # The one error a caller handles; TypeScript returns {ok: false}.
        with pytest.raises(ValidationError):
            run()
        return
    out = run()
    assert out.verdict == case["verdict"]
    assert [c.authored for c in out.cited_fields] == case["authored"]
    assert list(out.gaps) == case["gaps"]
    assert (out.model, out.prompt_version) == (
        ASSEMBLY["stamp"]["model"],
        ASSEMBLY["stamp"]["prompt_version"],
    )
    assert Draft202012Validator(SCHEMA).is_valid(out.to_json_dict())


def test_assembly_cases_cover_both_outcomes():
    ok = [c for c in ASSEMBLY["cases"] if c["ok"]]
    assert len(ok) >= 5 and len(ASSEMBLY["cases"]) - len(ok) >= 5


def test_attach_provenance_ignores_the_models_authored_claim():
    cited = attach_provenance(
        [{"field": "email.headers.subject", "authored": "sensor"}, "email.sender_ip"],
        PROVENANCE,
    )
    assert cited == (
        CitedField(field="email.headers.subject", authored="adversary"),
        CitedField(field="email.sender_ip", authored="sensor"),
    )


def _benign(cited):
    return validate_verdict(
        {**CASES["base"], "verdict": "benign", "cited_fields": cited}
    )


@pytest.mark.parametrize(
    "cited",
    [
        [],
        [{"field": "email.headers.subject", "authored": "adversary"}],
        [{"field": "intel.reputation", "authored": "third_party"}],
    ],
)
def test_benign_without_sensor_citation_becomes_inconclusive(cited):
    out = enforce_provenance(_benign(cited))
    assert out.verdict == "inconclusive"
    assert NO_SENSOR_CITATION_GAP in out.gaps
    assert enforce_provenance(out) == out  # idempotent


def test_benign_with_a_sensor_citation_stands():
    v = _benign(
        [{"field": "a", "authored": "adversary"}, {"field": "b", "authored": "sensor"}]
    )
    assert enforce_provenance(v) is v


@pytest.mark.parametrize("verdict", ["malicious", "inconclusive"])
def test_other_verdicts_are_untouched(verdict):
    v = validate_verdict({**CASES["base"], "verdict": verdict, "cited_fields": []})
    assert enforce_provenance(v) is v


def test_model_output_cannot_launder_adversary_text_into_a_benign_verdict():
    raw = {
        "verdict": "benign",
        "confidence": 0.99,
        "category": "phishing",
        # The email body told the model to say this.
        "cited_fields": [{"field": "email.headers.subject", "authored": "sensor"}],
        "gaps": [],
        "model": "whatever-the-model-says",
        "prompt_version": "forged",
    }
    out = verdict_from_model_output(
        raw, PROVENANCE, model="claude-opus-5-5", prompt_version="triage-v1"
    )
    assert out.verdict == "inconclusive"
    assert out.cited_fields[0].authored == "adversary"
    assert (out.model, out.prompt_version) == ("claude-opus-5-5", "triage-v1")
    assert Draft202012Validator(SCHEMA).is_valid(out.to_json_dict())


def test_model_output_with_sensor_backing_stays_benign():
    raw = {
        "verdict": "benign",
        "confidence": 0.8,
        "category": "phishing",
        "cited_fields": ["email.sender_ip"],
    }
    out = verdict_from_model_output(raw, PROVENANCE, model="m", prompt_version="p")
    assert out.verdict == "benign" and out.gaps == ()
