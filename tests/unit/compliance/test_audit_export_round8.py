"""Round 8 verifier findings (WP w3.6): special-category personal data keys,
Unicode folding before matching, and dict keys that carry secrets or PII.

The cases are the verifier's probes (p1, p2, p7) turned into assertions."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from core.compliance import audit_export_router as api
from core.compliance.audit_export import (
    REDACTED,
    AuditEvent,
    AuditExportConfig,
    Redactor,
    fold_unicode,
    pii_key,
    redact_text,
    special_category_key,
)

from .test_audit_export_service import (
    MemoryConfigStore,
    _admin,
    _request,
    _service,
)

pytestmark = pytest.mark.unit

S = "Zq8vR2xLp9TkW4mN"
TS = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)


def _ev(details=None, message="m", source="config_audit"):
    return AuditEvent(
        id="1",
        source=source,
        category="c",
        action="a",
        outcome="success",
        severity=3,
        timestamp=TS,
        message=message,
        details=details or {},
    )


def _details(details, **kw):
    return Redactor(**kw).event(_ev(details)).details


def _message(message, **kw):
    return Redactor(**kw).event(_ev(message=message)).message


# -- (1) special categories: GDPR Art. 9/10, KVKK md. 6 -----------------------

SPECIAL = {
    "diagnosis": "Type 2 diabetes",
    "health_status": "HIV positive",
    "healthStatus": "HIV positive",
    "health_condition": "HIV positive",
    "mental_health": "depression",
    "medical_history": "asthma",
    "disability": "wheelchair user",
    "criminal_record": "DUI conviction 2019",
    "criminal_convictions": "DUI 2019",
    "race": "Black African",
    "racial_origin": "Black African",
    "blood_type": "O+",
    "bloodType": "O+",
    "pregnancy_status": "pregnant",
    "illness": "cancer",
    "allergies": "penicillin",
    "medications": "insulin",
    "patient_id": "P-001",
    "religious_affiliation": "Catholic",
    "faith": "Catholic",
    "sexual_life": "x-y",
    "genetic_markers": "BRCA1",
    "biometricTemplate": "tmpl",
    "sağlık_durumu": "kronik",
    "sabika_kaydi": "var",
    "nationality": "Turkish",
    "marital_status": "married",
    "place_of_birth": "Ankara",
}


@pytest.mark.parametrize("key,value", sorted(SPECIAL.items()))
def test_special_category_values_are_masked_by_key(key, value):
    assert pii_key(key), key
    out = _details({key: value})
    assert value not in json.dumps(out, ensure_ascii=False)
    message = _message(f"{key}={value}")
    assert value not in message, message


def test_special_category_text_pairs_are_masked():
    for text in ("diagnosis: HIV positive", "health_status=HIV positive"):
        assert "HIV" not in _message(text)


def test_special_categories_pass_with_redact_pii_off():
    assert _details({"diagnosis": "flu"}, redact_pii=False) == {"diagnosis": "flu"}


# Trade-offs, pinned: keys that only look special stay readable.
BENIGN = [
    "health_check",
    "healthcheck_url",
    "healthz",
    "service_health",
    "integration_health_status",
    "health_probe_interval",
    "diagnostics",
    "diagnostic_bundle",
    "disabled",
    "is_disabled",
    "race_condition",
    "trace_id",
    "embrace",
    "faithful",
    "criminal_record_count",
]


@pytest.mark.parametrize("key", BENIGN)
def test_benign_lookalike_keys_are_not_special(key):
    assert not special_category_key(key), key
    assert _details({key: "some value"}) == {key: "some value"}


def test_bare_health_status_keeps_service_states_but_not_conditions():
    # ``health_status`` alone is masked (it may be a person's), except for the
    # vocabulary of a system's state.
    assert _details({"health_status": "degraded"}) == {"health_status": "degraded"}
    assert _details({"health": "ok"}) == {"health": "ok"}
    assert _details({"health_status": "stable"}) == {"health_status": REDACTED}
    assert _details({"medical_status": "ok"}) == {"medical_status": REDACTED}


# -- (2) Unicode folding before matching --------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "ｐａｓｓｗｏｒｄ",  # fullwidth
        "pass​word",  # zero-width space
        "pass­word",  # soft hyphen
        "pаssword",  # Cyrillic a
        "ｈｅａｌｔｈ＿ｓｔａｔｕｓ",
    ],
)
def test_folded_keys_mask_their_values(key):
    out = _details({key: S if "pass" in fold_unicode(key) else "HIV positive"})
    assert list(out.values()) == [REDACTED]


@pytest.mark.parametrize(
    "text",
    [
        f"pass​word={S}",
        f"ｐａｓｓｗｏｒｄ={S}",
        f"password = {S}",
        f"password　=　{S}",
        f"pаssword={S}",
        f"ｐａｓｓｗｏｒｄ＝{S}",
        "ｄｉａｇｎｏｓｉｓ: HIV positive",
    ],
)
def test_folded_text_is_redacted(text):
    out = _message(text)
    assert S not in out and "HIV" not in out
    assert "REDACTED" in out


def test_folding_does_not_rewrite_text_without_secrets():
    for text in (
        "Ｗｉｄｅ ｔｅｘｔ",
        "naïve café ﬁle",
        "İstanbul şube ğ",
        "zero​width",
    ):
        assert _message(text) == text


def test_fold_unicode_is_identity_on_ascii():
    s = "password=x"
    assert fold_unicode(s) is s


def test_verb_first_prose_secret():
    assert S not in redact_text(f"set password to {S}")
    assert S not in redact_text(f"reset the admin password to {S}.")
    assert redact_text("set token to expire") == "set token to expire"


# -- (3) dict keys are scanned ------------------------------------------------


def test_secret_inside_a_key_is_cut():
    out = _details({"password=" + S: True})
    assert S not in json.dumps(out)
    assert list(out.values()) == [True]


def test_email_as_key_is_masked_with_its_value():
    out = _details({"alice@example.com": "admin"})
    assert "alice@example.com" not in json.dumps(out)
    assert "admin" not in json.dumps(out)
    # Without redact_pii, who is who stays readable.
    assert _details({"alice@example.com": "admin"}, redact_pii=False) == {
        "alice@example.com": "admin"
    }


def test_long_key_strength_is_checked_before_the_cut():
    out = _details({"a" * 130 + "_password": S})
    assert S not in json.dumps(out)
    assert all(len(k) <= 128 for k in out)
    out = _details({"x" * 300: S})  # too long to match by word: masked
    assert S not in json.dumps(out)


def test_keys_that_redact_alike_stay_distinct():
    out = _details({"a@example.com": 1, "b@example.com": 2})
    assert len(out) == 2


def test_plain_keys_pass_verbatim():
    details = {"user_id": "u-1", "webhookUrl_count": 3, "x-request-id": "abc"}
    assert _details(details) == details


# -- notes: secret-name collision, token bound to its endpoint ---------------


def test_destination_names_that_share_a_secret_are_refused():
    dests = [
        {"type": "http", "name": "siem-a", "url": "https://a.example/"},
        {"type": "http", "name": "siem_a", "url": "https://b.example/"},
    ]
    with pytest.raises(ValidationError):
        AuditExportConfig.model_validate({"destinations": dests})


@pytest.fixture
def secret_box(monkeypatch):
    box: dict[str, str] = {}
    monkeypatch.setattr(api, "get_secret", lambda k, d=None: box.get(k, d))
    monkeypatch.setattr(api, "set_secret", lambda k, v: box.__setitem__(k, v) or True)
    monkeypatch.setattr(api, "delete_secret", lambda k: box.pop(k, None) is not None)
    return box


def _put(req, url, secrets=None):
    body = api.ConfigUpdate(
        config={"destinations": [{"type": "http", "name": "hec", "url": url}]},
        secrets=secrets or {},
    )
    return api.put_config(body, req, _admin())


def test_a_stored_token_does_not_follow_a_new_host(tmp_path, secret_box):
    req = _request(_service(tmp_path, MemoryConfigStore()))
    _put(req, "https://siem.example/", {"hec": api.DestinationSecrets(token="t0k")})
    _put(req, "https://siem.example/other-path")  # same endpoint: fine
    with pytest.raises(HTTPException) as exc:
        _put(req, "https://attacker.example/")
    assert exc.value.status_code == 409
    with pytest.raises(HTTPException):
        _put(req, "https://siem.example:8443/")
    assert secret_box == {"AUDIT_EXPORT_HEC_TOKEN": "t0k"}
    # Re-entering the token (or clearing it) moves the destination.
    _put(req, "https://new.example/", {"hec": api.DestinationSecrets(token="t1")})
    assert secret_box == {"AUDIT_EXPORT_HEC_TOKEN": "t1"}


def test_a_recreated_destination_does_not_inherit_a_stale_token(tmp_path, secret_box):
    secret_box["AUDIT_EXPORT_HEC_TOKEN"] = "old"
    req = _request(_service(tmp_path, MemoryConfigStore()))
    with pytest.raises(HTTPException) as exc:
        _put(req, "https://anywhere.example/")
    assert exc.value.status_code == 409
    _put(
        req,
        "https://anywhere.example/",
        {"hec": api.DestinationSecrets(clear_token=True)},
    )
    assert secret_box == {}
