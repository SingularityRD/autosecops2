"""Round 9 verifier findings (WP w3.6): whole-value masking of personal-data
and secret pairs in free text, folding used only to find spans, values under
special-category look-alike keys, Turkish/Russian secret words, and the
stored token bound to how it is sent (``tls_verify``, ``ca_pem``,
``auth_header``).

The cases are the verifier's probes (q1, q2, q3, q6) turned into assertions."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from core.compliance import audit_export_router as api
from core.compliance.audit_export import (
    REDACTED,
    AuditEvent,
    Redactor,
    fold_with_map,
    identifier_strength,
    special_lookalike_key,
    unfold_redactions,
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


def _ev(details=None, message="m"):
    return AuditEvent(
        id="1",
        source="config_audit",
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


# -- (M) the whole value of a personal-data pair in free text -----------------

PII_TEXT = [
    ("diagnosis: Type 2 diabetes", ("Type", "2 diabetes")),
    ("diagnosis=Type 2 diabetes mellitus", ("Type", "diabetes", "mellitus")),
    ("health_status=HIV positive", ("HIV", "positive")),
    ("criminal_record=DUI conviction 2019", ("DUI", "conviction", "2019")),
    ("medical_history: asthma and depression", ("asthma", "depression")),
    ("race=Black African", ("Black", "African")),
    ('diagnosis="Type 2 diabetes"', ("Type", "diabetes")),
    ("patient diagnosis: HIV positive", ("HIV", "positive")),
    ("disability: wheelchair user since 2010", ("wheelchair", "since 2010")),
    ("religion: Roman Catholic", ("Roman", "Catholic")),
    ("mental_health=severe depression, anxiety", ("severe", "depression", "anxiety")),
    ("dob: 01 Jan 1980", ("01", "Jan", "1980")),
    ('{"note": 1, "diagnosis": "Type 2 diabetes"} x', ("Type", "diabetes")),
    ('"diagnosis": "Type 2 diabetes", "x": 1', ("Type", "diabetes")),
    ("diagnosis: Crohn's disease", ("Crohn", "disease")),
]


@pytest.mark.parametrize("text,leaks", PII_TEXT)
def test_pii_pairs_in_text_lose_the_whole_value(text, leaks):
    out = _message(text)
    for word in leaks:
        assert word not in out, (text, out)


def test_pii_value_ends_at_a_clear_boundary():
    out = _message("diagnosis: HIV positive, user=bob; ok=1 | tail")
    assert "HIV" not in out and "positive" not in out
    assert out.endswith(", user=bob; ok=1 | tail"), out
    out = _message("diagnosis: HIV positive\nnext line")
    assert out.endswith("\nnext line") and "positive" not in out
    out = _message("religion: Roman Catholic group=a")
    assert "Catholic" not in out and out.endswith(" group=a"), out


@pytest.mark.parametrize(
    "text,leaks",
    [
        ("password: correct horse battery staple", ("horse", "battery", "staple")),
        ("password = correct horse battery staple", ("horse", "staple")),
        ('password="correct horse battery staple"', ("horse",)),
        ("client_secret: two words, user=bob", ("two", "words")),
    ],
)
def test_strong_secret_pairs_in_text_lose_the_whole_value(text, leaks):
    out = _message(text)
    for word in leaks:
        assert word not in out, (text, out)


def test_secret_value_stops_at_the_next_pair():
    out = _message("password: correct horse; user=bob")
    assert out == f"password: {REDACTED}; user=bob"


# -- (L1) folding finds spans; the text outside them is exported as it was -----

FOLD_TEXT = [
    f"Kullanıcı Çağrı Öztürk İstanbul şubesinde ayarı değiştirdi; pаssword={S}",
    f"Пользователь Иван изменил настройки, pаssword={S}",
    f"Kullanıcı Çağrı Öztürk pass​word={S}",
    f"Ünlü müşteri ｐａｓｓｗｏｒｄ={S}",
    f"Сервер ВОЛГА-1 ok; password={S}",
]


@pytest.mark.parametrize("text", FOLD_TEXT)
def test_folding_masks_only_the_secret_span(text):
    head = text[: text.rindex("=") + 1]
    out = _message(text)
    assert S not in out
    assert out == head + REDACTED, out  # byte-identical outside the value
    assert _details({"note": text}) == {"note": head + REDACTED}


def test_folding_keeps_non_secret_unicode_byte_identical():
    text = "Kullanıcı Çağrı Öztürk giriş yaptı ｆｕｌｌ ①② ﬁle"
    assert _message(text) == text


def test_unfold_masks_a_ligature_touched_by_a_span_whole():
    original = "x ﬁ=1"
    folded, starts = fold_with_map(original)
    assert folded == "x fi=1"
    # A span that starts inside the ligature masks the whole ligature.
    alt = "x f[REDACTED]=1"
    assert unfold_redactions(original, folded, starts, alt) == "x [REDACTED]=1"


def test_unfold_refuses_an_output_that_is_not_the_folded_text():
    original = "Çağrı x"
    folded, starts = fold_with_map(original)
    assert unfold_redactions(original, folded, starts, "rewritten") is None


# -- (L2) values under special-category look-alike keys -----------------------

LOOKALIKE = [
    "diagnosis_count",
    "service_health",
    "diagnosis_enabled",
    "diagnosis_consent",
    "health_check_url",
    "healthcheck",
    "diagnostics",
    "race_condition",
    "blood_count",
    "criminal_enabled",
    "conviction_count",
]


@pytest.mark.parametrize("key", LOOKALIKE)
def test_lookalike_keys_pass_only_status_words_and_numbers(key):
    assert special_lookalike_key(key), key
    assert _details({key: "HIV positive"}) == {key: REDACTED}
    assert _details({key: ["HIV positive"]}) == {key: [REDACTED]}
    for value in (3, 2.5, True, None, "ok", "degraded", "UP", "12", "30s"):
        assert _details({key: value}) == {key: value}, value


def test_lookalike_key_restricts_nested_values():
    out = _details(
        {"service_health": {"db": "ok", "latency_ms": 12, "note": "HIV positive"}}
    )
    assert out == {"service_health": {"db": "ok", "latency_ms": 12, "note": REDACTED}}


def test_lookalike_key_in_text():
    assert "HIV" not in _message("service_health=HIV positive")
    assert _message("service_health=degraded") == "service_health=degraded"


def test_lookalike_keys_pass_with_redact_pii_off():
    assert _details({"service_health": "x y"}, redact_pii=False) == {
        "service_health": "x y"
    }


def test_ordinary_keys_are_not_lookalikes():
    for key in ("trace_id", "disabled", "embrace", "faithful", "note"):
        assert not special_lookalike_key(key), key


# -- (L3) Turkish / Russian secret words --------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "parola",
        "şifre",
        "sifre",
        "ŞİFRE",
        "пароль",
        "ПАРОЛЬ",
        "секрет",
        "gizli_anahtar",
        "kullanici_sifresi",
        "api_anahtarı",
    ],
)
def test_foreign_strong_secret_keys(key):
    assert identifier_strength(key) == 2, key
    assert _details({key: S}) == {key: REDACTED}
    assert _details({key: "kısa"}) == {key: REDACTED}
    assert S not in _message(f"{key}={S}")
    assert S not in _message(f"{key}: {S}")


@pytest.mark.parametrize("key", ["jeton", "токен", "anahtar", "ключ"])
def test_foreign_weak_secret_keys(key):
    assert identifier_strength(key) == 1, key
    assert _details({key: S}) == {key: REDACTED}
    assert _details({key: "expired"}) == {key: "expired"}
    assert S not in _message(f"{key}={S}")


@pytest.mark.parametrize(
    "key", ["şifreleme", "şifreli", "parolasız", "anahtar_sayisi", "açıklama"]
)
def test_benign_turkish_words_are_not_secrets(key):
    assert identifier_strength(key) == 0, key
    assert _details({key: "değer"}) == {key: "değer"}


def test_turkish_prose_about_a_password_stays():
    text = "Kullanıcı şifresini değiştirdi: Çağrı Öztürk"
    assert _message(text) == text


# -- (L4) the stored token is bound to how it is sent -------------------------


@pytest.fixture
def secret_box(monkeypatch):
    box: dict[str, str] = {}
    monkeypatch.setattr(api, "get_secret", lambda k, d=None: box.get(k, d))
    monkeypatch.setattr(api, "set_secret", lambda k, v: box.__setitem__(k, v) or True)
    monkeypatch.setattr(api, "delete_secret", lambda k: box.pop(k, None) is not None)
    return box


def _put(req, secrets=None, **dest):
    d = {"type": "http", "name": "hec", "url": "https://siem.example/in"}
    d.update(dest)
    body = api.ConfigUpdate(config={"destinations": [d]}, secrets=secrets or {})
    return api.put_config(body, req, _admin())


PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"


@pytest.mark.parametrize(
    "change",
    [
        {"tls_verify": False},
        {"ca_pem": PEM},
        {"auth_header": "X-Log-Me"},
    ],
)
def test_token_does_not_follow_a_weakened_channel(tmp_path, secret_box, change):
    req = _request(_service(tmp_path, MemoryConfigStore()))
    _put(req, {"hec": api.DestinationSecrets(token="t0k")})
    with pytest.raises(HTTPException) as exc:
        _put(req, **change)
    assert exc.value.status_code == 409
    assert secret_box == {"AUDIT_EXPORT_HEC_TOKEN": "t0k"}
    # Re-entering the token makes the change.
    _put(req, {"hec": api.DestinationSecrets(token="t1")}, **change)
    assert secret_box == {"AUDIT_EXPORT_HEC_TOKEN": "t1"}


def test_ca_bundle_removed_or_replaced_needs_the_token(tmp_path, secret_box):
    req = _request(_service(tmp_path, MemoryConfigStore()))
    _put(req, {"hec": api.DestinationSecrets(token="t0k")}, ca_pem=PEM)
    with pytest.raises(HTTPException):
        _put(req)
    with pytest.raises(HTTPException):
        _put(req, ca_pem=PEM.replace("MIIB", "MIIC"))
    _put(req, ca_pem=PEM)  # unchanged: fine


def test_legitimate_edits_keep_the_token(tmp_path, secret_box):
    req = _request(_service(tmp_path, MemoryConfigStore()))
    _put(req, {"hec": api.DestinationSecrets(token="t0k")}, tls_verify=False)
    _put(req, url="https://siem.example/other?x=1", tls_verify=False)
    _put(req, url="https://siem.example:443/in", tls_verify=False)
    _put(req, url="https://SIEM.example/in")  # tls_verify back on: stricter
    _put(req, auth_header="authorization")  # header names are case-blind
    _put(req, auth_scheme="Splunk")
    assert secret_box == {"AUDIT_EXPORT_HEC_TOKEN": "t0k"}
    stored = req.app.state.audit_export.load_config().destinations[0]
    assert stored.auth_scheme == "Splunk"
    assert json.dumps(api._view(req.app.state.audit_export.load_config()))
