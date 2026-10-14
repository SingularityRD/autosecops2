"""Round 10 verifier findings (WP w3.6): one key/value locator and one key
classifier for the secret pass and the personal-data pass.

Three rounds in a row found a free-text form one pass handled and the other
did not (XML elements, YAML blocks and sequences were masked for
``password`` but not for ``diagnosis``). The fix is structural: both passes
walk the pairs :func:`locate_pairs` finds and judge keys with
:func:`classify_key`. :func:`test_form_by_key_class_matrix` runs every form
against every key class so the passes cannot drift apart again; the
verifier's probes (``/tmp/verify-w3.6/probes``, ``r9/probes``,
``r10/probes``) follow as assertions."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from urllib.parse import quote

import pytest

from core.compliance.audit_export import (
    PAIR_FORMS,
    REDACTED,
    REDACTED_PII,
    AuditEvent,
    Redactor,
    classify_key,
    fold_unicode,
    format_cef,
    locate_pairs,
    network_address_value,
    pii_key,
    special_category_key,
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


def _message(message, **kw):
    return Redactor(**kw).event(_ev(message=message)).message


def _note(text, **kw):
    return Redactor(**kw).event(_ev({"note": text})).details["note"]


def _details(details, **kw):
    return Redactor(**kw).event(_ev(details)).details


# -- the matrix: every form x every key class ----------------------------------
#
# FORMS: name -> (template(key, value) -> text, context that must survive,
# the PAIR_FORMS entry the locator reports for it). The context is what
# surrounds the value and is not part of it: a delimiter, a closing tag, the
# next YAML key, the next query parameter.
FORMS = {
    "inline_eq": (lambda k, v: f"{k}={v}\nnext=1", ["\nnext=1"], "inline"),
    "inline_colon": (
        lambda k, v: f"event {k}: {v}; user=bob",
        ["; user=bob"],
        "inline",
    ),
    "inline_tab": (lambda k, v: f"{k}:\t{v}", [], "inline"),
    "arrow": (lambda k, v: f"{k} -> {v}", [], "inline"),
    "kv_list": (
        lambda k, v: f"act=login {k}={v} outcome=success",
        [" outcome=success", "act=login "],
        "inline",
    ),
    "bracketed": (lambda k, v: f"({k}: {v}) done", [") done"], "inline"),
    "line_continuation": (
        lambda k, v: f"{k}: {v.split()[0]}\n{' '.join(v.split()[1:]) or v}",
        [],
        "inline",
    ),
    "fat_arrow": (
        lambda k, v: f"['{k}' => '{v}', 'n' => 1]",
        [", 'n' => 1]"],
        "quoted",
    ),
    "quoted_dq": (lambda k, v: f'{k}="{v}" next=1', [" next=1"], "quoted"),
    "quoted_sq": (lambda k, v: f"{k}='{v}' next=1", [" next=1"], "quoted"),
    "json_fragment": (
        lambda k, v: f'event {{"{k}": "{v}", "n": 1}}',
        [', "n": 1}'],
        "quoted",
    ),
    "json_escaped": (
        lambda k, v: f'event {{\\"{k}\\": \\"{v}\\", \\"n\\": 1}}',
        [', \\"n\\": 1}'],
        "quoted",
    ),
    "json_document": (lambda k, v: json.dumps({k: v, "n": 1}), ['"n": 1'], "quoted"),
    "url_query": (
        lambda k, v: f"GET /api?{k}={quote(v)}&page=2 HTTP/1.1",
        ["&page=2 HTTP/1.1", "GET /api?"],
        "query",
    ),
    "url_encoded_pair": (lambda k, v: f"q={k}%3D{quote(v)}", [], "inline"),
    "xml_element": (
        lambda k, v: f"<r><{k}>{v}</{k}><n>1</n></r>",
        ["<n>1</n></r>"],
        "xml",
    ),
    "xml_ns_attrs": (lambda k, v: f'<ns:{k} id="1">{v}</ns:{k}>', ['id="1">'], "xml"),
    "xml_cdata": (lambda k, v: f"<{k}><![CDATA[{v}]]></{k}>", ["]]>"], "xml"),
    "xml_nested": (lambda k, v: f"<{k}><Value>{v}</Value></{k}>", ["</Value>"], "xml"),
    "xml_value_attr": (lambda k, v: f'<{k} value="{v}"/>', ['"/>'], "xml_attr"),
    "xml_key_value_attr": (
        lambda k, v: f'<add key="{k}" value="{v}"/>',
        ['"/>'],
        "xml_attr",
    ),
    "xml_field_name": (
        lambda k, v: f'<field name="{k}">{v}</field>',
        ["</field>"],
        "xml_attr",
    ),
    "yaml_block_literal": (
        lambda k, v: f"{k}: |\n  {v}\n  {v}\nnext: 1",
        ["\nnext: 1"],
        "yaml_block",
    ),
    "yaml_block_folded": (
        lambda k, v: f"{k}: >-\n  {v}\nnext: 1",
        ["\nnext: 1"],
        "yaml_block",
    ),
    "yaml_next_line": (
        lambda k, v: f"{k}:\n  {v}\nnext: 1",
        ["\nnext: 1"],
        "yaml_scalar",
    ),
    "yaml_sequence": (
        lambda k, v: f"{k}:\n  - {v}\n  - {v}\nnext: 1",
        ["\nnext: 1"],
        "yaml_item",
    ),
    "yaml_sequence_flush": (
        lambda k, v: f"{k}:\n- {v}\nnext: 1",
        ["\nnext: 1"],
        "yaml_item",
    ),
    "named_value": (
        lambda k, v: f"- name: {k}\n  value: {v}\n- name: n",
        ["\n- name: n"],
        "named",
    ),
    "heredoc": (
        lambda k, v: f"{k} = <<EOF\n{v}\nEOF\nnext = 1",
        ["\nEOF\nnext = 1"],
        "heredoc",
    ),
}

# Key classes: (class label, key, value, marker, words that must not leak).
SECRET_V = "Zq8vR2xL p9TkW4mN"
MASKED = [
    ("secret", "password", SECRET_V, REDACTED, ("Zq8vR2xL", "p9TkW4mN")),
    ("secret", "client_secret", SECRET_V, REDACTED, ("Zq8vR2xL", "p9TkW4mN")),
    ("secret", "şifre", SECRET_V, REDACTED, ("Zq8vR2xL", "p9TkW4mN")),
    ("weak_secret", "token", S, REDACTED, (S, "Zq8vR2")),
    ("special", "diagnosis", "HIV positive", REDACTED_PII, ("HIV", "positive")),
    ("special", "religion", "Roman Catholic", REDACTED_PII, ("Roman", "Catholic")),
    ("special", "criminal_record", "DUI 2019", REDACTED_PII, ("DUI", "2019")),
    ("special", "tanı", "HIV pozitif", REDACTED_PII, ("HIV", "pozitif")),
    ("special", "health", "HIV positive", REDACTED_PII, ("HIV", "positive")),
    ("pii", "dateOfBirth", "01 Jan 1980", REDACTED_PII, ("Jan", "1980")),
    ("pii", "first_name", "Alice Smith", REDACTED_PII, ("Alice", "Smith")),
    ("pii", "home_address", "1 Main St", REDACTED_PII, ("Main St",)),
    ("lookalike", "service_health", "HIV positive", REDACTED_PII, ("HIV", "positive")),
]
# Values a key class lets through: the text comes out unchanged.
KEPT = [
    ("benign", "note", "Brute force rule"),
    ("benign", "ip_address", "10.0.0.1"),
    ("benign", "mac_address", "aa:bb:cc:dd:ee:ff"),
    ("benign", "parola_uzunluğu", "12"),
    ("benign", "user", "Alice Smith"),  # actor: who acted is exported
    ("pii", "address", "10.0.0.1"),
    ("special", "health", "degraded"),
    ("lookalike", "service_health", "degraded"),
    ("lookalike", "health_check", "passed"),
    ("secret", "password", "changed"),
    ("weak_secret", "token", "expired"),
]


def test_matrix_covers_every_locator_form():
    assert {f[2] for f in FORMS.values()} == set(PAIR_FORMS) - {"braced"}


@pytest.mark.parametrize("label,key,value,marker,leaks", MASKED)
def test_key_classes_are_what_the_matrix_says(label, key, value, marker, leaks):
    assert classify_key(key).label == label


@pytest.mark.parametrize("form", sorted(FORMS))
def test_the_locator_reports_each_form(form):
    template, _, kind = FORMS[form]
    if form in ("json_document", "url_encoded_pair"):
        pytest.skip("walked as JSON / decoded first")
    text = template("diagnosis", "HIV positive")
    forms = {p.form for p in locate_pairs(text) if p.key == "diagnosis"}
    assert kind in forms, (text, forms)


def _balanced(text: str) -> set:
    """The bracket pairs that are balanced in ``text`` (markers aside)."""
    text = text.replace(REDACTED_PII, "").replace(REDACTED, "")
    text = text.replace("[REDACTED-EMAIL]", "")
    return {
        o + c for o, c in ("()", "[]", "{}", "<>") if text.count(o) == text.count(c)
    }


@pytest.mark.parametrize("form", sorted(FORMS))
@pytest.mark.parametrize(
    "label,key,value,marker,leaks", MASKED, ids=[f"{m[0]}:{m[1]}" for m in MASKED]
)
def test_form_by_key_class_matrix(form, label, key, value, marker, leaks):
    template, context, _ = FORMS[form]
    if form == "line_continuation" and label == "weak_secret":
        pytest.skip("a WEAK key masks the token it judged, not the next line")
    text = template(key, value)
    for out in (_message(text), _note(text)):
        for word in leaks:
            assert word not in out, (form, key, text, out)
            assert word not in fold_unicode(out), (form, key, text, out)
        if form == "json_document":
            # Walked as a structure: the structured marker.
            assert "[REDACTED" in out, (form, key, text, out)
        else:
            assert marker in out, (form, key, text, out)
        if marker == REDACTED:
            assert REDACTED_PII not in out, (form, key, text, out)
        for keep in context:
            assert keep in out, (form, key, text, out, keep)
        assert _balanced(text) <= _balanced(out), (form, key, text, out)


@pytest.mark.parametrize("form", sorted(FORMS))
@pytest.mark.parametrize(
    "label,key,value,marker,leaks", MASKED, ids=[f"{m[0]}:{m[1]}" for m in MASKED]
)
def test_matrix_with_redact_pii_off(form, label, key, value, marker, leaks):
    """Secrets go whatever ``redact_pii`` says; personal data stays."""
    template, _, _ = FORMS[form]
    if form == "line_continuation" and label == "weak_secret":
        pytest.skip("a WEAK key masks the token it judged, not the next line")
    text = template(key, value)
    out = _message(text, redact_pii=False)
    if marker == REDACTED:
        assert not any(w in out for w in leaks), (form, key, out)
    elif form != "json_document":
        assert out == text, (form, key, out)
    else:
        assert json.loads(out) == json.loads(text)


@pytest.mark.parametrize("form", sorted(FORMS))
@pytest.mark.parametrize("label,key,value", KEPT, ids=[f"{k[0]}:{k[1]}" for k in KEPT])
def test_matrix_values_a_class_lets_through(form, label, key, value):
    template, _, _ = FORMS[form]
    if form in ("line_continuation", "yaml_block_literal"):
        pytest.skip("the value twice is no longer a status word")
    if form == "json_document" and label in ("secret", "weak_secret"):
        pytest.skip("structured credential keys mask every value (reliable path)")
    text = template(key, value)
    assert classify_key(key).label == label
    for out in (_message(text), _note(text)):
        if form == "json_document":
            assert json.loads(out) == json.loads(text), (form, key, out)
        else:
            assert out == text, (form, key, text, out)


@pytest.mark.parametrize("key,value", [("password", S), ("token", S)])
def test_space_separated_pairs_are_read_for_secrets_only(key, value):
    """``password value`` (no separator) is prose as often as a pair: the
    secret pass reads it for credential keys, the personal-data pass does
    not (``diagnosis HIV`` / ``address 10.0.0.1`` in a sentence)."""
    out = _message(f"{key} {value}")
    assert S not in out and out == f"{key} {REDACTED}", out
    assert (
        _message("patient diagnosis HIV positive") == "patient diagnosis HIV positive"
    )


# -- the verifier's probes ---------------------------------------------------------

# r8 (MEDIUM): forms the secret pass knew and the personal-data pass did not.
R8 = [
    ("password:\n  - correct horse battery", ("correct", "horse", "battery")),
    (f"password:\n  - {S}", (S,)),
    ("<pwd>correct horse</pwd>", ("correct", "horse")),
    ("<diagnosis>HIV</diagnosis>", ("HIV",)),
    (
        "<patient><diagnosis>HIV</diagnosis><religion>Catholic</religion></patient>",
        ("HIV", "Catholic"),
    ),
    ("<Diagnosis>HIV</Diagnosis>", ("HIV",)),
    ("<dateOfBirth>1980-01-01</dateOfBirth>", ("1980",)),
    ("<criminal_record>DUI 2019</criminal_record>", ("DUI", "2019")),
    ("diagnosis:\n- HIV", ("HIV",)),
    ("religion: |\n  Roman Catholic", ("Roman", "Catholic")),
    ("diagnosis: >\n  HIV positive", ("HIV", "positive")),
]


@pytest.mark.parametrize("text,leaks", R8)
def test_r8_xml_and_yaml_forms_mask_personal_data(text, leaks):
    out = _message(text)
    assert not any(w in out for w in leaks), out


def test_r8_block_scalar_masks_the_block_not_the_indicator():
    assert _message("religion: |\n  Roman Catholic") == f"religion: |\n  {REDACTED_PII}"
    assert _message("diagnosis: >\n  HIV positive") == f"diagnosis: >\n  {REDACTED_PII}"


# r1 (LOW 1): where a value ends.
R1_EXACT = {
    "diagnosis: HIV; positive": f"diagnosis: {REDACTED_PII}",
    "diagnosis: HIV\npositive": f"diagnosis: {REDACTED_PII}",
    "diagnosis: HIV | positive": f"diagnosis: {REDACTED_PII}",
    "diagnosis: 'HIV' positive": f"diagnosis: {REDACTED_PII}",
    'diagnosis: "HIV" positive': f"diagnosis: {REDACTED_PII}",
    "diagnosis = HIV (positive) confirmed": f"diagnosis = {REDACTED_PII}",
    "diagnosis: HIV [positive]": f"diagnosis: {REDACTED_PII}",
    "religion: Roman Catholic (practising)": f"religion: {REDACTED_PII}",
    "diagnosis=HIV&x=1": f"diagnosis={REDACTED_PII}&x=1",
    "GET /api?diagnosis=HIV%20positive&name=x": f"GET /api?diagnosis={REDACTED_PII}&name=x",
    "GET /api?ssn=123-45-6789&name=x": f"GET /api?ssn={REDACTED_PII}&name=x",
    "diagnosis -> HIV": f"diagnosis -> {REDACTED_PII}",
    "password -> hunter2 hunter3": f"password -> {REDACTED}",
    "password: correct horse; battery staple": f"password: {REDACTED}",
    "password: correct horse\nbattery": f"password: {REDACTED}",
    "password: correct horse, user=bob": f"password: {REDACTED}, user=bob",
    "diagnosis: HIV, status: positive": f"diagnosis: {REDACTED_PII}, status: positive",
    "{'diagnosis': 'HIV positive'}": f"{{'diagnosis': '{REDACTED_PII}'}}",
    "(diagnosis: HIV positive) next": f"(diagnosis: {REDACTED_PII}) next",
    "diagnosis:\n  - HIV\n  - hepatitis C": f"diagnosis:\n  - {REDACTED_PII}\n  - {REDACTED_PII}",
    "diagnosis:\n  HIV positive": f"diagnosis:\n  {REDACTED_PII}",
    "<diagnosis>HIV positive</diagnosis>": f"<diagnosis>{REDACTED_PII}</diagnosis>",
}


@pytest.mark.parametrize("text", sorted(R1_EXACT))
def test_r1_value_boundaries(text):
    assert _message(text) == R1_EXACT[text]
    assert _note(text) == R1_EXACT[text]


R1_LEAKS = [
    ("diagnosis: Type 2 diabetes", ("Type", "diabetes")),
    ("religion: Roman Catholic", ("Roman", "Catholic")),
    ("race=Black African", ("Black", "African")),
    ("criminal_record=DUI conviction 2019", ("DUI", "conviction")),
    ("dob: 01 Jan 1980", ("Jan", "1980")),
    ("password: correct horse battery staple", ("correct", "horse", "staple")),
    (
        "user changed settings; password: correct horse battery staple; ok",
        ("horse", "staple"),
    ),
    ("diagnosis: a, b", ("a, b",)),
    ("diagnosis: HIV} positive", ("HIV", "positive")),
    ("diagnosis:HIV positive", ("HIV", "positive")),
    ("Diagnosis: HIV positive", ("HIV", "positive")),
    ("DIAGNOSIS=HIV POSITIVE", ("HIV", "POSITIVE")),
    ("diagnosis: HIV\\npositive", ("HIV", "positive")),
    ("diagnosis: HIV\u2028positive", ("HIV", "positive")),
    ("diagnosis: HIV\x85positive", ("HIV", "positive")),
    ("diagnosis%3AHIV%20positive", ("HIV", "positive")),
    ("diagnosis%3DHIV+positive", ("HIV", "positive")),
    ("diagnosis=HIV+positive", ("HIV", "positive")),
    ("sexual_orientation: gay", ("gay",)),
    ("ethnicity=Kurdish", ("Kurdish",)),
    ("political_opinion: socialist", ("socialist",)),
    ("trade_union: member of Unite", ("Unite",)),
    ("biometric: fingerprint template x", ("fingerprint",)),
    ("genetic: BRCA1 positive", ("BRCA1",)),
    ("sağlık_durumu: diyabet tip 2", ("diyabet",)),
    ("din: Müslüman", ("Müslüman",)),
    ("tanı: HIV pozitif", ("HIV", "pozitif")),
    ("irk: Kürt", ("Kürt",)),
    ("sabıka_kaydı: var", (": var",)),
]


@pytest.mark.parametrize("text,leaks", R1_LEAKS)
def test_r1_probe_values_do_not_leak(text, leaks):
    for out in (_message(text), _note(text)):
        assert not any(w in out for w in leaks), (text, out)


@pytest.mark.parametrize(
    "text,leaks",
    [
        ("password: correct horse battery staple", ("horse",)),
        ("parola: gizli sözcük burada", ("gizli", "burada")),
    ],
)
def test_r1_secrets_go_with_redact_pii_off(text, leaks):
    out = _message(text, redact_pii=False)
    assert not any(w in out for w in leaks), out
    assert (
        _message("diagnosis: HIV positive", redact_pii=False)
        == "diagnosis: HIV positive"
    )


# r2: forms, Turkish/Russian secret keys, and text that must come out as is.
R2_LEAKS = [
    ("<password>correct horse battery</password>", ("horse",)),
    ("password:\n  correct horse battery", ("horse",)),
    ("password:\n  - hunter2x", ("hunter2x",)),
    ("<ssn>123-45-6789</ssn>", ("6789",)),
    ("<dob>01 Jan 1980</dob>", ("1980",)),
    ("<religion>Roman Catholic</religion>", ("Catholic",)),
    ('<field name="diagnosis">HIV positive</field>', ("HIV",)),
    ('<diagnosis value="HIV positive"/>', ("HIV",)),
    ("diagnosis:\n  - HIV", ("HIV",)),
    ("dob:\n  1980-01-01", ("1980",)),
    ("password: hunter2; battery", ("hunter2", "battery")),
    ("password: 'correct' horse", ("correct", "horse")),
    ("parola: s3cretVal", ("s3cretVal",)),
    ("parola=correct horse", ("horse",)),
    ("şifre: Gizli123!", ("Gizli123",)),
    ("şifre=benim gizli şifrem", ("benim", "gizli")),
    ("пароль: секретное слово", ("секретное",)),
    ("секрет=abc def", ("abc", "def")),
    ("gizli_anahtar: abcd efgh", ("abcd", "efgh")),
    (f"gizli_anahtar={S}", (S,)),
    ('{"şifre": "x y z"}', ("x y z",)),
    ("ŞIFRE: abc def", ("abc",)),
    ("Şifre: abc def", ("abc",)),
    ("ПАРОЛЬ: abc", ("abc",)),
    ("user: bob, email: bob@example.com", ("bob@example.com",)),
    ("phone: +90 532 123 45 67", ("532",)),
]


@pytest.mark.parametrize("text,leaks", R2_LEAKS)
def test_r2_probe_values_do_not_leak(text, leaks):
    out = _message(text)
    assert not any(w in out for w in leaks), (text, out)


R2_UNCHANGED = [
    "şifreleme: AES-256 enabled",
    "şifreli: evet",
    "parolasız: true",
    "anahtar_sayisi: 3",
    "şifreleme=etkin",
    "veri şifreleme açık",
    "şifreleme algoritması: AES",
    "parola politikası: güçlü",
    "parola_uzunluğu: 12",
    "password_policy: strong",
    "password_length: 12",
    "User alice logged in from 10.0.0.1",
    "status: failed reason: invalid password",
    "action=update target=detection_rule name=Brute force",
    "role changed: analyst -> admin",
    "name: Brute Force Detection rule",
    "description: Detects multiple failed logins from same host",
    "host: web-01 os: Ubuntu 22.04",
    "gender_field_enabled: true",
    "address: 10.0.0.1",
    "address: 192.168.1.10 port: 443",
    "location: eu-west-1",
    "location: Istanbul office",
    "name=CASE-2026-0001 title=Phishing campaign targeting finance",
    "comment: escalated to tier 2 due to lateral movement",
    "note: false positive, closed",
    "age: 3 days",
    "birthdate field updated",
    "dob changed",
    "health: degraded",
    "health: ok, latency: 12ms",
    "mfa: enabled; password: changed",
    "password: changed",
    "password: reset",
    "password: null",
]


@pytest.mark.parametrize("text", R2_UNCHANGED)
def test_r2_ordinary_audit_text_is_not_masked(text):
    assert _message(text) == text
    assert _note(text) == text


@pytest.mark.parametrize(
    "text",
    ["password: ********", "password: [hidden]", "password: changed to Hunter2!"],
)
def test_r2_secret_values_that_are_not_a_status_word_still_go(text):
    out = _message(text)
    assert out == f"password: {REDACTED}", out


R2_DICTS = [
    ({"service_health": "degraded"}, True),
    ({"service_health": "HIV positive"}, False),
    ({"service_health": 3}, True),
    ({"service_health": True}, True),
    ({"service_health": None}, True),
    ({"diagnosis_count": 5}, True),
    ({"diagnosis_count": "5"}, True),
    ({"diagnosis_count": "five HIV cases"}, False),
    ({"mfa_enabled": True}, True),
    ({"marketing_consent": False}, True),
    ({"marketing_consent": "granted"}, True),
    ({"health_consent": "ok"}, True),
    ({"service_health": "ok"}, True),
    ({"service_health": "warning"}, True),
    ({"service_health": "1.5"}, True),
    ({"service_health": "positive"}, False),
    ({"service_health": "pending"}, True),
    ({"diagnosis_enabled": "disabled"}, True),
    ({"health_check": "passed"}, True),
]


@pytest.mark.parametrize("d,kept", R2_DICTS, ids=[json.dumps(d[0]) for d in R2_DICTS])
def test_r2_structured_allowlist(d, kept):
    out = _details(d)
    assert (out == d) is kept, out


# r3 (LOW 2): network addresses are SOC evidence, exported verbatim.
@pytest.mark.parametrize(
    "d",
    [
        {"address": "10.0.0.1"},
        {"ip_address": "10.0.0.1"},
        {"client_address": "10.0.0.1"},
        {"remote_address": "10.0.0.1"},
        {"source_address": "10.0.0.1"},
        {"bind_address": "0.0.0.0:8080"},
        {"mac_address": "aa:bb:cc:dd:ee:ff"},
        {"ip": "10.0.0.1"},
        {"src_ip": "10.0.0.1"},
        {"address": "2001:db8::1"},
        {"address": "[2001:db8::1]:443"},
        {"address": "https://siem.example.com:6514"},
        {"location": "Istanbul"},
        {"name": "Brute force"},
        {"user_agent": "Mozilla/5.0"},
    ],
)
def test_r3_network_addresses_are_exported(d):
    assert _details(d) == d


@pytest.mark.parametrize(
    "d",
    [
        {"address": "1 Main St"},
        {"home_address": "1 Main St"},
        {"email_address": "x@y.com"},
        {"health_consent": "HIV positive"},
        {"religion_consent": "Roman Catholic"},
        {"health_enabled": "Roman Catholic"},
    ],
)
def test_r3_personal_addresses_and_lookalikes_still_go(d):
    out = _details(d)
    assert list(out.values()) == [REDACTED], out


R3_TEXT = {
    "login from address 10.0.0.1": "login from address 10.0.0.1",
    "client address: 10.0.0.1": "client address: 10.0.0.1",
    "ip_address=10.0.0.1": "ip_address=10.0.0.1",
    "remote_address=10.0.0.1 user=bob": "remote_address=10.0.0.1 user=bob",
    "source_address: 203.0.113.9": "source_address: 203.0.113.9",
    "Failed login for bob from ip: 203.0.113.9": "Failed login for bob from ip: 203.0.113.9",
    "listen address: 0.0.0.0:8080": "listen address: 0.0.0.0:8080",
    "email_address: x@y.com": "email_address: [REDACTED-EMAIL]",
    "mac_address: aa:bb:cc:dd:ee:ff": "mac_address: aa:bb:cc:dd:ee:ff",
    "health_check: passed": "health_check: passed",
    "server health: degraded": "server health: degraded",
    "bind_address=127.0.0.1": "bind_address=127.0.0.1",
    "address=https://siem.example.com:6514": "address=https://siem.example.com:6514",
    "address: 1 Main St": f"address: {REDACTED_PII}",
}


@pytest.mark.parametrize("text", sorted(R3_TEXT))
def test_r3_text(text):
    assert _message(text) == R3_TEXT[text]


@pytest.mark.parametrize(
    "value,ok",
    [
        ("10.0.0.1", True),
        ("10.0.0.0/8", True),
        ("10.0.0.1:443", True),
        ("2001:db8::1", True),
        ("[::1]:8080", True),
        ("aa:bb:cc:dd:ee:ff", True),
        ("aabb.ccdd.eeff", True),
        ("https://x.example/a", True),
        ("1 Main St", False),
        ("Istanbul", False),
        ("10.0.0.1 Main St", False),
        ("web-01:abc", False),
    ],
)
def test_network_address_value(value, ok):
    assert network_address_value(value) is ok


# r3 (LOW 3): Turkish special-category keys, and no false positives.
@pytest.mark.parametrize(
    "key",
    [
        "tanı",
        "TANI",
        "tanısı",
        "teşhis",
        "teşhisi",
        "teshis_kodu",
        "ırk",
        "irk",
        "din",
        "dini",
        "inanç",
        "İnanç",
        "sabıka",
        "sabıka_kaydı",
        "engellilik",
        "engelli_durumu",
        "cinsel",
        "cinsel_yönelim",
        "biyometrik",
        "biyometrik_veri",
        "genetik",
        "sendika",
        "sendika_üyeliği",
    ],
)
def test_turkish_special_category_keys(key):
    assert special_category_key(key), key
    assert pii_key(key), key
    out = _message(f"{key}: gizli değer")
    assert "gizli" not in out and REDACTED_PII in out, out
    assert _details({key: "gizli değer"}) == {key: REDACTED}


@pytest.mark.parametrize(
    "key",
    [
        "dinamik",
        "dinleyici",
        "tanım",
        "tanımı",
        "tanıtım",
        "irkilme",
        "inançlı",
        "dinç",
        "dinlenme",
        "tanımlama",
        "genel",
    ],
)
def test_turkish_lookalike_words_are_not_special(key):
    assert not special_category_key(key), key
    text = f"{key}: değer burada"
    assert _message(text) == text


# Older rounds' probes: p7 (free text), q1-q3 (special categories, Turkish
# and Russian text around a secret), r4 (Unicode folding).
P7 = [
    f"PASSWORD={S}",
    f"Password : {S}",
    f"pass\u200bword={S}",
    f"ｐａｓｓｗｏｒｄ={S}",
    f"password = {S}",
    f"password\t{S}",
    f'PaSsWoRd="{S}"',
    f"password='{S}'",
    f"--Password={S}",
    f"secret:{S}",
    f"api-key: {S}",
    f"Authorization: bearer {S}",
    f"authorization=Bearer%20{S}",
    f"x-api-key:{S}",
    f"client_secret%3D{S}",
    f"password\\u003d{S}",
    f"password&#x3D;{S}",
    f"{{'password': '{S}'}}",
    f"password ={S}",
    f"pw={S}",
    f"passwd: {S}",
    f"AccountKey={S};",
    f"SharedAccessSignature=sv=2020&sig={S}",
    f"primaryKey={S}",
    f"set password to {S}",
    "diagnosis: HIV positive",
    "health_status=HIV positive",
]


@pytest.mark.parametrize("text", P7)
def test_p7_free_text(text):
    out = _message(text)
    assert S not in out and "HIV" not in out, out


Q1 = [
    ("diagnosis: Type 2 diabetes", ("diabetes",)),
    ("diagnosis=Type 2 diabetes mellitus", ("diabetes", "mellitus")),
    ("health_status=HIV positive", ("HIV",)),
    ("criminal_record=DUI conviction 2019", ("DUI",)),
    ("medical_history: asthma and depression", ("asthma", "depression")),
    ("race=Black African", ("Black",)),
    ('diagnosis="Type 2 diabetes"', ("diabetes",)),
    ("patient diagnosis: HIV positive", ("HIV",)),
    ("disability: wheelchair user since 2010", ("wheelchair",)),
    ("religion: Roman Catholic", ("Catholic",)),
    ("mental_health=severe depression, anxiety", ("depression", "anxiety")),
]


@pytest.mark.parametrize("text,leaks", Q1)
def test_q1_free_text(text, leaks):
    out = _message(text)
    assert not any(w in out for w in leaks), out


Q2_Q3 = [
    (
        f"Kullanıcı şifresini değiştirdi: Çağrı Öztürk İstanbul şubesi password={S}",
        "Çağrı Öztürk",
    ),
    (f"Пользователь Иван изменил настройки, password={S}", "Иван"),
    (f"ｐａｓｓｗｏｒｄ={S} ﾃｽﾄ ①②③ ﬁle", "ｐａｓｓｗｏｒｄ="),
    (f"Пароль: {S}", "Пароль"),
    (f"şifre={S}", "şifre"),
    (f"parola: {S}", "parola"),
    (f"пароль={S}", "пароль"),
    (f"Müşteri notu: ünlü İzmir password={S} ve ıslak", "İzmir"),
    (f"note ½ ™ ﬃ x² password={S}", "½ ™ ﬃ x²"),
    (
        f"Kullanıcı Çağrı Öztürk İstanbul şubesinde ayarı değiştirdi; pаssword={S}",
        "Öztürk",
    ),
    (f"Пользователь Иван изменил настройки, pаssword={S}", "Иван"),
    (f"Kullanıcı Çağrı Öztürk pass\u200bword={S} giriş", "Çağrı"),
    (f"Ünlü müşteri ｐａｓｓｗｏｒｄ={S}", "Ünlü"),
    (f"Сервер ВОЛГА-1 ok; password={S}", "ВОЛГА-1"),
    (f"Ахмед вошёл, IP 10.0.0.1, ключ ｓｅｃｒｅｔ={S}", "10.0.0.1"),
]


@pytest.mark.parametrize("text,kept", Q2_Q3)
def test_q2_q3_secret_in_non_latin_text(text, kept):
    for out in (_message(text), _note(text)):
        assert S not in out and S not in fold_unicode(out), out
        assert kept in out, out
    assert (
        _message("Kullanıcı Çağrı Öztürk giriş yaptı")
        == "Kullanıcı Çağrı Öztürk giriş yaptı"
    )


R4_SECRETS = [
    "ｐａｓｓｗｏｒｄ=" + S,
    "pass\u200bword=" + S,
    "pаssword=" + S + " rest ﬁne",
    "😀 ｐａｓｓｗｏｒｄ: correct horse battery; then ﬁne",
    "é password = " + S,
    "ｄｉａｇｎｏｓｉｓ: HIV positive; ok ﬁ",
    "𝐩𝐚𝐬𝐬𝐰𝐨𝐫𝐝=" + S + " 😀",
    "ﬁ ｓｓｎ=123-45-6789 ﬁ",
    "token=" + "".join(chr(0xFF00 + ord(c) - 0x20) for c in S) + " x",
]


@pytest.mark.parametrize("text", R4_SECRETS)
def test_r4_folded_forms(text):
    out = fold_unicode(_message(text))
    for word in (S, "horse", "HIV", "123-45-6789"):
        assert word not in out, out


R4_BENIGN = [
    "Kullanıcı ayarları güncellendi ①",
    "ﬁle ﬂow ™ ½ ㎏",
    "café naïve é ạ̈",
    "Ρώμη Москва İstanbul ışık",
    "Ｆｕｌｌｗｉｄｔｈ ｔｅｘｔ ok",
    "한국어 日本語 中文",
    "status: ﬁne",
    "rule ﬁred on host ｗｅｂ-01",
]


@pytest.mark.parametrize("text", R4_BENIGN)
def test_r4_benign_unicode_text_is_unchanged(text):
    assert _message(text) == text


# Structured probes (p1, p2, q1, q4): the reliable path.
P2 = {
    "race": "Black African",
    "diagnosis": "Type 2 diabetes",
    "health_status": "HIV positive",
    "disability": "wheelchair user",
    "criminal_record": "DUI conviction 2019",
    "blood_type": "O+",
    "pregnancy_status": "pregnant",
    "medical_history": "asthma",
    "sex_life": "xyz",
    "philosophical_beliefs": "atheist",
    "religious_belief": "Catholic",
    "faith": "Catholic",
    "mental_health": "depression",
    "illness": "cancer",
    "allergies": "penicillin",
    "medications": "insulin",
    "patient_id": "P-001",
    "salary": "95000",
    "credit_score": "720",
    "maiden_name": "Jones",
    "place_of_birth": "Ankara",
    "nationality": "Turkish",
    "marital_status": "married",
    "home_phone": "5551234",
    "personal_email": "a@b.c",
    "driver_license": "D123",
    "drivers_license_number": "D123",
    "license_plate": "34ABC",
}


@pytest.mark.parametrize("key", sorted(P2))
def test_p2_special_and_personal_keys(key):
    value = P2[key]
    assert value not in json.dumps(_details({key: value}))
    assert value not in _message(f"{key}={value}")


def test_p2_ip_address_is_exported_by_decision():
    """p2 listed ``ip_address`` as a leak; round 10 exports network
    addresses (AUDIT_EXPORT.md, "Network addresses")."""
    assert _details({"ip_address": "8.8.8.8"}) == {"ip_address": "8.8.8.8"}
    assert _message("ip_address=8.8.8.8") == "ip_address=8.8.8.8"


def test_q7_cef_has_no_line_breaks_or_secret():
    m = f"Çağrı INJECT pаssword={S}\r\nCEF:0|fake\u0085x y"
    ev = Redactor().event(
        _ev(
            {
                "ｐａｓｓｗｏｒｄ\n": S,
                "k ": "v\r\nCEF:0|x",
                "a_key": S,
                "primaryKey": S,
            },
            message=m,
        )
    )
    line = format_cef(ev, "h")
    assert not any(c in line for c in "\r\n\u0085\u2028\u2029")
    assert S not in line


# -- linear time: the locator on the r6/r7 adversarial patterns ------------------

R7 = {
    "diagcomma": "ｄｉａｇｎｏｓｉｓ: a, ",
    "kk": "ｋ:ｋ=",
    "svc": "service_health=ok ﬁ ",
    "pw": "ｐａｓｓｗｏｒｄ: a ",
    "q": "'ｐ'=\"",
    "xml": "<ｐａｓｓ>a</",
    "lt": "<<ｐ:",
    "semi": "password=a;b;ｃ;",
    "yaml_seq": "diagnosis:\n  - a: 1\n",
    "yaml_deep": " - k:\n",
    "brackets": "diagnosis: (",
    "quotes": 'diagnosis: a " ',
    "continuation": "diagnosis: a\nb\n",
    "xml_attr": '<a value="x" name="diagnosis"/>',
    "query": "?diagnosis=a&",
}


@pytest.mark.parametrize("name", sorted(R7))
def test_locator_is_linear_on_adversarial_fields(name):
    p = R7[name]
    s = "{" + (p * (16_383 // len(p) + 1))[:16_383]
    r = Redactor(max_string=16_384)
    start = time.perf_counter()
    r.text(s)
    assert time.perf_counter() - start < 3.0, name


# -- found by fuzzing the matrix forms inside random surrounding text -----------


def test_escaped_json_key_inside_longer_text_is_decoded():
    """``{"tan\\u0131": ...}`` inside a longer string is not JSON as a whole:
    the personal-data pass decodes ``\\uXXXX`` like the secret pass does."""
    text = 'event x {"tan\\u0131": "HIV pozitif", "n": 1} y'
    out = _message(text)
    assert "HIV" not in out and "pozitif" not in out, out
    plain = 'event {"caf\\u00e9": "ok"} 50%25 &amp; more'
    assert _message(plain) == plain


@pytest.mark.parametrize(
    "text,leaks,kept",
    [
        ("tanı: HIV\npozitif action: login", ("HIV", "pozitif"), " action: login"),
        ("password: Zq8vR2xL\np9TkW4mN action: login", ("p9TkW4mN",), " action: login"),
        ("dateOfBirth: 01\nJan 1980 action: login", ("Jan", "1980"), " action: login"),
    ],
)
def test_continuation_line_with_a_later_pair_is_still_part_of_the_value(
    text, leaks, kept
):
    out = _message(text)
    assert not any(w in out for w in leaks), out
    assert out.endswith(kept), out
