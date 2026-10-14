"""Round 12 verifier findings (WP w3.6): the shared locator
(:func:`locate_pairs`).

* MEDIUM: a bracket key with whitespace after ``=`` leaked
  (``user[password] = S``, ``patient[diagnosis] = HIV``); ``user[password]:``
  was not a key at all.
* LOW-MEDIUM: CDATA in a descendant of a sensitive XML element leaked
  (``<password><value><![CDATA[S]]></value></password>``).
* MEDIUM (over-masking): an inline value ran over the bracket params after
  it (``user[password]=S&user[name]=bob`` -> ``user[password]=[REDACTED]``).

Quoted and symbol subscripts (``$db['default']['password']``,
``ENV['API_KEY']``, ``os.environ["API_KEY"]``, ``params[:password]``) are
covered by the same locator. Every form is also in the round-10 form x
class matrix (``test_audit_export_round10.FORMS``)."""

from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest

from core.compliance.audit_export import (
    REDACTED,
    REDACTED_PII,
    AuditEvent,
    Redactor,
    mask_personal_data,
    redact_text,
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


def _outs(text, redact_pii=True):
    """What both export paths make of ``text``: the message and a detail."""
    r = Redactor(redact_pii=redact_pii)
    return [r.event(_ev(message=text)).message, r.event(_ev({"n": text})).details["n"]]


# (text, expected with redact_pii on). With it off, the expected text is the
# input with only the secret masked.
EXACT = [
    # 1. whitespace after ``=`` / ``:``: the spaces stay outside the mask.
    (f"user[password] = {S}", f"user[password] = {REDACTED}"),
    (f"user[password]= {S}", f"user[password]= {REDACTED}"),
    (f"user[password] ={S}", f"user[password] ={REDACTED}"),
    (f'settings[api_key] = "{S}"', f'settings[api_key] = "{REDACTED}"'),
    ("patient[diagnosis] = HIV", f"patient[diagnosis] = {REDACTED_PII}"),
    (f"user[password]: {S}", f"user[password]: {REDACTED}"),
    (f"user[password]:{S} x=1", f"user[password]:{REDACTED} x=1"),
    (f"user[password]:\t{S}", f"user[password]:\t{REDACTED}"),
    (f"password = {S}", f"password = {REDACTED}"),
    (f"GET /a?user[password]= {S}&x=1", f"GET /a?user[password]= {REDACTED}&x=1"),
    # 2. CDATA in a descendant; the markers stay.
    (
        f"<password><value><![CDATA[{S}]]></value></password><x>keep</x>",
        f"<password><value><![CDATA[{REDACTED}]]></value></password><x>keep</x>",
    ),
    (
        "<diagnosis><text><![CDATA[HIV]]></text></diagnosis><x>keep</x>",
        f"<diagnosis><text><![CDATA[{REDACTED_PII}]]></text></diagnosis><x>keep</x>",
    ),
    (
        f"<password><v><![CDATA[ {S} ]]></v><w>{S}</w></password>",
        f"<password><v><![CDATA[ {REDACTED} ]]></v><w>{REDACTED}</w></password>",
    ),
    # 3. the value ends before the next key, in every form.
    (f"user[password]={S}&user[name]=bob", f"user[password]={REDACTED}&user[name]=bob"),
    (
        f"data[User][password]={S} data[User][name]=bob",
        f"data[User][password]={REDACTED} data[User][name]=bob",
    ),
    (
        f"user[password]={S}&user%5Bname%5D=bob",
        f"user[password]={REDACTED}&user%5Bname%5D=bob",
    ),
    (f"password={S}&user.name=bob", f"password={REDACTED}&user.name=bob"),
    (f"user[password]={S}&user.role=admin", f"user[password]={REDACTED}&user.role=admin"),
    (f"password: {S}; user[role]=admin", f"password: {REDACTED}; user[role]=admin"),
    # quoted and symbol subscripts
    (
        f"$db['default']['password'] = '{S}';",
        f"$db['default']['password'] = '{REDACTED}';",
    ),
    (f"ENV['API_KEY'] = '{S}'", f"ENV['API_KEY'] = '{REDACTED}'"),
    (f'os.environ["API_KEY"] = "{S}"', f'os.environ["API_KEY"] = "{REDACTED}"'),
    (f"params[:password] = {S}", f"params[:password] = {REDACTED}"),
]


@pytest.mark.parametrize("text,expected", EXACT)
def test_exact_output(text, expected):
    for out in _outs(text):
        assert out == expected, (text, out)


@pytest.mark.parametrize("text,expected", EXACT)
def test_exact_output_with_pii_off(text, expected):
    want = text.replace(S, REDACTED)
    for out in _outs(text, redact_pii=False):
        assert out == want, (text, out)


RAILS = (
    f"user[email]=a@b.com&user[password]={S}&user[remember_me]=1&commit=Log+in"
)


def test_rails_body_keeps_every_other_param():
    for out in _outs(RAILS):
        assert S not in out and "a@b.com" not in out, out
        assert out.startswith("user[email]="), out
        assert out.endswith(
            f"&user[password]={REDACTED}&user[remember_me]=1&commit=Log+in"
        ), out
    for out in _outs(RAILS, redact_pii=False):
        assert out == RAILS.replace(S, REDACTED), out


def test_colon_after_a_bracket_is_not_a_url_scheme():
    text = "links[home]://example.org/a links[help]=x"
    for out in _outs(text):
        assert out == text, out


FLOODS = {
    "bracket_space": "a[password] = x&",
    "bracket_colon": "a[password]: x ",
    "bracket_params": "a[password]=x&b[c]=y&",
    "cdata_descendant": "<password><v><![CDATA[x]]></v>",
}


@pytest.mark.parametrize("name", sorted(FLOODS))
def test_floods_are_linear(name):
    def run(n):
        text = FLOODS[name] * (n // len(FLOODS[name]))
        t0 = time.perf_counter()
        mask_personal_data(text)
        redact_text(text)
        return time.perf_counter() - t0

    run(4096)
    small = min(run(32768) for _ in range(2))
    big = min(run(262144) for _ in range(2))
    assert big < 5.0, big
    assert big < max(small, 0.01) * 24, (small, big)
