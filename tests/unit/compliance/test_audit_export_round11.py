"""Round 11 verifier findings (WP w3.6): the shared locator
(:func:`locate_pairs`).

* MEDIUM: bracket keys (``user[password]=``, ``user%5Bpassword%5D=``,
  ``password[]=``, ``patient[diagnosis]=``) were not located, so neither
  pass masked them although :func:`classify_key` named them right.
* LOW-MEDIUM: under a sensitive XML element only the first child's text was
  masked (``<password><hash>h</hash><value>S</value></password>``).
* LOW: the heredoc and CDATA scans were quadratic on floods of openers; a
  quoted or YAML value under a WEAK key was judged token by token and leaked
  when it held a space.

The bracket and nested-XML forms are also in the round-10 form x class
matrix (``test_audit_export_round10.FORMS``)."""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone

import pytest

from core.compliance.audit_export import (
    REDACTED,
    REDACTED_PII,
    AuditEvent,
    Redactor,
    locate_pairs,
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


def _outs(text):
    """What both export paths make of ``text``: the message and a detail."""
    r = Redactor()
    return [r.event(_ev(message=text)).message, r.event(_ev({"n": text})).details["n"]]


# -- bracket keys ---------------------------------------------------------------

RAILS = f"utf8=%E2%9C%93&user%5Bemail%5D=a%40b.c&user%5Bpassword%5D={S}&commit=Log+in"

BRACKETS = [
    (f"?user[password]={S}&commit=1", f"?user[password]={REDACTED}&commit=1"),
    (f"data[User][password]={S}", f"data[User][password]={REDACTED}"),
    (f"settings[api_key]={S}", f"settings[api_key]={REDACTED}"),
    (f"password[0]={S}", f"password[0]={REDACTED}"),
    (f"password[]={S}", f"password[]={REDACTED}"),
    (f"user.password={S}", f"user.password={REDACTED}"),
    (f"a=1&user%5Bpassword%5D={S}&b=2", f"a=1&user%5Bpassword%5D={REDACTED}&b=2"),
    ("patient[diagnosis]=HIV", f"patient[diagnosis]={REDACTED_PII}"),
    ("diagnosis[]=HIV", f"diagnosis[]={REDACTED_PII}"),
    ("q?patient[diagnosis]=HIV&x=1", f"q?patient[diagnosis]={REDACTED_PII}&x=1"),
    ("user.diagnosis=HIV", f"user.diagnosis={REDACTED_PII}"),
]


@pytest.mark.parametrize("text,expected", BRACKETS)
def test_bracket_keys_mask_only_the_value(text, expected):
    for out in _outs(text):
        assert out == expected, (text, out)


def test_rails_login_body_masks_the_password_and_keeps_the_rest():
    for out in _outs(RAILS):
        assert S not in out, out
        assert out.startswith("utf8=%E2%9C%93&"), out
        assert f"&user%5Bpassword%5D={REDACTED}&commit=Log+in" in out, out
        # The e-mail is personal data; the delimiters around it stay.
        assert "a%40b.c" not in out and "&user%5Bemail%5D=" in out, out


def test_rails_login_body_byte_identical_with_pii_off():
    out = Redactor(redact_pii=False).event(_ev(message=RAILS)).message
    assert out == RAILS.replace(S, REDACTED), out


def test_bracket_key_is_classified_on_the_innermost_segment():
    keys = {p.key for p in locate_pairs(f"x[y][password]={S}&user%5Bemail%5D=a")}
    assert {"password", "email"} <= keys
    # Benign inner segments and indexes are left alone.
    for text in ("user[note]=hello", "health_check[0]=passed", "items[3]=x", "a[b]=c"):
        for out in _outs(text):
            assert out == text, out


def test_bracket_key_falls_back_to_the_whole_key():
    # ``x[...]`` with a benign innermost name is judged on the whole key.
    assert {p.key for p in locate_pairs(f"password[x]={S}")} == {"password[x]"}
    for out in _outs(f"password[x]={S}"):
        assert out == f"password[x]={REDACTED}", out


# -- nested XML -------------------------------------------------------------------

XML = [
    (
        f"<password><hash>sha</hash><value>{S}</value></password><n>1</n>",
        (S, "sha"),
        "</value></password><n>1</n>",
    ),
    (
        "<diagnosis><code>B20</code><text>HIV</text></diagnosis><n>1</n>",
        ("HIV", "B20"),
        "</text></diagnosis><n>1</n>",
    ),
    (
        "<Condition><diagnosis>\n  <coding><system>icd</system><code>B20</code>"
        "</coding>\n  <text>HIV positive</text>\n</diagnosis></Condition>",
        ("HIV", "B20", "icd"),
        "</text>\n</diagnosis></Condition>",
    ),
    # Nested same-name element: up to the matching close tag.
    (
        f"<password><a><password>x</password><b>{S}</b></a></password><n>1</n>",
        (S,),
        "<n>1</n>",
    ),
    # No close tag: to the end of the line.
    (f"<password><a>x</a><b>{S}</b>\nnext=1", (S,), "\nnext=1"),
]


@pytest.mark.parametrize("text,leaks,keep", XML)
def test_every_descendant_of_a_sensitive_element_is_masked(text, leaks, keep):
    for out in _outs(text):
        for word in leaks:
            assert word not in out, (text, out)
        assert keep in out, (text, out)


def test_descendants_after_the_close_tag_are_not_masked():
    text = "<diagnosis><code>B20</code></diagnosis><note><v>kept</v></note>"
    for out in _outs(text):
        assert out.endswith("<note><v>kept</v></note>"), out
        assert "B20" not in out


# -- WEAK keys: a quoted / YAML value is judged as a whole ----------------------------


@pytest.mark.parametrize(
    "text,leaks",
    [
        (f"token:\n  {S}\n  Tz8Kq2Lm9W", (S, "Tz8Kq2Lm9W")),
        (f'token: "{S} Tz8Kq2Lm9W" ok=1', (S, "Tz8Kq2Lm9W")),
        (f"token: 'Bearer {S}'", (S,)),
        (f"token:\n  - x {S}\nnext: 1", (S,)),
    ],
)
def test_weak_key_quoted_or_yaml_value_is_judged_whole(text, leaks):
    for out in _outs(text):
        for word in leaks:
            assert word not in out, (text, out)
        assert REDACTED in out


@pytest.mark.parametrize(
    "text", ['token: "invalid or expired"', "token:\n  not set\n  yet", "token: 'none'"]
)
def test_weak_key_wordy_values_still_pass(text):
    for out in _outs(text):
        assert out == text, out


# -- heredoc / CDATA: same pairs, linear time --------------------------------------

_OLD_HEREDOC = re.compile(
    r"(?ms)^([ \t]*[\"']?)([^\W\d][\w.\-]*)([\"']?[ \t]*[=:][ \t]*<<-?[ \t]*)"
    r"([\"']?)([A-Za-z_]\w*)\4[ \t]*\n(.*?)(^[ \t]*\5[ \t]*$)"
)
_OLD_CDATA = re.compile(
    r"<((?:[^\W\d][\w.\-]*:)?([^\W\d][\w.\-]*))(\s[^<>]*)?>(\s*<!\[CDATA\[)"
    r"(.*?)(\]\]>\s*</\1\s*>)",
    re.DOTALL,
)

SAMPLES = [
    f"password = <<EOF\n{S}\nEOF\nnext = 1",
    f"a = <<EOF\nx\nEOF\npassword = <<-'END'\n{S}\n  END  \nb=1",
    f"password = <<EOF\nEOF2\n{S}\nEOF\n",
    "password = <<EOF\nnever closed",
    f"x: <<A\npassword = <<B\n{S}\nB\nA\n",
    f"<password><![CDATA[{S}]]></password>",
    f"<password><![CDATA[a]]>b]]></password><token><![CDATA[{S}]]> </token>",
    f"<a><![CDATA[x]]></b><password><![CDATA[{S}]]></password>",
    "<password><![CDATA[open",
]


@pytest.mark.parametrize("text", SAMPLES)
def test_heredoc_and_cdata_find_what_the_lazy_patterns_found(text):
    from core.compliance.audit_export import _cdata_elements, _heredocs

    old_h = [
        (m.group(2), m.start(2), m.start(6), m.end(6))
        for m in _OLD_HEREDOC.finditer(text)
    ]
    assert list(_heredocs(text)) == old_h
    old_c = [
        (m.group(2), m.start(2), m.start(5), m.end(5))
        for m in _OLD_CDATA.finditer(text)
    ]
    assert list(_cdata_elements(text)) == old_c


FLOODS = {
    "heredoc": "password = <<EOF\n",
    "cdata": "<password><![CDATA[",
    "cdata_closed_at_end": "<password><![CDATA[",
    "xml_parent": "<password><a>x</a>\n",
    "bracket": "a[password]=x&",
}


@pytest.mark.parametrize("name", sorted(FLOODS))
def test_floods_are_linear(name):
    def run(n):
        text = FLOODS[name] * (n // len(FLOODS[name]))
        if name == "cdata_closed_at_end":
            text += "]]></password>"
        t0 = time.perf_counter()
        mask_personal_data(text)
        redact_text(text)
        return time.perf_counter() - t0

    run(4096)
    small = min(run(32768) for _ in range(2))
    big = min(run(262144) for _ in range(2))
    # 8x the input: well under the 64x a quadratic scan takes (was 124 s
    # for 512K characters of heredoc openers).
    assert big < 5.0, big
    assert big < max(small, 0.01) * 24, (small, big)
