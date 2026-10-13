"""Every credential form the verifier found leaking is cut out (WP w3.6)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from core.compliance.audit_export import (
    REDACTED,
    AuditEvent,
    Redactor,
    redact_text,
    secret_key,
)

pytestmark = pytest.mark.unit

# (text, the secret that must be gone, text that must survive)
FREE_TEXT = [
    ("login with password=hunter2 failed", "hunter2", "login with password="),
    ("PASSWORD: 'p@ss w0rd'", "p@ss w0rd", "PASSWORD:"),
    ("db_password=Tr0ub4dor&3 x", "Tr0ub4dor", "db_password="),
    (
        "Driver={ODBC Driver 18};Server=db;Uid=sa;Password=S3cr3t!x;Encrypt=yes",
        "S3cr3t!x",
        "Encrypt=yes",
    ),
    ("Server=db;Uid=sa;Pwd={a;b c};", "a;b c", "Uid=sa"),
    (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAxyz\nabc\n"
        "-----END RSA PRIVATE KEY----- tail",
        "MIIEpAIBAAKCAQEAxyz",
        "tail",
    ),
    (
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA (cut",
        "b3BlbnNzaC1rZXktdjEAAAAA",
        "",
    ),
    ("-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBg\\n", "MIIEvQIBADANBg", ""),
    ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz", "Authorization: Basic"),
    ("authorization=Bearer abc.def.ghi123", "abc.def.ghi123", "Bearer"),
    ("curl -H 'Bearer AbCdEf123456789'", "AbCdEf123456789", "Bearer"),
    ("key sk-proj-AbCdEfGhIjKlMnOpQrStUvWx12", "AbCdEfGhIjKlMnOp", "key"),
    ("sk-ant-api03-AbCdEfGhIjKlMnOpQrSt", "AbCdEfGhIjKlMnOpQrSt", ""),
    ("token ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", "ghp_AbCd", "token"),
    ("github_pat_11ABCDEFG0123456789_abcdefghijk", "github_pat_11ABC", ""),
    ("slack xoxb-1234567890-0987654321-AbCdEfGhIj", "xoxb-1234567890", "slack"),
    (
        "posting to https://hooks.slack.com/services/T0000/B0000/XXXXXXXXXXXXXXXX",
        "T0000/B0000/XXXX",
        "https://hooks.slack.com/services/",
    ),
    (
        "https://discord.com/api/webhooks/123456/AbCdEfGh-IjKl",
        "AbCdEfGh-IjKl",
        "discord.com",
    ),
    ("cache redis://:supersecret@redis:6379/0", "supersecret", "@redis:6379/0"),
    (
        "mongodb+srv://admin:pw123@cluster0.mongodb.net/db",
        "pw123",
        "cluster0.mongodb.net",
    ),
    ("postgresql://app:Pa55@db:5432/x", "Pa55", "db:5432"),
    ("https://token123@github.com/org/repo.git", "token123", "github.com/org"),
    (
        "GET https://api.example.com/v1/x?api_key=abc123def&page=2",
        "abc123def",
        "page=2",
    ),
    ("https://x.example/cb?access_token=zzTop99&state=1", "zzTop99", "state=1"),
    ("?X-Amz-Signature=abcdef0123&X-Amz-Date=1", "abcdef0123", "X-Amz-Date=1"),
    ("https://acct.blob.core.windows.net/c?sv=1&sig=AbC%2Bd", "AbC%2Bd", "sv=1"),
    (
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "wJalrXUtnFEMI",
        "aws_secret_access_key",
    ),
    ("secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY end", "wJalrXUtnFEMI", "end"),
    ("AKIAIOSFODNN7EXAMPLE used", "AKIAIOSFODNN7EXAMPLE", "used"),
    ("google AIzaSyA-abcdefghijklmnopqrstuvwxyz01234", "AIzaSyA-abc", "google"),
    ("stripe sk_live_AbCdEf0123456789", "sk_live_AbCd", "stripe"),
    ("glpat-AbCdEfGhIjKlMnOpQrSt", "glpat-AbCd", ""),
    ('{"credentials": "user:pw", "x": 1}', "user:pw", '"x": 1'),
    ('{"webhook_url":"https://h.example/abc"}', "h.example/abc", "webhook_url"),
    ("DATABASE_URL=postgres://u:p@h/d", "u:p", "DATABASE_URL="),
    ("signing_key: s3kr1t", "s3kr1t", "signing_key:"),
    ("pin=1234 accepted", "1234", "accepted"),
    ("access_key=AKIAXXXXX", "AKIAXXXXX", "access_key="),
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_nature", "eyJzdWIiOiIxIn0", ""),
]


@pytest.mark.parametrize("raw,secret,kept", FREE_TEXT)
def test_free_text_secret_forms_are_redacted(raw, secret, kept):
    out = redact_text(raw)
    assert secret not in out, out
    assert REDACTED in out
    assert kept in out


@pytest.mark.parametrize(
    "harmless",
    [
        "auth.login failure for alice",
        "block_ip on 10.0.0.1: approval.approved (approved)",
        "basic authentication failed for bearer tokens",
        "compliance config compliance.audit_export update",
        "agent run 4f1c event 3: tool_call",
        "spinning up pinned signal handler",
    ],
)
def test_ordinary_text_is_left_alone(harmless):
    assert redact_text(harmless) == harmless


@pytest.mark.parametrize(
    "key",
    [
        "credentials",
        "credential",
        "access_key",
        "accessKey",
        "aws.secret_access_key",
        "webhook_url",
        "webhookUrl",
        "database_url",
        "DATABASE_URL",
        "signing_key",
        "pwd",
        "pin",
        "user_pin",
        "sig",
        "signature",
        "client_secret",
        "private-key",
        "api_key",
        "x-api-key",
        "connection_string",
        "auth",
        "set-cookie",
        "mfa_code",
    ],
)
def test_secret_key_names(key):
    assert secret_key(key)


@pytest.mark.parametrize(
    "key",
    [
        "config_key",
        "auth_scheme",
        "auth_header",
        "max_tokens",
        "spin",
        "pinned",
        "signal",
        "design",
        "keyword",
        "status",
    ],
)
def test_ordinary_key_names(key):
    assert not secret_key(key)


def test_redactor_redacts_nested_key_names_and_text():
    ev = AuditEvent(
        id="config:1",
        source="config",
        category="configuration",
        action="config.update",
        outcome="success",
        severity=5,
        timestamp=datetime(2026, 10, 1, tzinfo=timezone.utc),
        message="set Password=abc123;",
        actor="admin",
        details={
            "new_value": {
                "credentials": {"user": "u", "password": "p"},
                "webhookUrl": "https://hooks.example/x",
                "nested": {"signing_key": "k", "pin": "0000", "sig": "s"},
                "note": "redis://:pw@cache:6379",
                "max_tokens": 1000,
            },
            "event_hash": "a" * 64,
        },
    )
    r = Redactor()
    out = r.event(ev)
    nv = out.details["new_value"]
    assert nv["credentials"] == REDACTED
    assert nv["webhookUrl"] == REDACTED
    assert nv["nested"] == {"signing_key": REDACTED, "pin": REDACTED, "sig": REDACTED}
    assert "pw" not in nv["note"] and nv["note"].endswith("@cache:6379")
    assert nv["max_tokens"] == 1000
    assert out.details["event_hash"] == "a" * 64
    assert "abc123" not in out.message
    assert r.count >= 5
