"""Round-6 regressions for audit-export field masking (WP w3.6).

1. Performance: the e-mail matcher is a linear scanner (the former regular
   expression was quadratic on long local-part runs), every field is capped
   before any pattern runs, and the pipeline scrubs a batch in a worker
   thread, not on the event loop.
2. Coverage: keys naming credentials or personal data mask their value
   whatever it looks like (key first); value shapes (cards, IBAN, SSN,
   T.C. kimlik, phone, more token formats, SNMP communities) second.
3. Over-masking: Windows SIDs, GUIDs, hash digests and case/finding ids pass
   through under id- and signature-like keys and in free text; credential
   keys still mask them.

Every value here is a fake placeholder (documentation card/IBAN numbers,
``FAKE0000`` token bodies). Token-shaped literals are split so repository
push protection does not flag the file.
"""

from __future__ import annotations

import asyncio
import contextlib
import random
import re
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from core.compliance.audit_export import (
    MAX_FIELD_CHARS,
    REDACTED,
    AuditCheckpointSource,
    AuditEvent,
    AuditExportConfig,
    FileCursorStore,
    Pipeline,
    Redactor,
    Source,
    allowed_identifier,
    email_spans,
    identifier_strength,
    mask_emails,
    pii_key,
    redact_text,
)

pytestmark = pytest.mark.unit

FAKE = "FAKE0000fake0000FAKE0000fake0000"
T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)

# -- 1. performance ------------------------------------------------------------

# The pattern this round replaced, kept as the reference for what an address
# is (on short strings, where it is fast).
OLD_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

LONG = 200_000
PATHOLOGICAL = {
    "local_run": "a" * LONG,
    "local_run_then_at": "a" * LONG + "@",
    "domain_no_tld": "x@" + "a" * LONG,
    "dotted_domain": "x@" + "a." * (LONG // 2) + "1",
    "many_ats": "a@" * (LONG // 2),
    "mixed_case_digits": "Ab1" * (LONG // 3),
    "key_colon_runs": "token:" * (LONG // 6),
    "key_value_runs": "key:" * (LONG // 4),
    "dash_p": "-p" * (LONG // 2),
    "hex": "0123456789abcdef" * (LONG // 16),
    "percent": "%41" * (LONG // 3),
    "digits": "4111 " * (LONG // 5),
}


@pytest.mark.parametrize("name", sorted(PATHOLOGICAL))
def test_email_scanner_is_fast_on_long_inputs(name):
    s = PATHOLOGICAL[name]
    best = float("inf")
    for _ in range(3):
        t0 = time.perf_counter()
        mask_emails(s)
        best = min(best, time.perf_counter() - t0)
    assert best < 0.5, name


def test_email_scanner_is_linear_not_quadratic():
    def cost(n):
        s = "a" * n
        t0 = time.perf_counter()
        for _ in range(5):
            email_spans(s)
        return time.perf_counter() - t0

    small, large = cost(20_000), cost(160_000)
    # 8x the input: linear is ~8x, the old pattern was ~64x.
    assert large < max(small, 1e-3) * 24


@pytest.mark.parametrize("name", sorted(PATHOLOGICAL))
def test_scrubbing_a_long_field_is_well_under_a_second(name):
    s = PATHOLOGICAL[name]
    for scrub in (
        lambda: Redactor().text(s),
        lambda: Redactor().value("", {"message": s, "token": s, "nested": [s]}),
        lambda: redact_text(s),  # capped at MAX_FIELD_CHARS, not max_string
    ):
        # Best of three: ~20 agents share this machine's 2 CPUs. The bound
        # is still ~10x below what the quadratic code took on these inputs.
        best = float("inf")
        for _ in range(3):
            t0 = time.perf_counter()
            scrub()
            best = min(best, time.perf_counter() - t0)
        assert best < 0.75, name


def test_email_scanner_agrees_with_the_old_pattern_on_short_text():
    rng = random.Random(6)
    alphabet = "ab1._%+-@ .xyzQ-:\n"  # ``@[ip]`` literals: tested below
    samples = [
        "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 24)))
        for _ in range(4000)
    ] + [
        "mail jane.doe+tag@example.co.uk now",
        "a@b.c",
        "a@b.cd",
        "x@-.io",
        "u@@d.com",
        "first@one.org,second@two.net",
        "trailing@dots.com.",
        "1@2.34",
        "ab@cd.e1fg",
        "p%q@r-s.tu",
    ]
    for s in samples:
        old = [m.span() for m in OLD_EMAIL.finditer(s)]
        assert email_spans(s) == old, s


def test_email_scanner_also_masks_address_literals():
    assert mask_emails("mail admin@[192.0.2.1] now") == "mail [REDACTED-EMAIL] now"
    assert "[REDACTED-EMAIL]" in mask_emails("to: ops@[IPv6:2001:db8::1]")
    assert mask_emails("arr@[not-an-ip]") == "arr@[not-an-ip]"


def test_every_field_is_capped_before_scanning():
    huge = "x" * (MAX_FIELD_CHARS * 4)
    out = redact_text(huge)
    assert len(out) <= MAX_FIELD_CHARS + 20 and out.endswith("...[truncated]")
    r = Redactor(max_string=100)
    out = r.text("password=" + FAKE + " " + "y" * 10_000)
    assert FAKE not in out and out.endswith("...[truncated]")
    assert len(out) <= 100 + len("...[truncated]")


def test_a_secret_straddling_the_export_cut_is_still_masked():
    r = Redactor(max_string=40)
    out = r.text("p" * 30 + " password=" + FAKE)
    assert "FAKE0000" not in out


class _ListSource(Source):
    name = "config"

    def __init__(self, events):
        self.events = events

    def initial_cursor(self, start_from):
        return {"id": 0}

    def fetch(self, cursor, limit):
        start = int(cursor["id"])
        return [
            (ev, {"id": start + i + 1})
            for i, ev in enumerate(self.events[start : start + limit])
        ]


class _Capture:
    def __init__(self):
        self.seen = []

    async def send(self, events):
        self.seen.extend(events)

    async def close(self):
        pass


def _event(i, **kw):
    kw.setdefault("message", f"event {i}")
    return AuditEvent(
        id=f"config:{i}",
        source="config",
        category="test",
        action="test.event",
        outcome="success",
        severity=3,
        timestamp=T0 + timedelta(seconds=i),
        **kw,
    )


async def test_pipeline_scrubs_batches_off_the_event_loop(tmp_path):
    loop_thread = threading.get_ident()
    threads = []

    class Recording(Redactor):
        def events(self, events):
            threads.append(threading.get_ident())
            return super().events(events)

    transport = _Capture()
    p = Pipeline(
        destination="siem",
        transport=transport,
        sources=[
            _ListSource([_event(i, details={"password": FAKE}) for i in (1, 2, 3)])
        ],
        cursors=FileCursorStore(tmp_path / "cursors.json"),
        cfg=AuditExportConfig(
            start_from="beginning", poll_interval_s=0.05, settle_s=0, batch_size=10
        ),
        redactor=Recording(),
        rng=random.Random(1),
    )
    p.start()
    try:
        deadline = time.monotonic() + 10
        while len(transport.seen) < 3 and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
    finally:
        await p.stop()
    assert [e.details for e in transport.seen] == [{"password": REDACTED}] * 3
    assert threads and loop_thread not in threads
    assert p.metrics.redactions == 3


async def test_event_loop_stays_responsive_while_a_heavy_batch_is_scrubbed(tmp_path):
    heavy = [
        _event(i, message="token:" * 2000, details={"blob": "key:" * 4000})
        for i in range(1, 41)
    ]
    transport = _Capture()
    p = Pipeline(
        destination="siem",
        transport=transport,
        sources=[_ListSource(heavy)],
        cursors=FileCursorStore(tmp_path / "cursors.json"),
        cfg=AuditExportConfig(
            start_from="beginning", poll_interval_s=0.05, settle_s=0, batch_size=40
        ),
        redactor=Redactor(),
        rng=random.Random(1),
    )
    gaps = []
    p.start()
    try:
        last = time.monotonic()
        deadline = last + 20
        while len(transport.seen) < len(heavy) and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
            now = time.monotonic()
            gaps.append(now - last)
            last = now
    finally:
        await p.stop()
    assert len(transport.seen) == len(heavy)
    # Generous for a shared 2-CPU CI box; scrubbing on the loop blocked it
    # for the whole batch.
    assert max(gaps) < 0.5


# -- 2. coverage: key first, pattern second ------------------------------------

PII_KEYS = [
    "email",
    "userEmail",
    "contact_email",
    "phone",
    "mobile",
    "telephone",
    "phone_number",
    "first_name",
    "lastName",
    "surname",
    "given_name",
    "family_name",
    "full_name",
    "dob",
    "date_of_birth",
    "birthdate",
    "passport_number",
    "iban",
    "card_number",
    "credit_card",
    "cc_number",
    "pan",
    "cvv",
    "ssn",
    "social_security_number",
    "tax_id",
    "driver_license",
    "national_id",
    "tckn",
    "tc_kimlik_no",
    "postal_code",
    "zip",
    "home_address",
]

SECRET_KEYS = [
    "password",
    "client_secret",
    "api_key",
    "refresh_token",
    "backup_codes",
    "recovery_codes",
    "seed_phrase",
    "mnemonic",
    "ssh_key",
    "sshKey",
    "kubeconfig",
    "keytab",
    "psk",
    "pre_shared_key",
    "wpa_key",
    "snmp_community",
    "storage_key",
    "shared_key",
    "saml_response",
    "SAMLResponse",
    "client_assertion",
    "code_verifier",
    "secret_id",
    "private_key_id",
    "access_key_id",
]


@pytest.mark.parametrize("key", PII_KEYS)
@pytest.mark.parametrize("value", ["x", "123", "Jane Placeholder", FAKE, 42])
def test_pii_keys_mask_any_value(key, value):
    assert pii_key(key), key
    out = Redactor(redact_pii=True).value("", {key: value})
    assert out[key] == REDACTED


@pytest.mark.parametrize("key", PII_KEYS)
def test_pii_keys_are_left_alone_with_redact_pii_off(key):
    out = Redactor(redact_pii=False).value("", {key: "Jane Placeholder"})
    assert out[key] == "Jane Placeholder"


@pytest.mark.parametrize("key", SECRET_KEYS)
@pytest.mark.parametrize("value", ["x1", "public", FAKE, "S-1-5-21-1-2-3-500"])
def test_credential_keys_mask_any_value(key, value):
    assert identifier_strength(key) == 2, key
    out = Redactor(redact_pii=False).value("", {key: value})
    assert out[key] == REDACTED


@pytest.mark.parametrize(
    "key", ["email_count", "phone_type", "email_verified_at", "address_id"]
)
def test_keys_about_personal_data_are_not_personal_data(key):
    assert not pii_key(key)


VALUE_SHAPES = [
    ("visa", "card 4111 1111 1111 1111 charged", "4111 1111"),
    ("visa_plain", "card 4111111111111111 charged", "4111111111111111"),
    ("amex", "amex 3782-822463-10005 used", "822463"),
    ("iban", "iban DE89370400440532013000 ok", "DE8937"),
    ("iban_spaced", "IBAN GB82 WEST 1234 5698 7654 32 ok", "5698 7654"),
    ("ssn", "ssn 078-05-1120 found", "078-05-1120"),
    ("tckn", "kimlik no 10000000146 ok", "10000000146"),
    ("phone_us", "call +1 202-555-0143 now", "555-0143"),
    ("phone_tr", "tel +90 532 000 00 00 now", "532 000"),
    ("email_literal", "mail admin@[192.0.2.1] sent", "admin@"),
    ("pypi", "py" "pi-AgEIcHlwaS5vcmc" + FAKE, FAKE),
    ("twilio_sk", "S" "K" + "0000ffff" * 4, "0000ffff" * 4),
    ("terraform", "atlas" "v1." + FAKE + FAKE, FAKE),
    ("snmp_community", f"snmpwalk -v2c -c {FAKE} 192.0.2.1", FAKE),
    ("snmp_v3", f"snmpget -v3 -l authPriv -u ops -A {FAKE} -X {FAKE}x h", FAKE),
]


@pytest.mark.parametrize(
    "label,text_,secret", VALUE_SHAPES, ids=[v[0] for v in VALUE_SHAPES]
)
def test_value_shapes_are_masked_in_text_and_details(label, text_, secret):
    r = Redactor(redact_pii=True)
    assert secret not in r.text(text_), label
    assert secret not in str(r.value("", {"note": text_})), label


@pytest.mark.parametrize(
    "text_",
    [
        "event 4111111111111112 rejected",  # fails Luhn
        "ts 1760400000000 ms",  # epoch milliseconds
        "aws account 123456789012",
        "order 12345678901 shipped",  # 11 digits, not a valid kimlik
        "build 2026-10-14 tag v1.2.3",
        "rule 000-00-0000 and 900-12-3456",  # not issuable SSNs
        "ip 192.0.2.10 port 8443",
        "counter +12 events",
    ],
)
def test_numbers_that_are_not_personal_data_survive(text_):
    assert Redactor(redact_pii=True).text(text_) == text_


# -- 3. over-masking: allowed identifier shapes --------------------------------

SID = "S-1-5-21-3623811015-3361044348-30300820-1013"
GUID = "6F9619FF-8B86-D011-B42D-00C04FC964FF"
UUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

PASS_THROUGH = {
    "sid": SID,
    "objectSid": SID,
    "user_sid": SID,
    "account_sid": SID,
    "subject_user_sid": SID,
    "auth_id": SID,
    "token_id": UUID,
    "key_id": GUID,
    "credential_id": GUID,
    "session_id": UUID,
    "object_guid": "{" + UUID + "}",
    "signature": SHA256,
    "sig": MD5,
    "cert_thumbprint": SHA1,
    "file_hash": SHA256,
    "token": "FND-7f3a9c21",
    "key": "CASE-2026-000123",
    "auth": "INC0012345",
    "pin": "T1003.001",
    "case_id": "CASE-2026-000123",
    "finding_id": "FND-7f3a9c21",
    "cve": "CVE-2024-3094",
    "password_last_set": "2026-10-01T10:00:00Z",
    "token_issued_at": "2026-10-01T10:00:00Z",
}


def test_identifiers_pass_through_in_details():
    for pii in (True, False):
        out = Redactor(redact_pii=pii).value("", dict(PASS_THROUGH))
        changed = {k: out[k] for k, v in PASS_THROUGH.items() if out[k] != v}
        assert changed == {}


@pytest.mark.parametrize("key", sorted(PASS_THROUGH))
def test_identifiers_pass_through_in_text(key):
    value = PASS_THROUGH[key]
    r = Redactor(redact_pii=True)
    for text_ in (
        f"user logon {key} {value} observed",
        f"{key}={value}",
        f'{{"{key}": "{value}", "msg": "ok"}}',
    ):
        assert value in r.text(text_), text_


def test_bare_identifiers_in_prose_survive():
    text_ = (
        f"Logon by {SID} on host {GUID}; sample {SHA256} (md5 {MD5}) "
        "linked to CASE-2026-000123 / FND-7f3a9c21, technique T1003.001"
    )
    assert Redactor(redact_pii=True).text(text_) == text_


@pytest.mark.parametrize(
    "details",
    [
        {"token": UUID},  # a GUID can be a bearer token
        {"token": SHA1},  # 40-hex: an API token shape
        {"key": "0000ffff" * 4},
        {"auth": GUID},
        {"cookie": UUID},
        {"password": GUID},  # STRONG keys mask every shape
        {"password": SID},
        {"client_secret": "CASE-2026-000123"},
        {"secret_id": UUID},  # Vault AppRole secret id
    ],
)
def test_credential_keys_still_mask_identifier_shapes(details):
    out = Redactor(redact_pii=False).value("", details)
    assert out == {k: REDACTED for k in details}


def test_signed_url_signature_is_masked_even_when_hex():
    url = f"https://bucket.example.com/o?X-Amz-Signature={SHA256}&sig={MD5}"
    out = Redactor().text(url)
    assert SHA256 not in out and MD5 not in out


def test_allowed_identifier_is_key_aware():
    assert allowed_identifier(SID) and allowed_identifier(SID, "token")
    assert allowed_identifier(UUID, "session_id")
    assert not allowed_identifier(UUID, "token")
    assert allowed_identifier(SHA256, "signature")
    assert not allowed_identifier(SHA256, "key")
    assert not allowed_identifier(SHA256)
    assert not allowed_identifier("Zq7Vx2Lm9Rt4", "sid")


# -- W1.10: signed audit-chain checkpoints -------------------------------------


@pytest.fixture
def checkpoint_db():
    engine = create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )

    @contextlib.contextmanager
    def scope():
        with Session(engine) as session:
            yield session
            session.commit()

    scope.engine = engine
    return scope


_DDL = """CREATE TABLE audit_checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT, created_at DATETIME,
    key_id TEXT, public_key TEXT, body TEXT, body_hash TEXT,
    prev_body_hash TEXT, signature TEXT, tsa_token TEXT)"""


def test_checkpoint_source_without_the_table_reads_nothing(checkpoint_db):
    src = AuditCheckpointSource(checkpoint_db, settle_s=0)
    cursor = src.initial_cursor("now")
    assert src.fetch(cursor, 10) == []
    with checkpoint_db.engine.begin() as conn:
        conn.execute(text(_DDL))
    assert src.fetch(cursor, 10) == []


def test_checkpoints_are_exported_verbatim(checkpoint_db):
    with checkpoint_db.engine.begin() as conn:
        conn.execute(text(_DDL))
    body = (
        '{"agent_events":{"heads":{}},"audit_chain":{"head":{"hash":"'
        + SHA256
        + '","seq":7}},"issued_at":"2026-10-01T00:00:00.000Z","key_id":"k1",'
        '"prev":"","v":1}'
    )
    signature = "FAKEsig0" * 11  # base64-shaped, would trip the scrubber
    with checkpoint_db.engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_checkpoints (created_at, key_id, public_key, "
                "body, body_hash, prev_body_hash, signature, tsa_token) VALUES "
                "(:t, 'k1', :pub, :body, :bh, '', :sig, NULL)"
            ),
            {
                "t": (T0 - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S.%f"),
                "pub": "ab" * 32,
                "body": body,
                "bh": SHA256,
                "sig": signature,
            },
        )
    src = AuditCheckpointSource(checkpoint_db, settle_s=0)
    rows = src.fetch(src.initial_cursor("beginning"), 10)
    assert len(rows) == 1
    ev, cursor = rows[0]
    assert ev.id == "audit_checkpoints:1" and cursor == {"id": 1}
    assert ev.details["audit_chain_head"] == {"hash": SHA256, "seq": 7}
    safe = Redactor(redact_pii=True).event(ev)
    assert safe.details["body"] == body
    assert safe.details["signature"] == signature
    assert safe.details["public_key"] == "ab" * 32
    assert "seq 7" in safe.message
