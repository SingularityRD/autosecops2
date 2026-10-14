"""Stream AutoSecOps' security-relevant events to a customer SIEM (WP w3.6).

What leaves, and from where:

========================  ==================================================
source                    read from
========================  ==================================================
``agent_events``          the agent ledger table (append-only, hash-chained)
``approvals``             ``approval_actions`` state transitions (requested,
                          decided, executed, verified, reversed)
``auth``                  a local append-only spool written by the auth and
                          user routers (login/logout/MFA/password/role change)
``config``                ``config_audit_log``
``case_audit``            ``case_audit_logs``
``audit_checkpoints``     W1.10's signed chain heads (``audit_checkpoints``):
                          each checkpoint body, its hash and Ed25519
                          signature, verbatim, so a copy of every head lives
                          outside the database. The ``audit_chain`` rows are
                          not exported: they chain ``approval_actions`` and
                          ``case_audit_logs``, which ``approvals`` and
                          ``case_audit`` already export.
========================  ==================================================

How it leaves: RFC 5424 syslog over TLS (RFC 5425 octet-counting framing), or
over plain TCP/UDP for labs, with structured data; or HTTPS POST of JSON or CEF.

Delivery is **at-least-once**. Each (destination, source) pair has a durable
cursor that is committed only after the destination accepted the batch, so a
restart re-reads whatever was in flight; every event carries a stable ``id``
for the receiver to deduplicate on. On Postgres the database cursors page in
transaction-id order and never pass the oldest transaction still running, so
a row committed late by a long transaction is waited for, not skipped (see
``_DbSource``). A failed delivery is retried with capped,
jittered exponential backoff and never dropped; the reader feeds a bounded
queue, so a dead receiver stalls reading instead of growing memory.

Off by default: with no ``compliance.audit_export`` system config, or with
``enabled: false``, nothing is spooled, no state directory is created and no
connection is opened. The field mapping and operator notes are in
``core/compliance/AUDIT_EXPORT.md``.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import fcntl
import functools
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import random
import re
import socket
import ssl
import tempfile
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import (
    Annotated,
    Any,
    Callable,
    ContextManager,
    Iterable,
    Literal,
    Optional,
    Union,
)
from urllib.parse import unquote, urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import DateTime, Integer, String, bindparam, text
from sqlalchemy.orm import Session

from core.platform.url_safety import (
    ALWAYS_REFUSED_REASONS,
    blocked_reason,
    ip_in_networks,
    parse_networks,
)
from core.telemetry_sanitizer import (
    _CONTENT_KEY_SUBSTRINGS,
    _SECRET_VALUE_PATTERNS,
    SensitiveAttributeScrubber,
)
from core.version import __version__

logger = logging.getLogger(__name__)

CONFIG_KEY = "compliance.audit_export"
SCHEMA = "autosecops.audit.v1"
PRODUCT = "AutoSecOps"
APP_NAME = "autosecops"
# RFC 5612 documentation PEN: a private-use SD-ID that needs no IANA number.
SD_ID = "autosecops@32473"

SOURCE_NAMES = (
    "agent_events",
    "approvals",
    "auth",
    "config",
    "case_audit",
    "audit_checkpoints",
)
APPROVAL_TRANSITIONS = ("created", "decided", "executed", "verified", "reversed")

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_DEST_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def secret_name(destination: str, kind: Literal["TOKEN", "CLIENT_KEY"]) -> str:
    """The secrets-manager key for one destination's credential.

    Derived from the destination name and never configurable, so a config
    write cannot point the exporter at another credential (an LLM key, say)
    and send it to an endpoint of the writer's choosing.
    """
    return f"AUDIT_EXPORT_{destination.upper().replace('-', '_')}_{kind}"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _TlsOptions(_Strict):
    tls_verify: bool = Field(
        True, description="Verify the receiver's certificate and hostname."
    )
    ca_pem: Optional[str] = Field(
        None,
        max_length=65536,
        description="PEM CA bundle to trust instead of the system store.",
    )
    client_cert_pem: Optional[str] = Field(
        None,
        max_length=65536,
        description="PEM client certificate for mutual TLS; its key is a secret.",
    )

    @field_validator("ca_pem", "client_cert_pem")
    @classmethod
    def _pem(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and "-----BEGIN CERTIFICATE-----" not in value:
            raise ValueError("must be a PEM certificate")
        return value


class _NamedDestination(_TlsOptions):
    name: str

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not _DEST_NAME.match(value):
            raise ValueError("lower-case letters, digits, '-' or '_', at most 32")
        return value


class SyslogDestination(_NamedDestination):
    type: Literal["syslog"]
    host: str = Field(..., min_length=1, max_length=253)
    port: int = Field(6514, ge=1, le=65535)
    protocol: Literal["tls", "tcp", "udp"] = "tls"
    format: Literal["rfc5424", "cef"] = "rfc5424"
    facility: int = Field(13, ge=0, le=23, description="13 = log audit.")
    max_message_bytes: int = Field(8192, ge=480, le=65000)
    timeout_s: float = Field(10.0, gt=0, le=120)

    @field_validator("host")
    @classmethod
    def _host(cls, value: str) -> str:
        refuse_reserved_literal(value)
        return value


class HttpDestination(_NamedDestination):
    type: Literal["http"]
    url: str = Field(..., max_length=2048)
    format: Literal["json", "cef"] = "json"
    auth_header: str = Field("Authorization", pattern=r"^[A-Za-z0-9-]{1,64}$")
    auth_scheme: str = Field("Bearer", pattern=r"^[A-Za-z0-9._-]{0,32}$")
    allow_plaintext: bool = Field(
        False, description="Permit http:// (labs only; the token travels in clear)."
    )
    timeout_s: float = Field(10.0, gt=0, le=120)

    @model_validator(mode="after")
    def _url(self) -> "HttpDestination":
        parsed = urlparse(self.url)
        if parsed.scheme not in ("https", "http") or not parsed.hostname:
            raise ValueError("url must be an absolute https:// URL")
        if parsed.scheme == "http" and not self.allow_plaintext:
            raise ValueError("http:// needs allow_plaintext: true")
        if parsed.username or parsed.password:
            raise ValueError("put credentials in the token secret, not the URL")
        refuse_reserved_literal(parsed.hostname)
        return self


Destination = Annotated[
    Union[SyslogDestination, HttpDestination], Field(discriminator="type")
]


class SourceToggles(_Strict):
    agent_events: bool = True
    approvals: bool = True
    auth: bool = True
    config: bool = True
    case_audit: bool = True
    audit_checkpoints: bool = True

    def enabled(self) -> list[str]:
        return [name for name in SOURCE_NAMES if getattr(self, name)]


class AuditExportConfig(_Strict):
    enabled: bool = False
    start_from: Literal["now", "beginning"] = "now"
    sources: SourceToggles = Field(default_factory=SourceToggles)
    agent_event_kinds: list[str] = Field(
        default_factory=list,
        max_length=100,
        description="Ledger kinds to export; empty exports every kind.",
    )
    redact_pii: bool = True
    batch_size: int = Field(100, ge=1, le=1000)
    queue_max: int = Field(1000, ge=10, le=100_000)
    poll_interval_s: float = Field(5.0, ge=0.05, le=300)
    settle_s: float = Field(
        5.0,
        ge=0,
        le=300,
        description="Non-Postgres databases only (tests): rows younger than "
        "this are left for the next poll. On Postgres the cursor is bounded by "
        "the oldest running transaction instead, so no wait is needed.",
    )
    max_backoff_s: float = Field(60.0, ge=0.1, le=3600)
    horizon_alert_s: float = Field(
        600.0,
        ge=30,
        le=86400,
        description="Postgres only: flag export as lagging (status "
        "horizon.stalled, metric xid_horizon_stalled) when the oldest running "
        "transaction has held the export horizon this long, e.g. a session "
        "left idle in transaction.",
    )
    spool_max_bytes: int = Field(256 * 1024 * 1024, ge=1024 * 1024, le=10 * 1024**3)
    destinations: list[Destination] = Field(default_factory=list, max_length=8)

    @model_validator(mode="after")
    def _unique(self) -> "AuditExportConfig":
        names = [d.name for d in self.destinations]
        if len(names) != len(set(names)):
            raise ValueError("destination names must be unique")
        if self.enabled and not self.destinations:
            raise ValueError("enabled needs at least one destination")
        return self

    def fingerprint(self) -> str:
        return hashlib.sha256(
            json.dumps(self.model_dump(mode="json"), sort_keys=True).encode()
        ).hexdigest()


# Metadata host names; the addresses are url_safety.CLOUD_METADATA_ADDRESSES.
_METADATA_NAMES = frozenset(
    {"metadata.google.internal", "metadata", "metadata.azure.internal"}
)
# Where a customer SIEM or a local relay may legitimately live, on top of the
# public internet: loopback, RFC 1918, carrier-grade NAT (VPN overlays) and
# IPv6 unique-local. Link-local, multicast, unspecified, reserved and the
# metadata addresses (even inside these ranges) stay refused — see
# ``core.platform.url_safety``, which every check here goes through.
SIEM_NETWORKS = parse_networks(
    "127.0.0.0/8, ::1/128, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, "
    "100.64.0.0/10, fc00::/7"
)


def _egress_refusal(addr: str) -> Optional[str]:
    """Why ``addr`` may not be dialled, or None. ``url_safety`` decides."""
    reason = blocked_reason(addr)
    if reason is None:
        return None
    if reason in ALWAYS_REFUSED_REASONS:
        return reason
    try:
        if ip_in_networks(addr, SIEM_NETWORKS):
            return None
    except ValueError:
        pass
    return reason


def refuse_reserved_literal(host: str) -> None:
    """Refuse (at config time) a host that is a forbidden address on its face."""
    if host.lower().rstrip(".") in _METADATA_NAMES:
        raise ValueError("metadata hosts are not a valid destination")
    literal = host.strip("[]")
    if "%" in literal:
        raise ValueError("scoped address refused")
    try:
        ipaddress.ip_address(literal)
    except ValueError:
        return
    reason = _egress_refusal(literal)
    if reason:
        raise ValueError(f"{reason} refused")


def resolve_egress(host: str, port: int) -> list[str]:
    """Resolve ``host`` once and return the addresses to dial — and only those.

    Every address in the answer must pass (one forbidden address refuses the
    host). Callers connect to the returned IPs, never to the name again, so a
    second DNS answer cannot swap in the metadata service between this check
    and the connection (DNS rebinding). Loopback, private, CGNAT and ULA stay
    allowed: a customer SIEM or a local relay usually lives there.
    """
    try:
        refuse_reserved_literal(host)
    except ValueError as exc:
        raise DeliveryError("egress_refused") from exc
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise DeliveryError("dns_failed") from exc
    addresses: list[str] = []
    for info in infos:
        addr = str(info[4][0])  # a zone id is kept: it is refused
        if addr in addresses:
            continue
        if _egress_refusal(addr):
            raise DeliveryError("egress_refused")
        addresses.append(addr)
    if not addresses:
        raise DeliveryError("dns_failed")
    return addresses


# ---------------------------------------------------------------------------
# Events and redaction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditEvent:
    """One exported event. ``id`` is stable across re-reads (dedupe key)."""

    id: str
    source: str
    category: str
    action: str
    outcome: str
    severity: int  # 0..10, the CEF scale
    timestamp: datetime  # aware, UTC
    message: str
    actor: Optional[str] = None
    actor_id: Optional[str] = None
    target_type: Optional[str] = None
    target_id: Optional[str] = None
    src_ip: Optional[str] = None
    user_agent: Optional[str] = None
    hash: Optional[str] = None
    details: dict = field(default_factory=dict)

    def to_dict(self, host: str) -> dict:
        return {
            "schema": SCHEMA,
            "id": self.id,
            "timestamp": iso_utc(self.timestamp),
            "source": self.source,
            "category": self.category,
            "action": self.action,
            "outcome": self.outcome,
            "severity": self.severity,
            "message": self.message,
            "actor": {"name": self.actor, "id": self.actor_id},
            "target": {"type": self.target_type, "id": self.target_id},
            "src_ip": self.src_ip,
            "user_agent": self.user_agent,
            "hash": self.hash,
            "details": self.details,
            "observer": {"product": PRODUCT, "version": __version__, "host": host},
        }


def as_utc(value: Any) -> datetime:
    """A DB/ISO timestamp as an aware UTC datetime (naive columns are UTC)."""
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def iso_utc(value: datetime) -> str:
    return as_utc(value).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


REDACTED = "[REDACTED]"
REDACTED_EMAIL = "[REDACTED-EMAIL]"
REDACTED_PII = "[REDACTED-PII]"
# Longest single string the scrubber looks at. Longer input is cut to this
# before any pattern runs, so one oversized field (a pasted log, a 10 MB user
# agent) costs bounded time; ``Redactor`` cuts further, to ``max_string`` plus
# a margin, so what it exports was scanned with its right-hand context.
MAX_FIELD_CHARS = 16_384
_SCAN_MARGIN = 512
_TRUNCATED = "...[truncated]"

# -- e-mail addresses: a linear-time scanner, not a regular expression ---------
#
# The former ``[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`` was quadratic:
# on a long run of local-part characters with no ``@`` (``"a" * n``) every
# start position rescanned the rest of the run (20 000 characters: 0.4 s, on
# the event loop). Here each ``@`` is found with ``str.find`` and the local
# part / domain are walked outward from it. A left walk stops at the previous
# ``@`` or match, a right walk at the next ``@``, so walks never overlap and
# the whole scan is O(n).
_EMAIL_LOCAL_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-"
)
_EMAIL_DOMAIN_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-"
)
_EMAIL_MAX_LITERAL = 64  # ``user@[192.0.2.1]``, ``user@[IPv6:2001:db8::1]``


def _email_end(text_: str, at: int) -> int:
    """End of the domain of an address whose ``@`` is at ``at``, or -1.

    Accepts what the former pattern did (domain characters up to the last
    ``.`` followed by two or more letters), plus a bracketed IP literal."""
    n = len(text_)
    start = at + 1
    if start < n and text_[start] == "[":
        close = text_.find("]", start, start + _EMAIL_MAX_LITERAL)
        if close > start + 1:
            inner = text_[start + 1 : close]
            if inner.lower().startswith("ipv6:"):
                inner = inner[5:]
            with contextlib.suppress(ValueError):
                ipaddress.ip_address(inner)
                return close + 1
        return -1
    end = start
    while end < n and text_[end] in _EMAIL_DOMAIN_CHARS:
        end += 1
    dot = text_.rfind(".", start + 1, end)
    while dot != -1:
        tld = dot + 1
        while tld < end and text_[tld].isascii() and text_[tld].isalpha():
            tld += 1
        if tld - dot - 1 >= 2:
            return tld
        dot = text_.rfind(".", start + 1, dot)
    return -1


# Candidate ``@``: a local-part character before it and a dot (or ``[``)
# ahead within its domain run. The lookahead stops at the next character that
# cannot be in a domain (another ``@`` included), so the lookaheads of
# different ``@`` cover disjoint text: linear, and the Python walk below only
# runs for plausible addresses.
_EMAIL_AT = re.compile(r"(?<=[A-Za-z0-9._%+\-])@(?=[A-Za-z0-9\-]*\.|\[)")


def email_spans(text_: str) -> list[tuple[int, int]]:
    """``(start, end)`` of each e-mail address in ``text_``, in O(len)."""
    spans: list[tuple[int, int]] = []
    if "@" not in text_:
        return spans
    floor = 0
    for m in _EMAIL_AT.finditer(text_):
        at = m.start()
        if at < floor:
            continue
        lo = at
        # Stop at the previous match, and at the previous ``@``: walks of
        # different candidates never overlap.
        while lo > floor and text_[lo - 1] in _EMAIL_LOCAL_CHARS:
            lo -= 1
        end = _email_end(text_, at) if lo < at else -1
        if end != -1:
            spans.append((lo, end))
            floor = end
        else:
            floor = at + 1
    return spans


def mask_emails(text_: str, replacement: str = REDACTED_EMAIL) -> str:
    spans = email_spans(text_)
    if not spans:
        return text_
    out: list[str] = []
    pos = 0
    for lo, hi in spans:
        out.append(text_[pos:lo])
        out.append(replacement)
        pos = hi
    out.append(text_[pos:])
    return "".join(out)


# -- other personal data in free text ------------------------------------------
#
# Each shape is validated (Luhn, IBAN mod 97, T.C. kimlik checksum, SSN
# ranges, digit count) so the many numeric ids in audit text (event ids,
# epoch milliseconds, cloud account numbers) are not taken for one. Every
# pattern starts at a boundary and every quantifier is bounded: linear time.
_CARD = re.compile(r"(?<![\w\-.])[2-6]\d{3}(?:[ \-]?\d){9,15}(?![\w\-]|\.\d)")
_IBAN = re.compile(
    r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}"
    r"(?:[A-Z0-9]{11,30}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?)"
    r"(?![A-Za-z0-9])"
)
_SSN = re.compile(r"(?<![\w\-])(\d{3})-(\d{2})-(\d{4})(?![\w\-])")
_TCKN = re.compile(r"(?<![\w\-.])[1-9]\d{10}(?![\w\-]|\.\d)")
_PHONE = re.compile(r"(?<![\w+])\+[1-9][\d \-.()]{6,20}\d(?![\w\-])")


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _card_redaction(m: "re.Match[str]") -> str:
    digits = "".join(c for c in m.group(0) if c.isdigit())
    return REDACTED_PII if 13 <= len(digits) <= 19 and _luhn(digits) else m.group(0)


def _iban_redaction(m: "re.Match[str]") -> str:
    raw = m.group(0).replace(" ", "")
    if not 15 <= len(raw) <= 34:
        return m.group(0)
    moved = raw[4:] + raw[:4]
    number = int("".join(str(int(c, 36)) for c in moved))
    return REDACTED_PII if number % 97 == 1 else m.group(0)


def _ssn_redaction(m: "re.Match[str]") -> str:
    area, group, serial = m.group(1), m.group(2), m.group(3)
    if area in ("000", "666") or area[0] == "9" or group == "00" or serial == "0000":
        return m.group(0)
    return REDACTED_PII


def _tckn_valid(s: str) -> bool:
    d = [ord(c) - 48 for c in s]
    odd = d[0] + d[2] + d[4] + d[6] + d[8]
    even = d[1] + d[3] + d[5] + d[7]
    return (odd * 7 - even) % 10 == d[9] and sum(d[:10]) % 10 == d[10]


def _phone_redaction(m: "re.Match[str]") -> str:
    digits = sum(c.isdigit() for c in m.group(0))
    return REDACTED_PII if 8 <= digits <= 15 else m.group(0)


def mask_personal_data(text_: str) -> str:
    """Mask e-mail addresses, payment card numbers, IBANs, US SSNs, Turkish
    national ids (T.C. kimlik) and ``+``-prefixed phone numbers in text."""
    out = mask_emails(text_)
    out = _IBAN.sub(_iban_redaction, out)
    out = _CARD.sub(_card_redaction, out)
    out = _SSN.sub(_ssn_redaction, out)
    out = _TCKN.sub(
        lambda m: REDACTED_PII if _tckn_valid(m.group(0)) else m.group(0), out
    )
    return _PHONE.sub(_phone_redaction, out)


# -- identifiers that are neither personal data nor credentials ----------------
#
# A value behind a WEAK key (``token``, ``sig``, ``sid``, ``session_id``) or
# after one in free text passes through when it has the shape of an object
# identifier. Which shapes depends on the key: a ticket id is never a token,
# but a GUID can be one (``token: <uuid>``) and a hex string can be an API key
# (``key: <40 hex>``), so GUIDs pass only under id-like keys and hex digests
# only under signature/hash-like keys. A STRONG key (``password``) masks
# every shape: a GUID can be a password.
_ID_ANY_KEY = re.compile(
    r"S-1-\d{1,2}(?:-\d{1,10}){1,15}"  # Windows SID
    r"|T\d{4}(?:\.\d{3})?"  # MITRE ATT&CK technique
    r"|CVE-\d{4}-\d{4,7}"
    r"|[A-Z]{2,10}(?:-\d{1,10}){1,3}"  # CASE-2026-000123, SEC-4821
    r"|[A-Z]{2,10}\d{4,12}"  # INC0012345
    r"|[A-Z]{2,10}-[0-9a-f]{6,16}"  # FND-7f3a9c21
)
_ID_GUID = re.compile(
    r"\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?"
    r"|[0-7][0-9A-HJKMNP-TV-Z]{25}"  # ULID
)
_ID_DIGEST = re.compile(
    r"(?:(?:md5|sha1|sha-1|sha256|sha-256|sha512|sha-512):)?"
    r"(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{56}|[0-9a-fA-F]{64}"
    r"|[0-9a-fA-F]{96}|[0-9a-fA-F]{128})"
)
_CREDENTIAL_WEAK = frozenset(
    {"token", "auth", "key", "pass", "cookie", "cookies", "sas", "otp", "totp", "pin"}
)
_SIGNATURE_WEAK = frozenset(
    {"sig", "signature", "hash", "digest", "checksum", "fingerprint", "thumbprint"}
)


def allowed_identifier(value: str, key: str = "") -> bool:
    """Whether ``value`` (whole) is an object identifier that may pass under
    the WEAK key ``key`` (unknown key: only the shapes safe under any key)."""
    s = value.strip()
    if len(s) >= 2 and s[0] in "\"'" and s[-1] == s[0]:
        s = s[1:-1]
    if not 0 < len(s) <= 140:
        return False
    if _ID_ANY_KEY.fullmatch(s):
        return True
    segments = set(key_segments(key.strip("\"'-\\ :"))) if key else set()
    if not segments:
        return False
    if segments & _SIGNATURE_WEAK and _ID_DIGEST.fullmatch(s):
        return True
    return not (segments & _CREDENTIAL_WEAK) and _ID_GUID.fullmatch(s) is not None


# Keys naming personal data: a whole segment (``email``, ``userEmail``,
# ``contact_phone``), consecutive segments (``first_name``,
# ``date_of_birth``) or a whole short key (``pan``, ``zip``).
_PII_KEYS = frozenset(
    {"email", "phone", "full_name", "ssn", "national_id", "tckn", "address"}
)
_PII_SEGMENTS = frozenset(
    {
        "email",
        "emails",
        "phone",
        "phones",
        "mobile",
        "telephone",
        "msisdn",
        "ssn",
        "tckn",
        "iban",
        "passport",
        "dob",
        "birthdate",
        "birthday",
        "surname",
        "cvv",
        "cvc",
        "cvv2",
        "address",
    }
)
_PII_PHRASES = tuple(
    tuple(p.split("_"))
    for p in (
        "full_name",
        "first_name",
        "last_name",
        "middle_name",
        "given_name",
        "family_name",
        "maiden_name",
        "date_of_birth",
        "birth_date",
        "national_id",
        "social_security",
        "tax_id",
        "tax_number",
        "driver_license",
        "drivers_license",
        "driving_licence",
        "card_number",
        "credit_card",
        "debit_card",
        "cc_number",
        "postal_code",
        "zip_code",
        "tc_kimlik",
        "kimlik_no",
    )
)
_PII_LEAVES = frozenset({"pan", "zip", "postcode"})


def pii_key(name: str) -> bool:
    """Whether a key names personal data (``email``, ``userPhone``,
    ``first_name``, ``date_of_birth``, ``iban``, ``pan``), so its value is
    masked whatever it looks like. ``email_count`` / ``phone_type`` are about
    personal data, not personal data."""
    lowered = name.lower()
    if lowered in _PII_KEYS or lowered in _PII_LEAVES:
        return True
    segments = key_segments(name)
    if _has_phrase(segments, _PII_PHRASES):
        return True
    if len(segments) > 1 and segments[-1] in _NON_SECRET_LEAVES:
        return False
    return bool(_PII_SEGMENTS.intersection(segments))


# Keys naming who acted. The audit trail exists to answer "who did this", so
# these are exported verbatim even with ``redact_pii`` on (secrets inside them
# are still cut). See AUDIT_EXPORT.md, "Redaction policy".
_ACTOR_KEYS = frozenset(
    {
        "actor",
        "actor_name",
        "actor_email",
        "user",
        "username",
        "user_name",
        "login",
        "approver",
        "approved_by",
        "decided_by",
        "created_by",
        "updated_by",
        "requested_by",
        "performed_by",
        "assignee",
        "reviewer",
        "analyst",
    }
)
_KEY_SPLIT = re.compile(r"[._\-\s/]+")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

# How sure a key name is that its value is a credential.
#   STRONG: ``password``, ``api_key``, ``client_secret``: the value goes,
#           whatever it looks like.
#   WEAK:   ``token``, ``key``, ``auth``, ``pin``, ``sig``, ``session_id``:
#           as often a status, a count, an id or a rule name (``auth: failed``,
#           ``key: SEC-4821``, ``signature: ET MALWARE ...``) as a secret, so
#           the value goes only when it reads as one (:func:`_secretish`).
WEAK = 1
STRONG = 2

_SECRET_WORDS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "passcode",
        "passkey",
        "secret",
        "secrets",
        "credential",
        "credentials",
        "creds",
        "apikey",
        "dsn",
        "jwt",
        "bearer",
        "authorization",
        "privatekey",
        "privkey",
        "clientkey",
        "authkey",
        "hmackey",
        "appkey",
        "phpsessid",
        "jsessionid",
        "aspsessionid",
        "mnemonic",
        "seedphrase",
        "sshkey",
        "kubeconfig",
        "keytab",
        "psk",
        "samlresponse",
    }
)
_WEAK_WORDS = frozenset(
    {
        "token",
        "pin",
        "sig",
        "signature",
        "otp",
        "totp",
        "cookie",
        "cookies",
        "sas",
        "sid",
        "sessionid",
    }
)
_SECRET_PHRASES = tuple(
    tuple(p.split("_"))
    for p in (
        "api_key",
        "access_key",
        "secret_key",
        "private_key",
        "priv_key",
        "signing_key",
        "encryption_key",
        "enc_key",
        "master_key",
        "account_key",
        "shared_access_key",
        "client_key",
        "auth_key",
        "hmac_key",
        "app_key",
        "license_key",
        "subscription_key",
        "functions_key",
        "function_key",
        "host_key",
        "key_material",
        "client_secret",
        "access_token",
        "refresh_token",
        "id_token",
        "auth_token",
        "webhook_url",
        "database_url",
        "db_url",
        "redis_url",
        "broker_url",
        "mongo_url",
        "mongodb_uri",
        "connection_string",
        "conn_str",
        "mfa_secret",
        "recovery_codes",
        "backup_codes",
        "seed_phrase",
        "ssh_key",
        "storage_key",
        "shared_key",
        "pre_shared_key",
        "wpa_key",
        "wifi_key",
        "snmp_community",
        "community_string",
        "saml_response",
        "client_assertion",
        "code_verifier",
    )
)
_WEAK_PHRASES = tuple(
    tuple(p.split("_"))
    for p in (
        "session_id",
        "session_key",
        "set_cookie",
        "mfa_code",
        "auth_code",
        "verification_code",
        "oauth_code",
        "authorization_code",
    )
)
# A one-word key that is a credential only on its own (``auth``, not
# ``auth_scheme``), and only when its value reads as one.
_WEAK_LEAVES = frozenset({"pass", "key", "auth", "session"})
# ``token_count``, ``password_policy``, ``credential_dumping``,
# ``cookie_consent``: about a credential, not one.
_NON_SECRET_LEAVES = frozenset(
    {
        "count",
        "counts",
        "usage",
        "used",
        "limit",
        "limits",
        "length",
        "len",
        "budget",
        "type",
        "kind",
        "method",
        "scheme",
        "mode",
        "status",
        "state",
        "expiry",
        "expires",
        "expired",
        "expiration",
        "ttl",
        "age",
        "enabled",
        "required",
        "changed",
        "sent",
        "consent",
        "rotated",
        "rotation",
        "policy",
        "dumping",
        "stuffing",
        "spraying",
        "harvesting",
        "theft",
        "reuse",
        "manager",
        "provider",
        "strength",
        "hint",
        "name",
        "names",
        # ``token_id``, ``credential_id``, ``user_sid``-like references and
        # timestamps (``password_last_set``, ``token_issued_at``): about a
        # credential, not one. ``secret_id`` (Vault AppRole) and
        # ``session_id`` are handled before this list (identifier_strength).
        "id",
        "ids",
        "uuid",
        "guid",
        "arn",
        "at",
        "set",
        "date",
        "time",
        "timestamp",
        "version",
    }
)
# ``<word>_id`` that is a credential after all.
_ID_LEAVES = frozenset({"id", "ids"})
_SECRET_ID_PREFIXES = frozenset({"secret"})  # Vault AppRole ``secret_id``
_WEAK_ID_PREFIXES = frozenset({"session"})
# Words containing a secret word that are not about one.
_NOT_EMBEDDED = ("secretary", "secretariat")


def key_segments(path: str) -> list[str]:
    """``details.webhookUrl`` -> ``["details", "webhook", "url"]``."""
    return [s for s in _KEY_SPLIT.split(_CAMEL.sub("_", path).lower()) if s]


def _has_phrase(segments: list[str], phrases: tuple) -> bool:
    for phrase in phrases:
        n = len(phrase)
        for i in range(len(segments) - n + 1):
            if tuple(segments[i : i + n]) == phrase:
                return True
    return False


# A free-text key (``PGPASSWORD``, ``dbPass``, ``x_api_key``, ``--password``)
# is STRONG when it contains one of these words anywhere (no separator
# needed: ``PGPASSWORD``, ``MYSQLPWD``, ``NEW_RELIC_LICENSE_KEY``).
_EMBEDDED_WORDS = (
    "password",
    "passwd",
    "passphrase",
    "passcode",
    "passkey",
    "secret",
    "apikey",
    "accesskey",
    "privatekey",
    "privkey",
    "clientkey",
    "authkey",
    "hmackey",
    "appkey",
    "licensekey",
    "subscriptionkey",
    "functionskey",
    "credential",
    "authtoken",
    "accesstoken",
    "refreshtoken",
    "sessiontoken",
    "securitytoken",
    "vaulttoken",
    "phpsessid",
    "jsessionid",
    "aspsessionid",
)
# ``…pass`` / ``…pwd`` glued to a prefix (``DBPASS``, ``MYSQLPWD``) unless the
# word is an ordinary one that happens to end that way.
_GLUED_SUFFIXES = ("pass", "pwd")
_NOT_GLUED = frozenset({"bypass", "compass", "surpass", "overpass", "underpass"})
# Flags naming where a secret comes from rather than the secret itself.
_INDIRECT_FLAG = re.compile(r"(?i)[-_](?:stdin|file|path|env|prompt|policy)$")


def _id_strength(segments: list[str]) -> int:
    """``<prefix>_id`` keys that still name a credential: ``secret_id``
    (Vault AppRole), ``private_key_id`` / ``access_key_id`` (a STRONG phrase
    before ``id``) are STRONG, ``session_id`` WEAK; other ids (``token_id``,
    ``key_id``, ``credential_id``) 0."""
    if len(segments) < 2 or segments[-1] not in _ID_LEAVES:
        return 0
    prefix = segments[:-1]
    if prefix[-1] in _SECRET_ID_PREFIXES or _has_phrase(prefix, _SECRET_PHRASES):
        return STRONG
    if prefix[-1] in _WEAK_ID_PREFIXES:
        return WEAK
    return 0


def _non_secret_leaf(segments: list[str]) -> bool:
    """``token_count``, ``credential_id``, ``password_last_set``: a key about
    a credential. Not ``secret_id``, ``private_key_id``, ``session_id``."""
    if len(segments) < 2 or segments[-1] not in _NON_SECRET_LEAVES:
        return False
    return not _id_strength(segments)


@functools.lru_cache(maxsize=8192)
def identifier_strength(name: str) -> int:
    """0, :data:`WEAK` or :data:`STRONG`: how surely a key, flag, tag or
    ``name`` field names a credential.

    Word-boundary and camelCase aware: ``dbPass``, ``DB_PASSWORD``,
    ``PGPASSWORD``, ``--password``, ``clientKey``, ``DD_APP_KEY``,
    ``bot_token`` are STRONG; ``token``, ``key``, ``auth``, ``pin``,
    ``signature``, ``session_id`` are WEAK; ``max_tokens``, ``bypass``,
    ``token_count``, ``config_key`` are 0.
    """
    bare = name.strip("\"'-\\ :")
    if not bare or len(bare) > 256:
        return 0
    segments = key_segments(bare)
    if not segments:
        return 0
    leaf = segments[-1]
    id_strength = _id_strength(segments)
    if id_strength:
        return id_strength
    if _non_secret_leaf(segments):
        return 0
    flat = re.sub(r"[^a-z0-9]", "", bare.lower())
    if any(word in flat for word in _EMBEDDED_WORDS) and not any(
        word in flat for word in _NOT_EMBEDDED
    ):
        return STRONG
    if _SECRET_WORDS.intersection(segments) or _has_phrase(segments, _SECRET_PHRASES):
        return STRONG
    if len(segments) > 1 and leaf in {"pass", "pw", "pwd", "token"}:
        return STRONG  # ``ssh_pass``, ``bot_token``, ``NPM_TOKEN``
    if leaf in {"pw", "pwd"}:
        return STRONG
    if leaf != "pass" and leaf not in _NOT_GLUED and leaf.endswith(_GLUED_SUFFIXES):
        return STRONG
    if _WEAK_WORDS.intersection(segments) or _has_phrase(segments, _WEAK_PHRASES):
        return WEAK
    if len(segments) == 1 and leaf in _WEAK_LEAVES:
        return WEAK
    return 0


def secret_key(path: str) -> bool:
    """Whether a dict key (or dotted path) may name a credential."""
    return identifier_strength(path) > 0


def secret_identifier(name: str) -> bool:
    """Whether a free-text key, flag, tag or ``name`` field may name a
    credential (STRONG or WEAK)."""
    return identifier_strength(name) > 0


def _numeric_identifier(name: str) -> bool:
    """A key whose secret is a number: ``pin``, ``otp``, ``mfa_code``."""
    return bool(
        {"pin", "otp", "totp", "mfa", "passcode", "code"}.intersection(
            key_segments(name.strip("\"'-\\ :"))
        )
    )


# Values that are a state, never a secret: ``auth: failed``, ``token:
# expired``, ``pin: true``, ``sig: valid``.
_STATUS_WORDS = frozenset(
    {
        "true",
        "false",
        "none",
        "null",
        "nil",
        "undefined",
        "yes",
        "no",
        "ok",
        "on",
        "off",
        "valid",
        "invalid",
        "verified",
        "unverified",
        "failed",
        "failure",
        "success",
        "succeeded",
        "successful",
        "expired",
        "revoked",
        "rotated",
        "required",
        "optional",
        "enabled",
        "disabled",
        "missing",
        "present",
        "absent",
        "set",
        "unset",
        "pending",
        "approved",
        "denied",
        "rejected",
        "accepted",
        "granted",
        "allowed",
        "blocked",
        "locked",
        "unlocked",
        "active",
        "inactive",
        "unknown",
        "empty",
        "hidden",
        "masked",
        "redacted",
        "changed",
        "reset",
        "sent",
        "received",
    }
)
_HEX_RUN = re.compile(r"[0-9a-fA-F]{32,}")
_TOKEN_CHARS = re.compile(r"[A-Za-z0-9+/=_\-.~]+")
_WORD_PIECES = re.compile(r"[-_.:@]+")


def _wordy(value: str) -> bool:
    """``case-session-1``, ``created_at``, ``lateral-movement``: an identifier
    made of words and small numbers, not random material."""
    pieces = [p for p in _WORD_PIECES.split(value) if p]
    return bool(pieces) and all(
        p.isalpha() or (p.isdigit() and len(p) <= 6) for p in pieces
    )


# A value is judged on its first characters only: whether ``token: <x>`` reads
# as a secret does not need all of a 16 KB ``x``, and judging it whole made
# ``token:token:token:…`` quadratic.
_SECRETISH_SCAN = 256
_NUMERIC_SECRET = re.compile(r"\d{4,12}")
_WHITESPACE = re.compile(r"\s")
_DIGIT = re.compile(r"\d")
_SYMBOL = re.compile(r"[!@#$%^*+=~]")


def _secretish(value: str, numeric_ok: bool = False, key: Optional[str] = "") -> bool:
    """Whether a value behind a WEAK key reads as a credential rather than a
    status word, a count, a rule name, a registry path or an object id.

    ``key`` is the WEAK key the value sits under: object-id shapes allowed
    under it (:func:`allowed_identifier`) are not secrets. ``None`` turns
    the id shapes off (URL ``?sig=``/``?code=``: a signed URL is a bearer
    credential whatever its signature looks like)."""
    s = value.strip()
    if len(s) >= 2 and s[0] in "\"'" and s[-1] == s[0]:
        s = s[1:-1]
    if len(s) > _SECRETISH_SCAN:
        s = s[:_SECRETISH_SCAN]
    if numeric_ok and _NUMERIC_SECRET.fullmatch(s):
        return True
    if len(s) < 6 or _WHITESPACE.search(s) or s.startswith("[REDACTED"):
        return False
    if s.lower() in _STATUS_WORDS:
        return False
    if key is not None and allowed_identifier(s, key):
        return False
    if "\\" in s or s.startswith("/"):
        return False  # a registry key or a path
    if _HEX_RUN.fullmatch(s):
        return True
    # str methods and one regex search, not per-character Python loops.
    upper = s != s.lower()
    lower = s != s.upper()
    digit = _DIGIT.search(s) is not None
    if len(s) >= 8 and upper and lower and digit:
        return True
    if len(s) >= 8 and (digit or upper) and _SYMBOL.search(s):
        return True
    if len(s) >= 12 and digit and (upper or lower) and not _wordy(s):
        return True
    return len(s) >= 20 and bool(_TOKEN_CHARS.fullmatch(s)) and not _wordy(s)


# -- free text ---------------------------------------------------------------

_IDENT = r"-{0,2}[A-Za-z_][A-Za-z0-9_.\-]{0,255}"
# ``key=value``, ``"key": "value"``, ``key%3Dvalue`` (URL-encoded),
# ``'key' => 'value'`` (PHP, Ruby, Perl), with an optional quote (plain or
# JSON-escaped) closing the key.
_KEY_SEP = re.compile(
    r"(?<![A-Za-z0-9_.\-%])(\\?[\"']?)(" + _IDENT + r")"
    r"((?:\\?[\"'])?[ \t]*(?:=>|=|:|%3[Dd]|%3[Aa])[ \t]*)"
)
# ``PASSWORD<tab>value``, ``token value``, ``--password value``.
_KEY_SPACE = re.compile(r"(?<![A-Za-z0-9_.\-%=:/\\])(" + _IDENT + r")([ \t]+)")
# Every quantifier is bounded: a value is matched at each ``key=`` in the
# text, and an unbounded value ran to the end of the line each time, which
# made ``key:key:key:…`` quadratic. An unquoted value that reaches the bound
# is extended (:func:`_value_end`) only when it is being cut, after which the
# scan resumes past it: linear overall.
_VALUE_MAX = 1024
_VALUE = re.compile(
    r"\\\r?\n[ \t]{0,64}[^\s;&,\"'<>]{1,1024}"  # ``DB_PASS=\`` + next line
    r"|\\\"(?:[^\"\\]|\\[^\"]){0,8192}\\\"|\"[^\"]{0,8192}\"|'[^']{0,8192}'"
    r"|\{[^}]{0,8192}\}"
    r"|[^\s;&,\"'<>][^\s;&,\"<>]{0,1023}"
)
_VALUE_TAIL = re.compile(r"[^\s;&,\"<>]+")
# ``Password=ab;cd`` where ``cd`` is no ``key=`` of its own: still the value.
_SEMI_TAIL = re.compile(r";([^\s;=&,\"'<>]+)(?=[\s,]|$)")
_SPACE_VALUE = re.compile(r"\"[^\"]{0,8192}\"|'[^']{0,8192}'|[^\s;,\"'<>|]{1,1024}")
_SPACE_VALUE_TAIL = re.compile(r"[^\s;,\"'<>|]+")


def _value_end(text_: str, vm: "re.Match[str]", tail: "re.Pattern[str]") -> int:
    """End of the value ``vm`` matched, past the match bound when an
    unquoted value is longer than :data:`_VALUE_MAX`."""
    end = vm.end()
    if end - vm.start() >= _VALUE_MAX and text_[vm.start()] not in "\"'{\\":
        more = tail.match(text_, end)
        if more is not None:
            end = more.end()
    return end


_YAML_BLOCK_INDICATOR = re.compile(r"^[|>][+-]?\d*$")
# ``password: >-`` / ``password: |`` and the indented lines under it.
_YAML_BLOCK = re.compile(
    r"(?m)^([ \t]*)(-[ \t]+)?([\"']?)([A-Za-z_][A-Za-z0-9_.\-]*)\3[ \t]*:[ \t]*"
    r"([|>][+-]?\d*)[ \t]*(?:#[^\n]*)?\n((?:\1[ \t]+\S[^\n]*(?:\n|$))+)"
)
# ``password:`` with its scalar on the next, deeper-indented line.
_YAML_NEXT_LINE = re.compile(
    r"(?m)^([ \t]*)(?:-[ \t]+)?([\"']?)([A-Za-z_][A-Za-z0-9_.\-]*)\2[ \t]*:[ \t]*"
    r"(?:#[^\n]*)?\n(\1[ \t]++)(?!-[ \t])(?!#)([^\n:#]*[^\s:#])[ \t]*$"
)
# HCL / shell heredoc: ``password = <<EOF`` ... ``EOF``.
_HEREDOC = re.compile(
    r"(?ms)^([ \t]*[\"']?)([A-Za-z_][\w.\-]*)([\"']?[ \t]*[=:][ \t]*<<-?[ \t]*)"
    r"([\"']?)([A-Za-z_]\w*)\4[ \t]*\n(.*?)(^[ \t]*\5[ \t]*$)"
)
# ``<password>x</password>``, ``<ns:ApiKey attr="1">x</ns:ApiKey>``.
_XML_ELEMENT = re.compile(
    r"<((?:[A-Za-z_][\w.\-]*:)?([A-Za-z_][\w.\-]*))(\s[^<>]*)?>([^<]*)</\1\s*>"
)
# ``<password><![CDATA[x]]></password>``.
_XML_CDATA = re.compile(
    r"<((?:[A-Za-z_][\w.\-]*:)?([A-Za-z_][\w.\-]*))(\s[^<>]*)?>(\s*<!\[CDATA\[)"
    r"(.*?)(\]\]>\s*</\1\s*>)",
    re.DOTALL,
)
# ``<Password><Value>x</Value></Password>``: the secret's name on the parent.
_XML_NESTED = re.compile(
    r"<((?:[A-Za-z_][\w.\-]*:)?([A-Za-z_][\w.\-]*))(\s[^<>]*)?>"
    r"(\s*<([A-Za-z_][\w.:\-]*)(?:\s[^<>]*)?>)([^<]*)(</\5\s*>)"
)
# .NET ``<add key="Password" value="x"/>`` and ``name="..." value="..."``.
_NAMED_VALUE_ATTR = re.compile(
    r"(?i)\b((?:key|name)\s*=\s*([\"'])([^\"']*)\2\s+value\s*=\s*)([\"'])([^\"']*)\4"
)
# Kubernetes env / header lists written out as text:
# ``- name: API_TOKEN\n  value: x``, ``"name": "X-Api-Key", "value": "x"``.
_NAMED_VALUE_TEXT = re.compile(
    r"(?i)(?<![\w-])([\"']?)(?:name|key|header)\1[ \t]*[:=][ \t]*([\"']?)"
    r"([A-Za-z_][\w.\-]{0,127})\2([ \t,;]*+(?:\r?\n[ \t]*+)?(?:-[ \t]++)?"
    r"([\"']?)(?:value|val)\5[ \t]*+[:=][ \t]*+)"
)
# ``mysql -pS3cret`` (attached), only where it reads as a password.
_DASH_P = re.compile(r"(?<![\w\-])(-p)([^\s\-;&,\"'<>|][^\s;&,\"'<>|]*)")
_MYSQL_CONTEXT = re.compile(
    r"(?i)\b(?:mysql|mysqldump|mysqladmin|mysqlimport|mariadb|mariadb-dump|mycli)\b"
)
_PORT_SHAPE = re.compile(r"^[\d.:\-\[\]]+(?:/(?:tcp|udp|sctp))?$")
_SSHPASS = re.compile(r"(?i)(\bsshpass\b[^\n|;&]{0,256}?\s-p[ \t]*)([^\s;&|]+)")
_NET_USE = re.compile(
    r"(?i)(\bnet\s+use\b[^\n]{0,256}?\\\\\S+[ \t]+)(?![/*])([^\s/]\S*)"
)
# ``echo S | docker login --password-stdin``, ``| gh auth login --with-token``,
# ``echo 'root:S' | chpasswd``.
_STDIN_SECRET = re.compile(
    r"(?i)(\b(?:echo|printf)\s+(?:-[neE]+\s+)?)([\"']?)([^\s\"'|]+)\2"
    r"(?=\s*\|[^\n|]{0,256}(?:--password-stdin|--with-token|--token-stdin"
    r"|--stdin\b|\bchpasswd\b))"
)
_HTPASSWD = re.compile(r"(?i)\bhtpasswd((?:[ \t]+[^\s;&|]+)+)")
_OTP_CODE = re.compile(
    r"(?i)\b((?:totp|otp|mfa|2fa|one[- ]time|verification|authenticator)"
    r"[ \t]+(?:code|token|pin|passcode)[ \t]*(?:[:=][ \t]*|is[ \t]+)?)(\d{6,8})\b"
)
# ``the new password is S``, ``pin was 1234``.
_PROSE_SECRET = re.compile(
    r"(?i)\b((?:password|passphrase|passwd|passcode|pin|secret|token|api[ _-]?key)"
    r"[ \t]+(?:is|was|=|set[ \t]+to|changed[ \t]+to|reset[ \t]+to)[ \t]+)"
    r"([\"']?)([^\s\"']+?)\2(?=[\s,;)]|\.(?:\s|$)|$)"
)
_AUTH_HEADER = re.compile(
    r"(?i)\b((?:proxy-)?authorization[\"']?\s*[:=]\s*[\"']?)"
    r"(?:(basic|bearer|digest|negotiate|ntlm|token|apikey|aws4-hmac-sha256)\s+)?"
    r"[^\r\n\"']+"
)
_SCHEME_CREDENTIAL = re.compile(r"(?i)\b(bearer|basic)\s+([A-Za-z0-9._~+/\-]{8,}=*)")
_PEM_PRIVATE = re.compile(
    r"-----BEGIN[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----.*?"
    r"(?:-----END[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----|\Z)",
    re.DOTALL,
)
# PuTTY ``.ppk``: the ``Private-Lines: N`` block.
_PPK_PRIVATE = re.compile(r"(?i)(Private-Lines:[ \t]*(\d{1,4})[ \t]*\r?\n)")
# ``scheme://user:password@host`` (and ``redis://:pw@``, ``mongodb+srv://``):
# the whole userinfo goes.
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]{1,30}://)[^\s/?#@\"'<>]*@")
# ``?code=`` (Azure Functions keys, OAuth codes) in a URL query.
_URL_CODE = re.compile(r"(?i)([?&](?:code|sig)=)([^&\s#\"'<>]+)")
# Webhook URLs whose path is the credential.
_WEBHOOK_URLS = re.compile(
    r"(?i)(https?://(?:hooks\.slack\.com/(?:services|workflows|triggers)/|"
    r"(?:[a-z0-9-]+\.)?discord(?:app)?\.com/api/webhooks/|"
    r"[a-z0-9.-]*webhook\.office\.com/|"
    r"[a-z0-9.-]*\.logic\.azure\.com[^\s\"'<>?]*\?))"
    r"[^\s\"'<>]+"
)
# Windows ``app.exe /p:"S"`` (an msbuild ``/p:Name=Value`` property is not).
_WIN_PASS_SWITCH = re.compile(
    r"(?i)((?<=\s)/(?:p|pw|pwd|pass|password):)(\"[^\"]*\"|'[^']*'|[^\s\"']+)"
)
# SQL and PowerShell statements that set a password.
_SQL_IDENTIFIED_BY = re.compile(
    r"(?i)(\bIDENTIFIED\s+(?:WITH\s+\S+\s+)?BY\s+(?:PASSWORD\s+|VALUES\s+)?)"
    r"(\"[^\"]*\"|'[^']*'|[^\s;'\"]+)"
)
_SQL_PASSWORD_FN = re.compile(r"(?i)(\b(?:OLD_)?PASSWORD\s*\(\s*)(\"[^\"]*\"|'[^']*')")
_SECURE_STRING = re.compile(
    r"(?i)(\bConvertTo-SecureString\s+(?:-String\s+)?)(\"[^\"]*\"|'[^']*'|[^\s\"'-]\S*)"
)
# ``.pgpass``: ``host:port:db:user:password``.
_PGPASS = re.compile(
    r"(?m)^([A-Za-z0-9.\-*\[\]_]+:(?:\d{1,5}|\*):[^:\s]+:[^:\s]+:)(\S+)[ \t]*$"
)
# Credentials recognisable by their shape alone.
_TOKEN_SHAPES = [
    re.compile(p)
    for p in (
        r"\bsk-(?:ant-|proj-|svcacct-|admin-|live-|test-)?[A-Za-z0-9_\-]{16,}",
        r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}",
        r"\bwhsec_[A-Za-z0-9+/=]{10,}",
        r"\bgh[pousr]_[A-Za-z0-9]{20,}",
        r"\bgithub_pat_[A-Za-z0-9_]{20,}",
        r"\bglpat-[A-Za-z0-9_\-]{20,}",
        r"\bgl(?:rt|ptt|dt|cbt|imt|ft|soat|agent)-[A-Za-z0-9_\-]{20,}",
        r"\bxox[abposer]-[A-Za-z0-9\-]{10,}",
        r"\bxapp-[A-Za-z0-9\-]{10,}",
        r"\bAIza[0-9A-Za-z_\-]{35}",
        r"\bya29\.[0-9A-Za-z_\-]{20,}",
        r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b",
        r"\bhf_[A-Za-z0-9]{30,}",
        r"\bnpm_[A-Za-z0-9]{36}\b",
        r"\bpypi-[A-Za-z0-9_\-]{50,}",
        r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{16,}",
        # Twilio API key SID, Terraform Cloud / Enterprise API token.
        r"\bSK[0-9a-fA-F]{32}\b",
        r"\batlasv1\.[A-Za-z0-9_\-=]{40,}",
        r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}",
        r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*",
        # HashiCorp Vault service/batch/recovery tokens.
        r"\bhv[sbr]\.[A-Za-z0-9_\-]{20,}",
        # Grafana service-account and Grafana Cloud tokens.
        r"\bglsa_[A-Za-z0-9_]{20,}",
        r"\bglc_[A-Za-z0-9+/=_\-]{20,}",
        # Databricks, DigitalOcean, Shopify, Linear, Doppler, Pulumi, Postman.
        r"\bdapi[0-9a-f]{32}(?:-\d)?",
        r"\bdo[opr]_v1_[a-f0-9]{64}",
        r"\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}",
        r"\blin_(?:api|oauth)_[A-Za-z0-9]{32,}",
        r"\bdp\.(?:st|ct|pt|sa)\.[A-Za-z0-9_\-]{20,}",
        r"\bpul-[a-f0-9]{40}",
        r"\bPMAK-[A-Za-z0-9\-]{30,}",
        # Telegram bot, Mailgun, Atlassian, Tailscale, age, Square, Meta,
        # Azure AD client secrets, OpenAI sessions.
        r"(?:(?<=bot)|(?<![A-Za-z0-9]))\d{6,12}:AA[A-Za-z0-9_\-]{30,}",
        r"\bkey-[0-9a-z]{32}\b",
        r"\bATATT3[A-Za-z0-9_\-=]{20,}",
        r"\btskey-[a-z]+-[A-Za-z0-9\-]{10,}",
        r"\bAGE-SECRET-KEY-1[0-9A-Z]{40,}",
        r"\bsq0(?:atp|csp|idp)-[A-Za-z0-9_\-]{20,}",
        r"\bEAA[A-Za-z0-9]{30,}",
        r"(?<![A-Za-z0-9_\-.~])[A-Za-z0-9_\-.]{3}\dQ~[A-Za-z0-9_.~\-]{20,}",
        r"\bsess-[A-Za-z0-9]{32,}",
    )
]
# The sanitizer's patterns match a secret's start (``sk-ant-``, ``AKIA...``, a
# DSN up to ``@``); a redaction must swallow the rest of that token as well.
# Its bare-hex rule is left out: hash IOCs (MD5, SHA-1, SHA-256) and trace ids
# are evidence, not credentials (``_LONG_HEX`` below).
_SECRET_TOKENS = [
    re.compile(p.pattern + r"[^\s\"',;]*", p.flags)
    for p in _SECRET_VALUE_PATTERNS
    if "a-fA-F0-9]{32" not in p.pattern
]
_LONG_HEX = re.compile(r"(?<![A-Za-z0-9])[a-fA-F0-9]{32,}(?![A-Za-z0-9])")
# MD5 / trace id, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512.
_HASH_HEX_LENGTHS = frozenset({32, 40, 56, 64, 96, 128})
# An AWS secret access key: 40 characters of base64 with no prefix to go by.
_AWS_SECRET = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])")
# Base64 runs worth decoding to look inside (``.dockerconfigjson``,
# kubeconfig ``client-key-data``, ``base64("password=...")``).
_B64_RUN = re.compile(
    r"(?<![A-Za-z0-9+/_\-])[A-Za-z0-9+/_\-]{24,}={0,2}(?![A-Za-z0-9+/=_\-])"
)
# Our own hash-chain values: hex by design, not a leaked credential.
_VERBATIM_HEX = frozenset({"prev_hash", "event_hash", "hash"})
_HEX = re.compile(r"^[0-9a-fA-F]{32,128}$")
_MAX_NEST = 4  # JSON-in-a-string / base64 / escape decoding depth


def _redacted_value(value: str) -> str:
    """``"x"`` -> ``"[REDACTED]"``: keep the quoting, lose the value."""
    if value.startswith('\\"') and value.endswith('\\"') and len(value) >= 4:
        return f'\\"{REDACTED}\\"'
    if value[:1] in "\"'" and value[-1:] == value[:1] and len(value) >= 2:
        return f"{value[0]}{REDACTED}{value[0]}"
    return REDACTED


def _is_flag_key(text_: str, start: int, ident: str) -> bool:
    """``--key=x`` / ``/pass:x`` / ``?sig=x``: a command-line switch or a URL
    query parameter, whose value is what its name says."""
    return ident.startswith("-") or (start > 0 and text_[start - 1] in "/?&")


def _redact_pairs(text_: str) -> str:
    """``key=value`` / ``"key": "value"`` / ``key%3Dvalue`` / ``key => value``
    whose key names a credential. Scanned key by key so that a non-secret pair
    never swallows a secret one after it (``foo=password=x``)."""
    out: list[str] = []
    pos = 0
    for m in _KEY_SEP.finditer(text_):
        if m.start() < pos:
            continue
        ident = m.group(2)
        strength = identifier_strength(ident)
        if not strength:
            continue
        vm = _VALUE.match(text_, m.end())
        if vm is None:
            continue
        value = vm.group(0)
        if value == REDACTED or _YAML_BLOCK_INDICATOR.match(value):
            continue
        if value.startswith("[REDACTED") or value.startswith("<<"):
            continue
        if text_.startswith(" " + REDACTED, vm.end()):
            continue  # ``Authorization: Basic [REDACTED]``: the scheme stays
        if (
            strength == WEAK
            and not _is_flag_key(text_, m.start(2), ident)
            and not _secretish(value, _numeric_identifier(ident), ident)
        ):
            continue
        end = _value_end(text_, vm, _VALUE_TAIL)
        if strength == STRONG:
            while True:
                tail = _SEMI_TAIL.match(text_, end)
                if tail is None:
                    break
                end = tail.end()
        out.append(text_[pos : vm.start()])
        out.append(_redacted_value(value) if end == vm.end() else REDACTED)
        pos = end
    out.append(text_[pos:])
    return "".join(out)


def _random_enough(value: str) -> bool:
    """A space-separated value is taken for a secret only when it does not
    read as a word: a digit next to a letter, or mixed case."""
    body = value.strip("\"'")
    if len(body) < 6:
        return False
    has_digit = any(c.isdigit() for c in body)
    has_alpha = any(c.isalpha() for c in body)
    mixed = any(c.isupper() for c in body[1:]) and any(c.islower() for c in body)
    return (has_digit and has_alpha) or mixed or any(c in "!@#$%^*+/=~" for c in body)


def _redact_spaced(text_: str) -> str:
    """``--password value``, ``PASSWORD<tab>value``, ``token value``."""
    out: list[str] = []
    pos = 0
    for m in _KEY_SPACE.finditer(text_):
        ident = m.group(1)
        if m.start() < pos:
            continue
        strength = identifier_strength(ident)
        if not strength:
            continue
        vm = _SPACE_VALUE.match(text_, m.end())
        if vm is None:
            continue
        value = vm.group(0)
        if value.startswith("[REDACTED"):
            continue
        is_flag = ident.startswith("-")
        if value.startswith("-"):
            # ``--password -S3cr3t``: a dash-led secret, not the next flag.
            if not (
                is_flag
                and strength == STRONG
                and not value.startswith("--")
                and _secretish(value[1:])
            ):
                continue
        if is_flag:
            if _INDIRECT_FLAG.search(ident):
                continue
        elif strength == WEAK:
            if not _secretish(value, _numeric_identifier(ident), ident):
                continue
        elif not _random_enough(value):
            continue
        out.append(text_[pos : vm.start()])
        end = _value_end(text_, vm, _SPACE_VALUE_TAIL)
        out.append(_redacted_value(value) if end == vm.end() else REDACTED)
        pos = end
    out.append(text_[pos:])
    return "".join(out)


def _pair_hit(name: str, value: str) -> bool:
    strength = identifier_strength(name)
    if strength == STRONG:
        return True
    return strength == WEAK and _secretish(value, _numeric_identifier(name), name)


def _yaml_block_redaction(match: "re.Match[str]") -> str:
    if not secret_identifier(match.group(4)):
        return match.group(0)
    indent = match.group(1)
    head = match.group(0)[: match.start(6) - match.start(0)]
    trailing = "\n" if match.group(6).endswith("\n") else ""
    return f"{head}{indent}  {REDACTED}{trailing}"


def _yaml_next_line_redaction(match: "re.Match[str]") -> str:
    value = match.group(5)
    if value.startswith("[REDACTED") or not _pair_hit(match.group(3), value):
        return match.group(0)
    head = match.group(0)[: match.start(5) - match.start(0)]
    return head + _redacted_value(value.strip())


def _heredoc_redaction(match: "re.Match[str]") -> str:
    body = match.group(6)
    if not body.strip() or not _pair_hit(match.group(2), body.strip()):
        return match.group(0)
    head = match.group(0)[: match.start(6) - match.start(0)]
    return f"{head}{REDACTED}\n{match.group(7)}"


def _xml_redaction(match: "re.Match[str]") -> str:
    content = match.group(4)
    if not content.strip() or not _pair_hit(match.group(2), content.strip()):
        return match.group(0)
    attrs = match.group(3) or ""
    return f"<{match.group(1)}{attrs}>{REDACTED}</{match.group(1)}>"


def _xml_cdata_redaction(match: "re.Match[str]") -> str:
    if not match.group(5).strip() or not _pair_hit(match.group(2), match.group(5)):
        return match.group(0)
    head = match.group(0)[: match.start(5) - match.start(0)]
    return head + REDACTED + match.group(6)


def _xml_nested_redaction(match: "re.Match[str]") -> str:
    inner = match.group(6)
    if not inner.strip() or inner.startswith("[REDACTED"):
        return match.group(0)
    if not _pair_hit(match.group(2), inner.strip()):
        return match.group(0)
    head = match.group(0)[: match.start(6) - match.start(0)]
    return head + REDACTED + match.group(7)


def _named_attr_redaction(match: "re.Match[str]") -> str:
    if not _pair_hit(match.group(3), match.group(5)):
        return match.group(0)
    q = match.group(4)
    return f"{match.group(1)}{q}{REDACTED}{q}"


def _redact_named_values(text_: str) -> str:
    """``- name: API_TOKEN`` / ``value: x`` written out as text."""
    out: list[str] = []
    pos = 0
    for m in _NAMED_VALUE_TEXT.finditer(text_):
        if m.start() < pos:
            continue
        vm = _VALUE.match(text_, m.end())
        if vm is None or vm.group(0).startswith("[REDACTED"):
            continue
        if not _pair_hit(m.group(3), vm.group(0)):
            continue
        out.append(text_[pos : vm.start()])
        end = _value_end(text_, vm, _VALUE_TAIL)
        out.append(_redacted_value(vm.group(0)) if end == vm.end() else REDACTED)
        pos = end
    out.append(text_[pos:])
    return "".join(out)


def _dash_p_redaction(match: "re.Match[str]") -> str:
    value = match.group(2)
    if value.startswith("[REDACTED") or _PORT_SHAPE.match(value):
        return match.group(0)
    line_start = match.string.rfind("\n", 0, match.start()) + 1
    context = match.string[line_start : match.start()]
    has_digit = any(c.isdigit() for c in value)
    has_alpha = any(c.isalpha() for c in value)
    mixed = any(c.isupper() for c in value) and any(c.islower() for c in value)
    if _MYSQL_CONTEXT.search(context) or (has_digit and has_alpha) or mixed:
        return match.group(1) + REDACTED
    return match.group(0)


def _htpasswd_redaction(match: "re.Match[str]") -> str:
    """``htpasswd -b file user PASS`` / ``htpasswd -nb user PASS``."""
    args = match.group(1)
    tokens = re.findall(r"[ \t]+|[^\s]+", args)
    words = [i for i, t in enumerate(tokens) if not t.isspace()]
    flags = "".join(
        tokens[i][1:] for i in words if tokens[i].startswith("-") and len(tokens[i]) > 1
    )
    if "b" not in flags:
        return match.group(0)
    positional = [i for i in words if not tokens[i].startswith("-")]
    index = 1 if "n" in flags else 2
    if len(positional) > index:
        tokens[positional[index]] = REDACTED
    return "htpasswd" + "".join(tokens)


def _auth_header_redaction(match: "re.Match[str]") -> str:
    scheme = match.group(2)
    return match.group(1) + (f"{scheme} " if scheme else "") + REDACTED


def _looks_random(value: str) -> bool:
    """Credential-like: mixes cases, or has a digit or a base64 symbol."""
    body = value.rstrip("=")
    return (
        any(c.isdigit() or c in "+/._~-" for c in body)
        or value.endswith("=")
        or (any(c.isupper() for c in body[1:]) and any(c.islower() for c in body))
    )


def _scheme_redaction(match: "re.Match[str]") -> str:
    if not _looks_random(match.group(2)):
        return match.group(0)  # "basic authentication", "bearer tokens"
    return f"{match.group(1)} {REDACTED}"


def _b64_decode_text(run: str) -> Optional[str]:
    """``run`` as base64(url) of printable UTF-8 text, or None."""
    body = run.rstrip("=")
    if len(body) % 4 == 1:
        return None
    padded = body + "=" * (-len(body) % 4)
    try:
        raw = base64.b64decode(
            padded.replace("-", "+").replace("_", "/"), validate=True
        )
        decoded = raw.decode("utf-8")
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    if not decoded or any(not (c.isprintable() or c in "\r\n\t") for c in decoded):
        return None
    return decoded


def _aws_secret_redaction(match: "re.Match[str]") -> str:
    value = match.group(0)
    if value.startswith("/") and value.count("/") >= 3:
        return value  # a path: ``/Users/JohnDoe/Library/Caches/Chrome1234``
    if _b64_decode_text(value) is not None:
        return value  # base64 of readable text (a file name), not a key
    if (
        any(c.isupper() for c in value)
        and any(c.islower() for c in value)
        and any(c.isdigit() or c in "/+" for c in value)
    ):
        return REDACTED
    return value


def _long_hex_redaction(match: "re.Match[str]") -> str:
    value = match.group(0)
    return value if len(value) in _HASH_HEX_LENGTHS else REDACTED


def _ppk_redaction(text_: str) -> str:
    out: list[str] = []
    pos = 0
    for m in _PPK_PRIVATE.finditer(text_):
        if m.start() < pos:
            continue
        end = m.end()
        for _ in range(int(m.group(2))):
            nl = text_.find("\n", end)
            end = len(text_) if nl < 0 else nl + 1
        body = text_[m.end() : end]
        if not body.strip():
            continue
        out.append(text_[pos : m.end()])
        out.append(REDACTED + ("\n" if body.endswith("\n") else ""))
        pos = end
    out.append(text_[pos:])
    return "".join(out)


# -- command lines -----------------------------------------------------------


@dataclass(frozen=True)
class _CliSpec:
    """Which arguments of a tool carry a credential.

    ``flags`` maps a flag to how its value is cut: ``all`` (the whole
    value), ``colon`` (``user:PASS``) or ``percent`` (``user%PASS``).
    ``requires`` lists subcommands one of which must be present
    (``docker login``, not ``docker run -p 80:80``). ``positional`` names a
    subcommand after which the n-th non-flag argument is the secret
    (``vault login S``, ``rabbitmqctl add_user u S``, ``net user u S``)."""

    flags: dict = field(default_factory=dict)
    requires: frozenset = frozenset()
    positional: tuple = ()  # ((subcommand, n), ...)
    ci: bool = False  # flags are case-insensitive (Windows tools)


_LOGIN = frozenset({"login"})
_CLI_TOOLS: dict[str, _CliSpec] = {}
for _names, _spec in (
    (
        ("curl",),
        _CliSpec(
            flags={
                "-u": "colon",
                "--user": "colon",
                "-U": "colon",
                "--proxy-user": "colon",
            }
        ),
    ),
    (
        ("redis-cli", "valkey-cli", "keydb-cli"),
        _CliSpec(flags={"-a": "all", "--pass": "all"}),
    ),
    (("sqlcmd", "bcp", "osql", "isql"), _CliSpec(flags={"-P": "all"})),
    (
        (
            "ldapsearch",
            "ldapmodify",
            "ldapadd",
            "ldapdelete",
            "ldapwhoami",
            "ldappasswd",
            "ldapcompare",
            "ldapmodrdn",
        ),
        _CliSpec(flags={"-w": "all"}),
    ),
    (
        ("docker", "podman", "buildah", "skopeo", "nerdctl", "oras", "crane", "helm"),
        _CliSpec(flags={"-p": "all", "--password": "all"}, requires=_LOGIN),
    ),
    (
        (
            "mongo",
            "mongosh",
            "mongodump",
            "mongorestore",
            "mongoexport",
            "mongoimport",
            "mongostat",
            "mongotop",
            "mongofiles",
        ),
        _CliSpec(flags={"-p": "all", "--password": "all"}),
    ),
    (("psexec", "psexec64", "paexec"), _CliSpec(flags={"-p": "all"}, ci=True)),
    (("az",), _CliSpec(flags={"-p": "all", "--password": "all"}, requires=_LOGIN)),
    (("zip", "zipcloak"), _CliSpec(flags={"-P": "all", "--password": "all"})),
    (("openssl",), _CliSpec(flags={"-k": "all", "-K": "all"})),
    (("twilio",), _CliSpec(flags={"-t": "all", "--auth-token": "all"})),
    (
        ("smbclient", "rpcclient", "smbcacls", "smbget", "smbtree"),
        _CliSpec(flags={"-U": "percent", "--user": "percent"}),
    ),
    (("smbmap", "crackmapexec", "nxc", "netexec"), _CliSpec(flags={"-p": "all"})),
    (("ssh-keygen",), _CliSpec(flags={"-N": "all", "-P": "all"})),
    (("schtasks",), _CliSpec(flags={"/rp": "all", "/p": "all"}, ci=True)),
    (("sshpass",), _CliSpec(flags={"-p": "all"})),
    (("vault", "bao"), _CliSpec(positional=(("login", 1),))),
    (
        ("rabbitmqctl",),
        _CliSpec(positional=(("add_user", 2), ("change_password", 2))),
    ),
    (("net", "net1"), _CliSpec(positional=(("user", 2),), ci=True)),
    (("mysqladmin",), _CliSpec(positional=(("password", 1),))),
    (
        (
            "snmpwalk",
            "snmpbulkwalk",
            "snmpget",
            "snmpgetnext",
            "snmpbulkget",
            "snmpset",
            "snmptable",
            "snmptrap",
            "snmpinform",
            "snmpdelta",
            "snmpstatus",
            "onesixtyone",
        ),
        # v1/v2c community, v3 auth and privacy pass phrases.
        _CliSpec(flags={"-c": "all", "-A": "all", "-X": "all"}),
    ),
):
    for _name in _names:
        _CLI_TOOLS[_name] = _spec


def _tool_name(arg: str) -> str:
    name = re.split(r"[\\/]", arg.strip("\"'"))[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def cli_secret_args(args: list) -> dict[int, str]:
    """Indices of ``args`` (an argv) that hold a credential, with how to cut
    each (``all`` / ``colon`` / ``percent``)."""
    strs = [a.strip("\"'") if isinstance(a, str) else "" for a in args]
    tool_at = next(
        (i for i, a in enumerate(strs[:8]) if _tool_name(a) in _CLI_TOOLS), None
    )
    if tool_at is None:
        return {}
    spec = _CLI_TOOLS[_tool_name(strs[tool_at])]
    rest = strs[tool_at + 1 :]
    if spec.requires and not any(a.lower() in spec.requires for a in rest):
        return {}
    hits: dict[int, str] = {}
    flags = {k.lower(): v for k, v in spec.flags.items()} if spec.ci else spec.flags
    for j in range(tool_at + 1, len(strs) - 1):
        flag = strs[j].lower() if spec.ci else strs[j]
        if flag in flags and strs[j + 1] and not strs[j + 1].startswith("[REDACTED"):
            hits[j + 1] = flags[flag]
    for sub, n in spec.positional:
        for j in range(tool_at + 1, len(strs)):
            if strs[j].lower() != sub:
                continue
            seen = 0
            for k in range(j + 1, len(strs)):
                a = strs[k]
                if a.startswith("-") or a.startswith("/") or "=" in a:
                    continue
                seen += 1
                if seen == n:
                    if a and a != "*" and not a.startswith("[REDACTED"):
                        hits[k] = "all"
                    break
            break
    return hits


def _cut_cli_value(value: str, mode: str) -> str:
    q = (
        value[0]
        if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]
        else ""
    )
    body = value[1:-1] if q else value
    sep = {"colon": ":", "percent": "%"}.get(mode)
    if sep is None:
        return f"{q}{REDACTED}{q}"
    user, found, secret = body.partition(sep)
    if not found or not secret or secret.startswith("[REDACTED"):
        return value
    if mode == "colon" and secret.isdigit():
        return value  # ``-u 1000:1000``: a uid:gid, not a password
    return f"{q}{user}{sep}{REDACTED}{q}"


_CLI_SEGMENT = re.compile(r"[^\n|;&]+")
_CLI_ARG = re.compile(r"\"(?:[^\"\\]|\\.)*\"|'[^']*'|\S+")


def _redact_cli(text_: str) -> str:
    """Tool-aware argv redaction over each command in free text."""
    if not any(
        name in text_.lower()
        for name in (
            "curl",
            "cli",
            "sql",
            "ldap",
            "login",
            "mongo",
            "exec",
            "zip",
            "openssl",
            "twilio",
            "smb",
            "ssh",
            "schtasks",
            "vault",
            "bao",
            "rabbitmq",
            "net",
            "mysqladmin",
            "crackmap",
            "nxc",
            "rpc",
            "snmp",
            "onesixtyone",
        )
    ):
        return text_
    edits: list[tuple[int, int, str]] = []
    for seg in _CLI_SEGMENT.finditer(text_):
        tokens = list(_CLI_ARG.finditer(seg.group(0)))
        hits = cli_secret_args([t.group(0) for t in tokens])
        for idx, mode in hits.items():
            t = tokens[idx]
            new = _cut_cli_value(t.group(0), mode)
            if new != t.group(0):
                edits.append((seg.start() + t.start(), seg.start() + t.end(), new))
    if not edits:
        return text_
    out: list[str] = []
    pos = 0
    for start, end, new in sorted(edits):
        out.append(text_[pos:start])
        out.append(new)
        pos = end
    out.append(text_[pos:])
    return "".join(out)


# -- decoders ----------------------------------------------------------------

_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")
_ESCAPES = re.compile(
    r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|&#(\d{1,7});|&#[xX]([0-9a-fA-F]{1,6});"
    r"|&(quot|apos|amp|lt|gt|equals|colon);"
)
_NAMED_ENTITIES = {
    "quot": '"',
    "apos": "'",
    "amp": "&",
    "lt": "<",
    "gt": ">",
    "equals": "=",
    "colon": ":",
}


def _unescape(match: "re.Match[str]") -> str:
    uni, hx, dec, hexent, named = match.groups()
    try:
        if uni or hx or hexent:
            return chr(int(uni or hx or hexent, 16))
        if dec:
            return chr(int(dec))
    except (ValueError, OverflowError):
        return match.group(0)
    return _NAMED_ENTITIES[named]


def _redact_base64(text_: str, depth: int) -> str:
    """Cut a base64 blob whole when what it decodes to holds a credential: a
    PEM key (kubeconfig ``client-key-data``), a ``.dockerconfigjson``, or
    ``base64("password=...")``."""
    if depth >= _MAX_NEST:
        return text_

    def one(match: "re.Match[str]") -> str:
        run = match.group(0)
        decoded = _b64_decode_text(run)
        if decoded is None or len(decoded) < 6:
            return run
        if (
            "PRIVATE KEY" in decoded
            or redact_text(decoded, _depth=depth + 1) != decoded
        ):
            return REDACTED
        return run

    return _B64_RUN.sub(one, text_)


def _redact_raw(value: str, depth: int = 0) -> str:
    out = _PEM_PRIVATE.sub(REDACTED, value)
    out = _ppk_redaction(out)
    out = _AUTH_HEADER.sub(_auth_header_redaction, out)
    out = _WEBHOOK_URLS.sub(lambda m: m.group(1) + REDACTED, out)
    out = _URL_USERINFO.sub(lambda m: m.group(1) + REDACTED + "@", out)
    out = _URL_CODE.sub(
        lambda m: (
            m.group(1) + REDACTED if _secretish(m.group(2), key=None) else m.group(0)
        ),
        out,
    )
    for pattern in _TOKEN_SHAPES:
        out = pattern.sub(REDACTED, out)
    out = _SCHEME_CREDENTIAL.sub(_scheme_redaction, out)
    out = _HEREDOC.sub(_heredoc_redaction, out)
    out = _YAML_BLOCK.sub(_yaml_block_redaction, out)
    out = _YAML_NEXT_LINE.sub(_yaml_next_line_redaction, out)
    out = _XML_CDATA.sub(_xml_cdata_redaction, out)
    out = _XML_NESTED.sub(_xml_nested_redaction, out)
    out = _XML_ELEMENT.sub(_xml_redaction, out)
    out = _NAMED_VALUE_ATTR.sub(_named_attr_redaction, out)
    out = _redact_named_values(out)
    out = _SQL_IDENTIFIED_BY.sub(
        lambda m: m.group(1) + _redacted_value(m.group(2)), out
    )
    out = _SQL_PASSWORD_FN.sub(lambda m: m.group(1) + _redacted_value(m.group(2)), out)
    out = _SECURE_STRING.sub(lambda m: m.group(1) + _redacted_value(m.group(2)), out)
    out = _WIN_PASS_SWITCH.sub(
        lambda m: (
            m.group(0)
            if "=" in m.group(2) or m.group(2).startswith("[REDACTED")
            else m.group(1) + _redacted_value(m.group(2))
        ),
        out,
    )
    out = _redact_pairs(out)
    out = _redact_cli(out)
    out = _SSHPASS.sub(lambda m: m.group(1) + REDACTED, out)
    out = _NET_USE.sub(lambda m: m.group(1) + REDACTED, out)
    out = _STDIN_SECRET.sub(
        lambda m: m.group(1) + m.group(2) + REDACTED + m.group(2), out
    )
    out = _HTPASSWD.sub(_htpasswd_redaction, out)
    out = _OTP_CODE.sub(lambda m: m.group(1) + REDACTED, out)
    out = _PROSE_SECRET.sub(
        lambda m: (
            m.group(1) + m.group(2) + REDACTED + m.group(2)
            if _secretish(m.group(3), numeric_ok=True)
            else m.group(0)
        ),
        out,
    )
    out = _DASH_P.sub(_dash_p_redaction, out)
    out = _redact_spaced(out)
    out = _PGPASS.sub(_pgpass_redaction, out)
    for pattern in _SECRET_TOKENS:
        out = pattern.sub(REDACTED, out)
    out = _LONG_HEX.sub(_long_hex_redaction, out)
    out = _redact_base64(out, depth)
    return _AWS_SECRET.sub(_aws_secret_redaction, out)


def _pgpass_redaction(match: "re.Match[str]") -> str:
    secret = match.group(2)
    if secret.startswith("[REDACTED"):
        return match.group(0)
    line = match.group(0).strip()
    with contextlib.suppress(ValueError):
        ipaddress.ip_address(line)
        return match.group(0)  # an IPv6 address, not a .pgpass line
    if re.fullmatch(r"[0-9a-fA-F]{1,4}", secret):
        return match.group(0)
    return match.group(1) + REDACTED


def _redact_json_text(value: str, depth: int) -> Optional[str]:
    """A string that is itself JSON (an object, an array, or an encoded
    string): redact it as a structure, so a secret nested in JSON nested in a
    string is still found. None when it is not JSON or nothing changed."""
    s = value.strip()
    if len(s) < 2 or len(s) > 1_000_000:
        return None
    if not (
        (s[0] == "{" and s[-1] == "}")
        or (s[0] == "[" and s[-1] == "]")
        or (s[0] == '"' and s[-1] == '"')
    ):
        return None
    try:
        parsed = json.loads(s)
    except (ValueError, RecursionError):
        return None
    if isinstance(parsed, str):
        inner = redact_text(parsed, _depth=depth + 1)
        return None if inner == parsed else json.dumps(inner)
    if not isinstance(parsed, (dict, list)):
        return None
    walker = Redactor(redact_pii=False, max_string=10**9, _depth=depth + 1)
    out = walker.value("", parsed)
    if walker.count == 0 or out == parsed:
        return None
    return json.dumps(out)


def redact_text(value: str, *, _depth: int = 0) -> str:
    """Cut every credential this module recognises out of free text.

    A string that is JSON is walked as a structure (recursively: JSON in a
    string in JSON). Text carrying percent-escapes, ``\\uXXXX`` / ``\\xXX``
    escapes or HTML entities is also redacted after decoding (``password%3Dx``,
    ``password\\u003dx``, ``password&#61;x``); when the decoded form hides a
    secret the raw form did not show, the decoded, redacted text is what is
    exported. Base64 blobs that decode to a credential are cut whole.

    Input longer than :data:`MAX_FIELD_CHARS` is cut to it first (and marked
    ``...[truncated]``): the scan is bounded per field."""
    if len(value) > MAX_FIELD_CHARS:
        return redact_text(value[:MAX_FIELD_CHARS], _depth=_depth) + _TRUNCATED
    if _depth < _MAX_NEST:
        structured = _redact_json_text(value, _depth)
        if structured is not None:
            return structured
    out = _redact_raw(value, _depth)
    if _depth >= _MAX_NEST:
        return out
    decoded = value
    if _PERCENT.search(decoded):
        for _ in range(3):  # double- and triple-encoded (``%25253D``) as well
            if not _PERCENT.search(decoded):
                break
            decoded = unquote(decoded)
    for _ in range(2):
        if not _ESCAPES.search(decoded):
            break
        decoded = _ESCAPES.sub(_unescape, decoded)
    if decoded != value:
        decoded_out = redact_text(decoded, _depth=_depth + 1)
        if decoded_out.count(REDACTED) > out.count(REDACTED):
            return decoded_out
    return out


# ``{"name": "DB_PASSWORD", "value": "x"}`` (Kubernetes env, HTTP header
# lists, ``{"key": "password", "value": "x"}`` settings rows): the secret's
# name sits in one field and the secret in a sibling.
_NAME_FIELDS = frozenset(
    {
        "name",
        "key",
        "k",
        "param",
        "parameter",
        "header",
        "field",
        "variable",
        "var",
        "id",
    }
)
_VALUE_FIELDS = frozenset(
    {
        "value",
        "val",
        "v",
        "values",
        "data",
        "content",
        "stringvalue",
        "string_value",
        "secret",
    }
)
# A JSON Web Key's private members.
_JWK_PRIVATE = frozenset({"d", "p", "q", "dp", "dq", "qi", "k", "oth"})


def _paired_value_keys(mapping: dict) -> dict:
    """Keys of ``mapping`` whose value is a secret named by a sibling field,
    mapped to ``(strength, numeric, name)`` of the naming field. A name that is
    prose (``"Rotate API key"``, ``"OS Credential Dumping"``) counts as WEAK:
    its value goes only when it reads as a secret."""
    best = 0
    numeric = False
    name = ""
    for k, v in mapping.items():
        if str(k).lower() not in _NAME_FIELDS or not isinstance(v, str):
            continue
        strength = identifier_strength(v)
        if strength and any(c.isspace() for c in v.strip()):
            strength = WEAK
        if strength:
            if strength > best:
                name = v
            best = max(best, strength)
            numeric = numeric or _numeric_identifier(v)
    if not best:
        return {}
    return {
        k: (best, numeric, name) for k in mapping if str(k).lower() in _VALUE_FIELDS
    }


_FLAG = re.compile(r"^-{1,2}[A-Za-z][A-Za-z0-9_.\-]*$")


def _is_argv(value: Any) -> bool:
    """An argv of a tool we know (``{"sshpass": ["sshpass", "-p", "x"]}``):
    cut argument by argument, not whole, even under a credential-named key."""
    return (
        isinstance(value, list)
        and bool(value)
        and isinstance(value[0], str)
        and _tool_name(value[0]) in _CLI_TOOLS
    )


def _secret_argument(args: Any, index: int) -> bool:
    """``["--password", "x"]``: the argument after a flag naming a
    credential. (Tool-specific flags, ``-a`` for ``redis-cli`` and the like,
    are :func:`cli_secret_args`.)"""
    if index == 0:
        return False
    prev = args[index - 1]
    if not isinstance(prev, str) or not _FLAG.match(prev):
        return False
    if args[index].startswith("-") or _INDIRECT_FLAG.search(prev):
        return False
    return secret_identifier(prev)


class Redactor:
    """Scrub secrets (and, by default, PII) from what an event carries.

    Key names: ``core.telemetry_sanitizer``'s sensitive segments and content
    keys, plus :func:`identifier_strength` (``credentials``, ``access_key``,
    ``webhook_url``, ``clientKey``, ``license_key``, ``pwd``, ... in snake,
    kebab, dotted or camel case) redact a value outright; WEAK names
    (``token``, ``key``, ``auth``, ``pin``, ``signature``, ``session_id``)
    redact it only when it reads as a secret, so a status (``auth: failed``),
    a count (``token_count: 512``) or a rule name (``signature: ET MALWARE``)
    survives. Booleans are never secrets. Free text goes through
    :func:`redact_text`. Only ``message``, ``details``, ``user_agent`` and
    ``actor`` are scrubbed; ids, hashes and enums are ours and are left
    alone. ``actor`` and actor-named detail keys (``user``, ``approved_by``,
    ...) lose secrets but never PII: who acted is what an audit trail is for.
    """

    def __init__(
        self,
        *,
        redact_pii: bool = True,
        max_string: int = 2048,
        max_depth: int = 6,
        max_items: int = 100,
        _depth: int = 0,
    ) -> None:
        self._scrubber = SensitiveAttributeScrubber()
        self.redact_pii = redact_pii
        self.max_string = max_string
        self.max_depth = max_depth
        self.max_items = max_items
        self._nest = _depth
        self.count = 0  # values redacted, for metrics

    def _key_strength(self, path: str) -> int:
        """Key first: a key naming a credential or personal data masks its
        value whatever the value looks like (patterns come second, in
        :meth:`text`)."""
        leaf = path.rsplit(".", 1)[-1]
        segments = key_segments(leaf)
        if self.redact_pii and pii_key(leaf):
            return STRONG
        if _non_secret_leaf(segments):
            return 0
        strength = identifier_strength(leaf)
        if strength:
            return strength
        if self._scrubber._should_redact(leaf.lower(), None):
            return WEAK if {"session", "cookie"} & set(segments) else STRONG
        lowered = path.lower()
        if any(c in lowered for c in _CONTENT_KEY_SUBSTRINGS):
            return STRONG
        return 0

    def text(self, value: str, *, pii: bool = True) -> str:
        # Cut before scanning: every pattern then runs on bounded input. The
        # margin past ``max_string`` keeps a secret that straddles the export
        # cut whole for the patterns (and the part of it that is exported is
        # inside the scanned text).
        limit = min(MAX_FIELD_CHARS, self.max_string + _SCAN_MARGIN)
        if value[:1] in ("{", "[") and len(value) <= MAX_FIELD_CHARS:
            limit = MAX_FIELD_CHARS  # JSON in a string: walk it whole
        clipped = len(value) > limit
        scanned = value[:limit] if clipped else value
        out = redact_text(scanned, _depth=self._nest)
        if self.redact_pii and pii:
            out = mask_personal_data(out)
        if out != scanned:
            self.count += 1
        if len(out) > self.max_string:
            out = out[: self.max_string] + _TRUNCATED
        elif clipped:
            out += _TRUNCATED
        return out

    def _redact(self) -> str:
        self.count += 1
        return REDACTED

    def value(
        self,
        path: str,
        value: Any,
        depth: int = 0,
        weak: Optional[bool] = None,
        weak_key: str = "",
    ) -> Any:
        """Redact ``value`` found under ``path``. ``weak`` is set below a WEAK
        key (``weak_key``): strings there go when they read as secrets
        (``True``: numbers too, under ``pin``/``otp``) and not as an object
        id allowed under that key (:func:`allowed_identifier`)."""
        if isinstance(value, bool) or value is None:
            return value
        strength = self._key_strength(path) if path else 0
        if strength == STRONG and not _is_argv(value):
            if value == "" or value == {} or value == []:
                return value
            return self._redact()
        if strength == WEAK:
            weak_key = path.rsplit(".", 1)[-1]
            weak = bool(weak) or _numeric_identifier(weak_key)
        if depth >= self.max_depth:
            return "[truncated]"
        if isinstance(value, dict):
            out = {}
            paired = _paired_value_keys(value)
            jwk = "kty" in value
            for i, (k, v) in enumerate(value.items()):
                if i >= self.max_items:
                    out["_truncated"] = True
                    break
                key = str(k)[:128]
                if jwk and key in _JWK_PRIVATE and v not in (None, "", {}, []):
                    out[key] = self._redact()
                    continue
                if k in paired and v not in (None, "", {}, []):
                    pstrength, numeric, pname = paired[k]
                    if pstrength == STRONG or (
                        isinstance(v, (str, int)) and _secretish(str(v), numeric, pname)
                    ):
                        out[key] = self._redact()
                        continue
                out[key] = self.value(
                    f"{path}.{key}" if path else key, v, depth + 1, weak, weak_key
                )
            return out
        if isinstance(value, (list, tuple)):
            items = []
            item_path = "" if _is_argv(value) else path
            cli = cli_secret_args(list(value[: self.max_items]))
            for i, v in enumerate(value[: self.max_items]):
                if isinstance(v, str) and v and i in cli:
                    new = _cut_cli_value(v, cli[i])
                    if new != v:
                        self.count += 1
                    items.append(new)
                    continue
                if isinstance(v, str) and v and _secret_argument(value, i):
                    items.append(self._redact())
                    continue
                items.append(self.value(item_path, v, depth + 1, weak, weak_key))
            if len(value) > self.max_items:
                items.append("[truncated]")
            return items
        if weak is not None:
            if isinstance(value, (str, int)) and _secretish(str(value), weak, weak_key):
                return self._redact()
        if isinstance(value, str):
            leaf = path.rsplit(".", 1)[-1]
            if leaf in _VERBATIM_HEX and _HEX.match(value):
                return value
            return self.text(value, pii=leaf.lower() not in _ACTOR_KEYS)
        if isinstance(value, (int, float)):
            return value
        return self.text(str(value))

    def events(self, events: list[AuditEvent]) -> list[AuditEvent]:
        """:meth:`event` over a batch (the pipeline runs this off the loop)."""
        return [self.event(ev) for ev in events]

    def event(self, ev: AuditEvent) -> AuditEvent:
        details = ev.details
        if ev.source == "audit_checkpoints" and isinstance(details, dict):
            # Our own signer's output (public key, hashes, signature, the
            # signed body): verbatim, or the signature no longer verifies.
            # Anything else in details is scrubbed as usual.
            keep = AuditCheckpointSource.VERBATIM
            rest = {k: v for k, v in details.items() if k not in keep}
            scrubbed = self.value("", rest) if rest else {}
            details = {k: (v if k in keep else scrubbed[k]) for k, v in details.items()}
        else:
            details = self.value("", details)
        return replace(
            ev,
            message=self.text(ev.message),
            actor=self.text(ev.actor, pii=False) if ev.actor else ev.actor,
            user_agent=self.text(ev.user_agent) if ev.user_agent else ev.user_agent,
            details=details,
        )


# ---------------------------------------------------------------------------
# Formats: JSON, CEF, RFC 5424
# ---------------------------------------------------------------------------


# Characters a line-oriented receiver may take for the end of a record: CR, LF,
# VT, FF, NEL (U+0085), LINE SEPARATOR (U+2028) and PARAGRAPH SEPARATOR
# (U+2029). Any other C0/C1 control or DEL is escaped too, so a value an
# attacker typed (a login name, a user agent) cannot forge a second record.
_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029]")
_NAMED_CONTROL = {"\r": "\\r", "\n": "\\n", "\t": "\\t"}


def _escape_control(match: "re.Match[str]") -> str:
    ch = match.group(0)
    return _NAMED_CONTROL.get(ch) or f"\\u{ord(ch):04x}"


def escape_controls(value: str) -> str:
    """``\\r``, ``\\n``, ``\\t`` and ``\\uXXXX`` for every line break or control."""
    return _CONTROL.sub(_escape_control, value)


def json_line_safe(text_: str) -> str:
    """JSON from ``json.dumps(ensure_ascii=False)`` with U+2028/U+2029/NEL
    escaped as well (json escapes only C0 controls); valid JSON either way."""
    return (
        text_.replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
        .replace("\u0085", "\\u0085")
    )


def cef_escape_header(value: Any) -> str:
    """CEF header field: escape ``\\`` and ``|``. A header has no escape for a
    line break, so every line break (CR, LF, NEL, U+2028, U+2029) and other
    control becomes a space."""
    s = "" if value is None else str(value)
    s = s.replace("\\", "\\\\").replace("|", "\\|")
    return _CONTROL.sub(" ", s.replace("\r\n", " "))


def cef_escape_ext(value: Any) -> str:
    """CEF extension value: escape ``\\`` and ``=``; line breaks and other
    controls become ``\\r``/``\\n``/``\\uXXXX``."""
    s = "" if value is None else str(value)
    s = s.replace("\\", "\\\\").replace("=", "\\=")
    return escape_controls(s)


def _valid_ip(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def format_cef(ev: AuditEvent, host: str, *, max_details: int = 1024) -> str:
    """One CEF:0 line (no trailing newline)."""
    header = "|".join(
        [
            "CEF:0",
            cef_escape_header(PRODUCT),
            cef_escape_header(PRODUCT),
            cef_escape_header(__version__),
            cef_escape_header(f"{ev.source}:{ev.action}"),
            cef_escape_header(ev.message[:512] or ev.action),
            str(max(0, min(10, int(ev.severity)))),
        ]
    )
    details = json.dumps(ev.details, sort_keys=True, separators=(",", ":"))
    if len(details) > max_details:
        details = details[:max_details] + "...[truncated]"
    ext: list[tuple[str, Any]] = [
        ("rt", int(as_utc(ev.timestamp).timestamp() * 1000)),
        ("externalId", ev.id),
        ("cat", ev.category),
        ("act", ev.action),
        ("outcome", ev.outcome),
        ("suser", ev.actor),
        ("suid", ev.actor_id),
        ("src", _valid_ip(ev.src_ip)),
        ("requestClientApplication", ev.user_agent),
        ("dvchost", host),
        ("msg", ev.message),
        ("cs1Label", "targetType"),
        ("cs1", ev.target_type),
        ("cs2Label", "targetId"),
        ("cs2", ev.target_id),
        ("cs3Label", "source"),
        ("cs3", ev.source),
        ("cs4Label", "details"),
        ("cs4", details),
        ("cs5Label", "eventHash"),
        ("cs5", ev.hash),
    ]
    present = {k for k, v in ext if v not in (None, "") and not k.endswith("Label")}
    parts = []
    for key, value in ext:
        if key.endswith("Label"):
            if key[:-5] not in present:
                continue
        elif key not in present:
            continue
        parts.append(f"{key}={cef_escape_ext(value)}")
    return header + "|" + " ".join(parts)


def sd_escape(value: Any) -> str:
    """RFC 5424 §6.3.3 PARAM-VALUE: escape ``"``, ``\\`` and ``]``.

    Line breaks (CR, LF, NEL, U+2028, U+2029) and other controls are written
    as ``\\r``/``\\n``/``\\uXXXX`` too: RFC 5424 allows them in a PARAM-VALUE,
    but a receiver that splits on newlines would see a forged second record.
    """
    s = "" if value is None else str(value)
    s = s.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")
    return escape_controls(s)


def _printable(value: str, limit: int) -> str:
    """RFC 5424 header token: PRINTUSASCII (33..126) or the NILVALUE ``-``."""
    s = "".join(c for c in value if 33 <= ord(c) <= 126)[:limit]
    return s or "-"


def syslog_severity(cef_severity: int) -> int:
    if cef_severity >= 9:
        return 2  # critical
    if cef_severity >= 7:
        return 4  # warning
    if cef_severity >= 4:
        return 5  # notice
    return 6  # informational


_BOM = "\ufeff"


def format_rfc5424(
    ev: AuditEvent,
    *,
    host: str,
    facility: int = 13,
    body: Literal["rfc5424", "cef"] = "rfc5424",
    max_bytes: int = 8192,
    procid: Optional[int] = None,
) -> bytes:
    """One RFC 5424 message (unframed) with the event in an SD element.

    The MSG part is the event as JSON (``rfc5424``) or a CEF line (``cef``),
    UTF-8 with the BOM RFC 5424 §6.4 asks for. Too long for ``max_bytes``,
    ``details`` is dropped first, then the MSG is cut on a character boundary.
    """
    pri = facility * 8 + syslog_severity(ev.severity)
    header = " ".join(
        [
            f"<{pri}>1",
            iso_utc(ev.timestamp),
            _printable(host, 255),
            APP_NAME,
            _printable(str(procid if procid is not None else os.getpid()), 128),
            _printable(ev.category, 32),
        ]
    )
    params = [
        ("id", ev.id),
        ("src", ev.source),
        ("act", ev.action),
        ("outcome", ev.outcome),
        ("sev", ev.severity),
        ("actor", ev.actor),
        ("targetType", ev.target_type),
        ("targetId", ev.target_id),
        ("srcIp", _valid_ip(ev.src_ip)),
    ]
    sd = (
        "["
        + SD_ID
        + "".join(f' {k}="{sd_escape(v)}"' for k, v in params if v not in (None, ""))
        + "]"
    )

    def render(event: AuditEvent) -> bytes:
        if body == "cef":
            msg = format_cef(event, host)
        else:
            msg = json_line_safe(
                json.dumps(
                    event.to_dict(host), separators=(",", ":"), ensure_ascii=False
                )
            )
        return f"{header} {sd} {_BOM}{msg}".encode("utf-8")

    out = render(ev)
    if len(out) <= max_bytes:
        return out
    out = render(replace(ev, details={"_truncated": True}))
    if len(out) <= max_bytes:
        return out
    return out[:max_bytes].decode("utf-8", "ignore").encode("utf-8")


def frame_octet_count(message: bytes) -> bytes:
    """RFC 5425 / RFC 6587 §3.4.1 octet-counting: ``MSG-LEN SP SYSLOG-MSG``."""
    return str(len(message)).encode("ascii") + b" " + message


# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------


class DeliveryError(Exception):
    """A batch was not accepted. ``reason`` is a fixed code safe to show."""

    def __init__(self, reason: str, retry_after: Optional[float] = None):
        super().__init__(reason)
        self.reason = reason
        self.retry_after = retry_after


class BatchTooLarge(DeliveryError):
    def __init__(self) -> None:
        super().__init__("batch_too_large")


def build_ssl_context(
    *,
    verify: bool = True,
    ca_pem: Optional[str] = None,
    client_cert_pem: Optional[str] = None,
    client_key_pem: Optional[str] = None,
) -> ssl.SSLContext:
    """Client TLS context: TLS 1.2+, verification on unless explicitly off.

    A custom CA replaces the system store (the receiver is pinned to the
    customer's CA). The client key, if any, comes from the secrets manager and
    touches disk only inside a private temp directory for the duration of
    ``load_cert_chain``.
    """
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cadata=ca_pem or None)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if client_cert_pem and client_key_pem:
        with tempfile.TemporaryDirectory(prefix="audit-export-") as tmp:
            os.chmod(tmp, 0o700)
            cert_path = Path(tmp) / "client.crt"
            key_path = Path(tmp) / "client.key"
            cert_path.write_text(client_cert_pem)
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(client_key_pem)
            ctx.load_cert_chain(str(cert_path), str(key_path))
    return ctx


SecretGetter = Callable[[str], Optional[str]]


class Transport(ABC):
    @abstractmethod
    async def send(self, events: list[AuditEvent]) -> None:
        """Deliver ``events`` or raise :class:`DeliveryError`."""

    async def close(self) -> None:
        return None


class SyslogTransport(Transport):
    """RFC 5424 over TLS/TCP (octet-counted) or UDP (one datagram each).

    Syslog has no application-level acknowledgement. Over TCP/TLS a reader
    task watches the connection, so a receiver that closed it is noticed
    before the next batch is written into a dead socket; a batch is reported
    delivered once it is flushed to a connection still open.
    """

    def __init__(
        self, dest: SyslogDestination, secrets: SecretGetter, host: str
    ) -> None:
        self.dest = dest
        self.host = host
        self._secrets = secrets
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._watch: Optional[asyncio.Task] = None
        self._dead = True
        self._ssl: Optional[ssl.SSLContext] = None

    def _context(self) -> ssl.SSLContext:
        if self._ssl is None:
            self._ssl = build_ssl_context(
                verify=self.dest.tls_verify,
                ca_pem=self.dest.ca_pem,
                client_cert_pem=self.dest.client_cert_pem,
                client_key_pem=(
                    self._secrets(secret_name(self.dest.name, "CLIENT_KEY"))
                    if self.dest.client_cert_pem
                    else None
                ),
            )
        return self._ssl

    def encode(self, ev: AuditEvent) -> bytes:
        limit = self.dest.max_message_bytes
        if self.dest.protocol == "udp":
            limit = min(limit, 65000)
        return format_rfc5424(
            ev,
            host=self.host,
            facility=self.dest.facility,
            body=self.dest.format,
            max_bytes=limit,
        )

    async def _drain_reader(self, reader: asyncio.StreamReader) -> None:
        try:
            while await reader.read(4096):
                pass
        except Exception:  # noqa: BLE001 - any read failure means the link is gone
            pass
        self._dead = True

    async def _connect(self) -> None:
        await self.close()
        addresses = await asyncio.to_thread(
            resolve_egress, self.dest.host, self.dest.port
        )
        tls = self.dest.protocol == "tls"
        try:
            ctx = self._context() if tls else None
        except (ssl.SSLError, ValueError, OSError) as exc:
            raise DeliveryError("tls_config_invalid") from exc
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    addresses[0],
                    self.dest.port,
                    ssl=ctx,
                    server_hostname=self.dest.host if tls else None,
                ),
                timeout=self.dest.timeout_s,
            )
        except ssl.SSLError as exc:
            raise DeliveryError("tls_handshake_failed") from exc
        except (OSError, asyncio.TimeoutError) as exc:
            raise DeliveryError("connect_failed") from exc
        self._reader, self._writer, self._dead = reader, writer, False
        self._watch = asyncio.create_task(self._drain_reader(reader))

    async def send(self, events: list[AuditEvent]) -> None:
        if self.dest.protocol == "udp":
            await self._send_udp(events)
            return
        # Let the watcher observe a FIN that arrived while we were idle.
        await asyncio.sleep(0)
        if self._dead or self._writer is None or self._writer.is_closing():
            await self._connect()
        assert self._writer is not None
        payload = b"".join(frame_octet_count(self.encode(ev)) for ev in events)
        try:
            self._writer.write(payload)
            await asyncio.wait_for(self._writer.drain(), timeout=self.dest.timeout_s)
        except (OSError, asyncio.TimeoutError, ConnectionError) as exc:
            self._dead = True
            raise DeliveryError("send_failed") from exc
        await asyncio.sleep(0)
        if self._dead:
            raise DeliveryError("connection_closed")

    async def _send_udp(self, events: list[AuditEvent]) -> None:
        addresses = await asyncio.to_thread(
            resolve_egress, self.dest.host, self.dest.port
        )
        family = socket.AF_INET6 if ":" in addresses[0] else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            sock.settimeout(self.dest.timeout_s)
            for ev in events:
                sock.sendto(self.encode(ev), (addresses[0], self.dest.port))
        except OSError as exc:
            raise DeliveryError("send_failed") from exc
        finally:
            sock.close()

    async def close(self) -> None:
        writer, self._writer = self._writer, None
        watch, self._watch = self._watch, None
        self._dead = True
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), timeout=2)
        if watch is not None:
            watch.cancel()
            with contextlib.suppress(BaseException):
                await watch


class HttpTransport(Transport):
    """HTTPS POST: a JSON array (``application/json``) or CEF lines (``text/plain``).

    2xx is acceptance. 413 asks the pipeline to split the batch; anything else
    (429, 5xx, 4xx, network) is retried, honouring ``Retry-After``.
    """

    def __init__(
        self,
        dest: HttpDestination,
        secrets: SecretGetter,
        host: str,
        *,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        self.dest = dest
        self.host = host
        self._secrets = secrets
        self._client: Optional[httpx.AsyncClient] = None
        self._transport = transport

    def _headers(self, batch_id: str) -> dict:
        headers = {
            "User-Agent": f"{PRODUCT}-audit-export/{__version__}",
            "X-AutoSecOps-Batch-Id": batch_id,
        }
        token = self._secrets(secret_name(self.dest.name, "TOKEN"))
        if token:
            scheme = self.dest.auth_scheme
            headers[self.dest.auth_header] = f"{scheme} {token}" if scheme else token
        return headers

    def body(self, events: list[AuditEvent]) -> tuple[bytes, str]:
        if self.dest.format == "cef":
            lines = "\n".join(format_cef(ev, self.host) for ev in events) + "\n"
            return lines.encode("utf-8"), "text/plain; charset=utf-8"
        data = [ev.to_dict(self.host) for ev in events]
        return (
            json_line_safe(
                json.dumps(data, separators=(",", ":"), ensure_ascii=False)
            ).encode(),
            "application/json",
        )

    def _client_for(self) -> httpx.AsyncClient:
        if self._client is None:
            parsed = urlparse(self.dest.url)
            verify: Any = True
            if parsed.scheme == "https":
                verify = build_ssl_context(
                    verify=self.dest.tls_verify,
                    ca_pem=self.dest.ca_pem,
                    client_cert_pem=self.dest.client_cert_pem,
                    client_key_pem=(
                        self._secrets(secret_name(self.dest.name, "CLIENT_KEY"))
                        if self.dest.client_cert_pem
                        else None
                    ),
                )
            self._client = httpx.AsyncClient(
                verify=verify,
                timeout=self.dest.timeout_s,
                follow_redirects=False,
                transport=self._transport,
                trust_env=False,
            )
        return self._client

    def pinned_request(self, address: str) -> tuple[httpx.URL, dict, dict]:
        """The URL with its host replaced by ``address``, plus the ``Host``
        header and the TLS SNI/verification name that keep the original host.

        The client then dials exactly the address :func:`resolve_egress`
        checked; httpx never resolves the name itself.
        """
        url = httpx.URL(self.dest.url)
        extensions: dict = {}
        if url.scheme == "https":
            extensions["sni_hostname"] = url.host
        host_header = url.netloc.decode("ascii")
        return url.copy_with(host=address), {"Host": host_header}, extensions

    async def send(self, events: list[AuditEvent]) -> None:
        parsed = urlparse(self.dest.url)
        addresses = await asyncio.to_thread(
            resolve_egress,
            parsed.hostname or "",
            parsed.port or (443 if parsed.scheme == "https" else 80),
        )
        try:
            client = self._client_for()
        except (ssl.SSLError, ValueError, OSError) as exc:
            raise DeliveryError("tls_config_invalid") from exc
        content, ctype = self.body(events)
        headers = self._headers(events[0].id if len(events) == 1 else _batch_id(events))
        headers["Content-Type"] = ctype
        response: Optional[httpx.Response] = None
        last: Optional[BaseException] = None
        for address in addresses:
            url, host_header, extensions = self.pinned_request(address)
            try:
                response = await client.post(
                    url,
                    content=content,
                    headers={**headers, **host_header},
                    extensions=extensions,
                )
                break
            except httpx.ConnectError as exc:
                if _is_tls_error(exc):
                    raise DeliveryError("tls_handshake_failed") from exc
                last = exc  # try the next checked address
            except httpx.TimeoutException as exc:
                raise DeliveryError("timeout") from exc
            except httpx.HTTPError as exc:
                raise DeliveryError("send_failed") from exc
        if response is None:
            raise DeliveryError("connect_failed") from last
        if 200 <= response.status_code < 300:
            return
        if response.status_code == 413:
            raise BatchTooLarge()
        retry_after = None
        with contextlib.suppress(TypeError, ValueError):
            retry_after = float(response.headers.get("Retry-After"))
        raise DeliveryError(f"http_{response.status_code}", retry_after=retry_after)

    async def close(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            await client.aclose()


def _is_tls_error(exc: BaseException) -> bool:
    seen: set[int] = set()
    cur: Optional[BaseException] = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, ssl.SSLError) or "CERTIFICATE_VERIFY_FAILED" in str(cur):
            return True
        cur = cur.__cause__ or cur.__context__
    return False


def _batch_id(events: list[AuditEvent]) -> str:
    digest = hashlib.sha256("\n".join(ev.id for ev in events).encode()).hexdigest()
    return digest[:32]


def build_transport(dest: Any, secrets: SecretGetter, host: str) -> Transport:
    if isinstance(dest, SyslogDestination):
        return SyslogTransport(dest, secrets, host)
    return HttpTransport(dest, secrets, host)


# ---------------------------------------------------------------------------
# Durable cursors
# ---------------------------------------------------------------------------


class FileCursorStore:
    """``{"<destination>/<source>": cursor}`` in one JSON file.

    Written whole on each commit: temp file, fsync, rename, fsync the
    directory. A crash leaves either the old or the new file, never a torn one.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._data: Optional[dict] = None

    def _load(self) -> dict:
        if self._data is None:
            try:
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
            except FileNotFoundError:
                self._data = {}
            except (OSError, ValueError):
                # A corrupt cursor file is not a reason to skip ahead: refuse.
                raise RuntimeError("audit export cursor file is unreadable")
        return self._data

    def get(self, destination: str, source: str) -> Optional[dict]:
        with self._lock:
            value = self._load().get(f"{destination}/{source}")
            return dict(value) if isinstance(value, dict) else None

    def all(self) -> dict:
        with self._lock:
            return json.loads(json.dumps(self._load()))

    def commit(self, destination: str, source: str, cursor: dict) -> None:
        with self._lock:
            data = dict(self._load())
            data[f"{destination}/{source}"] = cursor
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(
                prefix=".cursors-", dir=str(self.path.parent), text=True
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, sort_keys=True)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, self.path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise
            dir_fd = os.open(str(self.path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
            self._data = data


# ---------------------------------------------------------------------------
# Auth spool: an append-only, size-bounded JSONL log shared by processes
# ---------------------------------------------------------------------------


class AuthSpool:
    """Auth events written by request handlers, read by the exporter.

    Segments ``auth-<n>.jsonl`` grow to ``segment_bytes`` and roll over. Writes
    take an ``flock`` so processes sharing the directory interleave whole lines.
    Past ``max_bytes`` new events are dropped and counted (bounded disk beats
    a full volume taking the API down); the exporter prunes segments every
    destination has read past.
    """

    _NAME = re.compile(r"^auth-(\d{12})\.jsonl$")

    def __init__(
        self, directory: Path, *, max_bytes: int, segment_bytes: int = 8 * 1024**2
    ) -> None:
        self.directory = directory
        self.max_bytes = max_bytes
        self.segment_bytes = segment_bytes
        self.dropped = 0
        self.written = 0

    def _segments(self) -> list[int]:
        if not self.directory.is_dir():
            return []
        found = []
        for entry in self.directory.iterdir():
            m = self._NAME.match(entry.name)
            if m:
                found.append(int(m.group(1)))
        return sorted(found)

    def _path(self, n: int) -> Path:
        return self.directory / f"auth-{n:012d}.jsonl"

    @contextlib.contextmanager
    def _locked(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(self.directory, 0o700)
        fd = os.open(str(self.directory / ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def size(self) -> int:
        total = 0
        for n in self._segments():
            with contextlib.suppress(OSError):
                total += self._path(n).stat().st_size
        return total

    def append(self, record: dict) -> bool:
        line = (json.dumps(record, separators=(",", ":"), default=str) + "\n").encode()
        with self._locked():
            segments = self._segments()
            if self.size() + len(line) > self.max_bytes:
                self.dropped += 1
                return False
            n = segments[-1] if segments else 1
            path = self._path(n)
            if path.exists() and path.stat().st_size + len(line) > self.segment_bytes:
                n += 1
                path = self._path(n)
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)
        self.written += 1
        return True

    def tail(self) -> dict:
        segments = self._segments()
        if not segments:
            return {"segment": 1, "offset": 0}
        n = segments[-1]
        return {"segment": n, "offset": self._path(n).stat().st_size}

    def read(self, cursor: dict, limit: int) -> list[tuple[dict, dict]]:
        """Up to ``limit`` complete records after ``cursor``, each with its end."""
        out: list[tuple[dict, dict]] = []
        segment, offset = int(cursor.get("segment", 1)), int(cursor.get("offset", 0))
        for n in [s for s in self._segments() if s >= segment]:
            if n > segment:
                offset = 0
            try:
                with open(self._path(n), "rb") as fh:
                    fh.seek(offset)
                    while len(out) < limit:
                        line = fh.readline()
                        if not line or not line.endswith(b"\n"):
                            break  # end, or a write still in progress
                        offset += len(line)
                        try:
                            record = json.loads(line)
                        except ValueError:
                            logger.warning("audit export: skipped a corrupt spool line")
                            continue
                        out.append((record, {"segment": n, "offset": offset}))
            except FileNotFoundError:
                continue
            if len(out) >= limit:
                break
        return out

    def prune(self, keep_from_segment: int) -> int:
        removed = 0
        with self._locked():
            segments = self._segments()
            for n in segments[:-1]:  # never the segment being written
                if n < keep_from_segment:
                    with contextlib.suppress(FileNotFoundError):
                        self._path(n).unlink()
                        removed += 1
        return removed


AUTH_SEVERITY = {
    ("login", "success"): 3,
    ("login", "failure"): 5,
    ("login", "locked"): 7,
    ("login", "mfa_failure"): 6,
    ("logout", "success"): 2,
    ("password_change", "success"): 5,
    ("password_reset_request", "success"): 4,
    ("password_reset", "success"): 6,
    ("mfa_setup", "success"): 4,
    ("mfa_enable", "success"): 5,
    ("mfa_enable", "failure"): 5,
    ("mfa_disable", "success"): 7,
    ("mfa_recovery_codes", "success"): 5,
    ("user_create", "success"): 6,
    ("user_delete", "success"): 7,
    ("user_update", "success"): 5,
    ("role_change", "success"): 7,
    ("user_deactivate", "success"): 6,
    ("user_activate", "success"): 5,
}


def auth_record(
    action: str,
    *,
    outcome: str = "success",
    actor: Optional[str] = None,
    actor_id: Optional[str] = None,
    target_id: Optional[str] = None,
    src_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[dict] = None,
    now: Optional[datetime] = None,
) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "ts": iso_utc(now or datetime.now(timezone.utc)),
        "action": action,
        "outcome": outcome,
        "actor": actor,
        "actor_id": actor_id,
        "target_id": target_id,
        "src_ip": src_ip,
        "user_agent": (user_agent or "")[:256] or None,
        "details": details or {},
    }


def auth_event(record: dict) -> AuditEvent:
    action, outcome = str(record.get("action")), str(record.get("outcome"))
    actor = record.get("actor")
    target = record.get("target_id")
    what = action.replace("_", " ")
    message = f"{what} {outcome}" + (f" for {actor}" if actor else "")
    if target and target != record.get("actor_id"):
        message += f" (target {target})"
    return AuditEvent(
        id=f"auth:{record['id']}",
        source="auth",
        category="authentication",
        action=f"auth.{action}",
        outcome=outcome,
        severity=AUTH_SEVERITY.get((action, outcome), 5),
        timestamp=as_utc(record["ts"]),
        message=message,
        actor=actor,
        actor_id=record.get("actor_id"),
        target_type="user" if target else None,
        target_id=target,
        src_ip=record.get("src_ip"),
        user_agent=record.get("user_agent"),
        details=record.get("details") or {},
    )


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

SessionScope = Callable[[], ContextManager[Session]]
Clock = Callable[[], datetime]


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Source(ABC):
    name: str

    @abstractmethod
    def initial_cursor(self, start_from: str) -> dict:
        """Where a destination that has never committed starts."""

    @abstractmethod
    def fetch(self, cursor: dict, limit: int) -> list[tuple[AuditEvent, dict]]:
        """Events after ``cursor``, oldest first, each paired with its cursor."""


class AuthSpoolSource(Source):
    name = "auth"

    def __init__(self, spool: AuthSpool) -> None:
        self.spool = spool

    def initial_cursor(self, start_from: str) -> dict:
        if start_from == "beginning":
            segments = self.spool._segments()
            return {"segment": segments[0] if segments else 1, "offset": 0}
        return self.spool.tail()

    def fetch(self, cursor: dict, limit: int) -> list[tuple[AuditEvent, dict]]:
        out = []
        for record, after in self.spool.read(cursor, limit):
            try:
                out.append((auth_event(record), after))
            except (KeyError, TypeError, ValueError):
                logger.warning("audit export: skipped a malformed auth record")
        return out


def _json(value: Any) -> Any:
    if isinstance(value, (str, bytes)):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def _naive(value: datetime) -> datetime:
    return as_utc(value).replace(tzinfo=None)


# On Postgres every database source pages on the inserting (or last updating)
# transaction id first. ``xmin`` is the 32-bit id; widened to 64 bits against
# the snapshot's ``xmax`` (no live row is 2^32 transactions older than that).
_SNAPSHOT_SQL = (
    "(SELECT pg_snapshot_xmin(c)::text::bigint AS safe, "
    "pg_snapshot_xmax(c)::text::bigint AS top FROM pg_current_snapshot() AS c) "
    "AS snap"
)
_FULL_XID = "(((snap.top >> 32) << 32) | (t.xmin::text::bigint))"
_ROW_XID = (
    f"(CASE WHEN {_FULL_XID} >= snap.top THEN {_FULL_XID} - 4294967296 "
    f"ELSE {_FULL_XID} END)"
)


class _DbSource(Source):
    """A table read in a keyset order that a late commit cannot jump.

    **Postgres** (production): rows are read in ``(xid, key)`` order, where
    ``xid`` is the row's inserting transaction (``xmin``), and only rows whose
    transaction is older than ``pg_snapshot_xmin(pg_current_snapshot())`` —
    the oldest transaction still running — are read at all. Every transaction
    below that bound has committed or aborted, so nothing can later appear
    behind the cursor: a transaction that holds a lower id or an older
    timestamp open for an hour is simply waited for, and the cursor never
    passes an uncommitted row. ``settle_s`` is not used.

    **Anything else** (SQLite in unit tests, a single writer): rows are read in
    key order up to ``now - settle_s``.

    Known limits (also in AUDIT_EXPORT.md): a long-running transaction delays
    export of everything committed after it began (never loses it) — and xids
    are cluster-wide, so that includes a writer in another database on the
    same server; the xid
    filter cannot use an index, so each poll scans the source table; a row
    that is UPDATEd gets a new ``xmin`` and is read again (``approval_actions``
    — at-least-once, the event ``id`` is stable); a logical restore into
    another cluster (new xids) is detected when the cursor is ahead of the
    transaction counter and re-reads from the start.
    """

    def __init__(
        self,
        session_scope: SessionScope,
        *,
        settle_s: float = 5.0,
        clock: Clock = _now,
    ) -> None:
        self.session_scope = session_scope
        self.settle = timedelta(seconds=settle_s)
        self.clock = clock

    def cutoff(self) -> datetime:
        return self.clock() - self.settle

    @staticmethod
    def _postgres(session: Session) -> bool:
        return session.get_bind().dialect.name == "postgresql"

    @staticmethod
    def _snapshot(session: Session) -> tuple[int, int]:
        """``(xmin, xmax)`` of the current snapshot, as 64-bit ids."""
        row = session.execute(
            text(
                "SELECT pg_snapshot_xmin(c)::text::bigint, "
                "pg_snapshot_xmax(c)::text::bigint FROM pg_current_snapshot() AS c"
            )
        ).one()
        return int(row[0]), int(row[1])

    def _start_xid(self, session: Session, cursor: dict) -> int:
        xid = int(cursor.get("xid", 0))
        _, top = self._snapshot(session)
        if xid > top:
            logger.warning(
                "audit export: the %s cursor is ahead of this database's "
                "transaction counter (restored or replaced database?); "
                "re-reading from the start",
                self.name,
            )
            return 0
        return xid

    def _pg_rows(
        self,
        session: Session,
        cursor: dict,
        *,
        table: str,
        columns: str,
        keys: list[tuple[str, str, Any]],
        limit: int,
        where: str = "",
        params: Optional[dict] = None,
        binds: Iterable[Any] = (),
        types: Optional[dict] = None,
    ) -> list[dict]:
        """Rows after ``cursor`` in ``(xid, *keys)`` order, below the safe xid.

        ``keys`` are ``(output column, bind name, cursor value)``. Names are
        fixed by the subclasses, never user input.
        """
        key_cols = ", ".join(f"q.{col}" for col, _, _ in keys)
        key_binds = ", ".join(f":{bind}" for _, bind, _ in keys)
        inner = (
            f"SELECT {columns}, {_ROW_XID} AS _xid "  # nosec B608 - fixed names
            f"FROM {table} AS t CROSS JOIN {_SNAPSHOT_SQL} "
            f"WHERE {_ROW_XID} < snap.safe{where}"
        )
        stmt = text(
            f"SELECT * FROM ({inner}) AS q "  # nosec B608 - fixed names
            f"WHERE (q._xid, {key_cols}) > (:xid, {key_binds}) "
            f"ORDER BY q._xid, {key_cols} LIMIT :n"
        )
        if binds:
            stmt = stmt.bindparams(*binds)
        stmt = stmt.columns(_xid=Integer(), **(types or {}))
        values: dict[str, Any] = {
            "xid": self._start_xid(session, cursor),
            "n": limit,
            **(params or {}),
        }
        for _, bind, value in keys:
            values[bind] = value
        return [dict(r) for r in session.execute(stmt, values).mappings()]

    def _pg_initial(self, start_from: str, **keys: Any) -> dict:
        """A first cursor: everything (``beginning``) or what commits from now."""
        if start_from == "beginning":
            return {"xid": 0, **keys}
        with self.session_scope() as session:
            if not self._postgres(session):
                return {}
            safe, _ = self._snapshot(session)
        return {"xid": safe, **keys}


_HORIZON_HOLDER_SQL = text(
    "SELECT pid, datname, state, "
    "EXTRACT(EPOCH FROM (now() - xact_start))::float AS xact_age_s, "
    "EXTRACT(EPOCH FROM (now() - state_change))::float AS state_age_s "
    "FROM pg_stat_activity "
    "WHERE backend_xid IS NOT NULL AND pid <> pg_backend_pid() "
    "ORDER BY age(backend_xid) DESC LIMIT 1"
)


def probe_xid_horizon(session: Session) -> Optional[dict]:
    """The export horizon (``pg_snapshot_xmin``) and the session holding it.

    Postgres sources only export rows below the oldest running transaction,
    so one session left ``idle in transaction`` after a write stops export
    (of every database on the server) until it ends. Returns ``None`` off
    Postgres. ``holder`` is ``None`` when nothing holds the horizon, or when
    this role may not see the other session (``pg_read_all_stats`` lets it);
    no query text is read.
    """
    if session.get_bind().dialect.name != "postgresql":
        return None
    safe, top = _DbSource._snapshot(session)
    holder = None
    row = session.execute(_HORIZON_HOLDER_SQL).mappings().first()
    if row is not None:
        holder = {
            "pid": int(row["pid"]),
            "database": row["datname"],
            "state": row["state"],
            "xact_age_s": float(row["xact_age_s"] or 0.0),
            "state_age_s": float(row["state_age_s"] or 0.0),
        }
    return {"xmin": safe, "xmax": top, "holder": holder}


class _IdSource(_DbSource):
    """A table with an autoincrement id: cursor ``{"xid": x, "id": n}``.

    On Postgres the order is ``(xid, id)`` below the oldest running
    transaction (see :class:`_DbSource`). Elsewhere rows are read in id order
    and the read stops at the first row younger than the settle window.
    """

    table: str
    id_col: str
    ts_col: str = "timestamp"
    columns: str

    def initial_cursor(self, start_from: str) -> dict:
        if start_from == "beginning":
            return {"xid": 0, "id": 0}
        pg = self._pg_initial(start_from, id=0)
        if pg:
            return pg
        with self.session_scope() as session:
            top = session.execute(
                text(f"SELECT MAX({self.id_col}) FROM {self.table}")  # nosec B608
            ).scalar()
        return {"id": int(top or 0)}

    def fetch(self, cursor: dict, limit: int) -> list[tuple[AuditEvent, dict]]:
        with self.session_scope() as session:
            if self._postgres(session):
                rows = self._pg_rows(
                    session,
                    cursor,
                    table=self.table,
                    columns=self.columns,
                    keys=[(self.id_col, "id", int(cursor.get("id", 0)))],
                    limit=limit,
                    types={self.ts_col: DateTime(), self.id_col: Integer()},
                )
                return [
                    (
                        self.event(row),
                        {"xid": int(row["_xid"]), "id": int(row[self.id_col])},
                    )
                    for row in rows
                ]
            stmt = text(
                f"SELECT {self.columns} FROM {self.table} "  # nosec B608 - fixed names
                f"WHERE {self.id_col} > :id ORDER BY {self.id_col} LIMIT :n"
            ).columns(**{self.ts_col: DateTime(), self.id_col: Integer()})
            rows = session.execute(
                stmt, {"id": int(cursor.get("id", 0)), "n": limit}
            ).mappings()
            rows = [dict(r) for r in rows]
        cutoff = self.cutoff()
        out = []
        for row in rows:
            if as_utc(row[self.ts_col]) >= cutoff:
                break
            out.append((self.event(row), {"id": int(row[self.id_col])}))
        return out

    @abstractmethod
    def event(self, row: dict) -> AuditEvent: ...


class ConfigAuditSource(_IdSource):
    name = "config"
    table = "config_audit_log"
    id_col = "id"
    columns = (
        "id, config_type, config_key, action, old_value, new_value, "
        "changed_by, change_reason, timestamp"
    )

    def event(self, row: dict) -> AuditEvent:
        action = str(row["action"])
        return AuditEvent(
            id=f"config:{row['id']}",
            source=self.name,
            category="configuration",
            action=f"config.{action}",
            outcome="success",
            severity=6 if row["config_key"] == CONFIG_KEY else 5,
            timestamp=as_utc(row["timestamp"]),
            message=f"{row['config_type']} config {row['config_key']} {action}",
            actor=row["changed_by"],
            target_type=str(row["config_type"]),
            target_id=str(row["config_key"]),
            details={
                "config_type": row["config_type"],
                "config_key": row["config_key"],
                "change_reason": row["change_reason"],
                "old_value": _json(row["old_value"]),
                "new_value": _json(row["new_value"]),
            },
        )


class CaseAuditSource(_IdSource):
    name = "case_audit"
    table = "case_audit_logs"
    id_col = "audit_id"
    columns = (
        "audit_id, entity_type, entity_id, action, field_name, old_value, "
        "new_value, change_summary, changed_by, user_agent, ip_address, timestamp"
    )

    def event(self, row: dict) -> AuditEvent:
        action = str(row["action"])
        return AuditEvent(
            id=f"case_audit:{row['audit_id']}",
            source=self.name,
            category="case",
            action=f"case.{row['entity_type']}.{action}",
            outcome="success",
            severity=4 if action == "delete" else 3,
            timestamp=as_utc(row["timestamp"]),
            message=row["change_summary"]
            or f"{row['entity_type']} {row['entity_id']} {action}",
            actor=row["changed_by"],
            target_type=str(row["entity_type"]),
            target_id=str(row["entity_id"]),
            src_ip=row["ip_address"],
            user_agent=row["user_agent"],
            details={
                "field": row["field_name"],
                "old_value": row["old_value"],
                "new_value": row["new_value"],
            },
        )


class AuditCheckpointSource(_IdSource):
    """W1.10's signed audit-chain checkpoints (``audit_checkpoints``).

    The chain itself (``audit_chain``) is not exported: its rows mirror
    ``approval_actions`` and ``case_audit_logs`` changes, which the
    ``approvals`` and ``case_audit`` sources already send. What the SIEM
    gains is each checkpoint: the Ed25519-signed body naming the
    ``audit_chain`` head (seq, hash) and the agent-ledger heads, its
    ``body_hash``, ``prev_body_hash`` link and signature. W1.10 can only
    show chain-tail deletion or rewriting back to a checkpoint when a copy of
    the checkpoints is kept outside the database; the SIEM is that copy.
    ``python -m core.audit.verify --checkpoint-file`` style checks can be run
    against the exported ``body`` + ``signature``, so they are exported
    verbatim (see :meth:`Redactor.event`).

    A database without W1.10's schema has no such table: the source then
    reads nothing (and looks again on later polls) instead of failing.
    """

    name = "audit_checkpoints"
    table = "audit_checkpoints"
    id_col = "id"
    ts_col = "created_at"
    columns = (
        "id, created_at, key_id, public_key, body, body_hash, prev_body_hash, "
        "signature, tsa_token"
    )
    VERBATIM = frozenset(
        {
            "key_id",
            "public_key",
            "body",
            "body_hash",
            "prev_body_hash",
            "signature",
            "tsa_token",
            "audit_chain_head",
            "schema_change",
        }
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._present = False

    def _table_present(self) -> bool:
        if self._present:
            return True
        from sqlalchemy import inspect as sa_inspect

        with self.session_scope() as session:
            self._present = bool(sa_inspect(session.get_bind()).has_table(self.table))
        return self._present

    def initial_cursor(self, start_from: str) -> dict:
        if not self._table_present():
            # Created later (W1.10 installed afterwards): every checkpoint
            # it will hold is newer than this enable.
            return {"xid": 0, "id": 0}
        return super().initial_cursor(start_from)

    def fetch(self, cursor: dict, limit: int) -> list[tuple[AuditEvent, dict]]:
        if not self._table_present():
            return []
        return super().fetch(cursor, limit)

    def event(self, row: dict) -> AuditEvent:
        body = _json(row["body"])
        body = body if isinstance(body, dict) else {}
        chain = (
            body.get("audit_chain") if isinstance(body.get("audit_chain"), dict) else {}
        )
        head = chain.get("head")
        rebaseline = "schema_change" in body
        return AuditEvent(
            id=f"audit_checkpoints:{row['id']}",
            source=self.name,
            category="integrity",
            action="audit.checkpoint.rebaseline" if rebaseline else "audit.checkpoint",
            outcome="success",
            severity=5 if rebaseline else 3,
            timestamp=as_utc(row["created_at"]),
            message=(
                f"audit chain checkpoint {row['id']} signed by key {row['key_id']}"
                + (
                    f", chain head seq {head.get('seq')}"
                    if isinstance(head, dict)
                    else ""
                )
            ),
            target_type="audit_checkpoint",
            target_id=str(row["id"]),
            hash=row["body_hash"],
            details={
                "key_id": row["key_id"],
                "public_key": row["public_key"],
                "body": row["body"],
                "body_hash": row["body_hash"],
                "prev_body_hash": row["prev_body_hash"],
                "signature": row["signature"],
                "tsa_token": row["tsa_token"],
                "audit_chain_head": head,
                "schema_change": body.get("schema_change"),
            },
        )


class AgentEventsSource(_DbSource):
    """The agent ledger, keyset-paged on ``(xid, run_id, seq)`` on Postgres
    (``(ts, run_id, seq)`` up to the settle cutoff elsewhere).

    Exports the ledger coordinates, kind and hash-chain values, plus the
    payload's top-level scalars (redacted downstream); nested payload content
    (prompts, tool output) stays in AutoSecOps.
    """

    name = "agent_events"

    def __init__(self, *args: Any, kinds: Iterable[str] = (), **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.kinds = sorted(set(kinds))

    _COLUMNS = (
        "CAST(run_id AS TEXT) AS run_id, seq, ts, run_kind, kind, "
        "payload, schema_version, prev_hash, event_hash"
    )

    def initial_cursor(self, start_from: str) -> dict:
        if start_from == "beginning":
            return {"xid": 0, "ts": iso_utc(_EPOCH), "run_id": "", "seq": -1}
        pg = self._pg_initial(start_from, run_id="", seq=-1)
        if pg:
            return pg
        return {"ts": iso_utc(self.cutoff()), "run_id": "", "seq": -1}

    def _pg_fetch(
        self, session: Session, cursor: dict, limit: int
    ) -> list[tuple[AuditEvent, dict]]:
        binds = []
        params: dict[str, Any] = {}
        where = ""
        if self.kinds:
            where = " AND kind IN :kinds"
            binds.append(bindparam("kinds", expanding=True, type_=String()))
            params["kinds"] = self.kinds
        rows = self._pg_rows(
            session,
            cursor,
            table="agent_events",
            columns=self._COLUMNS,
            keys=[
                ("run_id", "rid", str(cursor.get("run_id", ""))),
                ("seq", "seq", int(cursor.get("seq", -1))),
            ],
            limit=limit,
            where=where,
            params=params,
            binds=binds,
            types={"ts": DateTime(timezone=True)},
        )
        out = []
        for row in rows:
            ts = as_utc(row["ts"])
            out.append(
                (
                    self.event(row, ts),
                    {
                        "xid": int(row["_xid"]),
                        "run_id": row["run_id"],
                        "seq": row["seq"],
                    },
                )
            )
        return out

    def fetch(self, cursor: dict, limit: int) -> list[tuple[AuditEvent, dict]]:
        with self.session_scope() as session:
            if self._postgres(session):
                return self._pg_fetch(session, cursor, limit)
        kind_filter = ""
        params: dict[str, Any] = {
            "ts": as_utc(cursor["ts"]),
            "rid": str(cursor.get("run_id", "")),
            "seq": int(cursor.get("seq", -1)),
            "cutoff": self.cutoff(),
            "n": limit,
        }
        if self.kinds:
            kind_filter = " AND kind IN :kinds"
        stmt = text(
            "SELECT CAST(run_id AS TEXT) AS run_id, seq, ts, run_kind, kind, "
            "payload, schema_version, prev_hash, event_hash FROM agent_events "
            "WHERE ts < :cutoff AND (ts > :ts OR (ts = :ts AND "
            "(CAST(run_id AS TEXT) > :rid OR "
            "(CAST(run_id AS TEXT) = :rid AND seq > :seq))))"
            + kind_filter
            + " ORDER BY ts, CAST(run_id AS TEXT), seq LIMIT :n"
        )
        binds = [
            bindparam("ts", type_=DateTime(timezone=True)),
            bindparam("cutoff", type_=DateTime(timezone=True)),
        ]
        if self.kinds:
            binds.append(bindparam("kinds", expanding=True, type_=String()))
            params["kinds"] = self.kinds
        stmt = stmt.bindparams(*binds).columns(ts=DateTime(timezone=True))
        with self.session_scope() as session:
            rows = [dict(r) for r in session.execute(stmt, params).mappings()]
        out = []
        for row in rows:
            ts = as_utc(row["ts"])
            out.append(
                (
                    self.event(row, ts),
                    {"ts": ts.isoformat(), "run_id": row["run_id"], "seq": row["seq"]},
                )
            )
        return out

    def event(self, row: dict, ts: datetime) -> AuditEvent:
        payload = _json(row["payload"])
        summary = {}
        if isinstance(payload, dict):
            for key, value in list(payload.items())[:40]:
                if value is None or isinstance(value, (bool, int, float)):
                    summary[key] = value
                elif isinstance(value, str):
                    summary[key] = value[:256]
        kind = str(row["kind"])
        return AuditEvent(
            id=f"agent_events:{row['run_id']}:{row['seq']}",
            source=self.name,
            category="agent",
            action=f"agent.{kind}",
            outcome="success",
            severity=4 if kind == "terminal" else 3,
            timestamp=ts,
            message=f"{row['run_kind']} run {row['run_id']} event {row['seq']}: {kind}",
            actor="agent",
            target_type="agent_run",
            target_id=str(row["run_id"]),
            hash=row.get("event_hash"),
            details={
                "run_kind": row["run_kind"],
                "seq": row["seq"],
                "schema_version": row["schema_version"],
                "prev_hash": row.get("prev_hash"),
                "payload": summary,
            },
        )


class ApprovalTransitionSource(_DbSource):
    """One ``approval_actions`` transition, keyset-paged on ``(xid, action_id)``
    on Postgres (``(<col>, action_id)`` up to the settle cutoff elsewhere).

    ``approval_actions`` is a mutable row, not a log; each timestamp column that
    is set once marks a transition, and each gets its own cursor.
    """

    COLUMNS = {
        "created": "created_at",
        "decided": "approved_at",
        "executed": "executed_at",
        "verified": "verified_at",
        "reversed": "reversed_at",
    }

    def __init__(self, transition: str, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.transition = transition
        self.col = self.COLUMNS[transition]
        self.name = f"approvals.{transition}"

    _COLUMNS = (
        "action_id, action_type, title, target, confidence, "
        "created_by, status, approved_by, rejection_reason, reversibility, "
        "workflow_run_id, verify_status, reverse_of, second_approver, parameters"
    )

    def initial_cursor(self, start_from: str) -> dict:
        if start_from == "beginning":
            return {"xid": 0, "ts": iso_utc(_EPOCH), "id": ""}
        pg = self._pg_initial(start_from, id="")
        if pg:
            return pg
        return {"ts": iso_utc(self.cutoff()), "id": ""}

    def _pg_fetch(
        self, session: Session, cursor: dict, limit: int
    ) -> list[tuple[AuditEvent, dict]]:
        # A transition is a column set once by an UPDATE; that UPDATE's xid is
        # the row's xmin until the next UPDATE, which makes the row (and so
        # this transition) come round again — a duplicate, never a loss.
        rows = self._pg_rows(
            session,
            cursor,
            table="approval_actions",
            columns=f"{self._COLUMNS}, {self.col} AS at",
            keys=[("action_id", "id", str(cursor.get("id", "")))],
            limit=limit,
            where=f" AND {self.col} IS NOT NULL",
            types={"at": DateTime()},
        )
        out = []
        for row in rows:
            at = as_utc(row["at"])
            out.append(
                (
                    self.event(row, at),
                    {"xid": int(row["_xid"]), "id": row["action_id"]},
                )
            )
        return out

    def fetch(self, cursor: dict, limit: int) -> list[tuple[AuditEvent, dict]]:
        with self.session_scope() as session:
            if self._postgres(session):
                return self._pg_fetch(session, cursor, limit)
        col = self.col
        stmt = (
            text(
                "SELECT action_id, action_type, title, target, confidence, "
                "created_by, status, approved_by, rejection_reason, reversibility, "
                "workflow_run_id, verify_status, reverse_of, second_approver, "
                f"parameters, {col} AS at FROM approval_actions "  # nosec B608
                f"WHERE {col} IS NOT NULL AND {col} < :cutoff AND "
                f"({col} > :ts OR ({col} = :ts AND action_id > :id)) "
                f"ORDER BY {col}, action_id LIMIT :n"
            )
            .bindparams(
                bindparam("ts", type_=DateTime()),
                bindparam("cutoff", type_=DateTime()),
            )
            .columns(at=DateTime())
        )
        params = {
            "ts": _naive(as_utc(cursor["ts"])),
            "cutoff": _naive(self.cutoff()),
            "id": str(cursor.get("id", "")),
            "n": limit,
        }
        with self.session_scope() as session:
            rows = [dict(r) for r in session.execute(stmt, params).mappings()]
        out = []
        for row in rows:
            at = as_utc(row["at"])
            out.append(
                (self.event(row, at), {"ts": at.isoformat(), "id": row["action_id"]})
            )
        return out

    def event(self, row: dict, at: datetime) -> AuditEvent:
        irreversible = row.get("reversibility") == "irreversible"
        t = self.transition
        actor = None
        if t == "created":
            action, outcome, severity = "approval.requested", "pending", 4
            actor = row["created_by"]
        elif t == "decided":
            rejected = bool(row["rejection_reason"]) or row["status"] == "rejected"
            action = "approval.rejected" if rejected else "approval.approved"
            outcome, severity = ("rejected" if rejected else "approved"), 5
            actor = row["approved_by"]
        elif t == "executed":
            failed = row["status"] == "failed"
            action, outcome = "response.executed", ("failure" if failed else "success")
            severity = 8 if irreversible else 6
        elif t == "verified":
            action, outcome, severity = (
                "response.verified",
                str(row["verify_status"] or "unknown"),
                4,
            )
        else:
            action, outcome, severity = "response.reversed", "success", 6
        if irreversible and t in ("created", "decided"):
            severity += 2
        return AuditEvent(
            id=f"approvals:{row['action_id']}:{t}",
            source="approvals",
            category="approval",
            action=action,
            outcome=outcome,
            severity=severity,
            timestamp=at,
            message=f"{row['action_type']} on {row['target']}: {action} ({outcome})",
            actor=actor,
            target_type="approval_action",
            target_id=str(row["action_id"]),
            details={
                "action_type": row["action_type"],
                "title": row["title"],
                "target": row["target"],
                "status": row["status"],
                "confidence": (
                    float(row["confidence"]) if row["confidence"] is not None else None
                ),
                "reversibility": row["reversibility"],
                "rejection_reason": row["rejection_reason"],
                "second_approver": row["second_approver"],
                "workflow_run_id": row["workflow_run_id"],
                "verify_status": row["verify_status"],
                "reverse_of": row["reverse_of"],
                "parameters": _json(row["parameters"]),
            },
        )


def build_sources(
    cfg: AuditExportConfig,
    session_scope: Optional[SessionScope],
    spool: Optional[AuthSpool],
    *,
    clock: Clock = _now,
) -> list[Source]:
    sources: list[Source] = []
    on = set(cfg.sources.enabled())
    db = {"settle_s": cfg.settle_s, "clock": clock}
    if session_scope is not None:
        if "agent_events" in on:
            sources.append(
                AgentEventsSource(session_scope, kinds=cfg.agent_event_kinds, **db)
            )
        if "approvals" in on:
            sources.extend(
                ApprovalTransitionSource(t, session_scope, **db)
                for t in APPROVAL_TRANSITIONS
            )
        if "config" in on:
            sources.append(ConfigAuditSource(session_scope, **db))
        if "case_audit" in on:
            sources.append(CaseAuditSource(session_scope, **db))
        if "audit_checkpoints" in on:
            sources.append(AuditCheckpointSource(session_scope, **db))
    if "auth" in on and spool is not None:
        sources.append(AuthSpoolSource(spool))
    return sources


# ---------------------------------------------------------------------------
# Pipeline: one destination, its sources, a bounded queue
# ---------------------------------------------------------------------------


@dataclass
class PipelineMetrics:
    events_read: int = 0
    events_sent: int = 0
    events_dropped: int = 0
    batches_sent: int = 0
    delivery_failures: int = 0
    source_errors: int = 0
    redactions: int = 0
    queue_depth: int = 0
    queue_max: int = 0
    cursor_commit_failures: int = 0
    # Delivered, but the cursor could not be saved: the sender holds and
    # retries the commit (never the batch) until it lands.
    commit_stalled: bool = False
    last_success_at: Optional[str] = None
    last_error: Optional[str] = None
    last_error_at: Optional[str] = None
    sent_by_source: dict = field(default_factory=dict)
    last_event_at_by_source: dict = field(default_factory=dict)

    def snapshot(self) -> dict:
        return {
            k: (dict(v) if isinstance(v, dict) else v) for k, v in self.__dict__.items()
        }


@dataclass
class _Item:
    source: str
    event: AuditEvent
    cursor: dict


Sleep = Callable[[float], Any]


class Pipeline:
    """Read sources into a bounded queue; deliver in batches; commit cursors.

    The reader's cursors run ahead of the committed ones. Only the sender
    commits, and only after the destination accepted a batch, so whatever
    is queued or in flight when the process stops is read again next start.
    """

    def __init__(
        self,
        *,
        destination: str,
        transport: Transport,
        sources: list[Source],
        cursors: FileCursorStore,
        cfg: AuditExportConfig,
        redactor: Redactor,
        rng: Optional[random.Random] = None,
        on_dead: Optional[Callable[[], None]] = None,
    ) -> None:
        self.destination = destination
        self.on_dead = on_dead
        self.transport = transport
        self.sources = sources
        self.cursors = cursors
        self.cfg = cfg
        self.redactor = redactor
        self.metrics = PipelineMetrics(queue_max=cfg.queue_max)
        self._rng = rng or random.Random()
        self._queue: asyncio.Queue[_Item] = asyncio.Queue(maxsize=cfg.queue_max)
        self._stop = asyncio.Event()
        self._tasks: list[asyncio.Task] = []
        self.backoff_base_s = 0.5

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        self._tasks = [
            asyncio.create_task(
                self._read_loop(), name=f"audit-read-{self.destination}"
            ),
            asyncio.create_task(
                self._send_loop(), name=f"audit-send-{self.destination}"
            ),
        ]
        for task in self._tasks:
            task.add_done_callback(self._task_done)

    def _task_done(self, task: asyncio.Task) -> None:
        """A reader or sender that ends while not stopping is a dead pipeline:
        log why and ask the supervisor to restart it now."""
        if self._stop.is_set():
            return
        exc = None if task.cancelled() else task.exception()
        self._error(f"task_died:{task.get_name().split('-')[1]}")
        logger.error(
            "audit export: %s ended unexpectedly (%s); restarting",
            task.get_name(),
            type(exc).__name__ if exc else "no error",
        )
        if self.on_dead is not None:
            with contextlib.suppress(Exception):
                self.on_dead()

    async def stop(self, grace_s: float = 5.0) -> None:
        """Stop reading at once; give the sender ``grace_s`` to commit the
        cursor of a batch the destination already accepted (otherwise that
        batch is simply sent again on the next start)."""
        self._stop.set()
        tasks, self._tasks = self._tasks, []
        for task in tasks:
            if task.get_name().startswith("audit-read-"):
                task.cancel()
        pending = [t for t in tasks if not t.done()]
        if pending:
            _, still = await asyncio.wait(pending, timeout=grace_s)
            for task in still:
                task.cancel()
        for task in tasks:
            with contextlib.suppress(BaseException):
                await task
        await self.transport.close()

    @property
    def running(self) -> bool:
        """Both the reader and the sender are alive.

        One without the other is a stalled pipeline (a dead sender leaves the
        reader blocked on a full queue forever), so the supervisor restarts
        it; the uncommitted queue is simply read again.
        """
        return len(self._tasks) == 2 and all(not t.done() for t in self._tasks)

    async def _wait(self, seconds: float) -> bool:
        """Sleep, returning True early if the pipeline is stopping."""
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=max(0.0, seconds))
            return True
        except asyncio.TimeoutError:
            return False

    def _error(self, reason: str) -> None:
        self.metrics.last_error = reason
        self.metrics.last_error_at = iso_utc(_now())

    # -- reading ----------------------------------------------------------

    async def _start_cursor(self, source: Source) -> dict:
        cursor = await asyncio.to_thread(
            self.cursors.get, self.destination, source.name
        )
        if cursor is None:
            cursor = await asyncio.to_thread(source.initial_cursor, self.cfg.start_from)
            # Pinned at once: "now" must mean the first enable, not each restart.
            await asyncio.to_thread(
                self.cursors.commit, self.destination, source.name, cursor
            )
        return cursor

    async def _read_loop(self) -> None:
        read_at: dict[str, dict] = {}
        backoff: dict[str, float] = {}
        while not self._stop.is_set():
            produced = 0
            for source in self.sources:
                if self._stop.is_set():
                    return
                if backoff.get(source.name, 0) > time.monotonic():
                    continue
                try:
                    if source.name not in read_at:
                        read_at[source.name] = await self._start_cursor(source)
                    rows = await asyncio.to_thread(
                        source.fetch, read_at[source.name], self.cfg.batch_size
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001 - keep the other sources going
                    self.metrics.source_errors += 1
                    self._error(f"source_failed:{source.name}")
                    logger.warning(
                        "audit export: reading %s failed (%s)",
                        source.name,
                        type(exc).__name__,
                    )
                    backoff[source.name] = time.monotonic() + min(
                        self.cfg.max_backoff_s, max(1.0, self.cfg.poll_interval_s)
                    )
                    continue
                if rows:
                    # Scrubbing is CPU-bound pattern work: a batch of large
                    # fields would stall every other coroutine of the API
                    # process, so it runs in a worker thread. Only this loop
                    # uses this pipeline's redactor.
                    before = self.redactor.count
                    scrubbed = await asyncio.to_thread(
                        self.redactor.events, [event for event, _ in rows]
                    )
                    self.metrics.redactions += self.redactor.count - before
                else:
                    scrubbed = []
                for (_, cursor), safe in zip(rows, scrubbed):
                    # Blocks while the queue is full: backpressure on reading.
                    await self._queue.put(_Item(source.name, safe, cursor))
                    self.metrics.queue_depth = self._queue.qsize()
                    read_at[source.name] = cursor
                    self.metrics.events_read += 1
                    produced += 1
            if produced == 0 and await self._wait(self.cfg.poll_interval_s):
                return

    # -- sending ----------------------------------------------------------

    async def _next_batch(self) -> list[_Item]:
        while not self._stop.is_set():
            try:
                first = await asyncio.wait_for(self._queue.get(), timeout=0.5)
                break
            except asyncio.TimeoutError:
                continue
        else:
            return []
        batch = [first]
        while len(batch) < self.cfg.batch_size:
            try:
                batch.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        self.metrics.queue_depth = self._queue.qsize()
        return batch

    def _delay(self, attempt: int, retry_after: Optional[float]) -> float:
        cap = min(self.cfg.max_backoff_s, self.backoff_base_s * (2 ** min(attempt, 20)))
        delay = self._rng.uniform(cap / 2, cap)  # jittered
        if retry_after is not None:
            delay = max(delay, min(retry_after, self.cfg.max_backoff_s))
        return delay

    async def _deliver(self, items: list[_Item]) -> bool:
        """Send ``items`` until accepted; False only if stopping first."""
        attempt = 0
        events = [i.event for i in items]
        while not self._stop.is_set():
            try:
                await self.transport.send(events)
                return True
            except BatchTooLarge:
                if len(items) > 1:
                    mid = len(items) // 2
                    return await self._deliver(items[:mid]) and await self._deliver(
                        items[mid:]
                    )
                if events[0].details != {"_truncated": True}:
                    events = [replace(events[0], details={"_truncated": True})]
                    continue
                # One event the receiver will never take: dropping it beats
                # stalling every event behind it forever.
                self.metrics.events_dropped += 1
                self._error("event_too_large")
                logger.error(
                    "audit export: %s refused %s as too large; dropped",
                    self.destination,
                    events[0].id,
                )
                return True
            except DeliveryError as exc:
                attempt += 1
                self.metrics.delivery_failures += 1
                self._error(exc.reason)
                if attempt in (1, 10) or attempt % 100 == 0:
                    logger.warning(
                        "audit export: delivery to %s failed (%s), attempt %d",
                        self.destination,
                        exc.reason,
                        attempt,
                    )
                if await self._wait(self._delay(attempt, exc.retry_after)):
                    return False
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - a bug must not drop events
                attempt += 1
                self.metrics.delivery_failures += 1
                self._error("internal_error")
                logger.exception(
                    "audit export: unexpected %s delivering to %s",
                    type(exc).__name__,
                    self.destination,
                )
                if await self._wait(self._delay(attempt, None)):
                    return False
        return False

    async def _commit(self, last: dict[str, _Item]) -> bool:
        """Save the cursors of a delivered batch, retrying with backoff.

        A failing commit (disk full, read-only volume) must not kill the
        sender: a restart would re-read and re-send the same batch, and a
        commit that keeps failing turned that into a tight re-delivery loop.
        Instead the sender holds here, retries only the commit, and reports
        ``commit_stalled`` / ``cursor_commit_failures`` until it lands. False
        only if stopping first.
        """
        pending = dict(last)
        attempt = 0
        while pending:
            source, item = next(iter(pending.items()))
            try:
                await asyncio.to_thread(
                    self.cursors.commit, self.destination, source, item.cursor
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - hold, do not re-send
                attempt += 1
                self.metrics.cursor_commit_failures += 1
                self.metrics.commit_stalled = True
                self._error("cursor_commit_failed")
                if attempt in (1, 10) or attempt % 100 == 0:
                    logger.error(
                        "audit export: delivered to %s but saving the %s cursor "
                        "failed (%s), attempt %d; holding",
                        self.destination,
                        source,
                        type(exc).__name__,
                        attempt,
                    )
                if await self._wait(self._delay(attempt, None)):
                    return False
                continue
            del pending[source]
            self.metrics.last_event_at_by_source[source] = iso_utc(item.event.timestamp)
        self.metrics.commit_stalled = False
        return True

    async def _send_loop(self) -> None:
        while not self._stop.is_set():
            batch = await self._next_batch()
            if not batch:
                continue
            if not await self._deliver(batch):
                return  # stopping; nothing committed, re-read next start
            last: dict[str, _Item] = {}
            for item in batch:
                last[item.source] = item
                self.metrics.sent_by_source[item.source] = (
                    self.metrics.sent_by_source.get(item.source, 0) + 1
                )
            if not await self._commit(last):
                return  # stopping; the batch is re-read (and re-sent) next start
            self.metrics.events_sent += len(batch)
            self.metrics.batches_sent += 1
            self.metrics.last_success_at = iso_utc(_now())


# ---------------------------------------------------------------------------
# Leadership: one exporter per deployment
# ---------------------------------------------------------------------------


class PgAdvisoryLeader:
    """A session-level Postgres advisory lock held on a dedicated connection.

    Every backend process runs the supervisor; only the holder exports. If the
    connection drops, so does the lock, and :meth:`alive` notices.
    """

    KEY = 8_274_136

    def __init__(self, engine_getter: Callable[[], Any]) -> None:
        self._engine_getter = engine_getter
        self._conn: Any = None

    def acquire(self) -> bool:
        if self._conn is not None:
            return True
        engine = self._engine_getter()
        if engine is None:
            return False
        conn = engine.connect()
        try:
            got = conn.execute(
                text("SELECT pg_try_advisory_lock(:k)"), {"k": self.KEY}
            ).scalar()
            conn.commit()
        except Exception:
            conn.close()
            raise
        if got:
            self._conn = conn
            return True
        conn.close()
        return False

    def alive(self) -> bool:
        if self._conn is None:
            return False
        try:
            self._conn.execute(text("SELECT 1"))
            self._conn.commit()
            return True
        except Exception:  # noqa: BLE001 - a dead connection means a lost lock
            self.release()
            return False

    def release(self) -> None:
        conn, self._conn = self._conn, None
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": self.KEY})
                conn.commit()
            with contextlib.suppress(Exception):
                conn.close()


class LocalLeader:
    """Always the leader: single-process deployments and tests."""

    def acquire(self) -> bool:
        return True

    def alive(self) -> bool:
        return True

    def release(self) -> None:
        return None


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class ConfigStore(ABC):
    @abstractmethod
    def load(self) -> Optional[dict]: ...

    @abstractmethod
    def save(self, value: dict, actor: str) -> None: ...


class SystemConfigStore(ConfigStore):
    """``system_config['compliance.audit_export']`` through ConfigService.

    Writes go through ConfigService so each change lands in
    ``config_audit_log`` with the admin's name — and is itself exported.
    """

    def load(self) -> Optional[dict]:
        from core.storage.config_service import get_config_service

        return get_config_service(user_id="audit-export").read_system_config(CONFIG_KEY)

    def save(self, value: dict, actor: str) -> None:
        from core.storage.config_service import get_config_service

        ok = get_config_service(user_id=actor).set_system_config(
            CONFIG_KEY,
            value,
            description="Audit stream export to a customer SIEM",
            config_type="compliance",
            change_reason="audit export configuration",
        )
        if not ok:
            raise RuntimeError("audit export config was not saved")


def _default_host() -> str:
    return socket.gethostname() or "autosecops"


class AuditExportService:
    """Owns the auth spool, the cursors and one pipeline per destination.

    Constructed in the API lifespan (``app.state.audit_export``). A supervisor
    task re-reads the config every ``refresh_s`` (or at once after a write
    through the admin API), takes leadership, and (re)starts pipelines when the
    config changes. Disabled, it holds no lock, runs no pipeline and writes
    nothing to disk.
    """

    def __init__(
        self,
        *,
        state_dir: Path,
        config_store: ConfigStore,
        secrets: SecretGetter,
        session_scope: Optional[SessionScope] = None,
        leader: Any = None,
        host: Optional[str] = None,
        refresh_s: float = 15.0,
        clock: Clock = _now,
    ) -> None:
        self.state_dir = state_dir
        self.config_store = config_store
        self.secrets = secrets
        self.session_scope = session_scope
        self.leader = leader or LocalLeader()
        self.host = host or _default_host()
        self.refresh_s = refresh_s
        self.clock = clock
        self.cursors = FileCursorStore(state_dir / "cursors.json")
        self.spool = AuthSpool(
            state_dir / "auth_spool",
            max_bytes=AuditExportConfig().spool_max_bytes,
        )
        self.config = AuditExportConfig()
        self.config_error: Optional[str] = None
        self.is_leader = False
        self.pipelines: dict[str, Pipeline] = {}
        self._fingerprint: Optional[str] = None
        self._spool_enabled = False
        self._task: Optional[asyncio.Task] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._wake: Optional[asyncio.Event] = None
        self._lock = asyncio.Lock()
        self._id_key: Optional[bytes] = None
        # Restarts of dead pipelines (as opposed to config changes): spaced by
        # a jittered exponential backoff so a pipeline that dies at once on
        # every start cannot spin.
        self.restart_base_s = 1.0
        self.restart_cap_s = 300.0
        self.restarts = 0  # total, for metrics
        # Per destination: only the pipeline that died is restarted, and its
        # backoff is its own (a healthy destination is never interrupted).
        self._consecutive_restarts: dict[str, int] = {}
        self._restart_not_before: dict[str, float] = {}
        self._started_at: dict[str, float] = {}
        self._restart_timer: Optional[asyncio.TimerHandle] = None
        self._rng = random.Random()
        # Export horizon (Postgres): see probe_xid_horizon.
        self.horizon: Optional[dict] = None
        self._horizon_xmin: Optional[int] = None
        self._horizon_since = 0.0

    # -- recording (request path) -----------------------------------------

    @property
    def spool_enabled(self) -> bool:
        return self._spool_enabled

    def record_auth(self, action: str, **fields: Any) -> bool:
        """Spool one auth event. Never raises; a no-op while export is off."""
        if not self._spool_enabled:
            return False
        try:
            return self.spool.append(auth_record(action, **fields))
        except Exception as exc:  # noqa: BLE001 - auditing must not break login
            logger.warning(
                "audit export: could not spool an auth event (%s)", type(exc).__name__
            )
            return False

    def identifier_digest(self, value: str) -> str:
        """HMAC-SHA256 of an unauthenticated identifier, keyed per install.

        The key lives in the state directory (0600) and never leaves it, so a
        SIEM reader cannot confirm a guessed password against the digest.
        """
        key = self._identifier_key()
        return hmac.new(key, value.encode("utf-8", "replace"), "sha256").hexdigest()[
            :24
        ]

    def _identifier_key(self) -> bytes:
        if self._id_key is None:
            path = self.state_dir / "identifier.key"
            try:
                self._id_key = path.read_bytes()
            except FileNotFoundError:
                self.state_dir.mkdir(parents=True, exist_ok=True)
                fd, tmp = tempfile.mkstemp(prefix=".identifier-", dir=self.state_dir)
                try:
                    with os.fdopen(fd, "wb") as fh:  # mkstemp: mode 0600
                        fh.write(os.urandom(32))
                        fh.flush()
                        os.fsync(fh.fileno())
                    try:
                        os.link(tmp, path)  # atomic; never a half-written key
                    except FileExistsError:
                        pass  # another process won the race: use its key
                finally:
                    os.unlink(tmp)
                self._id_key = path.read_bytes()
        return self._id_key

    # -- config -----------------------------------------------------------

    def load_config(self) -> AuditExportConfig:
        raw = self.config_store.load()
        return AuditExportConfig.model_validate(raw) if raw else AuditExportConfig()

    def _adopt(self, cfg: AuditExportConfig) -> None:
        self.config = cfg
        self.spool.max_bytes = cfg.spool_max_bytes
        self._spool_enabled = cfg.enabled and cfg.sources.auth

    def save_config(self, cfg: AuditExportConfig, actor: str) -> None:
        self.config_store.save(cfg.model_dump(mode="json"), actor)
        self._adopt(cfg)
        self.wake()

    def wake(self) -> None:
        """Ask the supervisor to re-read the config now (any thread)."""
        loop, event = self._loop, self._wake
        if loop is not None and event is not None and not loop.is_closed():
            loop.call_soon_threadsafe(event.set)

    # -- lifecycle --------------------------------------------------------

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._wake = asyncio.Event()
        register_metrics(self)
        self._task = asyncio.create_task(self._supervise(), name="audit-export")

    async def stop(self) -> None:
        if self._restart_timer is not None:
            self._restart_timer.cancel()
            self._restart_timer = None
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            with contextlib.suppress(BaseException):
                await task
        await self._stop_pipelines()
        await asyncio.to_thread(self.leader.release)
        self.is_leader = False

    async def _supervise(self) -> None:
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - the supervisor must survive
                logger.warning("audit export: supervisor tick failed (%s)", exc)
            assert self._wake is not None
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._wake.wait(), timeout=self.refresh_s)
            self._wake.clear()

    async def tick(self) -> None:
        async with self._lock:
            try:
                cfg = await asyncio.to_thread(self.load_config)
                self.config_error = None
            except Exception as exc:  # noqa: BLE001 - keep the last good config
                self.config_error = type(exc).__name__
                logger.warning("audit export: config unreadable (%s)", exc)
                cfg = self.config
            self._adopt(cfg)
            if not cfg.enabled:
                await self._stop_pipelines()
                if self.is_leader:
                    await asyncio.to_thread(self.leader.release)
                    self.is_leader = False
                return
            if self.is_leader and not await asyncio.to_thread(self.leader.alive):
                self.is_leader = False
                await self._stop_pipelines()
            if not self.is_leader:
                try:
                    self.is_leader = await asyncio.to_thread(self.leader.acquire)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("audit export: leader lock failed (%s)", exc)
                    self.is_leader = False
                if not self.is_leader:
                    return
            if self._fingerprint != cfg.fingerprint():
                self._consecutive_restarts.clear()
                self._restart_not_before.clear()
                await self._stop_pipelines()
                self._start_pipelines(cfg)
            else:
                dead = [n for n, p in self.pipelines.items() if not p.running]
                if dead:
                    await self._restart_dead(cfg, dead)
                now = time.monotonic()
                for name, pipeline in self.pipelines.items():
                    if (
                        self._consecutive_restarts.get(name)
                        and pipeline.running
                        and now - self._started_at.get(name, now)
                        >= self._restart_cap(cfg)
                    ):
                        # healthy long enough: forgive
                        self._consecutive_restarts[name] = 0
            await asyncio.to_thread(self._prune_spool)
            await self._check_horizon(cfg)

    def _restart_cap(self, cfg: AuditExportConfig) -> float:
        return max(self.restart_base_s, min(self.restart_cap_s, cfg.max_backoff_s))

    def restart_delay(self, n: int, cfg: Optional[AuditExportConfig] = None) -> float:
        """Jittered delay before the ``n``-th consecutive restart (n >= 1)."""
        cap = self._restart_cap(cfg or self.config)
        ceiling = min(cap, self.restart_base_s * (2 ** min(n - 1, 20)))
        return self._rng.uniform(ceiling / 2, ceiling)

    async def _restart_dead(self, cfg: AuditExportConfig, dead: list[str]) -> None:
        """Restart the dead destinations' pipelines, and only those: the
        others keep running (no re-read, no reconnect)."""
        now = time.monotonic()
        dests = {d.name: d for d in cfg.destinations}
        waits: list[float] = []
        for name in dead:
            not_before = self._restart_not_before.get(name, 0.0)
            if now < not_before:
                waits.append(not_before - now)
                continue
            n = self._consecutive_restarts.get(name, 0) + 1
            self._consecutive_restarts[name] = n
            self.restarts += 1
            delay = self.restart_delay(n, cfg)
            self._restart_not_before[name] = now + delay
            waits.append(delay)
            logger.warning(
                "audit export: restarting dead pipeline %s (restart %d in a row; "
                "next no sooner than %.1fs)",
                name,
                n,
                delay,
            )
            pipeline = self.pipelines.pop(name, None)
            if pipeline is not None:
                await pipeline.stop()
            if name in dests:
                self._start_pipeline(cfg, dests[name])
        if waits:
            self._schedule_wake(min(waits))

    def _schedule_wake(self, delay: float) -> None:
        if self._loop is None or self._loop.is_closed():
            return
        if self._restart_timer is not None:
            self._restart_timer.cancel()
        self._restart_timer = self._loop.call_later(max(0.0, delay), self.wake)

    def _start_pipeline(self, cfg: AuditExportConfig, dest: Any) -> None:
        self._started_at[dest.name] = time.monotonic()
        pipeline = Pipeline(
            destination=dest.name,
            transport=build_transport(dest, self.secrets, self.host),
            sources=build_sources(
                cfg, self.session_scope, self.spool, clock=self.clock
            ),
            cursors=self.cursors,
            cfg=cfg,
            redactor=Redactor(redact_pii=cfg.redact_pii),
            on_dead=self.wake,
        )
        pipeline.start()
        self.pipelines[dest.name] = pipeline

    def _start_pipelines(self, cfg: AuditExportConfig) -> None:
        for dest in cfg.destinations:
            self._start_pipeline(cfg, dest)
        self._fingerprint = cfg.fingerprint()
        logger.info(
            "audit export: started %d destination(s), sources %s",
            len(cfg.destinations),
            ",".join(cfg.sources.enabled()),
        )

    async def _stop_pipelines(self) -> None:
        pipelines, self.pipelines = self.pipelines, {}
        self._fingerprint = None
        for pipeline in pipelines.values():
            await pipeline.stop()

    async def _check_horizon(self, cfg: AuditExportConfig) -> None:
        """Flag export lag from a transaction holding the xid horizon."""
        if self.session_scope is None or not any(
            name != "auth" for name in cfg.sources.enabled()
        ):
            self.horizon = None
            return
        try:
            probe = await asyncio.to_thread(self._probe_horizon)
        except Exception as exc:  # noqa: BLE001 - a health probe must not stop export
            logger.debug("audit export: horizon probe failed (%s)", exc)
            return
        self.horizon = self.assess_horizon(probe, cfg.horizon_alert_s)

    def _probe_horizon(self) -> Optional[dict]:
        assert self.session_scope is not None
        with self.session_scope() as session:
            return probe_xid_horizon(session)

    def assess_horizon(
        self, probe: Optional[dict], alert_s: float, *, now: Optional[float] = None
    ) -> Optional[dict]:
        """Turn a probe into the ``horizon`` status block.

        ``held_s`` is how long the horizon has stood still while newer
        transactions exist (everything they wrote is waiting on it). The
        holder's own transaction age is used when visible, so the flag is
        right on the first probe after a restart too.
        """
        if probe is None:
            return None
        now = time.monotonic() if now is None else now
        xmin, xmax = int(probe["xmin"]), int(probe["xmax"])
        holder = probe.get("holder")
        if xmin != self._horizon_xmin:
            self._horizon_xmin, self._horizon_since = xmin, now
        # ``xmax`` is one past the latest *completed* transaction, so a
        # running transaction need not show as ``xmin < xmax``; but when it
        # does, something committed after the horizon and is waiting on it.
        waiting = xmax > xmin
        if not waiting and holder is None:
            self._horizon_since = now  # nothing running and nothing waiting
        held = now - self._horizon_since if waiting else 0.0
        if holder is not None:
            held = max(held, float(holder.get("xact_age_s") or 0.0))
        idle = bool(
            holder and str(holder.get("state") or "").startswith("idle in transaction")
        )
        idle_s = float(holder.get("state_age_s") or 0.0) if idle and holder else 0.0
        stalled = held >= alert_s
        reason = None
        if stalled:
            reason = (
                "idle_in_transaction"
                if idle and idle_s >= alert_s
                else "long_running_transaction"
            )
        if stalled and not (self.horizon or {}).get("stalled"):  # on transition
            logger.warning(
                "audit export: export horizon held for %.0fs by %s (pid %s, %s); "
                "Postgres events after it are waiting",
                held,
                reason,
                holder.get("pid") if holder else "?",
                holder.get("database") if holder else "another session",
            )
        return {
            "xmin": xmin,
            "held_s": round(held, 1),
            "alert_s": alert_s,
            "stalled": stalled,
            "reason": reason,
            "idle_in_transaction": idle,
            "holder": holder,
        }

    def _prune_spool(self) -> None:
        if not self.config.sources.auth or not self.spool.directory.is_dir():
            return
        segments = []
        for dest in self.config.destinations:
            cursor = self.cursors.get(dest.name, "auth")
            if cursor is None:
                return  # a destination that has not started reading keeps all
            segments.append(int(cursor.get("segment", 1)))
        if segments:
            self.spool.prune(min(segments))

    # -- admin ------------------------------------------------------------

    async def test_destination(self, name: str) -> dict:
        """Send one synthetic event to a configured destination."""
        dest = next((d for d in self.config.destinations if d.name == name), None)
        if dest is None:
            return {"ok": False, "error": "unknown_destination"}
        transport = build_transport(dest, self.secrets, self.host)
        event = AuditEvent(
            id=f"test:{uuid.uuid4()}",
            source="test",
            category="test",
            action="audit_export.test",
            outcome="success",
            severity=1,
            timestamp=self.clock(),
            message="AutoSecOps audit export test event",
        )
        try:
            await asyncio.wait_for(transport.send([event]), timeout=dest.timeout_s * 2)
            return {"ok": True, "error": None, "event_id": event.id}
        except DeliveryError as exc:
            return {"ok": False, "error": exc.reason}
        except asyncio.TimeoutError:
            return {"ok": False, "error": "timeout"}
        finally:
            await transport.close()

    def status(self) -> dict:
        cursors = {}
        try:
            cursors = self.cursors.all() if self.cursors.path.exists() else {}
        except RuntimeError:
            cursors = {"_error": "cursor_file_unreadable"}
        destinations = []
        for dest in self.config.destinations:
            pipeline = self.pipelines.get(dest.name)
            insecure = []
            if isinstance(dest, SyslogDestination) and dest.protocol != "tls":
                insecure.append(f"plaintext_{dest.protocol}")
            if isinstance(dest, HttpDestination) and dest.url.startswith("http:"):
                insecure.append("plaintext_http")
            if not dest.tls_verify:
                insecure.append("tls_verify_off")
            metrics = pipeline.metrics.snapshot() if pipeline else None
            if pipeline is not None and metrics is not None:
                metrics["queue_depth"] = pipeline._queue.qsize()
            destinations.append(
                {
                    "name": dest.name,
                    "type": dest.type,
                    "format": dest.format,
                    "running": bool(pipeline and pipeline.running),
                    "insecure": insecure,
                    "metrics": metrics,
                    "cursors": {
                        k.split("/", 1)[1]: v
                        for k, v in cursors.items()
                        if k.startswith(f"{dest.name}/")
                    },
                }
            )
        return {
            "enabled": self.config.enabled,
            "leader": self.is_leader,
            "config_error": self.config_error,
            "sources": self.config.sources.enabled(),
            "spool": {
                "enabled": self._spool_enabled,
                "bytes": self.spool.size() if self.spool.directory.is_dir() else 0,
                "max_bytes": self.spool.max_bytes,
                "written": self.spool.written,
                "dropped": self.spool.dropped,
            },
            "destinations": destinations,
            "restarts": self.restarts,
            "horizon": self.horizon,
        }


def audit_export_on(request: Any) -> bool:
    """Whether auth events are being spooled (cheap; for guarding lookups)."""
    try:
        service = getattr(request.app.state, "audit_export", None)
        return bool(service is not None and service.spool_enabled)
    except Exception:  # noqa: BLE001 - no app state means no export
        return False


def failed_login_fields(request: Any, identifier: Any, session: Any) -> dict:
    """``actor`` fields for a failed login, without leaking what was typed.

    A failed login's identifier is unauthenticated input and is often a
    password typed into the wrong box. If it names an existing account, the
    account's username (and id) is exported; otherwise only a keyed digest
    (stable per installation, so repeated attempts correlate in the SIEM, but
    not reversible by guessing) and its length.
    """
    raw = "" if identifier is None else str(identifier)[:512]
    try:
        from core.storage.models import User

        user = (
            session.query(User)
            .filter((User.username == raw) | (User.email == raw))
            .first()
        )
        if user is not None:
            return {"actor": user.username, "actor_id": user.user_id}
    except Exception as exc:  # noqa: BLE001 - fall back to the digest
        logger.debug("audit export: login identifier lookup failed (%s)", exc)
    service = getattr(getattr(request, "app", None), "state", None)
    service = getattr(service, "audit_export", None)
    digest = (
        service.identifier_digest(raw)
        if service is not None
        else hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]
    )
    return {
        "actor": None,
        "details": {
            "unknown_identifier": True,
            "identifier_digest": digest,
            "identifier_length": len(raw),
        },
    }


async def arecord_auth_event(request: Any, action: str, **fields: Any) -> None:
    """:func:`record_auth_event` for ``async def`` handlers.

    The spool write takes an ``flock`` and ``fsync``s; both block, so they run
    in a worker thread instead of on the event loop. Never raises.
    """
    if request is None or not audit_export_on(request):
        return
    try:
        await asyncio.to_thread(record_auth_event, request, action, **fields)
    except Exception as exc:  # noqa: BLE001 - auditing must not break the request
        logger.warning("audit export: auth hook failed (%s)", type(exc).__name__)


def record_auth_event(request: Any, action: str, **fields: Any) -> None:
    """Spool an auth event from a request handler. Never raises.

    Reads the service from ``request.app.state.audit_export`` (absent in tools
    and some tests: then a no-op) and fills the client address and user agent.
    """
    if request is None:
        return
    try:
        service = getattr(request.app.state, "audit_export", None)
        if service is None or not service.spool_enabled:
            return
        client = getattr(request, "client", None)
        fields.setdefault("src_ip", getattr(client, "host", None))
        fields.setdefault("user_agent", request.headers.get("user-agent"))
        service.record_auth(action, **fields)
    except Exception as exc:  # noqa: BLE001 - auditing must not break the request
        logger.warning("audit export: auth hook failed (%s)", type(exc).__name__)


# ---------------------------------------------------------------------------
# Prometheus
# ---------------------------------------------------------------------------

_METRIC_PREFIX = "autosecops_audit_export"


class _Collector:
    def __init__(self, service: AuditExportService) -> None:
        self.service = service

    def describe(self):
        from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily

        for name in (
            "enabled",
            "leader",
            "queue_depth",
            "last_success_timestamp_seconds",
            "xid_horizon_held_seconds",
            "xid_horizon_stalled",
            "cursor_commit_stalled",
        ):
            yield GaugeMetricFamily(f"{_METRIC_PREFIX}_{name}", name)
        for name in (
            "spool_dropped",
            "events_sent",
            "delivery_failures",
            "events_dropped",
            "pipeline_restarts",
            "cursor_commit_failures",
        ):
            yield CounterMetricFamily(f"{_METRIC_PREFIX}_{name}", name)

    def collect(self):
        from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily

        svc = self.service
        enabled = GaugeMetricFamily(
            f"{_METRIC_PREFIX}_enabled", "1 when audit export is enabled."
        )
        enabled.add_metric([], 1.0 if svc.config.enabled else 0.0)
        yield enabled
        leader = GaugeMetricFamily(
            f"{_METRIC_PREFIX}_leader", "1 when this process is the exporter."
        )
        leader.add_metric([], 1.0 if svc.is_leader else 0.0)
        yield leader
        dropped = CounterMetricFamily(
            f"{_METRIC_PREFIX}_spool_dropped",
            "Auth events dropped because the spool was full.",
        )
        dropped.add_metric([], float(svc.spool.dropped))
        yield dropped
        sent = CounterMetricFamily(
            f"{_METRIC_PREFIX}_events_sent",
            "Events accepted by a destination.",
            labels=["destination", "source"],
        )
        failures = CounterMetricFamily(
            f"{_METRIC_PREFIX}_delivery_failures",
            "Failed delivery attempts (each is retried).",
            labels=["destination"],
        )
        drops = CounterMetricFamily(
            f"{_METRIC_PREFIX}_events_dropped",
            "Single events a destination refused as too large.",
            labels=["destination"],
        )
        depth = GaugeMetricFamily(
            f"{_METRIC_PREFIX}_queue_depth",
            "Events read and waiting for delivery.",
            labels=["destination"],
        )
        last = GaugeMetricFamily(
            f"{_METRIC_PREFIX}_last_success_timestamp_seconds",
            "Unix time of the last accepted batch.",
            labels=["destination"],
        )
        horizon = svc.horizon or {}
        held = GaugeMetricFamily(
            f"{_METRIC_PREFIX}_xid_horizon_held_seconds",
            "Postgres: how long the oldest running transaction has held the "
            "export horizon (export lag it causes).",
        )
        held.add_metric([], float(horizon.get("held_s") or 0.0))
        stalled = GaugeMetricFamily(
            f"{_METRIC_PREFIX}_xid_horizon_stalled",
            "1 when the export horizon has been held longer than horizon_alert_s.",
            labels=["reason"],
        )
        stalled.add_metric(
            [str(horizon.get("reason") or "")], 1.0 if horizon.get("stalled") else 0.0
        )
        restarts = CounterMetricFamily(
            f"{_METRIC_PREFIX}_pipeline_restarts",
            "Dead pipelines restarted (with backoff).",
        )
        restarts.add_metric([], float(svc.restarts))
        commit_failures = CounterMetricFamily(
            f"{_METRIC_PREFIX}_cursor_commit_failures",
            "Failed cursor saves after an accepted batch (retried; never re-sent).",
            labels=["destination"],
        )
        commit_stalled = GaugeMetricFamily(
            f"{_METRIC_PREFIX}_cursor_commit_stalled",
            "1 while a delivered batch's cursor cannot be saved.",
            labels=["destination"],
        )
        yield from (held, stalled, restarts)
        for name, pipeline in list(svc.pipelines.items()):
            m = pipeline.metrics
            commit_failures.add_metric([name], float(m.cursor_commit_failures))
            commit_stalled.add_metric([name], 1.0 if m.commit_stalled else 0.0)
            for source, count in m.sent_by_source.items():
                sent.add_metric([name, source], float(count))
            failures.add_metric([name], float(m.delivery_failures))
            drops.add_metric([name], float(m.events_dropped))
            depth.add_metric([name], float(pipeline._queue.qsize()))
            if m.last_success_at:
                last.add_metric([name], as_utc(m.last_success_at).timestamp())
        yield from (sent, failures, drops, depth, last, commit_failures, commit_stalled)


def register_metrics(service: AuditExportService) -> None:
    from prometheus_client import REGISTRY

    marker = f"{_METRIC_PREFIX}_enabled"
    previous = REGISTRY._names_to_collectors.get(marker)
    if previous is not None:
        REGISTRY.unregister(previous)
    REGISTRY.register(_Collector(service))
