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
========================  ==================================================

How it leaves: RFC 5424 syslog over TLS (RFC 5425 octet-counting framing), or
over plain TCP/UDP for labs, with structured data; or HTTPS POST of JSON or CEF.

Delivery is **at-least-once**. Each (destination, source) pair has a durable
cursor that is committed only after the destination accepted the batch, so a
restart re-reads whatever was in flight; every event carries a stable ``id``
for the receiver to deduplicate on. A failed delivery is retried with capped,
jittered exponential backoff and never dropped; the reader feeds a bounded
queue, so a dead receiver stalls reading instead of growing memory.

Off by default: with no ``compliance.audit_export`` system config, or with
``enabled: false``, nothing is spooled, no state directory is created and no
connection is opened. The field mapping and operator notes are in
``core/compliance/AUDIT_EXPORT.md``.
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import hashlib
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
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import DateTime, Integer, String, bindparam, text
from sqlalchemy.orm import Session

from core.telemetry_sanitizer import _SECRET_VALUE_PATTERNS, SensitiveAttributeScrubber
from core.version import __version__

logger = logging.getLogger(__name__)

CONFIG_KEY = "compliance.audit_export"
SCHEMA = "autosecops.audit.v1"
PRODUCT = "AutoSecOps"
APP_NAME = "autosecops"
# RFC 5612 documentation PEN: a private-use SD-ID that needs no IANA number.
SD_ID = "autosecops@32473"

SOURCE_NAMES = ("agent_events", "approvals", "auth", "config", "case_audit")
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
        description="Rows younger than this are left for the next poll, so a "
        "transaction that commits late is not skipped by the cursor.",
    )
    max_backoff_s: float = Field(60.0, ge=0.1, le=3600)
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


# Cloud metadata and other addresses no SIEM lives at.
_LINK_LOCAL_NAMES = frozenset({"metadata.google.internal", "metadata"})


def _reserved(ip: ipaddress._BaseAddress) -> bool:
    return ip.is_link_local or ip.is_multicast or ip.is_unspecified


def refuse_reserved_literal(host: str) -> None:
    """Refuse a host that is a link-local/metadata address on its face."""
    if host.lower() in _LINK_LOCAL_NAMES:
        raise ValueError("metadata hosts are not a valid destination")
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return
    if _reserved(ip):
        raise ValueError("link-local, multicast or unspecified address refused")


def resolve_egress(host: str, port: int) -> list[str]:
    """Resolve ``host`` and refuse it if any address is link-local or reserved.

    Loopback and private ranges stay allowed: a customer SIEM or a local relay
    usually lives there. The literal check runs at config time; this one runs
    at connect time, so a name that later resolves to the metadata service is
    still refused.
    """
    refuse_reserved_literal(host)
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = []
    for info in infos:
        addr = info[4][0]
        if _reserved(ipaddress.ip_address(addr.split("%")[0])):
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
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PII_KEYS = frozenset(
    {"email", "phone", "full_name", "ssn", "national_id", "tckn", "address"}
)
_KEY_SPLIT = re.compile(r"[._\-]")
# Credentials the span scrubber's list does not name on their own.
_EXTRA_SECRET_SEGMENTS = frozenset(
    {"token", "otp", "mfa_code", "mfa_secret", "recovery_codes", "passphrase"}
)
# The sanitizer's patterns match a secret's start (``sk-ant-``, ``AKIA...``, a
# DSN up to ``@``); a redaction must swallow the rest of that token as well.
_SECRET_TOKENS = [
    re.compile(p.pattern + r"[^\s\"',;]*", p.flags) for p in _SECRET_VALUE_PATTERNS
]
# Our own hash-chain values: hex by design, not a leaked credential.
_VERBATIM_HEX = frozenset({"prev_hash", "event_hash", "hash"})
_HEX = re.compile(r"^[0-9a-fA-F]{32,128}$")


class Redactor:
    """Scrub secrets (and, by default, PII) from what an event carries.

    Reuses ``core.telemetry_sanitizer``: its sensitive key segments and content
    keys redact a value outright, and its secret value patterns (JWTs, API key
    prefixes, DSNs with passwords, long hex tokens, AWS key ids) are cut out of
    free text. Only ``message``, ``details``, ``user_agent`` and ``actor`` are
    scrubbed; ids, hashes and enums are ours and are left alone.
    """

    def __init__(
        self,
        *,
        redact_pii: bool = True,
        max_string: int = 2048,
        max_depth: int = 6,
        max_items: int = 100,
    ) -> None:
        self._scrubber = SensitiveAttributeScrubber()
        self.redact_pii = redact_pii
        self.max_string = max_string
        self.max_depth = max_depth
        self.max_items = max_items
        self.count = 0  # values redacted, for metrics

    def _key_hit(self, path: str) -> bool:
        lowered = path.lower()
        # Ask the span scrubber with a non-secret value: only its key rules fire.
        if self._scrubber._should_redact(lowered, None):
            return True
        leaf = lowered.rsplit(".", 1)[-1]
        segments = set(_KEY_SPLIT.split(lowered))
        if leaf in _EXTRA_SECRET_SEGMENTS or segments & {"token", "otp"}:
            return True
        if self.redact_pii and (leaf in _PII_KEYS or segments & _PII_KEYS):
            return True
        return False

    def text(self, value: str) -> str:
        out = value
        for pattern in _SECRET_TOKENS:
            out = pattern.sub(REDACTED, out)
        if self.redact_pii:
            out = _EMAIL.sub("[REDACTED-EMAIL]", out)
        if out != value:
            self.count += 1
        if len(out) > self.max_string:
            out = out[: self.max_string] + "...[truncated]"
        return out

    def value(self, path: str, value: Any, depth: int = 0) -> Any:
        if path and self._key_hit(path):
            if value is None or value == "" or value == {}:
                return value
            self.count += 1
            return REDACTED
        if depth >= self.max_depth:
            return "[truncated]"
        if isinstance(value, dict):
            out = {}
            for i, (k, v) in enumerate(value.items()):
                if i >= self.max_items:
                    out["_truncated"] = True
                    break
                key = str(k)[:128]
                out[key] = self.value(f"{path}.{key}" if path else key, v, depth + 1)
            return out
        if isinstance(value, (list, tuple)):
            items = [self.value(path, v, depth + 1) for v in value[: self.max_items]]
            if len(value) > self.max_items:
                items.append("[truncated]")
            return items
        if isinstance(value, str):
            leaf = path.rsplit(".", 1)[-1]
            if leaf in _VERBATIM_HEX and _HEX.match(value):
                return value
            return self.text(value)
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return self.text(str(value))

    def event(self, ev: AuditEvent) -> AuditEvent:
        return replace(
            ev,
            message=self.text(ev.message),
            actor=self.text(ev.actor) if ev.actor else ev.actor,
            user_agent=self.text(ev.user_agent) if ev.user_agent else ev.user_agent,
            details=self.value("", ev.details),
        )


# ---------------------------------------------------------------------------
# Formats: JSON, CEF, RFC 5424
# ---------------------------------------------------------------------------


def cef_escape_header(value: Any) -> str:
    """CEF header field: escape ``\\`` and ``|``; a header cannot hold a newline."""
    s = "" if value is None else str(value)
    s = s.replace("\\", "\\\\").replace("|", "\\|")
    return s.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")


def cef_escape_ext(value: Any) -> str:
    """CEF extension value: escape ``\\`` and ``=``, encode CR/LF as ``\\r``/``\\n``."""
    s = "" if value is None else str(value)
    s = s.replace("\\", "\\\\").replace("=", "\\=")
    return s.replace("\r", "\\r").replace("\n", "\\n")


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
    """RFC 5424 §6.3.3 PARAM-VALUE: escape ``"``, ``\\`` and ``]``."""
    s = "" if value is None else str(value)
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


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
            msg = json.dumps(
                event.to_dict(host), separators=(",", ":"), ensure_ascii=False
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
        loop = asyncio.get_running_loop()
        try:
            addresses = await loop.run_in_executor(
                None, resolve_egress, self.dest.host, self.dest.port
            )
        except DeliveryError:
            raise
        except OSError as exc:
            raise DeliveryError("dns_failed") from exc
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
        loop = asyncio.get_running_loop()
        try:
            addresses = await loop.run_in_executor(
                None, resolve_egress, self.dest.host, self.dest.port
            )
        except OSError as exc:
            raise DeliveryError("dns_failed") from exc
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
            json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode(),
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

    async def send(self, events: list[AuditEvent]) -> None:
        parsed = urlparse(self.dest.url)
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(
                None,
                resolve_egress,
                parsed.hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80),
            )
        except OSError as exc:
            raise DeliveryError("dns_failed") from exc
        try:
            client = self._client_for()
        except (ssl.SSLError, ValueError, OSError) as exc:
            raise DeliveryError("tls_config_invalid") from exc
        content, ctype = self.body(events)
        headers = self._headers(events[0].id if len(events) == 1 else _batch_id(events))
        headers["Content-Type"] = ctype
        try:
            response = await client.post(
                self.dest.url, content=content, headers=headers
            )
        except httpx.ConnectError as exc:
            if _is_tls_error(exc):
                raise DeliveryError("tls_handshake_failed") from exc
            raise DeliveryError("connect_failed") from exc
        except httpx.TimeoutException as exc:
            raise DeliveryError("timeout") from exc
        except httpx.HTTPError as exc:
            raise DeliveryError("send_failed") from exc
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


class _DbSource(Source):
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


class _IdSource(_DbSource):
    """A table with an autoincrement id: cursor ``{"id": n}``.

    Rows are read in id order and the read stops at the first row younger than
    the settle window, so a lower id still in an open transaction is not passed.
    """

    table: str
    id_col: str
    ts_col: str = "timestamp"
    columns: str

    def initial_cursor(self, start_from: str) -> dict:
        if start_from == "beginning":
            return {"id": 0}
        with self.session_scope() as session:
            top = session.execute(
                text(f"SELECT MAX({self.id_col}) FROM {self.table}")  # nosec B608
            ).scalar()
        return {"id": int(top or 0)}

    def fetch(self, cursor: dict, limit: int) -> list[tuple[AuditEvent, dict]]:
        stmt = text(
            f"SELECT {self.columns} FROM {self.table} "  # nosec B608 - fixed names
            f"WHERE {self.id_col} > :id ORDER BY {self.id_col} LIMIT :n"
        ).columns(**{self.ts_col: DateTime(), self.id_col: Integer()})
        with self.session_scope() as session:
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


class AgentEventsSource(_DbSource):
    """The agent ledger, keyset-paged on ``(ts, run_id, seq)``.

    Exports the ledger coordinates, kind and hash-chain values, plus the
    payload's top-level scalars (redacted downstream); nested payload content
    (prompts, tool output) stays in AutoSecOps.
    """

    name = "agent_events"

    def __init__(self, *args: Any, kinds: Iterable[str] = (), **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.kinds = sorted(set(kinds))

    def initial_cursor(self, start_from: str) -> dict:
        if start_from == "beginning":
            return {"ts": iso_utc(_EPOCH), "run_id": "", "seq": -1}
        return {"ts": iso_utc(self.cutoff()), "run_id": "", "seq": -1}

    def fetch(self, cursor: dict, limit: int) -> list[tuple[AuditEvent, dict]]:
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
    """One ``approval_actions`` transition, keyset-paged on ``(<col>, action_id)``.

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

    def initial_cursor(self, start_from: str) -> dict:
        start = _EPOCH if start_from == "beginning" else self.cutoff()
        return {"ts": iso_utc(start), "id": ""}

    def fetch(self, cursor: dict, limit: int) -> list[tuple[AuditEvent, dict]]:
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
    ) -> None:
        self.destination = destination
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
        return any(not t.done() for t in self._tasks)

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
                for event, cursor in rows:
                    before = self.redactor.count
                    safe = self.redactor.event(event)
                    self.metrics.redactions += self.redactor.count - before
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
            for source, item in last.items():
                await asyncio.to_thread(
                    self.cursors.commit, self.destination, source, item.cursor
                )
                self.metrics.last_event_at_by_source[source] = iso_utc(
                    item.event.timestamp
                )
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
            if self._fingerprint != cfg.fingerprint() or not all(
                p.running for p in self.pipelines.values()
            ):
                await self._stop_pipelines()
                self._start_pipelines(cfg)
            await asyncio.to_thread(self._prune_spool)

    def _start_pipelines(self, cfg: AuditExportConfig) -> None:
        for dest in cfg.destinations:
            pipeline = Pipeline(
                destination=dest.name,
                transport=build_transport(dest, self.secrets, self.host),
                sources=build_sources(
                    cfg, self.session_scope, self.spool, clock=self.clock
                ),
                cursors=self.cursors,
                cfg=cfg,
                redactor=Redactor(redact_pii=cfg.redact_pii),
            )
            pipeline.start()
            self.pipelines[dest.name] = pipeline
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
        }


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
        ):
            yield GaugeMetricFamily(f"{_METRIC_PREFIX}_{name}", name)
        for name in (
            "spool_dropped",
            "events_sent",
            "delivery_failures",
            "events_dropped",
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
        for name, pipeline in list(svc.pipelines.items()):
            m = pipeline.metrics
            for source, count in m.sent_by_source.items():
                sent.add_metric([name, source], float(count))
            failures.add_metric([name], float(m.delivery_failures))
            drops.add_metric([name], float(m.events_dropped))
            depth.add_metric([name], float(pipeline._queue.qsize()))
            if m.last_success_at:
                last.add_metric([name], as_utc(m.last_success_at).timestamp())
        yield from (sent, failures, drops, depth, last)


def register_metrics(service: AuditExportService) -> None:
    from prometheus_client import REGISTRY

    marker = f"{_METRIC_PREFIX}_enabled"
    previous = REGISTRY._names_to_collectors.get(marker)
    if previous is not None:
        REGISTRY.unregister(previous)
    REGISTRY.register(_Collector(service))
