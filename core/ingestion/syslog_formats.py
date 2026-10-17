"""Syslog, CEF and LEEF lines as findings (W0.41).

QRadar, ArcSight, FortiGate, Logsign and Wazuh most often forward alerts as
syslog, with a CEF or LEEF body or FortiGate's own ``key=value`` record. This
module reads one line of that into the finding dict the webhook takes, so the
daemon's syslog listener (services/daemon/syslog_listener.py) and its
``POST /ingest/syslog`` route hand the same thing to the spool.

What is read:

* the syslog header: RFC 5424 (``<PRI>1 TIMESTAMP HOST APP PROCID MSGID SD``),
  RFC 3164 (``<PRI>Mmm dd hh:mm:ss HOST TAG:``), or none;
* the body: ``CEF:0|...`` (ArcSight CEF 0/1), ``LEEF:1.0|...`` and
  ``LEEF:2.0|...`` (QRadar), FortiGate ``key=value`` (it has ``devid=`` and
  ``logid=``), or a JSON object (Wazuh's syslog output).

A line that is none of these is not a finding: :func:`parse_line` returns
None and the caller counts it. Plain syslog chatter is not an alert.

Everything in a line is chosen by whoever wrote the log, so the finding is
``data_source = "syslog"`` and gets the webhook provenance map
(core/federation/provenance.py): only addresses that parse as IPs are sensor,
names and text are adversary.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Tuple

from core.integrations._base.ids import EXTERNAL_ID_MAX, FINDING_ID_MAX, fit_id

DATA_SOURCE = "syslog"

# A line longer than this is cut before it is parsed or stored: a syslog
# relay's own limit is usually 8 KB or 64 KB.
MAX_LINE_BYTES = 64 * 1024
# Keys kept from a body's extension; a forged line with thousands of keys
# does not grow the stored finding without bound.
MAX_FIELDS = 200
MAX_VALUE_CHARS = 4096

_MONTHS = {
    m: i + 1
    for i, m in enumerate(
        (
            "Jan",
            "Feb",
            "Mar",
            "Apr",
            "May",
            "Jun",
            "Jul",
            "Aug",
            "Sep",
            "Oct",
            "Nov",
            "Dec",
        )
    )
}

_PRI = re.compile(r"^<(\d{1,3})>")
_RFC5424 = re.compile(
    r"^1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) "
)
_RFC3164 = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
)
_TAG = re.compile(r"^(?P<tag>[^\s:\[]{1,64})(?:\[\d+\])?: ")


@dataclass
class SyslogHeader:
    facility: Optional[int] = None
    severity: Optional[int] = None
    timestamp: Optional[datetime] = None
    hostname: Optional[str] = None
    app: Optional[str] = None


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso_time(text: str) -> Optional[datetime]:
    try:
        return _aware(datetime.fromisoformat(text.replace("Z", "+00:00")))
    except ValueError:
        return None


def _skip_structured_data(rest: str) -> str:
    """``rest`` after the RFC 5424 STRUCTURED-DATA (``-`` or ``[...]...``)."""
    if rest.startswith("- "):
        return rest[2:]
    if rest == "-":
        return ""
    i = 0
    while i < len(rest) and rest[i] == "[":
        i += 1
        while i < len(rest):
            ch = rest[i]
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                i += 1
                while i < len(rest) and rest[i] != '"':
                    i += 2 if rest[i] == "\\" else 1
            elif ch == "]":
                i += 1
                break
            i += 1
    return rest[i:].lstrip(" ")


def split_header(line: str, now: datetime) -> Tuple[SyslogHeader, str]:
    """The syslog header of ``line`` and the message after it."""
    header = SyslogHeader()
    rest = line
    pri = _PRI.match(rest)
    if pri:
        value = int(pri.group(1))
        if value <= 191:
            header.facility, header.severity = divmod(value, 8)
        rest = rest[pri.end() :]
    m5424 = _RFC5424.match(rest)
    if m5424:
        if m5424.group("ts") != "-":
            header.timestamp = _iso_time(m5424.group("ts"))
        header.hostname = _nil(m5424.group("host"))
        header.app = _nil(m5424.group("app"))
        rest = _skip_structured_data(rest[m5424.end() :])
        if rest.startswith("\ufeff"):
            rest = rest[1:]
        return header, rest
    m3164 = _RFC3164.match(rest)
    if m3164:
        try:
            hh, mm, ss = (int(x) for x in m3164.group("time").split(":"))
            stamp = datetime(
                now.year,
                _MONTHS[m3164.group("mon")],
                int(m3164.group("day")),
                hh,
                mm,
                ss,
                tzinfo=timezone.utc,
            )
            # RFC 3164 has no year: a December line read in January is last year's.
            if (stamp - now).days > 1:
                stamp = stamp.replace(year=now.year - 1)
            header.timestamp = stamp
        except (KeyError, ValueError):
            header.timestamp = None
        header.hostname = m3164.group("host")
        rest = rest[m3164.end() :]
        tag = _TAG.match(rest)
        if tag and not rest.startswith(("CEF:", "LEEF:")):
            header.app = tag.group("tag")
            rest = rest[tag.end() :]
    return header, rest


def _nil(value: str) -> Optional[str]:
    return None if value == "-" else value


# --- CEF -----------------------------------------------------------------

_CEF_KEY = re.compile(r"(?:^|(?<=\s))([A-Za-z0-9_.\[\]-]{1,64})=")


def _split_header_fields(text: str, count: int) -> Optional[Tuple[List[str], str]]:
    """``count`` ``|``-separated fields (``\\|`` and ``\\\\`` escaped) and the rest."""
    fields: List[str] = []
    buf: List[str] = []
    i = 0
    while i < len(text) and len(fields) < count:
        ch = text[i]
        if ch == "\\" and i + 1 < len(text) and text[i + 1] in "|\\":
            buf.append(text[i + 1])
            i += 2
            continue
        if ch == "|":
            fields.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    if len(fields) < count:
        return None
    return fields, text[i:]


def _cef_unescape(value: str) -> str:
    out: List[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            nxt = value[i + 1]
            out.append({"n": "\n", "r": "\r"}.get(nxt, nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def parse_cef_extension(text: str) -> Dict[str, str]:
    """CEF ``key=value`` pairs; a value runs to the next unescaped `` key=``."""
    # A key is only ever [A-Za-z0-9_.[]-] right before "=", so an escaped "\="
    # inside a value (its backslash) never starts one.
    starts = list(_CEF_KEY.finditer(text))
    out: Dict[str, str] = {}
    for n, m in enumerate(starts):
        end = starts[n + 1].start(1) if n + 1 < len(starts) else len(text)
        value = text[m.end() : end].rstrip(" ")
        if len(out) >= MAX_FIELDS:
            break
        out[m.group(1)] = _cef_unescape(value)[:MAX_VALUE_CHARS]
    return out


def parse_cef(body: str) -> Optional[Dict[str, Any]]:
    """``CEF:Version|Vendor|Product|DevVersion|SignatureID|Name|Severity|Ext``."""
    if not body.startswith("CEF:"):
        return None
    split = _split_header_fields(body[4:], 7)
    if split is None:
        return None
    (version, vendor, product, dev_version, signature, name, severity), ext = split
    return {
        "format": "cef",
        "version": version.strip(),
        "vendor": vendor,
        "product": product,
        "device_version": dev_version,
        "signature_id": signature,
        "name": name,
        "severity": severity.strip(),
        "fields": parse_cef_extension(ext),
    }


# --- LEEF ----------------------------------------------------------------


def _leef_delimiter(spec: str) -> str:
    """LEEF 2.0 delimiter field: one character, or ``xHH`` / ``0xHH`` hex."""
    spec = spec.strip()
    hexed = re.fullmatch(r"(?:0?[xX])([0-9A-Fa-f]{2,4})", spec)
    if hexed:
        return chr(int(hexed.group(1), 16))
    return spec[:1] or "\t"


def parse_leef(body: str) -> Optional[Dict[str, Any]]:
    """``LEEF:1.0|Vendor|Product|Version|EventID|attrs`` (tab) or LEEF 2.0
    with a delimiter field before the attributes."""
    if not body.startswith("LEEF:"):
        return None
    split = _split_header_fields(body[5:], 5)
    if split is None:
        return None
    (version, vendor, product, dev_version, event_id), rest = split
    version = version.strip()
    delimiter = "\t"
    if version.startswith("2"):
        # The delimiter field may be absent (then tab).
        candidate = _split_header_fields(rest, 1)
        if (
            candidate is not None
            and len(candidate[0][0].strip()) <= 4
            and "=" not in candidate[0][0]
        ):
            delimiter = _leef_delimiter(candidate[0][0]) if candidate[0][0] else "\t"
            rest = candidate[1]
    fields: Dict[str, str] = {}
    for part in rest.split(delimiter):
        key, sep, value = part.partition("=")
        key = key.strip()
        if not sep or not key or len(key) > 64:
            continue
        if len(fields) >= MAX_FIELDS:
            break
        fields[key] = value.strip()[:MAX_VALUE_CHARS]
    return {
        "format": "leef",
        "version": version,
        "vendor": vendor,
        "product": product,
        "device_version": dev_version,
        "signature_id": event_id,
        "name": fields.get("name") or event_id,
        "severity": fields.get("sev", ""),
        "fields": fields,
    }


# --- FortiGate key=value -------------------------------------------------

_KV = re.compile(r'([A-Za-z_][A-Za-z0-9_]{0,63})=("(?:[^"\\]|\\.)*"|\S*)')


def parse_kv(body: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in _KV.finditer(body):
        if len(out) >= MAX_FIELDS:
            break
        value = m.group(2)
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1].replace('\\"', '"')
        out[m.group(1)] = value[:MAX_VALUE_CHARS]
    return out


def parse_fortigate(body: str) -> Optional[Dict[str, Any]]:
    """FortiOS ``date=... devname="..." devid="..." logid="..." ...``."""
    if "devid=" not in body or "logid=" not in body:
        return None
    fields = parse_kv(body)
    if "devid" not in fields or "logid" not in fields:
        return None
    name = (
        fields.get("attack")
        or fields.get("virus")
        or fields.get("msg")
        or f"{fields.get('type', 'event')}/{fields.get('subtype', '')}".rstrip("/")
    )
    return {
        "format": "fortigate",
        "version": "",
        "vendor": "Fortinet",
        "product": "FortiGate",
        "device_version": "",
        "signature_id": fields.get("logid", ""),
        "name": name,
        "severity": fields.get("level", ""),
        "fields": fields,
    }


# --- JSON (Wazuh) --------------------------------------------------------


def parse_json_body(body: str) -> Optional[Dict[str, Any]]:
    start = body.find("{")
    if start < 0 or start > 64:
        return None
    try:
        data = json.loads(body[start:])
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    rule = data.get("rule") if isinstance(data.get("rule"), Mapping) else {}
    name = rule.get("description") or data.get("message") or data.get("title")
    if not name:
        return None
    agent = data.get("agent") if isinstance(data.get("agent"), Mapping) else {}
    flat: Dict[str, str] = {}
    src = data.get("data") if isinstance(data.get("data"), Mapping) else {}
    for key in ("srcip", "dstip", "srcuser", "dstuser", "srcport", "dstport", "url"):
        if src.get(key) is not None:
            flat[key] = str(src[key])[:MAX_VALUE_CHARS]
    if agent.get("name"):
        flat["agent_name"] = str(agent["name"])[:MAX_VALUE_CHARS]
    if agent.get("ip"):
        flat["agent_ip"] = str(agent["ip"])[:MAX_VALUE_CHARS]
    mitre = rule.get("mitre") if isinstance(rule.get("mitre"), Mapping) else {}
    return {
        "format": "json",
        "version": "",
        "vendor": "Wazuh" if rule else "",
        "product": "Wazuh" if rule else "",
        "device_version": "",
        "signature_id": str(rule.get("id", "")),
        "name": str(name),
        "severity": str(rule.get("level", "")),
        "severity_scale": "wazuh" if rule else "",
        "fields": flat,
        "mitre_ids": [str(t) for t in (mitre.get("id") or []) if isinstance(t, str)],
    }


# --- to a finding --------------------------------------------------------

_CEF_WORDS = {
    "unknown": "medium",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "very-high": "critical",
    "very high": "critical",
}
_FORTI_LEVELS = {
    "emergency": "critical",
    "alert": "critical",
    "critical": "critical",
    "error": "high",
    "warning": "medium",
    "notice": "low",
    "information": "low",
    "debug": "low",
}


def severity_of(parsed: Mapping[str, Any], header: SyslogHeader) -> str:
    raw = str(parsed.get("severity") or "").strip().lower()
    if parsed.get("format") == "fortigate" and raw in _FORTI_LEVELS:
        return _FORTI_LEVELS[raw]
    if raw in _CEF_WORDS:
        return _CEF_WORDS[raw]
    try:
        number = float(raw)
    except ValueError:
        number = None
    if number is not None:
        if parsed.get("severity_scale") == "wazuh":  # rule level 0..15
            number = number * 10 / 15
        if number >= 9:
            return "critical"
        if number >= 7:
            return "high"
        if number >= 4:
            return "medium"
        return "low"
    if header.severity is not None:
        return (
            "critical",
            "critical",
            "critical",
            "high",
            "medium",
            "low",
            "low",
            "low",
        )[header.severity]
    return "medium"


# Field names per entity, across CEF, LEEF, FortiGate and the Wazuh flattening.
_SRC_IP = ("src", "srcip", "sourceAddress", "c6a2")
_DST_IP = ("dst", "dstip", "destinationAddress", "c6a3")
_HOSTS = (
    "shost",
    "dhost",
    "dvchost",
    "identHostName",
    "devname",
    "hostname",
    "srcname",
    "dstname",
    "agent_name",
)
_USERS = ("suser", "duser", "usrName", "user", "srcuser", "dstuser", "accountName")
_HASHES = ("fileHash", "oldFileHash", "filehash", "checksum")
_URLS = ("request", "url")
_FILES = ("fname", "filePath", "filename", "file")
_DOMAINS = ("destinationDnsDomain", "sourceDnsDomain", "domain", "hostname_dns")


def _values(fields: Mapping[str, str], keys) -> List[str]:
    out: List[str] = []
    for key in keys:
        value = fields.get(key)
        if value and value not in out and value != "-":
            out.append(value)
    return out


def _ips(fields: Mapping[str, str], keys) -> List[str]:
    out = []
    for value in _values(fields, keys):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        out.append(value)
    return out


def _event_time(parsed: Mapping[str, Any], header: SyslogHeader) -> Optional[datetime]:
    fields = parsed.get("fields") or {}
    for key in ("rt", "devTime", "end", "start", "eventtime"):
        raw = fields.get(key)
        if not raw:
            continue
        if raw.isdigit():
            number = int(raw)
            # FortiGate eventtime is in ns, CEF rt in ms, some senders use s.
            for scale in (1, 1e3, 1e6, 1e9):
                if number / scale < 4_102_444_800:  # before 2100
                    try:
                        return datetime.fromtimestamp(number / scale, tz=timezone.utc)
                    except (OverflowError, OSError, ValueError):
                        break
            continue
        stamp = _iso_time(raw)
        if stamp:
            return stamp
        for fmt in ("%b %d %Y %H:%M:%S", "%b %d %Y %H:%M:%S.%f"):
            try:
                return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                pass
    if (
        parsed.get("format") == "fortigate"
        and fields.get("date")
        and fields.get("time")
    ):
        stamp = _iso_time(f"{fields['date']}T{fields['time']}")
        if stamp:
            return stamp
    return header.timestamp


def parse_line(
    line: str, *, peer: Optional[str] = None, now: Optional[datetime] = None
) -> Optional[Dict[str, Any]]:
    """The finding ``line`` carries, or None when it is not an alert we read."""
    now = now or datetime.now(timezone.utc)
    raw = line.encode("utf-8", "replace")[:MAX_LINE_BYTES].decode("utf-8", "ignore")
    raw = raw.rstrip("\r\n\x00")
    if not raw.strip():
        return None
    header, body = split_header(raw, now)
    body = body.strip()
    # A relay may leave its own host before the body ("fw01 CEF:0|...").
    for marker in ("CEF:", "LEEF:"):
        at = body.find(marker)
        if 0 < at <= 128 and " " in body[:at]:
            body = body[at:]
            break
    parsed = (
        parse_cef(body)
        or parse_leef(body)
        or parse_fortigate(body)
        or parse_json_body(body)
    )
    if parsed is None:
        return None
    return to_finding(parsed, header, raw, peer=peer, now=now)


def to_finding(
    parsed: Mapping[str, Any],
    header: SyslogHeader,
    raw: str,
    *,
    peer: Optional[str],
    now: datetime,
) -> Dict[str, Any]:
    fields: Mapping[str, str] = parsed.get("fields") or {}
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
    when = _event_time(parsed, header) or now
    name = (parsed.get("name") or "").strip() or "Syslog event"
    vendor = (parsed.get("vendor") or "").strip()
    product = (parsed.get("product") or "").strip()
    title = name[:200]
    origin = " ".join(p for p in (vendor, product) if p) or (header.hostname or "")
    parts = [title]
    if origin:
        parts.append(f"Reported by {origin}")
    if parsed.get("signature_id"):
        parts.append(f"Signature {parsed['signature_id']}")
    msg = fields.get("msg") or fields.get("message")
    if msg and msg != title:
        parts.append(msg)
    entity_context = {
        "src_ips": _ips(fields, _SRC_IP),
        "dest_ips": _ips(fields, _DST_IP),
        "hostnames": _values(fields, _HOSTS)
        + (
            [header.hostname]
            if header.hostname and header.hostname not in _values(fields, _HOSTS)
            else []
        ),
        "usernames": _values(fields, _USERS),
        "file_hashes": _values(fields, _HASHES),
        "urls": _values(fields, _URLS),
        "file_names": _values(fields, _FILES),
        "domains": _values(fields, _DOMAINS),
    }
    mitre = {
        t.upper(): 0.9
        for t in parsed.get("mitre_ids") or []
        if re.fullmatch(r"[Tt]\d{4}(\.\d{3})?", t)
    }
    return {
        "finding_id": fit_id("syslog-", digest, FINDING_ID_MAX),
        "external_id": fit_id("", digest, EXTERNAL_ID_MAX),
        "data_source": DATA_SOURCE,
        "timestamp": when.astimezone(timezone.utc).isoformat(),
        "severity": severity_of(parsed, header),
        "status": "new",
        "title": title,
        "description": ". ".join(parts)[:500],
        "entity_context": {k: v for k, v in entity_context.items() if v},
        "raw_event": {"message": raw, "fields": dict(fields)},
        "anomaly_score": 0.5,
        "mitre_predictions": mitre,
        "metadata": {
            "syslog_format": parsed.get("format"),
            "format_version": parsed.get("version") or None,
            "vendor": vendor or None,
            "product": product or None,
            "device_version": parsed.get("device_version") or None,
            "signature_id": parsed.get("signature_id") or None,
            "syslog_host": header.hostname,
            "syslog_app": header.app,
            "syslog_facility": header.facility,
            "syslog_severity": header.severity,
            "syslog_peer": peer,
        },
    }
