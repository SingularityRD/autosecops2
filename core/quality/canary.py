"""Hidden canary alerts (W1.5).

A canary is a replay of a known-malicious alert from the held-out test split of
the eval corpus (``eval/corpus/v1/test.jsonl``) that the daemon pushes through
the normal ingest hand-off, under the record's own realistic ``data_source``
(``crowdstrike``, ``sentinel``, ...). It lands in the queue as an ordinary
alert so both the AI triage and the analysts are tested on it. Unlike a
known-answer probe (``services/daemon/probes.py``, ``data_source = "probe"``),
nothing on the finding says it is a test: it gets a fresh id and external id in
its source's shape, a current timestamp, and the corpus' ``synthetic`` flag is
removed. The only record of what it is lives in ``canary_injections``, with a
random secret ``marker`` and the ``finding_id`` it became.

Off by default. Injection runs only while the admin setting
``quality.canary`` (``system_config``) says ``enabled``; the setting is written
through ``ConfigService`` so every change is in ``config_audit_log`` under the
admin who made it. The daemon side additionally has a deployment kill switch
(``DAEMON_CANARIES_ENABLED``).

Safety and hygiene, enforced elsewhere through
``core.storage.canary_exclusion``:

- the daemon never sends a canary to the responder (no isolate/block, no
  Slack/PagerDuty escalation), to autonomous investigation (no intake trigger,
  whichever path asks), or to external threat-intel and sandbox lookups (the
  check runs before enrichment);
- canaries are left out of customer metrics, findings/IOC exports, Jira, and
  any webhook or SIEM write-back.

Scoring: ``score_after_hours`` after injection a canary is ``caught`` when any
of these happened, else ``missed`` (``error`` when the finding was never
stored):

- the AI verdict on the finding is ``malicious``;
- a case links the finding (an analyst or an agent opened one on it);
- an analyst recorded the AI decision on it as ``true_positive``.

``canary_summary`` is the report card behind ``GET /api/quality/canaries``.
"""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import json
import logging
import re
import secrets
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from sqlalchemy import func, insert, select, update
from sqlalchemy.orm import Session

from core.ingestion.handoff import envelope
from core.storage.canary_exclusion import (
    canary_finding_ids,
    canary_injections,
    canary_table_present,
    is_canary_finding,
)
from core.storage.config_service import get_config_service
from core.storage.models import AIDecisionLog, Finding, case_findings
from core.storage.unit_of_work import unit_of_work

logger = logging.getLogger(__name__)

SETTINGS_KEY = "quality.canary"
CANARY_KIND = "corpus_replay"
CORPUS_VERSION = "v1"
CORPUS_SPLIT = "test"
# Repo root / image workdir: core/quality/canary.py -> parents[2].
CORPUS_PATH = (
    Path(__file__).resolve().parents[2]
    / "eval"
    / "corpus"
    / CORPUS_VERSION
    / "test.jsonl"
)

VERDICTS = ("malicious", "benign", "inconclusive")
CATEGORIES = ("phishing", "malware", "identity", "network", "cloud", "other")
OUTCOMES = ("pending", "caught", "missed", "error")
# What an analyst's AI-decision feedback calls a real threat.
ANALYST_MALICIOUS_OUTCOMES = ("true_positive",)

MIN_PER_DAY, MAX_PER_DAY = 1, 24
MIN_SCORE_AFTER_H, MAX_SCORE_AFTER_H = 1, 168

# Finding ids this process has injected. The daemon that injects a canary is
# the one that processes it, so the common case never needs the database; the
# lookup covers a canary re-read from the database (the enrichment backfill
# after a restart).
_injected: Set[str] = set()


@dataclass(frozen=True)
class CanarySettings:
    enabled: bool = False
    per_day: int = 1
    score_after_hours: int = 24

    @classmethod
    def from_value(cls, value: Optional[Dict[str, Any]]) -> "CanarySettings":
        value = value or {}
        default = cls()

        def _int(name: str, lo: int, hi: int) -> int:
            raw = value.get(name, getattr(default, name))
            try:
                n = int(raw)
            except (TypeError, ValueError):
                return getattr(default, name)
            return min(max(n, lo), hi)

        return cls(
            # Only a literal true enables: a malformed row stays off.
            enabled=value.get("enabled") is True,
            per_day=_int("per_day", MIN_PER_DAY, MAX_PER_DAY),
            score_after_hours=_int(
                "score_after_hours", MIN_SCORE_AFTER_H, MAX_SCORE_AFTER_H
            ),
        )


# ---------------------------------------------------------------------------
# Settings (admin-only, audited)
# ---------------------------------------------------------------------------


def read_canary_settings() -> CanarySettings:
    """The stored setting; off when absent, and off when the read fails."""
    try:
        value = get_config_service().read_system_config(SETTINGS_KEY)
    except Exception as e:  # noqa: BLE001
        logger.warning("Cannot read %s; canaries stay off: %s", SETTINGS_KEY, e)
        return CanarySettings()
    return CanarySettings.from_value(value)


def write_canary_settings(
    settings: CanarySettings, *, user_id: str, reason: Optional[str] = None
) -> bool:
    """Store the setting as ``user_id``; ConfigService writes the audit row
    in the same transaction, so a change never commits unaudited."""
    return bool(
        get_config_service(user_id=user_id).set_system_config(
            SETTINGS_KEY,
            asdict(settings),
            description="Hidden canary alerts (W1.5): off unless an admin enables them.",
            config_type="quality",
            change_reason=reason
            or ("canaries enabled" if settings.enabled else "canaries disabled"),
        )
    )


# ---------------------------------------------------------------------------
# Corpus and the canary finding
# ---------------------------------------------------------------------------


def load_corpus_records(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Malicious records of the corpus' test split."""
    path = path or CORPUS_PATH
    records = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            labels = record.get("labels") or {}
            meta = record.get("meta") or {}
            if labels.get("verdict") != "malicious":
                continue
            if meta.get("split") != CORPUS_SPLIT:
                continue
            if not isinstance(record.get("alert"), dict):
                continue
            records.append(record)
    return records


def _iso_z(when: datetime) -> str:
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- looking like the real thing ---------------------------------------------
#
# The corpus is synthetic and says so to anyone who looks: every address is in
# an RFC 5737 documentation range (192.0.2/24, 198.51.100/24, 203.0.113/24),
# domains end in reserved TLDs (.test, .example), the same template always
# carries the same hash, and raw_event has three keys where a real connector
# sends a vendor envelope. A replay rewrites all of that, consistently across
# entity_context and every free-text field, so the canary cannot be picked out
# by those tells, while staying safe:
#
# - addresses come from ``CANARY_ADDRESS_POOL`` (default: the RFC 1918 private
#   ranges). Only non-global ranges are accepted, so a canary never names a
#   host on the internet; an operator should point it at an unused internal
#   subnet so it never names one of theirs either;
# - hashes are fresh random hex of the same length (never a real file);
# - reserved-TLD domains are rewritten under ``CANARY_DOMAIN_SUFFIX`` only when
#   the operator sets one (a domain they own); otherwise they stay as they are,
#   because any made-up public name might belong to somebody;
# - raw_event gains the per-alert identifiers its vendor would send (detection
#   / alert / event ids), never tenant-level ones (account, tenant, CID) that
#   a replay cannot know.
#
# What stays recognisable is documented in docs/wp/w1.5.md.

DEFAULT_ADDRESS_POOL = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

_IPV4 = re.compile(r"(?<!\d)(?<!\d\.)(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
_HASH = re.compile(
    r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Za-z])"
)
_RESERVED_DOMAIN = re.compile(
    r"(?<![\w.-])((?:[A-Za-z0-9-]+\.)+?)"
    r"(example\.(?:com|net|org)|test|example|invalid)(?![\w-])",
    re.IGNORECASE,
)


def address_pool(raw: Optional[str] = None) -> List[ipaddress.IPv4Network]:
    """The IPv4 networks canary addresses are drawn from.

    ``raw`` (default: ``CANARY_ADDRESS_POOL``) is comma-separated CIDRs. A
    range that is global (routable on the internet), not IPv4, or too small
    for a host address is dropped with a warning; nothing usable left means
    the default private ranges.
    """
    if raw is None:
        try:
            from core.config import get_settings

            raw = get_settings().canary_address_pool
        except Exception:  # noqa: BLE001
            raw = DEFAULT_ADDRESS_POOL
    nets = []
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError:
            logger.warning("Canary address pool: %r is not a CIDR; ignored", part)
            continue
        if net.version != 4 or net.is_global or net.num_addresses < 4:
            logger.warning(
                "Canary address pool: %s is not a private IPv4 range; ignored", net
            )
            continue
        nets.append(net)
    if not nets:
        nets = [ipaddress.ip_network(p) for p in DEFAULT_ADDRESS_POOL.split(",")]
    return nets


def _domain_suffix() -> str:
    try:
        from core.config import get_settings

        return (get_settings().canary_domain_suffix or "").strip().strip(".")
    except Exception:  # noqa: BLE001
        return ""


class _Rewriter:
    """One alert's consistent substitutions (same input, same output)."""

    def __init__(
        self, pool: List[ipaddress.IPv4Network], domain_suffix: str, rng: Any
    ) -> None:
        self.pool = pool
        self.suffix = domain_suffix
        self.rng = rng
        self.ips: Dict[str, str] = {}
        self.hashes: Dict[str, str] = {}

    def _ip(self, m: "re.Match[str]") -> str:
        old = m.group(0)
        try:
            ipaddress.IPv4Address(old)
        except ValueError:
            return old  # a version string, not an address
        if old not in self.ips:
            used = set(self.ips.values())
            while True:
                net = self.rng.choice(self.pool)
                host = net.network_address + self.rng.randint(1, net.num_addresses - 2)
                if str(host) not in used:
                    break
            self.ips[old] = str(host)
        return self.ips[old]

    def _hash(self, m: "re.Match[str]") -> str:
        old = m.group(0)
        key = old.lower()
        if key not in self.hashes:
            self.hashes[key] = "".join(
                self.rng.choice("0123456789abcdef") for _ in range(len(old))
            )
        new = self.hashes[key]
        return new.upper() if old.isupper() else new

    def _domain(self, m: "re.Match[str]") -> str:
        return f"{m.group(1)}{self.suffix}"

    def text(self, value: str) -> str:
        value = _IPV4.sub(self._ip, value)
        value = _HASH.sub(self._hash, value)
        if self.suffix:
            value = _RESERVED_DOMAIN.sub(self._domain, value)
        return value

    def walk(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.walk(v) for v in value]
        if isinstance(value, dict):
            return {k: self.walk(v) for k, v in value.items()}
        return value


def _hex(rng: Any, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _uuid(rng: Any) -> str:
    return str(uuid.UUID(_hex(rng, 32), version=4))


def _vendor_fields(alert: Dict[str, Any], rng: Any) -> Dict[str, Any]:
    """Per-alert identifiers and fields the source's connector would carry."""
    source = str(alert.get("data_source") or "").lower()
    severity = str(alert.get("severity") or "medium").lower()
    techniques = sorted(
        (alert.get("mitre_predictions") or {}).items(), key=lambda kv: -kv[1]
    )
    technique = techniques[0][0] if techniques else None
    ts = alert.get("timestamp")
    sev_num = {"low": 2, "medium": 5, "high": 7, "critical": 9}.get(severity, 5)
    if source == "crowdstrike":
        return {
            "detection_id": f"ldt:{_hex(rng, 32)}:{rng.randint(10**10, 10**11 - 1)}",
            "device_id": _hex(rng, 32),
            "severity_name": severity.capitalize(),
            "technique_id": technique,
            "pattern_id": rng.randint(10000, 99999),
            "product": "epp",
            "created_timestamp": ts,
        }
    if source == "sentinel":
        return {
            "SystemAlertId": _uuid(rng),
            "ProductName": "Azure Sentinel",
            "ProviderName": "ASI Scheduled Alerts",
            "AlertSeverity": severity.capitalize(),
            "Techniques": [technique] if technique else [],
            "TimeGenerated": ts,
        }
    if source == "defender":
        return {
            "alertId": f"da{rng.randint(10**17, 10**18 - 1)}_{rng.randint(10**8, 10**9 - 1)}",
            "incidentId": rng.randint(1000, 99999),
            "serviceSource": "microsoftDefenderForEndpoint",
            "detectionSource": "microsoftDefenderForEndpoint",
            "mitreTechniques": [technique] if technique else [],
            "createdDateTime": ts,
        }
    if source == "entra":
        return {
            "id": _hex(rng, 64),
            "correlationId": _uuid(rng),
            "source": "IdentityProtection",
            "riskLevel": severity if severity in ("low", "medium", "high") else "high",
            "activityDateTime": ts,
        }
    if source == "aws_guardduty":
        return {
            "Id": _hex(rng, 32),
            "SchemaVersion": "2.0",
            "Severity": float(sev_num) + rng.randint(0, 9) / 10,
            "Service": {
                "ServiceName": "guardduty",
                "Count": alert.get("raw_event", {}).get("event_count", 1),
            },
            "UpdatedAt": ts,
        }
    if source == "proofpoint":
        return {
            "GUID": "".join(
                rng.choice(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                )
                for _ in range(30)
            ),
            "QID": f"{rng.randint(10**8, 10**9 - 1):x}{_hex(rng, 6)}",
            "policyRoutes": ["default_inbound"],
            "messageTime": ts,
        }
    if source == "zeek":
        return {
            "uid": "C"
            + "".join(
                rng.choice(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                )
                for _ in range(17)
            ),
            "ts": round(_epoch(ts, rng), 6),
            "proto": "tcp",
        }
    if source == "dlp":
        return {
            "incident_id": rng.randint(100000, 999999),
            "policy_name": alert.get("raw_event", {}).get("rule_name"),
            "detected_at": ts,
        }
    if source == "kubernetes":
        return {
            "auditID": _uuid(rng),
            "stage": "ResponseComplete",
            "requestReceivedTimestamp": ts,
        }
    return {"event_id": _uuid(rng), "event_time": ts}


def _epoch(ts: Any, rng: Any) -> float:
    try:
        base = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        base = datetime.now(timezone.utc)
    return base.timestamp() + rng.random()  # sub-second part, as zeek logs it


def build_canary_finding(
    record: Dict[str, Any],
    now: datetime,
    *,
    pool: Optional[List[ipaddress.IPv4Network]] = None,
    domain_suffix: Optional[str] = None,
    rng: Any = None,
) -> Dict[str, Any]:
    """The alert as a fresh, ordinary-looking finding.

    Same source, same shape. New ``finding_id`` and ``external_id`` in the
    corpus' own ``<prefix>-<20 hex>`` form (so a replay never collides with an
    earlier one or with the dedup key), the current time, no
    ``raw_event.synthetic`` flag, addresses / hashes (and, when configured,
    reserved domains) rewritten consistently everywhere they appear, and the
    vendor's per-alert identifiers in ``raw_event``. Nothing on it names it a
    canary.
    """
    rng = rng or secrets.SystemRandom()
    rewriter = _Rewriter(
        pool if pool is not None else address_pool(),
        _domain_suffix() if domain_suffix is None else domain_suffix,
        rng,
    )
    alert = rewriter.walk(copy.deepcopy(record["alert"]))
    source_id = str(record["alert"].get("finding_id") or "")
    prefix = source_id.split("-", 1)[0] if "-" in source_id else ""
    ext = secrets.token_hex(10)
    alert["finding_id"] = f"{prefix}-{ext}" if prefix else ext
    alert["external_id"] = ext
    alert["timestamp"] = _iso_z(now)
    alert["status"] = "new"
    raw = alert.get("raw_event")
    if not isinstance(raw, dict):
        raw = {}
        alert["raw_event"] = raw
    raw.pop("synthetic", None)
    for key, value in _vendor_fields(alert, rng).items():
        raw.setdefault(key, value)
    return alert


# ---------------------------------------------------------------------------
# Injection
# ---------------------------------------------------------------------------


def _aware(value: Any) -> Optional[datetime]:
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def injection_due(settings: CanarySettings, now: datetime, session: Session) -> bool:
    """Whether a canary is due: enabled, and the last one is at least
    ``24h / per_day`` old (one per sweep, so a backlog never bursts)."""
    if not settings.enabled:
        return False
    last = _aware(
        session.execute(select(func.max(canary_injections.c.injected_at))).scalar()
    )
    if last is None:
        return True
    return now - last >= timedelta(hours=24) / settings.per_day


def record_injection(
    record: Dict[str, Any], now: datetime, session: Session
) -> Dict[str, Any]:
    """Insert the canary_injections row; return the finding to hand off.

    The row is written (and committed by the caller) before the finding goes
    on the queue, so no moment exists in which the finding is stored but not
    yet known to be a canary.
    """
    finding = build_canary_finding(record, now)
    labels = record.get("labels") or {}
    meta = record.get("meta") or {}
    category = labels.get("category")
    session.execute(
        insert(canary_injections).values(
            marker=secrets.token_urlsafe(24),
            canary_kind=CANARY_KIND,
            expected_verdict="malicious",
            expected_category=category if category in CATEGORIES else None,
            payload={
                "corpus": CORPUS_VERSION,
                "split": CORPUS_SPLIT,
                "pair_id": meta.get("pair_id"),
                "template_id": meta.get("template_id"),
                "source_finding_id": record["alert"].get("finding_id"),
                "data_source": finding.get("data_source"),
                "alert": finding,
            },
            injected_at=now,
            finding_id=finding["finding_id"],
        )
    )
    return finding


def _mark_error(finding_id: str, error: str, session: Session) -> None:
    session.execute(
        update(canary_injections)
        .where(canary_injections.c.finding_id == finding_id)
        .values(outcome="error", error=error[:500])
    )


def _prepare(
    corpus_path: Optional[Path], now: datetime, rng: Any
) -> Optional[Dict[str, Any]]:
    """Sync half of a sweep's injection: the due check and the row."""
    settings = read_canary_settings()
    if not settings.enabled:
        return None
    with unit_of_work() as session:
        if not canary_table_present(session):
            logger.warning(
                "Canaries are enabled but canary_injections is missing; "
                "apply infra/database/init/46_eval_qa_canary.sql"
            )
            return None
        if not injection_due(settings, now, session):
            return None
    try:
        records = load_corpus_records(corpus_path)
    except OSError as e:
        logger.warning("Canary corpus unreadable; none injected: %s", e)
        return None
    if not records:
        logger.warning("Canary corpus has no malicious test records; none injected")
        return None
    record = rng.choice(records)
    with unit_of_work() as session:
        return record_injection(record, now, session)


async def inject_canary(
    queue: asyncio.Queue,
    *,
    corpus_path: Optional[Path] = None,
    now: Optional[datetime] = None,
    rng: Any = None,
) -> Optional[str]:
    """Queue one canary if one is due; return its finding_id.

    Same envelope and queue as the poller and Kafka ingestor. A full queue is
    not waited on (the scheduler runs its tasks in turn); that canary is
    recorded as ``error`` and the next sweep tries again.
    """
    now = now or datetime.now(timezone.utc)
    rng = rng or secrets.SystemRandom()
    finding = await asyncio.to_thread(_prepare, corpus_path, now, rng)
    if finding is None:
        return None
    _injected.add(finding["finding_id"])
    try:
        queue.put_nowait(envelope(finding, finding.get("data_source") or "unknown"))
    except asyncio.QueueFull:

        def _fail() -> None:
            with unit_of_work() as session:
                _mark_error(finding["finding_id"], "hand-off queue full", session)

        await asyncio.to_thread(_fail)
        # Debug only: the daemon log is readable by analysts, and a line at the
        # moment of injection (or of scoring, a fixed time later) would date it.
        logger.debug("Hand-off full; canary not injected this sweep")
        return None
    return finding["finding_id"]


# ---------------------------------------------------------------------------
# Response guard
# ---------------------------------------------------------------------------


def _withhold(finding_id: Optional[str]) -> bool:
    if finding_id and finding_id in _injected:
        return True
    try:
        return is_canary_finding(finding_id)
    except Exception as e:  # noqa: BLE001
        # Fail closed once this process has injected canaries: one names hosts
        # and users that may exist, and containment on them must not happen.
        # Before that there is nothing a failed lookup could be hiding.
        if _injected:
            logger.error(
                "Cannot tell whether %s is a canary; withholding response: %s",
                finding_id,
                e,
            )
            return True
        logger.debug(
            "Canary lookup failed for %s; none injected here: %s", finding_id, e
        )
        return False


async def withhold_response(finding_id: Optional[str]) -> bool:
    """True when the daemon must not respond to or investigate this finding
    automatically: it is a canary, or that could not be ruled out."""
    return await asyncio.to_thread(_withhold, finding_id)


def without_canaries(
    findings: List[Dict[str, Any]], cases: List[Dict[str, Any]]
) -> tuple:
    """``findings`` minus canaries and ``cases`` minus canary-only cases, for
    summaries counted in Python (the daemon's scheduled report). That report
    is only logged, so a failed lookup keeps everything rather than failing
    it."""
    try:
        ids = canary_finding_ids()
    except Exception as e:  # noqa: BLE001
        logger.warning("Canary lookup failed; report counts include them: %s", e)
        return findings, cases
    if not ids:
        return findings, cases

    def _canary_only(case: Dict[str, Any]) -> bool:
        linked = set(case.get("finding_ids") or [])
        return bool(linked) and linked <= ids

    return (
        [f for f in findings if f.get("finding_id") not in ids],
        [c for c in cases if not _canary_only(c)],
    )


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _verdict_value(value: Any) -> Optional[str]:
    if isinstance(value, dict):
        value = value.get("verdict")
    if isinstance(value, str) and value.lower() in VERDICTS:
        return value.lower()
    return None


def ai_verdict(ai_enrichment: Optional[Dict[str, Any]]) -> Optional[str]:
    """The AI's malicious/benign/inconclusive call stored on a finding.

    Reads a verdict.schema.json document wherever the triage keeps it (its own
    ``verdict`` key, or ``ai_triage`` / ``ai_triage.result``). Triage that
    predates the verdict contract only recommends an action; ``isolate`` and
    ``block`` read as malicious, ``dismiss`` as benign, the rest inconclusive.
    """
    enrichment = ai_enrichment or {}
    triage = enrichment.get("ai_triage") or {}
    result = triage.get("result") if isinstance(triage, dict) else None
    result = result if isinstance(result, dict) else {}
    for candidate in (
        enrichment.get("verdict"),
        triage.get("verdict") if isinstance(triage, dict) else None,
        result.get("verdict"),
    ):
        found = _verdict_value(candidate)
        if found:
            return found
    action = result.get("recommended_action")
    if isinstance(action, dict):
        action = action.get("type")
    if not isinstance(action, str) or not action:
        return None
    action = action.lower()
    if action in ("isolate", "block"):
        return "malicious"
    if action == "dismiss":
        return "benign"
    return "inconclusive"


def score_one(finding_id: Optional[str], session: Session) -> Dict[str, Any]:
    """Outcome, observed verdict and the signals behind them for one canary."""
    if not finding_id:
        return {"outcome": "error", "observed_verdict": None, "error": "no finding id"}
    finding = session.get(Finding, finding_id)
    if finding is None:
        return {
            "outcome": "error",
            "observed_verdict": None,
            "error": "finding was never stored",
        }
    verdict = ai_verdict(finding.ai_enrichment)
    case_opened = bool(
        session.execute(
            select(func.count())
            .select_from(case_findings)
            .where(case_findings.c.finding_id == finding_id)
        ).scalar()
    )
    analyst_malicious = bool(
        session.execute(
            select(func.count())
            .select_from(AIDecisionLog)
            .where(
                AIDecisionLog.finding_id == finding_id,
                AIDecisionLog.actual_outcome.in_(ANALYST_MALICIOUS_OUTCOMES),
            )
        ).scalar()
    )
    signals = {
        "ai_verdict": verdict,
        "case_opened": case_opened,
        "analyst_marked_malicious": analyst_malicious,
    }
    caught = verdict == "malicious" or case_opened or analyst_malicious
    return {
        "outcome": "caught" if caught else "missed",
        "observed_verdict": "malicious" if caught else verdict,
        "signals": signals,
        "error": None,
    }


def score_due_canaries(
    now: Optional[datetime] = None,
    settings: Optional[CanarySettings] = None,
    session: Optional[Session] = None,
) -> int:
    """Score every pending canary past ``score_after_hours``; return how many.

    Runs whatever the enabled flag says, so canaries injected before an admin
    turned the feature off still get a result. A scored row is never rescored.
    """
    now = now or datetime.now(timezone.utc)
    settings = settings or read_canary_settings()
    cutoff = now - timedelta(hours=settings.score_after_hours)
    scored = 0
    with unit_of_work(session) as s:
        if not canary_table_present(s):
            return 0
        due = s.execute(
            select(
                canary_injections.c.id,
                canary_injections.c.finding_id,
                canary_injections.c.payload,
            ).where(
                canary_injections.c.outcome == "pending",
                canary_injections.c.injected_at <= cutoff,
            )
        ).all()
        for row_id, finding_id, payload in due:
            try:
                result = score_one(finding_id, s)
            except Exception as e:  # noqa: BLE001 — one bad row must not stop the rest
                logger.warning("Canary scoring failed for one row: %s", e)
                result = {"outcome": "error", "observed_verdict": None, "error": str(e)}
            new_payload = dict(payload or {})
            if result.get("signals") is not None:
                new_payload["score"] = {
                    **result["signals"],
                    "scored_at": now.isoformat(),
                }
            s.execute(
                update(canary_injections)
                .where(canary_injections.c.id == row_id)
                .values(
                    outcome=result["outcome"],
                    observed_verdict=result["observed_verdict"],
                    observed_at=now,
                    error=(result.get("error") or None),
                    payload=new_payload,
                )
            )
            scored += 1
    if scored:
        logger.debug("Scored %d canary alert(s)", scored)
    return scored


async def canary_sweep(queue: Optional[asyncio.Queue]) -> Dict[str, Any]:
    """One daemon tick: score what is due, then inject one canary if due."""
    scored = await asyncio.to_thread(score_due_canaries)
    injected = None
    if queue is not None:
        injected = await inject_canary(queue)
    return {"scored": scored, "injected": 1 if injected else 0}


# ---------------------------------------------------------------------------
# Report card
# ---------------------------------------------------------------------------


def _rate(caught: int, missed: int) -> Optional[float]:
    total = caught + missed
    return round(caught / total, 4) if total else None


def canary_summary(
    limit: int = 50, session: Optional[Session] = None
) -> Dict[str, Any]:
    """Counts, catch rate (overall, by category, by signal) and recent canaries.

    ``catch_rate`` is caught / (caught + missed); pending and error rows are
    not in it. The marker is never returned.
    """
    settings = read_canary_settings()
    empty = {
        "settings": asdict(settings),
        "table_present": False,
        "totals": {o: 0 for o in OUTCOMES},
        "catch_rate": None,
        "by_category": {},
        "caught_by": {"ai_verdict": 0, "case_opened": 0, "analyst_marked_malicious": 0},
        "canaries": [],
    }
    with unit_of_work(session) as s:
        if not canary_table_present(s):
            return empty
        c = canary_injections.c
        totals = {o: 0 for o in OUTCOMES}
        by_category: Dict[str, Dict[str, int]] = {}
        for category, outcome, n in s.execute(
            select(c.expected_category, c.outcome, func.count()).group_by(
                c.expected_category, c.outcome
            )
        ):
            totals[outcome] = totals.get(outcome, 0) + int(n)
            bucket = by_category.setdefault(
                category or "unknown", {o: 0 for o in OUTCOMES}
            )
            bucket[outcome] = bucket.get(outcome, 0) + int(n)
        caught_by = {"ai_verdict": 0, "case_opened": 0, "analyst_marked_malicious": 0}
        for (payload,) in s.execute(select(c.payload).where(c.outcome == "caught")):
            score = (payload or {}).get("score") or {}
            if score.get("ai_verdict") == "malicious":
                caught_by["ai_verdict"] += 1
            if score.get("case_opened"):
                caught_by["case_opened"] += 1
            if score.get("analyst_marked_malicious"):
                caught_by["analyst_marked_malicious"] += 1
        rows = s.execute(
            select(
                c.id,
                c.finding_id,
                c.canary_kind,
                c.expected_verdict,
                c.expected_category,
                c.payload,
                c.injected_at,
                c.observed_verdict,
                c.observed_at,
                c.outcome,
                c.error,
            )
            .order_by(c.injected_at.desc())
            .limit(limit)
        ).all()
    canaries = []
    for r in rows:
        payload = r.payload or {}
        canaries.append(
            {
                "id": str(r.id),
                "finding_id": r.finding_id,
                "canary_kind": r.canary_kind,
                "data_source": payload.get("data_source"),
                "template_id": payload.get("template_id"),
                "expected_verdict": r.expected_verdict,
                "expected_category": r.expected_category,
                "injected_at": r.injected_at.isoformat() if r.injected_at else None,
                "observed_verdict": r.observed_verdict,
                "observed_at": r.observed_at.isoformat() if r.observed_at else None,
                "outcome": r.outcome,
                "signals": payload.get("score"),
                "error": r.error,
            }
        )
    return {
        "settings": asdict(settings),
        "table_present": True,
        "totals": totals,
        "catch_rate": _rate(totals["caught"], totals["missed"]),
        "by_category": {
            k: {**v, "catch_rate": _rate(v["caught"], v["missed"])}
            for k, v in sorted(by_category.items())
        },
        "caught_by": caught_by,
        "canaries": canaries,
    }
