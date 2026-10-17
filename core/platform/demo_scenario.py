"""A scripted demo that shows what AutoSecOps claims (W0.50).

The random demo data (``DEMO_MODE``) fills screens; it shows no approval, no
revert, no evidence pack and no regulatory clock, and it is off in the air-gap
profile. This writes one coherent incident into the real database instead, so
every screen that carries the claim has something true to show:

* three findings with stored triage verdicts that cite fields and say who
  wrote them (one malicious phish, one malicious C2 beacon, one benign updater);
* a case holding them;
* a host isolation waiting for a person's approval (nothing is autonomous);
* an IP block that was executed and then reversed, with its undo row, on the
  case's action timeline;
* DORA and KVKK clocks running from the recorded awareness instant;
* the evidence pack, built on demand from the case.

Everything it writes has an id starting ``demo-sc-`` and ``remove`` deletes
exactly that. No executor runs and nothing leaves the install, so it works
air-gapped. ``seed`` is idempotent: run twice, it writes once.

    python -m core.platform.demo_scenario seed
    python -m core.platform.demo_scenario remove
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.time import utcnow

PREFIX = "demo-sc-"
CASE_ID = f"{PREFIX}case-1"
ACTOR = "demo-scenario"


def _verdict(verdict: str, confidence: float, category: str, cited, gaps, action=None):
    doc: Dict[str, Any] = {
        "verdict": verdict,
        "confidence": confidence,
        "category": category,
        "cited_fields": [{"field": f, "authored": a} for f, a in cited],
        "gaps": gaps,
        "model": "demo-scenario",
        "prompt_version": "demo",
    }
    if action:
        doc["recommended_action"] = {"type": action[0], "target": action[1]}
    return doc


def findings(now: datetime) -> List[Dict[str, Any]]:
    t0 = now - timedelta(hours=3)
    return [
        {
            "finding_id": f"{PREFIX}phish",
            "data_source": "microsoft_defender",
            "severity": "high",
            "title": "Credential phishing link clicked by a payments analyst",
            "description": (
                "User selin.demir clicked a link to odeme-portali-giris.example in "
                "an e-mail from an external sender; the page asked for corporate "
                "credentials. A sign-in from 198.51.100.24 followed 4 minutes later."
            ),
            "entity_context": {
                "usernames": ["selin.demir"],
                "src_ips": ["198.51.100.24"],
                "domains": ["odeme-portali-giris.example"],
                "hostnames": ["FIN-WS-014"],
            },
            "timestamp": t0,
            "verdict": _verdict(
                "malicious",
                0.88,
                "phishing",
                [
                    ("entity_context.src_ips", "sensor"),
                    ("entity_context.domains", "adversary"),
                    ("description", "adversary"),
                ],
                ["no mail gateway verdict for the message"],
                ("disable_user", "selin.demir"),
            ),
        },
        {
            "finding_id": f"{PREFIX}c2",
            "data_source": "syslog",
            "severity": "critical",
            "title": "Periodic beacon from FIN-WS-014 to 203.0.113.50",
            "description": (
                "FortiGate IPS: Backdoor.Cobalt.Strike signature, 60 s interval "
                "HTTPS beacon from FIN-WS-014 (10.20.4.14) to 203.0.113.50."
            ),
            "entity_context": {
                "src_ips": ["10.20.4.14"],
                "dest_ips": ["203.0.113.50"],
                "hostnames": ["FIN-WS-014"],
            },
            "timestamp": t0 + timedelta(minutes=40),
            "verdict": _verdict(
                "malicious",
                0.93,
                "network",
                [
                    ("entity_context.dest_ips", "sensor"),
                    ("entity_context.src_ips", "sensor"),
                    ("title", "adversary"),
                ],
                [],
                ("isolate_host", "FIN-WS-014"),
            ),
        },
        {
            "finding_id": f"{PREFIX}updater",
            "data_source": "crowdstrike",
            "severity": "low",
            "title": "Signed vendor updater registered a scheduled task",
            "description": (
                "The vendor-signed updater for the office suite registered daily task "
                "OfficeUpdate on FIN-WS-022 during an IT-approved install (REQ-48213)."
            ),
            "entity_context": {
                "hostnames": ["FIN-WS-022"],
                "file_hashes": ["e3b0c442" * 8],
            },
            "timestamp": t0 + timedelta(minutes=55),
            "verdict": _verdict(
                "benign",
                0.81,
                "malware",
                [
                    ("entity_context.file_hashes", "sensor"),
                    ("description", "adversary"),
                ],
                ["change ticket not verified against the ITSM"],
            ),
        },
    ]


def _exists(session: Session) -> bool:
    return bool(
        session.execute(
            text("SELECT 1 FROM cases WHERE case_id = :c"), {"c": CASE_ID}
        ).scalar()
    )


def seed(session: Session, now: datetime | None = None) -> Dict[str, Any]:
    """Write the scenario; nothing when it is already there."""
    now = now or utcnow()
    if _exists(session):
        return {"seeded": False, "case_id": CASE_ID}
    items = findings(now)
    for f in items:
        session.execute(
            text(
                "INSERT INTO findings (finding_id, data_source, title, description,"
                " entity_context, timestamp, severity, status, ai_enrichment,"
                " anomaly_score, created_at, updated_at) VALUES (:id, :src, :title,"
                " :desc, CAST(:ctx AS jsonb), :ts, :sev, 'new', CAST(:ai AS jsonb), 0.8,"
                " :ts, :ts)"
            ),
            {
                "id": f["finding_id"],
                "src": f["data_source"],
                "title": f["title"],
                "desc": f["description"],
                "ctx": json.dumps(f["entity_context"]),
                "ts": f["timestamp"],
                "sev": f["severity"],
                "ai": json.dumps(
                    {
                        "ai_triage": {
                            "timestamp": (
                                f["timestamp"] + timedelta(seconds=40)
                            ).isoformat(),
                            "prompt_version": "demo",
                            "verdict": f["verdict"],
                        }
                    }
                ),
            },
        )
    aware = items[0]["timestamp"] + timedelta(minutes=50)
    session.execute(
        text(
            "INSERT INTO cases (case_id, title, description, status, priority, assignee,"
            " timeline, created_at, updated_at) VALUES (:c, :t, :d, 'investigating',"
            " 'critical', 'ayse', '[]'::jsonb, :at, :at)"
        ),
        {
            "c": CASE_ID,
            "t": "Ödeme ekibinde kimlik avı ve C2 trafiği (demo)",
            "d": (
                "Demo senaryosu: kimlik avı bağlantısına tıklayan kullanıcının "
                "iş istasyonundan dışarı periyodik işaret trafiği. Konak izolasyonu "
                "onay bekliyor; IP engeli uygulandı ve geri alındı."
            ),
            "at": aware,
        },
    )
    for f in items[:2]:
        session.execute(
            text(
                "INSERT INTO case_findings (case_id, finding_id, added_at)"
                " VALUES (:c, :f, :at)"
            ),
            {"c": CASE_ID, "f": f["finding_id"], "at": aware},
        )

    def action(aid, kind, title, target, status, **extra):
        row = {
            "id": f"{PREFIX}{aid}",
            "type": kind,
            "title": title,
            "desc": title,
            "target": target,
            "conf": 0.9,
            "reason": "Demo scenario",
            "evidence": json.dumps([f"{PREFIX}c2"]),
            "at": aware + timedelta(minutes=5),
            "by": "triage",
            "status": status,
            "params": json.dumps({"case_id": CASE_ID, "target": target}),
            "rev": "reversible",
            "approved_at": extra.get("approved_at"),
            "approved_by": extra.get("approved_by"),
            "executed_at": extra.get("executed_at"),
            "reversed_at": extra.get("reversed_at"),
            "reverse_of": extra.get("reverse_of"),
        }
        session.execute(
            text(
                "INSERT INTO approval_actions (action_id, action_type, title, description,"
                " target, confidence, reason, evidence, created_at, created_by,"
                " requires_approval, status, parameters, reversibility, approved_at,"
                " approved_by, executed_at, reversed_at, reverse_of) VALUES (:id, :type,"
                " :title, :desc, :target, :conf, :reason, CAST(:evidence AS jsonb), :at,"
                " :by, true, :status, CAST(:params AS jsonb), :rev, :approved_at,"
                " :approved_by, :executed_at, :reversed_at, :reverse_of)"
            ),
            row,
        )

    t = aware + timedelta(minutes=10)
    action("isolate", "isolate_host", "Isolate FIN-WS-014", "FIN-WS-014", "pending")
    action(
        "block",
        "block_ip",
        "Block 203.0.113.50 at the perimeter",
        "203.0.113.50",
        "executed",
        approved_at=t,
        approved_by="ayse",
        executed_at=t + timedelta(seconds=20),
        reversed_at=t + timedelta(minutes=30),
    )
    action(
        "unblock",
        "unblock_ip",
        "Undo: unblock 203.0.113.50 (shared CDN address)",
        "203.0.113.50",
        "executed",
        approved_at=t + timedelta(minutes=29),
        approved_by="mehmet",
        executed_at=t + timedelta(minutes=30),
        reverse_of=f"{PREFIX}block",
    )
    session.flush()

    clocks = "not recorded"
    try:
        from core.compliance.regulatory_service import RegulatoryService, SqlClockStore

        # Instants carry a UTC offset; the case rows above are naive UTC.
        utc_now = now.replace(tzinfo=timezone.utc)
        utc_aware = aware.replace(tzinfo=timezone.utc)
        service = RegulatoryService(SqlClockStore(session), now=lambda: utc_now)
        with session.begin_nested():
            service.record_instant(CASE_ID, "dora", "aware_at", utc_aware, ACTOR)
            service.record_instant(
                CASE_ID,
                "dora",
                "classification_at",
                utc_aware + timedelta(minutes=20),
                ACTOR,
            )
            service.record_instant(CASE_ID, "kvkk", "aware_at", utc_aware, ACTOR)
        clocks = "dora, kvkk"
    except Exception as exc:  # noqa: BLE001 - the clocks need init SQL 50/65
        clocks = f"skipped ({type(exc).__name__})"
    return {
        "seeded": True,
        "case_id": CASE_ID,
        "findings": len(items),
        "clocks": clocks,
    }


def remove(session: Session) -> Dict[str, int]:
    """Delete every ``demo-sc-`` row the scenario wrote."""
    like = {"p": f"{PREFIX}%"}
    counts: Dict[str, int] = {}
    statements = [
        ("approval_actions", "DELETE FROM approval_actions WHERE action_id LIKE :p"),
        ("case_findings", "DELETE FROM case_findings WHERE case_id LIKE :p"),
        ("findings", "DELETE FROM findings WHERE finding_id LIKE :p"),
    ]
    for name, sql in statements:
        counts[name] = session.execute(text(sql), like).rowcount or 0
    # The case delete cascades to its clock rows and drafts (init SQL 50/58).
    counts["cases"] = (
        session.execute(text("DELETE FROM cases WHERE case_id LIKE :p"), like).rowcount
        or 0
    )
    return counts


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m core.platform.demo_scenario")
    parser.add_argument("command", choices=("seed", "remove"))
    args = parser.parse_args(argv)
    from core.storage.connection import get_db_manager
    from core.storage.unit_of_work import unit_of_work

    manager = get_db_manager()
    if manager.engine is None:
        manager.initialize()
    with unit_of_work() as session:
        result = seed(session) if args.command == "seed" else remove(session)
    print(json.dumps(result, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
