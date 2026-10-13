#!/usr/bin/env python3
"""Score a staging replay: what the instance's triage said vs. corpus labels.

Standard library only. Reads ``labels.jsonl`` written by corpus_to_findings.py,
fetches each finding from ``GET /api/v1/findings/{id}`` and maps the stored
triage onto a verdict the same way evalkit's ``legacy-v1`` adapter does:
isolate/block/investigate -> malicious, dismiss/monitor -> benign, anything
else -> inconclusive. A finding with no ``ai_triage`` yet is ``pending``.

Env: STAGING_BASE_URL (required), API_TOKEN (bearer; never on argv).
Writes ``report.json`` to --out and prints a one-line summary. Exit 1 only
when ``--min-coverage`` is given and the triaged fraction is below it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

MALICIOUS_ACTIONS = {"isolate", "block", "investigate"}
BENIGN_ACTIONS = {"dismiss", "monitor"}

Fetch = Callable[[str], Optional[Dict[str, Any]]]


def http_fetcher(base_url: str, token: str, timeout: float = 30.0) -> Fetch:
    def fetch(finding_id: str) -> Optional[Dict[str, Any]]:
        url = f"{base_url.rstrip('/')}/api/v1/findings/{urllib.parse.quote(finding_id, safe='')}"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator-given URL
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise

    return fetch


def triage_of(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The stored triage block; the daemon keeps it inside ai_enrichment."""
    enrichment = finding.get("ai_enrichment") or {}
    if isinstance(enrichment, dict) and isinstance(enrichment.get("ai_triage"), dict):
        return enrichment["ai_triage"]
    if isinstance(finding.get("ai_triage"), dict):
        return finding["ai_triage"]
    return None


def verdict_of(triage: Optional[Dict[str, Any]]) -> str:
    if triage is None:
        return "pending"
    action = ((triage.get("result") or {}).get("recommended_action") or "").lower()
    if action in MALICIOUS_ACTIONS:
        return "malicious"
    if action in BENIGN_ACTIONS:
        return "benign"
    return "inconclusive"


def score(labels: List[Dict[str, Any]], fetch: Fetch) -> Dict[str, Any]:
    outcomes: Counter = Counter()
    confusion: Counter = Counter()
    cases = []
    for lab in labels:
        finding = fetch(lab["finding_id"])
        if finding is None:
            got = "missing"
        else:
            got = verdict_of(triage_of(finding))
        outcomes[got] += 1
        if got in ("malicious", "benign", "inconclusive"):
            confusion[f"{lab.get('verdict')}->{got}"] += 1
        cases.append({"finding_id": lab["finding_id"], "suite": lab.get("suite"),
                      "expected": lab.get("verdict"), "got": got})
    total = len(labels)
    triaged = outcomes["malicious"] + outcomes["benign"] + outcomes["inconclusive"]
    decided = outcomes["malicious"] + outcomes["benign"]
    correct = confusion["malicious->malicious"] + confusion["benign->benign"]
    return {
        "total": total,
        "triaged": triaged,
        "coverage": (triaged / total) if total else 0.0,
        "outcomes": dict(outcomes),
        "confusion": dict(confusion),
        # Of the decided (non-inconclusive) answers, how many match the label.
        "decided_accuracy": (correct / decided) if decided else None,
        # Most expensive error: a malicious alert called benign.
        "false_benign": confusion["malicious->benign"],
        "cases": cases,
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--labels", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--min-coverage", type=float, default=None)
    args = ap.parse_args(argv)

    base = os.environ.get("STAGING_BASE_URL", "")
    token = os.environ.get("API_TOKEN", "")
    if not base or not token:
        raise SystemExit("STAGING_BASE_URL and API_TOKEN must be set")
    labels = [json.loads(x) for x in args.labels.read_text(encoding="utf-8").splitlines() if x.strip()]
    report = score(labels, http_fetcher(base, token))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    acc = report["decided_accuracy"]
    print(
        f"replay: total={report['total']} triaged={report['triaged']} "
        f"coverage={report['coverage']:.2f} "
        f"decided_accuracy={'n/a' if acc is None else f'{acc:.2f}'} "
        f"false_benign={report['false_benign']}"
    )
    if args.min_coverage is not None and report["coverage"] < args.min_coverage:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
