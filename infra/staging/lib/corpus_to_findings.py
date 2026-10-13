#!/usr/bin/env python3
"""Turn evaluation-corpus records into findings a staging instance can ingest.

Standard library only: runs on the staging VM's system python3, not the
project venv.

Each corpus line is ``{"alert": {...}, "labels": {...}, "meta": {...}}``. Only
``alert`` goes to the instance (as evalkit does: labels never reach the
model). ``finding_id`` and ``external_id`` are rewritten with a tag, because
ingestion skips a finding whose id or (source, external_id) it already holds;
the tag makes a replay run land as new rows and keeps the demo seed stable.
``timestamp`` is set to now so replayed rows show up as today's.

Outputs, under ``--out-dir``:
  batch-0001.jsonl ...   findings, ``--batch`` per file (the API reads one
                         multipart field; keep each well under 1 MiB)
  labels.jsonl           {"finding_id", "suite", "verdict", "category"} per
                         finding, for replay_report.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[3]
CORPUS_DIR = REPO_ROOT / "eval" / "corpus" / "v1"
INJECTION_FILE = REPO_ROOT / "eval" / "suites" / "injection" / "v1.jsonl"
SPLITS = ("train", "dev", "test", "test_unseen")
SUITES = SPLITS + ("injection",)
FINDING_ID_MAX = 50  # findings.finding_id is VARCHAR(50)


def suite_path(suite: str, corpus_dir: Path, injection_file: Path) -> Path:
    if suite == "injection":
        return injection_file
    if suite in SPLITS:
        return corpus_dir / f"{suite}.jsonl"
    raise SystemExit(f"unknown suite {suite!r}; choose from {', '.join(SUITES)}")


def expected_sha256(suite: str, corpus_dir: Path) -> Optional[str]:
    manifest_path = corpus_dir / "manifest.json"
    if not manifest_path.exists():
        return None
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if suite == "injection":
        return (manifest.get("injection") or {}).get("sha256")
    return ((manifest.get("files") or {}).get(f"{suite}.jsonl") or {}).get("sha256")


def verify(path: Path, want: Optional[str]) -> None:
    if not want:
        return
    got = hashlib.sha256(path.read_bytes()).hexdigest()
    if got != want:
        raise SystemExit(f"{path}: sha256 {got} does not match manifest {want}")


def read_records(path: Path, limit: Optional[int]) -> Iterator[Dict]:
    with path.open(encoding="utf-8") as fh:
        n = 0
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if limit is not None and n >= limit:
                return
            n += 1
            yield json.loads(line)


def to_finding(alert: Dict, tag: str, now_iso: str) -> Dict:
    finding = dict(alert)
    original = str(alert.get("finding_id") or alert.get("external_id") or "")
    if not original:
        raise ValueError("corpus alert without finding_id/external_id")
    finding["finding_id"] = f"{tag}-{original}"
    if len(finding["finding_id"]) > FINDING_ID_MAX:
        raise SystemExit(
            f"finding_id {finding['finding_id']!r} exceeds {FINDING_ID_MAX} chars; use a shorter --tag"
        )
    finding["external_id"] = f"{tag}-{alert.get('external_id') or original}"
    finding["timestamp"] = now_iso
    return finding


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--suites", default="dev", help="comma list of " + ",".join(SUITES))
    ap.add_argument("--limit", type=int, default=None, help="first N records per suite")
    ap.add_argument("--tag", required=True, help="id prefix, e.g. demo or replay-20261013")
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--batch", type=int, default=100)
    ap.add_argument("--corpus-dir", type=Path, default=CORPUS_DIR)
    ap.add_argument("--injection-file", type=Path, default=INJECTION_FILE)
    ap.add_argument("--no-verify", action="store_true", help="skip manifest sha256 check")
    args = ap.parse_args(argv)

    if args.batch < 1:
        raise SystemExit("--batch must be >= 1")
    tag = args.tag.strip()
    if not tag or any(c.isspace() for c in tag):
        raise SystemExit("--tag must be a non-empty token")

    now_iso = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    findings: List[Dict] = []
    labels: List[Dict] = []
    for suite in [s.strip() for s in args.suites.split(",") if s.strip()]:
        path = suite_path(suite, args.corpus_dir, args.injection_file)
        if not args.no_verify:
            verify(path, expected_sha256(suite, args.corpus_dir))
        for record in read_records(path, args.limit):
            finding = to_finding(record["alert"], tag, now_iso)
            findings.append(finding)
            lab = record.get("labels") or {}
            labels.append(
                {
                    "finding_id": finding["finding_id"],
                    "suite": suite,
                    "verdict": lab.get("verdict"),
                    "category": lab.get("category"),
                }
            )

    for i in range(0, len(findings), args.batch):
        chunk = findings[i : i + args.batch]
        out = args.out_dir / f"batch-{i // args.batch + 1:04d}.jsonl"
        out.write_text(
            "".join(json.dumps(f, sort_keys=True) + "\n" for f in chunk),
            encoding="utf-8",
        )
    (args.out_dir / "labels.jsonl").write_text(
        "".join(json.dumps(x, sort_keys=True) + "\n" for x in labels), encoding="utf-8"
    )
    print(len(findings))
    return 0


if __name__ == "__main__":
    sys.exit(main())
