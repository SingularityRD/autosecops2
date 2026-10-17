"""Load the v1 corpus splits and the injection suite.

Each JSONL row is ``{"alert": {...}, "labels": {...}, "meta": {...}}``. Only
``alert`` ever reaches the model; ``labels`` and ``meta`` stay with the scorer.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_DIR = REPO_ROOT / "eval" / "corpus" / "v1"
INJECTION_PATH = REPO_ROOT / "eval" / "suites" / "injection" / "v1.jsonl"

CORPUS_SPLITS = ("train", "dev", "test", "test_unseen")
INJECTION_SUITE = "injection"
SUITES = CORPUS_SPLITS + (INJECTION_SUITE,)
# What CI replays: the held-out splits and the injection suite.
DEFAULT_SUITES = ("test", "test_unseen", INJECTION_SUITE)
# W0.49: a customer's own labelled alerts (``--cases FILE``), not in the manifest.
CUSTOMER_SUITE = "customer"
VERDICT_LABELS = ("malicious", "benign", "inconclusive")


@dataclass(frozen=True)
class Case:
    """One labelled alert."""

    case_id: str
    suite: str
    alert: Dict[str, Any]
    labels: Dict[str, Any]
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def expected_verdict(self) -> str:
        return self.labels["verdict"]

    @property
    def expected_category(self) -> Optional[str]:
        return self.labels.get("category")


class CorpusError(ValueError):
    """The corpus on disk does not match what the harness expects."""


def suite_path(suite: str, corpus_dir: Path = CORPUS_DIR) -> Path:
    if suite == INJECTION_SUITE:
        return INJECTION_PATH
    if suite not in CORPUS_SPLITS:
        raise CorpusError(f"unknown suite {suite!r}; expected one of {SUITES}")
    return corpus_dir / f"{suite}.jsonl"


def suite_db_name(suite: str) -> str:
    """The ``eval_runs.suite`` value for a suite."""
    if suite == CUSTOMER_SUITE:
        return CUSTOMER_SUITE
    return "injection-v1" if suite == INJECTION_SUITE else f"corpus-v1/{suite}"


def _parse_rows(path: Path, suite: str) -> List[Case]:
    cases: List[Case] = []
    seen = set()
    with path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                alert = row["alert"]
                labels = row["labels"]
            except (ValueError, KeyError, TypeError) as exc:
                raise CorpusError(f"{path}:{lineno}: malformed row ({exc})") from exc
            case_id = alert.get("finding_id")
            if not case_id:
                raise CorpusError(f"{path}:{lineno}: alert has no finding_id")
            if case_id in seen:
                raise CorpusError(f"{path}:{lineno}: duplicate finding_id {case_id}")
            seen.add(case_id)
            cases.append(
                Case(
                    case_id=case_id,
                    suite=suite,
                    alert=alert,
                    labels=labels,
                    meta=row.get("meta") or {},
                )
            )
    return cases


def load_cases_file(path: Path, *, limit: Optional[int] = None) -> List[Case]:
    """A customer's labelled alerts (W0.49): the corpus row shape, with at least
    ``labels.verdict``. No manifest; the report records the file's sha256."""
    path = Path(path)
    if not path.is_file():
        raise CorpusError(f"{path}: no such file")
    cases = _parse_rows(path, CUSTOMER_SUITE)
    for case in cases:
        verdict = case.labels.get("verdict") if isinstance(case.labels, dict) else None
        if verdict not in VERDICT_LABELS:
            raise CorpusError(
                f"{path}: case {case.case_id} label verdict must be one of "
                f"{', '.join(VERDICT_LABELS)}"
            )
    if not cases:
        raise CorpusError(f"{path}: no cases")
    return cases[:limit] if limit is not None else cases


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(corpus_dir: Path = CORPUS_DIR) -> Dict[str, Any]:
    return json.loads((corpus_dir / "manifest.json").read_text(encoding="utf-8"))


def expected_sha256(suite: str, corpus_dir: Path = CORPUS_DIR) -> Optional[str]:
    manifest = load_manifest(corpus_dir)
    if suite == INJECTION_SUITE:
        return (manifest.get("injection") or {}).get("sha256")
    return ((manifest.get("files") or {}).get(f"{suite}.jsonl") or {}).get("sha256")


def load_suite(
    suite: str,
    *,
    corpus_dir: Path = CORPUS_DIR,
    verify: bool = True,
    limit: Optional[int] = None,
) -> List[Case]:
    """Every case of one suite, in file order.

    ``verify`` checks the file against the manifest sha256 so a report can
    never silently describe a different corpus than the one it names.
    ``limit`` keeps the first N cases (smoke runs only).
    """
    path = suite_path(suite, corpus_dir)
    if verify:
        want = expected_sha256(suite, corpus_dir)
        if want and sha256_file(path) != want:
            raise CorpusError(f"{path} does not match manifest sha256 {want}")
    cases = _parse_rows(path, suite)
    return cases[:limit] if limit is not None else cases


def load_suites(
    suites: Iterable[str],
    *,
    corpus_dir: Path = CORPUS_DIR,
    verify: bool = True,
    limit: Optional[int] = None,
) -> Dict[str, List[Case]]:
    return {
        s: load_suite(s, corpus_dir=corpus_dir, verify=verify, limit=limit)
        for s in suites
    }


def parse_suite_list(value: str) -> Sequence[str]:
    names = [s.strip() for s in value.split(",") if s.strip()]
    for s in names:
        if s not in SUITES:
            raise CorpusError(f"unknown suite {s!r}; expected one of {SUITES}")
    return tuple(dict.fromkeys(names))
