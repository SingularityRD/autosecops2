"""``python -m evalkit {run,record,ci}``."""

from __future__ import annotations

import argparse
import asyncio
import logging
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from core.time import utcnow
from evalkit.backends import (
    DEFAULT_CASSETTE,
    Budget,
    BudgetExceeded,
    CassetteBackend,
    CassetteRecorder,
    LiveBackend,
    StubBackend,
    describe,
    resolve_live_target,
)
from evalkit.corpus import DEFAULT_SUITES, REPO_ROOT, load_suites, parse_suite_list
from evalkit.report import build_report, write_report
from evalkit.runner import CaseResult, run_cases
from evalkit.triage import (
    ADAPTER_VERSION,
    PROVENANCE_MODES,
    prompt_version,
    set_subject_guards,
)

logger = logging.getLogger("evalkit")


def _git_sha() -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        return out.stdout.strip() or None
    except Exception:  # noqa: BLE001 — a missing git is not a failed eval
        return None


def _now() -> str:
    return utcnow().replace(microsecond=0).isoformat()


def make_backend(args: argparse.Namespace):
    if args.backend == "stub":
        return StubBackend()
    if args.backend == "cassette":
        return CassetteBackend(Path(args.cassette))
    if args.backend == "live":
        if args.budget_usd is None:
            raise SystemExit("--backend live needs --budget-usd (a hard USD cap)")
        spec, model = resolve_live_target(args.provider_id, args.model)
        return LiveBackend(
            provider=spec,
            model=model,
            budget=Budget(args.budget_usd),
            max_tokens=args.max_tokens,
            allow_unpriced=args.allow_unpriced,
            unpriced_call_usd=args.unpriced_call_usd,
        )
    raise SystemExit(f"unknown backend {args.backend!r}")


async def execute(
    suites: Sequence[str],
    backend: Any,
    *,
    provenance: str = "off",
    concurrency: int = 4,
    limit: Optional[int] = None,
    verify: bool = True,
) -> Dict[str, List[CaseResult]]:
    version = prompt_version()
    cases = load_suites(suites, verify=verify, limit=limit)
    out: Dict[str, List[CaseResult]] = {}
    for suite in suites:
        out[suite] = await run_cases(
            cases[suite],
            backend,
            prompt_version=version,
            provenance=provenance,
            concurrency=concurrency,
        )
    return out


def run_meta(backend: Any, args: argparse.Namespace, started_at: str) -> Dict[str, Any]:
    meta = {
        "backend": describe(backend),
        "prompt_version": prompt_version(),
        "adapter": ADAPTER_VERSION,
        "provenance": args.provenance,
        "subject_guards": getattr(args, "subject_guards", "off"),
        "git_sha": _git_sha(),
        "started_at": started_at,
        "finished_at": _now(),
        "triggered_by": args.triggered_by,
        "limit": args.limit,
    }
    budget = getattr(backend, "budget", None) or getattr(
        getattr(backend, "inner", None), "budget", None
    )
    if budget is not None:
        meta["budget"] = {
            "cap_usd": budget.cap_usd,
            "spent_usd": round(budget.spent_usd, 6),
            "calls": budget.calls,
            "refused": budget.refused,
        }
    return meta


def _summary_line(report: Dict[str, Any]) -> str:
    parts = []
    for suite, rep in report["suites"].items():
        if "overall" in rep:
            o = rep["overall"]
            parts.append(
                f"{suite}: F1={o['f1']} P={o['precision']['value']} "
                f"R={o['recall']['value']} inc={o['inconclusive_rate']['value']}"
            )
        else:
            parts.append(f"{suite}: ASR={rep['asr']['value']}")
    return " | ".join(parts)


def cmd_run(args: argparse.Namespace) -> int:
    suites = parse_suite_list(args.suite)
    try:
        backend = make_backend(args)
    except BudgetExceeded as exc:
        print(f"evalkit: {exc}", file=sys.stderr)
        return 2
    recorder: Optional[CassetteRecorder] = None
    if args.record:
        recorder = CassetteRecorder(
            backend, Path(args.record), prompt_version=prompt_version()
        )
        backend = recorder

    set_subject_guards(getattr(args, "subject_guards", "off") == "on")
    started_at = _now()
    results = asyncio.run(
        execute(
            suites,
            backend,
            provenance=args.provenance,
            concurrency=args.concurrency,
            limit=args.limit,
            verify=not args.no_verify,
        )
    )
    if recorder is not None:
        n = recorder.save(merge=not args.overwrite)
        print(f"evalkit: cassette {recorder.path} holds {n} answers")

    report = build_report(results, run=run_meta(backend, args, started_at))
    out = Path(args.out or Path(tempfile.gettempdir()) / f"evalkit-{args.command}")
    paths = write_report(out, report, results)
    print(f"evalkit: {_summary_line(report)}")
    print(f"evalkit: report {paths['markdown']} / {paths['json']}")

    if args.db:
        from evalkit.db import write_all

        ids = write_all(results, report, tenant_id=args.tenant)
        print(f"evalkit: wrote eval_runs {ids}")

    errors = sum(rep["operational"]["errors"] for rep in report["suites"].values())
    misses = sum(
        rep["operational"]["cassette_misses"] for rep in report["suites"].values()
    )
    if args.max_errors is not None and errors > args.max_errors:
        print(
            f"evalkit: FAIL {errors} errored case(s) ({misses} cassette miss(es)) "
            f"> --max-errors {args.max_errors}",
            file=sys.stderr,
        )
        return 1
    return 0


def _add_common(p: argparse.ArgumentParser, *, backend_default: str) -> None:
    p.add_argument(
        "--suite",
        default=",".join(DEFAULT_SUITES),
        help="comma list of train,dev,test,test_unseen,injection "
        "(default: %(default)s)",
    )
    p.add_argument(
        "--backend", choices=("stub", "cassette", "live"), default=backend_default
    )
    p.add_argument("--cassette", default=str(DEFAULT_CASSETTE), help="replay file")
    p.add_argument(
        "--out",
        default=None,
        help="report directory (default: <tmp>/evalkit-<command>)",
    )
    p.add_argument("--limit", type=int, default=None, help="first N cases per suite")
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--provenance", choices=PROVENANCE_MODES, default="off")
    p.add_argument(
        "--subject-guards",
        choices=("off", "on"),
        default="off",
        help="withhold steering ADVERSARY-INFLUENCEABLE values (W0.30)",
    )
    p.add_argument("--no-verify", action="store_true", help="skip manifest sha256")
    p.add_argument("--max-errors", type=int, default=None)
    p.add_argument("--triggered-by", default="evalkit")
    live = p.add_argument_group("live backend")
    live.add_argument("--budget-usd", type=float, default=None)
    live.add_argument("--provider-id", default=None)
    live.add_argument("--model", default=None)
    live.add_argument("--max-tokens", type=int, default=2048)
    live.add_argument("--allow-unpriced", action="store_true")
    live.add_argument("--unpriced-call-usd", type=float, default=0.05)
    db = p.add_argument_group("database")
    db.add_argument("--db", action="store_true", help="write eval_runs/eval_results")
    db.add_argument("--tenant", default="default")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m evalkit",
        description="AutoSecOps offline triage evaluation",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="evaluate a backend and write a report")
    _add_common(run, backend_default="cassette")
    run.add_argument("--record", default=None, help="also record a cassette here")
    run.add_argument("--overwrite", action="store_true", help="replace, not merge")
    run.set_defaults(func=cmd_run)

    record = sub.add_parser("record", help="run a backend and record a cassette")
    _add_common(record, backend_default="stub")
    record.add_argument("--record", default=str(DEFAULT_CASSETTE))
    record.add_argument("--overwrite", action="store_true", help="replace, not merge")
    record.set_defaults(func=cmd_run)

    ci = sub.add_parser("ci", help="replay the committed cassette; fail on any miss")
    _add_common(ci, backend_default="cassette")
    ci.set_defaults(func=cmd_run, record=None, overwrite=False, max_errors=0)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    logging.basicConfig(
        level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s"
    )
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "ci":
        args.max_errors = 0 if args.max_errors is None else args.max_errors
        if args.backend != "cassette":
            parser.error("ci replays a cassette; use `run` for other backends")
    return int(args.func(args))
