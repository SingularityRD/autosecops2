"""Local model lane in the eval: candidate Ollama models compete, eval picks one.

``python -m evalkit.local_lane rank`` runs every candidate model (through
:class:`core.llm.local_lane.LocalModelLane`, i.e. Bifrost → Ollama with a
JSON-schema answer) over the same corpus slice, offline, and ranks them:

1. A candidate is *eligible* when its recall on the slice reaches the floor
   (``--min-recall``; default ``baseline`` = the deterministic stub's recall on
   the same slice, the floor any real model must beat) and its schema-error
   rate stays within ``--max-schema-error-rate``.
2. Eligible candidates are ordered by F1, then recall, then p50 latency, then
   name. The first one is the selection; ``--write-selection`` writes it where
   the runtime reads the default model (``LOCAL_LANE_SELECTION_FILE``).

The ``small_lane`` slice approximates what W2.2 routes to the small model: the
alerts whose severity is not ``critical`` (critical always goes to the verdict
lane). ``--slice all`` ranks on the whole split.

No candidate is eligible: exit 3 and no selection is written. The gateway is
not local (and ``--allow-nonlocal-gateway`` is off): exit 4 before any case
runs, the baseline included.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from core.llm.local_lane import SELECTION_FORMAT, LocalModelLane, NonLocalGateway
from core.time import utcnow
from evalkit.backends import BackendResult, StubBackend
from evalkit.cli import _git_sha
from evalkit.corpus import CORPUS_SPLITS, REPO_ROOT, Case, load_suites
from evalkit.report import build_report, write_report
from evalkit.runner import CaseResult, run_cases
from evalkit.triage import ADAPTER_VERSION, prompt_version

logger = logging.getLogger("evalkit.local_lane")

CANDIDATES_FILE = REPO_ROOT / "eval" / "suites" / "local_lane" / "candidates.json"
CANDIDATES_FORMAT = "autosecops.local_lane.candidates/v1"
RANKING_FORMAT = "autosecops.local_lane.ranking/v1"
SLICES = ("small_lane", "all")
SMALL_LANE_EXCLUDED_SEVERITIES = frozenset({"critical"})
SCHEMA_ERROR_PREFIX = "schema:"
EXIT_NO_ELIGIBLE = 3
EXIT_NONLOCAL_GATEWAY = 4


class LocalLaneBackend:
    """An evalkit backend over a :class:`LocalModelLane`.

    A local model has no per-call price, so ``cost_usd`` is ``0.0`` (known
    zero), not ``None`` (unknown).
    """

    name = "local_lane"

    def __init__(self, lane: Any):
        self.lane = lane
        self.model = lane.model

    async def complete(self, prompt: str) -> BackendResult:
        answer = await self.lane.triage(prompt)
        return BackendResult(
            content=answer.content,
            model=answer.model,
            cost_usd=0.0,
            latency_ms=answer.latency_ms,
            error=answer.error,
        )


def slice_cases(cases: Sequence[Case], name: str) -> List[Case]:
    if name == "all":
        return list(cases)
    if name == "small_lane":
        return [
            c
            for c in cases
            if str(c.alert.get("severity") or "").lower()
            not in SMALL_LANE_EXCLUDED_SEVERITIES
        ]
    raise ValueError(f"unknown slice {name!r}; expected one of {SLICES}")


def load_candidates(path: Path) -> List[str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("format") != CANDIDATES_FORMAT:
        raise ValueError(f"{path}: not a {CANDIDATES_FORMAT} file")
    models = [str(c["model"]).strip() for c in data.get("candidates") or []]
    return [m for m in dict.fromkeys(models) if m]


def summarize(results: Sequence[CaseResult], suite: str) -> Dict[str, Any]:
    """The numbers the ranking uses, from evalkit's own report."""
    rep = build_report({suite: results}, run={})["suites"][suite]
    overall, ops = rep["overall"], rep["operational"]
    n = overall["n"]
    schema_errors = sum(
        1 for r in results if (r.error or "").startswith(SCHEMA_ERROR_PREFIX)
    )
    return {
        "n": n,
        "n_malicious": overall["n_malicious"],
        "recall": overall["recall"]["value"],
        "recall_lower95": overall["recall"].get("lower95"),
        "precision": overall["precision"]["value"],
        "f1": overall["f1"],
        "false_benign_rate": overall["false_benign_rate"]["value"],
        "inconclusive_rate": overall["inconclusive_rate"]["value"],
        "errors": ops["errors"],
        "schema_errors": schema_errors,
        "schema_error_rate": (schema_errors / n) if n else None,
        "latency_p50_ms": ops["latency_ms"]["p50"],
        "latency_p95_ms": ops["latency_ms"]["p95"],
    }


def _num(value: Optional[float], default: float) -> float:
    return default if value is None else float(value)


def rank(
    metrics: Dict[str, Dict[str, Any]],
    *,
    min_recall: float,
    max_schema_error_rate: float,
) -> List[Dict[str, Any]]:
    """Every candidate with ``eligible``/``reasons``; eligible ones first, best first."""
    rows = []
    for model, m in metrics.items():
        reasons = []
        if m["n"] == 0:
            reasons.append("no cases in slice")
        if _num(m["recall"], 0.0) < min_recall:
            reasons.append(f"recall {_num(m['recall'], 0.0):.3f} < {min_recall:.3f}")
        if _num(m["schema_error_rate"], 1.0) > max_schema_error_rate:
            reasons.append(
                f"schema error rate {_num(m['schema_error_rate'], 1.0):.3f} "
                f"> {max_schema_error_rate:.3f}"
            )
        rows.append({"model": model, "eligible": not reasons, "reasons": reasons, **m})

    def key(row: Dict[str, Any]):
        return (
            not row["eligible"],
            -_num(row["f1"], 0.0),
            -_num(row["recall"], 0.0),
            _num(row["latency_p50_ms"], float("inf")),
            row["model"],
        )

    rows.sort(key=key)
    for i, row in enumerate(rows, 1):
        row["rank"] = i if row["eligible"] else None
    return rows


def _safe(model: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", model)


def to_markdown(ranking: Dict[str, Any]) -> str:
    def pct(v: Any) -> str:
        return "–" if v is None else f"{100 * v:.1f}%"

    lines = [
        "# AutoSecOps local model lane — candidate ranking",
        "",
        f"- Suite: `{ranking['suite']}`, slice: `{ranking['slice']}` "
        f"({ranking['n_cases']} cases)",
        f"- Recall floor: {pct(ranking['criteria']['min_recall'])} "
        f"({ranking['criteria']['min_recall_source']}); schema error ceiling: "
        f"{pct(ranking['criteria']['max_schema_error_rate'])}",
        f"- Selected: `{ranking['selected'] or 'none'}`",
        "",
        "| # | Model | Recall | F1 | Precision | False benign | Schema err | p50 ms | Eligible |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for row in ranking["candidates"]:
        f1 = "–" if row["f1"] is None else f"{row['f1']:.3f}"
        lines.append(
            f"| {row['rank'] or '–'} | `{row['model']}` | {pct(row['recall'])} | "
            f"{f1} | "
            f"{pct(row['precision'])} | {pct(row['false_benign_rate'])} | "
            f"{pct(row['schema_error_rate'])} | "
            f"{'–' if row['latency_p50_ms'] is None else row['latency_p50_ms']} | "
            f"{'yes' if row['eligible'] else '; '.join(row['reasons'])} |"
        )
    return "\n".join(lines) + "\n"


def _now() -> str:
    return utcnow().replace(microsecond=0).isoformat()


async def evaluate(
    cases: Sequence[Case],
    backend: Any,
    *,
    concurrency: int,
) -> List[CaseResult]:
    return await run_cases(
        cases, backend, prompt_version=prompt_version(), concurrency=concurrency
    )


def cmd_rank(args: argparse.Namespace) -> int:
    if args.candidates:
        candidates = [m.strip() for m in args.candidates.split(",") if m.strip()]
    else:
        candidates = load_candidates(Path(args.candidates_file))
    if not candidates:
        print("evalkit.local_lane: no candidate models", file=sys.stderr)
        return 2
    if args.suite not in CORPUS_SPLITS:
        print(
            f"evalkit.local_lane: --suite must be one of {CORPUS_SPLITS}",
            file=sys.stderr,
        )
        return 2
    if args.bifrost_url is None:
        from core.config import get_settings

        args.bifrost_url = get_settings().bifrost_url

    # Every lane is built (and so the gateway checked) before any work: a
    # non-local gateway or a bad model name fails here, not after the baseline.
    try:
        lanes = [
            LocalModelLane(
                model,
                bifrost_url=args.bifrost_url,
                timeout_s=args.timeout_s,
                max_tokens=args.max_tokens,
                allow_nonlocal_gateway=args.allow_nonlocal_gateway,
            )
            for model in candidates
        ]
    except NonLocalGateway as exc:
        print(f"evalkit.local_lane: {exc}", file=sys.stderr)
        return EXIT_NONLOCAL_GATEWAY
    except ValueError as exc:
        print(f"evalkit.local_lane: {exc}", file=sys.stderr)
        return 2

    loaded = load_suites([args.suite], verify=not args.no_verify)[args.suite]
    cases = slice_cases(loaded, args.slice)
    if args.limit is not None:
        cases = cases[: args.limit]

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    started_at = _now()

    baseline = summarize(
        asyncio.run(evaluate(cases, StubBackend(), concurrency=args.concurrency)),
        args.suite,
    )
    if args.min_recall == "baseline":
        min_recall = _num(baseline["recall"], 0.0)
        source = "stub lexical baseline on the same slice"
    else:
        min_recall = float(args.min_recall)
        source = "explicit"

    metrics: Dict[str, Dict[str, Any]] = {}
    for lane in lanes:
        model = lane.bare_model
        backend = LocalLaneBackend(lane)
        results = asyncio.run(evaluate(cases, backend, concurrency=args.concurrency))
        report = build_report(
            {args.suite: results},
            run={
                "backend": {"backend": backend.name, "model": backend.model},
                "prompt_version": prompt_version(),
                "adapter": ADAPTER_VERSION,
                "provenance": "off",
                "git_sha": _git_sha(),
                "triggered_by": "evalkit.local_lane",
                "slice": args.slice,
                "started_at": started_at,
                "finished_at": _now(),
            },
        )
        write_report(out / _safe(model), report, {args.suite: results})
        metrics[lane.model] = summarize(results, args.suite)
        m = metrics[lane.model]
        print(
            f"evalkit.local_lane: {lane.model} recall={m['recall']} f1={m['f1']} "
            f"schema_err={m['schema_errors']}/{m['n']} p50={m['latency_p50_ms']}ms"
        )

    rows = rank(
        metrics,
        min_recall=min_recall,
        max_schema_error_rate=args.max_schema_error_rate,
    )
    winner = rows[0] if rows and rows[0]["eligible"] else None
    ranking = {
        "format": RANKING_FORMAT,
        "suite": args.suite,
        "slice": args.slice,
        "n_cases": len(cases),
        "prompt_version": prompt_version(),
        "bifrost_url": args.bifrost_url,
        "started_at": started_at,
        "finished_at": _now(),
        "criteria": {
            "min_recall": min_recall,
            "min_recall_source": source,
            "max_schema_error_rate": args.max_schema_error_rate,
            "order": ["f1 desc", "recall desc", "latency_p50_ms asc", "model"],
        },
        "baseline": baseline,
        "selected": winner["model"] if winner else None,
        "candidates": rows,
    }
    (out / "ranking.json").write_text(
        json.dumps(ranking, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "ranking.md").write_text(to_markdown(ranking), encoding="utf-8")
    print(f"evalkit.local_lane: ranking {out / 'ranking.md'} / {out / 'ranking.json'}")

    if winner is None:
        print(
            "evalkit.local_lane: no candidate met the recall floor and schema "
            "ceiling; no selection written",
            file=sys.stderr,
        )
        return EXIT_NO_ELIGIBLE

    print(f"evalkit.local_lane: selected {winner['model']}")
    if args.write_selection:
        path = Path(args.write_selection)
        path.parent.mkdir(parents=True, exist_ok=True)
        selection = {
            "format": SELECTION_FORMAT,
            "provider": "ollama",
            "model": winner["model"].split("/", 1)[1],
            "selected_at": _now(),
            "suite": args.suite,
            "slice": args.slice,
            "prompt_version": prompt_version(),
            "criteria": ranking["criteria"],
            "metrics": {k: v for k, v in winner.items() if k not in ("reasons",)},
            "ranking": [r["model"] for r in rows if r["eligible"]],
        }
        path.write_text(
            json.dumps(selection, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"evalkit.local_lane: selection written to {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m evalkit.local_lane",
        description="AutoSecOps local model lane: rank candidate Ollama models",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    r = sub.add_parser("rank", help="run every candidate on the corpus and rank")
    src = r.add_mutually_exclusive_group()
    src.add_argument("--candidates", default=None, help="comma list of Ollama models")
    src.add_argument("--candidates-file", default=str(CANDIDATES_FILE))
    r.add_argument("--suite", default="dev", help="corpus split (default: dev)")
    r.add_argument("--slice", choices=SLICES, default="small_lane")
    r.add_argument("--limit", type=int, default=None, help="first N cases of the slice")
    r.add_argument(
        "--min-recall",
        default="baseline",
        help="recall floor in [0,1], or 'baseline' (default: the stub's recall)",
    )
    r.add_argument("--max-schema-error-rate", type=float, default=0.02)
    r.add_argument(
        "--bifrost-url", default=None, help="gateway (default: BIFROST_URL setting)"
    )
    r.add_argument("--allow-nonlocal-gateway", action="store_true")
    r.add_argument("--timeout-s", type=float, default=120.0)
    r.add_argument("--max-tokens", type=int, default=512)
    r.add_argument("--concurrency", type=int, default=2)
    r.add_argument("--no-verify", action="store_true", help="skip manifest sha256")
    r.add_argument(
        "--out",
        default=str(Path(tempfile.gettempdir()) / "evalkit-local-lane"),
        help="report directory (default: %(default)s)",
    )
    r.add_argument(
        "--write-selection",
        default=None,
        help="write the winner here (runtime default: "
        "eval/suites/local_lane/selection.json)",
    )
    r.set_defaults(func=cmd_rank)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    logging.basicConfig(
        level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s"
    )
    args = build_parser().parse_args(argv)
    if args.min_recall != "baseline":
        try:
            value = float(args.min_recall)
        except ValueError:
            value = -1.0
        if not 0.0 <= value <= 1.0:
            print(
                "evalkit.local_lane: --min-recall must be in [0,1] or 'baseline'",
                file=sys.stderr,
            )
            return 2
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
