"""JSON and Markdown reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from evalkit.corpus import INJECTION_SUITE
from evalkit.runner import CaseResult
from evalkit.scoring import case_passed, corpus_report, injection_report

REPORT_SCHEMA = "evalkit.report/v1"


def suite_report(suite: str, results: Sequence[CaseResult]) -> Dict[str, Any]:
    if suite == INJECTION_SUITE:
        return injection_report(results)
    return corpus_report(results)


def build_report(
    results_by_suite: Mapping[str, Sequence[CaseResult]],
    *,
    run: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema": REPORT_SCHEMA,
        "run": run,
        "suites": {s: suite_report(s, rs) for s, rs in results_by_suite.items()},
    }


def case_rows(results: Sequence[CaseResult]) -> List[Dict[str, Any]]:
    """Per-case detail (written as cases.jsonl next to the report)."""
    rows = []
    for r in results:
        rows.append(
            {
                "case_id": r.case_id,
                "suite": r.case.suite,
                "template_id": r.case.meta.get("template_id"),
                "expected_verdict": r.expected_verdict,
                "expected_category": r.expected_category,
                "actual_verdict": r.actual_verdict,
                "actual_category": r.actual_category,
                "confidence": r.confidence,
                "raw_action": r.raw_action,
                "raw_category": r.raw_category,
                "recommended_action": r.recommended_action,
                "passed": case_passed(r),
                "latency_ms": r.latency_ms,
                "cost_usd": r.cost_usd,
                "error": r.error,
                "prompt_sha256": r.prompt_sha256,
            }
        )
    return rows


# --------------------------------------------------------------------------
# markdown
# --------------------------------------------------------------------------


def _pct(rate: Optional[Dict[str, Any]], key: str = "value") -> str:
    if not rate or rate.get(key) is None:
        return "–"
    return f"{100 * rate[key]:.1f}%"


def _num(value: Any, fmt: str = "{:.3f}") -> str:
    return "–" if value is None else fmt.format(value)


def _bound(rate: Dict[str, Any]) -> str:
    key = "lower95" if "lower95" in rate and "upper95" not in rate else "upper95"
    sign = "≥" if key == "lower95" else "≤"
    return f"{_pct(rate)} ({sign}{_pct(rate, key)})"


def _corpus_md(name: str, rep: Dict[str, Any]) -> List[str]:
    lines = [
        f"## Split `{name}`",
        "",
        "Positive class `malicious`. Parantez içi: tek yönlü %95 Clopper–Pearson "
        "sınırı (≥ alt sınır, ≤ üst sınır).",
        "",
        "| Kategori | n | Precision | Recall | F1 | Inconclusive | False-benign | Kategori doğruluğu |",
        "|---|---|---|---|---|---|---|---|",
    ]
    rows = [("**tümü**", rep["overall"])] + list(rep["by_category"].items())
    for cat, m in rows:
        lines.append(
            f"| {cat} | {m['n']} | {_bound(m['precision'])} | {_bound(m['recall'])} | "
            f"{_num(m['f1'])} | {_bound(m['inconclusive_rate'])} | "
            f"{_bound(m['false_benign_rate'])} | {_pct(m['category_accuracy'])} |"
        )
    lines += [""] + _ops_md(rep["operational"])
    return lines


def _ops_md(op: Dict[str, Any]) -> List[str]:
    cost = op["cost"]
    lat = op["latency_ms"]
    per_alert = cost["per_alert_usd"]
    return [
        f"- Maliyet/uyarı: {_num(per_alert, '${:.6f}')} "
        f"(fiyatlı {cost['priced_n']}, fiyatsız {cost['unpriced_n']}); "
        f"toplam {_num(cost['total_usd'], '${:.4f}')}",
        f"- Gecikme: p50 {_num(lat['p50'], '{:.0f} ms')}, "
        f"p95 {_num(lat['p95'], '{:.0f} ms')} (n={lat['n']})",
        f"- Hata: {op['errors']}, kaset ıskası: {op['cassette_misses']}, "
        f"provenance düşürmesi (enforce olsaydı): {op['provenance_downgrades']}",
        f"- Ham eylemler: {', '.join(f'{k}={v}' for k, v in op['raw_actions'].items())}",
        "",
    ]


def _injection_md(rep: Dict[str, Any]) -> List[str]:
    asr = rep["asr"]
    lines = [
        "## Enjeksiyon paketi",
        "",
        f"Genel saldırı başarı oranı (ASR): **{_pct(asr)}** "
        f"({asr['k']}/{asr['n']}; %95 aralık {_pct(asr, 'lower95')}–{_pct(asr, 'upper95')})",
        "",
        "| Hedef | n | ASR (≤ üst sınır) |",
        "|---|---|---|",
    ]
    for goal, g in rep["by_goal"].items():
        lines.append(f"| {goal} | {g['asr']['n']} | {_bound(g['asr'])} |")
        for field, f in g["by_injected_field"].items():
            lines.append(f"| &nbsp;&nbsp;alan `{field}` | {f['n']} | {_bound(f)} |")
        for kind, f in (g.get("by_requested_action") or {}).items():
            lines.append(f"| &nbsp;&nbsp;istenen `{kind}` | {f['n']} | {_bound(f)} |")
        if "asr_on_benign_base" in g:
            b = g["asr_on_benign_base"]
            lines.append(
                f"| &nbsp;&nbsp;zararsız temel uyarıda | {b['n']} | {_bound(b)} |"
            )
    v = rep["verdict"]
    lines += [
        "",
        f"Alttaki kararın korunması: doğruluk {_bound(v['accuracy'])}, "
        f"recall {_bound(v['recall'])}, false-benign {_bound(v['false_benign_rate'])}.",
        "",
    ] + _ops_md(rep["operational"])
    return lines


def to_markdown(report: Dict[str, Any]) -> str:
    run = report["run"]
    lines = [
        "# AutoSecOps triage değerlendirme raporu",
        "",
        "| | |",
        "|---|---|",
        f"| Arka uç | `{run['backend']['backend']}` |",
        f"| Model | `{run['backend']['model']}` |",
        f"| İstem sürümü | `{run['prompt_version']}` |",
        f"| Karar eşlemesi | `{run['adapter']}` |",
        f"| Provenance | `{run['provenance']}` |",
        f"| Git | `{run.get('git_sha') or '-'}` |",
        f"| Başlangıç | {run.get('started_at') or '-'} |",
        "",
        "`test` görülen senaryoların varyantlarıdır; genelleme için `test_unseen` "
        "skorunu esas alın (bkz. eval/corpus/v1/DATASHEET.md). Korpus sınıfları "
        "dengelidir; kesinlik gerçek SOC oranlarına göre yeniden ağırlıklandırılmalıdır.",
        "",
    ]
    for suite, rep in report["suites"].items():
        if suite == INJECTION_SUITE:
            lines += _injection_md(rep)
        else:
            lines += _corpus_md(suite, rep)
    return "\n".join(lines).rstrip() + "\n"


def write_report(
    out_dir: Path,
    report: Dict[str, Any],
    results_by_suite: Mapping[str, Sequence[CaseResult]],
) -> Dict[str, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": out_dir / "report.json",
        "markdown": out_dir / "report.md",
        "cases": out_dir / "cases.jsonl",
    }
    paths["json"].write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    paths["markdown"].write_text(to_markdown(report), encoding="utf-8")
    with paths["cases"].open("w", encoding="utf-8") as fh:
        for rs in results_by_suite.values():
            for row in case_rows(rs):
                fh.write(json.dumps(row, sort_keys=True) + "\n")
    return paths
