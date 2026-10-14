"""Ingest-to-verdict latency and loss accounting, read from the database.

Everything here is measured from database timestamps, so the numbers do not
depend on the load generator's clock (which on staging is another machine):

* **ingest** -- ``findings.created_at``: the moment the daemon (webhook path)
  or the API (``/api/ingest/ingest-string`` path) stored the row. Naive UTC
  (``core.time.utcnow``).
* **verdict**, by the lane the daemon chose (``alert_lane_decisions``, the
  first decision for the finding):

  ``rules``        ``alert_lane_decisions.decided_at``: the outcome is settled
                   deterministically at decision time, no model is called.
  ``small_model``  ``findings.ai_enrichment->'ai_triage'->>'timestamp'``: the
                   moment the triage verdict was applied (naive UTC). A
                   re-triage (backfill, restarted daemon) overwrites that
                   timestamp, so the *first* value ever read for the finding
                   is kept (``FirstTriage``, fed by every poll of the run:
                   the backlog sampler and ``wait_settled``); latency is
                   measured to the first verdict, not the last.
  ``verdict``      ``workflow_runs.finished_at`` of the decision's
                   ``verdict_run_id``. Until a verdict-run work package wires
                   the enqueuer this lane degrades to ``small_model``
                   (``degraded_from='verdict'``, ``deferred_verdict``) and is
                   reported under ``small_model``; the count of such findings
                   is in ``deferred_verdict``.
  ``unrouted``     no decision row (``ALERT_LANES_ENABLED`` off): triage time,
                   as for ``small_model``.

The plan's SLO table names ``alert_routes`` as the source; in this code base
``alert_routes`` is the outbound-notification routing table (47_*.sql) and the
lane decision lives in ``alert_lane_decisions`` (56_*.sql), which is what is
read here.

Loss and duplication:

* **lost** -- a finding the sender was told was accepted (HTTP 200 counting
  it) that never reached ``findings``.
* **unsettled** -- stored but with no verdict by the end of the wait.
* **duplicate rows** -- more than one ``findings`` row for one sent alert
  (matched on ``external_id`` inside the run's id prefix); the primary key on
  ``finding_id`` makes this zero by construction unless an id was rewritten.
* **re-decided** -- findings with more than one lane decision. Processing is
  at-least-once (the backfill re-routes a finding whose triage failed, a
  restarted daemon re-reads unsettled rows), so this is reported, not failed.
* **double processed** -- findings with a lane decision made *after* the
  finding already had its verdict (``last decision > verdict + slack``): the
  pipeline processed a settled finding again (two active daemons, a replay of
  something already stored and decided, a backfill that does not skip settled
  rows). Unlike ``re_decided`` this is not explained by at-least-once retries
  of unfinished work; the chaos runner fails a scenario when it exceeds the
  scenario's threshold (default 0). The ``findings`` primary key makes
  duplicate *rows* impossible, so this is the signal that catches duplicate
  *processing*.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------
# SLO table (docs/wp/NORTHSTAR_PLAN.md, "SLO'lar"); seconds.
# --------------------------------------------------------------------------

SLO_P95_SECONDS: Dict[str, float] = {
    "rules": 5.0,
    "small_model": 60.0,
    "verdict": 600.0,
}
SLO_LOSS = 0

LANES = ("rules", "small_model", "verdict", "unrouted")


def percentile(values: Sequence[float], q: float) -> Optional[float]:
    """Linear-interpolated percentile (numpy's default), ``q`` in [0, 100]."""
    if not values:
        return None
    if not 0 <= q <= 100:
        raise ValueError("q must be within [0, 100]")
    data = sorted(values)
    if len(data) == 1:
        return float(data[0])
    pos = (len(data) - 1) * q / 100.0
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return float(data[lo])
    return float(data[lo] + (data[hi] - data[lo]) * (pos - lo))


@dataclass
class FindingRow:
    finding_id: str
    external_id: Optional[str]
    created_epoch: float
    lane: Optional[str]  # first decision's lane, None when unrouted
    decided_epoch: Optional[float]
    degraded_from: Optional[str]
    deferred_verdict: bool
    triage_epoch: Optional[float]
    triage_error: Optional[str]
    verdict_finished_epoch: Optional[float]
    decisions: int
    has_enrichment: bool
    # Earliest rules-lane decision, when a later re-decision (backfill) chose
    # rules after a first non-rules one, e.g. a suppression rule younger than
    # the daemon's rule cache.
    rules_epoch: Optional[float] = None
    # Latest lane decision (any lane); with ``decisions > 1`` it shows whether
    # the finding was routed again after it had settled (double processing).
    last_decided_epoch: Optional[float] = None
    # The stored ai_triage timestamp moved after it was first read: a later
    # re-triage overwrote it (``triage_epoch`` keeps the first value).
    retriaged: bool = False


def settlement(row: FindingRow) -> Tuple[Optional[float], str]:
    """``(when, lane)`` of the finding's verdict; ``when`` is None while unsettled.

    The lane is the one that settled the finding: the first decision's lane,
    unless a rules decision settled it earlier than that lane did (a finding
    first routed to the model and re-routed to a rule by the backfill counts as
    a rules-lane finding settled at the rule's decision).
    """
    first = row.lane or "unrouted"
    options: List[Tuple[float, str]] = []
    rules_at = row.rules_epoch
    if rules_at is None and first == "rules":
        rules_at = row.decided_epoch
    if rules_at is not None:
        options.append((rules_at, "rules"))
    if first == "verdict":
        if row.verdict_finished_epoch is not None:
            options.append((row.verdict_finished_epoch, "verdict"))
    elif first != "rules" and row.triage_epoch is not None:
        options.append((row.triage_epoch, first))
    if not options:
        return None, first
    return min(options)


def lane_of(row: FindingRow) -> str:
    return settlement(row)[1]


def verdict_epoch(row: FindingRow) -> Optional[float]:
    """When the finding got its verdict, by lane; None while unsettled."""
    return settlement(row)[0]


def is_settled(row: FindingRow) -> bool:
    return verdict_epoch(row) is not None


@dataclass
class LaneStats:
    lane: str
    count: int
    settled: int
    p50: Optional[float]
    p95: Optional[float]
    p99: Optional[float]
    max: Optional[float]


def lane_stats(rows: Iterable[FindingRow]) -> Dict[str, LaneStats]:
    buckets: Dict[str, List[FindingRow]] = {}
    for row in rows:
        buckets.setdefault(lane_of(row), []).append(row)
    out: Dict[str, LaneStats] = {}
    for lane in LANES:
        group = buckets.get(lane, [])
        lat = [
            max(0.0, v - r.created_epoch)
            for r in group
            if (v := verdict_epoch(r)) is not None
        ]
        out[lane] = LaneStats(
            lane=lane,
            count=len(group),
            settled=len(lat),
            p50=percentile(lat, 50),
            p95=percentile(lat, 95),
            p99=percentile(lat, 99),
            max=max(lat) if lat else None,
        )
    return out


@dataclass
class SloCheck:
    name: str
    target: str
    measured: str
    status: str  # PASS / FAIL / n/a


def compare_slo(
    stats: Dict[str, LaneStats], lost: int, *, min_samples: int = 20
) -> List[SloCheck]:
    """The SLO table beside what was measured.

    A lane with fewer than ``min_samples`` settled findings is ``n/a``: a p95
    over a handful of points is not a measurement of the SLO.
    """
    checks: List[SloCheck] = []
    names = {
        "rules": "Ingest->verdict, rules lane",
        "small_model": "Ingest->verdict, small model lane",
        "verdict": "Ingest->verdict, verdict run",
    }
    for lane, target in SLO_P95_SECONDS.items():
        st = stats.get(lane)
        if st is None or st.settled == 0:
            checks.append(SloCheck(names[lane], f"p95 < {target:g} s", "-", "n/a"))
            continue
        measured = f"p95 {st.p95:.2f} s (n={st.settled})"
        unsettled = st.count - st.settled
        if unsettled:
            measured += f", {unsettled} unsettled"
        if st.settled < min_samples:
            status = "n/a"
            measured += f" [< {min_samples} samples]"
        else:
            status = "PASS" if (st.p95 < target and not unsettled) else "FAIL"
        checks.append(SloCheck(names[lane], f"p95 < {target:g} s", measured, status))
    checks.append(
        SloCheck(
            "Alert loss",
            f"{SLO_LOSS}",
            str(lost),
            "PASS" if lost <= SLO_LOSS else "FAIL",
        )
    )
    return checks


@dataclass
class Accounting:
    sent: int
    accepted: int
    stored: int
    lost: List[str]
    unexpected: List[str]
    duplicate_rows: int
    unsettled: List[str]
    re_decided: int
    deferred_verdict: int
    triage_errors_open: int
    double_processed: List[str] = field(default_factory=list)
    retriaged: int = 0


# Clock slack between the decision writer and the triage writer (both are the
# daemon's ``utcnow`` today; on staging they may be different pods).
DOUBLE_SLACK_SECONDS = 2.0


def is_double_processed(row: FindingRow, slack: float = DOUBLE_SLACK_SECONDS) -> bool:
    """A lane decision was made after the finding already had its verdict."""
    if row.decisions < 2 or row.last_decided_epoch is None:
        return False
    settled = verdict_epoch(row)
    return settled is not None and row.last_decided_epoch > settled + slack


def account(
    accepted_ids: Iterable[str],
    sent_ids: Iterable[str],
    rows: Sequence[FindingRow],
    *,
    double_slack: float = DOUBLE_SLACK_SECONDS,
) -> Accounting:
    accepted = set(accepted_ids)
    sent = set(sent_ids)
    stored = {r.finding_id for r in rows}
    ext_count: Dict[str, int] = {}
    for r in rows:
        if r.external_id:
            ext_count[r.external_id] = ext_count.get(r.external_id, 0) + 1
    return Accounting(
        sent=len(sent),
        accepted=len(accepted),
        stored=len(stored),
        lost=sorted(accepted - stored),
        unexpected=sorted(stored - sent),
        duplicate_rows=sum(n - 1 for n in ext_count.values() if n > 1),
        unsettled=sorted(r.finding_id for r in rows if not is_settled(r)),
        re_decided=sum(1 for r in rows if r.decisions > 1),
        deferred_verdict=sum(1 for r in rows if r.deferred_verdict),
        triage_errors_open=sum(
            1 for r in rows if r.triage_error and r.triage_epoch is None
        ),
        double_processed=sorted(
            r.finding_id for r in rows if is_double_processed(r, double_slack)
        ),
        retriaged=sum(1 for r in rows if r.retriaged),
    )


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------

# One row per finding of the run. ``created_at`` and the ai_triage timestamp
# are naive UTC; decided_at is timestamptz.
_ROWS_SQL = """
WITH d AS (
    SELECT finding_id,
           count(*) AS n,
           (array_agg(lane ORDER BY decided_at, id))[1] AS lane,
           (array_agg(decided_at ORDER BY decided_at, id))[1] AS decided_at,
           (array_agg(degraded_from ORDER BY decided_at, id))[1] AS degraded_from,
           bool_or(deferred_verdict) AS deferred_verdict,
           (array_agg(verdict_run_id ORDER BY decided_at, id))[1] AS verdict_run_id,
           min(decided_at) FILTER (WHERE lane = 'rules') AS rules_decided_at,
           max(decided_at) AS last_decided_at
    FROM alert_lane_decisions
    WHERE finding_id LIKE :prefix
    GROUP BY finding_id
)
SELECT f.finding_id,
       f.external_id,
       EXTRACT(EPOCH FROM (f.created_at AT TIME ZONE 'UTC')) AS created_epoch,
       d.lane,
       EXTRACT(EPOCH FROM d.decided_at) AS decided_epoch,
       d.degraded_from,
       COALESCE(d.deferred_verdict, false) AS deferred_verdict,
       EXTRACT(EPOCH FROM (
           (f.ai_enrichment->'ai_triage'->>'timestamp')::timestamp AT TIME ZONE 'UTC'
       )) AS triage_epoch,
       f.ai_enrichment->>'ai_triage_error' AS triage_error,
       EXTRACT(EPOCH FROM (w.finished_at AT TIME ZONE 'UTC')) AS verdict_epoch,
       COALESCE(d.n, 0) AS decisions,
       f.ai_enrichment IS NOT NULL AS has_enrichment,
       EXTRACT(EPOCH FROM d.rules_decided_at) AS rules_epoch,
       EXTRACT(EPOCH FROM d.last_decided_at) AS last_decided_epoch
FROM findings f
LEFT JOIN d ON d.finding_id = f.finding_id
LEFT JOIN workflow_runs w ON w.run_id = d.verdict_run_id
WHERE f.finding_id LIKE :prefix
"""


def _f(v: Any) -> Optional[float]:
    return None if v is None else float(v)


def fetch_rows(engine, id_prefix: str) -> List[FindingRow]:
    from sqlalchemy import text

    with engine.connect() as conn:
        result = conn.execute(text(_ROWS_SQL), {"prefix": id_prefix + "%"})
        return [
            FindingRow(
                finding_id=r.finding_id,
                external_id=r.external_id,
                created_epoch=float(r.created_epoch),
                lane=r.lane,
                decided_epoch=_f(r.decided_epoch),
                degraded_from=r.degraded_from,
                deferred_verdict=bool(r.deferred_verdict),
                triage_epoch=_f(r.triage_epoch),
                triage_error=r.triage_error,
                verdict_finished_epoch=_f(r.verdict_epoch),
                decisions=int(r.decisions),
                has_enrichment=bool(r.has_enrichment),
                rules_epoch=_f(r.rules_epoch),
                last_decided_epoch=_f(r.last_decided_epoch),
            )
            for r in result
        ]


@dataclass
class Backlog:
    at: float
    stored: int
    settled: int

    @property
    def pending(self) -> int:
        return self.stored - self.settled


def backlog(rows: Sequence[FindingRow], at: Optional[float] = None) -> Backlog:
    return Backlog(
        at=time.time() if at is None else at,
        stored=len(rows),
        settled=sum(1 for r in rows if is_settled(r)),
    )


class FirstTriage:
    """The first ai_triage timestamp read for each finding.

    The daemon stores one ``ai_triage`` per finding and a re-triage replaces
    it, timestamp included. Every poll of the run goes through ``apply``,
    which remembers the earliest value seen and puts it back on the row, so
    latency is measured to the first verdict. Resolution is the poll interval:
    a re-triage that lands before the first poll after the first triage is not
    seen (the row then reports the later time, an over-estimate).
    """

    def __init__(self) -> None:
        self._seen: Dict[str, float] = {}
        self._lock = threading.Lock()

    def apply(self, rows: Sequence[FindingRow]) -> List[FindingRow]:
        with self._lock:
            for r in rows:
                if r.triage_epoch is None:
                    continue
                first = self._seen.get(r.finding_id)
                if first is None:
                    self._seen[r.finding_id] = r.triage_epoch
                elif r.triage_epoch != first:
                    r.retriaged = True
                    if r.triage_epoch > first:
                        r.triage_epoch = first
                    else:  # clock oddity; keep the earliest
                        self._seen[r.finding_id] = r.triage_epoch
        return list(rows)


class Sampler(threading.Thread):
    """Background poll of the run's rows: backlog samples + first triage times."""

    def __init__(
        self,
        engine,
        prefix: str,
        every: float = 3.0,
        first_triage: Optional[FirstTriage] = None,
        fetch: Callable[[Any, str], List[FindingRow]] = fetch_rows,
    ):
        super().__init__(daemon=True)
        self.engine, self.prefix, self.every = engine, prefix, every
        self.first_triage = first_triage or FirstTriage()
        self.fetch = fetch
        self.samples: List[Backlog] = []
        self.stop_evt = threading.Event()

    def run(self) -> None:
        while not self.stop_evt.is_set():
            try:
                rows = self.first_triage.apply(self.fetch(self.engine, self.prefix))
                self.samples.append(backlog(rows))
            except Exception:  # noqa: BLE001 - database may be down (pg_restart)
                pass
            self.stop_evt.wait(self.every)


def wait_settled(
    engine,
    id_prefix: str,
    expected_ids: Iterable[str],
    *,
    timeout: float,
    poll: float = 3.0,
    on_poll: Optional[Callable[[Backlog], None]] = None,
    fetch: Callable[[Any, str], List[FindingRow]] = fetch_rows,
    first_triage: Optional[FirstTriage] = None,
) -> List[FindingRow]:
    """Poll until every expected finding is stored and settled, or ``timeout``.

    Rows pass through ``first_triage`` (a fresh one when not given), so the
    triage time returned is the first one read, not a later re-triage's.
    """
    expected = set(expected_ids)
    first_triage = first_triage or FirstTriage()
    deadline = time.monotonic() + timeout
    rows: List[FindingRow] = []
    while True:
        try:
            rows = first_triage.apply(fetch(engine, id_prefix))
        except Exception:  # noqa: BLE001 - the database may be restarting
            rows = rows or []
        else:
            if on_poll:
                on_poll(backlog(rows))
            done = {r.finding_id for r in rows if is_settled(r)}
            if expected <= done:
                return rows
        if time.monotonic() >= deadline:
            return rows
        time.sleep(poll)


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------


@dataclass
class Report:
    run_id: str
    label: str
    profile: Dict[str, Any]
    client: Dict[str, Any]
    lanes: Dict[str, LaneStats]
    accounting: Accounting
    slo: List[SloCheck]
    notes: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)
    # The same latencies split by how the finding came in (webhook / api).
    by_path: Dict[str, Dict[str, LaneStats]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Long id lists are capped in the JSON; counts stay exact.
        for key in ("lost", "unexpected", "unsettled", "double_processed"):
            ids = d["accounting"][key]
            d["accounting"][f"{key}_count"] = len(ids)
            d["accounting"][key] = ids[:50]
        return d


def _fmt(v: Optional[float]) -> str:
    return "-" if v is None else f"{v:.2f}"


def render_markdown(report: Report) -> str:
    a = report.accounting
    lines = [
        f"# Load report `{report.run_id}` ({report.label})",
        "",
        "## Profile",
        "",
    ]
    for k, v in report.profile.items():
        lines.append(f"- `{k}`: {v}")
    lines += ["", "## Ingest -> verdict latency (seconds, DB timestamps)", ""]
    lines.append("| Lane | Findings | Settled | p50 | p95 | p99 | max |")
    lines.append("|---|---|---|---|---|---|---|")
    for st in report.lanes.values():
        if st.count == 0:
            continue
        lines.append(
            f"| {st.lane} | {st.count} | {st.settled} | {_fmt(st.p50)} | "
            f"{_fmt(st.p95)} | {_fmt(st.p99)} | {_fmt(st.max)} |"
        )
    if report.by_path:
        lines += ["", "### By ingest path", ""]
        lines.append("| Path | Lane | Findings | Settled | p50 | p95 | p99 |")
        lines.append("|---|---|---|---|---|---|---|")
        for path, lanes in report.by_path.items():
            for st in lanes.values():
                if st.count:
                    lines.append(
                        f"| {path} | {st.lane} | {st.count} | {st.settled} | "
                        f"{_fmt(st.p50)} | {_fmt(st.p95)} | {_fmt(st.p99)} |"
                    )
    lines += ["", "## SLO comparison", ""]
    lines.append("| SLO | Target | Measured | Status |")
    lines.append("|---|---|---|---|")
    for c in report.slo:
        lines.append(f"| {c.name} | {c.target} | {c.measured} | {c.status} |")
    lines += [
        "",
        "## Accounting",
        "",
        f"- sent {a.sent}, accepted {a.accepted}, stored {a.stored}",
        f"- lost (accepted, never stored): {len(a.lost)}",
        f"- unsettled at end of wait: {len(a.unsettled)}",
        f"- duplicate rows: {a.duplicate_rows}; unexpected rows: {len(a.unexpected)}",
        f"- re-decided (at-least-once, informational): {a.re_decided}",
        f"- double processed (decided again after the verdict): "
        f"{len(a.double_processed)}",
        f"- re-triaged (first triage time kept): {a.retriaged}",
        f"- deferred verdict (verdict lane degraded): {a.deferred_verdict}",
        f"- open triage errors: {a.triage_errors_open}",
        "",
        "## Client side",
        "",
    ]
    for k, v in report.client.items():
        lines.append(f"- `{k}`: {v}")
    if report.extra:
        lines += ["", "## Extra", ""]
        for k, v in report.extra.items():
            lines.append(f"- `{k}`: {v}")
    if report.notes:
        lines += ["", "## Notes", ""]
        lines += [f"- {n}" for n in report.notes]
    return "\n".join(lines) + "\n"
