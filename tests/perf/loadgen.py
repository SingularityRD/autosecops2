"""Load generator: eval-corpus findings into the daemon webhook and the API.

Open-loop (arrivals follow the schedule whatever the server does), asyncio +
httpx, no extra dependency. A run:

1. builds a send schedule from a sustained rate plus periodic bursts;
2. sends each finding -- a copy of an eval-corpus alert with a run-unique
   ``finding_id``/``external_id`` -- to the daemon webhook (default) or, for
   ``--api-fraction`` of them, to ``POST /api/ingest/ingest-string``; a 503 or a
   connection error is retried (``Retry-After`` honoured) until
   ``--max-retry-seconds``, as a real sender holding its bookmark would;
3. optionally probes ``GET /api/v1/findings`` at ``--api-read-rps`` to see API
   latency under the ingest load;
4. waits until every accepted finding has a verdict (or ``--settle-timeout``),
   then reads per-lane ingest->verdict latency from the database
   (tests/perf/measure.py) and compares it with the SLO table.

``--rules-fraction`` sends that share with ``data_source=loadtest-rules`` and,
with ``--seed-rules``, inserts a suppression rule matching it, so the rules lane
is exercised; the rest take whatever lane the router gives them.

Example (local stack from ``python -m tests.perf.chaos --target local
--scenario none``, or staging per docs/operations/load-chaos-runbook.md)::

    python -m tests.perf.loadgen \\
        --webhook http://127.0.0.1:8081/webhook --webhook-token "$TOKEN" \\
        --db-url "$LOADTEST_DB_URL" --rate 5 --duration 600 \\
        --burst-rate 50 --burst-duration 30 --burst-every 120 \\
        --out /tmp/load/report
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import secrets
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import httpx

from tests.perf import measure

REPO = Path(__file__).resolve().parents[2]
DEFAULT_CORPUS = REPO / "eval" / "corpus" / "v1" / "dev.jsonl"
RULES_SOURCE = "loadtest-rules"
ID_PREFIX = "lt"
MAX_FINDING_ID = 50  # findings.finding_id is VARCHAR(50)


# --------------------------------------------------------------------------
# Schedule and payloads
# --------------------------------------------------------------------------


@dataclass
class Profile:
    rate: float = 2.0  # sustained findings per second
    duration: float = 60.0  # seconds
    burst_rate: float = 0.0  # extra findings per second during a burst
    burst_duration: float = 0.0
    burst_every: float = 0.0  # seconds between burst starts (0: no bursts)
    burst_offset: float = 0.0  # first burst start
    api_fraction: float = 0.0
    rules_fraction: float = 0.0
    batch_size: int = 1  # findings per webhook request

    def validate(self) -> None:
        if self.rate < 0 or self.duration <= 0:
            raise ValueError("rate must be >= 0 and duration > 0")
        if not 0 <= self.api_fraction <= 1 or not 0 <= self.rules_fraction <= 1:
            raise ValueError("fractions must be within [0, 1]")
        if self.batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        if self.burst_rate and (self.burst_duration <= 0 or self.burst_every <= 0):
            raise ValueError("a burst needs burst_duration > 0 and burst_every > 0")


def schedule(profile: Profile) -> List[float]:
    """Send offsets (seconds from start), evenly spaced per phase, sorted."""
    profile.validate()
    times: List[float] = []
    if profile.rate > 0:
        step = 1.0 / profile.rate
        n = int(profile.duration * profile.rate + 1e-9)
        times += [i * step for i in range(n)]
    if profile.burst_rate > 0:
        start = profile.burst_offset
        while start < profile.duration:
            end = min(start + profile.burst_duration, profile.duration)
            step = 1.0 / profile.burst_rate
            t = start
            while t < end - 1e-9:
                times.append(t)
                t += step
            start += profile.burst_every
    return sorted(times)


def load_corpus(path: Path, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                alerts.append(json.loads(line)["alert"])
                if limit and len(alerts) >= limit:
                    break
    if not alerts:
        raise ValueError(f"no alerts in {path}")
    return alerts


def run_prefix(run_id: str) -> str:
    return f"{ID_PREFIX}-{run_id}-"


def make_finding(
    alert: Dict[str, Any], run_id: str, seq: int, *, rules: bool = False
) -> Dict[str, Any]:
    """A copy of ``alert`` with a run-unique id; the corpus labels never leave."""
    finding = json.loads(json.dumps(alert))
    fid = f"{run_prefix(run_id)}{seq:07d}"
    if len(fid) > MAX_FINDING_ID:
        raise ValueError(f"finding id {fid!r} longer than {MAX_FINDING_ID}")
    finding["finding_id"] = fid
    # (data_source, external_id) is a dedup key: keep it unique per send.
    finding["external_id"] = fid
    finding["status"] = "new"
    if rules:
        finding["data_source"] = RULES_SOURCE
        # Rules may only settle up to suppress_max_severity (high).
        if str(finding.get("severity", "")).lower() == "critical":
            finding["severity"] = "high"
    raw = dict(finding.get("raw_event") or {})
    raw["loadtest_run"] = run_id
    finding["raw_event"] = raw
    return finding


# --------------------------------------------------------------------------
# Sending
# --------------------------------------------------------------------------


@dataclass
class Target:
    webhooks: List[str] = field(default_factory=list)  # several = failover
    webhook_token: str = ""
    api_base: Optional[str] = None
    api_token: Optional[str] = None
    verify_tls: bool = True


@dataclass
class SendRecord:
    ids: List[str]
    path: str  # webhook | api
    scheduled: float  # offset in the schedule
    first_try: float = 0.0  # epoch
    accepted_at: Optional[float] = None  # epoch
    attempts: int = 0
    status: Optional[int] = None
    error: Optional[str] = None
    accepted_ids: List[str] = field(default_factory=list)


@dataclass
class ClientLog:
    sends: List[SendRecord] = field(default_factory=list)
    reads: List[Dict[str, Any]] = field(default_factory=list)
    started: float = 0.0
    ended: float = 0.0
    late: int = 0  # sends that started > 1 s after their slot

    def sent_ids(self) -> List[str]:
        return [i for s in self.sends for i in s.ids]

    def accepted_ids(self) -> List[str]:
        return [i for s in self.sends for i in s.accepted_ids]

    def summary(self) -> Dict[str, Any]:
        accept_lat = [
            s.accepted_at - s.first_try for s in self.sends if s.accepted_at is not None
        ]
        read_lat = [r["seconds"] for r in self.reads if r.get("status") == 200]
        statuses: Dict[str, int] = {}
        for s in self.sends:
            key = str(s.status) if s.status is not None else (s.error or "none")
            statuses[key] = statuses.get(key, 0) + 1
        return {
            "requests": len(self.sends),
            "findings_sent": len(self.sent_ids()),
            "findings_accepted": len(self.accepted_ids()),
            "final_status": statuses,
            "retried_requests": sum(1 for s in self.sends if s.attempts > 1),
            "late_sends": self.late,
            "accept_p50_s": _r(measure.percentile(accept_lat, 50)),
            "accept_p95_s": _r(measure.percentile(accept_lat, 95)),
            "accept_max_s": _r(max(accept_lat) if accept_lat else None),
            "api_reads": len(self.reads),
            "api_read_errors": sum(1 for r in self.reads if r.get("status") != 200),
            "api_read_p95_s": _r(measure.percentile(read_lat, 95)),
            "wall_seconds": _r(self.ended - self.started),
        }


def _r(v: Optional[float]) -> Optional[float]:
    return None if v is None else round(v, 3)


def _retry_after(resp: httpx.Response, default: float) -> float:
    try:
        return max(0.2, min(30.0, float(resp.headers.get("Retry-After", default))))
    except ValueError:
        return default


async def _send_webhook(
    client: httpx.AsyncClient,
    target: Target,
    rec: SendRecord,
    findings: List[Dict[str, Any]],
    max_retry: float,
) -> None:
    """POST until accepted or ``max_retry`` seconds; a partial 503 (``ingested``
    = n) is retried whole, the daemon's dedup skips the ones already taken."""
    deadline = time.monotonic() + max_retry
    body: Any = findings if len(findings) > 1 else findings[0]
    headers = {"Authorization": f"Bearer {target.webhook_token}"}
    i = 0
    while True:
        url = target.webhooks[i % len(target.webhooks)]
        rec.attempts += 1
        wait = 1.0
        try:
            resp = await client.post(url, json=body, headers=headers)
            rec.status = resp.status_code
            rec.error = None
            if resp.status_code == 200:
                rec.accepted_at = time.time()
                rec.accepted_ids = list(rec.ids)
                return
            if resp.status_code not in (502, 503, 504, 429):
                rec.error = resp.text[:200]
                return
            wait = _retry_after(resp, 1.0)
        except httpx.HTTPError as e:
            rec.status = None
            rec.error = type(e).__name__
        i += 1  # fail over to the next webhook (standby takes over)
        if time.monotonic() + wait > deadline:
            return
        await asyncio.sleep(wait)


async def _send_api(
    client: httpx.AsyncClient,
    target: Target,
    rec: SendRecord,
    findings: List[Dict[str, Any]],
    max_retry: float,
) -> None:
    deadline = time.monotonic() + max_retry
    headers = {"Authorization": f"Bearer {target.api_token}"}
    data = {"data": json.dumps(findings), "format": "json", "data_type": "finding"}
    while True:
        rec.attempts += 1
        try:
            resp = await client.post(
                f"{target.api_base}/api/ingest/ingest-string",
                data=data,
                headers=headers,
            )
            rec.status = resp.status_code
            rec.error = None
            if resp.status_code == 200:
                body = resp.json()
                # IngestionStats: findings_imported (+ skipped as duplicates).
                if body.get("success", True):
                    rec.accepted_at = time.time()
                    rec.accepted_ids = list(rec.ids)
                    return
                rec.error = str(body.get("message"))[:200]
            elif resp.status_code < 500:
                rec.error = resp.text[:200]
                return
        except httpx.HTTPError as e:
            rec.status = None
            rec.error = type(e).__name__
        if time.monotonic() + 1.0 > deadline:
            return
        await asyncio.sleep(1.0)


async def _api_reader(
    client: httpx.AsyncClient, target: Target, rps: float, stop: asyncio.Event, log
):
    headers = {"Authorization": f"Bearer {target.api_token}"}
    while not stop.is_set():
        t0 = time.monotonic()
        entry: Dict[str, Any] = {"at": time.time()}
        try:
            resp = await client.get(
                f"{target.api_base}/api/v1/findings",
                params={"limit": 50},
                headers=headers,
            )
            entry["status"] = resp.status_code
        except httpx.HTTPError as e:
            entry["status"] = type(e).__name__
        entry["seconds"] = time.monotonic() - t0
        log.reads.append(entry)
        try:
            await asyncio.wait_for(stop.wait(), timeout=max(0.0, 1.0 / rps))
        except asyncio.TimeoutError:
            pass


async def run_load(
    profile: Profile,
    target: Target,
    alerts: Sequence[Dict[str, Any]],
    run_id: str,
    *,
    max_retry: float = 300.0,
    max_inflight: int = 200,
    api_read_rps: float = 0.0,
    timeout: float = 30.0,
    seed: int = 0,
    log: Optional[ClientLog] = None,
) -> ClientLog:
    """Send the schedule; returns once every send has been accepted or given up."""
    if not target.webhooks and profile.api_fraction < 1:
        raise ValueError("a webhook URL is needed unless api_fraction is 1")
    if (profile.api_fraction > 0 or api_read_rps > 0) and not (
        target.api_base and target.api_token
    ):
        raise ValueError("API sends/reads need api_base and api_token")
    rng = random.Random(seed)
    offsets = schedule(profile)
    log = log or ClientLog()
    sem = asyncio.Semaphore(max_inflight)
    tasks: List[asyncio.Task] = []
    stop_reads = asyncio.Event()
    seq = 0
    limits = httpx.Limits(max_connections=max_inflight, max_keepalive_connections=50)
    async with httpx.AsyncClient(
        timeout=timeout, limits=limits, verify=target.verify_tls
    ) as client:
        reader = (
            asyncio.create_task(
                _api_reader(client, target, api_read_rps, stop_reads, log)
            )
            if api_read_rps > 0
            else None
        )
        log.started = time.time()
        t0 = time.monotonic()
        i = 0
        while i < len(offsets):
            # Group consecutive webhook findings into one request (batch_size).
            path = "api" if rng.random() < profile.api_fraction else "webhook"
            n = profile.batch_size if path == "webhook" else 1
            group = offsets[i : i + n]
            i += len(group)
            findings = []
            for _ in group:
                alert = alerts[seq % len(alerts)]
                rules = rng.random() < profile.rules_fraction
                findings.append(make_finding(alert, run_id, seq, rules=rules))
                seq += 1
            slot = group[0]
            delay = slot - (time.monotonic() - t0)
            if delay > 0:
                await asyncio.sleep(delay)
            elif delay < -1.0:
                log.late += 1
            rec = SendRecord(
                ids=[f["finding_id"] for f in findings], path=path, scheduled=slot
            )
            log.sends.append(rec)

            async def go(rec=rec, findings=findings, path=path):
                async with sem:
                    rec.first_try = time.time()
                    send = _send_api if path == "api" else _send_webhook
                    await send(client, target, rec, findings, max_retry)

            tasks.append(asyncio.create_task(go()))
        await asyncio.gather(*tasks)
        stop_reads.set()
        if reader:
            await reader
        log.ended = time.time()
    return log


# --------------------------------------------------------------------------
# Database helpers (suppression rule for the rules lane)
# --------------------------------------------------------------------------


def seed_rules_lane(engine, run_id: str, tenant: str = "default") -> str:
    """Insert (or re-enable) a suppression rule matching ``RULES_SOURCE``."""
    from sqlalchemy import text

    name = f"loadtest-{RULES_SOURCE}"
    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO suppression_rules
                    (tenant_id, name, match, reason, enabled, created_by)
                VALUES (:t, :n, CAST(:m AS jsonb), :r, true, 'loadtest')
                ON CONFLICT (tenant_id, name) DO UPDATE SET enabled = true
                """),
            {
                "t": tenant,
                "n": name,
                "m": json.dumps({"data_source": RULES_SOURCE}),
                "r": f"W4.1 load test rules lane (run {run_id})",
            },
        )
    return name


def make_engine(db_url: str):
    from sqlalchemy import create_engine

    return create_engine(db_url, pool_pre_ping=True, pool_size=2, max_overflow=2)


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------


def build_report(
    engine,
    run_id: str,
    label: str,
    profile: Profile,
    log: ClientLog,
    *,
    settle_timeout: float,
    min_samples: int = 20,
    notes: Optional[List[str]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> measure.Report:
    rows = measure.wait_settled(
        engine, run_prefix(run_id), log.accepted_ids(), timeout=settle_timeout
    )
    stats = measure.lane_stats(rows)
    acc = measure.account(log.accepted_ids(), log.sent_ids(), rows)
    paths: Dict[str, set] = {}
    for s in log.sends:
        paths.setdefault(s.path, set()).update(s.ids)
    by_path = {
        path: measure.lane_stats([r for r in rows if r.finding_id in ids])
        for path, ids in sorted(paths.items())
    }
    return measure.Report(
        by_path=by_path,
        run_id=run_id,
        label=label,
        profile=dict(profile.__dict__),
        client=log.summary(),
        lanes=stats,
        accounting=acc,
        slo=measure.compare_slo(stats, len(acc.lost), min_samples=min_samples),
        notes=list(notes or []),
        extra=dict(extra or {}),
    )


def write_report(report: measure.Report, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".json").write_text(
        json.dumps(report.to_dict(), indent=2, default=str), encoding="utf-8"
    )
    out.with_suffix(".md").write_text(measure.render_markdown(report), encoding="utf-8")


def new_run_id() -> str:
    return secrets.token_hex(4)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument(
        "--webhook",
        action="append",
        default=[],
        help="daemon webhook URL (repeat for failover)",
    )
    p.add_argument(
        "--webhook-token", default=os.environ.get("DAEMON_WEBHOOK_TOKEN", "")
    )
    p.add_argument("--api", dest="api_base", default=None, help="API base URL")
    p.add_argument("--api-token", default=os.environ.get("LOADTEST_API_TOKEN"))
    p.add_argument(
        "--db-url",
        default=os.environ.get("LOADTEST_DB_URL"),
        help="SQLAlchemy URL for measurement (read; write only with --seed-rules)",
    )
    p.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    p.add_argument("--rate", type=float, default=2.0)
    p.add_argument("--duration", type=float, default=60.0)
    p.add_argument("--burst-rate", type=float, default=0.0)
    p.add_argument("--burst-duration", type=float, default=0.0)
    p.add_argument("--burst-every", type=float, default=0.0)
    p.add_argument("--burst-offset", type=float, default=0.0)
    p.add_argument("--api-fraction", type=float, default=0.0)
    p.add_argument("--rules-fraction", type=float, default=0.0)
    p.add_argument("--seed-rules", action="store_true")
    p.add_argument("--batch-size", type=int, default=1)
    p.add_argument("--api-read-rps", type=float, default=0.0)
    p.add_argument("--max-retry-seconds", type=float, default=300.0)
    p.add_argument("--max-inflight", type=int, default=200)
    p.add_argument("--settle-timeout", type=float, default=900.0)
    p.add_argument("--min-samples", type=int, default=20)
    p.add_argument("--run-id", default=None)
    p.add_argument("--label", default="load")
    p.add_argument(
        "--insecure",
        action="store_true",
        help="skip TLS verification (staging self-signed)",
    )
    p.add_argument(
        "--out",
        type=Path,
        required=True,
        help="report path without suffix (.json and .md are written)",
    )
    p.add_argument(
        "--enforce-slo", action="store_true", help="exit 1 when an SLO row is FAIL"
    )
    return p  # fmt: skip


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    if not args.db_url:
        print("--db-url (or LOADTEST_DB_URL) is required to measure", file=sys.stderr)
        return 2
    profile = Profile(
        rate=args.rate,
        duration=args.duration,
        burst_rate=args.burst_rate,
        burst_duration=args.burst_duration,
        burst_every=args.burst_every,
        burst_offset=args.burst_offset,
        api_fraction=args.api_fraction,
        rules_fraction=args.rules_fraction,
        batch_size=args.batch_size,
    )
    target = Target(
        webhooks=args.webhook,
        webhook_token=args.webhook_token,
        api_base=args.api_base,
        api_token=args.api_token,
        verify_tls=not args.insecure,
    )
    run_id = args.run_id or new_run_id()
    engine = make_engine(args.db_url)
    if args.seed_rules:
        seed_rules_lane(engine, run_id)
    alerts = load_corpus(args.corpus)
    print(f"run {run_id}: {len(schedule(profile))} findings scheduled", flush=True)
    log = asyncio.run(
        run_load(
            profile,
            target,
            alerts,
            run_id,
            max_retry=args.max_retry_seconds,
            max_inflight=args.max_inflight,
            api_read_rps=args.api_read_rps,
        )
    )
    report = build_report(
        engine,
        run_id,
        args.label,
        profile,
        log,
        settle_timeout=args.settle_timeout,
        min_samples=args.min_samples,
    )
    write_report(report, args.out)
    print(measure.render_markdown(report))
    failed = [c for c in report.slo if c.status == "FAIL"]
    return 1 if (failed and args.enforce_slo) else 0


if __name__ == "__main__":
    sys.exit(main())
