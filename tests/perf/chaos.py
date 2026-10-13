"""Chaos scenarios (W4.2): break one piece under load, heal it, and check that
no finding was lost or duplicated and that everything settled within a bound.

Each scenario runs the load generator (tests/perf/loadgen.py) at a steady rate
for ``pre + fault + post`` seconds, injects the fault ``pre`` seconds in,
heals it ``fault`` seconds later, then waits for every accepted finding to have
a verdict. It passes when:

* lost == 0       -- every finding the webhook/API accepted is in ``findings``;
* duplicates == 0 -- one row per sent alert, no row the run did not send;
* unsettled == 0 and the last finding settled within ``recovery_bound``
  seconds of the heal;
* the scenario's own checks (below) hold.

Scenarios:

``llm_outage``   model provider answers 5xx. Rules-lane findings arriving
                 during the outage still settle during it (no model needed);
                 model-lane findings pile up (the backlog grows) and are
                 triaged by the enrichment backfill after the heal.
``llm_timeout``  model provider hangs (calls time out); same checks.
``pg_restart``   PostgreSQL stopped for ``fault`` seconds, then started.
``redis_restart`` Redis stopped for ``fault`` seconds, then started (no
                 persistence: dedup keys and queued LLM jobs are gone).
``daemon_kill``  daemon SIGKILLed, started again after ``fault`` seconds.
``daemon_kill_standby`` with W3.9 leader election: two daemons, the leader is
                 SIGKILLed, the standby must take over (no restart of the
                 killed one until heal). Skipped when W3.9 is not merged.
``slow_vendor``  model provider answers after ``CHAOS_SLOW_SECONDS`` (20);
                 ingest must not slow down (webhook accept p95 < 2 s).

Targets:

``local``    tests/perf/stack.py starts a private stack; faults are applied
             directly (process signals, pg_ctl, the stub model's mode).
``staging``  an existing install (W0.6 staging VM). Endpoints come from the
             environment and every fault is a shell command from
             ``CHAOS_CMD_<ACTION>`` (see docs/operations/load-chaos-runbook.md);
             a scenario whose command is not set is skipped, never faked.

CLI::

    python -m tests.perf.chaos --target local --scenario all --out /tmp/chaos
    python -m tests.perf.chaos --target staging --scenario llm_outage,pg_restart \\
        --rate 5 --fault 120 --out /var/lib/autosecops-staging/chaos
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from tests.perf import loadgen, measure

# --------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------

ACTIONS = (
    "llm_error",
    "llm_hang",
    "llm_slow",
    "llm_heal",
    "pg_stop",
    "pg_start",
    "redis_stop",
    "redis_start",
    "daemon_kill",
    "daemon_start",
    "leader_kill",
    "leader_restart",
)


class Unsupported(Exception):
    """The target cannot apply this fault; the scenario is skipped."""


@dataclass
class TargetInfo:
    webhooks: List[str]
    webhook_token: str
    db_url: str
    api_base: Optional[str] = None
    api_token: Optional[str] = None
    verify_tls: bool = True


class LocalTarget:
    """Faults applied to a tests.perf.stack.LocalStack."""

    name = "local"

    def __init__(self, stack, slow_seconds: float = 20.0):
        self.stack = stack
        self.slow_seconds = slow_seconds
        ep = stack.endpoints
        self.info = TargetInfo(
            webhooks=list(ep.webhooks),
            webhook_token=ep.webhook_token,
            db_url=ep.db_url,
            api_base=ep.api_base,
            api_token=ep.api_token,
        )
        self._killed_leader: Optional[int] = None

    def events(self, since: float) -> List[str]:
        """Process exits the stack's supervisor saw (and restarted) since ``since``."""
        return self.stack.events_since(since)

    def supports(self, action: str) -> Optional[str]:
        if action in ("leader_kill", "leader_restart"):
            if not self.stack.leader_election:
                return "local stack runs without leader election (W3.9)"
        return None

    def _leader(self) -> int:
        for i in range(len(self.stack.daemons)):
            if self.stack.daemon_role(i) == "leader":
                return i
        raise Unsupported("no daemon reports role=leader")

    def do(self, action: str) -> None:
        s = self.stack
        if action == "llm_error":
            s.llm.set_mode("error")
        elif action == "llm_hang":
            s.llm.set_mode("hang", hang_seconds=max(30.0, s.triage_timeout * 2))
        elif action == "llm_slow":
            s.llm.set_mode("slow", delay_seconds=self.slow_seconds)
        elif action == "llm_heal":
            s.llm.set_mode("ok")
        elif action == "pg_stop":
            s.pg.stop("fast")
        elif action == "pg_start":
            s.pg.start()
        elif action == "redis_stop":
            s.redis.stop()
        elif action == "redis_start":
            s.redis.start()
        elif action == "daemon_kill":
            s.kill_daemon(0)
        elif action == "daemon_start":
            s.start_daemon(0)
            s.wait_daemon_ready(0)
        elif action == "leader_kill":
            self._killed_leader = self._leader()
            s.kill_daemon(self._killed_leader)
        elif action == "leader_restart":
            if self._killed_leader is not None:
                s.start_daemon(self._killed_leader)
                self._killed_leader = None
        else:
            raise ValueError(action)


class StagingTarget:
    """Faults as operator-supplied shell commands (``CHAOS_CMD_<ACTION>``)."""

    name = "staging"

    def __init__(self, env: Optional[Dict[str, str]] = None, timeout: float = 600):
        self.env = dict(os.environ if env is None else env)
        self.timeout = timeout
        hooks = [
            w for w in self.env.get("LOADTEST_WEBHOOK_URLS", "").split(",") if w.strip()
        ]
        self.info = TargetInfo(
            webhooks=[w.strip() for w in hooks],
            webhook_token=self.env.get("DAEMON_WEBHOOK_TOKEN", ""),
            db_url=self.env.get("LOADTEST_DB_URL", ""),
            api_base=self.env.get("LOADTEST_API_BASE") or None,
            api_token=self.env.get("LOADTEST_API_TOKEN") or None,
            verify_tls=self.env.get("LOADTEST_INSECURE", "") not in ("1", "true"),
        )

    @staticmethod
    def var(action: str) -> str:
        return f"CHAOS_CMD_{action.upper()}"

    def missing(self) -> List[str]:
        out = []
        if not self.info.webhooks:
            out.append("LOADTEST_WEBHOOK_URLS")
        if not self.info.webhook_token:
            out.append("DAEMON_WEBHOOK_TOKEN")
        if not self.info.db_url:
            out.append("LOADTEST_DB_URL")
        return out

    def supports(self, action: str) -> Optional[str]:
        if not self.env.get(self.var(action), "").strip():
            return f"{self.var(action)} is not set"
        return None

    def do(self, action: str) -> None:
        cmd = self.env.get(self.var(action), "").strip()
        if not cmd:
            raise Unsupported(f"{self.var(action)} is not set")
        done = subprocess.run(
            ["bash", "-c", cmd],
            env=self.env,
            capture_output=True,
            text=True,
            timeout=self.timeout,
        )
        if done.returncode != 0:
            raise RuntimeError(
                f"{self.var(action)} exited {done.returncode}: "
                f"{done.stdout[-500:]}{done.stderr[-500:]}"
            )


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------


@dataclass
class Window:
    inject_at: float
    heal_at: float


@dataclass
class Scenario:
    name: str
    inject: Sequence[str]
    heal: Sequence[str]
    recovery_bound: float
    description: str
    checks: List[Callable[["Observation"], Optional[str]]] = field(default_factory=list)
    # Actions that must be supported (inject + heal by default).
    required: Optional[Sequence[str]] = None

    def needs(self) -> List[str]:
        return list(self.required or [*self.inject, *self.heal])


@dataclass
class Observation:
    rows: List[measure.FindingRow]
    log: loadgen.ClientLog
    window: Window
    samples: List[measure.Backlog]


def _sent_in_window(obs: Observation) -> set:
    return {
        i
        for s in obs.log.sends
        if obs.window.inject_at <= s.first_try < obs.window.heal_at
        for i in s.ids
    }


def check_rules_lane_survives(obs: Observation) -> Optional[str]:
    """Rules-lane findings sent during the fault settle before the heal."""
    during = _sent_in_window(obs)
    rules = [r for r in obs.rows if r.finding_id in during and r.lane == "rules"]
    if not rules:
        return (
            "no rules-lane finding arrived during the fault (raise --rate or --fault)"
        )
    late = [
        r.finding_id
        for r in rules
        if r.decided_epoch is None or r.decided_epoch > obs.window.heal_at + 1.0
    ]
    if late:
        return f"{len(late)}/{len(rules)} rules-lane findings waited for the heal"
    return None


def check_backlog_grows(obs: Observation) -> Optional[str]:
    """Model-lane findings pile up while the model is down (queued, not dropped)."""
    inside = [
        s for s in obs.samples if obs.window.inject_at <= s.at <= obs.window.heal_at
    ]
    if not inside:
        return "no backlog sample during the fault"
    if max(s.pending for s in inside) <= max(
        (s.pending for s in obs.samples if s.at < obs.window.inject_at), default=0
    ):
        return "backlog did not grow during the model outage"
    return None


def check_ingest_not_blocked(obs: Observation, limit: float = 2.0) -> Optional[str]:
    lat = [
        s.accepted_at - s.first_try
        for s in obs.log.sends
        if s.accepted_at is not None
        and obs.window.inject_at <= s.first_try < obs.window.heal_at
    ]
    p95 = measure.percentile(lat, 95)
    if p95 is None:
        return "nothing accepted during the slow-vendor window"
    if p95 > limit:
        return f"webhook accept p95 {p95:.2f}s > {limit}s while the vendor was slow"
    return None


def _bound(name: str, default: float) -> float:
    return float(os.environ.get(f"CHAOS_RECOVERY_{name.upper()}", default))


def scenarios() -> Dict[str, Scenario]:
    # Model-outage recovery = breaker cooldown (120 s, processor.py) + one
    # backfill interval + the drain itself.
    return {
        s.name: s
        for s in (
            Scenario(
                "llm_outage",
                ["llm_error"],
                ["llm_heal"],
                _bound("llm_outage", 360),
                "model provider 5xx",
                [check_rules_lane_survives, check_backlog_grows],
            ),
            Scenario(
                "llm_timeout",
                ["llm_hang"],
                ["llm_heal"],
                _bound("llm_timeout", 420),
                "model provider hangs (timeouts)",
                [check_rules_lane_survives, check_backlog_grows],
            ),
            Scenario(
                "pg_restart",
                ["pg_stop"],
                ["pg_start"],
                _bound("pg_restart", 240),
                "PostgreSQL down, then back",
            ),
            Scenario(
                "redis_restart",
                ["redis_stop"],
                ["redis_start"],
                _bound("redis_restart", 240),
                "Redis down (no persistence), then back",
            ),
            Scenario(
                "daemon_kill",
                ["daemon_kill"],
                ["daemon_start"],
                _bound("daemon_kill", 240),
                "daemon SIGKILL, restarted",
            ),
            Scenario(
                "daemon_kill_standby",
                ["leader_kill"],
                ["leader_restart"],
                _bound("daemon_kill_standby", 180),
                "leader SIGKILL, standby takes over (W3.9)",
            ),
            Scenario(
                "slow_vendor",
                ["llm_slow"],
                ["llm_heal"],
                _bound("slow_vendor", 300),
                "model provider answers slowly",
                [check_ingest_not_blocked],
            ),
        )
    }


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------


@dataclass
class ScenarioResult:
    scenario: str
    target: str
    status: str  # PASS / FAIL / SKIP / ERROR
    reasons: List[str] = field(default_factory=list)
    run_id: str = ""
    recovery_seconds: Optional[float] = None
    recovery_bound: Optional[float] = None
    accounting: Dict[str, Any] = field(default_factory=dict)
    client: Dict[str, Any] = field(default_factory=dict)
    lanes: Dict[str, Any] = field(default_factory=dict)
    backlog_peak: Optional[int] = None
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    # Unplanned process exits during the scenario (local target's supervisor).
    target_events: List[str] = field(default_factory=list)


class _Sampler(threading.Thread):
    def __init__(self, engine, prefix: str, every: float = 3.0):
        super().__init__(daemon=True)
        self.engine, self.prefix, self.every = engine, prefix, every
        self.samples: List[measure.Backlog] = []
        self.stop_evt = threading.Event()

    def run(self) -> None:
        while not self.stop_evt.is_set():
            try:
                rows = measure.fetch_rows(self.engine, self.prefix)
                self.samples.append(measure.backlog(rows))
            except Exception:  # noqa: BLE001 - database may be down (pg_restart)
                pass
            self.stop_evt.wait(self.every)


def run_scenario(
    target,
    scenario: Scenario,
    *,
    rate: float = 1.0,
    pre: float = 15.0,
    fault: float = 30.0,
    post: float = 15.0,
    rules_fraction: float = 0.3,
    seed_rules: bool = True,
    max_retry: float = 600.0,
    run_id: Optional[str] = None,
    log_event: Callable[[str], None] = lambda m: print(m, flush=True),
) -> ScenarioResult:
    run_id = run_id or loadgen.new_run_id()
    res = ScenarioResult(scenario.name, target.name, "SKIP", run_id=run_id)
    res.recovery_bound = scenario.recovery_bound
    for action in scenario.needs():
        why = target.supports(action)
        if why and why not in res.reasons:
            res.reasons.append(why)
    if res.reasons:
        return res

    info: TargetInfo = target.info
    engine = loadgen.make_engine(info.db_url)
    if seed_rules and rules_fraction > 0:
        loadgen.seed_rules_lane(engine, run_id)
    profile = loadgen.Profile(
        rate=rate, duration=pre + fault + post, rules_fraction=rules_fraction
    )
    tgt = loadgen.Target(
        webhooks=info.webhooks,
        webhook_token=info.webhook_token,
        api_base=info.api_base,
        api_token=info.api_token,
        verify_tls=info.verify_tls,
    )
    alerts = loadgen.load_corpus(loadgen.DEFAULT_CORPUS)
    prefix = loadgen.run_prefix(run_id)
    sampler = _Sampler(engine, prefix)
    sampler.start()
    log = loadgen.ClientLog()
    errors: List[BaseException] = []

    def _load() -> None:
        try:
            asyncio.run(
                loadgen.run_load(
                    profile, tgt, alerts, run_id, max_retry=max_retry, log=log
                )
            )
        except BaseException as e:  # noqa: BLE001
            errors.append(e)

    loader = threading.Thread(target=_load, daemon=True)
    t_start = time.time()
    loader.start()
    timeline: List[Dict[str, Any]] = []

    def mark(event: str) -> None:
        timeline.append({"t": round(time.time() - t_start, 2), "event": event})
        log_event(f"[{scenario.name}] +{timeline[-1]['t']:.1f}s {event}")

    try:
        time.sleep(pre)
        window = Window(inject_at=time.time(), heal_at=0.0)
        for action in scenario.inject:
            mark(f"inject {action}")
            target.do(action)
        time.sleep(fault)
        for action in scenario.heal:
            mark(f"heal {action}")
            target.do(action)
        window.heal_at = time.time()
        loader.join()
        mark("load finished")
        if errors:
            raise errors[0]
        remaining = max(30.0, scenario.recovery_bound - (time.time() - window.heal_at))
        rows = measure.wait_settled(
            engine, prefix, log.accepted_ids(), timeout=remaining
        )
        settled_epochs = [measure.verdict_epoch(r) for r in rows]
        mark("settle wait finished")
    except Unsupported as e:
        sampler.stop_evt.set()
        res.reasons.append(str(e))
        return res
    except Exception as e:  # noqa: BLE001
        sampler.stop_evt.set()
        res.status = "ERROR"
        res.reasons.append(f"{type(e).__name__}: {e}")
        res.timeline = timeline
        return res
    finally:
        sampler.stop_evt.set()

    acc = measure.account(log.accepted_ids(), log.sent_ids(), rows)
    obs = Observation(rows=rows, log=log, window=window, samples=sampler.samples)
    last = max((e for e in settled_epochs if e is not None), default=None)
    res.recovery_seconds = (
        None if last is None else round(max(0.0, last - window.heal_at), 2)
    )
    res.accounting = {
        "sent": acc.sent,
        "accepted": acc.accepted,
        "stored": acc.stored,
        "lost": len(acc.lost),
        "lost_ids": acc.lost[:20],
        "not_accepted": acc.sent - acc.accepted,
        "unsettled": len(acc.unsettled),
        "duplicate_rows": acc.duplicate_rows,
        "unexpected_rows": len(acc.unexpected),
        "re_decided": acc.re_decided,
        "deferred_verdict": acc.deferred_verdict,
    }
    res.client = log.summary()
    res.lanes = {k: asdict(v) for k, v in measure.lane_stats(rows).items()}
    res.backlog_peak = max((s.pending for s in sampler.samples), default=None)
    res.timeline = timeline

    fails: List[str] = []
    if acc.lost:
        fails.append(f"{len(acc.lost)} accepted finding(s) never stored")
    if acc.sent - acc.accepted:
        fails.append(
            f"{acc.sent - acc.accepted} finding(s) never accepted within "
            f"{max_retry:.0f}s of retries"
        )
    if acc.duplicate_rows or acc.unexpected:
        fails.append(
            f"duplicates: {acc.duplicate_rows} duplicate, "
            f"{len(acc.unexpected)} unexpected row(s)"
        )
    if acc.unsettled:
        fails.append(
            f"{len(acc.unsettled)} finding(s) without a verdict "
            f"{scenario.recovery_bound:.0f}s after the heal"
        )
    elif res.recovery_seconds is not None and (
        res.recovery_seconds > scenario.recovery_bound
    ):
        fails.append(
            f"recovery {res.recovery_seconds}s > bound {scenario.recovery_bound:.0f}s"
        )
    for check in scenario.checks:
        msg = check(obs)
        if msg:
            fails.append(msg)
    events = getattr(target, "events", None)
    res.target_events = events(t_start) if events else []
    if any("api exited" in e for e in res.target_events):
        fails.append("the API process exited")
    res.status = "FAIL" if fails else "PASS"
    res.reasons = fails
    engine.dispose()
    return res


def render(results: Sequence[ScenarioResult]) -> str:
    lines = [
        "| Scenario | Target | Status | Sent/accepted/stored | Lost | Dup | "
        "Unsettled | Recovery (s) / bound | Backlog peak | Reasons | "
        "Process exits |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        a = r.accounting
        lines.append(
            f"| {r.scenario} | {r.target} | {r.status} | "
            f"{a.get('sent', '-')}/{a.get('accepted', '-')}/{a.get('stored', '-')} | "
            f"{a.get('lost', '-')} | {a.get('duplicate_rows', '-')} | "
            f"{a.get('unsettled', '-')} | {r.recovery_seconds} / "
            f"{r.recovery_bound:.0f} | {r.backlog_peak} | "
            f"{'; '.join(r.reasons) or '-'} | {'; '.join(r.target_events) or '-'} |"
        )
    return "\n".join(lines) + "\n"


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Run W4.2 chaos scenarios.")
    p.add_argument("--target", choices=("local", "staging"), default="local")
    p.add_argument("--scenario", default="all", help="comma-separated names or 'all'")
    p.add_argument("--rate", type=float, default=1.0)
    p.add_argument("--pre", type=float, default=15.0)
    p.add_argument("--fault", type=float, default=30.0)
    p.add_argument("--post", type=float, default=15.0)
    p.add_argument("--rules-fraction", type=float, default=0.3)
    p.add_argument("--no-seed-rules", action="store_true")
    p.add_argument("--workdir", type=Path, default=Path("/tmp/autosecops-chaos"))
    p.add_argument(
        "--standby",
        action="store_true",
        help="local: two daemons with leader election (needs W3.9)",
    )
    p.add_argument(
        "--out",
        type=Path,
        required=True,
        help="directory for results.json and results.md",
    )
    return p  # fmt: skip


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    catalogue = scenarios()
    names = list(catalogue) if args.scenario == "all" else args.scenario.split(",")
    unknown = [n for n in names if n not in catalogue]
    if unknown:
        print(f"unknown scenario(s): {unknown}; known: {list(catalogue)}")
        return 2
    args.out.mkdir(parents=True, exist_ok=True)
    stack = None
    if args.target == "local":
        from tests.perf.stack import LocalStack

        standby = args.standby and LocalStack.leader_election_supported()
        stack = LocalStack(
            args.workdir,
            daemons=2 if standby else 1,
            leader_election=standby,
        )
        stack.start()
        target: Any = LocalTarget(stack)
    else:
        target = StagingTarget()
        missing = target.missing()
        if missing:
            print(f"staging target needs: {', '.join(missing)}")
            return 2
    results: List[ScenarioResult] = []
    try:
        for name in names:
            res = run_scenario(
                target,
                catalogue[name],
                rate=args.rate,
                pre=args.pre,
                fault=args.fault,
                post=args.post,
                rules_fraction=args.rules_fraction,
                seed_rules=not args.no_seed_rules,
            )
            results.append(res)
            print(f"{name}: {res.status} {res.reasons}", flush=True)
            (args.out / "results.json").write_text(
                json.dumps([asdict(r) for r in results], indent=2, default=str),
                encoding="utf-8",
            )
    finally:
        if stack is not None:
            stack.stop()
    (args.out / "results.md").write_text(render(results), encoding="utf-8")
    print(render(results))
    return 1 if any(r.status in ("FAIL", "ERROR") for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
