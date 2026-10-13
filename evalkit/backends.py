"""Model backends: the one thing the harness swaps out of the triage path.

Every backend takes the exact prompt ``_build_triage_prompt`` produced and
returns a :class:`BackendResult`. Three kinds:

``stub``      deterministic lexical baseline; no network, no randomness.
``cassette``  replays answers recorded under ``evalkit/cassettes/`` keyed by
              the prompt's sha256; a prompt it has no answer for is a miss.
``live``      the existing ``LLMRouter`` (Bifrost) with a hard USD budget.

:class:`CassetteRecorder` wraps any backend and writes what it answered.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Protocol, Tuple

from core.time import utcnow
from evalkit.triage import prompt_hash

CASSETTE_DIR = Path(__file__).resolve().parent / "cassettes"
DEFAULT_CASSETTE = CASSETTE_DIR / "stub-v1.jsonl"
CASSETTE_FORMAT = "evalkit.cassette/v1"


@dataclass(frozen=True)
class BackendResult:
    """One model answer, or the reason there is none.

    ``cost_usd`` is ``None`` when the call could not be priced (never ``0``
    for unknown); ``latency_ms`` is what the backend measured or recorded.
    """

    content: Optional[str]
    model: str
    cost_usd: Optional[float] = None
    latency_ms: Optional[int] = None
    error: Optional[str] = None
    cassette_miss: bool = False


class Backend(Protocol):
    name: str
    model: str

    async def complete(self, prompt: str) -> BackendResult: ...


# --------------------------------------------------------------------------
# stub
# --------------------------------------------------------------------------

_ALERT_BLOCK = re.compile(r"<alert_data>(.*?)</alert_data>", re.DOTALL)
_MITRE = re.compile(r"^MITRE Predictions: (.*)$", re.MULTILINE)
_HOSTS = re.compile(r"^- Hostnames: (.*)$", re.MULTILINE)

# Written from train.jsonl and the datasheet's "lexical cues" section only;
# test and test_unseen were not looked at. Weights are deliberately crude:
# this is a floor any real model must beat, not a detector.
_BENIGN_CUES: Tuple[Tuple[str, int], ...] = (
    (r"\bapproved\b", 2),
    (r"corporate vpn egress", 2),
    (r"vendor-signed|signed by (the )?(internal|backup|vendor)", 2),
    (r"\ballowlist", 2),
    (r"\bregistered\b", 1),
    (r"\bannounced\b|\bannouncement\b", 1),
    (r"\bverified\b", 1),
    (r"\b(CHG|REQ|JOB|REL|SIM|SCAN|DR|PT|LH|IMG|INC|TRV|PKG|ASSET)-\d+", 1),
    (r"\bmatch(es|ing)?\b", 1),
    (r"\b(nightly|hourly|daily|every hour|every night)\b", 1),
    (r"\bdocument(s|ed)\b", 1),
    (r"\bpass(es)?\b", 1),
    (r"\bcompliant\b|\bcovers\b|within engagement|\bscope\b", 1),
)
_MALICIOUS_CUES: Tuple[Tuple[str, int], ...] = (
    (r"\bnever\b", 2),
    (r"\bnot\b", 1),
    (r"\bno\b", 1),
    (r"\bunsigned\b|\bunverified\b|\bunregistered\b|\bunknown\b", 2),
    (r"temp folder", 2),
    (r"\.test\b|\.example(?![.\w])", 2),
    (r"\bfail(ed|s)?\b", 1),
    (r"hosting provider", 2),
    (r"\b(closed|ended|cancelled)\b", 1),
    (r"lookalike|imitated|self-signed|ransomware|first seen", 2),
    (r"personal cloud|command-and-control", 2),
)

# ATT&CK technique prefix -> the legacy prompt's CATEGORY vocabulary.
_TECHNIQUE_CATEGORY = {
    "T1110": "credential_theft",
    "T1078": "credential_theft",
    "T1558": "credential_theft",
    "T1621": "credential_theft",
    "T1003": "credential_theft",
    "T1098": "credential_theft",
    "T1021": "lateral_movement",
    "T1570": "lateral_movement",
    "T1048": "data_exfil",
    "T1041": "data_exfil",
    "T1567": "data_exfil",
    "T1537": "data_exfil",
    "T1052": "data_exfil",
    "T1560": "data_exfil",
    "T1059": "malware",
    "T1204": "malware",
    "T1486": "malware",
    "T1490": "malware",
    "T1053": "malware",
    "T1547": "malware",
    "T1574": "malware",
    "T1505": "malware",
    "T1190": "intrusion",
    "T1133": "intrusion",
    "T1046": "intrusion",
    "T1071": "intrusion",
}


def _score(text: str, cues: Tuple[Tuple[str, int], ...]) -> int:
    return sum(w * len(re.findall(p, text, re.IGNORECASE)) for p, w in cues)


def stub_answer(prompt: str) -> str:
    """The stub's reply, in the format the prompt asks for."""
    block = _ALERT_BLOCK.search(prompt)
    text = block.group(1) if block else prompt
    margin = _score(text, _MALICIOUS_CUES) - _score(text, _BENIGN_CUES)
    hosts = _HOSTS.search(prompt)
    has_host = bool(hosts and hosts.group(1).strip("[] "))

    if margin >= 4:
        action, severity = ("isolate" if has_host else "block"), "high"
    elif margin > 0:
        action, severity = "investigate", "medium"
    elif margin <= -3:
        action, severity = "dismiss", "low"
    else:
        action, severity = "monitor", "low"
    confidence = min(0.95, 0.5 + 0.05 * abs(margin))

    category = "other"
    mitre = _MITRE.search(prompt)
    for technique in re.findall(r"T\d{4}", mitre.group(1) if mitre else ""):
        category = _TECHNIQUE_CATEGORY.get(technique, category)
        break
    return (
        f"SEVERITY: {severity}\n"
        f"CONFIDENCE: {confidence:.2f}\n"
        f"CATEGORY: {category}\n"
        f"RECOMMENDED_ACTION: {action}\n"
        f"REASONING: lexical baseline, cue margin {margin:+d}\n"
    )


class StubBackend:
    """Deterministic baseline. Free (cost 0.0) and instantaneous (0 ms)."""

    name = "stub"
    model = "evalkit-stub-lexical-v1"

    async def complete(self, prompt: str) -> BackendResult:
        return BackendResult(
            content=stub_answer(prompt), model=self.model, cost_usd=0.0, latency_ms=0
        )


# --------------------------------------------------------------------------
# cassette
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class CassetteEntry:
    key: str
    content: Optional[str]
    model: str
    cost_usd: Optional[float]
    latency_ms: Optional[int]
    error: Optional[str] = None


class CassetteError(ValueError):
    pass


def read_cassette(path: Path) -> Tuple[Dict[str, Any], Dict[str, CassetteEntry]]:
    meta: Dict[str, Any] = {}
    entries: Dict[str, CassetteEntry] = {}
    with Path(path).open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if "_meta" in row:
                meta = row["_meta"]
                continue
            try:
                entry = CassetteEntry(**row)
            except TypeError as exc:
                raise CassetteError(f"{path}:{lineno}: bad entry ({exc})") from exc
            entries[entry.key] = entry
    if meta.get("format") != CASSETTE_FORMAT:
        raise CassetteError(f"{path}: not an {CASSETTE_FORMAT} cassette")
    return meta, entries


class CassetteBackend:
    """Replays recorded answers. Deterministic: same prompt, same answer."""

    name = "cassette"

    def __init__(self, path: Path = DEFAULT_CASSETTE):
        self.path = Path(path)
        self.meta, self._entries = read_cassette(self.path)
        self.model = str(self.meta.get("model") or "unknown")
        self.misses = 0

    def __len__(self) -> int:
        return len(self._entries)

    async def complete(self, prompt: str) -> BackendResult:
        entry = self._entries.get(prompt_hash(prompt))
        if entry is None:
            self.misses += 1
            return BackendResult(
                content=None,
                model=self.model,
                error="cassette miss: prompt not recorded (prompt changed? re-record)",
                cassette_miss=True,
            )
        return BackendResult(
            content=entry.content,
            model=entry.model,
            cost_usd=entry.cost_usd,
            latency_ms=entry.latency_ms,
            error=entry.error,
        )


class CassetteRecorder:
    """Passes calls through to ``inner`` and keeps every answer for ``save``."""

    def __init__(self, inner: Backend, path: Path, *, prompt_version: str):
        self.inner = inner
        self.path = Path(path)
        self.prompt_version = prompt_version
        self.name = f"record:{inner.name}"
        self.model = inner.model
        self._entries: Dict[str, CassetteEntry] = {}

    async def complete(self, prompt: str) -> BackendResult:
        result = await self.inner.complete(prompt)
        # A budget refusal is not an answer; it must not be replayed as one.
        if not (result.error and result.error.startswith(BUDGET_ERROR_PREFIX)):
            key = prompt_hash(prompt)
            self._entries[key] = CassetteEntry(
                key=key,
                content=result.content,
                model=result.model,
                cost_usd=result.cost_usd,
                latency_ms=result.latency_ms,
                error=result.error,
            )
        return result

    def save(self, *, merge: bool = True) -> int:
        """Write the cassette (sorted by key, so diffs stay small)."""
        entries: Dict[str, CassetteEntry] = {}
        if merge and self.path.exists():
            _, entries = read_cassette(self.path)
        entries.update(self._entries)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        meta = {
            "format": CASSETTE_FORMAT,
            "backend": self.inner.name,
            "model": self.inner.model,
            "prompt_version": self.prompt_version,
            "recorded_at": utcnow().replace(microsecond=0).isoformat(),
        }
        with self.path.open("w", encoding="utf-8") as fh:
            fh.write(json.dumps({"_meta": meta}, sort_keys=True) + "\n")
            for key in sorted(entries):
                fh.write(json.dumps(asdict(entries[key]), sort_keys=True) + "\n")
        return len(entries)


# --------------------------------------------------------------------------
# live
# --------------------------------------------------------------------------

BUDGET_ERROR_PREFIX = "budget:"


class BudgetExceeded(RuntimeError):
    pass


class Budget:
    """A hard USD cap.

    Before each call the worst case (prompt tokens estimated generously plus
    ``max_tokens`` of output, at the model's rates) is reserved; the call is
    refused if spent + reserved + worst case would pass the cap. After the
    call the reservation is replaced by the priced cost. A call that cannot be
    priced stops the run: an unpriced call makes the cap unenforceable.
    """

    def __init__(self, cap_usd: float):
        if cap_usd <= 0:
            raise ValueError("budget cap must be positive")
        self.cap_usd = float(cap_usd)
        self.spent_usd = 0.0
        self.reserved_usd = 0.0
        self.calls = 0
        self.refused = 0
        self._lock = asyncio.Lock()

    async def reserve(self, worst_case_usd: float) -> None:
        async with self._lock:
            if self.spent_usd + self.reserved_usd + worst_case_usd > self.cap_usd:
                self.refused += 1
                raise BudgetExceeded(
                    f"{BUDGET_ERROR_PREFIX} next call (worst case ${worst_case_usd:.6f}) "
                    f"would exceed cap ${self.cap_usd:.2f} "
                    f"(spent ${self.spent_usd:.6f})"
                )
            self.reserved_usd += worst_case_usd

    async def settle(self, reserved_usd: float, actual_usd: Optional[float]) -> None:
        async with self._lock:
            self.reserved_usd = max(0.0, self.reserved_usd - reserved_usd)
            # Unknown actual cost: charge the worst case so the cap still holds.
            self.spent_usd += reserved_usd if actual_usd is None else actual_usd
            self.calls += 1


@dataclass(frozen=True)
class Rates:
    input: float
    output: float
    cache_read: float = 0.0
    pricing_source: str = "exact"


RatesLookup = Callable[[str, str], Optional[Rates]]
Dispatch = Callable[..., Awaitable[Dict[str, Any]]]

# Generous token estimate for the reservation: ~3 characters per token.
_CHARS_PER_TOKEN = 3


def registry_rates(model: str, provider_type: str) -> Optional[Rates]:
    """The gateway's per-token rates, or ``None`` when the model is unpriced."""
    from core.llm.providers.registry import get_registry

    r = get_registry().get_rates(model, provider_type)
    if r.get("pricing_source") == "unknown":
        return None
    return Rates(
        input=float(r["input"]),
        output=float(r["output"]),
        cache_read=float(r.get("cache_read") or 0.0),
        pricing_source=str(r.get("pricing_source")),
    )


def resolve_live_target(
    provider_id: Optional[str], model: Optional[str]
) -> Tuple[Any, str]:
    """(ProviderSpec, model): the daemon's own triage resolution by default."""
    from core.llm.router.router import get_default_provider_spec, get_provider_spec
    from evalkit.triage import processor

    if provider_id is None:
        target = type(processor())._resolve_triage_target()
        if target is None:
            raise RuntimeError("no LLM provider configured for the triage component")
        provider_id, resolved_model = target
        model = model or resolved_model
    spec = get_provider_spec(provider_id) or get_default_provider_spec()
    if spec is None:
        raise RuntimeError(f"provider {provider_id!r} is not dispatchable")
    return spec, model or spec.default_model


class LiveBackend:
    """Calls the model through ``LLMRouter.dispatch`` (Bifrost)."""

    name = "live"

    def __init__(
        self,
        *,
        provider: Any,
        model: str,
        budget: Budget,
        dispatch: Optional[Dispatch] = None,
        rates: RatesLookup = registry_rates,
        max_tokens: int = 2048,
        allow_unpriced: bool = False,
        unpriced_call_usd: float = 0.05,
    ):
        self.provider = provider
        self.model = f"{provider.provider_type}/{model}"
        self._bare_model = model
        self.budget = budget
        self.max_tokens = max_tokens
        self.allow_unpriced = allow_unpriced
        self.unpriced_call_usd = float(unpriced_call_usd)
        self._rates = rates(model, provider.provider_type)
        if self._rates is None and not allow_unpriced:
            raise BudgetExceeded(
                f"{BUDGET_ERROR_PREFIX} model {self.model} has no gateway price; "
                "the budget cap cannot be enforced (pass --allow-unpriced to "
                "count each call at a flat --unpriced-call-usd instead)"
            )
        if dispatch is None:
            from core.llm.router.router import LLMRouter

            dispatch = LLMRouter().dispatch
        self._dispatch = dispatch

    def _worst_case(self, prompt: str) -> float:
        if self._rates is None:
            return self.unpriced_call_usd
        in_tokens = len(prompt) // _CHARS_PER_TOKEN + 1
        return in_tokens * self._rates.input + self.max_tokens * self._rates.output

    def _cost(self, result: Dict[str, Any]) -> Optional[float]:
        if self._rates is None:
            return None
        in_tokens = int(result.get("input_tokens") or 0)
        out_tokens = int(result.get("output_tokens") or 0)
        cache_read = int(result.get("cache_read_tokens") or 0)
        return (
            max(0, in_tokens - cache_read) * self._rates.input
            + cache_read * self._rates.cache_read
            + out_tokens * self._rates.output
        )

    async def complete(self, prompt: str) -> BackendResult:
        worst = self._worst_case(prompt)
        try:
            await self.budget.reserve(worst)
        except BudgetExceeded as exc:
            return BackendResult(content=None, model=self.model, error=str(exc))
        started = time.monotonic()
        cost: Optional[float] = None
        try:
            result = await self._dispatch(
                provider=self.provider,
                messages=[{"role": "user", "content": prompt}],
                model=self._bare_model,
                max_tokens=self.max_tokens,
            )
            cost = self._cost(result)
        except Exception as exc:  # noqa: BLE001 — one failed call is one errored case
            await self.budget.settle(worst, None)
            return BackendResult(
                content=None,
                model=self.model,
                latency_ms=int((time.monotonic() - started) * 1000),
                error=f"{type(exc).__name__}: {exc}",
            )
        await self.budget.settle(worst, cost)
        return BackendResult(
            content=str(result.get("content") or ""),
            model=self.model,
            cost_usd=cost,
            latency_ms=int((time.monotonic() - started) * 1000),
        )


def describe(backend: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"backend": backend.name, "model": backend.model}
    if isinstance(backend, CassetteBackend):
        out["cassette"] = str(backend.path)
        out["cassette_meta"] = backend.meta
    if isinstance(backend, LiveBackend):
        out["budget_cap_usd"] = backend.budget.cap_usd
    return out


__all__: List[str] = [
    "Backend",
    "BackendResult",
    "Budget",
    "BudgetExceeded",
    "CassetteBackend",
    "CassetteRecorder",
    "LiveBackend",
    "Rates",
    "StubBackend",
    "describe",
    "read_cassette",
    "registry_rates",
    "resolve_live_target",
    "stub_answer",
]
