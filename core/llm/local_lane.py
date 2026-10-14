"""Local model lane: triage on an Ollama model behind Bifrost, schema-constrained.

The small/local model lane (W2.2 routes low-difficulty alerts to it) needs a
provider that is cheap, runs without the internet and cannot drift out of the
triage format. This module is that provider:

* The call goes through the existing :class:`~core.llm.router.router.LLMRouter`
  to Bifrost's ``/v1`` surface as ``ollama/<model>`` — the one egress ADR 0011
  allows, so no second client and no new network call site. There is no cloud
  fallback: a failed call is an error, never a silent switch to another model.
* The prompt is the daemon's own triage prompt (``daemon-triage-v2``, W1.2),
  sent as is with no system prompt of the lane's own: the small lane answers
  the same question the main lane does.
* Decoding is constrained with an OpenAI ``response_format`` JSON schema
  (Bifrost hands it to Ollama, which enforces it), at temperature 0. The schema
  is the verdict object that prompt asks for, built from the verdict contract
  (``core/contracts/verdict.schema.json``). The answer is validated again here,
  against that schema and the contract's own validator; an answer that does not
  fit is an error, not a guess.
* The validated object is returned as canonical JSON text, which
  ``FindingProcessor._apply_triage_result`` (``parse_triage_reply``) turns into
  the stored verdict with provenance enforced, exactly as for the main lane.
* The model is chosen by eval: ``LOCAL_LANE_MODEL`` when set, else the model
  ``python -m evalkit.local_lane rank --write-selection`` wrote to the selection
  file. Neither: :func:`get_local_lane` returns ``None`` and the lane is off.
* The lane refuses a gateway that is not local (loopback, RFC 1918, IPv6 ULA,
  dotless service name, ``.local``/``.internal``/``.svc``/``.lan``; numeric
  hosts are decoded as the IPv4 literals the resolver sees) unless
  ``LOCAL_LANE_ALLOW_NONLOCAL_GATEWAY`` says otherwise.
* An answer is accepted only from the model asked for: when Bifrost reports a
  different model (a fallback it was configured with), the answer is an error.
  ``foo`` and ``foo:latest`` are the same Ollama model; ``hf.co/<repo>`` names
  are Ollama models too.
* :func:`get_local_lane` caches the lane per process and rebuilds it only when
  the settings or the selection file (by mtime) change.

How W2.2 plugs it in (once merged) is described in ``docs/wp/w2.3.md``: when
the lane hook selected the small-model lane and :func:`get_local_lane` returns
a lane, triage calls ``await lane.triage(prompt)`` instead of the queue.
"""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional, Protocol, Tuple
from urllib.parse import urlsplit

from core.contracts import verdict as _contract

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]

PROVIDER_TYPE = "ollama"
PROVIDER_ID = "local-lane"
SELECTION_FORMAT = "autosecops.local_lane.selection/v1"

# services.daemon.probes.ACTIONS; a unit test keeps the two in step without
# core importing services. The triage prompt (daemon-triage-v2) offers these
# as recommended_action.type.
ACTIONS = ("isolate", "block", "investigate", "monitor", "dismiss")
# The verdict contract's vocabulary (W1.2, core/contracts/verdict.schema.json).
VERDICTS = _contract.VERDICTS
CATEGORIES = _contract.CATEGORIES
# Bounds that keep a constrained small model from rambling inside the object.
_MAX_LIST_ITEMS = 64
_MAX_ITEM_CHARS = 200


def _reply_schema() -> Dict[str, Any]:
    """The JSON object the triage prompt asks for, as a JSON schema.

    Built from the verdict contract (``core/contracts/verdict.schema.json``),
    minus what code stamps (``model``, ``prompt_version``, ``authored``):
    ``cited_fields`` is the list of field names the prompt asks for, and
    ``recommended_action.type`` the prompt's action vocabulary. Every key is
    required (``recommended_action`` may be null) so strict structured output
    accepts it. No ``$ref``: the schema is handed to the provider's grammar.
    """
    contract = _contract.load_schema()
    props = contract["properties"]
    action = contract["$defs"]["recommendedAction"]
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "verdict",
            "confidence",
            "category",
            "cited_fields",
            "gaps",
            "recommended_action",
        ],
        "properties": {
            "verdict": copy.deepcopy(props["verdict"]),
            "confidence": copy.deepcopy(props["confidence"]),
            "category": copy.deepcopy(props["category"]),
            "cited_fields": {
                "type": "array",
                "maxItems": _MAX_LIST_ITEMS,
                "items": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": _MAX_ITEM_CHARS,
                },
            },
            "gaps": {
                "type": "array",
                "maxItems": _MAX_LIST_ITEMS,
                "items": dict(
                    copy.deepcopy(props["gaps"]["items"]), maxLength=_MAX_ITEM_CHARS
                ),
            },
            "recommended_action": {
                "anyOf": [
                    {"type": "null"},
                    {
                        "type": "object",
                        "additionalProperties": False,
                        "required": list(action["required"]),
                        "properties": {
                            "type": {"type": "string", "enum": list(ACTIONS)},
                            "target": dict(
                                copy.deepcopy(action["properties"]["target"]),
                                maxLength=_MAX_ITEM_CHARS,
                            ),
                        },
                    },
                ]
            },
        },
    }


TRIAGE_SCHEMA: Dict[str, Any] = _reply_schema()

RESPONSE_FORMAT: Dict[str, Any] = {
    "type": "json_schema",
    "json_schema": {
        "name": "triage_verdict",
        "strict": True,
        "schema": TRIAGE_SCHEMA,
    },
}


# --------------------------------------------------------------------------
# schema
# --------------------------------------------------------------------------


class SchemaError(ValueError):
    """The model's answer does not fit :data:`TRIAGE_SCHEMA`."""


def _check_string(key: str, value: Any, rule: Mapping[str, Any]) -> None:
    if not isinstance(value, str):
        raise SchemaError(f"{key}: expected a string")
    if "enum" in rule and value not in rule["enum"]:
        raise SchemaError(f"{key}: {value!r} not in {rule['enum']}")
    if len(value) < rule.get("minLength", 0):
        raise SchemaError(f"{key}: empty")
    if "maxLength" in rule and len(value) > rule["maxLength"]:
        raise SchemaError(f"{key}: longer than {rule['maxLength']}")


def _check_object(key: str, obj: Any, rule: Mapping[str, Any]) -> None:
    if not isinstance(obj, dict):
        raise SchemaError(f"{key}: expected an object, got {type(obj).__name__}")
    props: Mapping[str, Any] = rule["properties"]
    extra = sorted(set(obj) - set(props))
    if extra:
        raise SchemaError(f"{key}: unexpected keys {extra}")
    missing = [k for k in rule["required"] if k not in obj]
    if missing:
        raise SchemaError(f"{key}: missing keys {missing}")
    for name, sub in props.items():
        _check(f"{name}" if key == "answer" else f"{key}.{name}", obj[name], sub)


def _check(key: str, value: Any, rule: Mapping[str, Any]) -> None:
    if "anyOf" in rule:
        errors = []
        for option in rule["anyOf"]:
            try:
                _check(key, value, option)
                return
            except SchemaError as exc:
                errors.append(str(exc))
        raise SchemaError("; ".join(errors))
    kind = rule["type"]
    if kind == "null":
        if value is not None:
            raise SchemaError(f"{key}: expected null")
    elif kind == "string":
        _check_string(key, value, rule)
    elif kind == "number":
        # bool is an int subclass; true is not a confidence.
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise SchemaError(f"{key}: expected a number")
        if value != value or not rule["minimum"] <= value <= rule["maximum"]:
            raise SchemaError(f"{key}: {value!r} outside [0, 1]")
    elif kind == "array":
        if not isinstance(value, list):
            raise SchemaError(f"{key}: expected an array")
        if len(value) > rule.get("maxItems", len(value)):
            raise SchemaError(f"{key}: more than {rule['maxItems']} items")
        for item in value:
            _check(f"{key}[]", item, rule["items"])
    elif kind == "object":
        _check_object(key, value, rule)
    else:  # pragma: no cover — the schema above uses only these
        raise SchemaError(f"{key}: unsupported schema type {kind!r}")


def validate_assessment(obj: Any) -> Dict[str, Any]:
    """``obj`` if it fits :data:`TRIAGE_SCHEMA` and the verdict contract,
    else :class:`SchemaError`."""
    _check_object("answer", obj, TRIAGE_SCHEMA)
    # The contract's own validator, as the daemon will run it (provenance is
    # the daemon's to apply; an empty map only checks the shape).
    from pydantic import ValidationError

    try:
        _contract.verdict_from_model_output(
            obj, {}, model="local-lane", prompt_version="local-lane-check"
        )
    except ValidationError as exc:
        kinds = sorted({err.get("type", "invalid") for err in exc.errors()})
        raise SchemaError(f"verdict contract: {', '.join(kinds)}") from None
    return obj


_FENCED = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.DOTALL)


def _no_duplicates(pairs: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise SchemaError(f"repeated key {key!r}")
        out[key] = value
    return out


def _no_constants(name: str) -> Any:
    raise SchemaError(f"{name} is not JSON")


def parse_assessment(content: Optional[str]) -> Dict[str, Any]:
    """The validated verdict object in a model answer, else :class:`SchemaError`.

    As strict as the daemon's reply parser: the whole answer (optionally one
    ```json fence), no repeated keys, no NaN/Infinity.
    """
    text = (content or "").strip()
    if not text:
        raise SchemaError("empty answer")
    fenced = _FENCED.match(text)
    if fenced:
        text = fenced.group(1)
    try:
        obj = json.loads(
            text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants
        )
    except json.JSONDecodeError as exc:
        raise SchemaError(f"not JSON ({exc.msg})") from exc
    except RecursionError:
        raise SchemaError("nested too deeply") from None
    return validate_assessment(obj)


def render_reply(obj: Mapping[str, Any]) -> str:
    """The validated object as the JSON verdict text the daemon's
    ``parse_triage_reply`` reads (canonical, ASCII-only: no line separators
    or invisible characters survive as raw text)."""
    return json.dumps(dict(obj), ensure_ascii=True, sort_keys=True)


# --------------------------------------------------------------------------
# air gap
# --------------------------------------------------------------------------

_LOCAL_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".svc",
    ".cluster.local",
    ".lan",
    ".home.arpa",
)

# Cloud metadata services: local-looking, but the one place a gateway must
# never point (credentials live there).
_METADATA_NAMES = frozenset(
    {
        "metadata",
        "metadata.google.internal",
        "instance-data",
        "instance-data.ec2.internal",
    }
)

# An explicit allowlist, not ``ip.is_private``: Python's "private" also covers
# 6to4 (2002::/16), 240.0.0.0/4, 198.18.0.0/15 and 192.0.0.0/24, none of which
# is this deployment's own network. Link-local is left out entirely: nothing
# serves a gateway there and 169.254.169.254 / fd00:ec2::254 are metadata.
_ALLOWED_NETS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
    )
)
_DENIED_ADDRS = frozenset(
    ipaddress.ip_address(a) for a in ("169.254.169.254", "fd00:ec2::254")
)

# What ``inet_aton`` (glibc, and so httpx/getaddrinfo) reads as an IPv4
# literal: 1-4 dot-separated parts, each decimal, 0x-hex or 0-octal.
# Anything that starts like one (a digit, then digits / hex / x / dots) is
# treated as one: when inet_aton refuses it, getaddrinfo sends it to DNS,
# which is egress, so the gateway check refuses it too.
_NUMERIC_HOST = re.compile(r"^[0-9][0-9a-fx.]*$")
_HEX_PART = re.compile(r"^0x[0-9a-f]+$")
_OCT_PART = re.compile(r"^0[0-7]*$")
_DEC_PART = re.compile(r"^[1-9][0-9]*$")


def _inet_aton(host: str) -> Optional[ipaddress.IPv4Address]:
    """``host`` decoded the way ``inet_aton`` does (``2130706433``,
    ``0x7f.1``, ``0177.0.0.1``, ``127.1``), or None if it is not valid."""
    parts = host.lower().split(".")
    if not 1 <= len(parts) <= 4:
        return None
    nums = []
    for part in parts:
        # Each part exactly as inet_aton's strtoul reads it: no second "0x"
        # (Python's int(..., 16) would accept "0x0x7f"), no empty part (a
        # trailing dot), no sign, underscore or whitespace.
        if _HEX_PART.match(part):
            n = int(part[2:], 16)
        elif _OCT_PART.match(part):
            n = int(part, 8)
        elif _DEC_PART.match(part):
            n = int(part, 10)
        else:
            return None
        nums.append(n)
    *head, last = nums
    if any(n > 0xFF for n in head) or last >= 1 << (8 * (4 - len(head))):
        return None
    value = 0
    for n in head:
        value = (value << 8) | n
    value = (value << (8 * (4 - len(head)))) | last
    return ipaddress.IPv4Address(value)


def _ip_is_local(ip: "ipaddress.IPv4Address | ipaddress.IPv6Address") -> bool:
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if ip in _DENIED_ADDRS:
        return False
    return any(ip.version == net.version and ip in net for net in _ALLOWED_NETS)


def is_local_endpoint(url: str) -> bool:
    """Whether ``url`` names this machine or the deployment's own network.

    Literal addresses must be loopback, RFC 1918 or IPv6 ULA (``fc00::/7``);
    a host that is all digits / hex / dots is an IPv4 literal to the resolver
    (``http://134744072`` is 8.8.8.8) and is decoded as one, or refused when
    ``inet_aton`` would not decode it (``0x0x7f.1``, ``127.0.0.1.``): libc
    then resolves it as a name. Names must be ``localhost``, a dotless service name
    (compose / Kubernetes short names) or end in a local-only suffix, and not
    name a cloud metadata service. No DNS lookup: resolving a name would itself
    be the egress being guarded against.
    """
    try:
        raw = (urlsplit(url).hostname or "").strip().lower()
    except ValueError:
        return False
    host = raw.rstrip(".")
    if not host:
        return False
    if "%" in host:  # IPv6 zone id: link-local by construction
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None or _NUMERIC_HOST.match(host):
        # A trailing dot makes an address a DNS name to libc (inet_aton
        # refuses "127.0.0.1."), and a name is looked up: refused.
        if raw != host:
            return False
        if ip is None:
            ip = _inet_aton(host)
        return ip is not None and _ip_is_local(ip)
    if host in _METADATA_NAMES:
        return False
    return host == "localhost" or "." not in host or host.endswith(_LOCAL_SUFFIXES)


class NonLocalGateway(ValueError):
    """The configured gateway is not local and the override is off."""


# --------------------------------------------------------------------------
# the lane
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class LaneAnswer:
    """One triage answer from the lane, or why there is none.

    ``content`` is the verdict JSON text ``parse_triage_reply`` reads
    (``None`` on error); ``structured`` the validated object it was rendered
    from.
    """

    content: Optional[str]
    model: str
    structured: Optional[Dict[str, Any]] = None
    latency_ms: Optional[int] = None
    input_tokens: int = 0
    output_tokens: int = 0
    error: Optional[str] = None


class SmallModelProvider(Protocol):
    """What the small-model lane needs from a provider."""

    name: str
    model: str

    async def triage(self, prompt: str) -> LaneAnswer: ...


Dispatch = Callable[..., Awaitable[Dict[str, Any]]]


def ollama_model_key(name: str) -> str:
    """``name`` as Ollama resolves it: an untagged name means ``:latest``.

    The tag is looked for in the last path segment only, so a registry host
    with a port (``host:5000/repo``) is not mistaken for one.
    """
    head, _, last = name.rpartition("/")
    if ":" not in last:
        last = f"{last}:latest"
    return f"{head}/{last}" if head else last


class LocalModelLane:
    """Triage on ``ollama/<model>`` through Bifrost with a JSON-schema answer."""

    name = "local_lane"

    def __init__(
        self,
        model: str,
        *,
        bifrost_url: str,
        timeout_s: float = 60.0,
        max_tokens: int = 512,
        allow_nonlocal_gateway: bool = False,
        dispatch: Optional[Dispatch] = None,
    ):
        model = (model or "").strip()
        if model.startswith(f"{PROVIDER_TYPE}/"):
            model = model[len(PROVIDER_TYPE) + 1 :]
        if not model:
            raise ValueError("local lane needs a model")
        if not allow_nonlocal_gateway and not is_local_endpoint(bifrost_url):
            raise NonLocalGateway(
                f"gateway {bifrost_url!r} is not local; the local model lane "
                "only talks to a local gateway (LOCAL_LANE_ALLOW_NONLOCAL_GATEWAY)"
            )
        from core.llm.router.router import ProviderSpec

        self.bare_model = model
        self.model = f"{PROVIDER_TYPE}/{model}"
        self.bifrost_url = bifrost_url.rstrip("/")
        self.timeout_s = float(timeout_s)
        self.max_tokens = int(max_tokens)
        self.provider = ProviderSpec(
            provider_id=PROVIDER_ID,
            provider_type=PROVIDER_TYPE,
            base_url=None,
            api_key_ref=None,
            default_model=model,
            config={},
        )
        if dispatch is None:
            from core.llm.router.router import LLMRouter

            dispatch = LLMRouter(bifrost_url=self.bifrost_url).dispatch
        self._dispatch = dispatch

    @property
    def target(self) -> Tuple[str, str]:
        """(provider_type, model) as Bifrost routes it."""
        return PROVIDER_TYPE, self.bare_model

    def answered_by_me(self, reported: str) -> bool:
        """Whether ``reported`` (the response's ``model``) is this lane's model.

        Bifrost may echo ``ollama/<model>`` or the provider's bare ``<model>``;
        Ollama adds ``:latest`` to an untagged name (and the configured name may
        carry it when the answer does not). ``hf.co/<user>/<repo>[:tag]`` is an
        Ollama model name, slash and all. Anything else (or nothing) is another
        model answering, e.g. a Bifrost fallback chain.
        """
        name = reported.strip()
        if not name:
            return False
        if name.startswith(f"{PROVIDER_TYPE}/"):
            name = name[len(PROVIDER_TYPE) + 1 :]
        return ollama_model_key(name) == ollama_model_key(self.bare_model)

    async def triage(self, prompt: str) -> LaneAnswer:
        started = time.monotonic()

        def elapsed() -> int:
            return int((time.monotonic() - started) * 1000)

        try:
            result = await asyncio.wait_for(
                self._dispatch(
                    provider=self.provider,
                    messages=[{"role": "user", "content": prompt}],
                    system_prompt=None,
                    model=self.bare_model,
                    max_tokens=self.max_tokens,
                    temperature=0.0,
                    response_format=RESPONSE_FORMAT,
                ),
                timeout=self.timeout_s,
            )
        except asyncio.TimeoutError:
            return LaneAnswer(
                content=None,
                model=self.model,
                latency_ms=elapsed(),
                error=f"timeout: no answer within {self.timeout_s:g}s",
            )
        except Exception as exc:  # noqa: BLE001 — one failed call is one error
            return LaneAnswer(
                content=None,
                model=self.model,
                latency_ms=elapsed(),
                error=f"{type(exc).__name__}: {exc}",
            )

        tokens = {
            "input_tokens": int(result.get("input_tokens") or 0),
            "output_tokens": int(result.get("output_tokens") or 0),
        }
        answered_by = str(result.get("model") or "").strip()
        if not self.answered_by_me(answered_by):
            return LaneAnswer(
                content=None,
                model=self.model,
                latency_ms=elapsed(),
                error=(
                    f"model: answer came from {answered_by or 'an unnamed model'!r}, "
                    f"not {self.model!r}; refusing a gateway fallback"
                ),
                **tokens,
            )
        try:
            obj = parse_assessment(result.get("content"))
        except SchemaError as exc:
            return LaneAnswer(
                content=None,
                model=self.model,
                latency_ms=elapsed(),
                error=f"schema: {exc}",
                **tokens,
            )
        return LaneAnswer(
            content=render_reply(obj),
            model=self.model,
            structured=obj,
            latency_ms=elapsed(),
            **tokens,
        )


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------


def _resolve(path: str) -> Path:
    p = Path(path)
    return p if p.is_absolute() else REPO_ROOT / p


def read_selection(path: Path) -> Optional[str]:
    """The model a selection file names, or None (missing / unreadable)."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        logger.warning("local lane selection %s unreadable: %s", path, exc)
        return None
    if not isinstance(data, dict) or data.get("format") != SELECTION_FORMAT:
        logger.warning("local lane selection %s is not %s", path, SELECTION_FORMAT)
        return None
    model = data.get("model")
    if not isinstance(model, str) or not model.strip():
        logger.warning("local lane selection %s names no model", path)
        return None
    return model.strip()


def selected_model(settings: Any = None) -> Optional[str]:
    """``LOCAL_LANE_MODEL``, else the eval-selected model, else None."""
    if settings is None:
        from core.config import get_settings

        settings = get_settings()
    explicit = (settings.local_lane_model or "").strip()
    if explicit:
        return explicit
    return read_selection(_resolve(settings.local_lane_selection_file))


def _selection_stamp(path: Path) -> Optional[Tuple[int, int, int]]:
    """What changes when the selection file is rewritten (None: no file)."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size, st.st_ino)


def _build_lane(
    settings: Any, model: Optional[str], dispatch: Optional[Dispatch]
) -> Optional[LocalModelLane]:
    if not model:
        return None
    try:
        return LocalModelLane(
            model,
            bifrost_url=settings.bifrost_url,
            timeout_s=settings.local_lane_timeout_s,
            max_tokens=settings.local_lane_max_tokens,
            allow_nonlocal_gateway=settings.local_lane_allow_nonlocal_gateway,
            dispatch=dispatch,
        )
    except NonLocalGateway as exc:
        logger.warning("local model lane off: %s", exc)
        return None


# One lane per process: (cache key, lane or None). Rebuilt when a setting
# the lane is made from changes or the selection file is rewritten (mtime),
# so a new eval selection takes effect without a restart and a triage call
# neither re-reads the file nor builds a new HTTP client.
_CACHE: Optional[Tuple[Tuple[Any, ...], Optional[LocalModelLane]]] = None
_CACHE_LOCK = threading.Lock()


def reset_local_lane_cache() -> None:
    """Forget the cached lane (tests; settings reloaded in place)."""
    global _CACHE
    with _CACHE_LOCK:
        _CACHE = None


def get_local_lane(
    settings: Any = None, *, dispatch: Optional[Dispatch] = None
) -> Optional[LocalModelLane]:
    """The configured lane, or None when no model is configured or selected,
    or when the gateway is not local and the override is off.

    Cached per process (see ``_CACHE``); a call with its own ``dispatch`` is
    built fresh and not cached.
    """
    global _CACHE
    if settings is None:
        from core.config import get_settings

        settings = get_settings()
    if dispatch is not None:
        return _build_lane(settings, selected_model(settings), dispatch)
    explicit = (settings.local_lane_model or "").strip()
    path = _resolve(settings.local_lane_selection_file)
    key = (
        explicit,
        str(path),
        None if explicit else _selection_stamp(path),
        settings.bifrost_url,
        settings.local_lane_timeout_s,
        settings.local_lane_max_tokens,
        settings.local_lane_allow_nonlocal_gateway,
    )
    with _CACHE_LOCK:
        if _CACHE is not None and _CACHE[0] == key:
            return _CACHE[1]
        lane = _build_lane(settings, explicit or read_selection(path), None)
        _CACHE = (key, lane)
        return lane


__all__ = [
    "ACTIONS",
    "CATEGORIES",
    "VERDICTS",
    "LaneAnswer",
    "LocalModelLane",
    "NonLocalGateway",
    "RESPONSE_FORMAT",
    "SchemaError",
    "SmallModelProvider",
    "TRIAGE_SCHEMA",
    "get_local_lane",
    "is_local_endpoint",
    "parse_assessment",
    "ollama_model_key",
    "read_selection",
    "reset_local_lane_cache",
    "render_reply",
    "selected_model",
    "validate_assessment",
]
