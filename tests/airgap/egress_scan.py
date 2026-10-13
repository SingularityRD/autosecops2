"""Find every place AutoSecOps can open an outbound connection.

The scan is static and deliberately coarse: it reports *call sites* that build
a network client or make a request (per file, per client kind, with a count),
and the external hosts those files name. It does not decide whether a site is
safe; ``tests/airgap/egress_inventory.json`` says that, one reviewed entry per
site, and ``test_egress_inventory.py`` holds the two together.

Run as a script to see what the scan finds, or to refresh the counts in the
inventory after a reviewed change (new sites are added as UNREVIEWED, which the
test refuses until someone classifies them):

    python -m tests.airgap.egress_scan            # print the scan
    python -m tests.airgap.egress_scan --write    # merge into the inventory

Four kinds of source are scanned:

* Python under ``core/``, ``services/`` and ``tools/`` (AST: imports resolved,
  calls matched by dotted name; ``subprocess`` launching a network CLI);
* the TypeScript agent layer under ``services/agent/`` (line patterns);
* the web console's static entry points (an external ``src``/``href``/``url()``
  would make every browser that opens the console reach the internet);
* configuration that names a destination: ``mcp-config.json`` servers and the
  Bifrost provider seed in ``infra/docker/bifrost/config.json``.

Postgres and Redis clients are not listed: they are the deployment's own state
stores and the air-gap profile points them at local hosts like every other
internal URL (see ``infra/airgap/airgap.env``).
"""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[2]
INVENTORY = Path(__file__).resolve().parent / "egress_inventory.json"

PY_ROOTS = ("core", "services", "tools")
SKIP_PARTS = {"__pycache__", "node_modules", "venv", ".venv", "tests", "test"}

# --------------------------------------------------------------------------
# Python: which dotted call names open (or prepare to open) a connection.
# --------------------------------------------------------------------------

# (dotted prefix, kind). The longest matching prefix wins; kind None = ignore.
PY_RULES: Tuple[Tuple[str, Optional[str]], ...] = (
    ("httpx", "httpx"),
    ("requests", "requests"),
    ("requests.auth", None),
    ("requests.adapters", None),
    ("requests.exceptions", None),
    ("aiohttp", "aiohttp"),
    ("aiohttp.web", None),  # a server, not a client
    ("aiohttp.ClientTimeout", None),
    ("aiohttp.BasicAuth", None),
    ("aiohttp.FormData", None),
    ("aiohttp.TCPConnector", None),
    ("urllib.request.urlopen", "urllib"),
    ("urllib.request.build_opener", "urllib"),
    ("urllib.request.urlretrieve", "urllib"),
    ("urllib3.PoolManager", "urllib3"),
    ("urllib3.ProxyManager", "urllib3"),
    ("urllib3.request", "urllib3"),
    ("http.client.HTTPConnection", "http.client"),
    ("http.client.HTTPSConnection", "http.client"),
    ("socket.create_connection", "socket"),
    ("socket.socket", "socket"),
    ("socket.getaddrinfo", "dns"),
    ("socket.gethostbyname", "dns"),
    ("socket.gethostbyname_ex", "dns"),
    ("socket.gethostbyaddr", "dns"),
    ("smtplib.SMTP", "smtp"),
    ("smtplib.SMTP_SSL", "smtp"),
    ("aiosmtplib", "smtp"),
    ("websockets.connect", "websocket"),
    ("websockets.client.connect", "websocket"),
    ("aiokafka.AIOKafkaConsumer", "kafka"),
    ("aiokafka.AIOKafkaProducer", "kafka"),
    ("kafka.KafkaConsumer", "kafka"),
    ("kafka.KafkaProducer", "kafka"),
    ("boto3.client", "aws-sdk"),
    ("boto3.resource", "aws-sdk"),
    ("boto3.Session", "aws-sdk"),
    ("boto3.session.Session", "aws-sdk"),
    ("anthropic.Anthropic", "llm-sdk"),
    ("anthropic.AsyncAnthropic", "llm-sdk"),
    ("openai.OpenAI", "llm-sdk"),
    ("openai.AsyncOpenAI", "llm-sdk"),
    ("sentry_sdk.init", "sentry"),
    ("opentelemetry.exporter", "otel-exporter"),
    ("mcp.client.stdio.stdio_client", "mcp-client"),
    ("mcp.client.sse.sse_client", "mcp-client"),
    ("mcp.client.streamable_http.streamablehttp_client", "mcp-client"),
    ("mcp.client.streamable_http.streamable_http_client", "mcp-client"),
    ("ldap3.Connection", "ldap"),
    ("paramiko.SSHClient", "ssh"),
    ("git.Repo.clone_from", "exec:git"),
    ("taxii2client", "taxii"),
    ("azure.identity", "azure-sdk"),
    ("azure.mgmt", "azure-sdk"),
    ("sshtunnel.SSHTunnelForwarder", "ssh"),
    # Native code: fetches Tesseract language data from the internet on first OCR
    # unless TESSDATA_PREFIX names a folder that has it.
    ("liteparse.LiteParse", "ocr-data-download"),
    # Downloads BPE files from a public blob store on first use unless
    # TIKTOKEN_CACHE_DIR already holds them.
    ("tiktoken.get_encoding", "model-data-download"),
    ("tiktoken.encoding_for_model", "model-data-download"),
)

# Names under a client module that build values, not connections.
_INERT_LEAVES = {
    "Timeout",
    "Limits",
    "URL",
    "Headers",
    "Cookies",
    "QueryParams",
    "Request",
    "Response",
    "BasicAuth",
    "DigestAuth",
    "Auth",
    "Proxy",
    "codes",
    "MockTransport",
    "ASGITransport",
    "WSGITransport",
}

SUBPROCESS_CALLS = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
    "os.system",
    "os.popen",
}
# Command-line tools that reach the network on their own.
NET_COMMANDS = {
    "git",
    "npx",
    "npm",
    "pip",
    "pip3",
    "uv",
    "uvx",
    "curl",
    "wget",
    "docker",
    "ssh",
    "scp",
    "rsync",
    "nc",
    "helm",
    "kubectl",
}

# Hosts that are this machine, a deployment-internal service name, or reserved
# for documentation and tests -- naming them is not naming an outside party.
_LOCAL_HOSTS = {"localhost", "0.0.0.0", "::1", "[::1]"}
_RESERVED_SUFFIXES = (
    ".invalid",
    ".test",
    ".example",
    ".local",
    ".localhost",
    ".internal",
    ".svc",
    ".cluster.local",
)
_RESERVED_DOMAINS = ("example.com", "example.org", "example.net")
URL_RE = re.compile(r"\b(?:https?|wss?)://([A-Za-z0-9.\-\[\]:_${}]+)")


def is_external_host(host: str) -> bool:
    """True for a host an air-gapped install could not reach by definition."""
    host = host.strip().lower().rstrip(".")
    if host.startswith("[") and "]" in host:
        host = host[1 : host.index("]")]
    elif host.count(":") == 1:
        host = host.split(":", 1)[0]
    if not host or "$" in host or "{" in host:
        return False  # templated: the destination is configuration
    if host in _LOCAL_HOSTS or host.startswith("127."):
        return False
    if "." not in host:
        return False  # a compose/k8s service name (bifrost, postgres, ...)
    if host.endswith(_RESERVED_SUFFIXES):
        return False
    if any(host == d or host.endswith("." + d) for d in _RESERVED_DOMAINS):
        return False
    try:
        import ipaddress

        ip = ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local)
    except ValueError:
        return True


def _relative(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def python_files() -> List[Path]:
    files = []
    for root in PY_ROOTS:
        for path in (REPO_ROOT / root).rglob("*.py"):
            rel = path.relative_to(REPO_ROOT).parts
            if any(p in SKIP_PARTS for p in rel):
                continue
            if rel[:2] == ("services", "agent"):
                continue
            if path.name.startswith("test_") or path.name == "conftest.py":
                continue
            files.append(path)
    return sorted(files)


def _dotted(node: ast.AST) -> Optional[str]:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _bindings(tree: ast.AST) -> Dict[str, str]:
    """Local name -> fully dotted module/attribute, from every import."""
    out: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    out[alias.asname] = alias.name
                else:
                    top = alias.name.split(".")[0]
                    out.setdefault(top, top)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                out[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return out


def _kind_for(full: str) -> Optional[str]:
    best: Tuple[int, Optional[str]] = (-1, None)
    for prefix, kind in PY_RULES:
        if full == prefix or full.startswith(prefix + "."):
            if len(prefix) > best[0]:
                best = (len(prefix), kind)
    kind = best[1]
    if kind is None:
        return None
    leaf = full.rsplit(".", 1)[-1]
    if leaf in _INERT_LEAVES or leaf.endswith(("Error", "Exception", "Warning")):
        return None
    return kind


def _command_of(call: ast.Call) -> Optional[str]:
    if not call.args:
        return None
    first = call.args[0]
    token: Optional[str] = None
    if isinstance(first, (ast.List, ast.Tuple)) and first.elts:
        head = first.elts[0]
        if isinstance(head, ast.Constant) and isinstance(head.value, str):
            token = head.value
    elif isinstance(first, ast.Constant) and isinstance(first.value, str):
        token = first.value.split()[0] if first.value.split() else None
    if not token:
        return None
    name = token.rsplit("/", 1)[-1]
    return name if name in NET_COMMANDS else None


def _docstring_lines(tree: ast.AST) -> set:
    lines = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            first = node.body[0] if node.body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                lines.add(first.value.lineno)
    return lines


def scan_python_source(text: str) -> Dict[str, int]:
    """Kind -> count of outbound call sites (plus ``host:<h>`` for named hosts)."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {}
    binds = _bindings(tree)
    kinds: Dict[str, int] = {}

    def resolve(expr: ast.AST) -> Optional[str]:
        dotted = _dotted(expr)
        if not dotted:
            return None
        head, _, rest = dotted.partition(".")
        if head not in binds:
            return None
        return binds[head] + ("." + rest if rest else "")

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        full = resolve(node.func)
        if full in SUBPROCESS_CALLS:
            cmd = _command_of(node)
            if cmd:
                kinds[f"exec:{cmd}"] = kinds.get(f"exec:{cmd}", 0) + 1
            continue
        # The call itself, and a client function handed to another call to run
        # (asyncio.to_thread(httpx.get, ...), loop.run_in_executor(None, ...)).
        targets = [full] + [
            resolve(a) for a in node.args if isinstance(a, (ast.Name, ast.Attribute))
        ]
        for target in targets:
            kind = _kind_for(target) if target else None
            if kind:
                kinds[kind] = kinds.get(kind, 0) + 1
    if kinds:
        prose = _docstring_lines(tree)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.lineno not in prose
            ):
                for host in URL_RE.findall(node.value):
                    if is_external_host(host):
                        key = f"host:{host.lower()}"
                        kinds[key] = kinds.get(key, 0) + 1
    return kinds


# --------------------------------------------------------------------------
# TypeScript agent layer.
# --------------------------------------------------------------------------

TS_ROOT = "services/agent"
TS_RULES: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("llm-sdk", re.compile(r"\bnew\s+(?:OpenAI|Anthropic)\s*\(")),
    ("fetch", re.compile(r"globalThis\.fetch\b|(?<![\w.])fetch\s*\(")),
    ("node-http", re.compile(r"\bhttps?\.(?:request|get)\s*\(")),
    ("socket", re.compile(r"\b(?:net|tls)\.connect\s*\(")),
    ("websocket", re.compile(r"\bnew\s+WebSocket\s*\(")),
    ("exec", re.compile(r"\b(?:spawn|execFile|execSync|exec)\s*\(\s*[\"'`]")),
)


def ts_files() -> List[Path]:
    root = REPO_ROOT / TS_ROOT
    out = []
    for path in root.rglob("*.ts"):
        rel = path.relative_to(root).parts
        if any(p in ("node_modules", "tests", "scripts", "dist") for p in rel):
            continue
        if path.name.endswith((".test.ts", ".spec.ts", ".d.ts")):
            continue
        out.append(path)
    return sorted(out)


def scan_ts_source(text: str) -> Dict[str, int]:
    kinds: Dict[str, int] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("//", "*", "/*")):
            continue
        for kind, pattern in TS_RULES:
            n = len(pattern.findall(line))
            if n:
                kinds[kind] = kinds.get(kind, 0) + n
    if kinds:
        for line in text.splitlines():
            if line.strip().startswith(("//", "*", "/*")):
                continue
            for host in URL_RE.findall(line):
                if is_external_host(host):
                    key = f"host:{host.lower()}"
                    kinds[key] = kinds.get(key, 0) + 1
    return kinds


# --------------------------------------------------------------------------
# Web console static assets.
# --------------------------------------------------------------------------

WEB_ROOT = "clients/web"
_ASSET_RE = re.compile(
    r"""(?:\bsrc|\bhref)\s*=\s*["'](https?:)?//([^"'/]+)|url\(\s*["']?(https?:)?//([^"')/]+)|@import\s+["'](https?:)?//([^"'/]+)"""
)


def web_files() -> List[Path]:
    root = REPO_ROOT / WEB_ROOT
    out: List[Path] = []
    for name in ("index.html",):
        if (root / name).exists():
            out.append(root / name)
    for sub, globs in (("public", ("*.html", "*.css")), ("src", ("*.css", "*.html"))):
        base = root / sub
        if base.is_dir():
            for g in globs:
                out.extend(p for p in base.rglob(g) if "node_modules" not in p.parts)
    return sorted(set(out))


def scan_web_source(text: str) -> Dict[str, int]:
    kinds: Dict[str, int] = {}
    for m in _ASSET_RE.finditer(text):
        host = next(g for g in (m.group(2), m.group(4), m.group(6)) if g)
        if is_external_host(host):
            key = f"browser-asset:{host.lower()}"
            kinds[key] = kinds.get(key, 0) + 1
    return kinds


# --------------------------------------------------------------------------
# Configuration that names destinations.
# --------------------------------------------------------------------------

MCP_CONFIG = "mcp-config.json"
BIFROST_CONFIG = "infra/docker/bifrost/config.json"


def scan_mcp_config(data: dict) -> Dict[str, Dict[str, int]]:
    """``mcp-config.json#<server>`` -> kinds.

    ``npx``/``uvx``/``docker`` resolve the package or image from a registry at
    launch unless it is already cached; ``mcp-remote`` and a ``url`` dial a
    remote MCP server; an external host in args/env is a vendor API.
    """
    out: Dict[str, Dict[str, int]] = {}
    for name, server in (data.get("mcpServers") or {}).items():
        if name.startswith("_") or not isinstance(server, dict):
            continue
        kinds: Dict[str, int] = {}
        command = (server.get("command") or "").rsplit("/", 1)[-1]
        args = [str(a) for a in server.get("args") or []]
        if command in NET_COMMANDS:
            kinds[f"exec:{command}"] = 1
        if any(a.startswith("git+") for a in args):
            kinds["exec:git"] = 1
        if any("mcp-remote" in a for a in args) or server.get("url"):
            kinds["mcp-remote"] = 1
        values = list(args) + [
            str(v)
            for k, v in (server.get("env") or {}).items()
            if not str(k).startswith("_")
        ]
        if server.get("url"):
            values.append(str(server["url"]))
        for value in values:
            for host in URL_RE.findall(value):
                if is_external_host(host):
                    kinds[f"host:{host.lower()}"] = (
                        kinds.get(f"host:{host.lower()}", 0) + 1
                    )
        if kinds:
            out[f"{MCP_CONFIG}#{name}"] = kinds
    return out


# Bifrost talks to each provider's public API unless network_config.base_url
# points it elsewhere. The default host per provider type, as Bifrost uses it.
BIFROST_DEFAULT_HOSTS = {
    "anthropic": "api.anthropic.com",
    "openai": "api.openai.com",
    "gemini": "generativelanguage.googleapis.com",
    "vertex": "aiplatform.googleapis.com",
    "bedrock": "bedrock-runtime.amazonaws.com",
    "azure": "openai.azure.com",
    "mistral": "api.mistral.ai",
    "groq": "api.groq.com",
    "cohere": "api.cohere.ai",
}


def scan_bifrost_config(data: dict) -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {}
    for name, provider in (data.get("providers") or {}).items():
        network = (provider or {}).get("network_config") or {}
        base = network.get("base_url")
        if base:
            host = urlparse(base).hostname or ""
            if not is_external_host(host):
                continue
        else:
            host = BIFROST_DEFAULT_HOSTS.get(name, "")
            if not host:
                continue  # e.g. ollama: its URL is a key (OLLAMA_URL), not a default
        out[f"{BIFROST_CONFIG}#{name}"] = {f"provider:{host}": 1}
    return out


# --------------------------------------------------------------------------


def scan() -> Dict[str, Dict[str, int]]:
    """Site id -> {kind: count} for the whole repository."""
    sites: Dict[str, Dict[str, int]] = {}
    for path in python_files():
        kinds = scan_python_source(path.read_text(encoding="utf-8"))
        if any(not k.startswith("host:") for k in kinds):
            sites[_relative(path)] = kinds
    for path in ts_files():
        kinds = scan_ts_source(path.read_text(encoding="utf-8"))
        if any(not k.startswith("host:") for k in kinds):
            sites[_relative(path)] = kinds
    for path in web_files():
        kinds = scan_web_source(path.read_text(encoding="utf-8", errors="replace"))
        if kinds:
            sites[_relative(path)] = kinds
    mcp = REPO_ROOT / MCP_CONFIG
    if mcp.exists():
        sites.update(scan_mcp_config(json.loads(mcp.read_text(encoding="utf-8"))))
    bifrost = REPO_ROOT / BIFROST_CONFIG
    if bifrost.exists():
        sites.update(
            scan_bifrost_config(json.loads(bifrost.read_text(encoding="utf-8")))
        )
    return dict(sorted(sites.items()))


def load_inventory(path: Path = INVENTORY) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def merge(inventory: dict, found: Dict[str, Dict[str, int]]) -> dict:
    """Refresh counts from ``found``; new sites arrive UNREVIEWED, gone ones leave."""
    by_id = {e["site"]: e for e in inventory.get("sites", [])}
    merged = []
    for site, kinds in found.items():
        entry = dict(by_id.get(site) or {"site": site, "category": "UNREVIEWED"})
        entry["kinds"] = kinds
        merged.append(entry)
    inventory = dict(inventory)
    inventory["sites"] = merged
    return inventory


def dump(inventory: dict) -> str:
    return json.dumps(inventory, indent=2, ensure_ascii=False) + "\n"


def _main(argv: Iterable[str]) -> int:
    found = scan()
    if "--write" in argv:
        inv = load_inventory() if INVENTORY.exists() else {"sites": []}
        INVENTORY.write_text(dump(merge(inv, found)), encoding="utf-8")
        print(f"wrote {len(found)} site(s) to {_relative(INVENTORY)}")
        return 0
    for site, kinds in found.items():
        print(site, json.dumps(kinds, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
