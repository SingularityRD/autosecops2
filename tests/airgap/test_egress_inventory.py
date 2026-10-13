"""Static egress inventory: every outbound call site is reviewed and switched off.

``egress_scan.scan()`` finds call sites; ``egress_inventory.json`` classifies
each one; ``infra/airgap/airgap.env`` is the profile that must turn them off.
The tests here hold the three together:

* ratchet -- a site, a client kind, or a higher count the scan finds that the
  inventory does not list fails (refresh with ``python -m
  tests.airgap.egress_scan --write`` and classify the new entry);
* every entry has a valid classification, and every switch it names is set
  the right way in the air-gap profile;
* MCP servers an entry relies on being off are not on by default.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Dict, Set
from urllib.parse import urlparse

import pytest

from tests.airgap import egress_scan as es

PROFILE = es.REPO_ROOT / "infra" / "airgap" / "airgap.env"
MCP_SERVICE = es.REPO_ROOT / "core" / "integrations" / "mcp" / "service.py"

CATEGORIES = {"internal", "gated", "operator-action", "local-only", "known-gap"}
OFF = {"", "false", "0", "no", "off"}
ON = {"true", "1", "yes", "on"}
EXTERNAL_KIND = re.compile(r"^(host|provider|browser-asset):")
# Switches read by third-party tools rather than by AutoSecOps settings.
TOOL_NATIVE_KEYS = {
    "NPM_CONFIG_OFFLINE",
    "UV_OFFLINE",
    "PIP_NO_INDEX",
    "TESSDATA_PREFIX",
}


def parse_env(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        out[key.strip()] = value
    return out


def allowlist(env: Dict[str, str]) -> Set[str]:
    return {
        h.strip().lower()
        for h in env.get("AIRGAP_EGRESS_ALLOWLIST", "").split(",")
        if h.strip()
    }


def is_internal_value(value: str, allowed: Set[str]) -> bool:
    """A URL or host:port that stays inside the deployment (or is allowlisted)."""
    value = value.strip()
    if not value:
        return False
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    netloc = parsed.netloc.rsplit("@", 1)[-1].lower()
    if host in allowed or netloc in allowed:
        return True
    return not es.is_external_host(host)


def switch_ok(expect: str, value: str, allowed: Set[str]) -> bool:
    v = value.strip()
    if expect == "off":
        return v.lower() in OFF
    if expect == "on":
        return v.lower() in ON
    if expect == "set":
        return bool(v)
    if expect == "internal":
        return is_internal_value(v, allowed)
    if expect.startswith("="):
        return v == expect[1:]
    raise AssertionError(f"unknown switch expectation {expect!r}")


def default_enabled_mcp_servers() -> Set[str]:
    tree = ast.parse(MCP_SERVICE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and any(
                isinstance(t, ast.Name) and t.id == "_DEFAULT_ENABLED"
                for t in node.targets
            )
            and isinstance(node.value, ast.Set)
        ):
            return {e.value for e in node.value.elts if isinstance(e, ast.Constant)}
    raise AssertionError("MCPService._DEFAULT_ENABLED not found")


@pytest.fixture(scope="module")
def found() -> Dict[str, Dict[str, int]]:
    return es.scan()


@pytest.fixture(scope="module")
def inventory() -> dict:
    return es.load_inventory()


@pytest.fixture(scope="module")
def entries(inventory) -> Dict[str, dict]:
    sites = inventory["sites"]
    ids = [e["site"] for e in sites]
    assert len(ids) == len(set(ids)), "duplicate site in egress_inventory.json"
    return {e["site"]: e for e in sites}


@pytest.fixture(scope="module")
def profile() -> Dict[str, str]:
    return parse_env(PROFILE.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# Ratchet
# --------------------------------------------------------------------------

HOW = (
    "Run `python -m tests.airgap.egress_scan --write`, then classify the new "
    "entry in tests/airgap/egress_inventory.json (see tests/airgap/README.md)."
)


def test_no_unlisted_outbound_call_sites(found, entries):
    problems = []
    for site, kinds in found.items():
        entry = entries.get(site)
        if entry is None:
            problems.append(f"{site}: not in inventory {kinds}")
            continue
        listed = entry.get("kinds", {})
        for kind, count in kinds.items():
            if kind not in listed:
                problems.append(f"{site}: new kind {kind!r} x{count}")
            elif count > listed[kind]:
                problems.append(f"{site}: {kind} {listed[kind]} -> {count}")
    assert not problems, (
        "New outbound call sites:\n  " + "\n  ".join(problems) + "\n" + HOW
    )


def test_inventory_has_no_stale_sites(found, entries):
    stale = sorted(set(entries) - set(found))
    assert not stale, f"Sites no longer found by the scan: {stale}\n{HOW}"


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------


def test_every_entry_is_classified(entries):
    bad = []
    for site, e in entries.items():
        cat = e.get("category")
        if cat not in CATEGORIES:
            bad.append(f"{site}: category {cat!r}")
            continue
        if not (e.get("note") or "").strip():
            bad.append(f"{site}: no note")
        switches = e.get("switches") or {}
        gates = e.get("gates") or []
        for g in gates:
            if not re.match(r"^(integration|mcp-server|operator-action):\S", g):
                bad.append(f"{site}: bad gate {g!r}")
        if cat == "internal" and "internal" not in switches.values():
            bad.append(f"{site}: internal without an 'internal' switch")
        if cat == "gated" and not (switches or gates):
            bad.append(f"{site}: gated without a switch or gate")
        if cat == "operator-action" and not any(
            g.startswith("operator-action:") for g in gates
        ):
            bad.append(f"{site}: operator-action without an operator-action gate")
        if cat in ("internal", "local-only") and any(
            EXTERNAL_KIND.match(k) for k in e.get("kinds", {})
        ):
            bad.append(f"{site}: {cat} but names an external host")
    assert not bad, "\n".join(bad)


def test_profile_turns_every_switch_off(entries, profile):
    allowed = allowlist(profile)
    bad = []
    for site, e in entries.items():
        for key, expect in (e.get("switches") or {}).items():
            if key not in profile:
                bad.append(f"{site}: {key} missing from airgap.env")
            elif not switch_ok(expect, profile[key], allowed):
                bad.append(f"{site}: {key}={profile[key]!r} is not {expect!r}")
    assert not bad, "\n".join(bad)


def test_switch_keys_are_real_settings(entries):
    """A switch nobody reads would pass the profile check and protect nothing."""
    keys = {
        k for e in entries.values() for k in (e.get("switches") or {})
    } - TOOL_NATIVE_KEYS
    haystack = []
    for root in (
        "core",
        "services/api",
        "services/daemon",
        "services/agent",
        "infra/docker",
    ):
        base = es.REPO_ROOT / root
        for pattern in ("*.py", "*.ts", "*.json", "*.yml"):
            for p in base.rglob(pattern):
                if "node_modules" in p.parts or "tests" in p.parts:
                    continue
                haystack.append(p.read_text(encoding="utf-8", errors="replace"))
    text = "\n".join(haystack)
    unknown = [
        k for k in sorted(keys) if not re.search(rf"\b({k}|{k.lower()})\b", text)
    ]
    assert not unknown, f"switches not read anywhere in the code: {unknown}"


def test_gated_mcp_servers_are_off_by_default(entries):
    default_on = default_enabled_mcp_servers()
    servers = json.loads((es.REPO_ROOT / es.MCP_CONFIG).read_text(encoding="utf-8"))[
        "mcpServers"
    ]
    bad = []
    for site, e in entries.items():
        for g in e.get("gates") or []:
            if not g.startswith("mcp-server:"):
                continue
            name = g.split(":", 1)[1]
            if name == "*":
                continue
            if name not in servers:
                bad.append(f"{site}: gate names unknown MCP server {name!r}")
            elif name in default_on:
                bad.append(f"{site}: MCP server {name!r} is enabled by default")
    assert not bad, "\n".join(bad)


def test_default_enabled_mcp_servers_are_offline(entries, profile):
    """A server on by default must not need the network to start."""
    default_on = default_enabled_mcp_servers()
    bad = []
    for name in sorted(default_on):
        e = entries.get(f"{es.MCP_CONFIG}#{name}")
        if e is None:
            continue  # the scan found no network launcher / host for it
        if any(EXTERNAL_KIND.match(k) or k == "mcp-remote" for k in e["kinds"]):
            bad.append(f"{name}: default-enabled server dials a remote host")
        if not e.get("switches"):
            bad.append(f"{name}: default-enabled server has no offline switch")
    assert not bad, "\n".join(bad)


def test_known_gaps_are_documented(entries):
    readme = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")
    missing = [
        site
        for site, e in entries.items()
        if e["category"] == "known-gap" and site not in readme
    ]
    assert not missing, f"known-gap sites not explained in README.md: {missing}"


# --------------------------------------------------------------------------
# Scanner self-checks (the ratchet is only as good as the scan)
# --------------------------------------------------------------------------


def test_scan_sees_aliased_and_deferred_calls():
    src = (
        "import asyncio\n"
        "import httpx as hx\n"
        "from requests import post\n"
        "import subprocess\n"
        "async def f():\n"
        "    await asyncio.to_thread(hx.get, 'https://api.vendor.io/x')\n"
        "    post('http://localhost:1')\n"
        "    subprocess.run(['git', 'clone', 'u'])\n"
        "    hx.Timeout(3)\n"
    )
    kinds = es.scan_python_source(src)
    assert kinds["httpx"] == 1
    assert kinds["requests"] == 1
    assert kinds["exec:git"] == 1
    assert kinds["host:api.vendor.io"] == 1
    assert "host:localhost:1" not in kinds


def test_scan_ignores_servers_and_errors():
    src = "from aiohttp import web\nimport httpx\nweb.Application()\nraise httpx.HTTPError('x')\n"
    assert es.scan_python_source(src) == {}


@pytest.mark.parametrize(
    "host,external",
    [
        ("api.openai.com", True),
        ("8.8.8.8", True),
        ("localhost:8080", False),
        ("127.0.0.1", False),
        ("10.1.2.3", False),
        ("bifrost:8080", False),
        ("svc.example.com", False),
        ("${SPLUNK_HOST}", False),
    ],
)
def test_external_host_classification(host, external):
    assert es.is_external_host(host) is external


def test_internal_value_respects_allowlist():
    assert is_internal_value("http://127.0.0.1:8080", set())
    assert not is_internal_value("https://siem.corp.com:8089", set())
    assert is_internal_value("https://siem.corp.com:8089", {"siem.corp.com"})
    assert not is_internal_value("", set())
