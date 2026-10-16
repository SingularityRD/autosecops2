"""The README and admin-guide connector lists follow SERVER_SUPPORT (W0.28).

``clients/web/src/screens/settings/integrationsData.ts`` holds the one status
map the console reads. The README's Experimental paragraph and the admin
guide's "Bağlayıcı destek durumu" table name the same servers in words; a
server added to or removed from the map without the docs fails here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]
DATA = REPO / "clients/web/src/screens/settings/integrationsData.ts"
README = REPO / "README.md"
GUIDE = REPO / "docs/guide/yonetici-kilavuzu.md"

# server id -> the name the docs use (README and guide alike)
DOC_NAMES = {
    "experimental": {
        "crowdstrike": "CrowdStrike Falcon",
        "sentinelone": "SentinelOne",
        "azure-sentinel": "Microsoft Sentinel",
        "splunk": "Splunk MCP",
        "gcp-secops": "Google SecOps",
        "gcp-threat-intel": "Google Threat Intelligence",
        "joe-sandbox": "Joe Sandbox",
        "vstrike": "vStrike",
        "atomic-red-team": "Atomic Red Team",
        "cape-sandbox": "CAPE Sandbox",
        # the response executors (W0.37)
        "microsoft-defender": "Microsoft Defender",
        "azure-ad": "Entra ID (Azure AD)",
        "palo-alto": "Palo Alto",
    },
    "wip": {
        "carbon-black": "Carbon Black",
        "hybrid-analysis": "Hybrid Analysis",
        "anyrun": "ANY.RUN",
        "alienvault-otx": "AlienVault OTX",
        "slack": "Slack",
        "misp": "MISP",
        "ip-geolocation": "IP Geolocation",
        "url-analysis": "URL Analysis",
        "microsoft-teams": "Microsoft Teams",
    },
}


def _support_map() -> dict[str, str]:
    text = DATA.read_text(encoding="utf-8")
    body = text[text.index("const SERVER_SUPPORT") :]
    body = body[body.index("{") + 1 : body.index("\n}")]
    return dict(re.findall(r"'([a-z0-9-]+)':\s*'(experimental|wip)'", body))


def _guide_row(label: str) -> str:
    for line in GUIDE.read_text(encoding="utf-8").splitlines():
        if line.startswith(f"| {label}"):
            return line.split("|")[2]
    raise AssertionError(f"no '{label}' row in the guide's support table")


def _readme_paragraph() -> str:
    for line in README.read_text(encoding="utf-8").splitlines():
        if line.startswith("Some integrations are marked **Experimental**"):
            return line
    raise AssertionError("README lost its Experimental paragraph")


def _names_in(cell: str) -> list[str]:
    return [n.strip() for n in re.split(r",(?![^(]*\))", cell) if n.strip()]


@pytest.mark.parametrize("status", ["experimental", "wip"])
def test_doc_name_table_covers_the_status_map(status):
    servers = {s for s, st in _support_map().items() if st == status}
    assert servers, f"no {status} servers parsed; the ratchet is vacuous"
    assert servers == set(DOC_NAMES[status]), (
        f"integrationsData.ts {status} servers changed; update README, the "
        f"guide table and DOC_NAMES: {sorted(servers ^ set(DOC_NAMES[status]))}"
    )


def test_guide_experimental_row_names_exactly_the_experimental_servers():
    cell = _names_in(_guide_row("Deneysel"))
    names = DOC_NAMES["experimental"].values()
    assert len(cell) == len(names), cell
    assert all(any(n in c for c in cell) for n in names), cell


def test_guide_wip_row_names_exactly_the_wip_servers():
    cell = _names_in(_guide_row("Sunulmuyor"))
    names = DOC_NAMES["wip"].values()
    assert len(cell) == len(names), cell
    assert all(any(n in c for c in cell) for n in names), cell


def test_readme_names_every_experimental_server():
    paragraph = _readme_paragraph()
    listed = paragraph.split(" in Settings: ", 1)[1].split(". ", 1)[0]
    cell = _names_in(listed.replace(" and ", ", "))
    names = DOC_NAMES["experimental"].values()
    assert len(cell) == len(names), cell
    assert all(any(n in c for c in cell) for n in names), cell
