"""Ratchet (W0.30): agent-layer traces never carry prompts, responses or tool I/O
in the shipped production and air-gap profiles.

``services/agent/core/tracing.ts`` (upstream 05e50665) attaches prompts, model
responses and tool arguments/results to spans only when
``VIGIL_OTEL_CAPTURE_CONTENT`` is on. That content is customer logs, IOCs and
possibly PII, and the TypeScript side does not scrub it, so every profile we
ship must pin the switch off explicitly -- not just leave it unset.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from tests.airgap.test_egress_inventory import parse_env

ROOT = Path(__file__).resolve().parents[2]
SWITCH = "VIGIL_OTEL_CAPTURE_CONTENT"
OFF = {"false", "0", "no", "off"}

HELM_PROFILES = [
    "infra/helm/vigil/values.yaml",  # production chart defaults
    "infra/airgap/values-airgap.yaml",  # air-gap Helm overlay
]


@pytest.mark.parametrize("rel", HELM_PROFILES)
def test_helm_profile_pins_capture_off(rel: str) -> None:
    values = yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))
    config = values.get("config") or {}
    assert SWITCH in config, f"{rel}: config.{SWITCH} must be set explicitly"
    assert str(config[SWITCH]).strip().lower() in OFF, f"{rel}: {SWITCH} must be false"


def test_airgap_env_pins_capture_off() -> None:
    env = parse_env((ROOT / "infra/airgap/airgap.env").read_text(encoding="utf-8"))
    assert env.get(SWITCH, "").strip().lower() in OFF


def test_compose_defaults_capture_off() -> None:
    text = (ROOT / "infra/docker/docker-compose.yml").read_text(encoding="utf-8")
    defaults = re.findall(rf"{SWITCH}=\$\{{{SWITCH}:-([^}}]*)\}}", text)
    assert defaults, "docker-compose.yml no longer passes the switch to the agent"
    assert all(d.strip().lower() in OFF for d in defaults)


def test_tracing_reads_this_switch() -> None:
    # A rename in tracing.ts would leave every profile above pinning a dead name.
    src = (ROOT / "services/agent/core/tracing.ts").read_text(encoding="utf-8")
    assert f'enabled("{SWITCH}")' in src
