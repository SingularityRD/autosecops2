"""Every GitHub workflow declares a top-level token permission (W0.13 review).

ci-cd.yml, helm-chart.yml and nightly.yml had none, so their jobs got the
repository's default GITHUB_TOKEN scope (read-write on older repositories)
while running third-party actions, one of them pinned to a branch
(aquasecurity/trivy-action@master). A job that needs more declares it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

WORKFLOWS = sorted((Path(__file__).resolve().parents[3] / ".github" / "workflows").glob("*.yml"))


def test_workflows_found():
    assert len(WORKFLOWS) >= 5


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_workflow_declares_top_level_permissions(path):
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert "permissions" in doc, f"{path.name}: add a top-level `permissions:` block"
    perms = doc["permissions"]
    assert perms != "write-all", path.name
