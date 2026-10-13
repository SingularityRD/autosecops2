"""Operator-facing messages say AutoSecOps, not Vigil (W0.13 review).

The rebrand commits covered the console, emails and the desktop app, but the
banners start.sh / setup_dev.sh / shutdown_all.sh print, the venv check in
scripts/lib.sh, the shipped-default password error, the empty-schema summary
the storage status reports and the restore error still named Vigil.
Comments, identifiers, paths and env names (VIGIL_*, vigil_app, the chart
directory) are not user-visible and stay.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]

SHELL = ("start.sh", "setup_dev.sh", "shutdown_all.sh", "scripts/lib.sh")
# Shell lines that print: echo/printf with a literal containing the old name.
PRINTS = re.compile(r"^\s*(echo|printf)\b.*\bVigil\b")


@pytest.mark.parametrize("path", SHELL)
def test_shell_messages_do_not_name_vigil(path):
    lines = (REPO / path).read_text(encoding="utf-8").splitlines()
    hits = [f"{path}:{n}: {ln.strip()}" for n, ln in enumerate(lines, 1) if PRINTS.search(ln)]
    assert not hits, "\n".join(hits)


@pytest.mark.parametrize(
    "path, message",
    [
        ("core/storage/connection.py", "published default shipped with "),
        ("core/storage/connection.py", "Database has no "),
        ("core/backup/restore.py", "snapshot does not contain one "),
        ("scripts/create_workflow.py", "on finding <id>"),
        ("scripts/generate_sample_data.py", "Sample Data Generator\")"),
    ],
)
def test_python_messages_do_not_name_vigil(path, message):
    text = (REPO / path).read_text(encoding="utf-8")
    at = text.index(message)
    window = text[at : at + 160]
    assert "Vigil" not in window, window


def test_api_startup_logs_do_not_name_vigil_soc():
    """Round 3: the API's startup log lines said "Vigil SOC"."""
    text = (REPO / "services/api/main.py").read_text(encoding="utf-8")
    assert "Vigil SOC" not in text
