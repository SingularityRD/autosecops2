"""The third-party LogLM connector stays out of the product surface (W0.29).

We do not ship DeepTempo's paid LogLM connector; our own model is separate
work. This ratchet fails when user-visible code or docs name the product or the
vendor again: the web console source (including the generated API types, so
backend docstrings count), the API routers, the MCP server catalogue, the
operator guide, the runbooks, README.md and the built-in workflow and skill
definitions users read in the console.

Lower-case ``deeptempo`` on its own is not matched. It is an infrastructure
identifier inherited from upstream (the Postgres role and database
``deeptempo_soc``, ``~/.deeptempo``, container names), not a product mention;
renaming those is separate work (FORK.md, "Where this repository differs").

History is allowed: CHANGELOG.md and FORK.md are not scanned, and
``HISTORY_ALLOWLIST`` lists the exact lines (path + full line text) in scanned
files that may keep a mention because they record the past rather than describe
the product. Every other line of those files is scanned.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]

SCOPE = (
    "clients/web/src",
    "services/api/routers",
    "mcp-config.json",
    "docs/guide",
    "docs/operations",
    "README.md",
    "core/workflows/definitions",
    "core/skills/library",
)

# (path, exact stripped line) -> why that one line may still name the vendor
HISTORY_ALLOWLIST = {
    (
        "README.md",
        "- [DeepTempo](https://deeptempo.ai): sponsor of the upstream Vigil project",
    ): "credits DeepTempo as the upstream project's sponsor",
}

FORBIDDEN = re.compile(r"(?i:loglm)|DeepTempo|(?i:deeptempo\.ai)")

_TEXT_SUFFIXES = {
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".css",
    ".html",
    ".json",
    ".py",
    ".md",
    ".yaml",
    ".yml",
    ".txt",
}


def _tracked(paths: tuple[str, ...]) -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "--", *paths],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [line for line in out.splitlines() if line]


def mentions(rel_paths: list[str], root: Path = REPO) -> list[str]:
    """Every ``path:line: text`` in ``rel_paths`` that names the product."""
    found: list[str] = []
    for rel in rel_paths:
        path = root / rel
        if path.suffix not in _TEXT_SUFFIXES or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            if FORBIDDEN.search(line) and (rel, line.strip()) not in HISTORY_ALLOWLIST:
                found.append(f"{rel}:{number}: {line.strip()[:120]}")
    return found


def test_user_visible_surface_does_not_name_loglm_or_deeptempo():
    files = _tracked(SCOPE)
    assert files, "git ls-files returned nothing for the scope"
    found = mentions(files)
    assert not found, (
        "LogLM / DeepTempo is back in user-visible code or docs (removed in "
        "W0.29; see FORK.md):\n" + "\n".join(found)
    )


def test_allowlist_entries_exist():
    for rel, line in HISTORY_ALLOWLIST:
        text = (REPO / rel).read_text(encoding="utf-8")
        assert line in {raw.strip() for raw in text.splitlines()}, (
            f"stale allow-list entry: {rel}: {line}"
        )


def _readme_with(tmp_path, extra: str) -> Path:
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    (tmp_path / "README.md").write_text(readme + extra, encoding="utf-8")
    return tmp_path


def test_readme_allows_only_the_sponsor_line():
    """The real README passes only because its one sponsor line is listed."""
    assert mentions(["README.md"]) == []
    text = (REPO / "README.md").read_text(encoding="utf-8")
    hits = [line.strip() for line in text.splitlines() if FORBIDDEN.search(line)]
    assert hits == [line for _, line in HISTORY_ALLOWLIST]


def test_a_planted_loglm_line_in_readme_fails(tmp_path):
    root = _readme_with(tmp_path, "\nEnable LogLM in Settings for anomaly detection.\n")
    found = mentions(["README.md"], root=root)
    assert len(found) == 1 and "LogLM" in found[0]


def test_a_reworded_sponsor_line_in_readme_fails(tmp_path):
    root = _readme_with(
        tmp_path, "\n- [DeepTempo](https://deeptempo.ai): LogLM connects via MCP\n"
    )
    assert mentions(["README.md"], root=root)


@pytest.mark.parametrize(
    "line",
    [
        "{ id: 'loglm', name: 'LogLM' }",
        "Requires the paid, opt-in LOGLM connector.",
        "chip={'DeepTempo'}",
        "docs_url: 'https://docs.deeptempo.ai/x'",
    ],
)
def test_the_check_catches_a_mention(tmp_path, line):
    (tmp_path / "x.tsx").write_text(line + "\n", encoding="utf-8")
    assert mentions(["x.tsx"], root=tmp_path)


@pytest.mark.parametrize(
    "line",
    [
        'DATABASE_URL="postgresql://deeptempo:pw@db:5432/deeptempo_soc"',
        "container_name: deeptempo-postgres",
        "~/.deeptempo/.env",
    ],
)
def test_the_check_leaves_infrastructure_identifiers_alone(tmp_path, line):
    (tmp_path / "x.md").write_text(line + "\n", encoding="utf-8")
    assert mentions(["x.md"], root=tmp_path) == []
