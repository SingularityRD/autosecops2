"""THIRD_PARTY_LICENSES: generated from the lockfiles, checked in, current (W0.38).

The release attaches the file and every image, the desktop app, the air-gap
bundle carry the checked-in snapshot, so the snapshot must list exactly the
components the lockfiles pin, each with a licence, and nothing that ships may
be under a licence this product cannot redistribute.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]
TOOL = REPO / "scripts" / "release" / "release_tool.py"
SNAPSHOT = REPO / "THIRD_PARTY_LICENSES"

sys.path.insert(0, str(REPO / "scripts" / "release"))
import release_tool as rt  # noqa: E402

REGENERATE = "python3 scripts/release/release_tool.py third-party-licenses --write"
# Not open source, or a network copyleft: none of these may ship.
FORBIDDEN = re.compile(
    r"\b(AGPL|SSPL|BUSL|RSAL\w*|Elastic)\b|Business Source|Commons Clause", re.I
)


@pytest.fixture(scope="module")
def rows() -> dict:
    return rt.parse_third_party(SNAPSHOT.read_text(encoding="utf-8"))


def test_snapshot_is_current() -> None:
    """Fails after a lockfile change: regenerate and review the licence diff."""
    assert rt.third_party_licenses(REPO) == SNAPSHOT.read_text(
        encoding="utf-8"
    ), f"THIRD_PARTY_LICENSES is stale; run `{REGENERATE}`"


def test_snapshot_lists_every_lockfile_component(rows: dict) -> None:
    for _suffix, kind, rel, _name in rt.LOCKFILES:
        lock = REPO / rel
        comps = (
            rt.python_components(lock) if kind == "python" else rt.npm_components(lock)
        )
        want = {(rel, c["name"], c["version"]) for c in comps}
        have = {k for k in rows if k[0] == rel}
        assert want == have, f"{rel}: run `{REGENERATE}`"


def test_everything_that_ships_has_a_licence() -> None:
    text = SNAPSHOT.read_text(encoding="utf-8")
    unknown = [
        ln
        for ln in text.splitlines()
        if re.match(r"^  \S+  \S+  (runtime|platform)  UNKNOWN$", ln)
    ]
    assert not unknown, "add the checked licence to LICENSE_OVERRIDES:\n" + "\n".join(
        unknown
    )


def test_nothing_that_ships_is_under_a_non_redistributable_licence() -> None:
    text = SNAPSHOT.read_text(encoding="utf-8")
    licences = (
        re.match(r"^  \S+  \S+  runtime  (.+)$", ln) for ln in text.splitlines()
    )
    bad = [m.group(0) for m in licences if m and FORBIDDEN.search(m.group(1))]
    assert not bad, "\n".join(bad)


@pytest.mark.parametrize(
    "lic", ["AGPL-3.0-only", "SSPL-1.0", "Elastic-2.0", "BUSL-1.1", "RSALv2"]
)
def test_the_forbidden_list_catches(lic: str) -> None:
    assert FORBIDDEN.search(lic)


@pytest.mark.parametrize("lic", ["ISC", "MIT", "LGPL-2.1", "universal-user-agent"])
def test_the_forbidden_list_spares(lic: str) -> None:
    assert not FORBIDDEN.search(lic)


def _mini_repo(tmp_path: Path, web_license: str | None) -> Path:
    """A repository with every LOCKFILES path, one component each."""
    for _suffix, kind, rel, _name in rt.LOCKFILES:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if kind == "python":
            path.write_text(
                "pytest==9.1.1\n    # via -r requirements.txt\n"
                "pywin32==312 ; sys_platform == 'win32'\n"
            )
            continue
        entry: dict = {"version": "1.0.0", "dev": rel.startswith("clients/desktop")}
        if web_license and rel.startswith("clients/web"):
            entry["license"] = web_license
        name = "pipenet" if rel.startswith("infra") else "left-pad"
        path.write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {"": {"name": "x"}, f"node_modules/{name}": entry},
                }
            )
        )
    return tmp_path


def test_licence_sources_scope_and_round_trip(tmp_path: Path) -> None:
    repo = _mini_repo(tmp_path, "MIT")
    sections = dict(rt.third_party_rows(repo))
    assert sections["clients/web/package-lock.json"] == [
        ("left-pad", "1.0.0", "runtime", "MIT")
    ]
    # No licence in the lock: the hand-checked override.
    assert sections["infra/docker/mcp-packages/package-lock.json"] == [
        ("pipenet", "1.0.0", "runtime", "MIT")
    ]
    assert sections["clients/desktop/package-lock.json"] == [
        ("left-pad", "1.0.0", "dev", "UNKNOWN")
    ]
    py = dict((r[0], r) for r in sections["requirements.lock"])
    assert py["pywin32"] == ("pywin32", "312", "platform", "PSF-2.0")
    assert (
        py["pytest"][2] == "runtime" and py["pytest"][3] != "UNKNOWN"
    )  # installed metadata
    text = rt.render_third_party(rt.third_party_rows(repo))
    parsed = rt.parse_third_party(text)
    assert parsed[("clients/web/package-lock.json", "left-pad", "1.0.0")] == "MIT"
    assert "== runtime licence summary ==" in text


def test_snapshot_supplies_licences_a_release_machine_cannot_read(
    tmp_path: Path,
) -> None:
    """The release job has no packages installed: the snapshot's licence stays."""
    repo = _mini_repo(tmp_path, None)
    (repo / rt.THIRD_PARTY_FILE).write_text(
        "== clients/web/package-lock.json ==\n  left-pad  1.0.0  runtime  WTFPL\n"
    )
    sections = dict(
        rt.third_party_rows(
            repo, rt.parse_third_party((repo / rt.THIRD_PARTY_FILE).read_text())
        )
    )
    assert sections["clients/web/package-lock.json"] == [
        ("left-pad", "1.0.0", "runtime", "WTFPL")
    ]


def test_check_fails_on_a_stale_snapshot_and_write_fixes_it(tmp_path: Path) -> None:
    repo = _mini_repo(tmp_path, "MIT")
    cmd = [sys.executable, str(TOOL), "--repo", str(repo), "third-party-licenses"]
    stale = subprocess.run([*cmd, "--check"], capture_output=True, text=True)
    assert stale.returncode == 1 and "is stale" in stale.stderr
    subprocess.run([*cmd, "--write"], check=True, capture_output=True)
    out = tmp_path / "dist" / "T.txt"
    ok = subprocess.run(
        [*cmd, "--check", "--out", str(out)], capture_output=True, text=True
    )
    assert ok.returncode == 0, ok.stderr
    assert out.read_text() == (repo / rt.THIRD_PARTY_FILE).read_text()


def test_release_and_dry_run_produce_it() -> None:
    wf = (REPO / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    sbom = wf[wf.index("  sbom:") : wf.index("  smoke-test:")]
    assert "release_tool.py third-party-licenses --check" in sbom
    assert "dist/autosecops-${VERSION}-THIRD_PARTY_LICENSES.txt" in sbom
    assert 'cp NOTICE "dist/autosecops-${VERSION}-NOTICE.txt"' in sbom
    dry = (REPO / "scripts" / "release" / "dry-run.sh").read_text(encoding="utf-8")
    assert "third-party-licenses --check" in dry
