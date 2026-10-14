"""scripts/release: offline dry run and the release_tool checks it relies on."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import pytest

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]
DRY_RUN = REPO / "scripts" / "release" / "dry-run.sh"

sys.path.insert(0, str(REPO / "scripts" / "release"))
import release_tool as rt  # noqa: E402

# Loaded through PYTHONPATH by every python3 the dry run starts: any socket
# connection fails the run, so "offline" is enforced, not assumed.
NO_NET = """
import socket
def _blocked(*a, **k):
    raise RuntimeError("network access attempted during release dry run")
socket.socket.connect = _blocked
socket.socket.connect_ex = _blocked
socket.create_connection = _blocked
socket.getaddrinfo = _blocked
"""


def _offline_env(tmp_path: Path) -> dict:
    site = tmp_path / "nonet"
    site.mkdir(exist_ok=True)
    (site / "sitecustomize.py").write_text(NO_NET)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(site)
    env["SOURCE_DATE_EPOCH"] = "1700000000"
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        env[k] = "http://127.0.0.1:9"
    return env


def _dry_run(tmp_path: Path, out: Path, *extra: str):
    return subprocess.run(
        ["sh", str(DRY_RUN), "--out", str(out), *extra],
        env=_offline_env(tmp_path),
        capture_output=True,
        text=True,
        cwd=REPO,
        timeout=600,
    )


# --- the dry run itself --------------------------------------------------------


def test_dry_run_builds_valid_sboms_offline(tmp_path: Path) -> None:
    out = tmp_path / "out"
    proc = _dry_run(tmp_path, out, "--tag", "v" + rt.read_version())
    assert proc.returncode == 0, proc.stdout + proc.stderr
    version = rt.read_version()
    assert f"DRY RUN OK: {version}" in proc.stdout

    names = sorted(p.name for p in out.iterdir())
    expected = sorted(
        [f"autosecops-{version}-{s}.cdx.json" for s, *_ in rt.LOCKFILES]
        + ["SHA256SUMS"]
    )
    assert names == expected

    sums = (out / "SHA256SUMS").read_text().splitlines()
    assert len(sums) == len(rt.LOCKFILES)
    for line in sums:
        digest, name = line.split("  ", 1)
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == digest

    for p in out.glob("*.cdx.json"):
        bom = json.loads(p.read_text())
        assert rt.validate_bom(bom) > 10
        assert bom["specVersion"] == "1.6"
        assert bom["metadata"]["component"]["version"] == version
        assert bom["metadata"]["timestamp"] == "2023-11-14T22:13:20Z"


def test_dry_run_sboms_match_the_lockfiles(tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert _dry_run(tmp_path, out).returncode == 0
    version = rt.read_version()

    # Every pinned Python requirement is a component.
    py = json.loads((out / f"autosecops-{version}-python.cdx.json").read_text())
    purls = {c["purl"] for c in py["components"]}
    pins = [
        line.split(";")[0].strip()
        for line in (REPO / "requirements.lock").read_text().splitlines()
        if line and line[0] not in " #-" and "==" in line
    ]
    assert pins
    for pin in pins:
        name, ver = pin.split("==")
        assert f"pkg:pypi/{rt._pep503(name.split('[')[0])}@{ver}" in purls

    # Every installed npm package of the web console, with its integrity hash.
    lock = json.loads((REPO / "clients/web/package-lock.json").read_text())
    web = json.loads((out / f"autosecops-{version}-node-web.cdx.json").read_text())
    by_purl = {c["purl"]: c for c in web["components"]}
    for key, entry in lock["packages"].items():
        if not key or entry.get("link") or "version" not in entry:
            continue
        name = entry.get("name") or key.rsplit("node_modules/", 1)[1]
        comp = by_purl[rt.npm_purl(name, entry["version"])]
        if entry.get("integrity", "").startswith("sha512-"):
            want = base64.b64decode(entry["integrity"][7:]).hex()
            assert {"alg": "SHA-512", "content": want} in comp["hashes"]


def test_dry_run_is_deterministic(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    assert _dry_run(tmp_path, a).returncode == 0
    assert _dry_run(tmp_path, b).returncode == 0
    for p in a.iterdir():
        assert p.read_bytes() == (b / p.name).read_bytes(), p.name


def test_dry_run_rejects_a_tag_that_does_not_match_version(tmp_path: Path) -> None:
    proc = _dry_run(tmp_path, tmp_path / "out", "--tag", "v9.9.9")
    assert proc.returncode != 0
    assert "does not match VERSION" in proc.stderr


def test_release_versions_are_consistent() -> None:
    assert rt.check_versions() == rt.read_version() == "2.0.0"


# These two check the real docs/release/2.0.0.md against this checkout's own
# merge history, so they need it; a shallow CI checkout (actions/checkout with
# the default fetch-depth: 1) or a source export has none. The same logic runs
# on fixture repositories below, which always have their history.
needs_repo_history = pytest.mark.skipif(
    not (REPO / ".git").exists() or rt.is_shallow(REPO),
    reason="needs the repository's full merge history (shallow clone or no .git);"
    " run `git fetch --unshallow --tags`",
)


@needs_repo_history
def test_release_notes_included_items_are_merged() -> None:
    rows = rt.check_notes(REPO / "docs/release/2.0.0.md", REPO)
    included = {r["wp"] for r in rows if r["included"]}
    assert {"W0.1", "W2.2", "W3.3", "W3.8"} <= included
    # Whatever is merged when the test runs, not a snapshot of the drafting day:
    # "Dahil" exactly for the merged wp/<id>-* branches (W4.7 itself excepted).
    merged = set(rt.merged_wps(rt.merged_branches(REPO))) - {"W4.7"}
    assert {r["wp"] for r in rows if r["wp"] in merged} == merged
    # WPs whose work landed under another branch name (W0.2: brand/...,
    # W4.2: wp/w4.1-load-chaos) name it in the data file.
    data = json.loads((REPO / "docs/release/2.0.0.json").read_text())
    explicit = {w["id"] for w in data["wps"] if w.get("branch")}
    assert {"W0.2", "W4.2"} <= explicit
    assert included - explicit == merged
    for r in rows:
        if not r["included"]:
            assert r["wp"] not in merged, r["wp"]


@needs_repo_history
def test_release_notes_are_rendered_from_history() -> None:
    """docs/release/2.0.0.md and the CHANGELOG block are fresh for HEAD."""
    data = REPO / "docs/release/2.0.0.json"
    rows = rt.check_notes(REPO / "docs/release/2.0.0.md", REPO, strict=True, data=data)
    assert len(rows) == len(json.loads(data.read_text())["wps"])


# --- check-tag / check-versions ------------------------------------------------


@pytest.mark.parametrize(
    "tag,expected",
    [("v2.0.0", ("2.0.0", False)), ("v2.0.0-rc.1", ("2.0.0-rc.1", True))],
)
def test_parse_tag_accepts(tag, expected) -> None:
    assert rt.parse_tag(tag, "2.0.0") == expected


@pytest.mark.parametrize(
    "tag",
    ["2.0.0", "v2.0.1", "v2.0.0-beta", "v2.0.0-rc.0", "v2.0", "v2.0.0+x", "vv2.0.0"],
)
def test_parse_tag_rejects(tag) -> None:
    with pytest.raises(rt.ReleaseError):
        rt.parse_tag(tag, "2.0.0")


def _mini_repo(root: Path, version: str = "2.0.0") -> Path:
    for rel in (
        "clients/web/package.json",
        "clients/web/package-lock.json",
        "clients/desktop/package.json",
        "clients/desktop/package-lock.json",
        ".github/.release-please-manifest.json",
        "infra/helm/vigil/Chart.yaml",
        "scripts/vigil-support/VERSION",
        "VERSION",
    ):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / rel, root / rel)
    return root


def test_check_versions_reports_drift(tmp_path: Path) -> None:
    repo = _mini_repo(tmp_path)
    assert rt.check_versions(repo) == "2.0.0"
    chart = repo / "infra/helm/vigil/Chart.yaml"
    chart.write_text(
        chart.read_text().replace("appVersion: 2.0.0", "appVersion: 1.9.9")
    )
    lock = repo / "clients/web/package-lock.json"
    doc = json.loads(lock.read_text())
    doc["packages"][""]["version"] = "0.7.1"
    lock.write_text(json.dumps(doc))
    with pytest.raises(rt.ReleaseError) as exc:
        rt.check_versions(repo)
    assert "Chart.yaml:appVersion" in str(exc.value)
    assert "clients/web/package-lock.json:packages.''.version" in str(exc.value)
    assert rt.main(["--repo", str(repo), "check-versions"]) == 1


# --- check-notes against a fixture history --------------------------------------


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@example.invalid",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@example.invalid",
        },
    )


@pytest.fixture()
def history(tmp_path: Path) -> Path:
    repo = tmp_path / "h"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "integration")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "root")
    for branch in ("wp/w1.1-eval-harness", "wp/w2.2-alert-lanes"):
        _git(repo, "checkout", "-q", "-b", branch, "integration")
        _git(repo, "commit", "-q", "--allow-empty", "-m", f"work on {branch}")
        _git(repo, "checkout", "-q", "integration")
        _git(
            repo,
            "merge",
            "-q",
            "--no-ff",
            branch,
            "-m",
            f"Merge {branch} into integration",
        )
    return repo


NOTES = """
| WP | Konu | Durum | Birleştirme |
|---|---|---|---|
| W1.1 | Eval | Dahil | `wp/w1.1-eval-harness` |
| W2.2 | Lanes | {w22} | {w22b} |
| W1.9 | SSO | {w19} | {w19b} |
"""


def _notes(tmp_path: Path, **kw) -> Path:
    p = tmp_path / "notes.md"
    p.write_text(NOTES.format(**kw))
    return p


def test_check_notes_passes_when_claims_match(tmp_path: Path, history: Path) -> None:
    notes = _notes(
        tmp_path, w22="Dahil", w22b="`wp/w2.2-alert-lanes`", w19="Dahil değil", w19b="—"
    )
    rows = rt.check_notes(notes, history, strict=True)
    assert [r["included"] for r in rows] == [True, True, False]


def test_check_notes_rejects_unmerged_item_marked_included(
    tmp_path: Path, history: Path
) -> None:
    notes = _notes(
        tmp_path,
        w22="Dahil",
        w22b="`wp/w2.2-alert-lanes`",
        w19="Dahil",
        w19b="`wp/w1.9-oidc`",
    )
    with pytest.raises(
        rt.ReleaseError, match="W1.9: marked Dahil but branch wp/w1.9-oidc"
    ):
        rt.check_notes(notes, history)


def test_check_notes_strict_rejects_merged_item_marked_not_included(
    tmp_path: Path, history: Path
) -> None:
    notes = _notes(tmp_path, w22="Dahil değil", w22b="—", w19="Dahil değil", w19b="—")
    rt.check_notes(notes, history)  # drafting mode tolerates it
    with pytest.raises(rt.ReleaseError, match="W2.2: marked 'Dahil değil'"):
        rt.check_notes(notes, history, strict=True)


def test_check_notes_rejects_unknown_status(tmp_path: Path, history: Path) -> None:
    notes = _notes(tmp_path, w22="Belki", w22b="—", w19="Dahil değil", w19b="—")
    with pytest.raises(rt.ReleaseError, match="status must be"):
        rt.check_notes(notes, history)


# --- SBOM parsing details ----------------------------------------------------------


def test_python_lock_parsing(tmp_path: Path) -> None:
    lock = tmp_path / "r.lock"
    lock.write_text(
        "# header\n"
        "Foo_Bar==1.2.3\n"
        "    # via -r requirements.txt\n"
        "colorama==0.4.6 ; sys_platform == 'win32'\n"
        "uvicorn[standard]==0.30.0 \\\n"
        "    --hash=sha256:abc\n"
        "--index-url https://example.invalid/simple\n"
    )
    comps = rt.python_components(lock)
    assert [c["purl"] for c in comps] == [
        "pkg:pypi/colorama@0.4.6",
        "pkg:pypi/foo-bar@1.2.3",
        "pkg:pypi/uvicorn@0.30.0",
    ]
    marker = comps[0]["properties"][0]
    assert marker == {
        "name": "autosecops:python-marker",
        "value": "sys_platform == 'win32'",
    }
    lock.write_text("not a pin\n")
    with pytest.raises(rt.ReleaseError):
        rt.python_components(lock)


def test_npm_lock_parsing(tmp_path: Path) -> None:
    integrity = "sha512-" + base64.b64encode(b"\x01" * 64).decode()
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app", "version": "1.0.0"},
                    "node_modules/@scope/pkg": {
                        "version": "2.0.0",
                        "integrity": integrity,
                        "license": "MIT",
                        "resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-2.0.0.tgz",
                    },
                    "node_modules/devonly": {"version": "1.0.0", "dev": True},
                    "node_modules/a/node_modules/devonly": {"version": "1.0.0"},
                    "node_modules/linked": {"resolved": "../x", "link": True},
                    "packages/x": {"version": "0.0.1"},
                },
            }
        )
    )
    comps = {c["purl"]: c for c in rt.npm_components(lock)}
    assert set(comps) == {"pkg:npm/%40scope/pkg@2.0.0", "pkg:npm/devonly@1.0.0"}
    scoped = comps["pkg:npm/%40scope/pkg@2.0.0"]
    assert scoped["name"] == "@scope/pkg"
    assert scoped["hashes"] == [{"alg": "SHA-512", "content": "01" * 64}]
    assert scoped["licenses"] == [{"license": {"name": "MIT"}}]
    # Required somewhere (nested copy) wins over dev-only.
    assert "scope" not in comps["pkg:npm/devonly@1.0.0"]
    assert [c["purl"] for c in rt.npm_components(lock, omit_dev=True)] == [
        "pkg:npm/%40scope/pkg@2.0.0",
        "pkg:npm/devonly@1.0.0",
    ]
    lock.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {}}))
    with pytest.raises(rt.ReleaseError, match="lockfileVersion"):
        rt.npm_components(lock)


def test_validate_bom_rejects_broken_documents(tmp_path: Path) -> None:
    lock = tmp_path / "r.lock"
    lock.write_text("a==1\nb==2\n")
    bom = rt.build_bom(rt.python_components(lock), "x", "1.0.0", lock)
    assert rt.validate_bom(bom) == 2
    dup = json.loads(json.dumps(bom))
    dup["components"].append(dict(dup["components"][0]))
    with pytest.raises(rt.ReleaseError, match="duplicate bom-ref"):
        rt.validate_bom(dup)
    bad = json.loads(json.dumps(bom))
    bad["components"][0]["purl"] = "a@1"
    with pytest.raises(rt.ReleaseError, match="not a purl"):
        rt.validate_bom(bad)
    bad = json.loads(json.dumps(bom))
    bad["bomFormat"] = "SPDX"
    with pytest.raises(rt.ReleaseError, match="bomFormat"):
        rt.validate_bom(bad)


# --- images manifest, provenance, checksums ------------------------------------------


def _blob(obj: dict) -> tuple[bytes, str]:
    raw = json.dumps(obj).encode()
    return raw, "sha256:" + hashlib.sha256(raw).hexdigest()


def _digests_dir(tmp_path: Path) -> Path:
    d = tmp_path / "digests"
    d.mkdir()
    for comp in rt.COMPONENTS:
        manifests = []
        for arch in ("amd64", "arm64"):
            cfg = "sha256:" + hashlib.sha256(f"{comp}{arch}cfg".encode()).hexdigest()
            raw, dg = _blob({"config": {"digest": cfg}, "layers": []})
            (d / f"{comp}.{dg[7:]}.json").write_bytes(raw)
            manifests.append(
                {"digest": dg, "platform": {"os": "linux", "architecture": arch}}
            )
        manifests.append(
            {
                "digest": "sha256:" + "0" * 64,
                "platform": {"os": "unknown", "architecture": "unknown"},
            }
        )
        raw, dg = _blob({"manifests": manifests})
        (d / f"{comp}.index.json").write_bytes(raw + b"\n")
        (d / comp).write_text(dg + "\n")
    return d


def test_images_manifest_and_refs(tmp_path: Path) -> None:
    d = _digests_dir(tmp_path)
    out = tmp_path / "images.json"
    assert (
        rt.main(
            [
                "images-manifest",
                "--version",
                "2.0.0",
                "--prefix",
                "ghcr.io/o/autosecops",
                "--digests",
                str(d),
                "--out",
                str(out),
            ]
        )
        == 0
    )
    doc = json.loads(out.read_text())
    assert [i["component"] for i in doc["images"]] == ["backend", "daemon", "agent"]
    backend = doc["images"][0]
    assert backend["repository"] == "ghcr.io/o/autosecops-backend"
    assert [p["platform"] for p in backend["platforms"]] == [
        "linux/amd64",
        "linux/arm64",
    ]
    want_cfg = "sha256:" + hashlib.sha256(b"backendamd64cfg").hexdigest()
    assert backend["platforms"][0]["config_digest"] == want_cfg
    rows = out.with_suffix(".tsv").read_text().splitlines()
    assert len(rows) == 3 + 6
    assert (
        rows[0]
        == f"backend\tindex\tghcr.io/o/autosecops-backend@{backend['index_digest']}"
    )
    assert rt.image_rows(doc, False)[1][1] == "arm64"


def test_images_manifest_rejects_tampered_index(tmp_path: Path) -> None:
    d = _digests_dir(tmp_path)
    idx = d / "daemon.index.json"
    idx.write_bytes(idx.read_bytes().replace(b"arm64", b"s390x"))
    with pytest.raises(rt.ReleaseError, match="daemon: index JSON does not hash"):
        rt.images_manifest("2.0.0", "p", d)


def test_images_manifest_rejects_tampered_platform_manifest(tmp_path: Path) -> None:
    d = _digests_dir(tmp_path)
    victim = sorted(d.glob("agent.*.json"))
    victim = [p for p in victim if not p.name.endswith("index.json")][0]
    victim.write_text(json.dumps({"config": {"digest": "sha256:" + "f" * 64}}))
    with pytest.raises(rt.ReleaseError, match="does not hash to"):
        rt.images_manifest("2.0.0", "p", d)


GH_ENV = {
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_REPOSITORY": "SingularityRD/autosecops2",
    "GITHUB_REF": "refs/tags/v2.0.0",
    "GITHUB_SHA": "a" * 40,
    "GITHUB_WORKFLOW_REF": "SingularityRD/autosecops2/.github/workflows/release.yml@refs/tags/v2.0.0",
    "GITHUB_RUN_ID": "42",
    "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_EVENT_NAME": "push",
}


def test_provenance_predicate() -> None:
    pred = rt.provenance_predicate("ghcr.io/o/x", "sha256:" + "b" * 64, GH_ENV)
    bd = pred["buildDefinition"]
    assert bd["externalParameters"]["workflow"] == {
        "ref": "refs/tags/v2.0.0",
        "repository": "https://github.com/SingularityRD/autosecops2",
        "path": ".github/workflows/release.yml",
    }
    assert bd["resolvedDependencies"][0]["digest"] == {"gitCommit": "a" * 40}
    assert pred["runDetails"]["builder"]["id"] == (
        "https://github.com/SingularityRD/autosecops2/.github/workflows/release.yml"
        "@refs/tags/v2.0.0"
    )
    assert pred["runDetails"]["metadata"]["invocationId"].endswith(
        "/actions/runs/42/attempts/1"
    )
    with pytest.raises(rt.ReleaseError, match="sha256"):
        rt.provenance_predicate("x", "sha256:short", GH_ENV)
    with pytest.raises(rt.ReleaseError, match="GITHUB_SHA"):
        rt.provenance_predicate("x", "sha256:" + "b" * 64, {**GH_ENV, "GITHUB_SHA": ""})


def test_checksums_skip_themselves(tmp_path: Path) -> None:
    (tmp_path / "b.txt").write_text("b")
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "SHA256SUMS.sigstore.json").write_text("{}")
    out = rt.write_checksums(tmp_path)
    names = [line.split("  ")[1] for line in out.read_text().splitlines()]
    assert names == ["a.txt", "b.txt"]


# --- strict: merged WPs without a row, two-digit ids ---------------------------


def _merge(repo: Path, branch: str, subject: Optional[str] = None) -> None:
    _git(repo, "checkout", "-q", "-b", branch, "integration")
    _git(repo, "commit", "-q", "--allow-empty", "-m", f"work on {branch}")
    _git(repo, "checkout", "-q", "integration")
    _git(
        repo,
        "merge",
        "-q",
        "--no-ff",
        branch,
        "-m",
        subject or f"Merge {branch} into integration (verified PASS)",
    )


@pytest.mark.parametrize(
    "branch,wp",
    [
        ("wp/w0.10-merged-followups", "W0.10"),
        ("wp/w0.11-more", "W0.11"),
        ("wp/w0.13-review-round5", "W0.13"),
        ("wp/w0.4b-gates-fix", "W0.4b"),
        ("wp/w12.3-x", "W12.3"),
        ("wp/w0.1-upstream-sync", "W0.1"),
        ("brand/autosecops-ui", None),
        ("wp/notawp", None),
    ],
)
def test_wp_id_of_branch(branch: str, wp: Optional[str]) -> None:
    assert rt.wp_id_of_branch(branch) == wp


def test_check_notes_strict_rejects_merged_wp_without_a_row(
    tmp_path: Path, history: Path
) -> None:
    _merge(history, "wp/w0.10-merged-followups")
    _merge(history, "wp/w0.13-review-round5")
    notes = _notes(
        tmp_path, w22="Dahil", w22b="`wp/w2.2-alert-lanes`", w19="Dahil değil", w19b="—"
    )
    rt.check_notes(notes, history)  # drafting mode tolerates it
    with pytest.raises(rt.ReleaseError) as exc:
        rt.check_notes(notes, history, strict=True)
    msg = str(exc.value)
    assert "W0.10: wp/w0.10-merged-followups is merged" in msg
    assert "W0.13: wp/w0.13-review-round5 is merged" in msg
    assert "has no row" in msg
    # W0.1 is not confused with W0.10 (prefix wp/w0.1- vs wp/w0.10-).
    assert "W0.1:" not in msg
    assert rt.main(
        ["--repo", str(history), "check-notes", "--notes", str(notes), "--strict"]
    ) == 1


def test_check_notes_strict_two_digit_id_marked_not_included(
    tmp_path: Path, history: Path
) -> None:
    _merge(history, "wp/w0.10-merged-followups")
    notes = tmp_path / "n.md"
    notes.write_text(
        NOTES.format(
            w22="Dahil", w22b="`wp/w2.2-alert-lanes`", w19="Dahil değil", w19b="—"
        )
        + "| W0.10 | Followups | Dahil değil | — |\n"
        + "| W0.1 | Sync | Dahil değil | — |\n"
    )
    with pytest.raises(rt.ReleaseError) as exc:
        rt.check_notes(notes, history, strict=True)
    assert "W0.10: marked 'Dahil değil'" in str(exc.value)
    assert "W0.1: marked" not in str(exc.value)


# --- render-notes: data-driven notes ---------------------------------------------


def _render_fixture(tmp_path: Path, repo: Path) -> Path:
    rel = repo / "docs" / "release"
    rel.mkdir(parents=True)
    init = repo / "infra" / "database" / "init"
    init.mkdir(parents=True)
    for name in ("45_old.sql", "46_a.sql", "47_b.sql", "56_c.sql", "58_d.sql"):
        (init / name).write_text("-- x\n")
    (rel / "t.md.in").write_text(
        "{{highlights}}\n\n{{wp_table}}\n\nSQL {{init_sql}}\n\n{{upgrade_notes}}\n\n"
        "OPEN\n{{known_issues}}\nFIXED\n{{fixed_issues}}\n"
        "{{included_count}}/{{not_included_count}} {{included_ids}} | {{not_included_ids}}\n"
    )
    (rel / "cl.md.in").write_text("inc: {{included_en}}\nnot: {{not_included_en}}\n")
    (repo / "CHANGELOG.md").write_text("# Changelog\n<!-- b -->\nold\n<!-- e -->\ntail\n")
    data = {
        "notes": "docs/release/n.md",
        "template": "t.md.in",
        "changelog": {
            "file": "CHANGELOG.md",
            "template": "cl.md.in",
            "begin": "<!-- b -->",
            "end": "<!-- e -->",
        },
        "self": ["W4.7"],
        "init_sql_from": 46,
        "wps": [
            {"id": "W0.2", "topic": "Marka", "topic_en": "brand", "branch": "brand/x"},
            {"id": "W0.10", "topic": "Takip", "topic_en": "follow-ups"},
            {"id": "W1.1", "topic": "Eval", "topic_en": "eval"},
            {"id": "W2.2", "topic": "Lanes", "topic_en": "lanes"},
            {"id": "W3.6", "topic": "Export", "topic_en": "export"},
        ],
        "highlights": [
            {"when": ["W1.1"], "text": "H-eval"},
            {"when": ["W3.6"], "text": "H-export"},
        ],
        "upgrade_notes": [
            {"unless": ["W3.6"], "text": "U-cgnat-open"},
            {"when": ["W3.6"], "text": "U-cgnat-allowlist"},
        ],
        "known_issues": [
            {"wp": "W1.1", "text": "cgnat", "fixed_by": "W3.6"},
            {"wp": "W1.1", "text": "doc", "fixed_by": "W0.10"},
            {"wp": "W3.6", "text": "not shown: W3.6 not merged"},
        ],
    }
    p = rel / "n.json"
    p.write_text(json.dumps(data))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "files")
    return p


def test_render_notes_from_history(tmp_path: Path, history: Path) -> None:
    data = _render_fixture(tmp_path, history)
    _merge(history, "wp/w0.10-merged-followups")
    _merge(history, "brand/x", "Merge brand/x: the brand")
    out = rt.render_notes(rt._load_notes_data(data), history)
    notes = out[(history / "docs/release/n.md").resolve()]
    assert "| W0.10 | Takip | Dahil | `wp/w0.10-merged-followups` |" in notes
    assert "| W0.2 | Marka | Dahil | `brand/x` |" in notes
    assert "| W1.1 | Eval | Dahil | `wp/w1.1-eval-harness` |" in notes
    assert "| W3.6 | Export | Dahil değil | — |" in notes
    assert "H-eval" in notes and "H-export" not in notes
    assert "U-cgnat-open" in notes and "U-cgnat-allowlist" not in notes
    assert "SQL 46–47, 56, 58" in notes
    open_part, fixed_part = notes.split("OPEN\n")[1].split("FIXED\n")
    assert "W1.1: cgnat" in open_part and "doc" not in open_part
    assert "W1.1: doc (W0.10 ile giderildi)" in fixed_part
    assert "not shown" not in notes
    assert "4/1 W0.2, W0.10, W1.1, W2.2 | W3.6" in notes
    cl = out[(history / "CHANGELOG.md").resolve()]
    assert cl.startswith("# Changelog\n<!-- b -->\ninc: W0.2 brand; W0.10 follow-ups")
    assert "not: W3.6 export\n<!-- e -->\ntail\n" in cl

    # W3.6 merges: the CGNAT issue moves to "fixed", the notes flip.
    _merge(history, "wp/w3.6-audit-export")
    notes = rt.render_notes(rt._load_notes_data(data), history)[
        (history / "docs/release/n.md").resolve()
    ]
    assert "U-cgnat-allowlist" in notes and "U-cgnat-open" not in notes
    assert "W1.1: cgnat (W3.6 ile giderildi)" in notes
    assert "H-export" in notes


def test_render_notes_refuses_merged_wp_missing_from_data(
    tmp_path: Path, history: Path
) -> None:
    data = _render_fixture(tmp_path, history)
    _merge(history, "wp/w0.11-new-thing")
    _merge(history, "wp/w4.7-release")  # self: allowed without a row
    with pytest.raises(rt.ReleaseError, match=r"W0.11 \(wp/w0.11-new-thing\)") as exc:
        rt.render_notes(rt._load_notes_data(data), history)
    assert "W4.7" not in str(exc.value)


def test_check_notes_with_data_detects_stale_notes(
    tmp_path: Path, history: Path
) -> None:
    data = _render_fixture(tmp_path, history)
    assert rt.main(
        ["--repo", str(history), "render-notes", "--data", str(data), "--write"]
    ) == 0
    notes = history / "docs/release/n.md"
    rt.check_notes(notes, history, strict=True, data=data)
    # A WP merges after the notes were rendered: stale, the tag must fail.
    _merge(history, "wp/w0.10-merged-followups")
    with pytest.raises(rt.ReleaseError, match="n.md is stale"):
        rt.check_notes(notes, history, strict=True, data=data)
    assert rt.main(
        ["--repo", str(history), "render-notes", "--data", str(data), "--write"]
    ) == 0
    rt.check_notes(notes, history, strict=True, data=data)
    # A hand edit of the generated CHANGELOG block is caught too.
    cl = history / "CHANGELOG.md"
    cl.write_text(cl.read_text().replace("inc: ", "inc: W9.9 extra; "))
    with pytest.raises(rt.ReleaseError, match="CHANGELOG.md is stale"):
        rt.check_notes(notes, history, strict=True, data=data)


# --- check-on-main ----------------------------------------------------------------


def test_check_on_main(tmp_path: Path, history: Path) -> None:
    _git(history, "branch", "main", "integration")
    on_main = subprocess.run(
        ["git", "-C", str(history), "rev-parse", "integration"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert rt.check_on_main(history, on_main, "main") == on_main
    _git(history, "checkout", "-q", "-b", "feature", "integration")
    _git(history, "commit", "-q", "--allow-empty", "-m", "not on main")
    with pytest.raises(rt.ReleaseError, match="is not on main"):
        rt.check_on_main(history, "feature", "main")
    assert (
        rt.main(["--repo", str(history), "check-on-main", "--commit", "feature", "--main", "main"])
        == 1
    )
    with pytest.raises(rt.ReleaseError, match="cannot resolve"):
        rt.check_on_main(history, "HEAD", "origin/main")


# --- merge subjects: GitHub PR merges and squash merges (Round 6) -----------------


@pytest.mark.parametrize(
    "subject,parents,branch",
    [
        ("Merge pull request #12 from SingularityRD/wp/w3.6-audit-export", 2,
         "wp/w3.6-audit-export"),
        ("Merge pull request #7 from acme/feature/x\n\nbody", 2, "feature/x"),
        ("Merge remote-tracking branch 'origin/wp/w1.9-oidc' into integration", 2,
         "wp/w1.9-oidc"),
        ("Merge branch 'wp/w1.9-oidc' into integration", 2, "wp/w1.9-oidc"),
        ("Merge branch 'integration' into wp/w4.7-release", 2, "integration"),
        ("Merge wp/w0.11-security-hotfix into integration (verified PASS)", 2,
         "wp/w0.11-security-hotfix"),
        ("Merge brand/autosecops-ui: the product shows AutoSecOps", 2,
         "brand/autosecops-ui"),
        ("W1.9: OIDC SSO (#13)", 1, "PR #13 (W1.9)"),
        ("W0.12b spool hardening (#21)", 1, "PR #21 (W0.12b)"),
        ("W1.9: OIDC SSO, no PR number", 1, None),
        ("fix: something (#14)", 1, None),
        ("Merge pull request #12 from x/wp/w3.6-audit-export", 1, None),
    ],
)
def test_branch_of_subject(subject: str, parents: int, branch: Optional[str]) -> None:
    assert rt.branch_of_subject(subject.split("\n")[0], parents) == branch


def test_wp_id_of_squash_label() -> None:
    assert rt.wp_id_of_branch("PR #13 (W1.9)") == "W1.9"
    assert rt.wp_id_of_branch("PR #13 (feature)") is None


def test_github_pr_merge_and_squash_merge_count_as_merged(
    tmp_path: Path, history: Path
) -> None:
    _merge(
        history,
        "wp/w3.6-audit-export",
        "Merge pull request #12 from SingularityRD/wp/w3.6-audit-export",
    )
    _git(history, "commit", "-q", "--allow-empty", "-m", "W1.9: OIDC SSO (#13)")
    merged = rt.merged_branches(history)
    assert {"wp/w3.6-audit-export", "PR #13 (W1.9)"} <= merged
    assert "pull" not in merged
    by_wp = rt.merged_wps(merged)
    assert by_wp["W3.6"] == "wp/w3.6-audit-export"
    assert by_wp["W1.9"] == "PR #13 (W1.9)"

    # strict: both must be "Dahil", W1.9 with its PR label as the merge cell.
    stale = _notes(
        tmp_path, w22="Dahil", w22b="`wp/w2.2-alert-lanes`", w19="Dahil değil", w19b="—"
    )
    with pytest.raises(rt.ReleaseError) as exc:
        rt.check_notes(stale, history, strict=True)
    assert "W1.9: marked 'Dahil değil' but PR #13 (W1.9) is merged" in str(exc.value)
    assert "W3.6: wp/w3.6-audit-export is merged" in str(exc.value)
    fresh = _notes(
        tmp_path,
        w22="Dahil",
        w22b="`wp/w2.2-alert-lanes`",
        w19="Dahil",
        w19b="`PR #13 (W1.9)`",
    )
    fresh.write_text(fresh.read_text() + "| W3.6 | Export | Dahil | `wp/w3.6-audit-export` |\n")
    rows = rt.check_notes(fresh, history, strict=True)
    assert {r["wp"] for r in rows if r["included"]} == {"W1.1", "W2.2", "W1.9", "W3.6"}


def test_render_lists_every_merged_branch_of_a_wp(tmp_path: Path, history: Path) -> None:
    data = _render_fixture(tmp_path, history)
    _merge(history, "wp/w0.10-review-a")
    _merge(history, "wp/w0.10-review-b")
    notes = rt.render_notes(rt._load_notes_data(data), history)[
        (history / "docs/release/n.md").resolve()
    ]
    assert "| W0.10 | Takip | Dahil | `wp/w0.10-review-a`, `wp/w0.10-review-b` |" in notes
    p = tmp_path / "multi.md"
    p.write_text(notes)
    rows = {r["wp"]: r for r in rt.check_notes(p, history, strict=True, data=None)}
    assert rows["W0.10"]["branches"] == ["wp/w0.10-review-a", "wp/w0.10-review-b"]
    # A listed branch that is not merged is an error even if the other one is.
    p.write_text(notes.replace("wp/w0.10-review-b", "wp/w0.10-review-c"))
    with pytest.raises(rt.ReleaseError, match="wp/w0.10-review-c has no merge commit"):
        rt.check_notes(p, history)


# --- shallow clones (Round 6) ------------------------------------------------------


def _shallow_clone(src: Path, dst: Path) -> Path:
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", "--no-local", f"file://{src}", str(dst)],
        check=True,
        capture_output=True,
    )
    return dst


def test_shallow_clone_is_refused_not_misread(tmp_path: Path, history: Path) -> None:
    _git(history, "branch", "main", "integration")
    _git(history, "checkout", "-q", "-b", "feature", "integration")
    _git(history, "commit", "-q", "--allow-empty", "-m", "not on main")
    _git(history, "checkout", "-q", "integration")
    clone = _shallow_clone(history, tmp_path / "shallow")
    assert rt.is_shallow(clone) and not rt.is_shallow(history)
    # A depth-1 clone sees no merge commits: refusing beats "nothing merged".
    with pytest.raises(rt.ReleaseError, match="shallow clone.*git fetch --unshallow"):
        rt.merged_branches(clone)
    notes = _notes(
        tmp_path, w22="Dahil", w22b="`wp/w2.2-alert-lanes`", w19="Dahil değil", w19b="—"
    )
    assert rt.main(["--repo", str(clone), "check-notes", "--notes", str(notes)]) == 1
    # check-on-main: "not an ancestor" in a shallow clone may be missing history.
    _git(clone, "fetch", "-q", "--depth", "1", "origin", "feature:feature")
    with pytest.raises(rt.ReleaseError, match="shallow clone"):
        rt.check_on_main(clone, "feature", "HEAD")
    # The documented fix works.
    _git(clone, "fetch", "-q", "--unshallow", "origin")
    assert not rt.is_shallow(clone)
    assert {"wp/w1.1-eval-harness", "wp/w2.2-alert-lanes"} <= rt.merged_branches(clone)
    rt.check_notes(notes, clone, strict=True)
    with pytest.raises(rt.ReleaseError, match="is not on"):
        rt.check_on_main(clone, "feature", "HEAD")


def _dry_run_fixture(tmp_path: Path) -> Path:
    """A small repo with the release scripts, version files, notes and lockfiles."""
    src = _mini_repo(tmp_path / "src")
    rels = [
        "scripts/release/dry-run.sh",
        "scripts/release/release_tool.py",
        "docs/release/2.0.0.md",
        *[rel for _, _, rel, _ in rt.LOCKFILES],
    ]
    for rel in rels:
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / rel, src / rel)
    _git(src, "init", "-q", "-b", "main")
    _git(src, "add", "-A")
    _git(src, "commit", "-q", "-m", "one")
    _git(src, "commit", "-q", "--allow-empty", "-m", "two")
    return src


def test_dry_run_on_a_shallow_clone(tmp_path: Path) -> None:
    clone = _shallow_clone(_dry_run_fixture(tmp_path), tmp_path / "shallow")
    dry = clone / "scripts/release/dry-run.sh"

    def run(*extra: str):
        return subprocess.run(
            ["sh", str(dry), "--out", str(tmp_path / "out"), *extra],
            env=_offline_env(tmp_path),
            capture_output=True,
            text=True,
            cwd=clone,
            timeout=600,
        )

    proc = run()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "SKIP release notes: shallow clone" in proc.stdout
    assert "DRY RUN OK" in proc.stdout
    proc = run("--strict-notes")
    assert proc.returncode != 0
    assert "--strict-notes needs the full merge history (shallow clone)" in proc.stderr
    assert "git fetch --unshallow" in proc.stderr
