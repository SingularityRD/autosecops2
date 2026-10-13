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


def test_release_notes_included_items_are_merged() -> None:
    rows = rt.check_notes(REPO / "docs/release/2.0.0.md", REPO)
    included = {r["wp"] for r in rows if r["included"]}
    assert {"W0.1", "W2.2", "W3.3", "W3.8"} <= included
    assert "W1.9" not in included  # not merged when the notes were drafted


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
