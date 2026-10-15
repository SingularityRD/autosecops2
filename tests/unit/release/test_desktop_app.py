"""The desktop app (clients/desktop) as a supported product component (WP W0.24).

Static checks over the Electron app and its pipelines:

* identity: appId, package name, artifact names and icons are AutoSecOps, not
  the upstream Vigil / DeepTempo ones; no user-visible string says Vigil;
* packaging: dmg (arm64 + x64), AppImage, NSIS; never published, no updater;
* Electron hardening: every window isolated, sandboxed, no Node, web security
  on; navigation, new windows, <webview> and shell.openExternal guarded;
  Electron fuses flipped; the Electron major is a supported one;
* release.yml: desktop installers built on matching runners, signing secrets
  only in the desktop build step's env, installers signed and checksummed by
  the sign job; the desktop lockfile has an SBOM;
* ci-cd.yml: a build-only desktop job without secrets, registry or publish.

The URL policy itself is unit-tested in clients/desktop/test (node --test),
which the CI and release jobs run.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]
DESKTOP = REPO / "clients" / "desktop"
SRC = DESKTOP / "src"
RELEASE = REPO / ".github" / "workflows" / "release.yml"
CI = REPO / ".github" / "workflows" / "ci-cd.yml"
CANONICAL = "github.repository == 'SingularityRD/autosecops2'"
SHA_PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")

APP_ID = "com.singularityrd.autosecops"
# Electron majors receive security fixes for the latest three stable lines;
# 44 was the newest stable when W0.24 landed (2026-10). Raise, never lower.
MIN_ELECTRON_MAJOR = 44
SIGNING_SECRETS = {
    "CSC_LINK",
    "CSC_KEY_PASSWORD",
    "APPLE_ID",
    "APPLE_APP_SPECIFIC_PASSWORD",
    "APPLE_TEAM_ID",
    "WIN_CSC_LINK",
    "WIN_CSC_KEY_PASSWORD",
}
# sha256 of the upstream Vigil mark the app shipped before W0.24.
VIGIL_ICONS = {
    "256x256.png": "1b4f6d65d15d7d5baadfbbfe68d5133eb571068feb00e4bb7b6f81f3ee144def",
    "512x512.png": "51d65927603a0e59fe2f479d5b4de3be02a9facbb3248125acd42aa052854fcd",
    "icon.icns": "3ec0bb45b44a2a6dba4823e1a506aff86364fb8bb2f842ab729241525ad78539",
    "tray.png": "d88a3c84b38386e21ed451f58f8e1f87414108b830fb82723c9ae005bb0a21e9",
    "tray@2x.png": "cf2ae75236ccfa4bae5932d2862ad2e6f5265af5a902ddf17f69d58e120df0a9",
}


def _load_wf(path: Path) -> dict:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if True in doc:  # YAML 1.1 reads the bare key `on` as boolean True
        doc["on"] = doc.pop(True)
    return doc


@pytest.fixture(scope="module")
def builder() -> dict:
    return yaml.safe_load(
        (DESKTOP / "electron-builder.yml").read_text(encoding="utf-8")
    )


@pytest.fixture(scope="module")
def main_ts() -> str:
    return (SRC / "main.ts").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def release() -> dict:
    return _load_wf(RELEASE)


@pytest.fixture(scope="module")
def ci() -> dict:
    return _load_wf(CI)


def _strip_comments(ts: str) -> str:
    ts = re.sub(r"/\*.*?\*/", "", ts, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$|(?<=[;,{}()\s])//[^\n\"'`]*$", "", ts)


def _string_literals(ts: str) -> list[str]:
    return re.findall(
        r"\"((?:[^\"\\\n]|\\.)*)\"|`((?:[^`\\]|\\.)*)`", _strip_comments(ts)
    )


# --------------------------------------------------------------------- identity


def test_app_id_and_names_are_autosecops(builder: dict) -> None:
    assert builder["appId"] == APP_ID
    assert builder["productName"] == "AutoSecOps"
    assert builder["artifactName"].startswith("autosecops-${version}-desktop-")
    assert builder["linux"]["executableName"] == "autosecops"
    pkg = json.loads((DESKTOP / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((DESKTOP / "package-lock.json").read_text(encoding="utf-8"))
    assert (
        pkg["name"]
        == lock["name"]
        == lock["packages"][""]["name"]
        == "autosecops-desktop"
    )
    assert pkg["productName"] == "AutoSecOps"
    text = (DESKTOP / "electron-builder.yml").read_text(encoding="utf-8")
    assert "ai.deeptempo" not in text.replace("the upstream ai.deeptempo.vigil", "")


def test_no_user_visible_string_says_vigil(main_ts: str) -> None:
    sources = {p.name: p.read_text(encoding="utf-8") for p in SRC.glob("*.ts")}
    for name, ts in sources.items():
        for groups in _string_literals(ts):
            lit = "".join(groups)
            # VIGIL_* env vars and the vigil-support.sh file name are internal
            # identifiers kept on purpose (FORK.md §2); lowercase clone folders
            # find pre-rename checkouts.
            assert "Vigil" not in lit and "DeepTempo" not in lit, f"{name}: {lit!r}"
    splash = (SRC / "splash.html").read_text(encoding="utf-8")
    visible = re.sub(r"<script>.*?</script>|<style>.*?</style>", "", splash, flags=re.S)
    assert not re.search(r"vigil|deeptempo", visible, re.I)


def test_log_names_are_autosecops() -> None:
    ts = (SRC / "logkeep.ts").read_text(encoding="utf-8")
    assert 'name = "autosecops-desktop.log"' in ts
    assert "`autosecops-${stamp(now)}.log`" in ts
    assert '"autosecops-logs.txt"' in (SRC / "main.ts").read_text(encoding="utf-8")
    support = (REPO / "scripts" / "vigil-support" / "vigil-support.sh").read_text()
    assert "'autosecops-desktop.log*'" in support and "'autosecops-*.log'" in support


def test_icons_are_not_the_vigil_mark() -> None:
    icons = DESKTOP / "build" / "icons"
    for name, vigil in VIGIL_ICONS.items():
        digest = hashlib.sha256((icons / name).read_bytes()).hexdigest()
        assert digest != vigil, f"{name} is still the upstream Vigil mark"


# --------------------------------------------------------------------- packaging


def test_targets_dmg_appimage_nsis(builder: dict) -> None:
    mac = builder["mac"]["target"]
    assert [t["target"] for t in mac] == ["dmg"]
    assert set(mac[0]["arch"]) == {"arm64", "x64"}
    assert [t["target"] for t in builder["linux"]["target"]] == ["AppImage"]
    assert [t["target"] for t in builder["win"]["target"]] == ["nsis"]
    assert (
        "identity" not in builder["mac"]
    ), "identity: null would block Developer ID signing"
    assert builder["mac"]["hardenedRuntime"] is True
    assert builder["nsis"]["deleteAppDataOnUninstall"] is False


def test_never_published_and_no_auto_updater(builder: dict) -> None:
    assert "publish" in builder and builder["publish"] is None
    pkg = json.loads((DESKTOP / "package.json").read_text(encoding="utf-8"))
    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
    assert "electron-updater" not in deps
    assert "--publish never" in pkg["scripts"]["dist"]
    for ts in SRC.glob("*.ts"):
        assert "autoUpdater" not in ts.read_text(encoding="utf-8"), ts.name


# Every fuse the app depends on and its required state; after-pack.js sets
# them and the CI job reads them back from a real build.
REQUIRED_FUSES = {
    "RunAsNode": False,
    "EnableNodeOptionsEnvironmentVariable": False,
    "EnableNodeCliInspectArguments": False,
    "EnableEmbeddedAsarIntegrityValidation": True,
    "OnlyLoadAppFromAsar": True,
    "EnableCookieEncryption": True,
}


def test_after_pack_flips_fuses_and_signs_only_without_developer_id(
    builder: dict,
) -> None:
    hook = DESKTOP / builder["afterPack"]
    assert hook.is_file()
    js = hook.read_text(encoding="utf-8")
    set_fuses = dict(re.findall(r"\[FuseV1Options\.(\w+)\]:\s*(true|false)", js))
    assert set_fuses == {k: str(v).lower() for k, v in REQUIRED_FUSES.items()}
    assert (
        "electronFuses" not in builder
    ), "electron-builder would flip them after the ad-hoc signature"
    assert "disableAsarIntegrity" not in builder, "the integrity fuse needs the hash"
    assert builder.get("asar", True) is not False
    assert "hasDeveloperId()" in js and "CSC_LINK" in js


def test_ci_reads_back_every_required_fuse(ci: dict) -> None:
    step = next(
        s
        for s in ci["jobs"]["build-desktop"]["steps"]
        if "electron-fuses read" in s.get("run", "")
    )
    run = step["run"]
    m = re.search(r"for want in (.*?); do", run, re.S)
    assert m, "fuse loop"
    wanted = dict(w.split(":") for w in m.group(1).replace("\\", " ").split())
    assert wanted == {
        k: ("Enabled" if v else "Disabled") for k, v in REQUIRED_FUSES.items()
    }
    # Exact whole-line match, and a miss fails the step.
    assert 'grep -qxF "$line" || {' in run and "exit 1" in run
    assert "set -eu" in run


def test_electron_is_a_supported_major() -> None:
    lock = json.loads((DESKTOP / "package-lock.json").read_text(encoding="utf-8"))
    version = lock["packages"]["node_modules/electron"]["version"]
    assert int(version.split(".")[0]) >= MIN_ELECTRON_MAJOR, version


# --------------------------------------------------------------------- hardening


ISOLATION = ("contextIsolation", "nodeIntegration", "sandbox", "webSecurity")


def _prefs_ok(p: str) -> None:
    assert re.search(r"contextIsolation:\s*true", p), p
    assert re.search(r"nodeIntegration:\s*false", p), p
    assert re.search(r"sandbox:\s*true", p), p
    assert re.search(r"webSecurity:\s*true", p), p


def test_every_window_is_isolated_and_sandboxed(main_ts: str) -> None:
    prefs = re.findall(r"webPreferences:\s*\{(.*?)\}", main_ts, flags=re.S)
    assert len(prefs) == 2, "splash and main window"
    for p in prefs:
        _prefs_ok(p)
    guard = (SRC / "navguard.ts").read_text(encoding="utf-8")
    m = re.search(r"const CHILD_WINDOW_PREFS = \{(.*?)\};", guard)
    assert m, "child windows opened by the console"
    _prefs_ok(m.group(1))
    for text in (main_ts, guard):
        for bad in (
            "webSecurity: false",
            "allowRunningInsecureContent",
            "nodeIntegrationInSubFrames",
            "webviewTag: true",
        ):
            assert bad not in text, bad


def test_navigation_windows_and_webviews_are_guarded(main_ts: str) -> None:
    """main.ts wires navguard's tested functions into every webContents and
    the default session, and installs no handler of its own."""
    code = _strip_comments(main_ts)
    assert re.search(
        r'app\.on\("web-contents-created", \(_event, contents\) =>\s*'
        r"hardenWebContents\(contents, \(url\) => void shell\.openExternal\(url\)",
        code,
    )
    assert "applyPermissionPolicy(session.defaultSession);" in code
    for own in (
        "setPermissionRequestHandler",
        "setPermissionCheckHandler",
        "setWindowOpenHandler",
        '"will-navigate"',
        "startsWith(BACKEND_URL)",
    ):
        assert own not in code, f"main.ts must leave {own} to navguard.ts"
    guard = _strip_comments((SRC / "navguard.ts").read_text(encoding="utf-8"))
    for needle in (
        '"will-navigate"',
        '"will-redirect"',
        '"will-attach-webview"',
        "setWindowOpenHandler",
        "setPermissionRequestHandler",
        "setPermissionCheckHandler",
    ):
        assert needle in guard, needle


def test_open_external_only_for_fixed_urls_or_the_allow_list(main_ts: str) -> None:
    code = _strip_comments(main_ts)
    calls = re.findall(r"shell\.openExternal\(([^)]*)\)", code)
    assert calls
    for arg in calls:
        assert arg in {
            "FDA_SETTINGS_URL",
            "DOCKER_INSTALL_URL",
            "BACKEND_URL",
            "url",
        }, arg
    # `url` (from web content) reaches the OS only through hardenWebContents,
    # which passes it through externalUrl first.
    assert code.count("shell.openExternal(url)") == 1
    guard = (SRC / "navguard.ts").read_text(encoding="utf-8")
    assert 'new Set(["https:", "mailto:"])' in guard
    assert "const safe = externalUrl(url);" in guard


def test_node_unit_tests_pass_when_dependencies_are_installed() -> None:
    """The fakes-based tests of the wiring (test/navguard.test.js); CI and the
    release job run them too. Skipped where clients/desktop has no node_modules."""
    if not (DESKTOP / "node_modules" / "typescript").is_dir():
        pytest.skip("clients/desktop/node_modules not installed (npm ci)")
    npm = shutil.which("npm")
    if not npm:
        pytest.skip("npm not installed")
    proc = subprocess.run(
        [npm, "test"], cwd=DESKTOP, capture_output=True, text=True, timeout=300
    )
    assert proc.returncode == 0, proc.stdout[-4000:] + proc.stderr[-2000:]
    assert re.search(r"^# fail 0$", proc.stdout, re.M), proc.stdout[-2000:]


def test_splash_never_renders_markup_from_messages() -> None:
    splash = (SRC / "splash.html").read_text(encoding="utf-8")
    # Constant markup is fine; markup built from a value is not.
    assert not re.search(r"innerHTML\s*=[^;]*\+", splash)
    assert "err.textContent = msg" in splash
    assert "default-src 'none'" in splash  # CSP stays


def test_devtools_only_in_development(main_ts: str) -> None:
    assert '...(app.isPackaged ? [] : [{ role: "toggleDevTools" as const }])' in main_ts
    assert "openDevTools" not in main_ts


# --------------------------------------------------------------------- release.yml


def test_release_builds_installers_on_matching_runners(release: dict) -> None:
    job = release["jobs"]["desktop"]
    assert job["if"] == CANONICAL
    assert set(job["needs"]) == {"version", "desktop-resources"}
    assert job["permissions"] == {"contents": "read"}
    runners = {e["platform"]: e["runner"] for e in job["strategy"]["matrix"]["include"]}
    assert set(runners) == {"mac", "linux", "win"}
    assert runners["mac"].startswith("macos-")
    assert runners["linux"].startswith("ubuntu-")
    assert runners["win"].startswith("windows-")
    build = next(s for s in job["steps"] if s.get("name") == "Build installers")
    assert "npm ci" in build["run"] and "npm test" in build["run"]
    assert "--publish never" in build["run"]
    assert '-c.extraMetadata.version="$VERSION"' in build["run"]
    assert build["env"]["VERSION"] == "${{ needs.version.outputs.version }}"


def test_desktop_resources_come_from_the_released_image(release: dict) -> None:
    job = release["jobs"]["desktop-resources"]
    assert job["if"] == CANONICAL
    assert "build-images" in job["needs"]
    assert job["permissions"] == {"contents": "read", "packages": "read"}
    run = " ".join(s.get("run", "") for s in job["steps"])
    assert "node clients/desktop/scripts/prepare-standalone.js" in run
    step = next(s for s in job["steps"] if "prepare-standalone" in s.get("run", ""))
    assert (
        step["env"]["AUTOSECOPS_DESKTOP_VERSION"]
        == "${{ needs.version.outputs.version }}"
    )
    js = (DESKTOP / "scripts" / "prepare-standalone.js").read_text(encoding="utf-8")
    assert "process.env.AUTOSECOPS_DESKTOP_VERSION" in js


def test_signing_secrets_only_in_the_desktop_build_env(release: dict) -> None:
    raw = RELEASE.read_text(encoding="utf-8")
    used = set(re.findall(r"secrets\.(\w+)", raw)) - {"GITHUB_TOKEN"}
    assert used == SIGNING_SECRETS
    for name, job in release["jobs"].items():
        for step in job.get("steps", []):
            env = step.get("env") or {}
            text = json.dumps({k: v for k, v in step.items() if k != "env"})
            for s in SIGNING_SECRETS:
                assert (
                    f"secrets.{s}" not in text
                ), f"{name}/{step.get('name')}: {s} outside env"
            in_env = [
                k
                for k, v in env.items()
                if any(f"secrets.{s}" in str(v) for s in SIGNING_SECRETS)
            ]
            if in_env:
                assert (
                    name == "desktop"
                ), f"{name}: signing secret outside the desktop job"
                assert step["name"] in {
                    "Build installers",
                    "Which signing material is configured",
                }
        assert "env" not in job or not any(
            "secrets." in str(v) for v in job["env"].values()
        ), name
    assert not any("secrets." in str(v) for v in (release.get("env") or {}).values())


def test_each_platform_sees_only_its_own_certificate(release: dict) -> None:
    build = next(
        s
        for s in release["jobs"]["desktop"]["steps"]
        if s.get("name") == "Build installers"
    )
    env = build["env"]
    for key in (
        "CSC_LINK",
        "CSC_KEY_PASSWORD",
        "APPLE_ID",
        "APPLE_APP_SPECIFIC_PASSWORD",
        "APPLE_TEAM_ID",
    ):
        assert (
            env[key] == f"${{{{ matrix.platform == 'mac' && secrets.{key} || '' }}}}"
        ), key
    for key in ("WIN_CSC_LINK", "WIN_CSC_KEY_PASSWORD"):
        assert (
            env[key] == f"${{{{ matrix.platform == 'win' && secrets.{key} || '' }}}}"
        ), key
    probe = next(
        s
        for s in release["jobs"]["desktop"]["steps"]
        if s.get("name") == "Which signing material is configured"
    )
    # Only booleans reach the shell.
    for v in probe["env"].values():
        assert "secrets." not in str(v) or "!= ''" in str(v), v
    assert "refusing to ship a signed but unnotarized dmg" in probe["run"]


def test_unsigned_installers_are_labelled(release: dict) -> None:
    step = next(
        s
        for s in release["jobs"]["desktop"]["steps"]
        if s.get("name") == "Collect and label installers"
    )
    assert "-unsigned.${name##*.}" in step["run"]
    assert step["env"]["SIGNED"] == "${{ steps.signing.outputs.signed }}"


def test_installers_are_signed_checksummed_and_released(release: dict) -> None:
    sign = release["jobs"]["sign"]
    assert "desktop" in sign["needs"]
    dl = [s for s in sign["steps"] if s.get("name") == "Download desktop installers"]
    assert dl and dl[0]["with"]["pattern"] == "desktop-installer-*"
    assert dl[0]["with"]["path"] == "dist"
    uploads = {
        s["with"]["name"]
        for j in release["jobs"].values()
        for s in j.get("steps", [])
        if s.get("uses", "").startswith("actions/upload-artifact@")
    }
    # The pattern must catch the installers and nothing else.
    caught = {n for n in uploads if n.startswith("desktop-installer-")}
    assert caught == {"desktop-installer-${{ matrix.platform }}"}
    run = " ".join(s.get("run", "") for s in sign["steps"])
    assert (
        "for f in dist/*; do" in run and "release_tool.py checksums --dir dist" in run
    )
    verify = (REPO / "scripts" / "release" / "verify-release.sh").read_text()
    assert 'autosecops-"${version}"-desktop-*' in verify


def test_desktop_lockfile_has_an_sbom() -> None:
    sys.path.insert(0, str(REPO / "scripts" / "release"))
    import release_tool  # noqa: E402

    assert (
        "node-desktop",
        "npm",
        "clients/desktop/package-lock.json",
        "autosecops-desktop",
    ) in (release_tool.LOCKFILES)


def test_desktop_jobs_pin_actions_and_disable_credentials(release: dict) -> None:
    for name in ("desktop", "desktop-resources"):
        for step in release["jobs"][name]["steps"]:
            uses = step.get("uses")
            if uses:
                assert SHA_PIN.match(uses), uses
            if str(uses).startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False


# --------------------------------------------------------------------- ci-cd.yml


def test_ci_builds_the_desktop_app_without_secrets_or_publishing(ci: dict) -> None:
    job = ci["jobs"]["build-desktop"]
    assert job["if"] == CANONICAL
    assert job["permissions"] == {"contents": "read"}
    text = json.dumps(job)
    assert "secrets." not in text
    for forbidden in (
        "CSC_LINK",
        "APPLE_ID",
        "WIN_CSC_LINK",
        "docker login",
        "docker push",
    ):
        assert forbidden not in text, forbidden
    run = " ".join(s.get("run", "") for s in job["steps"])
    assert "npm ci" in run and "npm test" in run
    assert (
        "electron-builder --config electron-builder.yml --linux --dir --publish never"
        in run
    )
    assert "electron-fuses read" in run
    release_refs = set(re.findall(r"uses: (\S+@[0-9a-f]{40})", RELEASE.read_text()))
    for step in job["steps"]:
        uses = step.get("uses")
        if uses:
            assert SHA_PIN.match(uses) and uses in release_refs, uses


# --------------------------------------------------------------------- signing probe


def _probe(release: dict) -> dict:
    return next(
        s
        for s in release["jobs"]["desktop"]["steps"]
        if s.get("name") == "Which signing material is configured"
    )


@pytest.mark.parametrize(
    "platform,mac,notary,win,code,signed",
    [
        ("mac", "true", "true", "false", 0, "true"),
        ("mac", "false", "false", "false", 0, "false"),
        ("mac", "false", "true", "false", 0, "false"),
        # A certificate without the notarization secrets must stop the job.
        ("mac", "true", "false", "false", 1, None),
        ("win", "false", "false", "true", 0, "true"),
        ("win", "true", "true", "false", 0, "false"),
        ("linux", "true", "true", "true", 0, "false"),
    ],
)
def test_signing_probe_decides_and_refuses_unnotarized(
    release: dict, tmp_path: Path, platform, mac, notary, win, code, signed
) -> None:
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash not installed")
    step = _probe(release)
    out = tmp_path / "github_output"
    out.write_text("")
    env = {
        "PATH": "/usr/bin:/bin",
        "GITHUB_OUTPUT": str(out),
        "PLATFORM": platform,
        "HAS_MAC_CERT": mac,
        "HAS_NOTARY": notary,
        "HAS_WIN_CERT": win,
    }
    proc = subprocess.run(
        [bash, "-c", step["run"]], env=env, capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == code, proc.stdout + proc.stderr
    if code:
        assert "::error::" in proc.stdout
        assert "signed=" not in out.read_text()
    else:
        assert out.read_text() == f"signed={signed}\n"


def test_no_step_can_print_a_signing_secret(release: dict) -> None:
    """No run script names a signing variable, so none can echo, printenv or
    `set -x` it; the probe sees only booleans."""
    names = "|".join(sorted(SIGNING_SECRETS))
    ref = re.compile(rf"\$\{{?(?:{names})\b")
    for name, job in release["jobs"].items():
        for step in job.get("steps", []):
            run = step.get("run", "")
            assert not ref.search(run), f"{name}/{step.get('name')}: reads a secret"
            for bad in ("printenv", "set -x", "env |", "export -p"):
                assert bad not in run, f"{name}/{step.get('name')}: {bad}"
    probe = _probe(release)
    for key, value in probe["env"].items():
        if "secrets." in str(value):
            assert key.startswith("HAS_") and re.fullmatch(
                r"\$\{\{ (secrets\.\w+ != '' ?(&& )?)+\}\}", str(value)
            ), (key, value)
