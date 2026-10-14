"""A git rule source cannot run commands or reach internal hosts (W0.11, W4.3 F-1).

The URL of a git source used to reach ``git clone`` unchecked: ``ext::sh -c ...``
ran a command and ``--upload-pack=...`` was read as an option. These tests use
a local probe file as the canary; nothing here touches the network (hosts are
IP literals or ``localhost``, and the real git runs only against URLs it must
refuse before connecting).
"""

import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from core.config import get_settings
from core.detections import detection_rules_service as drs
from core.detections.detection_rules_service import (
    DetectionRulesService,
    check_git_url,
    validate_git_url,
)

pytestmark = pytest.mark.unit

HAS_GIT = shutil.which("git") is not None


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_DIR", raising=False)
    monkeypatch.delenv("VIGIL_DETECTION_GIT_ALLOWED_CIDRS", raising=False)
    get_settings.cache_clear()
    with patch.object(Path, "home", return_value=tmp_path):
        yield DetectionRulesService()
    get_settings.cache_clear()


@pytest.fixture
def probe(tmp_path):
    return tmp_path / "pwned"


@pytest.fixture
def permissive_git(monkeypatch):
    """A host whose git config allows ext:: (git's own default refuses it).

    Without W0.11 a plain ``git clone ext::...`` runs the command under this
    config; the hardened call must hold regardless of what the host allows.
    """
    monkeypatch.setenv("GIT_CONFIG_COUNT", "2")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "protocol.ext.allow")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "always")
    monkeypatch.setenv("GIT_CONFIG_KEY_1", "protocol.allow")
    monkeypatch.setenv("GIT_CONFIG_VALUE_1", "always")


def _ext(probe: Path) -> str:
    # git's ext:: transport: "% " is a literal space, so this runs
    # `sh -c "touch <probe>"` if git is allowed to use the transport.
    return f"ext::sh -c touch% {probe}"


BAD_URLS = [
    "ext::sh -c touch% /tmp/x/pwn",
    "--upload-pack=touch /tmp/x/evil",
    "-uhttps://example.com/evil",
    "file:///etc/x/repo",
    "/srv/git/repo",
    "../repo",
    "http://example.com/repo.git",
    "git://example.com/repo.git",
    "ssh://git@example.com/repo.git",
    "git@example.com:org/repo.git",
    "fd::17/repo",
    "https://user:token@example.com/repo.git",
    "https://example.com/repo.git?x=1",
    "https://example.com/repo.git#frag",
    "https://example.com/re po.git",
    "https://example.com/repo.git\n--upload-pack=x",
    "https:///repo.git",
    "",
]


@pytest.mark.parametrize("url", BAD_URLS)
def test_add_source_refuses_anything_but_plain_https(service, url):
    with patch.object(drs.subprocess, "run") as run:
        with pytest.raises(ValueError):
            service.add_source("Bad", "git", "sigma", url=url)
    run.assert_not_called()
    assert all(s.get("git_url") != url for s in service.sources)


@pytest.mark.parametrize("url", BAD_URLS)
def test_validate_git_url_refuses(url):
    with pytest.raises(ValueError):
        validate_git_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/org/repo.git",
        "https://localhost/org/repo.git",
        "https://10.1.2.3/org/repo.git",
        "https://169.254.169.254/latest/repo.git",
        "https://[::1]/org/repo.git",
        "https://[::ffff:169.254.169.254]/repo.git",
    ],
)
def test_internal_hosts_are_refused_before_git_runs(service, url):
    with patch.object(drs.subprocess, "run") as run:
        with pytest.raises(ValueError):
            service.add_source("Internal", "git", "sigma", url=url)
    run.assert_not_called()


def test_an_allowed_cidr_lets_an_internal_git_server_through(monkeypatch):
    monkeypatch.setenv("VIGIL_DETECTION_GIT_ALLOWED_CIDRS", "127.0.0.0/8")
    get_settings.cache_clear()
    try:
        assert check_git_url("https://127.0.0.1/org/repo.git") == ["127.0.0.1"]
        with pytest.raises(ValueError):  # metadata stays refused
            check_git_url("https://169.254.169.254/repo.git")
    finally:
        get_settings.cache_clear()


def _public(host, port, allowed_networks=()):
    return ["93.184.216.34"]


def test_clone_argv_and_environment(service):
    """``--`` before the URL, https-only env, no prompts, no submodules, timeout."""
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"], seen["kwargs"] = argv, kwargs
        Path(argv[-1]).mkdir(parents=True)
        return subprocess.CompletedProcess(argv, 0, "", "")

    with (
        patch.object(drs, "resolve_allowed_addresses", side_effect=_public),
        patch.object(drs.subprocess, "run", side_effect=fake_run),
    ):
        service.add_source(
            "Mine", "git", "sigma", url="https://git.example.com/org/rules.git"
        )

    argv, kwargs = seen["argv"], seen["kwargs"]
    assert argv[0] == "git"
    clone = argv.index("clone")
    dashdash = argv.index("--")
    assert clone < dashdash and argv[dashdash + 1] == (
        "https://git.example.com/org/rules.git"
    )
    assert argv[dashdash + 2].startswith(str(service.base_dir))
    assert "--no-recurse-submodules" in argv and "--recurse-submodules" not in argv
    config = [argv[i + 1] for i, a in enumerate(argv[:clone]) if a == "-c"]
    assert "protocol.ext.allow=never" in config
    assert "protocol.file.allow=never" in config
    assert "http.followRedirects=false" in config
    assert "http.curloptResolve=git.example.com:443:93.184.216.34" in config
    env = kwargs["env"]
    assert env["GIT_ALLOW_PROTOCOL"] == "https"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert kwargs["timeout"] and kwargs["timeout"] <= 300
    assert kwargs.get("shell") in (None, False)


def test_a_stored_url_is_checked_again_on_update(service):
    """A URL written into detection_sources.json before W0.11 cannot reach git."""
    service.sources.append(
        {
            "id": "legacy1",
            "name": "Legacy",
            "type": "git",
            "git_url": "ext::sh -c touch% /tmp/x/pwn",
            "format": "sigma",
            "subdirectory": "",
            "story_subdirectory": "",
            "clone_name": "pwn",
            "local_path": str(service.base_dir / "pwn"),
            "rule_count": 0,
            "last_updated": None,
            "status": "not_cloned",
        }
    )
    with patch.object(drs.subprocess, "run") as run:
        with pytest.raises(ValueError):
            service.update_source("legacy1")
    run.assert_not_called()


# --- the real git, against URLs it must refuse -------------------------------


@pytest.mark.skipif(not HAS_GIT, reason="git not installed")
def test_git_itself_refuses_ext_even_past_the_url_check(service, probe, permissive_git):
    """Defence in depth: with the URL check bypassed, git still will not run ext::."""
    target = str(service.base_dir / "pwn")
    with patch.object(drs, "check_git_url", return_value=[]):
        with pytest.raises(RuntimeError):
            service._git_clone(_ext(probe), target)
    assert not probe.exists()


@pytest.mark.skipif(not HAS_GIT, reason="git not installed")
def test_an_option_shaped_url_is_not_read_as_an_option(service, probe, permissive_git):
    target = str(service.base_dir / "evil")
    url = f"--upload-pack=touch {probe}"
    with patch.object(drs, "check_git_url", return_value=[]):
        with pytest.raises(RuntimeError):
            service._git_clone(url, target)
    assert not probe.exists()


@pytest.mark.skipif(not HAS_GIT, reason="git not installed")
def test_add_source_with_ext_url_runs_nothing(service, probe, permissive_git):
    with pytest.raises(ValueError):
        service.add_source("Pwn", "git", "sigma", url=_ext(probe) + "/pwn")
    assert not probe.exists()


@pytest.mark.skipif(not HAS_GIT, reason="git not installed")
def test_pull_ignores_a_planted_origin_and_checks_the_given_url(
    service, probe, permissive_git
):
    """The clone's origin is never used; the URL handed in is checked instead."""
    repo = service.base_dir / "planted"
    repo.mkdir(parents=True)
    env = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": str(service.base_dir),
        "PATH": "/usr/bin:/bin",
    }
    subprocess.run(["git", "init", "-q", str(repo)], check=True, env=env)
    subprocess.run(
        ["git", "-C", str(repo), "remote", "add", "origin", _ext(probe)],
        check=True,
        env=env,
    )
    with pytest.raises(ValueError, match="not an allowed https URL"):
        service._git_pull(str(repo), _ext(probe))
    assert not probe.exists()
    # Even with the URL check bypassed, git's own transport policy holds.
    with patch.object(drs, "check_git_url", return_value=[]):
        with pytest.raises(RuntimeError):
            service._git_pull(str(repo), _ext(probe))
    assert not probe.exists()


@pytest.mark.skipif(not HAS_GIT, reason="git not installed")
def test_the_probe_does_fire_without_the_hardening(tmp_path, probe, permissive_git):
    """Control: the canary is live, so the tests above prove a refusal."""
    subprocess.run(
        ["git", "clone", "--quiet", "--depth", "1", _ext(probe), str(tmp_path / "t")],
        capture_output=True,
        timeout=60,
    )
    assert probe.exists()


def test_clone_target_must_stay_under_the_clone_root(service):
    with patch.object(drs, "check_git_url", return_value=[]):
        with patch.object(drs.subprocess, "run") as run:
            with pytest.raises(ValueError):
                service._git_clone("https://example.com/r.git", "/tmp/elsewhere")
    run.assert_not_called()


# --- Round 5: update does not trust the clone's own remote/branch config -----


def _git(*args, cwd=None):
    env = {"GIT_CONFIG_NOSYSTEM": "1", "HOME": str(cwd or "/"), "PATH": "/usr/bin:/bin"}
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        check=True,
        cwd=cwd,
        env=env,
        capture_output=True,
    )


def _upstream_and_clone(service, tmp_path):
    """A file:// upstream and a depth-1 clone of it under base_dir, like _git_clone makes."""
    up = tmp_path / "upstream"
    up.mkdir()
    _git("init", "-q", "-b", "main", cwd=up)
    (up / "a.yml").write_text("one\n")
    _git("add", ".", cwd=up)
    _git("commit", "-qm", "one", cwd=up)
    service.base_dir.mkdir(parents=True, exist_ok=True)
    clone = service.base_dir / "rules"
    _git("clone", "-q", "--depth", "1", "--single-branch", f"file://{up}", str(clone))
    return up, clone


def test_update_fetches_the_stored_url_not_the_clone_origin(service):
    """fetch names the checked URL after ``--``, then an explicit reset."""
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        out = "core.bare\nremote.origin.url\n" if "config" in argv else ""
        return subprocess.CompletedProcess(argv, 0, out, "")

    clone = service.base_dir / "rules"
    clone.mkdir(parents=True)
    with (
        patch.object(drs, "resolve_allowed_addresses", side_effect=_public),
        patch.object(drs.subprocess, "run", side_effect=fake_run),
    ):
        service._git_pull(str(clone), "https://git.example.com/org/rules.git")
    fetch = next(a for a in calls if "fetch" in a)
    i = fetch.index("--")
    assert fetch[i + 1 :] == ["https://git.example.com/org/rules.git", "HEAD"]
    assert "pull" not in [x for a in calls for x in a]
    config = [fetch[k + 1] for k, a in enumerate(fetch) if a == "-c"]
    assert "core.fsmonitor=false" in config
    assert "credential.helper=" in config
    assert "core.hooksPath=/dev/null" in config
    assert "http.curloptResolve=git.example.com:443:93.184.216.34" in config
    reset = next(a for a in calls if "reset" in a)
    assert reset[-2:] == ["--hard", "FETCH_HEAD"]
    assert "core.fsmonitor=false" in reset


@pytest.mark.skipif(not HAS_GIT, reason="git not installed")
def test_update_fetch_and_reset_really_update_a_shallow_clone(service, tmp_path):
    """The fetch/reset sequence works on a depth-1 clone (file:// for the test only)."""
    up, clone = _upstream_and_clone(service, tmp_path)
    (up / "a.yml").write_text("two\n")
    _git("commit", "-qam", "two", cwd=up)
    with (
        patch.object(drs, "check_git_url", return_value=[]),
        patch.object(drs, "_GIT_SAFE_CONFIG", ("-c", "protocol.file.allow=always")),
        patch.object(drs, "_git_env", return_value={"PATH": "/usr/bin:/bin"}),
    ):
        service._git_pull(str(clone), f"file://{up}")
    assert (clone / "a.yml").read_text() == "two\n"


@pytest.mark.skipif(not HAS_GIT, reason="git not installed")
@pytest.mark.parametrize(
    "key,value",
    [
        ("url.file:///srv/.insteadOf", "https://git.example.com/"),
        ("http.proxy", "http://10.0.0.1:3128"),
        ("include.path", "/tmp/evil.cfg"),
        ("core.sshCommand", "touch /tmp/x"),
        ("core.fsmonitor", "touch /tmp/x"),
    ],
)
def test_update_refuses_a_clone_with_planted_config(service, tmp_path, key, value):
    _, clone = _upstream_and_clone(service, tmp_path)
    _git("config", key, value, cwd=clone)
    with patch.object(drs, "resolve_allowed_addresses", side_effect=_public):
        with pytest.raises(ValueError, match="git config sets"):
            service._git_pull(str(clone), "https://git.example.com/org/rules.git")


@pytest.mark.skipif(not HAS_GIT, reason="git not installed")
def test_a_fresh_clone_config_passes_the_allowlist(service, tmp_path):
    _, clone = _upstream_and_clone(service, tmp_path)
    service._check_clone_config(str(clone))


def test_update_source_refuses_a_stored_git_path_outside_base_dir(service, tmp_path):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    service.sources.append(
        {
            "id": "moved1",
            "name": "Moved",
            "type": "git",
            "git_url": "https://git.example.com/org/rules.git",
            "format": "sigma",
            "local_path": str(outside),
            "status": "ready",
        }
    )
    with patch.object(drs.subprocess, "run") as run:
        with pytest.raises(ValueError, match="inside"):
            service.update_source("moved1")
    run.assert_not_called()


def test_update_source_refuses_a_stored_local_path_outside_the_roots(service):
    service.sources.append(
        {
            "id": "local1",
            "name": "Etc",
            "type": "local",
            "format": "sigma",
            "local_path": "/etc",
            "status": "ready",
        }
    )
    with pytest.raises(ValueError, match="Local path must be under"):
        service.update_source("local1")
