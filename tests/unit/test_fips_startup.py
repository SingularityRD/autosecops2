"""FIPS_MODE=true refuses to start without the OpenSSL 3 FIPS provider (W3.10)."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

import core.config as config_module
import core.crypto.fips as fips
from core.crypto.fips import FipsStatus, fips_refusal_reason, fips_status

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]

needs_non_fips_host = pytest.mark.skipif(
    fips_status().active, reason="host runs the FIPS provider; refusal cannot be shown"
)


def _run(argv_tail, **extra_env):
    env = os.environ.copy()
    env.update({"DEV_MODE": "true", "VIGIL_DISABLE_DOTENV": "1", **extra_env})
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (str(REPO_ROOT), env.get("PYTHONPATH")) if p
    )
    return subprocess.run(
        [sys.executable, *argv_tail],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=180,
    )


def _status(**overrides):
    base = dict(
        hashlib_openssl="OpenSSL 3.0.13",
        hashlib_fips=True,
        cryptography_openssl="OpenSSL 3.0.13",
        cryptography_fips=True,
        kernel_fips=None,
    )
    return FipsStatus(**{**base, **overrides})


# --- the probe --------------------------------------------------------------


def test_both_openssls_must_report_fips():
    assert fips_refusal_reason(_status()) is None
    assert _status().active

    reason = fips_refusal_reason(_status(cryptography_fips=False))
    assert "cryptography" in reason and "hashlib" not in reason

    reason = fips_refusal_reason(_status(hashlib_fips=False))
    assert "hashlib" in reason and "cryptography (" not in reason

    assert not _status(hashlib_fips=False, cryptography_fips=False).active


def test_openssl_older_than_3_is_refused(monkeypatch):
    monkeypatch.setattr(fips.ssl, "OPENSSL_VERSION_INFO", (1, 1, 1, 23, 15))
    assert "not OpenSSL 3" in fips_refusal_reason(_status())


def test_status_reports_this_process():
    status = fips_status().as_dict()
    assert set(status) >= {"hashlib_fips", "cryptography_fips", "active", "kernel_fips"}
    assert status["hashlib_openssl"].startswith("OpenSSL")


# --- validate_settings_or_exit ------------------------------------------------


def _settings(monkeypatch, **overrides):
    settings = config_module.get_settings().model_copy(update=overrides)
    monkeypatch.setattr(config_module, "get_settings", lambda: settings)
    return settings


def test_default_mode_never_probes(monkeypatch):
    settings = _settings(monkeypatch, fips_mode=False)
    monkeypatch.setattr(fips, "fips_refusal_reason", lambda *a: pytest.fail("probed"))
    assert config_module.validate_settings_or_exit() is settings


def test_fips_mode_starts_when_provider_active(monkeypatch):
    settings = _settings(monkeypatch, fips_mode=True)
    monkeypatch.setattr(fips, "fips_refusal_reason", lambda *a: None)
    assert config_module.validate_settings_or_exit() is settings


def test_fips_mode_exits_ex_config_when_provider_missing(monkeypatch, capsys):
    _settings(monkeypatch, fips_mode=True)
    monkeypatch.setattr(fips, "fips_refusal_reason", lambda *a: "no provider here")
    with pytest.raises(SystemExit) as exc:
        config_module.validate_settings_or_exit()
    assert exc.value.code == os.EX_CONFIG
    assert (
        "configuration error: FIPS_MODE=true but no provider here"
        in capsys.readouterr().err
    )


# --- real entrypoints, real (non-FIPS) OpenSSL ---------------------------------


@needs_non_fips_host
@pytest.mark.parametrize(
    "argv",
    [["-c", "import services.api.main"], ["-m", "services.worker"]],
    ids=["api", "worker"],
)
def test_entrypoints_refuse_fips_mode_without_provider(argv):
    result = _run(argv, FIPS_MODE="true")

    assert result.returncode == os.EX_CONFIG, result.stderr[-2000:]
    assert result.stderr.count("configuration error: FIPS_MODE=true but") == 1
    assert "FIPS provider is not active" in result.stderr
    assert "Traceback" not in result.stderr


@needs_non_fips_host
def test_bcrypt_with_fips_is_a_configuration_error():
    result = _run(
        ["-c", "from core.config import validate_settings_or_exit as v; v()"],
        FIPS_MODE="true",
        PASSWORD_HASH_SCHEME="bcrypt",
    )
    assert result.returncode == os.EX_CONFIG
    assert "PASSWORD_HASH_SCHEME=bcrypt is not FIPS-approved" in result.stderr


def test_default_mode_validation_passes_in_a_subprocess():
    result = _run(
        [
            "-c",
            "from core.config import validate_settings_or_exit as v; v(); print('ok')",
        ],
        FIPS_MODE="false",
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.strip().endswith("ok")
