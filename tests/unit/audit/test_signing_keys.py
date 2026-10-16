"""Install-time signing keys (W0.36, U-13): provision, export, health warning.

Each test gets an empty encrypted secrets store of its own (``VIGIL_DIR`` in a
temp directory, a fresh ``SecretsManager``), as a fresh Compose volume is.
"""

from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-not-for-prod")

from core import secrets_manager  # noqa: E402
from core.audit import signing_keys  # noqa: E402
from core.audit.checkpoint import (  # noqa: E402
    load_private_key,
    signing_key_from_secrets,
)
from core.compliance import verify_bundle  # noqa: E402
from core.compliance.evidence_bundle import load_signing_key  # noqa: E402

pytestmark = pytest.mark.unit

SECRETS = ("AUDIT_CHECKPOINT_SIGNING_KEY", "EVIDENCE_PACK_SIGNING_KEY")


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("VIGIL_DISABLE_DOTENV", "1")
    for name in SECRETS:
        monkeypatch.delenv(name, raising=False)
    manager = secrets_manager.SecretsManager(write_backend="encrypted")
    monkeypatch.setattr(secrets_manager, "_secrets_manager", manager)
    signing_keys._health_cache.clear()
    yield tmp_path / "state"
    signing_keys._health_cache.clear()
    for name in SECRETS:
        os.environ.pop(name, None)  # set_secret mirrors into os.environ


def _seed(name: str) -> str:
    return secrets_manager.get_secrets_manager().encrypted_backend.get(name)


def test_provision_creates_both_keys_in_the_encrypted_store(store, capsys):
    assert signing_keys.main(["provision"]) == 0
    out = capsys.readouterr()
    assert (store / "secrets.enc").is_file()
    for name in SECRETS:
        seed = _seed(name)
        assert seed, name
        # Never printed or logged: only the public half and the key id.
        assert seed not in out.out and seed not in out.err
        assert f"{name}: generated" in out.out
    assert signing_key_from_secrets() is not None
    _key, source = load_signing_key()
    assert source == "configured"


def test_provision_never_replaces_a_key(store, capsys):
    signing_keys.main(["provision"])
    first = {name: _seed(name) for name in SECRETS}
    capsys.readouterr()
    assert signing_keys.main(["provision"]) == 0
    assert {name: _seed(name) for name in SECRETS} == first
    assert "present" in capsys.readouterr().out


def test_an_unusable_key_is_reported_not_overwritten(store, capsys):
    secrets_manager.get_secrets_manager().set("EVIDENCE_PACK_SIGNING_KEY", "not-a-key")
    assert signing_keys.main(["provision"]) == 1
    assert _seed("EVIDENCE_PACK_SIGNING_KEY") == "not-a-key"
    assert "UNUSABLE" in capsys.readouterr().out
    # The other key is still created.
    assert _seed("AUDIT_CHECKPOINT_SIGNING_KEY")
    assert signing_keys.main(["provision", "--warn-only"]) == 0


def test_a_process_only_store_is_refused(store, monkeypatch, capsys):
    monkeypatch.setattr(
        secrets_manager,
        "_secrets_manager",
        secrets_manager.SecretsManager(write_backend="env"),
    )
    assert signing_keys.main(["provision"]) == 1
    assert "SECRETS_BACKEND=env" in capsys.readouterr().err
    assert signing_keys.main(["provision", "--warn-only"]) == 0


def test_export_gives_public_keys_the_verifiers_accept(store, capsys):
    signing_keys.main(["provision"])
    capsys.readouterr()
    assert signing_keys.main(["export"]) == 0
    env = dict(
        line.split("=", 1) for line in capsys.readouterr().out.strip().splitlines()
    )
    assert set(env) == {"AUDIT_CHECKPOINT_PUBLIC_KEY", "EVIDENCE_PACK_PUBLIC_KEY"}
    evidence_private = load_private_key(_seed("EVIDENCE_PACK_SIGNING_KEY"))
    assert verify_bundle.parse_public_key(env["EVIDENCE_PACK_PUBLIC_KEY"]) == (
        evidence_private.public_key().public_bytes_raw()
    )

    assert (
        signing_keys.main(["export", "--format", "pem", "--purpose", "evidence_packs"])
        == 0
    )
    pem = capsys.readouterr().out
    assert pem.count("BEGIN PUBLIC KEY") == 1
    assert verify_bundle.parse_public_key(pem.split("\n", 1)[1]).hex() == (
        env["EVIDENCE_PACK_PUBLIC_KEY"]
    )

    assert signing_keys.main(["export", "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["algorithm"] == "ed25519"
    assert "PRIVATE" not in json.dumps(doc)


def test_status_never_carries_a_private_part(store, capsys):
    signing_keys.main(["provision"])
    capsys.readouterr()
    assert signing_keys.main(["status", "--json"]) == 0
    text = capsys.readouterr().out
    for name in SECRETS:
        assert _seed(name) not in text


def test_health_warns_until_both_keys_exist(store, monkeypatch):
    monkeypatch.setattr(signing_keys, "_recent_checkpoint", lambda interval: False)
    before = signing_keys.signing_health(use_cache=False)
    assert before == {
        "audit_checkpoints": False,
        "evidence_packs": False,
        "warnings": [signing_keys.WARN_CHECKPOINTS, signing_keys.WARN_EVIDENCE],
    }
    signing_keys.provision()
    after = signing_keys.signing_health(use_cache=False)
    assert after == {"audit_checkpoints": True, "evidence_packs": True, "warnings": []}


def test_health_counts_a_recent_checkpoint_when_the_key_is_elsewhere(
    store, monkeypatch
):
    """Helm: only the daemon holds the checkpoint key."""
    monkeypatch.setattr(signing_keys, "_recent_checkpoint", lambda interval: True)
    assert signing_keys.signing_health(use_cache=False)["audit_checkpoints"] is True


def test_health_warns_when_the_checkpoint_job_is_off(store, monkeypatch):
    from core.config import get_settings

    signing_keys.provision()
    monkeypatch.setattr(get_settings(), "audit_checkpoint_interval_seconds", 0)
    health = signing_keys.signing_health(use_cache=False)
    assert health["warnings"] == [signing_keys.WARN_CHECKPOINTS]


def test_api_health_and_readiness_carry_the_warning_but_stay_up(store, monkeypatch):
    from services.api import main as backend_main

    monkeypatch.setattr(signing_keys, "_recent_checkpoint", lambda interval: False)
    http = TestClient(backend_main.app)
    for path in ("/api/health", "/api/health/ready"):
        body = http.get(path).json()
        assert body["signing"] == {"audit_checkpoints": False, "evidence_packs": False}
        assert signing_keys.WARN_EVIDENCE in body["warnings"]
    # A missing key alone never makes the pod unready.
    signing_keys._health_cache.clear()
    signing_keys.provision()
    signing_keys._health_cache.clear()
    body = http.get("/api/health").json()
    assert body["signing"] == {"audit_checkpoints": True, "evidence_packs": True}
    assert body["warnings"] == []


def test_the_public_keys_route_needs_settings_read(store, monkeypatch):
    from core.storage.models import User
    from services.api import main as backend_main
    from services.api.middleware import auth as auth_module

    signing_keys.provision()
    user = User(
        user_id="u-1",
        username="aud",
        email="a@t.local",
        password_hash="",
        role_id="role-viewer",
        is_active=True,
        mfa_enabled=False,
    )
    granted = {"perms": set()}
    monkeypatch.setattr(
        "core.auth.auth_service.AuthService.check_permission",
        lambda user_id, perm, session=None: perm in granted["perms"],
    )
    monkeypatch.setattr(
        "core.audit.signing_keys_router._latest_checkpoint_key", lambda: None
    )
    app = backend_main.app
    app.dependency_overrides[auth_module.get_current_active_user] = lambda: user
    app.dependency_overrides[auth_module.get_current_user] = lambda: user
    try:
        http = TestClient(app)
        assert http.get("/api/audit/signing-keys").status_code == 403
        granted["perms"] = {"settings.read"}
        response = http.get("/api/audit/signing-keys")
        assert response.status_code == 200, response.text
        keys = {k["purpose"]: k for k in response.json()["keys"]}
        for name in SECRETS:
            assert _seed(name) not in response.text
        evidence = keys["evidence_packs"]
        assert evidence["source"] == "secret" and evidence["algorithm"] == "ed25519"
        assert "BEGIN PUBLIC KEY" in evidence["public_key_pem"]
        assert keys["audit_checkpoints"]["configured"] is True
    finally:
        app.dependency_overrides.pop(auth_module.get_current_active_user, None)
        app.dependency_overrides.pop(auth_module.get_current_user, None)
