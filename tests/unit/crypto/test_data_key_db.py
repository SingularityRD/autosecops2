"""The data key against a real Postgres: the database secret store and the rekey.

Runs in the throwaway database tests/unit/conftest.py provisions for
``external_service`` tests. ``platform_secrets`` is SQL-only, so it is built from
its init file, as Compose's db-seed and Helm's db-init Job build it.
"""

from __future__ import annotations

import os
from pathlib import Path

import pyotp
import pytest
from sqlalchemy import text

import core.auth.auth_service as auth_service
from core.auth.auth_service import MFA_DATA_KEY_PREFIX, AuthService
from core.crypto import data_key, rekey
from core.secrets_manager import DatabaseBackend
from core.storage.connection import get_db_manager

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

REPO = Path(__file__).resolve().parents[3]
INIT_SQL = REPO / "infra" / "database" / "init" / "63_platform_secrets.sql"
TOTP = "JBSWY3DPEHPK3PXP"
KEY_NEW = "data-key-new-for-the-db-tests-00000001"
KEY_OLD = "data-key-old-for-the-db-tests-00000002"


def _exec(statement: str, params: dict | None = None):
    with get_db_manager().engine.begin() as conn:
        return conn.execute(text(statement), params or {})


def _rows(statement: str, params: dict | None = None) -> list[tuple]:
    with get_db_manager().engine.connect() as conn:
        return [tuple(r) for r in conn.execute(text(statement), params or {})]


@pytest.fixture(autouse=True)
def schema(monkeypatch):
    with get_db_manager().engine.begin() as conn:
        conn.exec_driver_sql(INIT_SQL.read_text(encoding="utf-8"))
        conn.exec_driver_sql(INIT_SQL.read_text(encoding="utf-8"))  # rerunnable
        conn.execute(text("DELETE FROM platform_secrets"))
        conn.execute(text("DELETE FROM users WHERE user_id LIKE 'dk-%'"))
        conn.execute(text("DELETE FROM config_audit_log WHERE config_type = 'secrets'"))
        conn.execute(
            text(
                "INSERT INTO roles (role_id, name, description, permissions, "
                "is_system_role) VALUES ('role-dk', 'DK', 'dk', '{}', false) "
                "ON CONFLICT DO NOTHING"
            )
        )
    monkeypatch.setenv("VIGIL_DATA_KEY", KEY_NEW)
    monkeypatch.setenv("SECRETS_BACKEND", "database")
    monkeypatch.setattr(auth_service, "_last_undecryptable_log", float("-inf"))


def _user(user_id: str, mfa_secret: str | None) -> None:
    _exec(
        "INSERT INTO users (user_id, username, email, password_hash, full_name, "
        "role_id, is_active, is_verified, mfa_enabled, mfa_secret, "
        "mfa_recovery_codes, login_count) VALUES (:id, :id, :email, 'x', 'x', "
        "'role-dk', true, true, true, :mfa, '[]', 0)",
        {"id": user_id, "email": f"{user_id}@example.test", "mfa": mfa_secret},
    )


def _mfa(user_id: str) -> str:
    return _rows("SELECT mfa_secret FROM users WHERE user_id = :id", {"id": user_id})[
        0
    ][0]


def _under(key: str, plaintext: bytes) -> str:
    return data_key.KeyRing((data_key.derive(key),), "env").encrypt(plaintext)


# -- database secret store -----------------------------------------------------


def test_store_round_trip_keeps_only_ciphertext_in_the_row():
    backend = DatabaseBackend(cache_seconds=0)

    assert backend.set("SPLUNK_PASSWORD", "hunter2-plaintext") is True
    assert backend.get("SPLUNK_PASSWORD") == "hunter2-plaintext"
    [(name, ciphertext)] = _rows("SELECT name, ciphertext FROM platform_secrets")
    assert name == "SPLUNK_PASSWORD"
    assert "hunter2" not in ciphertext
    assert data_key.current().decrypt(ciphertext) == b"hunter2-plaintext"

    assert backend.set("SPLUNK_PASSWORD", "second") is True
    assert backend.get("SPLUNK_PASSWORD") == "second"
    assert backend.set("SPLUNK_PASSWORD", "") is True  # empty clears, like delete
    assert backend.get("SPLUNK_PASSWORD") is None
    assert _rows("SELECT count(*) FROM platform_secrets") == [(0,)]


def test_store_sees_another_writer_after_its_cache_window():
    reader = DatabaseBackend(cache_seconds=3600)
    assert reader.get("OIDC_CLIENT_SECRET_CORP") is None
    DatabaseBackend().set("OIDC_CLIENT_SECRET_CORP", "from-the-other-replica")

    assert reader.get("OIDC_CLIENT_SECRET_CORP") is None  # cached miss
    reader._invalidate()  # what the cache window's expiry does
    assert reader.get("OIDC_CLIENT_SECRET_CORP") == "from-the-other-replica"


def test_row_under_an_unknown_key_reads_as_unset(caplog):
    _exec(
        "INSERT INTO platform_secrets (name, ciphertext) VALUES ('X_TOKEN', :t)",
        {"t": _under(KEY_OLD, b"lost")},
    )
    backend = DatabaseBackend(cache_seconds=0)

    assert backend.get("X_TOKEN") is None
    assert "cannot be decrypted with the current data key" in caplog.text
    assert "lost" not in caplog.text


def test_missing_table_reads_as_empty_and_save_fails():
    _exec("DROP TABLE platform_secrets")
    backend = DatabaseBackend(cache_seconds=0)

    assert backend.get("SPLUNK_PASSWORD") is None
    assert backend.set("SPLUNK_PASSWORD", "x") is False


# -- rekey ------------------------------------------------------------------------


def test_rekey_moves_every_kind_of_row_once_and_jwt_rotation_keeps_mfa(monkeypatch):
    jwt_key = auth_service.JWT_SECRET_KEY
    legacy = AuthService._legacy_fernet(jwt_key).encrypt(TOTP.encode()).decode()
    _user("dk-legacy", legacy)
    _user("dk-plain", TOTP)
    _user("dk-current", AuthService._encrypt_mfa_secret(TOTP))
    _user("dk-oldkey", MFA_DATA_KEY_PREFIX + _under(KEY_OLD, TOTP.encode()))
    other_jwt = AuthService._legacy_fernet("a-jwt-key-nobody-has").encrypt(b"Z")
    _user("dk-lost", other_jwt.decode())
    _user("dk-none", None)
    _exec(
        "INSERT INTO platform_secrets (name, ciphertext) VALUES ('A', :a), ('B', :b)",
        {"a": _under(KEY_OLD, b"va"), "b": _under(KEY_NEW, b"vb")},
    )

    # The old key is still in the ring, second: the rotation phase.
    monkeypatch.setenv("VIGIL_DATA_KEY", f"{KEY_NEW},{KEY_OLD}")
    status = rekey.run(actor="t", dry_run=True)
    assert status["pending"] == 4
    assert _mfa("dk-legacy") == legacy  # status writes nothing

    report = rekey.run(actor="tester")
    assert report["mfa"] == {
        "legacy": 2,
        "rotated": 1,
        "current": 1,
        "undecryptable": ["dk-lost"],
    }
    assert report["platform_secrets"] == {
        "rotated": 1,
        "current": 1,
        "undecryptable": [],
    }
    for user_id in ("dk-legacy", "dk-plain", "dk-current", "dk-oldkey"):
        assert _mfa(user_id).startswith(MFA_DATA_KEY_PREFIX)
    assert _mfa("dk-lost") == other_jwt.decode()  # left for its recovery codes

    audit = _rows(
        "SELECT changed_by, action FROM config_audit_log WHERE config_type = 'secrets'"
    )
    assert audit == [("tester", "rekey")]
    again = rekey.run(actor="tester")
    assert again["mfa"]["legacy"] == again["mfa"]["rotated"] == 0
    assert again["platform_secrets"]["rotated"] == 0
    assert (
        len(_rows("SELECT 1 FROM config_audit_log WHERE config_type = 'secrets'")) == 1
    )

    # The old data key can go, and the JWT key can rotate: MFA keeps working.
    monkeypatch.setenv("VIGIL_DATA_KEY", KEY_NEW)
    code = pyotp.TOTP(TOTP).now()
    for user_id in ("dk-legacy", "dk-plain", "dk-oldkey"):
        assert pyotp.TOTP(AuthService._decrypt_mfa_secret(_mfa(user_id))).verify(code)
    assert AuthService._decrypt_mfa_secret(_mfa("dk-legacy"), jwt_secret="rotated")
    assert DatabaseBackend(cache_seconds=0).get("A") == "va"


def test_startup_rekey_is_off_when_the_setting_says_so(monkeypatch):
    legacy = AuthService._legacy_fernet().encrypt(TOTP.encode()).decode()
    _user("dk-legacy", legacy)
    monkeypatch.setattr(
        "core.config.get_settings",
        lambda: type("S", (), {"data_key_rekey_on_start": False})(),
    )
    assert rekey.startup_rekey() is None
    assert _mfa("dk-legacy") == legacy

    monkeypatch.setattr(
        "core.config.get_settings",
        lambda: type("S", (), {"data_key_rekey_on_start": True})(),
    )
    report = rekey.startup_rekey()
    assert report["mfa"]["legacy"] == 1
    assert _mfa("dk-legacy").startswith(MFA_DATA_KEY_PREFIX)


def test_startup_rekey_without_a_key_changes_nothing(monkeypatch):
    legacy = AuthService._legacy_fernet().encrypt(TOTP.encode()).decode()
    _user("dk-legacy", legacy)
    monkeypatch.delenv("VIGIL_DATA_KEY")
    monkeypatch.setattr(
        "core.config.get_settings",
        lambda: type("S", (), {"data_key_rekey_on_start": True, "dev_mode": False})(),
    )

    assert rekey.startup_rekey() is None
    assert _mfa("dk-legacy") == legacy


# -- master.key rotation (Compose / single host) ---------------------------------


@pytest.fixture
def file_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_DIR", str(tmp_path / "state"))
    monkeypatch.delenv("VIGIL_DATA_KEY")
    monkeypatch.delenv("SECRETS_BACKEND")
    return tmp_path / "state"


def test_rotate_master_key_reencrypts_secrets_enc_and_mfa(file_mode):
    from cryptography.fernet import Fernet, InvalidToken

    from core.secrets_manager import EncryptedFileBackend

    store = EncryptedFileBackend()
    assert store.set("SPLUNK_PASSWORD", "kept-across-rotation")
    _user("dk-file", AuthService._encrypt_mfa_secret(TOTP))
    old_key = (file_mode / "master.key").read_bytes()

    report = rekey.rotate_master_key(actor="ops")

    new_key = (file_mode / "master.key").read_bytes()
    assert new_key != old_key
    assert report["master_key_rotated"] and report["secrets_enc_reencrypted"]
    assert report["mfa"]["rotated"] == 1
    assert EncryptedFileBackend().get("SPLUNK_PASSWORD") == "kept-across-rotation"
    with pytest.raises(InvalidToken):
        Fernet(old_key).decrypt((file_mode / "secrets.enc").read_bytes())
    assert AuthService._decrypt_mfa_secret(_mfa("dk-file")) == TOTP
    assert sorted(p.name for p in file_mode.iterdir()) == ["master.key", "secrets.enc"]
    assert _rows(
        "SELECT action FROM config_audit_log WHERE config_type = 'secrets'"
    ) == [("rotate_master_key",)]


def test_rotate_master_key_refuses_a_mismatched_secrets_enc(file_mode):
    from cryptography.fernet import Fernet

    from core.secrets_manager import EncryptedFileBackend

    assert EncryptedFileBackend().set("A", "b")
    (file_mode / "master.key").write_bytes(Fernet.generate_key())
    before = (file_mode / "secrets.enc").read_bytes()

    with pytest.raises(rekey.RekeyError, match="not encrypted under"):
        rekey.rotate_master_key(actor="ops")
    assert (file_mode / "secrets.enc").read_bytes() == before


def test_rotate_master_key_is_refused_for_the_database_store(monkeypatch):
    monkeypatch.setenv("SECRETS_BACKEND", "database")
    with pytest.raises(rekey.RekeyError, match="VIGIL_DATA_KEY"):
        rekey.rotate_master_key(actor="ops")


# -- callers of the store ----------------------------------------------------------


@pytest.fixture
def database_manager(monkeypatch):
    from core import secrets_manager

    monkeypatch.setattr(secrets_manager, "_secrets_manager", None)
    manager = secrets_manager.get_secrets_manager()
    assert manager.write_backend is manager.database_backend
    yield manager
    secrets_manager._secrets_manager = None


def test_oidc_secret_saved_in_the_database_is_not_the_deployments(
    database_manager, monkeypatch
):
    """The save mirrors the value into os.environ; that copy must still read as
    the application's, or the provider's secret could never be cleared."""
    from core.auth import oidc_router

    key = "OIDC_CLIENT_SECRET_DBSTORE"
    monkeypatch.setenv(key, "placeholder")
    monkeypatch.delenv(key)  # recorded, so teardown removes the mirror
    assert database_manager.set(key, "entered-in-the-console")
    assert os.environ[key] == "entered-in-the-console"

    assert oidc_router._secret_from_environment(key) is False
    monkeypatch.setenv(key, "a-different-deployment-value")
    assert oidc_router._secret_from_environment(key) is True


def test_platform_database_settings_are_refused_with_the_database_store(
    database_manager,
):
    from fastapi import HTTPException

    from services.api.routers import config

    with pytest.raises(HTTPException) as refused:
        config._refuse_database_store_bootstrap()
    assert refused.value.status_code == 409
    assert "deployment" in refused.value.detail
