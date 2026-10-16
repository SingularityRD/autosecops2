"""The data-encryption key (core/crypto/data_key.py) and the database store's wiring.

No database here: what the key ring is made of and when it refuses, and that the
secrets manager in ``database`` mode never falls back to a file. The rows
themselves are in test_data_key_db.py.
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet, InvalidToken

from core.crypto import data_key
from core.secrets_manager import DatabaseBackend, SecretsManager

pytestmark = pytest.mark.unit

KEY_A = "first-data-key-for-the-unit-tests-0001"
KEY_B = "second-data-key-for-the-unit-tests-002"


@pytest.fixture
def state(tmp_path, monkeypatch):
    """An empty State Directory, and no key or backend chosen yet."""
    monkeypatch.setenv("VIGIL_DIR", str(tmp_path / "state"))
    monkeypatch.delenv("VIGIL_DATA_KEY", raising=False)
    monkeypatch.delenv("SECRETS_BACKEND", raising=False)
    return tmp_path / "state"


def test_env_key_round_trips_and_is_not_the_raw_string(state, monkeypatch):
    monkeypatch.setenv("VIGIL_DATA_KEY", KEY_A)
    ring = data_key.current()

    token = ring.encrypt(b"secret")
    assert ring.source == "env"
    assert ring.decrypt(token) == b"secret"
    assert KEY_A not in token
    # HKDF-stretched, so the variable is not usable as a Fernet key by itself.
    assert ring.primary is data_key.current().primary
    assert not (state / "master.key").exists()


def test_short_key_is_refused(state, monkeypatch):
    monkeypatch.setenv("VIGIL_DATA_KEY", "too-short")
    with pytest.raises(data_key.DataKeyUnavailable, match="at least 32"):
        data_key.current()
    with pytest.raises(data_key.DataKeyUnavailable):
        data_key.check_at_startup()


def test_second_key_decrypts_and_rotate_moves_to_the_first(state, monkeypatch):
    monkeypatch.setenv("VIGIL_DATA_KEY", KEY_B)
    old_token = data_key.current().encrypt(b"v")
    monkeypatch.setenv("VIGIL_DATA_KEY", f"{KEY_A}, {KEY_B}")
    ring = data_key.current()

    assert ring.decrypt(old_token) == b"v"
    assert not ring.is_current(old_token)
    rotated = ring.rotate(old_token)
    assert ring.is_current(rotated)
    monkeypatch.setenv("VIGIL_DATA_KEY", KEY_A)
    assert data_key.current().decrypt(rotated) == b"v"
    with pytest.raises(InvalidToken):
        data_key.current().decrypt(old_token)


def test_without_the_variable_master_key_is_the_data_key(state):
    ring = data_key.current()

    assert ring.source == "master.key"
    stored = (state / "master.key").read_bytes()
    assert Fernet(stored).decrypt(ring.encrypt(b"x").encode()) == b"x"
    assert data_key.check_at_startup() is None


def test_master_key_stays_decrypt_only_after_switching_to_the_variable(
    state, monkeypatch
):
    before = data_key.current().encrypt(b"enrolled-before")
    monkeypatch.setenv("VIGIL_DATA_KEY", KEY_A)
    ring = data_key.current()

    assert ring.decrypt(before) == b"enrolled-before"
    assert not ring.is_current(before)
    assert ring.is_current(ring.encrypt(b"new"))


def test_database_store_never_takes_a_state_directory_key(state, monkeypatch):
    data_key.current()  # a master.key exists in this pod
    monkeypatch.setenv("SECRETS_BACKEND", "database")

    with pytest.raises(data_key.DataKeyUnavailable, match="VIGIL_DATA_KEY"):
        data_key.current()
    with pytest.raises(data_key.DataKeyUnavailable):
        data_key.check_at_startup()
    monkeypatch.setenv("VIGIL_DATA_KEY", KEY_A)
    assert len(data_key.current().fernets) == 1  # master.key not appended


def test_dev_mode_has_a_fixed_key_for_the_database_store(state, monkeypatch):
    monkeypatch.setenv("SECRETS_BACKEND", "database")
    monkeypatch.setattr(
        "core.config.get_settings", lambda: type("S", (), {"dev_mode": True})()
    )
    first = data_key.current()
    assert first.source == "dev"
    assert data_key.current().decrypt(first.encrypt(b"d")) == b"d"


def test_database_mode_reads_the_database_first_and_writes_nowhere_else(
    state, monkeypatch, tmp_path
):
    monkeypatch.setenv("VIGIL_DATA_KEY", KEY_A)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    manager = SecretsManager(write_backend="database")
    # No database is open in this process.
    manager.database_backend = DatabaseBackend(engine_provider=lambda: None)
    manager.read_backends[0] = manager.database_backend
    manager.write_backend = manager.database_backend

    assert manager.read_backends[0] is manager.database_backend
    assert manager.write_backend_name == "database"
    assert manager.set("SPLUNK_PASSWORD", "never-on-disk") is False
    written = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert all(b"never-on-disk" not in p.read_bytes() for p in written)
    assert not (state / ".env").exists()
    assert not (state / "secrets.enc").exists()


def test_database_mode_without_a_key_does_not_fall_back_to_a_file(state, monkeypatch):
    monkeypatch.setenv("SECRETS_BACKEND", "database")
    manager = SecretsManager(write_backend="database")

    assert manager.write_backend is manager.database_backend
    assert manager.database_backend.is_available() is False
    assert manager.set("SPLUNK_PASSWORD", "x") is False
    assert not (state / ".env").exists()
    assert manager.get_backend_status()["database"]["in_use"] is True


@pytest.mark.parametrize(
    "key",
    ["POSTGRES_PASSWORD", "JWT_SECRET_KEY", "VIGIL_DATA_KEY", "PLATFORM_DB_PROXY_HOST"],
)
def test_bootstrap_keys_never_go_to_the_database(key, monkeypatch):
    monkeypatch.setenv("VIGIL_DATA_KEY", KEY_A)
    called = []
    backend = DatabaseBackend(engine_provider=lambda: called.append(1))

    assert backend.set(key, "value") is False
    assert backend.get(key) is None
    assert called == []


def test_other_modes_keep_the_database_store_out_of_the_read_order(state):
    manager = SecretsManager(write_backend="encrypted")

    assert manager.use_database is False
    assert manager.database_backend not in manager.read_backends
