"""MFA behaviour when a key no longer matches the one that encrypted the secret.

A secret set up now is under the data key (``dk:``, core/crypto/data_key.py) and
does not depend on JWT_SECRET_KEY, so rotating the JWT key leaves MFA working
(PY-35). A row from before the data key is a bare token under the JWT-derived
key until the start-up rekey moves it; such a row still breaks if the JWT key
changes first, and so does any row whose data key is gone.
"""

import logging
import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import bcrypt
import pyotp
import pytest

import core.auth.auth_service as auth_service
from core.auth.auth_service import AuthService

TOTP_SECRET = "JBSWY3DPEHPK3PXP"
RECOVERY_CODE = "ABCD1234"


def _session(user):
    session = MagicMock()
    session.query.return_value.filter.return_value.first.return_value = user
    return session


def _user(mfa_secret):
    hashed = bcrypt.hashpw(RECOVERY_CODE.encode(), bcrypt.gensalt()).decode()
    return SimpleNamespace(
        username="ada",
        email="ada@example.com",
        mfa_secret=mfa_secret,
        mfa_enabled=True,
        mfa_recovery_codes=[hashed],
    )


@pytest.fixture(autouse=True)
def _reset_log_throttle(monkeypatch):
    monkeypatch.setattr(auth_service, "_last_undecryptable_log", float("-inf"))


def _legacy_token(jwt_secret: str) -> str:
    """How a secret was stored before the data key: Fernet under the JWT key."""
    return AuthService._legacy_fernet(jwt_secret).encrypt(TOTP_SECRET.encode()).decode()


@pytest.fixture
def rekeyed_user(monkeypatch):
    """A pre-data-key secret, and the JWT key changed before the rekey moved it."""
    user = _user(_legacy_token("old-key"))
    monkeypatch.setattr(auth_service, "JWT_SECRET_KEY", "new-key")
    return user


def test_undecryptable_secret_is_reported_not_treated_as_plaintext(
    rekeyed_user, caplog
):
    with caplog.at_level(logging.ERROR, logger=auth_service.logger.name):
        assert (
            AuthService.verify_mfa_code("u", "123456", _session(rekeyed_user)) is False
        )

    assert "cannot be decrypted with the current JWT_SECRET_KEY" in caplog.text
    assert "binascii" not in caplog.text
    assert "verify_mfa_code failed" not in caplog.text
    assert rekeyed_user.mfa_secret not in caplog.text


def test_undecryptable_secret_logs_once_per_interval(rekeyed_user, caplog):
    with caplog.at_level(logging.ERROR, logger=auth_service.logger.name):
        for _ in range(5):
            AuthService.verify_mfa_code("u", "123456", _session(rekeyed_user))

    assert caplog.text.count("cannot be decrypted") == 1


def test_enable_mfa_and_qr_uri_fail_cleanly_on_undecryptable_secret(
    rekeyed_user, caplog
):
    session = _session(rekeyed_user)
    with caplog.at_level(logging.ERROR, logger=auth_service.logger.name):
        assert AuthService.enable_mfa("u", "123456", session) is None
        assert AuthService.get_mfa_qr_uri("u", session) is None

    assert "cannot be decrypted with the current JWT_SECRET_KEY" in caplog.text
    assert "enable_mfa failed" not in caplog.text


def test_recovery_code_still_works_after_key_change_and_is_consumed(rekeyed_user):
    session = _session(rekeyed_user)

    assert AuthService.verify_mfa_code("u", "WRONG000", session) is False
    assert len(rekeyed_user.mfa_recovery_codes) == 1

    assert AuthService.verify_mfa_code("u", RECOVERY_CODE.lower(), session) is True
    assert rekeyed_user.mfa_recovery_codes == []
    assert AuthService.verify_mfa_code("u", RECOVERY_CODE, session) is False


def test_legacy_plaintext_secret_still_verifies():
    user = _user(TOTP_SECRET)
    code = pyotp.TOTP(TOTP_SECRET).now()

    assert AuthService.verify_mfa_code("u", code, _session(user)) is True
    assert AuthService.get_mfa_qr_uri("u", _session(user)).startswith("otpauth://")


def test_encrypted_secret_round_trips_under_the_same_key():
    user = _user(AuthService._encrypt_mfa_secret(TOTP_SECRET))
    code = pyotp.TOTP(TOTP_SECRET).now()

    assert AuthService.verify_mfa_code("u", code, _session(user)) is True


def test_new_secret_is_under_the_data_key_not_the_jwt_key():
    stored = AuthService._encrypt_mfa_secret(TOTP_SECRET)

    assert stored.startswith(auth_service.MFA_DATA_KEY_PREFIX)
    with pytest.raises(Exception):
        AuthService._legacy_fernet().decrypt(stored.encode())


def test_rotating_the_jwt_key_keeps_mfa_working(monkeypatch):
    """PY-35: rotating JWT_SECRET_KEY used to lock out every MFA user."""
    monkeypatch.setattr(auth_service, "JWT_SECRET_KEY", "key-before-rotation")
    user = _user(AuthService._encrypt_mfa_secret(TOTP_SECRET))
    monkeypatch.setattr(auth_service, "JWT_SECRET_KEY", "key-after-rotation")
    code = pyotp.TOTP(TOTP_SECRET).now()

    assert AuthService.verify_mfa_code("u", code, _session(user)) is True
    assert AuthService.get_mfa_qr_uri("u", _session(user)).startswith("otpauth://")


def test_legacy_secret_under_the_running_jwt_key_still_verifies():
    user = _user(_legacy_token(auth_service.JWT_SECRET_KEY))
    code = pyotp.TOTP(TOTP_SECRET).now()

    assert AuthService.verify_mfa_code("u", code, _session(user)) is True


def test_secret_under_a_lost_data_key_is_reported(monkeypatch, caplog):
    user = _user(AuthService._encrypt_mfa_secret(TOTP_SECRET))
    monkeypatch.setenv("VIGIL_DATA_KEY", "a-different-data-key-that-was-never-used")
    code = pyotp.TOTP(TOTP_SECRET).now()

    with caplog.at_level(logging.ERROR, logger=auth_service.logger.name):
        assert AuthService.verify_mfa_code("u", code, _session(user)) is False
    assert "cannot be decrypted with the current data key" in caplog.text
    assert user.mfa_secret not in caplog.text


def test_previous_data_key_still_decrypts_during_rotation(monkeypatch):
    user = _user(AuthService._encrypt_mfa_secret(TOTP_SECRET))
    old = os.environ["VIGIL_DATA_KEY"]
    monkeypatch.setenv("VIGIL_DATA_KEY", "the-new-data-key-for-this-rotation-x," + old)
    code = pyotp.TOTP(TOTP_SECRET).now()

    assert AuthService.verify_mfa_code("u", code, _session(user)) is True
