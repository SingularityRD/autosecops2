"""Password hashing under FIPS_MODE: PBKDF2 for new hashes, transparent rehash (W3.10)."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import bcrypt
import pytest
from pydantic import ValidationError

from core.auth import passwords
from core.auth.auth_service import AuthService, password_matches_any
from core.config import Settings, get_settings

pytestmark = pytest.mark.unit

# Low iterations keep the suite fast; the floor (100 000) is a Settings rule,
# and these tests bypass Settings validation on purpose via model_copy.
FAST = 1000


def _use(monkeypatch, **overrides):
    overrides.setdefault("password_pbkdf2_iterations", FAST)
    settings = get_settings().model_copy(update=overrides)
    monkeypatch.setattr(passwords, "get_settings", lambda: settings)
    return settings


@pytest.fixture
def default_mode(monkeypatch):
    return _use(monkeypatch, fips_mode=False, password_hash_scheme=None)


@pytest.fixture
def fips_mode(monkeypatch):
    return _use(
        monkeypatch,
        fips_mode=True,
        password_hash_scheme=None,
        fips_legacy_bcrypt_verify=True,
    )


def _bcrypt(plaintext: str) -> str:
    return bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=4)).decode()


# --- scheme selection -------------------------------------------------------


def test_default_mode_still_hashes_with_bcrypt(default_mode):
    hashed = AuthService.hash_password("correct horse battery")
    assert hashed.startswith("$2b$")
    assert AuthService.verify_password("correct horse battery", hashed)
    assert not passwords.needs_rehash(hashed)


def test_fips_mode_hashes_with_pbkdf2_sha256(fips_mode):
    hashed = AuthService.hash_password("correct horse battery")
    scheme, iterations, salt, digest = hashed.split("$")
    assert scheme == "pbkdf2_sha256"
    assert int(iterations) == FAST
    import base64

    assert len(base64.b64decode(salt)) == 16
    assert len(base64.b64decode(digest)) == 32
    assert AuthService.verify_password("correct horse battery", hashed)
    assert not AuthService.verify_password("correct horse batterY", hashed)


def test_pbkdf2_hashes_are_salted(fips_mode):
    assert AuthService.hash_password("same") != AuthService.hash_password("same")


def test_pbkdf2_selectable_without_fips(monkeypatch):
    _use(monkeypatch, fips_mode=False, password_hash_scheme="pbkdf2_sha256")
    assert AuthService.hash_password("x" * 12).startswith("pbkdf2_sha256$")


def test_fips_mode_never_produces_bcrypt(fips_mode):
    with pytest.raises(ValueError):
        passwords.hash_secret("x" * 12, scheme=passwords.BCRYPT)


def test_settings_reject_bcrypt_with_fips():
    with pytest.raises(ValidationError, match="FIPS"):
        Settings(_env_file=None, fips_mode=True, password_hash_scheme="bcrypt")


def test_settings_blank_scheme_is_unset_and_iterations_have_a_floor():
    assert (
        Settings(_env_file=None, password_hash_scheme="").password_hash_scheme is None
    )
    with pytest.raises(ValidationError):
        Settings(_env_file=None, password_pbkdf2_iterations=999)


# --- legacy bcrypt and rehash ---------------------------------------------------


def test_fips_mode_still_verifies_legacy_bcrypt_and_flags_it(fips_mode):
    legacy = _bcrypt("legacy-password-1")
    assert AuthService.verify_password("legacy-password-1", legacy)
    assert passwords.needs_rehash(legacy)


def test_fips_mode_can_refuse_legacy_bcrypt(monkeypatch):
    _use(monkeypatch, fips_mode=True, fips_legacy_bcrypt_verify=False)
    assert not AuthService.verify_password(
        "legacy-password-1", _bcrypt("legacy-password-1")
    )


def test_fewer_iterations_than_configured_needs_rehash(monkeypatch):
    _use(monkeypatch, fips_mode=True, password_pbkdf2_iterations=FAST)
    weak = passwords.hash_secret("pw-123456789")
    _use(monkeypatch, fips_mode=True, password_pbkdf2_iterations=FAST * 2)
    assert passwords.needs_rehash(weak)
    assert passwords.verify_secret("pw-123456789", weak)


@pytest.mark.parametrize(
    "garbage",
    [
        "",
        None,
        "plain",
        "pbkdf2_sha256$",
        "pbkdf2_sha256$x$y$z",
        "pbkdf2_sha256$10$!!$!!",
        "$2b$bad",
    ],
)
def test_malformed_hashes_never_verify_or_raise(fips_mode, garbage):
    assert AuthService.verify_password("anything", garbage) is False
    passwords.needs_rehash(garbage)  # must not raise; login only asks after a match


def _login_user(password_hash):
    return SimpleNamespace(
        user_id="user-1",
        username="ada",
        email="ada@example.com",
        is_active=True,
        locked_until=None,
        service_account=False,
        failed_login_count=0,
        last_login=None,
        login_count=0,
        password_hash=password_hash,
        password_history=["$2b$history"],
        password_changed_at="unchanged",
    )


def _session(user):
    session = MagicMock()
    session.query.return_value.filter.return_value.first.return_value = user
    return session


def test_login_rehashes_legacy_bcrypt_to_pbkdf2_under_fips(fips_mode):
    user = _login_user(_bcrypt("legacy-password-1"))

    assert (
        AuthService.authenticate_user("ada", "legacy-password-1", _session(user))
        is user
    )

    assert user.password_hash.startswith("pbkdf2_sha256$")
    assert AuthService.verify_password("legacy-password-1", user.password_hash)
    # Same password: history and change time are not touched.
    assert user.password_history == ["$2b$history"]
    assert user.password_changed_at == "unchanged"
    # The next login has nothing to migrate.
    assert not passwords.needs_rehash(user.password_hash)


def test_failed_login_does_not_rehash(fips_mode, monkeypatch):
    legacy = _bcrypt("legacy-password-1")
    user = _login_user(legacy)
    monkeypatch.setattr(
        AuthService, "_record_failed_attempt", staticmethod(lambda *a: None)
    )

    assert (
        AuthService.authenticate_user("ada", "wrong-password", _session(user)) is None
    )
    assert user.password_hash == legacy


def test_default_mode_login_leaves_bcrypt_alone(default_mode):
    legacy = _bcrypt("legacy-password-1")
    user = _login_user(legacy)

    assert (
        AuthService.authenticate_user("ada", "legacy-password-1", _session(user))
        is user
    )
    assert user.password_hash == legacy


# --- history and recovery codes ------------------------------------------------


def test_history_matches_across_both_schemes(fips_mode):
    history = [AuthService.hash_password("new-one-123"), _bcrypt("old-one-123")]
    assert password_matches_any("new-one-123", history)
    assert password_matches_any("old-one-123", history)
    assert not password_matches_any("other-123", history)
    assert not password_matches_any("x", [])


def test_recovery_codes_use_the_active_scheme_and_verify(fips_mode):
    codes, hashed = AuthService._generate_recovery_codes()
    assert all(h.startswith("pbkdf2_sha256$") for h in hashed)

    user = SimpleNamespace(
        username="ada", mfa_secret="JBSWY3DPEHPK3PXP", mfa_recovery_codes=list(hashed)
    )
    assert AuthService.verify_mfa_code("user-1", codes[3].lower(), _session(user))
    assert len(user.mfa_recovery_codes) == 9
    # One-time: the same code does not work twice.
    assert not AuthService.verify_mfa_code("user-1", codes[3], _session(user))


def test_legacy_bcrypt_recovery_code_still_works_under_fips(fips_mode):
    user = SimpleNamespace(
        username="ada",
        mfa_secret="JBSWY3DPEHPK3PXP",
        mfa_recovery_codes=[_bcrypt("ABCD1234")],
    )
    assert AuthService.verify_mfa_code("user-1", "abcd1234", _session(user))


# --- Round 3 fixes ---------------------------------------------------------------


@pytest.fixture
def strict_fips(monkeypatch):
    return _use(
        monkeypatch,
        fips_mode=True,
        password_hash_scheme=None,
        fips_legacy_bcrypt_verify=False,
    )


def test_strict_fips_still_honours_legacy_recovery_codes(strict_fips):
    """FIPS_LEGACY_BCRYPT_VERIFY=false must not lock users out of the recovery
    codes they were issued before FIPS_MODE: those cannot be rehashed."""
    user = SimpleNamespace(
        username="ada",
        mfa_secret="JBSWY3DPEHPK3PXP",
        mfa_recovery_codes=[_bcrypt("ABCD1234"), _bcrypt("EEEE0000")],
    )
    assert AuthService.verify_mfa_code("user-1", "abcd1234", _session(user))
    assert len(user.mfa_recovery_codes) == 1


def test_strict_fips_still_blocks_reuse_of_bcrypt_history(strict_fips):
    """Refusing bcrypt history entries would make old passwords reusable."""
    assert password_matches_any("old-one-123", [_bcrypt("old-one-123")])
    # ...while the login password itself is refused as before.
    assert not AuthService.verify_password("old-one-123", _bcrypt("old-one-123"))


def _pbkdf2_with(iterations: int) -> str:
    salt = passwords._b64(b"s" * 16)
    return f"pbkdf2_sha256${iterations}${salt}${passwords._b64(b'd' * 32)}"


@pytest.mark.parametrize("iterations", [10_000_001, 2_000_000_000, 10**30])
def test_absurd_stored_iteration_counts_are_refused_without_hashing(
    fips_mode, monkeypatch, iterations
):
    called = MagicMock(side_effect=AssertionError("PBKDF2 must not run"))
    monkeypatch.setattr(passwords, "_pbkdf2", called)
    stored = _pbkdf2_with(iterations)
    assert not passwords.verify_secret("anything", stored)
    assert not passwords.needs_rehash(stored)
    called.assert_not_called()


def test_iteration_cap_is_inclusive(fips_mode):
    assert passwords._parse_pbkdf2(_pbkdf2_with(passwords.MAX_PBKDF2_ITERATIONS))[
        0
    ] == (passwords.MAX_PBKDF2_ITERATIONS)


def test_settings_cap_configured_iterations():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, password_pbkdf2_iterations=10_000_001)
    assert (
        Settings(
            _env_file=None, password_pbkdf2_iterations=10_000_000
        ).password_pbkdf2_iterations
        == passwords.MAX_PBKDF2_ITERATIONS
    )
