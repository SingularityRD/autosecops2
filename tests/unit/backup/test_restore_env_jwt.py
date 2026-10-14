"""The last JWT_SECRET_KEY assignment in a .env is the one restore reads."""

from core.backup.restore import _env_jwt


def test_env_jwt_uses_the_last_assignment(tmp_path):
    path = tmp_path / ".env"
    path.write_text(
        'JWT_SECRET_KEY="first"\nOTHER=1\nJWT_SECRET_KEY=second\n',
        encoding="utf-8",
    )
    assert _env_jwt(path) == "second"

    path.write_text("JWT_SECRET_KEY=first\nJWT_SECRET_KEY=\n", encoding="utf-8")
    assert _env_jwt(path) is None
    assert _env_jwt(tmp_path / "missing") is None


def test_an_env_only_key_is_reported_as_read_from_secrets_after_a_restart(monkeypatch):
    """W0.18 (R29): secrets.enc is read before the environment, so the rotated
    key wins once the services restart; the old message said the opposite."""
    from types import SimpleNamespace

    from core.backup import restore

    monkeypatch.setenv("JWT_SECRET_KEY", "old-env-key")
    monkeypatch.setattr(restore, "_point_at_live", lambda cfg: None)
    monkeypatch.setattr(restore, "_stored_jwt_secret", lambda: None)
    monkeypatch.setattr(restore, "_reencrypt_and_expire", lambda *a: 2)
    written = []
    monkeypatch.setattr(
        restore, "_write_jwt_stores", lambda key, secrets_only: written.append(secrets_only)
    )
    monkeypatch.setattr(
        restore,
        "get_config_service",
        lambda user_id: SimpleNamespace(record_audit=lambda **kw: None),
    )
    lines = restore._settle_restored(
        None, {"created_at": "2026-10-01T00:00:00Z"}, "snap", "restore-bot"
    )
    assert written == [True]
    text = "\n".join(lines)
    assert "restart the services so they read the rotated key from secrets.enc" in text
    assert "replace the old value in the environment so a lost secrets.enc" in text
    assert "outranks" not in text
