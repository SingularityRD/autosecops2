"""
Unit tests for core.auth.password_reset.

Redis-backed single-use enforcement is mocked so tests run without a live
cache. The signature + expiry logic is pure itsdangerous and runs as-is.
"""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from core.auth import password_reset


@pytest.fixture(autouse=True)
def _mock_redis(monkeypatch):
    """Default every test to a mock Redis that records SET NX as success.
    Individual tests override as needed."""
    client = AsyncMock()
    client.set = AsyncMock(return_value=True)
    monkeypatch.setattr(password_reset, "_redis_client", lambda: client)
    return client


class TestPasswordReset:
    def test_token_roundtrip_returns_user_id(self):
        token = password_reset.generate_reset_token("user-abc")
        user_id = asyncio.run(password_reset.verify_reset_token(token))
        assert user_id == "user-abc"

    def test_tampered_token_is_rejected(self):
        token = password_reset.generate_reset_token("user-abc")
        tampered = token[:-2] + ("A" if token[-1] != "A" else "B") + "="
        user_id = asyncio.run(password_reset.verify_reset_token(tampered))
        assert user_id is None

    def test_token_for_one_user_does_not_unlock_another(self):
        token_a = password_reset.generate_reset_token("user-a")
        token_b = password_reset.generate_reset_token("user-b")
        a = asyncio.run(password_reset.verify_reset_token(token_a))
        b = asyncio.run(password_reset.verify_reset_token(token_b))
        assert a == "user-a"
        assert b == "user-b"

    def test_replay_is_rejected_when_redis_reports_used(self, _mock_redis):
        # First use succeeds (SET NX returns True), second attempt has the
        # key already present → SET NX returns False and verify rejects.
        _mock_redis.set = AsyncMock(side_effect=[True, False])
        token = password_reset.generate_reset_token("user-abc")
        first = asyncio.run(password_reset.verify_reset_token(token))
        second = asyncio.run(password_reset.verify_reset_token(token))
        assert first == "user-abc"
        assert second is None

    def test_redis_outage_fails_closed(self, monkeypatch):
        # W0.27: without the used-token store single use cannot be enforced,
        # so the token is refused (the confirm route answers 503).
        client = AsyncMock()
        client.set = AsyncMock(side_effect=RuntimeError("redis down"))
        monkeypatch.setattr(password_reset, "_redis_client", lambda: client)
        token = password_reset.generate_reset_token("user-abc")
        with pytest.raises(password_reset.ResetStoreUnavailable):
            asyncio.run(password_reset.verify_reset_token(token))

    def test_no_redis_client_fails_closed(self, monkeypatch):
        monkeypatch.setattr(password_reset, "_redis_client", lambda: None)
        token = password_reset.generate_reset_token("user-abc")
        with pytest.raises(password_reset.ResetStoreUnavailable):
            asyncio.run(password_reset.verify_reset_token(token))

    def test_expired_token_is_rejected(self, monkeypatch):
        # Force an already-elapsed TTL. itsdangerous raises SignatureExpired
        # only when age > max_age, so a TTL of 0 leaves a freshly-minted token
        # valid for its first second (age 0 is not > 0). A negative TTL makes
        # any token deterministically expired regardless of timing.
        monkeypatch.setattr(password_reset, "_ttl_seconds", lambda: -1)
        token = password_reset.generate_reset_token("user-abc")
        user_id = asyncio.run(password_reset.verify_reset_token(token))
        assert user_id is None
