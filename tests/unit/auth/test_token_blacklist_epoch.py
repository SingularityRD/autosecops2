"""revocation_epoch: tokens from before a Redis data reset are rejected (W0.38).

Redis's start wrapper moves Redis 7.4 data aside on the pinned 7.2 and sets
`revocation_epoch`. The logouts and per-user cutoffs went with that data, so
every token issued before the epoch must stop working; without the key nothing
changes.
"""

from __future__ import annotations

import pytest

from core.auth import token_blacklist as tb


class _Redis:
    def __init__(self, data=None):
        self.data = dict(data or {})

    async def exists(self, key):
        return int(key in self.data)

    async def get(self, key):
        return self.data.get(key)


@pytest.fixture
def redis(monkeypatch):
    client = _Redis()
    monkeypatch.setattr(tb, "_get_client", lambda: client)
    monkeypatch.setattr(tb, "_FAIL_OPEN", False)
    return client


@pytest.mark.asyncio
async def test_without_an_epoch_nothing_changes(redis):
    assert await tb.is_token_revoked({"jti": "j", "user_id": "u", "iat": 1}) is False


@pytest.mark.asyncio
async def test_a_token_issued_before_the_epoch_is_revoked(redis):
    redis.data["revocation_epoch"] = "1000"
    assert await tb.is_token_revoked({"jti": "j", "user_id": "u", "iat": 999}) is True


@pytest.mark.asyncio
@pytest.mark.parametrize("iat", [1000, 1001])
async def test_a_token_issued_at_or_after_the_epoch_is_valid(redis, iat):
    redis.data["revocation_epoch"] = "1000"
    assert await tb.is_token_revoked({"jti": "j", "user_id": "u", "iat": iat}) is False


@pytest.mark.asyncio
async def test_a_token_without_iat_is_revoked_once_there_is_an_epoch(redis):
    redis.data["revocation_epoch"] = "1000"
    assert await tb.is_token_revoked({"jti": "j", "user_id": "u"}) is True


@pytest.mark.asyncio
async def test_the_other_checks_still_apply_after_the_epoch(redis):
    redis.data.update(
        {
            "revocation_epoch": "1000",
            "blacklist:jti:j": "1",
            "user_revoked_before:u": "2000",
        }
    )
    assert await tb.is_token_revoked({"jti": "j", "user_id": "x", "iat": 1500}) is True
    assert await tb.is_token_revoked({"jti": "k", "user_id": "u", "iat": 1500}) is True
    assert await tb.is_token_revoked({"jti": "k", "user_id": "x", "iat": 1500}) is False


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_open, revoked", [(False, True), (True, False)])
async def test_a_malformed_epoch_follows_fail_open(
    redis, monkeypatch, fail_open, revoked
):
    monkeypatch.setattr(tb, "_FAIL_OPEN", fail_open)
    redis.data["revocation_epoch"] = "not-a-number"
    assert await tb.is_token_revoked({"jti": "j", "user_id": "u", "iat": 5}) is revoked


def test_the_wrapper_sets_the_key_the_api_reads():
    from pathlib import Path

    script = (
        Path(__file__).resolve().parents[3] / "infra/helm/vigil/files/redis-start.sh"
    ).read_text(encoding="utf-8")
    assert f"set {tb._EPOCH_KEY} " in script
