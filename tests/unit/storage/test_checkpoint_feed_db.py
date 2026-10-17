"""Check Point: block_ip through the polled block list, against Postgres (W0.60)."""

from __future__ import annotations

import contextlib
from datetime import timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from core.integrations.checkpoint import checkpoint_feed_router as feed_router
from core.integrations.checkpoint import feed
from core.integrations.checkpoint.executor import (
    BLOCK_IP,
    UNBLOCK_IP,
    CheckPointConfigError,
    CheckPointFeedExecutor,
    build_executor,
)
from core.response.executors.base import TypedAction
from core.routing import request_unit_of_work
from core.storage.connection import get_db_manager
from core.time import utcnow

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

TOKEN = "feed-token-7f3a"


@pytest.fixture()
def session():
    manager = get_db_manager()
    if manager.engine is None:
        manager.initialize()
    with manager.engine.connect() as conn:
        tx = conn.begin()
        try:
            with Session(bind=conn, join_transaction_mode="create_savepoint") as s:
                yield s
        finally:
            tx.rollback()


@pytest.fixture()
def executor(session):
    @contextlib.contextmanager
    def scope():
        yield session

    return CheckPointFeedExecutor(session_scope=scope)


def act(kind=BLOCK_IP, target="8.8.4.4", **kw):
    return TypedAction(action_type=kind, target=target, **kw)


def test_block_puts_the_ip_on_the_feed_and_verifies(executor, session):
    result = executor.execute(act(action_id="a-1"))
    assert result.status == "executed"
    assert result.before_state["listed"] is False and result.after_state["listed"]
    doc = feed.generic_data_center(session)
    assert doc["objects"][0]["ranges"] == ["8.8.4.4"]
    assert doc["objects"][0]["id"] == feed.OBJECT_ID
    assert feed.plain_text(session) == "8.8.4.4\n"
    assert executor.verify(act(), result).status == "verified"
    assert executor.execute(act()).status == "noop"


def test_reverse_and_unblock_take_it_off(executor, session):
    result = executor.execute(act())
    undo = executor.reverse(act(), result)
    assert undo.status == "executed" and feed.plain_text(session) == ""
    executor.execute(act(target="2001:4860::8888"))
    executor.execute(act())
    off = executor.execute(act(UNBLOCK_IP))
    assert off.status == "executed"
    assert feed.plain_text(session) == "2001:4860::8888\n"
    assert executor.reverse(act(UNBLOCK_IP), off).status == "executed"
    assert feed.plain_text(session) == "8.8.4.4\n2001:4860::8888\n"


def test_an_expired_entry_leaves_the_feed_before_the_sweep(session):
    feed.add(session, "8.8.4.4", ttl=timedelta(seconds=1), action_id=None, actor="t")
    assert feed.contains(session, "8.8.4.4")
    assert not feed.contains(session, "8.8.4.4", now=utcnow() + timedelta(seconds=5))


@pytest.mark.parametrize("target", ["10.1.2.3", "127.0.0.1", "10.0.0.0/24", "x"])
def test_validate_refuses_internal_and_bad_targets(executor, session, target):
    assert not executor.validate(act(target=target)).allowed
    assert executor.execute(act(target=target)).status == "failed"
    assert feed.plain_text(session) == ""


def test_build_needs_a_feed_token():
    with pytest.raises(CheckPointConfigError):
        build_executor({})
    assert build_executor({"feed_token": TOKEN}).default_ttl == timedelta(hours=24)


# --- the feed route ----------------------------------------------------------


@pytest.fixture()
def client(session, monkeypatch):
    monkeypatch.setattr(feed_router, "_expected_token", lambda: TOKEN)
    app = FastAPI()
    app.include_router(feed_router.router, prefix=feed_router.ROUTER_META.prefix)
    app.dependency_overrides[request_unit_of_work] = lambda: session
    feed.add(session, "8.8.4.4", ttl=timedelta(hours=1), action_id=None, actor="t")
    return TestClient(app)


def test_the_gateway_reads_the_feed_with_its_token(client):
    base = "/api/feeds/checkpoint"
    r = client.get(f"{base}/blocklist", headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200
    assert r.json()["objects"][0]["ranges"] == ["8.8.4.4"]
    assert r.headers["cache-control"] == "no-store"
    assert (
        client.get(f"{base}/blocklist.txt", params={"token": TOKEN}).text == "8.8.4.4\n"
    )
    r = client.get(f"{base}/blocklist", headers={"X-Feed-Token": TOKEN})
    assert r.status_code == 200


def test_a_wrong_or_missing_token_is_refused(client):
    base = "/api/feeds/checkpoint"
    assert client.get(f"{base}/blocklist").status_code == 401
    assert (
        client.get(
            f"{base}/blocklist", headers={"Authorization": "Bearer nope"}
        ).status_code
        == 401
    )


def test_the_feed_is_not_there_while_the_integration_is_off(client, monkeypatch):
    monkeypatch.setattr(feed_router, "_expected_token", lambda: None)
    r = client.get(
        "/api/feeds/checkpoint/blocklist", headers={"Authorization": f"Bearer {TOKEN}"}
    )
    assert r.status_code == 404
