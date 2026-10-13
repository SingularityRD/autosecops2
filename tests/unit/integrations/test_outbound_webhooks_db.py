"""Outbound webhooks end to end against a real Postgres and a local receiver.

``47_webhooks_alert_routes.sql`` is applied to the throwaway test database (the
tables are SQL-owned, so ``create_all`` does not make them). The signing secret
lives in a fake secrets store, which is also how the tests prove the database
holds only its name.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import text

from core.config import get_settings
from core.integrations import outbound_webhooks as hooks
from core.storage.connection import get_db_manager
from tests.unit.integrations._webhook_receiver import start_receiver

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

SQL = (
    Path(__file__).resolve().parents[3]
    / "infra"
    / "database"
    / "init"
    / "47_webhooks_alert_routes.sql"
)
T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def secrets_store(monkeypatch):
    store: dict = {}

    def set_secret(key, value):
        store[key] = value
        return True

    monkeypatch.setattr(hooks, "set_secret", set_secret)
    monkeypatch.setattr(hooks, "get_secret", lambda key, default=None: store.get(key))
    monkeypatch.setattr(hooks, "delete_secret", lambda key: bool(store.pop(key, 1)))
    return store


@pytest.fixture
def webhook_tables():
    with get_db_manager().engine.begin() as conn:
        conn.execute(text(SQL.read_text(encoding="utf-8")))
        conn.execute(
            text("TRUNCATE webhook_deliveries, alert_routes, webhook_endpoints")
        )
    yield


@pytest.fixture
def allow_loopback(monkeypatch):
    monkeypatch.setenv("WEBHOOK_ALLOWED_CIDRS", "127.0.0.1/32")
    get_settings.cache_clear()


@pytest.fixture
def receiver():
    r = start_receiver()
    yield r
    r.close()


def _deliveries():
    with get_db_manager().engine.connect() as conn:
        return [
            dict(r._mapping)
            for r in conn.execute(
                text("SELECT * FROM webhook_deliveries ORDER BY id")
            ).fetchall()
        ]


def _endpoint(receiver, **over):
    kwargs = dict(name="soc-hook", url=receiver.url(), event_types=[])
    kwargs.update(over)
    return hooks.create_endpoint(**kwargs)


@pytest.mark.asyncio
async def test_event_is_delivered_signed_once(
    webhook_tables, secrets_store, allow_loopback, receiver
):
    endpoint, secret = _endpoint(receiver)

    # The database names the secret; it never holds it.
    with get_db_manager().engine.connect() as conn:
        row = dict(conn.execute(text("SELECT * FROM webhook_endpoints")).one()._mapping)
    assert secret and secret.startswith("whsec_")
    assert row["secret_ref"].startswith(hooks.SECRET_REF_PREFIX)
    assert secrets_store[row["secret_ref"]] == secret
    assert secret not in repr(row)

    data = {"case": {"case_id": "c-1"}}
    assert hooks.enqueue_event("case.sla_warning", "sla:c-1:response:90", data) == 1
    # Re-emitting the same event is not a second delivery.
    assert hooks.enqueue_event("case.sla_warning", "sla:c-1:response:90", data) == 0

    counts = await hooks.WebhookSender().deliver_due()

    assert counts == {"delivered": 1}
    [request] = receiver.requests
    assert hooks.verify_signature(
        secret, request.headers["X-AutoSecOps-Signature"], request.body
    )
    assert request.headers["X-AutoSecOps-Event-Id"] == "sla:c-1:response:90"
    [delivery] = _deliveries()
    assert delivery["status"] == "delivered"
    assert delivery["attempts"] == 1
    assert delivery["response_status"] == 200
    assert request.headers["X-AutoSecOps-Delivery"] == str(delivery["id"])

    # Nothing left to send.
    assert await hooks.WebhookSender().deliver_due() == {}
    assert len(receiver.requests) == 1


@pytest.mark.asyncio
async def test_failures_back_off_exponentially_then_go_dead(
    webhook_tables, secrets_store, allow_loopback, receiver
):
    receiver.statuses = [500]
    _endpoint(receiver)
    hooks.enqueue_event("case.stale_case", "stale:c-1:2026-10-01", {}, now=T0)
    sender = hooks.WebhookSender(max_attempts=3)

    assert await sender.deliver_due(now=T0) == {"pending": 1}
    [d] = _deliveries()
    assert d["attempts"] == 1 and d["status"] == "pending"
    assert d["next_attempt_at"] == T0 + timedelta(seconds=30)
    assert d["last_error"] == "HTTP 500" and d["response_status"] == 500

    # Not due yet: nothing is sent.
    assert await sender.deliver_due(now=T0 + timedelta(seconds=29)) == {}
    assert len(receiver.requests) == 1

    t1 = T0 + timedelta(seconds=30)
    assert await sender.deliver_due(now=t1) == {"pending": 1}
    [d] = _deliveries()
    assert d["attempts"] == 2
    assert d["next_attempt_at"] == t1 + timedelta(seconds=60)

    assert await sender.deliver_due(now=t1 + timedelta(seconds=60)) == {"dead": 1}
    [d] = _deliveries()
    assert d["status"] == "dead" and d["attempts"] == 3
    assert len(receiver.requests) == 3

    # An admin can put it back; it then goes through.
    receiver.statuses = [200]
    endpoint_id = str(d["endpoint_id"])
    assert hooks.requeue_delivery(endpoint_id, d["id"], now=t1)["status"] == "pending"
    assert await sender.deliver_due(now=t1 + timedelta(seconds=61)) == {"delivered": 1}


@pytest.mark.asyncio
async def test_retry_then_success(
    webhook_tables, secrets_store, allow_loopback, receiver
):
    receiver.statuses = [503, 200]
    _endpoint(receiver)
    hooks.enqueue_event("case.sla_warning", "e-1", {}, now=T0)
    sender = hooks.WebhookSender()

    assert await sender.deliver_due(now=T0) == {"pending": 1}
    assert await sender.deliver_due(now=T0 + timedelta(seconds=30)) == {"delivered": 1}
    [d] = _deliveries()
    assert d["attempts"] == 2 and d["delivered_at"] is not None
    # Same event id and body both times.
    assert receiver.requests[0].body == receiver.requests[1].body


@pytest.mark.asyncio
async def test_a_client_error_fails_without_retrying(
    webhook_tables, secrets_store, allow_loopback, receiver
):
    receiver.statuses = [404]
    _endpoint(receiver)
    hooks.enqueue_event("case.sla_warning", "e-1", {}, now=T0)

    assert await hooks.WebhookSender().deliver_due(now=T0) == {"failed": 1}
    [d] = _deliveries()
    assert d["status"] == "failed" and d["attempts"] == 1


@pytest.mark.asyncio
async def test_a_target_refused_at_send_time_fails(
    webhook_tables, secrets_store, monkeypatch, receiver
):
    """Registered while allowed (or before DNS changed): checked again at send."""
    monkeypatch.setenv("WEBHOOK_ALLOWED_CIDRS", "")
    get_settings.cache_clear()
    hooks.create_endpoint(name="internal", url=receiver.url(), check_target=False)
    hooks.enqueue_event("case.sla_warning", "e-1", {}, now=T0)

    assert await hooks.WebhookSender().deliver_due(now=T0) == {"failed": 1}
    [d] = _deliveries()
    assert d["last_error"].startswith("target refused")
    assert receiver.requests == []


def test_creating_an_endpoint_for_an_internal_target_is_refused(
    webhook_tables, secrets_store, monkeypatch
):
    from core.platform.url_safety import UrlSafetyError

    monkeypatch.setenv("WEBHOOK_ALLOWED_CIDRS", "")
    get_settings.cache_clear()
    with pytest.raises(UrlSafetyError):
        hooks.create_endpoint(name="meta", url="http://169.254.169.254/latest")
    with pytest.raises(UrlSafetyError):
        hooks.create_endpoint(name="local", url="http://127.0.0.1:8080/hook")
    assert hooks.list_endpoints() == []
    assert secrets_store == {}


def test_subscriptions_disabled_endpoints_and_tenants_scope_the_queue(
    webhook_tables, secrets_store, allow_loopback, receiver
):
    _endpoint(receiver, name="sla-only", event_types=["case.sla_warning"])
    _endpoint(receiver, name="all")
    _endpoint(receiver, name="off", enabled=False)
    _endpoint(receiver, name="other-tenant", tenant_id="tenant-b")

    assert hooks.enqueue_event("case.stale_case", "s-1", {}) == 1  # "all"
    assert hooks.enqueue_event("case.sla_warning", "w-1", {}) == 2  # both
    assert hooks.enqueue_event("case.sla_warning", "w-2", {}, tenant_id="tenant-b") == 1
    rows = _deliveries()
    assert {r["tenant_id"] for r in rows} == {"default", "tenant-b"}


def test_update_rotates_the_secret_and_delete_removes_it(
    webhook_tables, secrets_store, allow_loopback, receiver
):
    endpoint, _ = _endpoint(receiver, secret="x" * 32)
    ref = hooks.get_endpoint(endpoint["id"])["secret_ref"]
    assert secrets_store[ref] == "x" * 32

    updated = hooks.update_endpoint(
        endpoint["id"], secret="y" * 32, enabled=False, name="renamed"
    )
    assert updated["name"] == "renamed" and updated["enabled"] is False
    assert secrets_store[ref] == "y" * 32

    with pytest.raises(hooks.WebhookConflict):
        _endpoint(receiver, name="renamed")

    assert hooks.delete_endpoint(endpoint["id"]) is True
    assert ref not in secrets_store
    assert hooks.delete_endpoint(endpoint["id"]) is False


@pytest.mark.asyncio
async def test_two_senders_never_send_the_same_delivery(
    webhook_tables, secrets_store, allow_loopback, receiver
):
    import asyncio

    _endpoint(receiver)
    for i in range(6):
        hooks.enqueue_event("case.sla_warning", f"e-{i}", {}, now=T0)

    a, b = await asyncio.gather(
        hooks.WebhookSender().deliver_due(now=T0),
        hooks.WebhookSender().deliver_due(now=T0),
    )

    assert a.get("delivered", 0) + b.get("delivered", 0) == 6
    ids = [r.headers["X-AutoSecOps-Event-Id"] for r in receiver.requests]
    assert sorted(ids) == sorted(f"e-{i}" for i in range(6))


def test_an_outcome_for_a_delivery_taken_over_meanwhile_is_dropped(
    webhook_tables, secrets_store, allow_loopback, receiver
):
    _endpoint(receiver)
    hooks.enqueue_event("case.sla_warning", "e-late", {}, now=T0)
    (claimed,) = hooks.claim_due_deliveries(now=T0)

    # The lease ran out and a second sender delivered it first.
    later = T0 + timedelta(seconds=hooks.CLAIM_LEASE_SECONDS + 1)
    (again,) = hooks.claim_due_deliveries(now=later)
    hooks.record_attempt(
        again, hooks.SendResult(hooks.DELIVERED, 200), max_attempts=8, now=later
    )

    # The first sender's late failure must not overwrite the delivery.
    hooks.record_attempt(
        claimed, hooks.SendResult("retry", 500, "HTTP 500"), max_attempts=8, now=later
    )

    (row,) = _deliveries()
    assert row["status"] == "delivered"
    assert row["attempts"] == 1
    assert row["response_status"] == 200


def test_a_stale_outcome_arriving_before_the_newer_one_is_dropped(
    webhook_tables, secrets_store, allow_loopback, receiver
):
    """The other ordering: the stale claim's result lands first."""
    _endpoint(receiver)
    hooks.enqueue_event("case.sla_warning", "e-late-first", {}, now=T0)
    (claimed,) = hooks.claim_due_deliveries(now=T0)
    later = T0 + timedelta(seconds=hooks.CLAIM_LEASE_SECONDS + 1)
    (again,) = hooks.claim_due_deliveries(now=later)

    # The first sender's late failure arrives before the second's success.
    hooks.record_attempt(
        claimed, hooks.SendResult("retry", 500, "HTTP 500"), max_attempts=8, now=later
    )
    (row,) = _deliveries()
    assert row["status"] == "pending"
    assert row["attempts"] == 0
    assert row["response_status"] is None

    # The newer claim's outcome is still recorded.
    status = hooks.record_attempt(
        again, hooks.SendResult(hooks.DELIVERED, 200), max_attempts=8, now=later
    )
    assert status == hooks.DELIVERED
    (row,) = _deliveries()
    assert row["status"] == "delivered"
    assert row["attempts"] == 1
    assert row["response_status"] == 200


def test_a_stale_outcome_is_dropped_after_a_requeue_resets_attempts(
    webhook_tables, secrets_store, allow_loopback, receiver
):
    """A requeue puts attempts back to 0: the count alone would match again."""
    endpoint, _ = _endpoint(receiver)
    hooks.enqueue_event("case.sla_warning", "e-aba", {}, now=T0)
    (stale,) = hooks.claim_due_deliveries(now=T0)
    later = T0 + timedelta(seconds=hooks.CLAIM_LEASE_SECONDS + 1)
    (again,) = hooks.claim_due_deliveries(now=later)
    hooks.record_attempt(
        again, hooks.SendResult(hooks.FAILED, 404, "HTTP 404"), max_attempts=8, now=later
    )
    (row,) = _deliveries()
    assert hooks.requeue_delivery(endpoint["id"], row["id"], now=later) is not None

    hooks.record_attempt(
        stale, hooks.SendResult(hooks.DELIVERED, 200), max_attempts=8, now=later
    )
    (row,) = _deliveries()
    assert row["status"] == "pending"
    assert row["attempts"] == 0
