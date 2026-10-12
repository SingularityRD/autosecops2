"""W0.5 tables reference each other by (tenant_id, id) in a real Postgres.

``46_eval_qa_canary.sql`` and ``47_webhooks_alert_routes.sql`` are applied
inside a transaction that is rolled back. A child row may point at a parent of
its own tenant and never at one of another tenant.
"""

from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from core.storage.connection import get_db_manager

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

INIT = Path(__file__).resolve().parents[3] / "infra" / "database" / "init"
FILES = ("46_eval_qa_canary.sql", "47_webhooks_alert_routes.sql")


def _refused(conn, sql, params):
    sp = conn.begin_nested()
    with pytest.raises(IntegrityError):
        conn.execute(text(sql), params)
    sp.rollback()


def test_cross_tenant_references_are_refused():
    with get_db_manager().engine.connect() as conn:
        tx = conn.begin()
        try:
            for name in FILES:
                conn.execute(text((INIT / name).read_text(encoding="utf-8")))

            run = conn.execute(
                text(
                    "INSERT INTO eval_runs (tenant_id, suite, model, prompt_version) "
                    "VALUES ('a', 's', 'm', 'p') RETURNING id"
                )
            ).scalar()
            endpoint = conn.execute(
                text(
                    "INSERT INTO webhook_endpoints (tenant_id, name, url) "
                    "VALUES ('a', 'e', 'https://example.test') RETURNING id"
                )
            ).scalar()

            result_sql = (
                "INSERT INTO eval_results (tenant_id, run_id, case_id, expected_verdict) "
                "VALUES (:t, :r, :c, 'benign')"
            )
            delivery_sql = (
                "INSERT INTO webhook_deliveries (tenant_id, endpoint_id, event_type, event_id, payload) "
                "VALUES (:t, :e, 'x', :ev, '{}'::jsonb)"
            )
            route_sql = (
                "INSERT INTO alert_routes (tenant_id, name, destination_kind, webhook_endpoint_id) "
                "VALUES (:t, :n, 'webhook', :e)"
            )

            # Same tenant: fine.
            conn.execute(text(result_sql), {"t": "a", "r": run, "c": "c1"})
            conn.execute(text(delivery_sql), {"t": "a", "e": endpoint, "ev": "ev1"})
            conn.execute(text(route_sql), {"t": "a", "n": "r1", "e": endpoint})

            # Another tenant, including the 'default' a caller gets by omission.
            for tenant in ("b", "default"):
                _refused(conn, result_sql, {"t": tenant, "r": run, "c": "c2"})
                _refused(conn, delivery_sql, {"t": tenant, "e": endpoint, "ev": "ev2"})
                _refused(conn, route_sql, {"t": tenant, "n": "r2", "e": endpoint})
            _refused(
                conn,
                "INSERT INTO eval_results (run_id, case_id, expected_verdict) "
                "VALUES (:r, 'c3', 'benign')",
                {"r": run},
            )

            # A route that is not a webhook needs no endpoint.
            conn.execute(
                text(
                    "INSERT INTO alert_routes (tenant_id, name, destination_kind) "
                    "VALUES ('b', 'slack', 'slack')"
                )
            )
            # RESTRICT holds through the composite key.
            _refused(
                conn, "DELETE FROM webhook_endpoints WHERE id = :e", {"e": endpoint}
            )
        finally:
            tx.rollback()
