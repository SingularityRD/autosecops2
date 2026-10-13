"""A signed-in caller who holds every permission, for handler-level API tests.

W0.11 put permission gates on write routes these suites exercise. They test
what the handler does, not the gate (tests/security/test_route_permissions.py
does that), so the gate is satisfied here: get_current_user returns a stub user
every permission check passes, and the request's unit of work is a no-op
unless the suite overrides it.
"""

from contextlib import nullcontext
from types import SimpleNamespace

import pytest

import core.routing
from core.auth import current_user
from core.auth.auth_service import AuthService


@pytest.fixture
def signed_in(monkeypatch):
    user = SimpleNamespace(user_id="tester", username="tester", is_active=True)
    monkeypatch.setattr(current_user, "DEV_MODE", True)
    monkeypatch.setattr(current_user, "_get_dev_user", lambda session: user)
    # get_current_user asks for the request's unit of work; these suites mount
    # routers without a database, and the stub user needs none.
    monkeypatch.setattr(core.routing, "unit_of_work", lambda *a, **k: nullcontext())
    monkeypatch.setattr(
        AuthService, "check_permission", staticmethod(lambda *a, **k: True)
    )
    return user
