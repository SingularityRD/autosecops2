"""W4.3: the role x route authorization matrix is a ratchet and it is real.

Three things are checked:

* **Ratchet** — the committed ``route_role_matrix.json`` equals the matrix
  recomputed from the live app and the seed SQL. A new route, a changed gate,
  or a changed role grant fails here until someone regenerates the file on
  purpose (``PYTHONPATH=. python -m tests.security.route_matrix --write``) and
  the JSON diff is reviewed. An unknown/new route cannot pass silently.
* **Grounded in the seed** — every init-SQL file that writes the ``roles``
  table is one the generator parses, so a future grant file can't drift the
  model away from what the database actually seeds.
* **Enforced, not just declared** — for every dependency-gated route, the app
  is driven with a user carrying each built-in role's real grants and the HTTP
  outcome (403 or not) is asserted to match the matrix. This proves the
  ``allow``/``deny`` cells describe runtime behaviour, not a restating of the
  file.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-not-for-prod")

from core.storage.models import User  # noqa: E402
from services.api import main as backend_main  # noqa: E402
from services.api.middleware import auth as auth_module  # noqa: E402
from tests.security import route_matrix as rm  # noqa: E402

pytestmark = pytest.mark.unit


def test_matrix_file_matches_the_live_app_and_seed():
    """Ratchet: regenerate and review the JSON when this fails (see module docstring)."""
    computed = rm.compute_matrix()
    committed = rm.load_matrix()
    new, gone, changed = rm.diff(committed, computed)
    assert not new, f"routes with no matrix row (unknown/new — regenerate): {new}"
    assert not gone, f"matrix rows for routes that no longer exist: {gone}"
    assert not changed, (
        "gate/role outcome changed for: "
        + ", ".join(f"{k} -> {computed[k]}" for k in changed)
    )


def test_every_role_grant_file_is_modelled():
    """A new init file that writes `roles` must be parsed by the generator."""
    actual = set(rm.role_grant_files())
    modelled = set(rm.ROLE_GRANT_FILES)
    assert actual <= modelled, (
        "init SQL writes the roles table but the matrix generator does not parse it: "
        f"{sorted(actual - modelled)}. Teach load_role_grants() about it."
    )


def test_every_route_has_an_outcome_for_every_builtin_role():
    for key, row in rm.load_matrix().items():
        if row.get("gate") == "mount":
            continue
        for role in rm.BUILTIN_ROLES:
            assert role in row, f"{key} has no outcome for {role}"
            assert row[role] in (rm.ALLOW, rm.DENY, rm.CONDITIONAL), (key, role)


def test_seeded_grants_match_the_known_builtin_roles():
    """Guards the SQL parser against a silent change to a seeded permission set."""
    grants = rm.load_role_grants()
    # Viewer's seed block lists only read grants; write perms are absent, which
    # the model treats as deny (role_outcome uses grants.get(perm, False)).
    assert grants["role-viewer"].get("settings.write", False) is False
    assert grants["role-viewer"].get("ai_chat.use") is False
    assert grants["role-analyst"].get("ai_chat.use") is True
    assert grants["role-analyst"].get("settings.write") is False
    assert grants["role-analyst"].get("integrations.write") is False
    assert grants["role-senior-analyst"].get("integrations.write") is True
    assert grants["role-senior-analyst"].get("settings.write") is False
    assert grants["role-manager"].get("settings.write") is True
    assert grants["role-admin"].get("users.delete") is True
    # Later grant files.
    assert grants["role-analyst"].get("loglm.view") is True
    assert grants["role-viewer"].get("loglm.view") in (None, False)
    assert grants["role-admin"].get("medic.admin") is True
    assert grants["role-manager"].get("medic.read") is True
    assert grants["role-manager"].get("medic.admin") in (None, False)


# --- live enforcement -------------------------------------------------------


def _dependency_gated_rows():
    """(key, gate, matrix_row) for routes enforced by a dependency alone.

    Inline-in-handler gates run after body validation, so a bodyless probe hits
    422 before the check — those stay covered structurally and by
    test_route_permissions. Here we only drive routes whose gate is a
    dependency (permission closure or the canary admin-role check), which runs
    before the handler for every role.
    """
    from services.api.main import PUBLIC_API_PATHS, app

    rows = rm.load_matrix()
    out = []
    for route in rm.iter_routes(app):
        path = getattr(route, "path", None)
        if not isinstance(path, str):
            continue
        for method in rm.route_methods(route):
            gate = rm.route_gate(route, method, PUBLIC_API_PATHS)
            if gate.dynamic or gate.inline_permissions:
                continue
            if not (gate.dep_permissions or gate.admin_role_only):
                continue
            key = rm.route_key(route, method)
            if key in rows:
                out.append((key, gate, rows[key]))
    return out


_GATED_ROWS = _dependency_gated_rows()


def _user_for(role_id: str) -> User:
    return User(
        user_id=f"user-{role_id}",
        username=f"u_{role_id}",
        email=f"{role_id}@test.local",
        password_hash="",
        role_id=role_id,
        is_active=True,
        mfa_enabled=False,
    )


def _fill_path(key: str) -> tuple[str, str]:
    method, path = key.split(" ", 1)
    # A UUID-shaped placeholder satisfies routes with a UUID path convertor.
    out = []
    for seg in path.split("/"):
        if seg.startswith("{"):
            out.append("9c1c2d3e-0000-4000-8000-0000000000aa")
        else:
            out.append(seg)
    return method, "/".join(out)


@pytest.mark.parametrize(
    "key,gate,row", _GATED_ROWS, ids=[r[0] for r in _GATED_ROWS]
)
def test_dependency_gated_route_enforces_the_matrix(key, gate, row, monkeypatch):
    grants = rm.load_role_grants()
    method, path = _fill_path(key)
    app = backend_main.app

    for role_id in rm.BUILTIN_ROLES:
        role_grants = grants[role_id]

        def _check(user_id, perm, session=None, _g=role_grants):
            return bool(_g.get(perm, False))

        monkeypatch.setattr(
            "core.auth.auth_service.AuthService.check_permission", _check
        )
        user = _user_for(role_id)
        app.dependency_overrides[auth_module.get_current_active_user] = lambda u=user: u
        app.dependency_overrides[auth_module.get_current_user] = lambda u=user: u
        try:
            from fastapi.testclient import TestClient

            resp = TestClient(app).request(method, path, json={})
        finally:
            app.dependency_overrides.pop(auth_module.get_current_active_user, None)
            app.dependency_overrides.pop(auth_module.get_current_user, None)

        expected = row[role_id]
        if expected == rm.DENY:
            assert resp.status_code == 403, (
                f"{key}: {role_id} is 'deny' in the matrix but got "
                f"{resp.status_code}: {resp.text[:160]}"
            )
        elif expected == rm.ALLOW:
            assert resp.status_code != 403, (
                f"{key}: {role_id} is 'allow' in the matrix but was refused 403: "
                f"{resp.text[:160]}"
            )
