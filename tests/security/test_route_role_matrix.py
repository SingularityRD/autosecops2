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

from core.storage.models import Role, User  # noqa: E402
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
    assert not changed, "gate/role outcome changed for: " + ", ".join(
        f"{k} -> {computed[k]}" for k in changed
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
    # 17_loglm_setup.sql (frozen 0.7.1 file) still grants the inert loglm.view.
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


def _isolate_handler_side_effects(key, app, monkeypatch, tmp_path) -> None:
    """Keep allowed roles' handler runs off the machine's real state.

    An ``allow`` role reaches the handler. For the detection-rules routes that
    used to mean the app's real service ``git pull``-ing every repo under
    ``~/security-detections`` over the network, rewriting
    ``~/.vigil/detection_sources.json``, and restarting a configured
    ``security-detections`` MCP stdio server inside the TestClient portal
    (anyio "cancel scope" RuntimeError). Whether that passed depended on the
    machine. Only the services are swapped: the route's permission dependency
    is untouched, so the 403/allow outcome is still the real gate's.
    """
    if not key.split(" ", 1)[1].startswith("/api/detection-rules"):
        return
    from core import deps
    from core.detections.detection_rules_service import DetectionRulesService

    state = tmp_path / "vigil"
    state.mkdir()
    (state / "detection_sources.json").write_text('{"sources": [], "version": 1}')
    monkeypatch.setenv("VIGIL_DIR", str(state))
    monkeypatch.setenv("HOME", str(tmp_path))
    service = DetectionRulesService()  # no sources: nothing to clone or pull
    for dep, value in (
        (deps.provide_detection_rules, service),
        (deps.provide_mcp_client, None),  # no MCP server to restart
        (deps.provide_mcp_registry, None),
    ):
        # setitem: removed again at teardown.
        monkeypatch.setitem(app.dependency_overrides, dep, lambda v=value: v)


class _SeededRoles:
    """A session that answers only ``query(Role).all()``, from the seed SQL.

    The admin-only gate (``require_sso_administrator``) compares the caller's
    grants with every role's, which it reads from the roles table. This job has
    no database, so the table is what the seed files would put there: the same
    grants the matrix itself is computed from.
    """

    def __init__(self, grants):
        self._grants = grants

    def query(self, model):
        assert model is Role, f"only the roles table is seeded, not {model!r}"
        return self

    def all(self):
        return [Role(role_id=r, permissions=dict(g)) for r, g in self._grants.items()]


def _seed_admin_gate(gate, grants, role_grants, app, monkeypatch) -> None:
    if not gate.admin_role_only:
        return
    from core.routing import request_unit_of_work

    monkeypatch.setattr(
        "core.auth.auth_service.AuthService.get_user_permissions",
        lambda user_id, session=None, _g=role_grants: dict(_g),
    )
    # setitem: removed again at teardown.
    monkeypatch.setitem(
        app.dependency_overrides, request_unit_of_work, lambda: _SeededRoles(grants)
    )


@pytest.mark.parametrize("key,gate,row", _GATED_ROWS, ids=[r[0] for r in _GATED_ROWS])
def test_dependency_gated_route_enforces_the_matrix(
    key, gate, row, monkeypatch, tmp_path
):
    grants = rm.load_role_grants()
    method, path = _fill_path(key)
    app = backend_main.app
    _isolate_handler_side_effects(key, app, monkeypatch, tmp_path)

    for role_id in rm.BUILTIN_ROLES:
        role_grants = grants[role_id]

        def _check(user_id, perm, session=None, _g=role_grants):
            return bool(_g.get(perm, False))

        monkeypatch.setattr(
            "core.auth.auth_service.AuthService.check_permission", _check
        )
        _seed_admin_gate(gate, grants, role_grants, app, monkeypatch)
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


# --- environment independence & the internal-token gate (round-5 fixes) ------


def test_flag_gated_routers_have_rows_whatever_the_flag(monkeypatch):
    """Feature flags off or on, the matrix is the same file.

    Every router whose ``RouterMeta.enabled`` predicate exists is listed with
    ``"flag"`` on its rows; forcing every predicate to False (the default env)
    must not drop them, and forcing True must not add any.
    """
    import dataclasses

    from services.api import discovery

    real = discovery.load_router_specs
    specs = real()
    gated = {getattr(m.enabled, "__name__", None) for _, _, m in specs if m.enabled}
    assert gated, "expected at least one feature-gated router (webhook receivers)"
    committed = rm.load_matrix()
    flags_in_matrix = {r["flag"] for r in committed.values() if "flag" in r}
    assert flags_in_matrix == gated, (flags_in_matrix, gated)

    for value in (False, True):

        def pinned(pred, _v=value):
            def predicate():
                return _v

            predicate.__name__ = pred.__name__  # same flag name, other value
            return predicate

        def forced():
            return [
                (
                    n,
                    r,
                    (
                        dataclasses.replace(m, enabled=pinned(m.enabled))
                        if m.enabled
                        else m
                    ),
                )
                for n, r, m in specs
            ]

        monkeypatch.setattr(discovery, "load_router_specs", forced)
        new, gone, changed = rm.diff(committed, rm.compute_matrix())
        assert not (new or gone or changed), (value, new, gone, changed)
    monkeypatch.setattr(discovery, "load_router_specs", real)


def test_frontend_and_context_path_do_not_change_the_matrix(tmp_path):
    """Static mounts and the context-path redirect are excluded by rule, and
    the context path is stripped, so neither a frontend build nor
    VIGIL_CONTEXT_PATH changes a row."""
    from fastapi import FastAPI
    from fastapi.responses import RedirectResponse
    from starlette.staticfiles import StaticFiles

    from services.api.main import PUBLIC_API_PATHS

    fake = FastAPI()
    fake.mount("/vigil/static", StaticFiles(directory=tmp_path), name="static")

    @fake.get("/vigil", include_in_schema=False)
    async def redirect_to_trailing_slash():
        return RedirectResponse(url="/vigil/")

    @fake.get("/vigil/api/health")
    async def health():
        return {}

    paths = [
        p
        for _, p, _ in rm.route_inventory(
            main_app=fake, context_path="/vigil", discover=False
        )
    ]
    assert "/api/health" in paths
    assert not any("static" in p for p in paths)
    assert "/vigil" not in paths and "/" not in paths
    route = next(
        r
        for r, p, _ in rm.route_inventory(
            main_app=fake, context_path="/vigil", discover=False
        )
        if p == "/api/health"
    )
    gate = rm.route_gate(route, "GET", PUBLIC_API_PATHS, path="/api/health")
    assert gate.public


def test_internal_routes_are_gated_by_the_agent_token():
    rows = rm.load_matrix()
    internal = {
        k: r for k, r in rows.items() if k.split(" ", 1)[1].startswith("/internal/")
    }
    assert internal, "no /internal routes found"
    for key, row in internal.items():
        assert "internal-token" in row["gate"], f"{key} lost its internal-token gate"
        for role in rm.BUILTIN_ROLES:
            assert row[role] == rm.DENY, (key, role)


def test_removing_authorise_changes_the_row():
    """The ratchet sees the token check: a handler without ``authorise`` reads
    as ungated (allow for every role), so dropping the call diffs the file."""
    from typing import Optional

    from fastapi import FastAPI, Header

    from core.agents.internal_auth import authorise

    fake = FastAPI()

    @fake.get("/internal/with")
    async def with_token(authorization: Optional[str] = Header(default=None)):
        authorise(authorization, "probe")
        return {}

    @fake.get("/internal/without")
    async def without_token(authorization: Optional[str] = Header(default=None)):
        return {}

    rows = rm.compute_matrix(app=fake, public_patterns=frozenset())
    assert rows["GET /internal/with"]["gate"] == "internal-token"
    assert all(rows["GET /internal/with"][r] == rm.DENY for r in rm.BUILTIN_ROLES)
    assert rows["GET /internal/without"]["gate"] == "none"
    assert all(rows["GET /internal/without"][r] == rm.ALLOW for r in rm.BUILTIN_ROLES)


def test_a_user_session_is_not_the_internal_token(monkeypatch):
    """Runtime proof for the 'deny' cells on internal-token rows: whatever a
    logged-in user presents (their own bearer JWT), ``authorise`` refuses it,
    and an unconfigured secret fails closed (503), never open."""
    from fastapi import HTTPException

    from core.agents.internal_auth import authorise

    monkeypatch.setattr(
        "core.agents.internal_auth.get_secret",
        lambda name: "w43-probe-token" if name == "AGENT_INTERNAL_TOKEN" else None,
    )
    for presented in (
        None,
        "",
        "Bearer eyJhbGciOiJIUzI1NiJ9.admin.session",
        "w43-probe-token",
    ):
        with pytest.raises(HTTPException) as exc:
            authorise(presented, "probe")
        assert exc.value.status_code == 401, presented
    authorise("Bearer w43-probe-token", "probe")  # the token itself passes

    monkeypatch.setattr("core.agents.internal_auth.get_secret", lambda name: None)
    with pytest.raises(HTTPException) as exc:
        authorise("Bearer anything", "probe")
    assert exc.value.status_code == 503


def test_enforcement_never_reaches_the_apps_real_detection_services(
    monkeypatch, tmp_path
):
    """W0.17: the allow-role probe of detection-rules routes is hermetic.

    It once ran the app's real DetectionRulesService (network ``git pull``,
    writes to ``~/.vigil``) and restarted a real MCP stdio server, so it
    failed only on machines where that server was configured. Here the app's
    real services are booby-trapped: touching them fails the test.
    """

    touched: list[str] = []

    class _Trap:
        # The app turns a handler exception into a 500, which an allow-role
        # probe accepts, so record the touch instead of only raising.
        def __getattr__(self, name):
            touched.append(name)
            raise AssertionError(f"real app service touched: .{name}")

        def __bool__(self):
            touched.append("__bool__")
            raise AssertionError("real app service touched")

    app = backend_main.app
    for attr in ("detection_rules", "mcp_client", "mcp_registry"):
        monkeypatch.setattr(app.state, attr, _Trap(), raising=False)
    rows = {key: (gate, row) for key, gate, row in _GATED_ROWS}
    for key in (
        "POST /api/detection-rules/update-all",
        "POST /api/detection-rules/reload",
    ):
        assert key in rows, key
        gate, row = rows[key]
        sub = tmp_path / key.replace("/", "_").replace(" ", "_")
        sub.mkdir()
        with pytest.MonkeyPatch.context() as mp:
            test_dependency_gated_route_enforces_the_matrix(key, gate, row, mp, sub)
    assert not touched, touched
