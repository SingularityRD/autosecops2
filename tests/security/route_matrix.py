"""Role x route authorization matrix (W4.3): model, generator and checker.

Every route the API serves gets one row per method in
``route_role_matrix.json``, with an explicit outcome for each built-in role
(``allow`` / ``deny``; ``conditional`` only where the permission is computed at
request time from a path parameter, with the reason in ``note``). The row is
*derived* from two sources the product already owns, never hand-typed:

* the route's gate, read off the FastAPI dependency chain
  (``require_permission`` closures, the canary ``require_admin`` role check,
  the vstrike inbound key) and off the handler's own source for the inline
  checks (``require_settings_admin``, ``_require_permission`` ...);
* each built-in role's grants, parsed from the seed SQL under
  ``infra/database/init`` (``06_auth_tables.sql`` plus the later grant files).

``test_route_role_matrix.py`` recomputes the matrix and compares it with the
committed file, so a new route, a changed gate or a changed role grant all
fail the test until the file is regenerated *on purpose*::

    PYTHONPATH=. python -m tests.security.route_matrix --write

and the diff of the JSON file is what a reviewer reads. The model assumes
``DEV_MODE`` is off (DEV_MODE grants everything by design).

The matrix does not depend on the environment it is generated in:

* routers are taken from ``services.api.discovery`` and mounted on a scratch
  app with **every feature flag on** (``RouterMeta.enabled`` ignored), so a
  flag-gated router (the Darktrace and Cloudflare webhook receivers) always has
  rows; those rows carry ``"flag": "<predicate>"`` -- with the flag off the
  router is not mounted at all and the rows simply do not exist;
* paths are written without ``VIGIL_CONTEXT_PATH``;
* the frontend (StaticFiles mounts, the context-path redirect) is excluded by
  rule, so whether ``clients/web/build`` exists does not matter.

The agent-layer shared-secret gate (``core.agents.internal_auth.authorise``) is
modelled as ``internal-token``: a user's login is not that token, so every
built-in role is ``deny``. Remove the call from an /internal handler and its row
turns to ``none``/``allow`` and the ratchet fails.
"""

from __future__ import annotations

import inspect
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

REPO = Path(__file__).resolve().parents[2]
MATRIX_FILE = Path(__file__).with_name("route_role_matrix.json")
INIT_SQL = REPO / "infra" / "database" / "init"

BUILTIN_ROLES = (
    "role-viewer",
    "role-analyst",
    "role-senior-analyst",
    "role-manager",
    "role-admin",
)

# Seed files that grant role permissions, in the order the installer runs them.
# ``test_every_role_grant_file_is_modelled`` fails when a new init file touches
# ``roles`` without being listed (and parsed) here.
ROLE_GRANT_FILES = (
    "06_auth_tables.sql",
    "43_medic_permissions.sql",
)

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

ALLOW, DENY, CONDITIONAL = "allow", "deny", "conditional"


# --- role grants ------------------------------------------------------------


def _json_obj(raw: str) -> Dict[str, bool]:
    return {k: bool(v) for k, v in json.loads(raw).items()}


def load_role_grants(init_dir: Path = INIT_SQL) -> Dict[str, Dict[str, bool]]:
    """Each built-in role's effective permission map after every seed file."""
    seed = (init_dir / "06_auth_tables.sql").read_text()
    grants: Dict[str, Dict[str, bool]] = {}
    for role_id, perms in re.findall(
        r"\('(role-[\w-]+)',\s*'[^']*',\s*'[^']*',\s*'(\{.*?\})'", seed, re.S
    ):
        grants[role_id] = _json_obj(perms)

    # 43: grants || permissions — an existing key wins.
    medic = (init_dir / "43_medic_permissions.sql").read_text()
    pairs = re.findall(r"\('(role-[\w-]+)',\s*'(\{.*?\})'::jsonb\)", medic)
    if not pairs:
        raise AssertionError("43_medic_permissions.sql no longer matches the parser")
    for role_id, perms in pairs:
        merged = dict(_json_obj(perms))
        merged.update(grants[role_id])
        grants[role_id] = merged

    missing = set(BUILTIN_ROLES) - set(grants)
    if missing:
        raise AssertionError(f"built-in roles missing from the seed: {missing}")
    return grants


def role_grant_files(init_dir: Path = INIT_SQL) -> List[str]:
    """Init files that write the ``roles`` table."""
    pat = re.compile(r"\b(INSERT\s+INTO|UPDATE)\s+roles\b", re.I)
    return sorted(p.name for p in init_dir.glob("*.sql") if pat.search(p.read_text()))


# --- route inventory ----------------------------------------------------------


def iter_routes(app) -> List[Any]:
    """Every effective route object (handles FastAPI >= 0.137 lazy routers)."""
    found: List[Any] = []

    def visit(obj) -> None:
        if type(obj).__name__ == "_IncludedRouter":
            for candidate in obj.effective_candidates():
                visit(candidate)
            return
        found.append(obj)

    for route in app.routes:
        visit(route)
    return found


def _dependencies(dependant) -> Iterable[Any]:
    if dependant is None:
        return
    for dep in dependant.dependencies:
        yield dep
        yield from _dependencies(dep)


def _closure(fn) -> Dict[str, Any]:
    code = getattr(fn, "__code__", None)
    cells = getattr(fn, "__closure__", None) or ()
    if code is None:
        return {}
    return {n: c.cell_contents for n, c in zip(code.co_freevars, cells)}


# Inline checks inside handler bodies. Group 1 is the permission.
_INLINE_LITERAL = re.compile(
    r"\b(?:_require_permission|_require|check_permission|username_has_permission"
    r"|require_permission)\(\s*[\w\.\[\]\"']*\s*,\s*\"([\w\.]+)\"\s*\)"
)
_INLINE_CONSTANT = re.compile(
    r"\b(?:_require_permission|_require|check_permission|username_has_permission)"
    r"\(\s*[\w\.]+\s*,\s*([A-Z][A-Z_]+)\s*\)"
)
_INLINE_DYNAMIC = re.compile(
    r"\b(?:_require_permission|_require|check_permission)\(\s*[\w\.]+\s*,\s*(?!\")"
    r"(?![A-Z][A-Z_]+\s*\))(\w+)\s*\)"
)
# ``core.agents.internal_auth.authorise(header, what)``: the agent-layer token.
_INTERNAL_TOKEN = re.compile(r"(?<![\w.])authorise\(")
# An inbound receiver's HMAC check over the raw body (webhook shared secret).
_SHARED_SECRET = re.compile(r"\bhmac\.compare_digest\(")
_INLINE_HELPERS = {
    "require_settings_admin(": "settings.write",
    "require_integrations_admin(": "integrations.write",
}


@dataclass
class Gate:
    """What a route asks of the caller, independent of role."""

    public: bool = False
    service_key: bool = False
    internal_token: bool = False
    shared_secret: bool = False
    authenticated: bool = False
    # Permissions checked by a dependency (enforced before the handler runs).
    dep_permissions: List[str] = field(default_factory=list)
    # Permissions checked inside the handler body.
    inline_permissions: List[str] = field(default_factory=list)
    admin_role_only: bool = False
    dynamic: Optional[str] = None
    generator: bool = False

    def describe(self) -> str:
        if self.public:
            return "public"
        parts: List[str] = []
        if self.service_key:
            parts.append("service-key")
        if self.internal_token:
            parts.append("internal-token")
        if self.shared_secret:
            parts.append("webhook-hmac")
        if self.authenticated:
            parts.append("login")
        parts += [f"perm:{p}" for p in self.dep_permissions]
        parts += [f"inline:{p}" for p in self.inline_permissions]
        if self.admin_role_only:
            parts.append("role:admin")
        if self.dynamic:
            parts.append(f"dynamic:{self.dynamic}")
        return " + ".join(parts) or "none"

    @property
    def only_dependency_gates(self) -> bool:
        return not self.inline_permissions and not self.dynamic


def _handler_source(endpoint) -> str:
    try:
        return inspect.getsource(inspect.unwrap(endpoint))
    except (OSError, TypeError):
        return ""


_CALLED = re.compile(r"\b([A-Za-z_]\w*)\(")
# ``asyncio.to_thread(helper, ...)`` / ``run_in_threadpool(helper, ...)``.
_DEFERRED = re.compile(r"\b(?:to_thread|run_in_threadpool)\(\s*([A-Za-z_]\w*)\s*[,)]")
# Names whose bodies are the checks themselves (matched by the patterns above),
# not helpers to descend into.
_CHECKERS = {
    "_require_permission",
    "_require",
    "check_permission",
    "username_has_permission",
    "require_permission",
    "require_settings_admin",
    "require_integrations_admin",
    "authorise",
}
HELPER_DEPTH = 2


def _reachable_source(endpoint, depth: int = HELPER_DEPTH) -> str:
    """The handler's source plus that of the repo functions it calls.

    Module-level helpers in ``core``/``services`` are followed ``depth`` levels
    deep, so a gate in a shared helper (``_lifecycle`` -> ``require_settings_admin``)
    is seen. A check deeper than that, or behind a method call, is not: the row
    then says ``login`` and the reviewer must look.
    """
    fn = inspect.unwrap(endpoint)
    seen: set = set()
    chunks: List[str] = []

    def visit(f, level: int) -> None:
        if f in seen:
            return
        seen.add(f)
        src = _handler_source(f)
        chunks.append(src)
        if level >= depth:
            return
        globs = getattr(f, "__globals__", {})
        for name in set(_CALLED.findall(src)) | set(_DEFERRED.findall(src)):
            if name in _CHECKERS:
                continue
            target = globs.get(name)
            mod = getattr(target, "__module__", "") or ""
            if inspect.isfunction(target) and mod.split(".")[0] in ("core", "services"):
                visit(target, level + 1)

    visit(fn, 0)
    return "\n".join(chunks)


def route_gate(route, method: str, public_patterns, path: Optional[str] = None) -> Gate:
    from fnmatch import fnmatch

    from core.auth.current_user import get_current_user

    gate = Gate()
    path = path or getattr(route, "path_format", None) or route.path
    dependant = getattr(route, "dependant", None)
    calls = [d.call for d in _dependencies(dependant)]
    gate.authenticated = any(c is get_current_user for c in calls)
    for call in calls:
        qual = getattr(call, "__qualname__", "")
        if qual.startswith("require_permission."):
            env = _closure(call)
            if env.get("unsafe_only") and method in _SAFE_METHODS:
                continue
            perm = env.get("permission")
            if perm and perm not in gate.dep_permissions:
                gate.dep_permissions.append(perm)
        elif qual == "require_admin" and "canary" in getattr(call, "__module__", ""):
            gate.admin_role_only = True
        elif getattr(call, "admin_role_only", False) is True:
            # A dependency that declares it admits, of the built-in roles,
            # only role-admin (W1.9's require_sso_administrator).
            gate.admin_role_only = True
        elif qual == "verify_inbound_key":
            gate.service_key = True

    endpoint = getattr(route, "endpoint", None)
    src = _reachable_source(endpoint) if endpoint is not None else ""
    for needle, perm in _INLINE_HELPERS.items():
        if needle in src and perm not in gate.inline_permissions:
            gate.inline_permissions.append(perm)
    if _INTERNAL_TOKEN.search(src):
        gate.internal_token = True
    elif _SHARED_SECRET.search(src):
        gate.shared_secret = True
    for perm in _INLINE_LITERAL.findall(src):
        if perm not in gate.inline_permissions:
            gate.inline_permissions.append(perm)
    globs = getattr(inspect.unwrap(endpoint), "__globals__", {}) if endpoint else {}
    for name in _INLINE_CONSTANT.findall(src):
        value = globs.get(name)
        if isinstance(value, str) and value not in gate.inline_permissions:
            gate.inline_permissions.append(value)
    for name in _INLINE_DYNAMIC.findall(src):
        gate.dynamic = name
    if endpoint is not None:
        fn = inspect.unwrap(endpoint)
        gate.generator = inspect.isgeneratorfunction(
            fn
        ) or inspect.isasyncgenfunction(fn)

    if (
        not gate.authenticated
        and not gate.service_key
        and not gate.internal_token
        and not gate.shared_secret
        and any(path == p or fnmatch(path, p) for p in public_patterns)
    ):
        gate.public = True
    return gate


def role_outcome(gate: Gate, grants: Dict[str, bool], role_id: str) -> str:
    if gate.public:
        return ALLOW
    if (gate.service_key or gate.internal_token or gate.shared_secret) and not (
        gate.authenticated
    ):
        # A user's login is not the inbound key, the agent-layer token or the
        # webhook's shared secret.
        return DENY
    if not gate.authenticated:
        # Not public and no login: the route makes no decision of its own.
        return ALLOW
    if gate.admin_role_only and role_id != "role-admin":
        return DENY
    for perm in gate.dep_permissions + gate.inline_permissions:
        if not grants.get(perm, False):
            return DENY
    if gate.dynamic:
        return CONDITIONAL
    return ALLOW


def route_methods(route) -> List[str]:
    methods = set(getattr(route, "methods", None) or ())
    if "GET" in methods:
        methods.discard("HEAD")
    return sorted(methods)


def route_key(route, method: str) -> str:
    return f"{method} {getattr(route, 'path_format', None) or route.path}"


# Per-variable notes for a permission computed from the request; none today.
DYNAMIC_NOTES: Dict[str, str] = {}


def _strip_context(path: str, context_path: str) -> str:
    if context_path and (path == context_path or path.startswith(context_path + "/")):
        return path[len(context_path):] or "/"
    return path


def is_frontend_route(route) -> bool:
    """The SPA's static mounts and the context-path redirect: not API surface.

    Excluded by rule so the matrix does not depend on whether a frontend build
    (``clients/web/build``) or a context path exists where it is generated.
    """
    from starlette.staticfiles import StaticFiles

    if isinstance(getattr(route, "app", None), StaticFiles):
        return True
    endpoint = getattr(route, "endpoint", None)
    return getattr(endpoint, "__name__", "") in FRONTEND_ENDPOINTS


FRONTEND_ENDPOINTS = frozenset({"redirect_to_trailing_slash"})


def route_inventory(
    main_app=None, context_path: Optional[str] = None, discover: bool = True
):
    """``[(route, path, flag)]`` for every API route, independent of the env.

    Discovered routers are mounted on a scratch app, each with its feature flag
    forced on and no context path; ``flag`` names the ``RouterMeta.enabled``
    predicate (``None`` when always mounted). Routes the main module registers
    itself (health, metrics, docs, the MCP mount) come from the main app, with
    the context path stripped and the frontend removed.
    """
    import dataclasses

    from fastapi import FastAPI

    from services.api import discovery
    from services.api import main as api_main

    main_app = main_app or api_main.app
    if context_path is None:
        context_path = api_main._CONTEXT_PATH if main_app is api_main.app else ""

    import logging

    out: List[Tuple[Any, str, Optional[str]]] = []
    discovered = set()
    real_specs = discovery.load_router_specs
    disc_log = logging.getLogger(discovery.__name__)
    was_disabled, disc_log.disabled = disc_log.disabled, True
    for name, router, meta in real_specs() if discover else ():
        flag = getattr(meta.enabled, "__name__", None) if meta.enabled else None
        forced = dataclasses.replace(meta, enabled=lambda: True)
        scratch = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
        discovery.load_router_specs = lambda _s=(name, router, forced): [_s]
        try:
            discovery.mount_routers(
                scratch, context_path="", auth_dependency=api_main.AUTH_DEPENDENCY
            )
        finally:
            discovery.load_router_specs = real_specs
        for route in iter_routes(scratch):
            discovered.add(getattr(route, "endpoint", None))
            path = getattr(route, "path_format", None) or route.path
            out.append((route, path, flag))
    disc_log.disabled = was_disabled

    for route in iter_routes(main_app):
        if not isinstance(getattr(route, "path", None), str):
            continue
        endpoint = getattr(route, "endpoint", None)
        if endpoint is not None and endpoint in discovered:
            continue
        if is_frontend_route(route):
            continue
        # A Mount's path_format carries a "{path}" tail; its prefix is the key.
        path = route.path if not route_methods(route) else (
            getattr(route, "path_format", None) or route.path
        )
        out.append((route, _strip_context(path, context_path), None))
    return out


MOUNT_NOTES = {
    "McpSurfaceGate": "The mounted app decides: the MCP surface toggle plus the "
    "caller's bearer token (services/api/mcp_surface.py), not a role check here.",
}


def compute_matrix(app=None, public_patterns=None) -> Dict[str, Dict[str, Any]]:
    if public_patterns is None:
        from services.api.main import PUBLIC_API_PATHS

        public_patterns = PUBLIC_API_PATHS
    grants = load_role_grants()
    rows: Dict[str, Dict[str, Any]] = {}
    # An explicit app (tests) is taken as-is; the default is the real API.
    for route, path, flag in route_inventory(app, discover=app is None):
        methods = route_methods(route)
        if not methods:
            # A Mount (sub-app): no method table; the sub-app gates itself.
            kind = type(getattr(route, "app", None)).__name__
            rows[f"MOUNT {path}"] = {
                "gate": f"mount:{kind}",
                **{r: CONDITIONAL for r in BUILTIN_ROLES},
                "note": MOUNT_NOTES.get(kind, "gated by the mounted app itself"),
            }
            continue
        for method in methods:
            gate = route_gate(route, method, public_patterns, path=path)
            row: Dict[str, Any] = {"gate": gate.describe()}
            for role in BUILTIN_ROLES:
                row[role] = role_outcome(gate, grants[role], role)
            if gate.dynamic:
                row["note"] = DYNAMIC_NOTES.get(
                    gate.dynamic, f"permission computed from '{gate.dynamic}'"
                )
            if flag:
                row["flag"] = flag
            rows[f"{method} {path}"] = row
    return dict(sorted(rows.items()))


def load_matrix(path: Path = MATRIX_FILE) -> Dict[str, Dict[str, Any]]:
    return json.loads(path.read_text())["routes"]


def write_matrix(rows: Dict[str, Dict[str, Any]], path: Path = MATRIX_FILE) -> None:
    doc = {
        "_about": (
            "W4.3 role x route authorization matrix. Generated by "
            "`PYTHONPATH=. python -m tests.security.route_matrix --write`; "
            "checked by tests/security/test_route_role_matrix.py. Each row is "
            "'METHOD path' -> gate + outcome per built-in role (DEV_MODE off). "
            "Generated with every feature flag on: a row with 'flag' exists only "
            "while that RouterMeta.enabled predicate is true. Paths exclude "
            "VIGIL_CONTEXT_PATH; frontend static routes are excluded. "
            "Review every changed row: a new 'allow' is a privilege grant."
        ),
        "roles": list(BUILTIN_ROLES),
        "routes": rows,
    }
    path.write_text(json.dumps(doc, indent=1, sort_keys=False) + "\n")


def diff(
    expected: Dict[str, Dict[str, Any]], actual: Dict[str, Dict[str, Any]]
) -> Tuple[List[str], List[str], List[str]]:
    new = sorted(set(actual) - set(expected))
    gone = sorted(set(expected) - set(actual))
    changed = sorted(k for k in set(actual) & set(expected) if actual[k] != expected[k])
    return new, gone, changed


def main(argv: List[str]) -> int:
    os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-not-for-prod")
    rows = compute_matrix()
    if "--write" in argv:
        write_matrix(rows)
        print(f"wrote {len(rows)} rows to {MATRIX_FILE.relative_to(REPO)}")
        return 0
    new, gone, changed = diff(load_matrix(), rows)
    for k in new:
        print(f"+ {k}: {rows[k]}")
    for k in gone:
        print(f"- {k}")
    for k in changed:
        print(f"~ {k}: {rows[k]}")
    return 1 if (new or gone or changed) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
