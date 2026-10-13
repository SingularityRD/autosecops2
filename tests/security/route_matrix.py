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
    "17_loglm_setup.sql",
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

    # 17: UPDATE roles SET permissions = permissions || '{...}' WHERE role_id IN (...)
    loglm = (init_dir / "17_loglm_setup.sql").read_text()
    m = re.search(
        r"permissions\s*\|\|\s*'(\{.*?\})'::jsonb.*?role_id IN \(([^)]*)\)",
        loglm,
        re.S,
    )
    if not m:
        raise AssertionError("17_loglm_setup.sql no longer matches the parser")
    add = _json_obj(m.group(1))
    for role_id in re.findall(r"'(role-[\w-]+)'", m.group(2)):
        # The file only grants when the key is absent or false.
        for k, v in add.items():
            if not grants[role_id].get(k):
                grants[role_id][k] = v

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
_INLINE_HELPERS = {
    "require_settings_admin(": "settings.write",
    "require_integrations_admin(": "integrations.write",
}


@dataclass
class Gate:
    """What a route asks of the caller, independent of role."""

    public: bool = False
    service_key: bool = False
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


def route_gate(route, method: str, public_patterns) -> Gate:
    from fnmatch import fnmatch

    from core.auth.current_user import get_current_user

    gate = Gate()
    path = getattr(route, "path_format", None) or route.path
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
        elif qual == "verify_inbound_key":
            gate.service_key = True

    endpoint = getattr(route, "endpoint", None)
    src = _reachable_source(endpoint) if endpoint is not None else ""
    for needle, perm in _INLINE_HELPERS.items():
        if needle in src and perm not in gate.inline_permissions:
            gate.inline_permissions.append(perm)
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
        and any(path == p or fnmatch(path, p) for p in public_patterns)
    ):
        gate.public = True
    return gate


def role_outcome(gate: Gate, grants: Dict[str, bool], role_id: str) -> str:
    if gate.public:
        return ALLOW
    if gate.service_key and not gate.authenticated:
        return DENY  # a user's login is not the inbound key
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


DYNAMIC_NOTES = {
    "required": "Permission is '<integration_id>.view', computed from the path: "
    "only a role holding that extension's view grant (loglm.view: Analyst and up) "
    "may mint a session token.",
}


def compute_matrix(app=None, public_patterns=None) -> Dict[str, Dict[str, Any]]:
    if app is None or public_patterns is None:
        from services.api.main import PUBLIC_API_PATHS
        from services.api.main import app as main_app

        app = app or main_app
        public_patterns = public_patterns or PUBLIC_API_PATHS
    grants = load_role_grants()
    rows: Dict[str, Dict[str, Any]] = {}
    for route in iter_routes(app):
        if not isinstance(getattr(route, "path", None), str):
            continue
        methods = route_methods(route)
        if not methods:
            # A Mount (static files, sub-app): no method table.
            rows[f"MOUNT {route.path}"] = {
                "gate": "mount",
                **{r: ALLOW for r in BUILTIN_ROLES},
            }
            continue
        for method in methods:
            gate = route_gate(route, method, public_patterns)
            row: Dict[str, Any] = {"gate": gate.describe()}
            for role in BUILTIN_ROLES:
                row[role] = role_outcome(gate, grants[role], role)
            if gate.dynamic:
                row["note"] = DYNAMIC_NOTES.get(
                    gate.dynamic, f"permission computed from '{gate.dynamic}'"
                )
            rows[route_key(route, method)] = row
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
