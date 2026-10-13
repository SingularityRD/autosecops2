#!/usr/bin/env bash
# Run the checks a work package's changes call for, and nothing else.
#
#   scripts/wp/gates.sh [<worktree>] [--base <ref>] [--full] [--dry-run]
#
# Changed files = <worktree> (committed, staged, unstaged, untracked) against
# merge-base(HEAD, <base>). Each changed area pulls in its checks:
#
#   clients/web/**        web:tsc, web:eslint (changed files), web:vitest (related; --full: all)
#   services/agent/**     agent:tsc, agent:vitest (all, incl. Postgres integration)
#   *.py (backend)        py:flake8/black/isort (changed files in services/ core/),
#                         py:import-linter, py:pytest (test dirs related to the change
#                         + tests/unit/_ratchets; --full: tests/unit tests/security)
#   infra/, env.example   py:pytest tests/unit/_ratchets
#   services/medic*/**    <svc>:ruff (check + format), <svc>:pytest (uv, as medic.yml;
#                         venv in <git-dir>/wp-venvs/<svc>, never services/<svc>/.venv)
#   *.sh / bash scripts   sh:syntax (bash -n), sh:shellcheck (if installed)
#   node_modules          git:node_modules FAILS if any tracked node_modules path
#                         is in the diff (always runs)
#
# Backend pytest runs with DEMO_MODE=false MCP_AUTO_CONNECT_ON_STARTUP=false,
# whatever .env says: demo seeding and MCP dials are not under test.
#
# Exit 0 only if every check that ran passed. Logs: <git-dir>/wp-gates/<check>.log
#
# Env (defaults in brackets):
#   GATES_BASE [target/main]         merge-base ref
#   GATES_ENV_SH [/tmp/claude-0/env.sh]  sourced before Python checks (venv + .env)
#   GATES_VENV [/root/vigil/venv]    used when GATES_ENV_SH is missing
#   AGENT_TEST_DATABASE_URL [postgres://test:test@localhost:5432/agent_test]
#   GATES_TIMEOUT [1200]             seconds per check (timeout(1) kills only its child)
#   SHELLCHECK_SEVERITY [warning]
#
# Processes are never killed by name: other agents share this machine.
# shellcheck disable=SC2016  # bash -c bodies use their own positional args, on purpose
set -uo pipefail

usage() { awk 'NR > 1 && /^#/ && !/shellcheck/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit "${1:-2}"; }

base="${GATES_BASE:-target/main}"
full=0
dry=0
wt=""
while [ $# -gt 0 ]; do
  case "$1" in
    --base) base="${2:?--base needs a ref}"; shift 2 ;;
    --full) full=1; shift ;;
    --dry-run) dry=1; shift ;;
    -h|--help) usage 0 ;;
    -*) echo "unknown option: $1" >&2; usage ;;
    *) [ -z "$wt" ] || usage; wt="$1"; shift ;;
  esac
done
wt="$(git -C "${wt:-.}" rev-parse --show-toplevel 2>/dev/null)" || { echo "not a git worktree" >&2; exit 2; }
cd "$wt" || exit 2

env_sh="${GATES_ENV_SH:-/tmp/claude-0/env.sh}"
venv="${GATES_VENV:-/root/vigil/venv}"
agent_dsn="${AGENT_TEST_DATABASE_URL:-postgres://test:test@localhost:5432/agent_test}"
tmo="${GATES_TIMEOUT:-1200}"
sc_sev="${SHELLCHECK_SEVERITY:-warning}"
gitdir="$(git rev-parse --absolute-git-dir)"
logdir="$gitdir/wp-gates"
mkdir -p "$logdir"
rm -f "$logdir"/*.log

# Bootstrap safety: node_modules is symlinked into worktrees, and .gitignore's
# "node_modules/" does not match a symlink. info/exclude is shared by every
# worktree of the repo; the line is idempotent.
exclude="$(git rev-parse --path-format=absolute --git-path info/exclude)"
if ! grep -qxF node_modules "$exclude" 2>/dev/null; then
  mkdir -p "$(dirname "$exclude")" && printf 'node_modules\n' >>"$exclude"
fi

mb="$(git merge-base HEAD "$base" 2>/dev/null)" || { echo "no merge-base between HEAD and '$base'" >&2; exit 2; }

# --- changed files ---------------------------------------------------------
nm_re='(^|/)node_modules(/|$)'
mapfile -t changed < <(
  { git diff --name-only "$mb"; git ls-files --others --exclude-standard; } \
    | grep -Ev "$nm_re" | sort -u
)
# Tracked (committed or staged) node_modules paths added or modified in the diff:
# never wanted. Deletions (the "git rm --cached" fix itself) are excluded.
mapfile -t tracked_nm < <(git diff --name-only --diff-filter=d "$mb" | grep -E "$nm_re" | sort -u)
exists() { [ -e "$1" ] || [ -L "$1" ]; }
# changed files that still exist, matching an extended regex
pick() { local f; for f in "${changed[@]}"; do [[ "$f" =~ $1 ]] && exists "$f" && printf '%s\n' "$f"; done; }
any() { local f; for f in "${changed[@]}"; do [[ "$f" =~ $1 ]] && return 0; done; return 1; }

echo "worktree:   $wt"
echo "head:       $(git rev-parse --short HEAD) $(git rev-parse --abbrev-ref HEAD)"
base_label="$base"; [[ "$base" =~ ^[0-9a-f]{40}$ ]] && base_label="${base:0:8}"
echo "merge-base: $(git rev-parse --short "$mb") ($base_label)"
echo "changed:    ${#changed[@]} file(s)"
if [ ${#changed[@]} -eq 0 ] && [ ${#tracked_nm[@]} -eq 0 ]; then echo "RESULT: PASS (nothing changed)"; exit 0; fi

# --- runner ----------------------------------------------------------------
results=()
failed=0
run() { # run <name> <command...>
  local name="$1"; shift
  local log="$logdir/${name//[:\/]/_}.log" t0 rc
  if [ "$dry" = 1 ]; then results+=("PLAN  $name: $*"); return 0; fi
  t0=$SECONDS
  printf '  .. %s\n' "$name"
  # bash -c so exported helpers (py) run under timeout like any command.
  timeout -k 10 "$tmo" bash -c '"$@"' _ "$@" >"$log" 2>&1
  rc=$?
  if [ $rc -eq 0 ]; then
    results+=("PASS  $name ($((SECONDS - t0))s)")
  else
    [ $rc -eq 124 ] && echo "TIMEOUT after ${tmo}s" >>"$log"
    results+=("FAIL  $name ($((SECONDS - t0))s, exit $rc) log: $log")
    failed=1
  fi
}
skip() { results+=("SKIP  $1: $2"); }
note() { results+=("NOTE  $1"); }

# --- node_modules ----------------------------------------------------------
if [ ${#tracked_nm[@]} -gt 0 ]; then
  run git:node_modules bash -c 'echo "tracked node_modules path(s) in the diff (git rm --cached them):"; printf "  %s\n" "$@" | head -n 50; echo "  ($# path(s))"; exit 1' _ "${tracked_nm[@]}"
else
  [ "$dry" = 1 ] && results+=("PLAN  git:node_modules: no tracked node_modules paths in the diff")
  [ "$dry" = 1 ] || results+=("PASS  git:node_modules (no tracked paths in the diff)")
fi

# Borrow node_modules from the main checkout when the worktree has none.
main_wt="$(git worktree list --porcelain | sed -n '1s/^worktree //p')"
ensure_node_modules() {
  local d="$1"
  [ -e "$d/node_modules" ] && return 0
  if [ -d "$main_wt/$d/node_modules" ]; then
    ln -s "$main_wt/$d/node_modules" "$d/node_modules"
    if ! cmp -s "$d/package-lock.json" "$main_wt/$d/package-lock.json"; then
      note "$d/package-lock.json differs from $main_wt; borrowed node_modules may be stale (npm ci in $d)"
    fi
    return 0
  fi
  return 1
}

# Python checks run in a subshell that has the venv and .env loaded, rooted in
# the worktree (env.sh cds to the main checkout; PYTHONPATH pins the worktree).
py() {
  (
    set +u
    if [ -f "$env_sh" ]; then
      # shellcheck disable=SC1090
      source "$env_sh" >/dev/null 2>&1
    else
      # shellcheck disable=SC1091
      source "$venv/bin/activate"
    fi
    cd "$wt" || exit 2
    export PYTHONPATH="$wt" TESTING=true
    "$@"
  )
}
export -f py
export env_sh venv wt

# --- web -------------------------------------------------------------------
if any '^clients/web/'; then
  if ensure_node_modules clients/web; then
    run web:tsc bash -c 'cd clients/web && ./node_modules/.bin/tsc --noEmit'
    mapfile -t wf < <(pick '^clients/web/.*\.(ts|tsx|js|jsx)$' | sed 's|^clients/web/||')
    if [ ${#wf[@]} -gt 0 ]; then
      run web:eslint bash -c 'cd clients/web && ./node_modules/.bin/eslint --no-warn-ignored --report-unused-disable-directives "$@"' _ "${wf[@]}"
    else
      skip web:eslint "no changed ts/js files"
    fi
    if [ "$full" = 1 ] || any '^clients/web/(package(-lock)?\.json|vitest\.config\.ts|vite\.config\.ts|tsconfig.*\.json|src/test/)'; then
      run web:vitest bash -c 'cd clients/web && ./node_modules/.bin/vitest run'
    elif [ ${#wf[@]} -gt 0 ]; then
      run web:vitest bash -c 'cd clients/web && ./node_modules/.bin/vitest related --run --passWithNoTests "$@"' _ "${wf[@]}"
    else
      skip web:vitest "no changed ts/js files"
    fi
  else
    run web:deps bash -c 'echo "clients/web/node_modules missing (npm ci in clients/web)"; exit 1'
  fi
fi

# --- agent -----------------------------------------------------------------
if any '^services/agent/'; then
  if ensure_node_modules services/agent; then
    run agent:tsc bash -c 'cd services/agent && ./node_modules/.bin/tsc --noEmit'
    # The integration tests silently pass against nothing only if the DSN is
    # wrong; check it answers first so a dead database fails loudly here.
    if command -v pg_isready >/dev/null && ! pg_isready -q -d "$agent_dsn" -t 5; then
      run agent:vitest bash -c 'echo "AGENT_TEST_DATABASE_URL does not answer: $1 (scripts/agent_testdb.sh, or export a *_test DSN)"; exit 1' _ "$agent_dsn"
    else
      run agent:vitest env AGENT_TEST_DATABASE_URL="$agent_dsn" bash -c 'cd services/agent && ./node_modules/.bin/vitest run'
    fi
  else
    run agent:deps bash -c 'echo "services/agent/node_modules missing (npm ci in services/agent)"; exit 1'
  fi
fi

# --- backend python --------------------------------------------------------
medic_re='^(services/medic(_gateway|_dockerproxy)?|scripts/medic)/'
mapfile -t pyf < <(pick '\.py$' | grep -Ev "$medic_re")
mapfile -t pylint < <(printf '%s\n' "${pyf[@]}" | grep -E '^(services|core)/' | grep -v '^services/medic/contracts/')
if [ ${#pylint[@]} -gt 0 ]; then
  run py:flake8 py flake8 "${pylint[@]}"
  run py:black py black --check --diff "${pylint[@]}"
  run py:isort py isort --check-only --diff "${pylint[@]}"
  [ -f .importlinter ] && run py:import-linter py lint-imports
fi
# Root has no ruff config (only the medic projects do), so ruff runs there only.

# Map changed backend files to test targets.
targets=()
add() { [ -e "$1" ] && targets+=("$1"); }
deleted_py=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if ! exists "$f"; then deleted_py=1; continue; fi
  case "$f" in
    tests/*)
      case "$(basename "$f")" in
        test_*.py) add "$f" ;;
        *) add "$(dirname "$f")" ;;   # conftest, fixtures, helpers
      esac
      continue ;;
  esac
  # Tests importing the module, by dotted path or "from <pkg> import <name>".
  mod="${f%.py}"; mod="${mod%/__init__}"; mod="${mod//\//.}"
  pkg="${mod%.*}"; leaf="${mod##*.}"
  while IFS= read -r t; do add "$t"; done < <(
    grep -rlE --include='test_*.py' \
      -e "(from|import)[[:space:]]+${mod//./\\.}([[:space:].]|$)" \
      -e "from[[:space:]]+${pkg//./\\.}[[:space:]]+import[[:space:]].*\\b${leaf}\\b" \
      tests/unit tests/security 2>/dev/null
  )
  # tests/unit/<segment> for each path segment (core/integrations/x.py -> tests/unit/integrations).
  IFS=/ read -ra segs <<<"${f%.py}"
  for s in "${segs[@]}"; do [ -d "tests/unit/$s" ] && add "tests/unit/$s"; done
done < <(printf '%s\n' "${changed[@]}" | grep -E '\.py$' | grep -Ev "$medic_re")
if [ ${#pyf[@]} -gt 0 ] || [ "$deleted_py" = 1 ] || any '^(infra/|env\.example$|docker-compose|start\.sh$|shutdown_all\.sh$|scripts/.*\.py$)'; then
  add tests/unit/_ratchets
fi
if [ ${#targets[@]} -gt 0 ]; then
  mapfile -t targets < <(printf '%s\n' "${targets[@]}" | sort -u)
  # A directory target makes its files redundant.
  pruned=()
  for t in "${targets[@]}"; do
    keep=1
    for d in "${targets[@]}"; do [ "$d" != "$t" ] && [ -d "$d" ] && [[ "$t" == "$d"/* ]] && keep=0; done
    [ $keep = 1 ] && pruned+=("$t")
  done
  if [ "$full" = 1 ] || [ ${#pruned[@]} -gt 40 ]; then pruned=(tests/unit tests/security); fi
  note "pytest targets: ${pruned[*]}"
  run py:pytest py env DEMO_MODE=false MCP_AUTO_CONNECT_ON_STARTUP=false \
    python -m pytest -c tests/pytest.ini --rootdir=. -o addopts= -p no:cacheprovider \
    --asyncio-mode=auto --strict-markers -m "not external_service" -q -ra "${pruned[@]}"
fi

# --- medic (own uv projects, as .github/workflows/medic.yml) ----------------
for svc in medic medic_gateway medic_dockerproxy; do
  any "^services/$svc/" || { [ "$svc" = medic ] && any '^scripts/medic/'; } || continue
  if command -v ruff >/dev/null; then
    run "$svc:ruff" bash -c 'ruff check "services/$1" && ruff format --check "services/$1"' _ "$svc"
  else
    skip "$svc:ruff" "ruff not installed"
  fi
  if command -v uv >/dev/null; then
    # Outside the source tree, as medic.yml's UV_PROJECT_ENVIRONMENT: a
    # services/<svc>/.venv would be scanned by the ratchets (and untracked).
    run "$svc:pytest" env UV_PROJECT_ENVIRONMENT="$gitdir/wp-venvs/$svc" \
      bash -c 'uv sync --quiet --project "services/$1" --frozen && uv run --no-sync --project "services/$1" pytest -q "services/$1"' _ "$svc"
  else
    run "$svc:pytest" bash -c 'echo "uv not installed"; exit 1'
  fi
done

# --- shell -----------------------------------------------------------------
shf=()
for f in "${changed[@]}"; do
  exists "$f" && [ -f "$f" ] || continue
  case "$f" in
    *.sh) shf+=("$f") ;;
    *.*|*node_modules*) ;;
    *) head -c 64 "$f" 2>/dev/null | grep -qE '^#!.*\b(ba)?sh\b' && shf+=("$f") ;;
  esac
done
if [ ${#shf[@]} -gt 0 ]; then
  run sh:syntax bash -c 'rc=0; for f; do bash -n "$f" || rc=1; done; exit $rc' _ "${shf[@]}"
  if command -v shellcheck >/dev/null; then
    run sh:shellcheck shellcheck -x -S "$sc_sev" "${shf[@]}"
  else
    skip sh:shellcheck "not installed"
  fi
fi

# --- summary ---------------------------------------------------------------
echo
echo "== gates: $(git rev-parse --short HEAD) vs $(git rev-parse --short "$mb") =="
[ ${#results[@]} -gt 0 ] || results+=("NOTE  no checks apply to the changed files (docs only?)")
printf '%s\n' "${results[@]}"
if [ "$failed" = 1 ]; then
  for r in "${results[@]}"; do
    [[ "$r" == FAIL* ]] || continue
    log="${r##*log: }"
    echo
    echo "--- ${r%% (*} (last 25 lines of $log)"
    tail -n 25 "$log"
  done
  echo
  echo "RESULT: FAIL"
  exit 1
fi
echo "RESULT: PASS"
