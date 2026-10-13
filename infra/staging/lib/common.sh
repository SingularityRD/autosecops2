# shellcheck shell=bash
# Shared helpers for the AutoSecOps staging scripts. Sourced, never run.
#
# DRY_RUN=1 makes `run` print the command instead of running it; every
# mutating step in the staging scripts goes through `run` (or checks
# `is_dry_run` itself), so a dry run touches nothing.

STAGING_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGING_DIR="$(cd "$STAGING_LIB_DIR/.." && pwd)"
STAGING_REPO_ROOT="$(cd "$STAGING_DIR/../.." && pwd)"
export STAGING_LIB_DIR STAGING_DIR STAGING_REPO_ROOT

# Fixed VM layout. Overridable so tests can point them at a temp dir.
: "${STAGING_ETC_DIR:=/etc/autosecops-staging}"
: "${STAGING_STATE_DIR:=/var/lib/autosecops-staging}"
: "${STAGING_SRC_DIR:=/opt/autosecops-staging/src}"
: "${STAGING_NAMESPACE:=autosecops-staging}"
: "${STAGING_RELEASE:=autosecops}"
export STAGING_ETC_DIR STAGING_STATE_DIR STAGING_SRC_DIR STAGING_NAMESPACE STAGING_RELEASE

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { log "HATA: $*"; exit 1; }

is_dry_run() { [ "${DRY_RUN:-0}" = "1" ]; }

# Run a command, or print it under DRY_RUN=1. Arguments are printed quoted so
# the plan can be pasted back into a shell.
run() {
  if is_dry_run; then
    printf '+ %s\n' "$(printf '%q ' "$@" | sed 's/ $//')"
    return 0
  fi
  "$@"
}

require_cmd() {
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || die "'$c' bulunamadı"
  done
}

# Load a KEY=VALUE env file if it exists. Values are not echoed.
load_env_file() {
  local f="$1"
  [ -f "$f" ] || return 0
  set -a
  # shellcheck disable=SC1090
  . "$f"
  set +a
}

# json_get <json> <dotted.path> — prints the value ("" when missing). Strings
# print raw, everything else as JSON. Uses python3 so no jq is needed.
json_get() {
  python3 -c '
import json, sys
try:
    cur = json.loads(sys.argv[1])
except ValueError:
    sys.exit(0)
for part in sys.argv[2].split(".") if sys.argv[2] else []:
    if isinstance(cur, dict) and part in cur:
        cur = cur[part]
    else:
        sys.exit(0)
print(cur if isinstance(cur, str) else json.dumps(cur))
' "$1" "$2"
}

# Random URL-safe secret of N bytes of entropy (default 48).
gen_secret() {
  python3 -c 'import secrets, sys; print(secrets.token_urlsafe(int(sys.argv[1])))' "${1:-48}"
}
