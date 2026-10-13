# shellcheck shell=bash
# HTTP helpers for talking to a running AutoSecOps backend. Sourced after
# common.sh. Needs STAGING_BASE_URL (e.g. http://127.0.0.1:16987).
#
# Secrets (password, bearer token) never go on a command line: request bodies
# go through stdin, the Authorization header through a curl config read from a
# process substitution. `ps` shows neither.

API_STATUS=""
API_BODY=""
API_TOKEN="${API_TOKEN:-}"

: "${STAGING_CURL_TIMEOUT:=30}"

# api_call METHOD PATH [extra curl args...]
# Sets API_STATUS (HTTP code, "000" on connection failure) and API_BODY.
# A request body, when needed, is passed with `--data-binary @-` and a
# here-string on stdin (never a pipe into api_call: that is a subshell).
api_call() {
  local method="$1" path="$2"
  shift 2
  local out
  out="$(mktemp)"
  API_STATUS="$(
    curl -sS -o "$out" -w '%{http_code}' --max-time "$STAGING_CURL_TIMEOUT" \
      -X "$method" \
      -K <(if [ -n "$API_TOKEN" ]; then printf 'header = "Authorization: Bearer %s"\n' "$API_TOKEN"; fi) \
      "$@" "${STAGING_BASE_URL%/}${path}" 2>/dev/null
  )" || API_STATUS="${API_STATUS:-000}"
  [ -n "$API_STATUS" ] || API_STATUS="000"
  API_BODY="$(cat "$out")"
  rm -f "$out"
}

# JSON body from environment variables, so values never hit argv.
# json_from_env KEY=ENVVAR [KEY=ENVVAR...]
json_from_env() {
  python3 -c '
import json, os, sys
doc = {}
for spec in sys.argv[1:]:
    key, var = spec.split("=", 1)
    doc[key] = os.environ.get(var, "")
print(json.dumps(doc))
' "$@"
}

# Wait until GET /api/health answers 200 (liveness), up to $1 seconds.
api_wait_up() {
  local deadline=$(( $(date +%s) + ${1:-300} ))
  while :; do
    api_call GET /api/health
    [ "$API_STATUS" = "200" ] && return 0
    [ "$(date +%s)" -ge "$deadline" ] && return 1
    sleep "${STAGING_POLL_INTERVAL:-5}"
  done
}

# Create the first admin from STAGING_ADMIN_* when the instance has no user.
# A second run finds `required: false` and does nothing.
api_ensure_admin() {
  : "${STAGING_ADMIN_USER:?STAGING_ADMIN_USER yok (admin.env)}"
  : "${STAGING_ADMIN_EMAIL:?STAGING_ADMIN_EMAIL yok (admin.env)}"
  : "${STAGING_ADMIN_PASSWORD:?STAGING_ADMIN_PASSWORD yok (admin.env)}"
  api_call GET /api/auth/bootstrap
  [ "$API_STATUS" = "200" ] || { log "bootstrap durumu okunamadı (HTTP $API_STATUS)"; return 1; }
  if [ "$(json_get "$API_BODY" required)" != "true" ]; then
    return 0
  fi
  log "ilk yönetici hesabı oluşturuluyor: $STAGING_ADMIN_USER"
  local body
  body="$(json_from_env username=STAGING_ADMIN_USER email=STAGING_ADMIN_EMAIL \
      password=STAGING_ADMIN_PASSWORD full_name=STAGING_ADMIN_USER)"
  # Here-string, not a pipe: a pipe would run api_call in a subshell and lose
  # API_STATUS/API_BODY.
  api_call POST /api/auth/bootstrap -H 'Content-Type: application/json' --data-binary @- <<<"$body"
  case "$API_STATUS" in
    201|200) return 0 ;;
    *) log "ilk yönetici oluşturulamadı (HTTP $API_STATUS)"; return 1 ;;
  esac
}

# Log in as STAGING_ADMIN_*; sets API_TOKEN. The endpoint allows 5/min.
api_login() {
  API_TOKEN=""
  local body
  body="$(json_from_env username_or_email=STAGING_ADMIN_USER password=STAGING_ADMIN_PASSWORD)"
  api_call POST /api/auth/login -H 'Content-Type: application/json' --data-binary @- <<<"$body"
  if [ "$API_STATUS" != "200" ]; then
    log "giriş başarısız (HTTP $API_STATUS)"
    return 1
  fi
  API_TOKEN="$(json_get "$API_BODY" access_token)"
  [ -n "$API_TOKEN" ] || { log "giriş yanıtında access_token yok"; return 1; }
}

# api_ingest_jsonl FILE — POST a JSONL file of findings to /api/ingest/ingest-string.
# Sets API_STATUS/API_BODY; returns non-zero unless the API reports success.
api_ingest_jsonl() {
  local file="$1"
  api_call POST /api/ingest/ingest-string \
    -F "data=<${file}" -F format=jsonl -F data_type=finding
  [ "$API_STATUS" = "200" ] || return 1
  [ "$(json_get "$API_BODY" success)" = "true" ]
}
