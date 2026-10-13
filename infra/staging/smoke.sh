#!/usr/bin/env bash
# AutoSecOps staging smoke test: health -> first admin (once) -> login ->
# ingest one finding -> read it back -> wait until the daemon has triaged it
# with the configured (local) model.
#
#   STAGING_BASE_URL=http://127.0.0.1:16987 infra/staging/smoke.sh
#
# Credentials come from $STAGING_ETC_DIR/admin.env (STAGING_ADMIN_USER,
# STAGING_ADMIN_EMAIL, STAGING_ADMIN_PASSWORD) unless already in the env.
#
# Env (defaults):
#   SMOKE_TRIAGE_TIMEOUT [900]  seconds to wait for ai_triage (CPU model + 60 s sweep)
#   SMOKE_SKIP_TRIAGE    [0]    1 = stop after read-back (no model on this box)
#   SMOKE_REPORT         []     path to write a JSON summary to
#   STAGING_POLL_INTERVAL [10]
#
# Exit 0 only if every step passed. Prints "SMOKE: PASS" / "SMOKE: FAIL <step>".
# shellcheck source-path=SCRIPTDIR
set -euo pipefail
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
# shellcheck source=lib/api.sh
source "$STAGING_LIB_DIR/api.sh"

: "${STAGING_BASE_URL:?STAGING_BASE_URL gerekli (ör. http://127.0.0.1:16987)}"
: "${SMOKE_TRIAGE_TIMEOUT:=900}"
: "${SMOKE_SKIP_TRIAGE:=0}"
: "${STAGING_POLL_INTERVAL:=10}"
export STAGING_POLL_INTERVAL
if [ -z "${STAGING_ADMIN_PASSWORD:-}" ]; then
  load_env_file "$STAGING_ETC_DIR/admin.env"
fi

step="init"
finding_id="smoke-$(date -u +%Y%m%d%H%M%S)-$RANDOM"
triage_action=""
started=$(date +%s)
tmp="$(mktemp -d)"

finish() {
  local rc=$?
  local result="PASS"
  rm -rf "$tmp"
  [ "$rc" -eq 0 ] || result="FAIL"
  if [ -n "${SMOKE_REPORT:-}" ]; then
    SMOKE_RESULT="$result" SMOKE_STEP="$step" SMOKE_FINDING="$finding_id" \
    SMOKE_ACTION="$triage_action" SMOKE_SECS="$(( $(date +%s) - started ))" \
      python3 -c '
import json, os, sys
keys = {"result": "SMOKE_RESULT", "step": "SMOKE_STEP", "finding_id": "SMOKE_FINDING",
        "recommended_action": "SMOKE_ACTION"}
doc = {k: os.environ[v] for k, v in keys.items()}
doc["seconds"] = int(os.environ["SMOKE_SECS"])
open(sys.argv[1], "w").write(json.dumps(doc) + "\n")
' "$SMOKE_REPORT" || true
  fi
  if [ "$rc" -eq 0 ]; then
    echo "SMOKE: PASS"
  else
    echo "SMOKE: FAIL $step"
  fi
}
trap finish EXIT

# 1. Health: liveness answers, storage is up, auth is NOT bypassed.
step="health"
api_wait_up 300 || die "/api/health yanıt vermiyor (HTTP $API_STATUS)"
api_call GET /api/health/ready
[ "$API_STATUS" = "200" ] || die "/api/health/ready HTTP $API_STATUS"
[ "$(json_get "$API_BODY" status)" = "healthy" ] || die "sağlık durumu: $(json_get "$API_BODY" status)"
[ "$(json_get "$API_BODY" auth_bypassed)" = "false" ] || die "kimlik doğrulama atlanıyor (DEV_MODE açık?)"
log "sağlık: healthy, sürüm $(json_get "$API_BODY" version)"

# 2. First admin (only on an empty instance), then login.
step="login"
api_ensure_admin || die "ilk yönetici adımı başarısız"
api_login || die "giriş başarısız"
log "giriş: tamam"

# 3. Ingest one finding.
step="ingest"
SMOKE_FINDING_ID="$finding_id" python3 -c '
import json, os
from datetime import datetime, timezone
fid = os.environ["SMOKE_FINDING_ID"]
print(json.dumps({
    "finding_id": fid,
    "external_id": fid,
    "data_source": "staging-smoke",
    "title": "Staging smoke: encoded PowerShell from Office macro",
    "description": "WINWORD.EXE on WS-SMOKE-01 spawned powershell.exe with an encoded "
                   "command that downloaded a binary from 203.0.113.10 into a temp folder "
                   "and executed it. The binary is unsigned and was first seen today.",
    "severity": "high",
    "anomaly_score": 0.91,
    "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "entity_context": {"hostnames": ["WS-SMOKE-01"], "src_ips": ["192.0.2.10"],
                       "dest_ips": ["203.0.113.10"], "usernames": ["smoke.user"],
                       "file_hashes": []},
    "mitre_predictions": {"T1059.001": 0.8},
}))
' >"$tmp/finding.jsonl"
api_ingest_jsonl "$tmp/finding.jsonl" || die "yükleme başarısız (HTTP $API_STATUS): $API_BODY"
[ "$(json_get "$API_BODY" findings_imported)" = "1" ] || die "bulgu içe alınmadı: $(json_get "$API_BODY" message)"
log "yükleme: $finding_id"

# 4. Read it back through the frozen v1 surface.
step="readback"
api_call GET "/api/v1/findings/$finding_id"
[ "$API_STATUS" = "200" ] || die "bulgu okunamadı (HTTP $API_STATUS)"
[ "$(json_get "$API_BODY" finding_id)" = "$finding_id" ] || die "okunan bulgu kimliği uyuşmuyor"

# 5. Triage by the daemon's backfill sweep, through the configured model.
step="triage"
if [ "$SMOKE_SKIP_TRIAGE" = "1" ]; then
  log "triage adımı atlandı (SMOKE_SKIP_TRIAGE=1)"
  exit 0
fi
deadline=$(( $(date +%s) + SMOKE_TRIAGE_TIMEOUT ))
last_error=""
while :; do
  api_call GET "/api/v1/findings/$finding_id"
  if [ "$API_STATUS" = "200" ]; then
    triage="$(json_get "$API_BODY" ai_enrichment.ai_triage)"
    [ -n "$triage" ] || triage="$(json_get "$API_BODY" ai_triage)"
    if [ -n "$triage" ]; then
      triage_action="$(json_get "$triage" result.recommended_action)"
      log "triage: tamam (recommended_action=${triage_action:-yok})"
      break
    fi
    last_error="$(json_get "$API_BODY" ai_enrichment.ai_triage_error)"
  fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    die "triage ${SMOKE_TRIAGE_TIMEOUT} sn içinde gelmedi${last_error:+ (son hata: $last_error)}"
  fi
  sleep "$STAGING_POLL_INTERVAL"
done
