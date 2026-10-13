#!/usr/bin/env bash
# Load the AutoSecOps staging demo data: the first $DEMO_LIMIT alerts of each
# eval-corpus split in $DEMO_SUITES, ingested as findings with ids prefixed
# "demo-". Idempotent: the ids are stable, so a second run is reported as
# "skipped" by the API and adds nothing. The daemon triages them with the
# local model on its next sweeps; response actions are off in staging.
#
#   STAGING_BASE_URL=http://127.0.0.1:16987 infra/staging/seed-demo.sh
#
# Credentials: $STAGING_ETC_DIR/admin.env (see bootstrap.sh).
set -euo pipefail
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
# shellcheck source=lib/api.sh
source "$STAGING_LIB_DIR/api.sh"

load_env_file "$STAGING_ETC_DIR/staging.env"
: "${STAGING_BASE_URL:?STAGING_BASE_URL gerekli}"
: "${DEMO_SUITES:=dev}"
: "${DEMO_LIMIT:=40}"
: "${DEMO_TAG:=demo}"
if [ -z "${STAGING_ADMIN_PASSWORD:-}" ]; then
  load_env_file "$STAGING_ETC_DIR/admin.env"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

count="$(python3 "$STAGING_LIB_DIR/corpus_to_findings.py" \
  --suites "$DEMO_SUITES" --limit "$DEMO_LIMIT" --tag "$DEMO_TAG" --out-dir "$work")"
log "demo verisi: $count bulgu ($DEMO_SUITES, her birinden ilk $DEMO_LIMIT)"

api_wait_up 300 || die "API yanıt vermiyor"
api_ensure_admin || die "ilk yönetici adımı başarısız"
api_login || die "giriş başarısız"

imported=0 skipped=0
for batch in "$work"/batch-*.jsonl; do
  [ -e "$batch" ] || continue
  api_ingest_jsonl "$batch" || die "yükleme başarısız ($(basename "$batch"), HTTP $API_STATUS): $(json_get "$API_BODY" message)"
  imported=$(( imported + $(json_get "$API_BODY" findings_imported) ))
  skipped=$(( skipped + $(json_get "$API_BODY" findings_skipped) ))
done
log "demo verisi: $imported yeni, $skipped zaten vardı"
echo "SEED: imported=$imported skipped=$skipped"
