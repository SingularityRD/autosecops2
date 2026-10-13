#!/usr/bin/env bash
# Replay eval-corpus alerts into AutoSecOps staging and score the local
# model's triage against the corpus labels. Run by
# autosecops-staging-replay.service after the nightly install; safe by hand.
#
#   infra/staging/replay.sh
#
# 1. corpus_to_findings.py: first $REPLAY_LIMIT alerts of each suite in
#    $REPLAY_SUITES, ids re-tagged "r<UTC yymmddHHMM>-" so every run lands as
#    new findings (labels never leave the VM; only the alert is sent)
# 2. ingest through /api/ingest/ingest-string
# 3. wait up to $REPLAY_WAIT_MINUTES for the daemon to triage them
# 4. replay_report.py -> $STAGING_STATE_DIR/replay/<tag>/report.json and
#    $STAGING_STATE_DIR/replay/latest.json (symlink)
#
# Exit non-zero if ingestion fails or coverage stays below
# $REPLAY_MIN_COVERAGE (default 0: report only).
set -euo pipefail
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

load_env_file "$STAGING_ETC_DIR/staging.env"
: "${REPLAY_SUITES:=test,injection}"
: "${REPLAY_LIMIT:=25}"
: "${REPLAY_WAIT_MINUTES:=60}"
: "${REPLAY_MIN_COVERAGE:=0}"
: "${STAGING_POLL_INTERVAL:=30}"
export STAGING_POLL_INTERVAL
if [ -z "${STAGING_ADMIN_PASSWORD:-}" ]; then
  load_env_file "$STAGING_ETC_DIR/admin.env"
fi

# shellcheck source=lib/api.sh
source "$STAGING_LIB_DIR/api.sh"
# shellcheck source=lib/cluster.sh
source "$STAGING_LIB_DIR/cluster.sh"

# Never alongside a nightly install (same port-forward, half-rolled pods).
mkdir -p "$STAGING_STATE_DIR"
exec 9>"$STAGING_STATE_DIR/nightly.lock"
flock -w "${REPLAY_LOCK_WAIT:-10800}" 9 || die "gece kurulumu bitmedi"

tag="${REPLAY_TAG:-r$(date -u +%y%m%d%H%M)}"
out="$STAGING_STATE_DIR/replay/$tag"
mkdir -p "$out"
trap stop_port_forward EXIT

count="$(python3 "$STAGING_LIB_DIR/corpus_to_findings.py" \
  --suites "$REPLAY_SUITES" --limit "$REPLAY_LIMIT" --tag "$tag" --out-dir "$out")"
log "replay $tag: $count uyarı ($REPLAY_SUITES)"

start_port_forward || die "backend'e ulaşılamıyor"
api_wait_up 300 || die "API yanıt vermiyor"
api_ensure_admin || die "ilk yönetici adımı başarısız"
api_login || die "giriş başarısız"

for batch in "$out"/batch-*.jsonl; do
  [ -e "$batch" ] || continue
  api_ingest_jsonl "$batch" || die "yükleme başarısız ($(basename "$batch"), HTTP $API_STATUS)"
done
log "replay $tag: yüklendi; triage bekleniyor (en çok $REPLAY_WAIT_MINUTES dk)"

export API_TOKEN STAGING_BASE_URL
deadline=$(( $(date +%s) + REPLAY_WAIT_MINUTES * 60 ))
while :; do
  python3 "$STAGING_LIB_DIR/replay_report.py" --labels "$out/labels.jsonl" \
    --out "$out/report.json" >"$out/summary.txt"
  if python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["coverage"] >= 1.0 else 1)' \
      "$out/report.json"; then
    break
  fi
  [ "$(date +%s)" -ge "$deadline" ] && break
  sleep "$STAGING_POLL_INTERVAL"
done

ln -sfn "$out/report.json" "$STAGING_STATE_DIR/replay/latest.json"
cat "$out/summary.txt"
python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["coverage"] >= float(sys.argv[2]) else 1)' \
  "$out/report.json" "$REPLAY_MIN_COVERAGE" || die "kapsam $REPLAY_MIN_COVERAGE altında"
