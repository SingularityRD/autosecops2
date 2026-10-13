# shellcheck shell=bash
# Cluster helpers for the staging scripts. Sourced after common.sh.

export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
: "${STAGING_LOCAL_PORT:=16987}"
# fullnameOverride in values-staging.yaml is "autosecops".
: "${STAGING_FULLNAME:=autosecops}"
BACKEND_DEPLOY="deploy/${STAGING_FULLNAME}-backend"
BACKEND_SVC="svc/${STAGING_FULLNAME}-backend"
export STAGING_LOCAL_PORT STAGING_FULLNAME BACKEND_DEPLOY BACKEND_SVC

kc() { kubectl -n "$STAGING_NAMESPACE" "$@"; }

PF_PID=""
PF_OWNS_URL=0

# Expose the backend on 127.0.0.1:$STAGING_LOCAL_PORT for the API scripts,
# unless STAGING_BASE_URL is already set (tests, or an operator pointing at the
# ingress). Sets STAGING_BASE_URL. stop_port_forward undoes it.
start_port_forward() {
  if [ -n "${STAGING_BASE_URL:-}" ]; then
    return 0
  fi
  local logf="$STAGING_STATE_DIR/port-forward.log"
  kc port-forward --address 127.0.0.1 "$BACKEND_SVC" "${STAGING_LOCAL_PORT}:6987" \
    >"$logf" 2>&1 &
  PF_PID=$!
  PF_OWNS_URL=1
  STAGING_BASE_URL="http://127.0.0.1:${STAGING_LOCAL_PORT}"
  export STAGING_BASE_URL
  local _
  for _ in $(seq 30); do
    if curl -sf --max-time 2 "$STAGING_BASE_URL/api/health" >/dev/null 2>&1; then
      return 0
    fi
    kill -0 "$PF_PID" 2>/dev/null || break
    sleep 1
  done
  log "port-forward hazır olmadı; günlük: $logf"
  return 1
}

stop_port_forward() {
  if [ -n "$PF_PID" ]; then
    kill "$PF_PID" 2>/dev/null || true
    wait "$PF_PID" 2>/dev/null || true
    PF_PID=""
  fi
  # Forget the URL we made up so the next start_port_forward opens a new one.
  if [ "$PF_OWNS_URL" = "1" ]; then
    unset STAGING_BASE_URL
    PF_OWNS_URL=0
  fi
}
