#!/usr/bin/env bash
# AutoSecOps staging nightly install from main. Run by
# autosecops-staging-nightly.service (root); safe to run by hand.
#
#   infra/staging/nightly.sh              # update checkout, then deploy
#   infra/staging/nightly.sh --no-update  # deploy what is checked out
#
# Phase 1 (update): fetch $STAGING_BRANCH into $STAGING_SRC_DIR and hard-reset
# to it, then re-exec the *updated* nightly.sh with --no-update, so tonight's
# scripts deploy tonight's code.
# Phase 2 (deploy):
#   1. build backend/daemon/agent images tagged with the commit (12 chars);
#      push to 127.0.0.1:5000 or import into k3s containerd
#   2. helm dependency build + lint + template (render check)
#   3. kubectl apply manifests/llm.yaml (Ollama + Bifrost), pull the model
#   4. helm upgrade --install --atomic --wait with values-staging.yaml and
#      $STAGING_ETC_DIR/secrets.yaml
#   5. register the local model as the default provider, restart daemon/worker
#   6. smoke.sh (health, login, ingest, triage), then seed-demo.sh
#   7. write $STAGING_STATE_DIR/last-run.json; exit non-zero on any failure
#
# A commit that already passed is not rebuilt unless STAGING_FORCE=1; the
# smoke test still runs. One run at a time (flock).
# shellcheck source-path=SCRIPTDIR
set -euo pipefail
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

load_env_file "$STAGING_ETC_DIR/staging.env"
: "${STAGING_BRANCH:=main}"
: "${STAGING_LOCAL_MODEL:=qwen2.5:1.5b}"
: "${STAGING_LOCAL_REGISTRY:=0}"
: "${STAGING_HOST:=autosecops-staging.local}"
: "${STAGING_FORCE:=0}"
: "${STAGING_HELM_TIMEOUT:=20m}"
: "${STAGING_IMAGE_NAMESPACE:=autosecops/vigil}"
: "${STAGING_SMOKE:=$STAGING_DIR/smoke.sh}"
: "${STAGING_SEED:=$STAGING_DIR/seed-demo.sh}"
export STAGING_LOCAL_MODEL

# shellcheck source=lib/cluster.sh
source "$STAGING_LIB_DIR/cluster.sh"

CHART="$STAGING_SRC_DIR/infra/helm/vigil"
RUN_STEP="init"
RUN_SHA=""
RUN_STARTED="$(date -u +%FT%TZ)"

image_registry() {
  if [ "$STAGING_LOCAL_REGISTRY" = "1" ]; then
    echo "127.0.0.1:5000"
  else
    # Never pulled from: images are imported into containerd under this name
    # and the chart's IfNotPresent policy uses the local copy.
    echo "staging.local"
  fi
}

write_status() {
  local result="$1"
  mkdir -p "$STAGING_STATE_DIR"
  RS_RESULT="$result" RS_STEP="$RUN_STEP" RS_SHA="$RUN_SHA" RS_STARTED="$RUN_STARTED" \
  RS_MODEL="$STAGING_LOCAL_MODEL" python3 -c '
import json, os, sys
from datetime import datetime, timezone
doc = {"result": os.environ["RS_RESULT"], "step": os.environ["RS_STEP"],
       "sha": os.environ["RS_SHA"], "started": os.environ["RS_STARTED"],
       "finished": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
       "model": os.environ["RS_MODEL"]}
smoke = os.path.join(os.path.dirname(sys.argv[1]), "smoke.json")
if os.path.exists(smoke):
    try:
        doc["smoke"] = json.load(open(smoke))
    except ValueError:
        pass
tmp = sys.argv[1] + ".tmp"
open(tmp, "w").write(json.dumps(doc, indent=2) + "\n")
os.replace(tmp, sys.argv[1])
' "$STAGING_STATE_DIR/last-run.json"
}

on_exit() {
  local rc=$?
  stop_port_forward
  if [ "$rc" -eq 0 ]; then
    write_status pass
    log "NIGHTLY: PASS ($RUN_SHA)"
  else
    write_status fail || true
    log "NIGHTLY: FAIL adım=$RUN_STEP ($RUN_SHA)"
  fi
}

update_checkout() {
  RUN_STEP="update"
  [ -d "$STAGING_SRC_DIR/.git" ] || die "$STAGING_SRC_DIR bir git deposu değil (önce bootstrap.sh)"
  log "güncelleniyor: $STAGING_BRANCH"
  git -C "$STAGING_SRC_DIR" fetch --prune origin "$STAGING_BRANCH"
  git -C "$STAGING_SRC_DIR" checkout -q -B "$STAGING_BRANCH" "origin/$STAGING_BRANCH"
  git -C "$STAGING_SRC_DIR" reset -q --hard "origin/$STAGING_BRANCH"
  git -C "$STAGING_SRC_DIR" clean -qfdx
}

already_green() {
  [ "$STAGING_FORCE" = "1" ] && return 1
  [ -f "$STAGING_STATE_DIR/last-run.json" ] || return 1
  python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
sys.exit(0 if d.get("result") == "pass" and d.get("sha") == sys.argv[2] else 1)
' "$STAGING_STATE_DIR/last-run.json" "$RUN_SHA"
}

build_images() {
  RUN_STEP="build"
  local reg comp ref
  reg="$(image_registry)"
  for comp in backend daemon agent; do
    ref="$reg/${STAGING_IMAGE_NAMESPACE}-${comp}:$RUN_SHA"
    log "imaj kuruluyor: $ref"
    docker build -q -f "$STAGING_SRC_DIR/infra/docker/Dockerfile.$comp" -t "$ref" "$STAGING_SRC_DIR"
    if [ "$STAGING_LOCAL_REGISTRY" = "1" ]; then
      docker push -q "$ref"
    else
      docker save "$ref" | k3s ctr -n k8s.io images import -
    fi
  done
}

render_chart() {
  RUN_STEP="chart"
  helm repo add bitnami https://charts.bitnami.com/bitnami --force-update >/dev/null
  helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts --force-update >/dev/null
  helm dependency build "$CHART" >/dev/null
  helm lint "$CHART" "${HELM_VALUES[@]}"
  helm template "$STAGING_RELEASE" "$CHART" -n "$STAGING_NAMESPACE" "${HELM_VALUES[@]}" >/dev/null
}

deploy_llm() {
  RUN_STEP="llm"
  kc apply -f "$STAGING_DIR/manifests/llm.yaml"
  kc rollout status deploy/ollama --timeout=10m
  kc rollout status deploy/bifrost --timeout=5m
  log "model çekiliyor: $STAGING_LOCAL_MODEL"
  kc exec deploy/ollama -- ollama pull "$STAGING_LOCAL_MODEL" >/dev/null
}

deploy_release() {
  RUN_STEP="helm"
  log "helm upgrade --install $STAGING_RELEASE ($RUN_SHA)"
  helm upgrade --install "$STAGING_RELEASE" "$CHART" -n "$STAGING_NAMESPACE" --create-namespace \
    "${HELM_VALUES[@]}" --atomic --wait --timeout "$STAGING_HELM_TIMEOUT"
}

register_model() {
  RUN_STEP="register-model"
  kc exec -i "$BACKEND_DEPLOY" -- env STAGING_LOCAL_MODEL="$STAGING_LOCAL_MODEL" python - \
    <"$STAGING_LIB_DIR/register_local_model.py"
  # Processes cache the provider registry; restart the two that dispatch triage.
  kc rollout restart "statefulset/${STAGING_FULLNAME}-daemon" "deploy/${STAGING_FULLNAME}-llm-worker"
  kc rollout status "statefulset/${STAGING_FULLNAME}-daemon" --timeout=10m
  kc rollout status "deploy/${STAGING_FULLNAME}-llm-worker" --timeout=10m
}

deploy() {
  exec 9>"$STAGING_STATE_DIR/nightly.lock"
  flock -w "${STAGING_LOCK_WAIT:-3600}" 9 || die "başka bir staging işi kilidi tutuyor"
  trap on_exit EXIT

  RUN_SHA="$(git -C "$STAGING_SRC_DIR" rev-parse --short=12 HEAD)"
  [[ "$STAGING_HOST" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || die "geçersiz STAGING_HOST: $STAGING_HOST"
  [ -f "$STAGING_ETC_DIR/secrets.yaml" ] || die "$STAGING_ETC_DIR/secrets.yaml yok (önce bootstrap.sh)"
  local reg
  reg="$(image_registry)"
  HELM_VALUES=(
    -f "$STAGING_DIR/values-staging.yaml"
    -f "$STAGING_ETC_DIR/secrets.yaml"
    --set "global.imageRegistry=$reg"
    --set "global.imageNamespace=$STAGING_IMAGE_NAMESPACE"
    --set "backend.image.tag=$RUN_SHA"
    --set "llmWorker.image.tag=$RUN_SHA"
    --set "daemon.image.tag=$RUN_SHA"
    --set "agentWorker.image.tag=$RUN_SHA"
    --set "agentServe.image.tag=$RUN_SHA"
    # The whole list: `--set ingress.hosts[0].host=` would replace the list
    # from values-staging.yaml with one that has no paths.
    --set-json "ingress.hosts=[{\"host\":\"$STAGING_HOST\",\"paths\":[{\"path\":\"/\",\"pathType\":\"Prefix\"}]}]"
  )
  log "commit $RUN_SHA, model $STAGING_LOCAL_MODEL, kayıt defteri $reg"

  if already_green; then
    log "$RUN_SHA zaten yeşil kuruldu; yeniden kurulmuyor (STAGING_FORCE=1 ile zorla)"
  else
    build_images
    render_chart
    deploy_llm
    deploy_release
    register_model
  fi

  RUN_STEP="port-forward"
  start_port_forward

  RUN_STEP="smoke"
  rm -f "$STAGING_STATE_DIR/smoke.json"
  SMOKE_REPORT="$STAGING_STATE_DIR/smoke.json" "$STAGING_SMOKE"

  RUN_STEP="seed"
  "$STAGING_SEED"

  RUN_STEP="prune"
  docker image prune -f --filter "until=72h" >/dev/null 2>&1 || true
  RUN_STEP="done"
}

main() {
  mkdir -p "$STAGING_STATE_DIR"
  if [ "${1:-}" != "--no-update" ]; then
    trap on_exit EXIT
    update_checkout
    trap - EXIT
    exec "$STAGING_SRC_DIR/infra/staging/nightly.sh" --no-update
  fi
  deploy
}

# Everything above is definitions; bash has parsed them before main runs, so
# the git reset in update_checkout cannot change the script under our feet.
main "$@"
