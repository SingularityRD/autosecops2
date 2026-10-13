#!/usr/bin/env bash
# Prepare a fresh Ubuntu 22.04/24.04 VM to run AutoSecOps staging. Idempotent:
# every step checks first and only changes what is missing or wrong, so a
# second run is a no-op. Run as root:
#
#   sudo infra/staging/bootstrap.sh            # from any checkout of the repo
#   DRY_RUN=1 infra/staging/bootstrap.sh       # print the plan, change nothing
#
# What it sets up:
#   - apt packages: curl, git, jq, python3, openssl, docker.io (image builds)
#   - k3s (pinned K3S_VERSION; Traefik ingress, local-path storage)
#   - helm (pinned HELM_VERSION, sha256-verified tarball)
#   - optional local registry on 127.0.0.1:5000 (STAGING_LOCAL_REGISTRY=1)
#   - repo checkout at $STAGING_SRC_DIR (default /opt/autosecops-staging/src)
#   - $STAGING_ETC_DIR (default /etc/autosecops-staging), mode 0700:
#       staging.env   non-secret settings (from staging.env.example)
#       secrets.yaml  Helm values with generated DB password / JWT key / agent token
#       admin.env     generated first-admin credentials for smoke/seed/replay
#     Existing files are never overwritten.
#   - systemd: autosecops-staging-nightly.timer and -replay.timer, enabled
#
# Env (defaults): K3S_VERSION [v1.31.4+k3s1], HELM_VERSION [v3.16.4],
#   REGISTRY_IMAGE [docker.io/library/registry:2.8.3], plus anything in
#   staging.env.example (read from $STAGING_ETC_DIR/staging.env when present).
set -euo pipefail
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

: "${K3S_VERSION:=v1.31.4+k3s1}"
: "${HELM_VERSION:=v3.16.4}"
: "${REGISTRY_IMAGE:=docker.io/library/registry:2.8.3}"
: "${SYSTEMD_DIR:=/etc/systemd/system}"
: "${K3S_REGISTRIES_FILE:=/etc/rancher/k3s/registries.yaml}"
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"

load_env_file "$STAGING_ETC_DIR/staging.env"
: "${STAGING_REPO_URL:=https://github.com/SingularityRD/autosecops2.git}"
: "${STAGING_BRANCH:=main}"
: "${STAGING_LOCAL_REGISTRY:=0}"
: "${STAGING_ADMIN_USER:=staging-admin}"
: "${STAGING_ADMIN_EMAIL:=staging-admin@autosecops.local}"

APT_PACKAGES=(curl ca-certificates git jq python3 openssl docker.io)

arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) die "desteklenmeyen mimari: $(uname -m)" ;;
  esac
}

check_host() {
  if ! is_dry_run && [ "$(id -u)" -ne 0 ]; then
    die "root olarak çalıştırın (sudo)"
  fi
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    [ "${ID:-}" = "ubuntu" ] || log "UYARI: Ubuntu dışı dağıtım (${ID:-?}); devam ediliyor"
  fi
}

ensure_packages() {
  local missing=() p
  for p in "${APT_PACKAGES[@]}"; do
    dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || missing+=("$p")
  done
  if [ "${#missing[@]}" -eq 0 ]; then
    log "apt paketleri: tamam"
    return 0
  fi
  log "apt paketleri kuruluyor: ${missing[*]}"
  run env DEBIAN_FRONTEND=noninteractive apt-get update -qq
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}"
  run systemctl enable --now docker
}

ensure_k3s() {
  local have=""
  if command -v k3s >/dev/null 2>&1; then
    have="$(k3s --version 2>/dev/null | awk 'NR==1 {print $3}')"
  fi
  if [ "$have" = "$K3S_VERSION" ]; then
    log "k3s $K3S_VERSION: tamam"
    return 0
  fi
  log "k3s ${have:-yok} -> $K3S_VERSION"
  local installer=/tmp/autosecops-k3s-install.sh
  is_dry_run || installer="$(mktemp)"
  run curl -sfL --retry 3 -o "$installer" https://get.k3s.io
  # 0600 kubeconfig: only root (the nightly unit) reads cluster-admin creds.
  run env INSTALL_K3S_VERSION="$K3S_VERSION" INSTALL_K3S_EXEC="server --write-kubeconfig-mode 0600" \
    sh "$installer"
  is_dry_run || rm -f "$installer"
  run k3s kubectl wait --for=condition=Ready node --all --timeout=180s
}

ensure_helm() {
  local have=""
  if command -v helm >/dev/null 2>&1; then
    have="$(helm version --template '{{.Version}}' 2>/dev/null || true)"
  fi
  if [ "$have" = "$HELM_VERSION" ]; then
    log "helm $HELM_VERSION: tamam"
    return 0
  fi
  log "helm ${have:-yok} -> $HELM_VERSION"
  local a tarball tmp
  a="$(arch)"
  tarball="helm-${HELM_VERSION}-linux-${a}.tar.gz"
  tmp=/tmp/autosecops-helm
  is_dry_run || tmp="$(mktemp -d)"
  run curl -sfL --retry 3 -o "$tmp/$tarball" "https://get.helm.sh/$tarball"
  run curl -sfL --retry 3 -o "$tmp/$tarball.sha256sum" "https://get.helm.sh/$tarball.sha256sum"
  if ! is_dry_run; then
    (cd "$tmp" && sha256sum -c "$tarball.sha256sum") || die "helm sha256 doğrulaması başarısız"
  fi
  run tar -xzf "$tmp/$tarball" -C "$tmp"
  run install -m 0755 "$tmp/linux-${a}/helm" /usr/local/bin/helm
  is_dry_run || rm -rf "$tmp"
}

ensure_registry() {
  if [ "$STAGING_LOCAL_REGISTRY" != "1" ]; then
    log "yerel kayıt defteri: kapalı (imajlar k3s containerd'ye aktarılır)"
    return 0
  fi
  if docker inspect -f '{{.State.Running}}' autosecops-registry 2>/dev/null | grep -qx true; then
    log "yerel kayıt defteri: çalışıyor"
  elif docker inspect autosecops-registry >/dev/null 2>&1; then
    run docker start autosecops-registry
  else
    run mkdir -p "$STAGING_STATE_DIR/registry"
    # Loopback only: the registry has no auth.
    run docker run -d --restart=always --name autosecops-registry \
      -p 127.0.0.1:5000:5000 -v "$STAGING_STATE_DIR/registry:/var/lib/registry" \
      "$REGISTRY_IMAGE"
  fi
  local want
  want="$(printf 'mirrors:\n  "127.0.0.1:5000":\n    endpoint:\n      - "http://127.0.0.1:5000"\n')"
  if [ -f "$K3S_REGISTRIES_FILE" ] && [ "$(cat "$K3S_REGISTRIES_FILE")" = "$want" ]; then
    return 0
  fi
  log "k3s registries.yaml yazılıyor"
  if is_dry_run; then
    printf '+ write %s\n' "$K3S_REGISTRIES_FILE"
  else
    mkdir -p "$(dirname "$K3S_REGISTRIES_FILE")"
    printf '%s\n' "$want" >"$K3S_REGISTRIES_FILE"
  fi
  run systemctl restart k3s
}

ensure_checkout() {
  if [ -d "$STAGING_SRC_DIR/.git" ]; then
    log "depo kopyası: $STAGING_SRC_DIR (gece kurulumu günceller)"
    return 0
  fi
  log "depo klonlanıyor: $STAGING_REPO_URL ($STAGING_BRANCH)"
  run mkdir -p "$(dirname "$STAGING_SRC_DIR")"
  run git clone --branch "$STAGING_BRANCH" "$STAGING_REPO_URL" "$STAGING_SRC_DIR"
}

# write_once <path> <generator-function>: create a 0600 file only if absent.
write_once() {
  local path="$1" gen="$2"
  if [ -f "$path" ]; then
    log "$(basename "$path"): mevcut, dokunulmadı"
    return 0
  fi
  if is_dry_run; then
    printf '+ write %s (0600, generated)\n' "$path"
    return 0
  fi
  (umask 077; "$gen" >"$path")
  chmod 0600 "$path"
  log "$(basename "$path"): oluşturuldu"
}

gen_staging_env() { cat "$STAGING_DIR/staging.env.example"; }

gen_secrets_yaml() {
  printf '# Generated by bootstrap.sh on %s. Do not commit.\n' "$(date -u +%FT%TZ)"
  printf 'secrets:\n'
  printf '  postgresPassword: "%s"\n' "$(gen_secret 24)"
  printf '  jwtSecretKey: "%s"\n' "$(gen_secret 64)"
  printf '  agentInternalToken: "%s"\n' "$(gen_secret 48)"
}

gen_admin_env() {
  printf '# Generated by bootstrap.sh on %s. Do not commit.\n' "$(date -u +%FT%TZ)"
  printf 'STAGING_ADMIN_USER=%s\n' "$STAGING_ADMIN_USER"
  printf 'STAGING_ADMIN_EMAIL=%s\n' "$STAGING_ADMIN_EMAIL"
  printf 'STAGING_ADMIN_PASSWORD=%s\n' "$(gen_secret 24)"
}

ensure_config() {
  run install -d -m 0700 "$STAGING_ETC_DIR"
  run install -d -m 0755 "$STAGING_STATE_DIR"
  write_once "$STAGING_ETC_DIR/staging.env" gen_staging_env
  write_once "$STAGING_ETC_DIR/secrets.yaml" gen_secrets_yaml
  write_once "$STAGING_ETC_DIR/admin.env" gen_admin_env
}

ensure_systemd() {
  local unit changed=0
  for unit in "$STAGING_DIR"/systemd/*.service "$STAGING_DIR"/systemd/*.timer; do
    local dest
    dest="$SYSTEMD_DIR/$(basename "$unit")"
    if [ -f "$dest" ] && cmp -s "$unit" "$dest"; then
      continue
    fi
    run install -m 0644 "$unit" "$dest"
    changed=1
  done
  if [ "$changed" = "1" ]; then
    run systemctl daemon-reload
  fi
  run systemctl enable --now autosecops-staging-nightly.timer
  run systemctl enable --now autosecops-staging-replay.timer
  log "systemd: autosecops-staging-nightly.timer, autosecops-staging-replay.timer etkin"
}

ensure_namespace() {
  if is_dry_run; then
    printf '+ kubectl create namespace %s (yoksa)\n' "$STAGING_NAMESPACE"
    return 0
  fi
  kubectl get namespace "$STAGING_NAMESPACE" >/dev/null 2>&1 \
    || kubectl create namespace "$STAGING_NAMESPACE"
}

main() {
  is_dry_run && log "DRY_RUN=1: yalnızca plan yazılıyor, hiçbir şey değişmeyecek"
  check_host
  ensure_packages
  ensure_k3s
  ensure_helm
  ensure_registry
  ensure_checkout
  ensure_config
  ensure_namespace
  ensure_systemd
  log "hazır. İlk kurulumu hemen başlatmak için: systemctl start autosecops-staging-nightly.service"
}

main "$@"
