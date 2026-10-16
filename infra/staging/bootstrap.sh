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
#   - k3s (pinned K3S_VERSION; Traefik ingress, local-path storage). The
#     installer comes from that version's tag on GitHub and the k3s binary from
#     its release; both are checked against sha256 values committed in
#     lib/pins.sh before anything runs as root.
#   - helm (pinned HELM_VERSION, tarball checked against lib/pins.sh)
#   - optional local registry on 127.0.0.1:5000 (STAGING_LOCAL_REGISTRY=1)
#   - repo checkout at $STAGING_SRC_DIR (default /opt/autosecops-staging/src)
#   - $STAGING_ETC_DIR (default /etc/autosecops-staging), mode 0700:
#       staging.env   non-secret settings (from staging.env.example)
#       secrets.yaml  Helm values with generated DB password / JWT key / agent token /
#                     data-encryption key
#       admin.env     generated first-admin credentials for smoke/seed/replay
#     Existing files are never overwritten.
#   - systemd: autosecops-staging-nightly.timer and -replay.timer, enabled;
#     the units are rendered with this run's STAGING_SRC_DIR / STAGING_ETC_DIR /
#     STAGING_STATE_DIR
#
# Env (defaults in lib/pins.sh): K3S_VERSION, HELM_VERSION, REGISTRY_IMAGE and
#   their *_SHA256* checksums, plus anything in
#   staging.env.example (read from $STAGING_ETC_DIR/staging.env when present).
# shellcheck source-path=SCRIPTDIR
set -euo pipefail
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

# shellcheck source=lib/pins.sh
source "$STAGING_LIB_DIR/pins.sh"
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

# URL-encode the "+" in k3s versions (v1.31.4+k3s1) for GitHub paths.
k3s_ref() { printf '%s' "${K3S_VERSION//+/%2B}"; }

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
  local a bin_name bin_sha tmp ref
  a="$(arch)"
  bin_name=k3s
  [ "$a" = "amd64" ] || bin_name="k3s-$a"
  bin_sha="$(pinned_sha K3S_BIN_SHA256 "$a")"
  ref="$(k3s_ref)"
  # Refuse before downloading anything when a pin is missing (e.g. an
  # overridden K3S_VERSION without its checksums).
  [[ "$K3S_INSTALL_SH_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "K3S_INSTALL_SH_SHA256 sabitlenmemiş ($K3S_VERSION; lib/pins.sh)"
  [[ "$bin_sha" =~ ^[0-9a-f]{64}$ ]] || die "K3S_BIN_SHA256_$a sabitlenmemiş ($K3S_VERSION; lib/pins.sh)"
  tmp=/tmp/autosecops-k3s
  is_dry_run || tmp="$(mktemp -d)"
  # Installer from the pinned tag (not the moving get.k3s.io), binary from the
  # pinned release; both verified against committed checksums.
  run curl -sfL --retry 3 -o "$tmp/install.sh" "https://raw.githubusercontent.com/k3s-io/k3s/$ref/install.sh"
  run curl -sfL --retry 3 -o "$tmp/$bin_name" "https://github.com/k3s-io/k3s/releases/download/$ref/$bin_name"
  if is_dry_run; then
    printf '+ sha256 check %s/install.sh == %s\n' "$tmp" "$K3S_INSTALL_SH_SHA256"
    printf '+ sha256 check %s/%s == %s\n' "$tmp" "$bin_name" "$bin_sha"
  else
    verify_sha256 "$tmp/install.sh" "$K3S_INSTALL_SH_SHA256"
    verify_sha256 "$tmp/$bin_name" "$bin_sha"
  fi
  run install -m 0755 "$tmp/$bin_name" /usr/local/bin/k3s
  # INSTALL_K3S_SKIP_DOWNLOAD: the installer uses the verified binary above.
  # 0600 kubeconfig: only root (the nightly unit) reads cluster-admin creds.
  run env INSTALL_K3S_SKIP_DOWNLOAD=true INSTALL_K3S_VERSION="$K3S_VERSION" \
    INSTALL_K3S_EXEC="server --write-kubeconfig-mode 0600" sh "$tmp/install.sh"
  is_dry_run || rm -rf "$tmp"
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
  local want
  a="$(arch)"
  tarball="helm-${HELM_VERSION}-linux-${a}.tar.gz"
  want="$(pinned_sha HELM_SHA256 "$a")"
  [[ "$want" =~ ^[0-9a-f]{64}$ ]] || die "HELM_SHA256_$a sabitlenmemiş ($HELM_VERSION; lib/pins.sh)"
  tmp=/tmp/autosecops-helm
  is_dry_run || tmp="$(mktemp -d)"
  run curl -sfL --retry 3 -o "$tmp/$tarball" "https://get.helm.sh/$tarball"
  # Checked against the committed pin, not a .sha256sum fetched from the same host.
  if is_dry_run; then
    printf '+ sha256 check %s/%s == %s\n' "$tmp" "$tarball" "$want"
  else
    verify_sha256 "$tmp/$tarball" "$want"
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
  # Generate next to the target, check it, then rename: a failed or empty
  # generator never leaves a half-written file that later runs would keep.
  local tmp
  tmp="$(umask 077; mktemp "$path.tmp.XXXXXX")"
  if ! (umask 077; "$gen" >"$tmp") || [ ! -s "$tmp" ]; then
    rm -f "$tmp"
    die "$(basename "$path") üretilemedi"
  fi
  chmod 0600 "$tmp"
  mv -f "$tmp" "$path"
  log "$(basename "$path"): oluşturuldu"
}

gen_staging_env() { cat "$STAGING_DIR/staging.env.example"; }

# Secrets are generated before anything is printed, so a failing generator
# returns non-zero instead of emitting an empty value (write_once then refuses).
gen_secrets_yaml() {
  local pg jwt agent data
  pg="$(gen_secret 24)" && [ -n "$pg" ] || return 1
  jwt="$(gen_secret 64)" && [ -n "$jwt" ] || return 1
  agent="$(gen_secret 48)" && [ -n "$agent" ] || return 1
  data="$(gen_secret 48)" && [ -n "$data" ] || return 1
  printf '# Generated by bootstrap.sh on %s. Do not commit.\n' "$(date -u +%FT%TZ)"
  printf 'secrets:\n'
  printf '  postgresPassword: "%s"\n' "$pg"
  printf '  jwtSecretKey: "%s"\n' "$jwt"
  printf '  agentInternalToken: "%s"\n' "$agent"
  printf '  dataEncryptionKey: "%s"\n' "$data"
}

gen_admin_env() {
  local pw
  pw="$(gen_secret 24)" && [ -n "$pw" ] || return 1
  printf '# Generated by bootstrap.sh on %s. Do not commit.\n' "$(date -u +%FT%TZ)"
  printf 'STAGING_ADMIN_USER=%s\n' "$STAGING_ADMIN_USER"
  printf 'STAGING_ADMIN_EMAIL=%s\n' "$STAGING_ADMIN_EMAIL"
  printf 'STAGING_ADMIN_PASSWORD=%s\n' "$pw"
}

ensure_config() {
  run install -d -m 0700 "$STAGING_ETC_DIR"
  run install -d -m 0755 "$STAGING_STATE_DIR"
  write_once "$STAGING_ETC_DIR/staging.env" gen_staging_env
  write_once "$STAGING_ETC_DIR/secrets.yaml" gen_secrets_yaml
  write_once "$STAGING_ETC_DIR/admin.env" gen_admin_env
}

# render_unit <file>: substitute @STAGING_SRC_DIR@ / @STAGING_ETC_DIR@ /
# @STAGING_STATE_DIR@ so the units run the checkout and config this bootstrap
# set up, wherever they are.
render_unit() {
  local d
  for d in "$STAGING_SRC_DIR" "$STAGING_ETC_DIR" "$STAGING_STATE_DIR"; do
    [[ "$d" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "systemd için geçersiz yol: $d"
  done
  sed -e "s|@STAGING_SRC_DIR@|$STAGING_SRC_DIR|g" \
      -e "s|@STAGING_ETC_DIR@|$STAGING_ETC_DIR|g" \
      -e "s|@STAGING_STATE_DIR@|$STAGING_STATE_DIR|g" "$1"
}

ensure_systemd() {
  local unit changed=0 rendered
  rendered="$(mktemp -d)"
  for unit in "$STAGING_DIR"/systemd/*.service "$STAGING_DIR"/systemd/*.timer; do
    local dest out
    dest="$SYSTEMD_DIR/$(basename "$unit")"
    out="$rendered/$(basename "$unit")"
    render_unit "$unit" >"$out"
    if [ -f "$dest" ] && cmp -s "$out" "$dest"; then
      continue
    fi
    if is_dry_run; then
      printf '+ install %s -> %s:\n' "$(basename "$unit")" "$dest"
      sed 's/^/    /' "$out"
    else
      install -m 0644 "$out" "$dest"
    fi
    changed=1
  done
  rm -rf "$rendered"
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
