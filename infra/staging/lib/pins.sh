# shellcheck shell=bash
# Pinned versions and checksums for everything bootstrap.sh downloads and runs
# as root. Sourced by bootstrap.sh. Changing a version means changing its
# checksums here in the same commit; an override from the environment must
# bring its own checksums (bootstrap refuses a version without them).
#
# Sources (record how each value was obtained when bumping):
#   k3s install.sh   https://raw.githubusercontent.com/k3s-io/k3s/<K3S_VERSION>/install.sh
#                    (`sha256sum install.sh`)
#   k3s binary       https://github.com/k3s-io/k3s/releases/download/<K3S_VERSION>/sha256sum-<arch>.txt
#   helm tarball     https://github.com/helm/helm/releases/tag/<HELM_VERSION> (release notes
#                    list the sha256 of each tarball; also get.helm.sh/<tarball>.sha256sum)
#
# Container images (manifests/llm.yaml, REGISTRY_IMAGE) are pinned by exact
# version tag, not digest: the digests could not be resolved from the
# authoring environment. To pin by digest on the VM, run
# `docker buildx imagetools inspect <image>` and set e.g.
# REGISTRY_IMAGE=docker.io/library/registry:2.8.3@sha256:<digest>.

: "${K3S_VERSION:=v1.31.4+k3s1}"
: "${HELM_VERSION:=v3.16.4}"
: "${REGISTRY_IMAGE:=docker.io/library/registry:2.8.3}"

if [ "$K3S_VERSION" = "v1.31.4+k3s1" ]; then
  : "${K3S_INSTALL_SH_SHA256:=f60c3d8940dfc896f7d83aaf57726c91cf21afc4bca40036472df108d9700b4b}"
  : "${K3S_BIN_SHA256_amd64:=74897e4af26ea383ce50f445752f40ca63a0aef0d90994fb74073c43063eeeb2}"
  : "${K3S_BIN_SHA256_arm64:=eff4cc82c8c057bd2dc432025b933616637dcf3df91e9e06720d9208743640d3}"
fi
if [ "$HELM_VERSION" = "v3.16.4" ]; then
  : "${HELM_SHA256_amd64:=fc307327959aa38ed8f9f7e66d45492bb022a66c3e5da6063958254b9767d179}"
  : "${HELM_SHA256_arm64:=d3f8f15b3d9ec8c8678fbf3280c3e5902efabe5912e2f9fcf29107efbc8ead69}"
fi
: "${K3S_INSTALL_SH_SHA256:=}" "${K3S_BIN_SHA256_amd64:=}" "${K3S_BIN_SHA256_arm64:=}"
: "${HELM_SHA256_amd64:=}" "${HELM_SHA256_arm64:=}"

# pinned_sha <VAR_PREFIX> <arch> -> value of ${VAR_PREFIX}_<arch>
pinned_sha() {
  local var="${1}_${2}"
  printf '%s' "${!var:-}"
}

# verify_sha256 <file> <expected> — exit via die on mismatch or missing pin.
verify_sha256() {
  local file="$1" want="$2" got
  [[ "$want" =~ ^[0-9a-f]{64}$ ]] || die "$(basename "$file") için sabitlenmiş sha256 yok (lib/pins.sh)"
  got="$(sha256sum "$file" | awk '{print $1}')"
  [ "$got" = "$want" ] || die "$(basename "$file") sha256 uyuşmuyor: beklenen $want, gelen $got"
}
