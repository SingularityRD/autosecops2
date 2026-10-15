#!/bin/sh
# verify-release.sh — verify a downloaded AutoSecOps release, offline if wanted.
#
# Usage:
#   sh verify-release.sh --dir DIR [--version V] [--repo OWNER/REPO]
#                        [--trusted-root FILE] [--skip-images]
#
#   --dir           directory holding the release files (SHA256SUMS, *.sigstore.json, ...)
#   --version       release version without the leading v (default: from the
#                   single autosecops-<V>-images.tsv in DIR)
#   --repo          repository the release workflow ran in (default SingularityRD/autosecops2)
#   --trusted-root  Sigstore trusted_root.json; with it no network is used.
#                   Without it cosign fetches the trusted root over TUF (online).
#   --skip-images   only verify the files, not the image attestations
#
# Steps (each failure stops with a non-zero exit):
#   1. every file listed in SHA256SUMS exists and matches (sha256sum / shasum)
#   2. SHA256SUMS carries a valid keyless signature from the release workflow
#   3. every SBOM, provenance, image list and web bundle carries its own signature,
#      and so does every desktop installer (autosecops-<V>-desktop-*) present
#   4. every image digest in autosecops-<V>-images.tsv has a signed SLSA
#      provenance (index) and CycloneDX SBOM (each platform) attestation
#
# Needs: POSIX sh, sha256sum or shasum, cosign >= 3 (COSIGN=/path overrides).
# Exit 0 and "RESULT: VERIFIED" only when everything passed.
set -eu

dir=""
version=""
repo="SingularityRD/autosecops2"
trusted_root=""
skip_images=0
COSIGN=${COSIGN:-cosign}
ISSUER="https://token.actions.githubusercontent.com"

die() { echo "verify-release: $*" >&2; exit 1; }
usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-2}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) dir="${2:?--dir needs a value}"; shift 2 ;;
    --version) version="${2:?--version needs a value}"; shift 2 ;;
    --repo) repo="${2:?--repo needs a value}"; shift 2 ;;
    --trusted-root) trusted_root="${2:?--trusted-root needs a value}"; shift 2 ;;
    --skip-images) skip_images=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "verify-release: unknown argument $1" >&2; usage 2 ;;
  esac
done

[ -n "$dir" ] || usage 2
[ -d "$dir" ] || die "no such directory: $dir"
case "$repo" in */*) ;; *) die "--repo must be OWNER/REPO" ;; esac
if [ -n "$trusted_root" ]; then
  [ -f "$trusted_root" ] || die "no such trusted root: $trusted_root"
  trusted_root=$(cd "$(dirname "$trusted_root")" && pwd)/$(basename "$trusted_root")
fi
command -v "$COSIGN" >/dev/null 2>&1 || die "cosign not found (set COSIGN=/path/to/cosign)"
cd "$dir"

if [ -z "$version" ]; then
  n=0
  for f in autosecops-*-images.tsv; do
    [ -f "$f" ] || continue
    n=$((n + 1))
    version=${f#autosecops-}
    version=${version%-images.tsv}
  done
  [ "$n" -eq 1 ] || die "cannot tell the version from $dir; pass --version"
fi
case "$version" in
  v*) die "--version takes the version without the leading v" ;;
  *[!0-9A-Za-z.-]*|'') die "bad version '$version'" ;;
esac
identity="https://github.com/${repo}/.github/workflows/release.yml@refs/tags/v${version}"
echo "release $version, expected signer $identity"

# --- 1. checksums --------------------------------------------------------------
[ -f SHA256SUMS ] || die "SHA256SUMS missing"
# Only bare file names: nothing may point outside this directory.
if grep -Ev '^[0-9a-f]{64}  [A-Za-z0-9][A-Za-z0-9._+-]*$' SHA256SUMS >/dev/null; then
  die "SHA256SUMS has a malformed line or a path outside the release directory"
fi
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c SHA256SUMS >/dev/null || die "checksum mismatch (run: sha256sum -c SHA256SUMS)"
else
  shasum -a 256 -c SHA256SUMS >/dev/null || die "checksum mismatch (run: shasum -a 256 -c SHA256SUMS)"
fi
echo "OK   checksums ($(wc -l < SHA256SUMS | tr -d ' ') files)"

# --- 2./3. blob signatures -------------------------------------------------------
verify_blob() { # file
  [ -f "$1.sigstore.json" ] || die "$1: signature bundle $1.sigstore.json missing"
  if [ -n "$trusted_root" ]; then
    "$COSIGN" verify-blob --bundle "$1.sigstore.json" \
      --certificate-identity "$identity" --certificate-oidc-issuer "$ISSUER" \
      --trusted-root "$trusted_root" "$1" >/dev/null 2>&1 \
      || die "$1: signature does not verify for $identity"
  else
    "$COSIGN" verify-blob --bundle "$1.sigstore.json" \
      --certificate-identity "$identity" --certificate-oidc-issuer "$ISSUER" \
      "$1" >/dev/null 2>&1 \
      || die "$1: signature does not verify for $identity"
  fi
  echo "OK   signature  $1"
}

verify_blob SHA256SUMS
images_tsv="autosecops-${version}-images.tsv"
for f in "autosecops-${version}-images.json" "$images_tsv" \
         "autosecops-${version}-web.tar.gz" autosecops-"${version}"-*.cdx.json \
         autosecops-"${version}"-*.provenance.json; do
  [ -f "$f" ] || die "expected release file missing: $f"
  grep -q "  $f\$" SHA256SUMS || die "$f is not listed in SHA256SUMS"
  verify_blob "$f"
done

# Desktop installers (dmg, AppImage, exe) are optional: a release may ship
# without them. When present they are checked like every other file.
for f in autosecops-"${version}"-desktop-*; do
  [ -f "$f" ] || continue
  case "$f" in *.sigstore.json) continue ;; esac
  grep -q "  $f\$" SHA256SUMS || die "$f is not listed in SHA256SUMS"
  verify_blob "$f"
done

# --- 4. image attestations -------------------------------------------------------
verify_att() { # bundle type digest label
  [ -f "$1" ] || die "$4: attestation bundle $1 missing"
  hex=${3#sha256:}
  if [ -n "$trusted_root" ]; then
    "$COSIGN" verify-blob-attestation --bundle "$1" --type "$2" \
      --digest "$hex" --digestAlg sha256 \
      --certificate-identity "$identity" --certificate-oidc-issuer "$ISSUER" \
      --trusted-root "$trusted_root" >/dev/null 2>&1 \
      || die "$4: $2 attestation does not verify for $3"
  else
    "$COSIGN" verify-blob-attestation --bundle "$1" --type "$2" \
      --digest "$hex" --digestAlg sha256 \
      --certificate-identity "$identity" --certificate-oidc-issuer "$ISSUER" \
      >/dev/null 2>&1 \
      || die "$4: $2 attestation does not verify for $3"
  fi
  echo "OK   $2 attestation  $4 $3"
}

if [ "$skip_images" -eq 0 ]; then
  n=0
  tab=$(printf '\t')
  while IFS="$tab" read -r component kind ref; do
    [ -n "$component" ] || continue
    digest=${ref##*@}
    case "$digest" in sha256:*) ;; *) die "$images_tsv: bad reference $ref" ;; esac
    if [ "$kind" = index ]; then
      verify_att "autosecops-${version}-image-${component}.provenance.att.sigstore.json" \
        slsaprovenance1 "$digest" "$component"
    else
      verify_att "autosecops-${version}-image-${component}-${kind}.sbom.att.sigstore.json" \
        cyclonedx "$digest" "$component/$kind"
    fi
    n=$((n + 1))
  done < "$images_tsv"
  [ "$n" -gt 0 ] || die "$images_tsv lists no images"
fi

echo "RESULT: VERIFIED"
