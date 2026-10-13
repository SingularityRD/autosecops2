#!/bin/sh
# dry-run.sh — rehearse the release locally, without network, docker or keys.
#
# Usage: scripts/release/dry-run.sh --out DIR [--version V] [--tag vX.Y.Z[-rc.N]] [--strict-notes]
#
# Runs the same checks and the same lockfile SBOM code as the version and sbom
# jobs of .github/workflows/release.yml:
#   1. version files agree with VERSION (and --tag, when given, with VERSION)
#   2. docs/release/<V>.md: every "Dahil" WP has a merge commit; with
#      --strict-notes also every merged wp/<id>-* branch has a "Dahil" row and
#      the notes + CHANGELOG block equal `release_tool.py render-notes` output
#      for HEAD (docs/release/<V>.json; the tag pipeline runs strict)
#   3. CycloneDX SBOMs from requirements.lock and every package-lock.json,
#      validated, into DIR
#   4. SHA256SUMS over DIR, checked back with sha256sum/shasum
# Image builds, image SBOMs (syft) and signing need the registry and an OIDC
# token, so they only run in the tag pipeline.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
tool="$here/release_tool.py"
PY=${PYTHON:-python3}

out=""
version=""
tag=""
strict=""
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="${2:?--out needs a value}"; shift 2 ;;
    --version) version="${2:?--version needs a value}"; shift 2 ;;
    --tag) tag="${2:?--tag needs a value}"; shift 2 ;;
    --strict-notes) strict="--strict"; shift ;;
    -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "dry-run: unknown argument $1" >&2; exit 2 ;;
  esac
done
[ -n "$out" ] || { echo "usage: $0 --out DIR [--version V] [--tag T] [--strict-notes]" >&2; exit 2; }

step() { printf '== %s\n' "$*"; }

step "version files"
"$PY" "$tool" --repo "$repo" check-versions
[ -n "$version" ] || version=$(tr -d '[:space:]' < "$repo/VERSION")
if [ -n "$tag" ]; then
  "$PY" "$tool" --repo "$repo" check-tag --tag "$tag"
fi

step "release notes"
notes="$repo/docs/release/${version%%-*}.md"
[ -f "$notes" ] || { echo "dry-run: release notes $notes missing" >&2; exit 1; }
data="$repo/docs/release/${version%%-*}.json"
if [ -n "$strict" ] && [ -f "$data" ]; then
  "$PY" "$tool" --repo "$repo" check-notes --notes "$notes" --strict --data "$data"
else
  # shellcheck disable=SC2086  # $strict is empty or one flag
  "$PY" "$tool" --repo "$repo" check-notes --notes "$notes" $strict
fi

step "lockfile SBOMs (offline)"
mkdir -p "$out"
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$repo" log -1 --format=%ct 2>/dev/null || echo 0)} \
  "$PY" "$tool" --repo "$repo" sboms --out "$out" --version "$version"
"$PY" "$tool" --repo "$repo" validate-sbom "$out"/autosecops-"$version"-*.cdx.json

step "checksums"
"$PY" "$tool" --repo "$repo" checksums --dir "$out" >/dev/null
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$out" && sha256sum -c SHA256SUMS >/dev/null)
else
  (cd "$out" && shasum -a 256 -c SHA256SUMS >/dev/null)
fi
echo "SHA256SUMS: $(wc -l < "$out/SHA256SUMS" | tr -d ' ') files"
echo "DRY RUN OK: $version -> $out"
