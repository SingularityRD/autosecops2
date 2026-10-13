#!/usr/bin/env bash
# Start a work package: a worktree on its own branch from target/main, with a
# spec stub to fill in.
#
#   scripts/wp/new.sh <id> <slug> [--base <ref>] [--fetch]
#
#   scripts/wp/new.sh w0.5 api-errors
#     -> worktree /root/wt/w0.5, branch wp/w0.5-api-errors, spec docs/wp/w0.5.md
#
# Env: WP_WORKTREE_ROOT (default /root/wt), WP_BASE (default target/main).
# The spec is left uncommitted; the implementer fills it in and commits it with
# the first change, so the verifier reads it from the branch.
set -euo pipefail

usage() { awk 'NR > 1 && /^#/ && !/shellcheck/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit "${1:-2}"; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
template="$here/../../docs/wp/TEMPLATE.md"
base="${WP_BASE:-target/main}"
root="${WP_WORKTREE_ROOT:-/root/wt}"
fetch=0
args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --base) base="${2:?--base needs a ref}"; shift 2 ;;
    --fetch) fetch=1; shift ;;
    -h|--help) usage 0 ;;
    -*) echo "unknown option: $1" >&2; usage ;;
    *) args+=("$1"); shift ;;
  esac
done
[ ${#args[@]} -eq 2 ] || usage
id="${args[0]}"
slug="${args[1]}"

# Lower-case, no slashes or spaces: both end up in a path and a ref name.
[[ "$id" =~ ^[a-z0-9][a-z0-9.-]*$ ]] || { echo "bad id '$id' (want e.g. w0.5)" >&2; exit 2; }
[[ "$slug" =~ ^[a-z0-9][a-z0-9-]*$ ]] || { echo "bad slug '$slug' (want kebab-case)" >&2; exit 2; }
[ -f "$template" ] || { echo "template missing: $template" >&2; exit 1; }

# Any worktree of the repo works as the anchor; use the one this script lives in.
repo="$(git -C "$here" rev-parse --show-toplevel)"
branch="wp/$id-$slug"
wt="$root/$id"

if [ "$fetch" = 1 ]; then
  remote="${base%%/*}"
  git -C "$repo" fetch --quiet "$remote" "${base#*/}"
fi
git -C "$repo" rev-parse --verify --quiet "$base^{commit}" >/dev/null \
  || { echo "base '$base' not found (try --fetch)" >&2; exit 1; }
[ ! -e "$wt" ] || { echo "$wt already exists" >&2; exit 1; }
if git -C "$repo" rev-parse --verify --quiet "refs/heads/$branch" >/dev/null; then
  echo "branch $branch already exists" >&2; exit 1
fi

mkdir -p "$root"
# --no-track: the WP branch must never push to (or pull from) target/main by accident.
git -C "$repo" worktree add --quiet --no-track -b "$branch" "$wt" "$base"
base_sha="$(git -C "$wt" rev-parse --short HEAD)"

spec="$wt/docs/wp/$id.md"
mkdir -p "$(dirname "$spec")"
sed -e "s|{{ID}}|$id|g" -e "s|{{BRANCH}}|$branch|g" -e "s|{{BASE_SHA}}|$base_sha|g" \
    -e "s|{{WORKTREE}}|$wt|g" -e "s|{{TITLE}}|$slug|g" "$template" > "$spec"

# node_modules is not tracked; borrow the main checkout's so gates can run at once.
# gates.sh does the same lazily, this just saves the first run a step.
# The symlink is not matched by .gitignore's "node_modules/" (a directory
# pattern), so exclude it first: a stray `git add -A` must not commit it.
# info/exclude is shared by all worktrees; the line is idempotent.
exclude="$(git -C "$wt" rev-parse --path-format=absolute --git-path info/exclude)"
if ! grep -qxF node_modules "$exclude" 2>/dev/null; then
  mkdir -p "$(dirname "$exclude")" && printf 'node_modules\n' >>"$exclude"
fi
main_wt="$(git -C "$repo" worktree list --porcelain | sed -n '1s/^worktree //p')"
for d in clients/web services/agent; do
  if [ -d "$main_wt/$d/node_modules" ] && [ ! -e "$wt/$d/node_modules" ] && [ -d "$wt/$d" ]; then
    ln -s "$main_wt/$d/node_modules" "$wt/$d/node_modules"
  fi
done

echo "worktree: $wt"
echo "branch:   $branch (from $base @ $base_sha)"
echo "spec:     $spec  (fill in, commit with the first change)"
