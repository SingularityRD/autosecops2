#!/usr/bin/env bash
# Merge verified work-package branches into an integration branch, one at a
# time, gating after each merge.
#
#   scripts/wp/merge-train.sh [options] <branch>...
#
#   --into <branch>      integration branch [integration]; created from --base if missing
#   --base <ref>         start point for a new integration branch [target/main]
#   --worktree <dir>     where to check it out if no worktree has it yet
#                        [$WP_WORKTREE_ROOT/<into>, WP_WORKTREE_ROOT=/root/wt]
#   --no-verify-check    merge branches without a verifier PASS note (testing only)
#   --full               pass --full to gates.sh
#
# A branch is "verified" when its tip commit carries a git note in
# refs/notes/wp-verify whose first line is "VERDICT: PASS" (docs/wp/VERIFIER.md).
# A branch that moved after verification has a new tip and no note, so it is
# refused. All branches are checked before anything is merged.
#
# Each branch is merged with --no-ff, then scripts/wp/gates.sh runs on the
# integration worktree against the pre-merge commit (exactly what the branch
# brought in). On a conflict the merge is aborted; on a gate failure the merge
# is undone (reset to the pre-merge commit: the merge commit is seconds old and
# local, so nothing published is rewritten). Either way the train stops there
# and exits 1. Branches already contained in the integration branch are skipped.
# Nothing is pushed.
set -euo pipefail

usage() { awk 'NR > 1 && /^#/ && !/shellcheck/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit "${1:-2}"; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
into=integration
base=target/main
iwt=""
verify=1
gate_args=()
branches=()
while [ $# -gt 0 ]; do
  case "$1" in
    --into) into="${2:?}"; shift 2 ;;
    --base) base="${2:?}"; shift 2 ;;
    --worktree) iwt="${2:?}"; shift 2 ;;
    --no-verify-check) verify=0; shift ;;
    --full) gate_args+=(--full); shift ;;
    -h|--help) usage 0 ;;
    -*) echo "unknown option: $1" >&2; usage ;;
    *) branches+=("$1"); shift ;;
  esac
done
[ ${#branches[@]} -gt 0 ] || usage

repo="$(git -C "$here" rev-parse --show-toplevel)"
g() { git -C "$repo" "$@"; }

# --- preflight: every branch exists and is verified at its current tip -------
bad=0
for b in "${branches[@]}"; do
  if ! g rev-parse --verify --quiet "refs/heads/$b" >/dev/null; then
    echo "missing branch: $b" >&2; bad=1; continue
  fi
  if [ "$verify" = 1 ]; then
    tip="$(g rev-parse "$b")"
    verdict="$(g notes --ref=wp-verify show "$tip" 2>/dev/null | head -n 1 || true)"
    if [ "$verdict" != "VERDICT: PASS" ]; then
      echo "not verified at tip ${tip:0:8}: $b (${verdict:-no wp-verify note})" >&2; bad=1
    fi
  fi
done
[ "$bad" = 0 ] || { echo "nothing merged" >&2; exit 1; }

# --- integration worktree ---------------------------------------------------
if ! g rev-parse --verify --quiet "refs/heads/$into" >/dev/null; then
  g branch --no-track "$into" "$base"
  echo "created $into from $base ($(g rev-parse --short "$into"))"
fi
existing="$(g worktree list --porcelain | awk -v ref="branch refs/heads/$into" '
  /^worktree / { wt = substr($0, 10) } $0 == ref { print wt; exit }')"
if [ -n "$existing" ]; then
  iwt="$existing"
else
  iwt="${iwt:-${WP_WORKTREE_ROOT:-/root/wt}/${into//\//-}}"
  [ ! -e "$iwt" ] || { echo "$iwt exists but does not have $into checked out" >&2; exit 1; }
  g worktree add --quiet "$iwt" "$into"
fi
if [ -n "$(git -C "$iwt" status --porcelain --untracked-files=no)" ]; then
  echo "$iwt has uncommitted changes; refusing to merge into it" >&2; exit 1
fi
echo "integration: $into @ $(git -C "$iwt" rev-parse --short HEAD) in $iwt"

# --- the train ----------------------------------------------------------------
merged=()
skipped=()
status=0
stopped_at=""
for b in "${branches[@]}"; do
  if git -C "$iwt" merge-base --is-ancestor "$b" HEAD; then
    skipped+=("$b"); echo "== $b: already in $into, skipped"; continue
  fi
  pre="$(git -C "$iwt" rev-parse HEAD)"
  echo
  echo "== merging $b ($(git -C "$iwt" rev-parse --short "$b")) into $into"
  if ! git -C "$iwt" merge --no-ff --no-edit "$b"; then
    git -C "$iwt" merge --abort || git -C "$iwt" reset --hard "$pre"
    echo "== $b: merge conflict, aborted; $into stays at ${pre:0:8}"
    status=1; stopped_at="$b (conflict)"; break
  fi
  if "$here/gates.sh" "$iwt" --base "$pre" "${gate_args[@]}"; then
    merged+=("$b")
  else
    git -C "$iwt" reset --quiet --hard "$pre"
    echo "== $b: gates failed, merge undone; $into back at ${pre:0:8}"
    status=1; stopped_at="$b (gates)"; break
  fi
done

echo
echo "== merge-train summary: $into @ $(git -C "$iwt" rev-parse --short HEAD)"
echo "merged:  ${merged[*]:-none}"
[ ${#skipped[@]} -eq 0 ] || echo "skipped: ${skipped[*]} (already merged)"
if [ "$status" != 0 ]; then
  echo "stopped: $stopped_at"
  rest=()
  hit=0
  for b in "${branches[@]}"; do
    [ "$hit" = 1 ] && rest+=("$b")
    [ "$b" = "${stopped_at%% (*}" ] && hit=1
  done
  echo "pending: ${rest[*]:-none}"
fi
exit "$status"
