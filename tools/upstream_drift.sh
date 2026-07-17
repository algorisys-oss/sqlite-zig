#!/usr/bin/env bash
# upstream_drift.sh — report how far the upstream C reference has drifted past
# the commit our vendored sources (and therefore the Zig port) are anchored to.
#
# Our vendored baseline is SQLite 3.54.0-in-development:
#   SQLITE_SOURCE_ID  2026-06-24 14:17:52 395cbed103af08e3a4fafd9a3041205535e019d4...  (Fossil)
# The Fossil check-in maps to git commit BASELINE below in the GitHub mirror
# (same commit date; it was the clone point before the first `git pull`).
#
# This script is READ-ONLY: it never checks out, fetches, or mutates anything.
# It just tells you (a) whether a NEW RELEASE TAG exists past the baseline, and
# (b) which ported modules a sync would touch — so a version hop is a deliberate,
# scoped act, never accidental drift. Pass `--fetch` to refresh remote tags first.
#
# Usage:
#   tools/upstream_drift.sh              # baseline -> latest release tag (or master)
#   tools/upstream_drift.sh <ref>        # baseline -> <ref> (a tag, branch, or SHA)
#   tools/upstream_drift.sh --fetch      # `git fetch --tags` first, then report
#
# See PROGRESS.md § "Upstream sync anchor" for the anchor of record and the
# per-release re-vendor + re-port hop loop.

set -euo pipefail

REF="${SQLITE_C_REF:-/home/rajesh/opensource/sqlite-ports/sqlite-c}"
PROJ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Anchor of record: git commit in the mirror matching our vendored 3.54.0 SOURCE_ID.
BASELINE="1968870813"
BASELINE_DESC="3.54.0-dev / SOURCE_ID 395cbed1… / 2026-06-24 14:17:52"

# Engine paths whose changes can affect ported modules (skip test/, tool/, doc/).
ENGINE_PATHS=(src/ ext/fts5/ ext/rtree/ ext/misc/)

do_fetch=0
target=""
for arg in "$@"; do
  case "$arg" in
    --fetch) do_fetch=1 ;;
    *) target="$arg" ;;
  esac
done

[ -d "$REF/.git" ] || { echo "error: C reference not a git repo at $REF" >&2; exit 1; }
git -C "$REF" cat-file -e "$BASELINE" 2>/dev/null || {
  echo "error: baseline commit $BASELINE not found in $REF" >&2
  echo "       (has the mirror been re-cloned? re-resolve it by SOURCE_ID date)" >&2
  exit 1; }

[ "$do_fetch" = 1 ] && { echo "fetching tags…"; git -C "$REF" fetch --tags --quiet origin; }

# Default target: newest release tag if it is past the baseline, else master.
latest_tag="$(git -C "$REF" tag --list 'version-*' | sort -V | tail -1)"
if [ -z "$target" ]; then
  if [ -n "$latest_tag" ] && git -C "$REF" merge-base --is-ancestor "$BASELINE" "$latest_tag" 2>/dev/null \
     && [ "$(git -C "$REF" rev-list --count "$BASELINE..$latest_tag")" -gt 0 ]; then
    target="$latest_tag"
  else
    target="master"
  fi
fi

git -C "$REF" rev-parse --verify --quiet "$target^{commit}" >/dev/null || {
  echo "error: target ref '$target' not found in $REF" >&2; exit 1; }

target_sha="$(git -C "$REF" rev-parse --short "$target")"
ahead="$(git -C "$REF" rev-list --count "$BASELINE..$target" 2>/dev/null || echo '?')"

echo "──────────────────────────────────────────────────────────────────────"
echo " upstream drift report"
echo "──────────────────────────────────────────────────────────────────────"
echo " reference   : $REF"
echo " baseline    : $BASELINE  ($BASELINE_DESC)"
echo " target      : $target  ($target_sha)"
echo " latest tag  : ${latest_tag:-<none>}"
echo " commits ahead of baseline: $ahead"
echo

if [ "$ahead" = "0" ]; then
  echo " ✔ in sync — target has no commits past the baseline. Nothing to port."
  exit 0
fi

case "$target" in
  master|*/master|main|*/main)
    echo " ⚠ target is a MOVING branch, not a release tag. These commits are"
    echo "   unreleased dev-churn that can still change before the next release."
    echo "   Prefer syncing to a 'version-*' tag. (latest: ${latest_tag:-none})"
    echo ;;
esac

# Which ported Zig modules would a sync touch? Derive the ported set from src/*.zig.
mapfile -t ported < <(cd "$PROJ/src" 2>/dev/null && ls *.zig 2>/dev/null | sed 's/\.zig$//' | sort -u)
is_ported() { local s="$1"; for p in "${ported[@]}"; do [ "$p" = "$s" ] && return 0; done; return 1; }

echo " engine files changed in ${BASELINE}..${target}:"
echo " (● = we have a src/<name>.zig port that must be reconciled)"
echo
changed_ported=0 changed_total=0
while IFS=$'\t' read -r added removed path; do
  [ -z "${path:-}" ] && continue
  base="$(basename "$path")"; stem="${base%.*}"
  changed_total=$((changed_total+1))
  if is_ported "$stem"; then mark="●"; changed_ported=$((changed_ported+1)); else mark=" "; fi
  printf "   %s  %-34s +%-5s -%s\n" "$mark" "$path" "${added:-0}" "${removed:-0}"
done < <(git -C "$REF" diff --numstat "$BASELINE..$target" -- "${ENGINE_PATHS[@]}" \
           | grep -E '\.(c|h)$' || true)

echo
echo " summary: $changed_total engine files changed, $changed_ported of them map to"
echo "          ported Zig modules (●) that need re-porting for this hop."
echo
echo " next: see PROGRESS.md § 'Upstream sync anchor' for the re-vendor + re-port loop."
