#!/usr/bin/env bash
# lane-reap.sh — sweep STALE untracked files out of idle console worktrees so a
# leftover file can't block a dispatch.
#
# WHY: 2026-09-13, xn-claude carried 9 untracked probe files from two weeks
# earlier; a dispatch refused it (correctly — never discard what you did not
# write). But those files were disposable residue, and there was no safe way to
# clear them, so the lane bounced until cleared by hand. This is that broom.
#
# ANTI-CLOBBER SAFE — three hard guarantees:
#   1. It backs EVERY file up to a timestamped archive before removing it, so
#      nothing is destroyed (recover from coordination/.reap-archive/<ts>/).
#   2. It touches ONLY untracked files (git ls-files --others). A worktree with
#      any TRACKED modification (real, uncommitted WIP) is skipped untouched.
#   3. It skips any worktree a live console has locked.
#
# usage: scripts/lane-reap.sh [--dry-run]
#   --dry-run  report what WOULD be reaped; change nothing.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
GH_DIR="$(dirname "$REPO_ROOT")"
c_b=$'\033[1;36m'; c_y=$'\033[1;33m'; c_g=$'\033[1;32m'; c_d=$'\033[2m'; c_o=$'\033[0m'
log(){ printf '%s[lane-reap]%s %s\n' "$c_b" "$c_o" "$*"; }
warn(){ printf '%s[lane-reap] %s%s\n' "$c_y" "$*" "$c_o"; }

. "$REPO_ROOT/scripts/lib/console-registry.sh"
LOCKDIR="$REPO_ROOT/${SWARM_COORD_DIR}/.console-locks"

DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1
ARCHIVE="$REPO_ROOT/${SWARM_COORD_DIR}/.reap-archive/$(date -u +%Y%m%dT%H%M%SZ)"

reaped_files=0; reaped_wts=0; skipped_wip=0; skipped_locked=0

for w in "$GH_DIR"/${SWARM_WT_PREFIX}*; do
  [ -d "$w/.git" ] || [ -f "$w/.git" ] || continue
  c="$(console_of_worktree "$w")"; [ -n "$c" ] || continue

  # Skip a worktree a live console owns.
  if [ -d "$LOCKDIR/$c" ]; then
    owner="$(cat "$LOCKDIR/$c/pid" 2>/dev/null || true)"
    if [ -n "$owner" ] && kill -0 "$owner" 2>/dev/null; then
      skipped_locked=$((skipped_locked + 1)); continue
    fi
  fi

  # Never reap a worktree with tracked (uncommitted) modifications — that is
  # real WIP, coordinate instead. A failed status is also a refusal.
  tracked="$(git -C "$w" status --porcelain --untracked-files=no 2>/dev/null)" || {
    warn "$(basename "$w"): git status failed — skipping"; continue; }
  if [ -n "$tracked" ]; then
    warn "$(basename "$w"): has tracked WIP ($(printf '%s' "$tracked" | grep -c .) file(s)) — skipping, coordinate don't reap"
    skipped_wip=$((skipped_wip + 1)); continue
  fi

  # Untracked files (respecting .gitignore) are the only reap candidates.
  # bash 3.2 (the macOS default) has no `mapfile`; read NUL-delimited so paths
  # with spaces survive.
  untracked=()
  while IFS= read -r -d '' f; do
    [ -n "$f" ] && untracked+=("$f")
  done < <(git -C "$w" ls-files --others --exclude-standard -z 2>/dev/null || true)
  [ "${#untracked[@]}" -gt 0 ] || continue

  log "$(basename "$w"): ${#untracked[@]} untracked file(s) $([ "$DRY" = 1 ] && echo '(dry-run)')"
  wt_had=0
  for f in "${untracked[@]}"; do
    [ -n "$f" ] || continue
    printf '%s    %s%s\n' "$c_d" "$f" "$c_o"
    if [ "$DRY" = 0 ]; then
      dest="$ARCHIVE/$(basename "$w")/$f"
      mkdir -p "$(dirname "$dest")"
      cp "$w/$f" "$dest" && rm "$w/$f"
    fi
    reaped_files=$((reaped_files + 1)); wt_had=1
  done
  [ "$wt_had" = 1 ] && reaped_wts=$((reaped_wts + 1))
done

echo
if [ "$DRY" = 1 ]; then
  log "DRY-RUN: would reap $reaped_files file(s) from $reaped_wts worktree(s); $skipped_wip with WIP, $skipped_locked locked (skipped)."
else
  log "${c_g}reaped $reaped_files file(s) from $reaped_wts worktree(s)${c_o} → backup: ${ARCHIVE#"$REPO_ROOT"/}"
  log "$skipped_wip worktree(s) with WIP skipped, $skipped_locked locked."
fi
