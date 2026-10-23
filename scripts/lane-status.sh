#!/usr/bin/env bash
# lane-status.sh — the operator's single view of the swarm.
#
# `scripts/lane-dispatch.sh` fires work into a lane. This answers the other
# half: what is out there right now, what came back, and what is waiting on me.
#
# Everything here is READ-ONLY. It runs no console, changes no state, and does
# not fetch by default (pass --fetch when you want fresh remote refs).
#
# Usage:
#   scripts/lane-status.sh            # the board
#   scripts/lane-status.sh --fetch    # refresh origin first (slower)
#   make lanes                        # same thing

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GH_DIR="$(dirname "$REPO_ROOT")"
cd "$REPO_ROOT"

# Per-project glue: base branch, coord dir, worktree prefix.
. "$REPO_ROOT/scripts/lib/swarm-config.sh"
# Manifest accessors: console roster + lane ownership (single source of truth).
. "$REPO_ROOT/scripts/lib/manifest.sh"

b=$'\033[1m'; dim=$'\033[2m'; cy=$'\033[1;36m'; gn=$'\033[32m'; yl=$'\033[33m'; rd=$'\033[31m'; off=$'\033[0m'
hdr() { printf '\n%s%s%s\n' "$cy" "$1" "$off"; }

[ "${1:-}" = "--fetch" ] && { printf '%sfetching origin...%s\n' "$dim" "$off"; git fetch -q origin 2>/dev/null || true; }

DEV="$(git rev-parse --short origin/${SWARM_BASE_BRANCH} 2>/dev/null || echo '?')"
printf '%s'"${SWARM_PROJECT_LABEL}"' swarm%s   '"${SWARM_BASE_BRANCH}"' @ %s   %s\n' "$b" "$off" "$DEV" "$(date '+%Y-%m-%d %H:%M')"

# ── consoles ────────────────────────────────────────────────────────────────
# Roster + lane ownership come straight from the manifest: swarm_consoles for the
# console list, console_lanes to invert the load-bearing lanes[].console field. No
# hand-kept table to drift — adding lane 7/8 to the agreement surfaces them here for
# free, and the LANES shown are exactly the lanes a dispatch to that console lands in.
hdr "CONSOLES"
printf '  %-8s %-22s %-34s %-8s %s\n' "CONSOLE" "LANES" "BRANCH" "DIRTY" "BEHIND"
consoles="$(swarm_consoles)"
[ -z "$consoles" ] && printf '  %sno manifest roster — check SWARM_MANIFEST (%s)%s\n' "$rd" "$SWARM_MANIFEST" "$off"
for con in $consoles; do
  owned="$(console_lanes "$con")"
  bkp="$(console_backup_lanes "$con")"
  lanes_col="$(echo "$owned" | sed 's/ /, /g')"
  [ -z "$owned" ] && lanes_col="—"
  [ -n "$bkp" ] && lanes_col="$lanes_col  +bkp:$(echo "$bkp" | sed 's/ /,/g')"
  wt="$GH_DIR/${SWARM_WT_PREFIX}$con"
  if [ ! -d "$wt" ]; then
    printf '  %-8s %-22s %s%-34s%s\n' "$con" "$lanes_col" "$rd" "worktree missing" "$off"; continue
  fi
  br="$(git -C "$wt" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
  dirty="$(git -C "$wt" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
  behind="$(git -C "$wt" rev-list --count HEAD..origin/${SWARM_BASE_BRANCH} 2>/dev/null || echo '?')"
  dc="$gn"; [ "$dirty" != "0" ] && dc="$yl"
  printf '  %-8s %-22s %-34s %s%-8s%s %s\n' "$con" "$lanes_col" "${br:0:34}" "$dc" "$dirty" "$off" "$behind"
done

# ── branches waiting on the operator ────────────────────────────────────────
hdr "AWAITING REVIEW  (pushed, not in ${SWARM_BASE_BRANCH})"
found=0
while read -r ref; do
  [ -z "$ref" ] && continue
  short="${ref#origin/}"
  case "$short" in ${SWARM_BASE_BRANCH}|main|dev|demo|HEAD) continue ;; esac
  ahead="$(git rev-list --count origin/${SWARM_BASE_BRANCH}.."$ref" 2>/dev/null || echo 0)"
  [ "$ahead" = "0" ] && continue
  when="$(git log -1 --format='%ad' --date=format:'%m-%d %H:%M' "$ref" 2>/dev/null)"
  subj="$(git log -1 --format='%s' "$ref" 2>/dev/null | cut -c1-52)"
  printf '  %s%2s%s  %-13s %-44s %s\n' "$gn" "$ahead" "$off" "$when" "${short:0:44}" "$subj"
  found=$((found+1))
done < <(git for-each-ref --sort=-committerdate --format='%(refname:short)' refs/remotes/origin 2>/dev/null | head -25 || true)
[ "$found" = "0" ] && printf '  %snothing pending%s\n' "$dim" "$off"

# ── inbox ───────────────────────────────────────────────────────────────────
hdr "INBOX  (unprocessed dispatches per lane)"
for L in $(lanes_current); do
  d="${SWARM_COORD_DIR}/inbox/lane-$L"
  [ -d "$d" ] || continue
  n="$(find "$d" -maxdepth 1 -name '*.md' 2>/dev/null | wc -l | tr -d ' ')"
  [ "$n" = "0" ] && continue
  # `ls -t | head -1` under `set -o pipefail`: head closes the pipe after the first
  # line and ls exits on SIGPIPE (141); `|| true` keeps that EXPECTED signal from
  # tripping errexit and aborting the whole board mid-render on a busy inbox.
  last="$(ls -t "$d"/*.md 2>/dev/null | head -1 || true)"
  printf '  lane-%-3s %4s msgs   last: %s\n' "$L" "$n" "$(basename "${last:-—}" | cut -c1-58)"
done

# ── run transcripts ─────────────────────────────────────────────────────────
hdr "LAST DISPATCH RUNS"
if [ -d ${SWARM_COORD_DIR}/dispatch-logs ]; then
  ls -t ${SWARM_COORD_DIR}/dispatch-logs/*.log 2>/dev/null | head -5 | while read -r f; do
    printf '  %-46s %6s lines\n' "$(basename "$f")" "$(wc -l < "$f" | tr -d ' ')"
  done || true  # same head-closes-pipe SIGPIPE guard as the inbox listing above
else
  printf '  %snone yet — nothing dispatched from this machine%s\n' "$dim" "$off"
fi

# ── leases ──────────────────────────────────────────────────────────────────
hdr "ACTIVE SCOPE LEASES"
if grep -q 'ACTIVE' ${SWARM_COORD_DIR}/scope-leases.md 2>/dev/null; then
  grep '| `' ${SWARM_COORD_DIR}/scope-leases.md | grep 'ACTIVE' | while IFS='|' read -r _ id owner _ rest; do
    printf '  %-32s %s\n' "$(echo "$id" | tr -d ' `' | cut -c1-32)" "$(echo "$owner" | sed 's/^ *//;s/ *$//' | cut -c1-40)"
  done
else
  printf '  %snone%s\n' "$dim" "$off"
fi

# ── stale status ledger ─────────────────────────────────────────────────────
# Manifest-driven, like CONSOLES/INBOX above: walk the CURRENT lanes and show each
# one's ledger freshness — or that it has none yet. The old `status/lane-*.md` glob
# mixed retired lanes in as noise AND silently omitted a current lane that had not
# filed a ledger, so the board neither matched the roster nor flagged a missing one.
hdr "STATUS LEDGER FRESHNESS"
for L in $(lanes_current); do
  f="${SWARM_COORD_DIR}/status/lane-$L.md"
  if [ -f "$f" ]; then
    age_d=$(( ( $(date +%s) - $(stat -f %m "$f" 2>/dev/null || stat -c %Y "$f") ) / 86400 ))
    c="$gn"; [ "$age_d" -gt 7 ] && c="$yl"; [ "$age_d" -gt 30 ] && c="$rd"
    printf '  %-16s %s%3sd ago%s\n' "lane-$L" "$c" "$age_d" "$off"
  else
    printf '  %-16s %sno ledger yet%s\n' "lane-$L" "$dim" "$off"
  fi
done

printf '\n%sdispatch:%s  make lane-dispatch LANE=<k0|1-6> OBJ="<closed objective>"\n' "$b" "$off"
printf '%sland:%s      scripts/local-land.sh <branch>   (after you read the diff)\n\n' "$b" "$off"
