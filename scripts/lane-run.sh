#!/usr/bin/env bash
# lane-run.sh — one clean run of one lane, from develop, every time.
#
# WHY THIS EXISTS. lane-dispatch.sh assumes the worktree is already where you
# want it. After a day of work that assumption is false: worktrees sit on
# whatever branch the last dispatch left, branches accumulate (354 local, 39
# unmerged remote at the time of writing), and each new run inherits that
# sediment. Every flaky symptom of that day traced back to state left behind —
# a dispatch refused for a dirty tree, a lane resuming into the wrong branch, an
# analysis run against a checkout six merges stale.
#
# So this does the one thing that removes the whole class: it puts the worktree
# on a FRESH branch cut from origin/develop before the console sees it, with a
# predictable name, and refuses rather than guessing when that is unsafe.
#
# usage: scripts/lane-run.sh <lane> <slug> <objective-file>
#        <slug> becomes the branch: lane<N>/<slug>
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
c_b=$'\033[1;36m'; c_r=$'\033[1;31m'; c_g=$'\033[1;32m'; c_d=$'\033[2m'; c_o=$'\033[0m'
log(){ printf '%s[lane-run]%s %s\n' "$c_b" "$c_o" "$*"; }
die(){ printf '%s[lane-run] %s%s\n' "$c_r" "$*" "$c_o" >&2; exit 1; }

LANE="${1:-}"; SLUG="${2:-}"; OBJ="${3:-}"
[ -n "$LANE" ] && [ -n "$SLUG" ] && [ -f "$OBJ" ] || die \
"usage: lane-run.sh <lane> <slug> <objective-file>
the slug names the branch (lane<N>/<slug>) so a run is identifiable from the
branch alone — 'chore/wire-new-guardrail-checkers' does not tell you which lane
produced it, and that ambiguity cost real time."

case "$SLUG" in *[!a-z0-9-]*) die "slug must be lowercase, digits and dashes only: '$SLUG'";; esac

BRANCH="lane${LANE}/${SLUG}"

# Find the worktree without claiming a console — the claim belongs to the
# dispatch, and taking it here would deadlock against it.
GH_DIR="$(dirname "$REPO_ROOT")"
# A worktree is only available when it is BOTH clean AND its console is
# unclaimed. Checking only cleanliness let two concurrent runs pick the same
# worktree; the second reached the dispatch and was refused there — correctly,
# but only after resetting the branch the first one was about to use.
LOCKDIR="$REPO_ROOT/${SWARM_COORD_DIR:-coordination}/.console-locks"
# The worktree -> console lookup used to be a `case` transcribed by hand from
# lane-dispatch.sh's registry. It fell out of sync exactly once and that was
# enough: three worktrees added to the registry stayed invisible here, so
# pick_wt() skipped them and dispatches bounced with "no clean worktree
# available" while three trees sat clean. Both scripts now read ONE table.
. "$REPO_ROOT/scripts/lib/console-registry.sh"
# Optional quota awareness. The operator pastes each CLI's /status into
# coordination/quota-observed.md (no CLI exposes quota non-interactively — see
# scripts/lib/quota-policy.sh for the full account). When that paste exists AND
# is fresh (<24h), pick_wt prefers the provider with the most headroom inside
# the requested class. With no file or stale data the function returns the
# class unchanged, so pick_wt's strict-class behavior is bit-for-bit what it
# was without this file.
. "$REPO_ROOT/scripts/lib/quota-policy.sh"
pick_wt() {
  # $1 = required console class (may be empty): a provider binary, or a
  # comma-separated list when several providers can serve the class. Worktrees
  # of that class are preferred STRICTLY: the lane names the provider its work
  # needs, and until 2026-09-01 that name was unreadable here, so whichever
  # worktree was idle chose the provider instead. Falling back to another
  # class is allowed — a lane that cannot run at all is worse than one that
  # runs on the wrong provider — but the caller is told, because a silent
  # deviation is how the imbalance stayed invisible for 114 dispatches.
  _want="${1:-}"
  # Quota preference: among the providers that can serve the class, the one
  # with the most headroom wins — but ONLY on fresh pasted data. No file, or
  # data older than 24h, yields _prefer = _want and this reduces to the strict
  # behavior described above.
  _prefer="$_want"
  if [ -n "$_want" ]; then
    _qp="$(quota_pick_provider "$_want" 2>/dev/null || true)"
    [ -n "$_qp" ] && _prefer="$_qp"
  fi
  _free=""
  for w in "$GH_DIR"/${SWARM_WT_PREFIX}*; do
    [ -d "$w/.git" ] || [ -f "$w/.git" ] || continue
    c="$(console_of_worktree "$w")"; [ -n "$c" ] || continue
    if [ -d "$LOCKDIR/$c" ]; then
      owner="$(cat "$LOCKDIR/$c/pid" 2>/dev/null || true)"
      # A lock whose owner is gone is not a claim; leave the reaping to the
      # dispatch, which owns the lock protocol, and just skip it here.
      [ -n "$owner" ] && kill -0 "$owner" 2>/dev/null && continue
    fi
    # Only usable if `git status` SUCCEEDS and reports empty. A FAILED status
    # (transient lock contention under concurrent picks) must NOT be read as
    # clean — with 2>/dev/null a failure yields empty stdout, and the old
    # `[ -z "$(...)" ]` misread that as clean, handing a DIRTY worktree to a
    # dispatch on 2026-09-13 (xn-claude with 9 untracked). If we cannot CONFIRM
    # clean, skip the worktree rather than guess.
    _st="$(git -C "$w" status --porcelain 2>/dev/null)" || continue
    [ -z "$_st" ] || continue
    if [ -n "$_want" ] && [ "$(console_binary "$c")" = "$_prefer" ]; then
      echo "$w"; return 0
    fi
    [ -n "$_free" ] || _free="$w"
  done
  [ -n "$_free" ] || return 1
  if [ -n "$_want" ]; then
    printf 'lane wanted %s; none free, running on %s instead\n' \
      "$_want" "$(console_binary "$(console_of_worktree "$_free")")" >&2
  fi
  echo "$_free"
}

log "preparing a clean branch ${BRANCH}"

# Serialize ONLY the fetch, not the whole run. Two concurrent fetches on one
# repository collide on .git/index.lock and the loser dies with an obscure
# "another git process seems to be running" — which is exactly how a dispatch
# was silently lost minutes after this script was written. Serializing the whole
# run instead would turn five parallel lanes into a queue and defeat the pool.
FETCHLOCK="$REPO_ROOT/${SWARM_COORD_DIR:-coordination}/.fetch-lock"
for _try in 1 2 3 4 5 6 7 8 9 10; do
  if mkdir "$FETCHLOCK" 2>/dev/null; then
    echo $$ > "$FETCHLOCK/pid"
    trap 'rm -rf "${FETCHLOCK:?}" 2>/dev/null || true' EXIT INT TERM
    # Hard timeout: a remote outage (origin unreachable, observed 2026-09-14)
    # otherwise hangs the fetch indefinitely under the lock. Best-effort (|| true):
    # on timeout we proceed with the refs we have rather than blocking the lane.
    timeout "${LANE_FETCH_TIMEOUT:-120}" git -C "$REPO_ROOT" fetch -q origin || true
    rm -rf "${FETCHLOCK:?}"; trap - EXIT INT TERM
    break
  fi
  _owner="$(cat "$FETCHLOCK/pid" 2>/dev/null || true)"
  if [ -n "$_owner" ] && ! kill -0 "$_owner" 2>/dev/null; then rm -rf "${FETCHLOCK:?}"; continue; fi
  [ "$_try" = "10" ] && die "could not take the fetch lock after 10 tries (held by pid ${_owner:-?})"
  sleep 2
done

# The reset is the whole point, so it is also the most dangerous line here. It
# only ever runs on a worktree that is already clean — a dirty tree means work
# someone did not commit, and discarding that is the one failure this project
# has actually suffered and rebuilt rules around.
WT="$(pick_wt "$(lane_class "$LANE")" || true)"
[ -n "$WT" ] || die "no clean worktree available — every one has uncommitted work.
Commit or stash it in the worktree itself; this script will not discard what it did not write."

git -C "$WT" checkout -q -B "$BRANCH" origin/${SWARM_BASE_BRANCH}
log "${c_g}$WT is on $BRANCH at $(git -C "$WT" rev-parse --short HEAD)${c_o}"

# Same table again — the second copy that used to live here is gone. An empty
# result is impossible for a worktree pick_wt returned, since pick_wt only ever
# returns one this lookup already named.
CONSOLE_ENV="$(console_of_worktree "$WT")"

log "dispatching lane $LANE on ${CONSOLE_ENV:-auto}"
CONSOLE="$CONSOLE_ENV" "$HERE/lane-dispatch.sh" "$LANE" "$(cat "$OBJ")"
RC=$?

AHEAD=$(git -C "$WT" rev-list --count "origin/${SWARM_BASE_BRANCH}..HEAD" 2>/dev/null || echo 0)
DIRTY=$(git -C "$WT" status --porcelain 2>/dev/null | wc -l | tr -d ' ')
log "exit=$RC  branch=$BRANCH  commits=$AHEAD  uncommitted=$DIRTY"
[ "$RC" = "0" ] && [ "$AHEAD" = "0" ] && \
  printf '%s[lane-run] exited clean but committed NOTHING — treat as a failure, not a pass%s\n' "$c_r" "$c_o"
exit $RC
