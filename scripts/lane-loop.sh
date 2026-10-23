#!/usr/bin/env bash
# lane-loop.sh — run a lane until its DONE-CHECK passes, or until the ceiling.
#
# WHAT THIS DOES AND DOES NOT DO. It re-dispatches a lane, feeding each failure
# back as the next attempt's input, until a mechanical check exits 0. That check
# is the objective's own definition of done, declared by the operator, and the
# loop can only ever verify what a command can decide: tests pass, a guardrail is
# green, a target runs.
#
# It CANNOT judge whether the work is right. A lane that keeps iterating until
# its own test goes green is the failure mode this project already knows well —
# four of six deliverables in one wave passed their own tests and still shipped
# real defects. So the loop stops at "mechanically satisfied" and hands the
# judgment back to the orchestrator, who runs the negative control and decides.
# A green loop is a REVIEW REQUEST, never a land.
#
# usage: scripts/lane-loop.sh <lane> <objective-file> <done-check-command> [max-iters]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
# Per-project glue: coord dir (the loop journal lives under it).
. "$REPO_ROOT/scripts/lib/swarm-config.sh"
c_blue=$'\033[1;36m'; c_dim=$'\033[2m'; c_red=$'\033[1;31m'; c_grn=$'\033[1;32m'; c_off=$'\033[0m'
log() { printf '%s[lane-loop]%s %s\n' "$c_blue" "$c_off" "$*"; }
die() { printf '%s[lane-loop] %s%s\n' "$c_red" "$*" "$c_off" >&2; exit 1; }

LANE="${1:-}"; OBJ_FILE="${2:-}"; DONE_CHECK="${3:-}"; MAX="${4:-3}"
[ -n "$LANE" ] && [ -f "$OBJ_FILE" ] && [ -n "$DONE_CHECK" ] || die \
"usage: lane-loop.sh <lane> <objective-file> '<done-check>' [max-iters]

the done-check is a shell command that must exit 0 when the objective is met.
it is the contract. if you cannot write one, the objective is not yet closed
enough to dispatch — say what 'done' means as a command first."

OBJECTIVE="$(cat "$OBJ_FILE")"
LOGDIR="$REPO_ROOT/${SWARM_COORD_DIR}/loop-logs"; mkdir -p "$LOGDIR"
TS="$(date -u '+%Y%m%dT%H%M%SZ')"
JOURNAL="$LOGDIR/${TS}-lane-${LANE}.md"

{
  echo "# lane $LANE loop — $TS"
  echo
  echo "**Done-check:** \`$DONE_CHECK\`"
  echo "**Ceiling:** $MAX attempts"
  echo
} > "$JOURNAL"

# Baseline: a done-check that ALREADY passes means the objective is met without
# work, or the check is vacuous. Either way the operator must know before a
# single token is spent.
if eval "$DONE_CHECK" >/dev/null 2>&1; then
  log "${c_grn}done-check ALREADY passes before any attempt${c_off}"
  echo "- Baseline: check passed before attempt 1. Either the work is done, or the check cannot fail. Verify which." >> "$JOURNAL"
  die "refusing to dispatch: the done-check passes on the current tree. Prove it can fail first, or the loop is theatre."
fi
echo "- Baseline: done-check fails on the current tree (good — it can distinguish)." >> "$JOURNAL"

FEEDBACK=""
for i in $(seq 1 "$MAX"); do
  log "attempt $i/$MAX — dispatching lane $LANE"
  PROMPT="$OBJECTIVE"
  if [ -n "$FEEDBACK" ]; then
    PROMPT="$OBJECTIVE

## Attempt $i — what the previous attempt left unfinished

Your last attempt did NOT satisfy the done-check. This is the check and its
output. Read it before changing anything: the gap is stated, not guessed.

\`\`\`
$DONE_CHECK
$FEEDBACK
\`\`\`

Do not restart from scratch — your previous work is on your branch. Close the
gap the output names. If the check itself is wrong, say so with evidence and
stop; a check that cannot be satisfied is the operator's defect, not yours."
  fi

  set +e
  if [ "$i" -eq 1 ]; then
    "$HERE/lane-dispatch.sh" "$LANE" "$PROMPT"
  else
    # Attempt 2+ RESUMES the console's session instead of restarting cold. A
    # restart discards everything the previous attempt reasoned through and
    # every uncommitted file it left, which is how a lane can burn three full
    # passes re-deriving the same context. The gap-feedback prompt reads as the
    # next turn of a conversation the console already remembers.
    CONTINUE=1 "$HERE/lane-dispatch.sh" "$LANE" "$PROMPT"
  fi
  RC=$?
  set -e
  echo "- Attempt $i: dispatch exit $RC" >> "$JOURNAL"
  if [ "$RC" -ne 0 ]; then
    # A dispatch that never ran is NOT a lane that failed to converge. Reporting
    # it as "ceiling reached" sends the operator to read attempts that do not
    # exist. Say which of the two happened.
    {
      echo
      echo "## Status: dispatch failed on attempt $i (exit $RC) — the lane never ran"
      echo
      echo "This is not a convergence failure. Nothing was attempted. Common causes:"
      echo "a dirty worktree, every console of the class busy, or a console that"
      echo "cannot authenticate. Read the dispatch output above, fix that, re-run."
    } >> "$JOURNAL"
    log "${c_red}dispatch failed (exit $RC) — the lane never ran; not retrying${c_off}"
    log "journal: ${JOURNAL#"$REPO_ROOT"/}"
    exit 2
  fi

  set +e
  OUT="$(eval "$DONE_CHECK" 2>&1)"
  CHECK_RC=$?
  set -e
  if [ "$CHECK_RC" -eq 0 ]; then
    log "${c_grn}done-check PASSED on attempt $i${c_off}"
    {
      echo "- Attempt $i: **done-check passed**"
      echo
      echo "## Status: awaiting orchestrator review"
      echo
      echo "The mechanical check is satisfied. That is NOT approval. The"
      echo "orchestrator still has to run the negative control — sabotage what the"
      echo "change claims to guard and confirm the test goes red — before this lands."
    } >> "$JOURNAL"
    log "journal: ${JOURNAL#"$REPO_ROOT"/}"
    log "${c_dim}mechanically satisfied — NOT approved. orchestrator review required.${c_off}"
    exit 0
  fi
  FEEDBACK="$(printf '%s' "$OUT" | tail -30)"
  echo "- Attempt $i: check failed, feeding output into attempt $((i+1))" >> "$JOURNAL"
done

{
  echo
  echo "## Status: ceiling reached without satisfying the check"
  echo
  echo "$MAX attempts did not close it. Do NOT simply raise the ceiling — a lane"
  echo "that cannot converge in $MAX passes is usually facing a wrong objective, a"
  echo "wrong check, or work that needs splitting. Read the attempts before"
  echo "re-dispatching."
} >> "$JOURNAL"
log "${c_red}ceiling reached ($MAX) without the check passing${c_off}"
log "journal: ${JOURNAL#"$REPO_ROOT"/}"
exit 3
