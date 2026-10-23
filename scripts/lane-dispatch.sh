#!/usr/bin/env bash
# lane-dispatch.sh — fire work into a lane from one place, without opening its console.
#
# The swarm model (docs/AGENT-SWARM-OPERATIONS.md) routes work by LANE; the
# operating agreement (docs/SWARM-OPERATING-AGREEMENT.md) maps each lane to a
# CONSOLE and each console to its own git worktree. This script joins the two:
# give it a lane and an objective, and it
#
#   1. writes a dispatch file into coordination/inbox/lane-<N>/  (audit trail,
#      write-once, the protocol's own format), and
#   2. runs that lane's console NON-INTERACTIVELY in that console's worktree,
#      capturing the transcript.
#
# All three consoles support a one-shot prompt, which is what makes this work:
#     claude -p "<prompt>"        codex exec "<prompt>"        kimi -p "<prompt>"
#
# Usage:
#   scripts/lane-dispatch.sh <lane> "<objective>"
#   scripts/lane-dispatch.sh k0 "Route the Phase 0 doc-drift gate work"
#   DRY_RUN=1 scripts/lane-dispatch.sh 2 "..."      # write the dispatch, don't run
#   NO_RUN=1  scripts/lane-dispatch.sh 2 "..."      # alias of DRY_RUN
#
# Env overrides:
#   CONSOLE=claude|codex|kimi|kimi2  force a console (default: from the lane map)
#   TIMEOUT=<seconds>           wall clock cap per run (default 1800)
#
# HONEST LIMITS — read these before trusting the output:
#   * A one-shot run has NO conversation. The console cannot ask you a
#     clarifying question; if the objective is ambiguous it will guess. Write
#     objectives that are closed, with an explicit definition of done.
#   * These runs are auto-approving by construction (that is the point of not
#     interacting). Scope each objective narrowly and review the diff.
#   * The run does NOT land anything. It stops at a pushed branch at most;
#     landing stays a deliberate `scripts/local-land.sh` step.
#   * Concurrent lanes touching the same files still collide. Claim scope in
#     coordination/scope-leases.md first — this script does not do it for you.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GH_DIR="$(dirname "$REPO_ROOT")"
TIMEOUT="${TIMEOUT:-1800}"

c_blue=$'\033[1;36m'; c_dim=$'\033[2m'; c_red=$'\033[1;31m'; c_off=$'\033[0m'
log()  { printf '%s[lane-dispatch]%s %s\n' "$c_blue" "$c_off" "$*"; }
dim()  { printf '%s  %s%s\n' "$c_dim" "$*" "$c_off"; }
die()  { printf '%s[lane-dispatch] %s%s\n' "$c_red" "$*" "$c_off" >&2; exit 1; }

# ── lane → console, per docs/SWARM-OPERATING-AGREEMENT.md § 2 ────────────────
# Four consoles across THREE tools: the operator runs two Kimi sessions. The
# runbook's fourth console is OpenCode, which is not what this operator uses, so
# lane 1 — "API + serializers + compliance shipping", OpenCode's slot there —
# is served by a second Kimi in its own worktree instead. Same binary, separate
# session, separate worktree, so the isolation rule still holds.
# ── console pool ─────────────────────────────────────────────────────────────
# The session -> binary -> worktree table used to live here as a literal. It
# also lived, transcribed by hand, inside lane-run.sh. Adding three worktrees to
# the copy here did nothing for a day because the other copy was never updated;
# see scripts/lib/console-registry.sh for the full account. There is now exactly
# ONE table, and both scripts read it from that file.
. "$REPO_ROOT/scripts/lib/console-registry.sh"

# A lane names the KIND of console it needs, never a specific session. The static
# lane->console map this replaces let lane 2 and lane 5 both resolve to `codex`,
# so two dispatches would run concurrently in xn-codex and destroy each other's
# working tree. The pool makes that impossible instead of merely unlikely.
# lane_class() now lives in scripts/lib/console-registry.sh — one source, so
# lane-run.sh can honour it when picking a worktree.

# ── claim / release ──────────────────────────────────────────────────────────
LOCKDIR="$REPO_ROOT/${SWARM_COORD_DIR}/.console-locks"
CLAIMED=""
release_console() { [ -n "$CLAIMED" ] && rm -rf "${LOCKDIR:?}/${CLAIMED:?}" 2>/dev/null; CLAIMED=""; }
trap release_console EXIT INT TERM

# Echoes the claimed console name, or nothing when every session of the class is
# busy. `mkdir` is the lock primitive because it is ATOMIC: two dispatches racing
# for the last free session cannot both succeed, which a test-then-create check
# (`[ -d ] || mkdir`) would allow.
claim_console() {
  mkdir -p "$LOCKDIR"
  for c in $(consoles_of_class "$1"); do
    if mkdir "$LOCKDIR/$c" 2>/dev/null; then
      echo $$ > "$LOCKDIR/$c/pid"; echo "$c"; return 0
    fi
    # A lock whose owner is dead is not a claim — a killed dispatch would
    # otherwise strand its console forever. Reap it and retry that one console.
    p="$(cat "$LOCKDIR/$c/pid" 2>/dev/null || true)"
    if [ -n "$p" ] && ! kill -0 "$p" 2>/dev/null; then
      rm -rf "${LOCKDIR:?}/${c:?}"
      if mkdir "$LOCKDIR/$c" 2>/dev/null; then
        echo $$ > "$LOCKDIR/$c/pid"; echo "$c"; return 0
      fi
    fi
  done
  return 1
}

busy_consoles() {
  for c in $(consoles_of_class "$1"); do
    [ -d "$LOCKDIR/$c" ] && printf '%s ' "$c"
  done
}

# ── args ─────────────────────────────────────────────────────────────────────
LANE="${1:-}"; OBJECTIVE="${2:-}"
[ -n "$LANE" ] && [ -n "$OBJECTIVE" ] || die "usage: scripts/lane-dispatch.sh <lane> \"<objective>\"  (lanes: k0 1 2 3 4 5 6)"

CLASS="$(lane_class "$LANE")"
[ -n "$CLASS" ] || die "unknown lane '$LANE' — the model defines k0 and 1-6 only. Do not create Lane 7."

if [ -n "${CONSOLE:-}" ]; then
  # An explicit override still has to be CLAIMED. An override that skipped the
  # lock would reintroduce exactly the collision the pool exists to prevent.
  [ -n "$(console_binary "$CONSOLE")" ] || die "unknown console '$CONSOLE' — scripts/lib/console-registry.sh has: $(printf '%s\n' "$CONSOLE_REGISTRY" | awk 'NF{printf "%s ", $1}')"
  mkdir -p "$LOCKDIR"
  mkdir "$LOCKDIR/$CONSOLE" 2>/dev/null || die "console '$CONSOLE' is already claimed by another dispatch (pid $(cat "$LOCKDIR/$CONSOLE/pid" 2>/dev/null || echo '?')). Wait for it, or let the pool choose."
  echo $$ > "$LOCKDIR/$CONSOLE/pid"
else
  CONSOLE="$(claim_console "$CLASS" || true)"
  [ -n "$CONSOLE" ] || die "every '$CLASS' console is busy: $(busy_consoles "$CLASS")
  wait for one to finish, or add a session to scripts/lib/console-registry.sh with its own worktree."
fi
CLAIMED="$CONSOLE"

BIN="$(console_binary "$CONSOLE")"
command -v "$BIN" >/dev/null 2>&1 || die "console '$CONSOLE' needs the '$BIN' binary, which is not on PATH"

# PROBE the console instead of inferring from config. Three preflights in a row
# were written here that could not fail: `kimi --help` succeeds while
# unconfigured; a `default_model` key check passes after `kimi migrate` brings
# the model over WITHOUT the credential ("provider managed:kimi-code has no
# credential configured"). Every config-shaped check guesses at what predicts a
# successful run. A trivial real prompt does not guess — it is the same code
# path the dispatch will take, so if it answers, the dispatch can run.
# Costs one cheap call per dispatch. SKIP_PROBE=1 opts out.
if [ -z "${SKIP_PROBE:-}" ]; then
  case "$BIN" in
    claude) PROBE_OUT="$(timeout 90 claude -p "Reply with OK." --output-format text 2>&1 || true)" ;;
    codex)  PROBE_OUT="$(timeout 90 codex exec -C "$GH_DIR" -s read-only "Reply with OK." 2>&1 || true)" ;;
    kimi)   PROBE_OUT="$(cd "$GH_DIR" && timeout 90 kimi -p "Reply with OK." --output-format text 2>&1 || true)" ;;
  esac
  if printf '%s' "$PROBE_OUT" | grep -qiE 'no credential|not configured|no model configured|not logged in|unauthor|Cannot combine|command not found|agent .* not found|Usage:'; then
    case "$BIN" in
      kimi)     HINT="run \`kimi\` interactively and /login. \`kimi migrate\` brings the model config over from a legacy ~/.kimi install but NOT the credential." ;;
      *)        HINT="check that \`$CONSOLE\` is signed in and configured." ;;
    esac
    die "console '$CONSOLE' cannot run — probe failed:
  $(printf '%s' "$PROBE_OUT" | grep -iE 'error|no credential|not configured|not found' | head -2)
  Fix: $HINT
  Re-run when the probe answers."
  fi
fi

WT="$(console_worktree "$CONSOLE")"
[ -d "$WT" ] || die "worktree missing: $WT
  create it:  git worktree add $WT -b console/$CONSOLE origin/${SWARM_BASE_BRANCH}"

# The worktree must be clean — a one-shot run cannot negotiate a dirty tree,
# and the anti-clobber HARD RULES forbid operating over someone else's edits.
DIRTY="$(git -C "$WT" status --porcelain | wc -l | tr -d ' ')"
[ "$DIRTY" = "0" ] || die "worktree $WT has $DIRTY uncommitted file(s). Commit or stash in that console first (docs/COLLABORATION_PROTOCOL.md § Git Safety)."

# ── 1. dispatch file (audit trail, protocol format, write-once) ──────────────
TS="$(date -u '+%Y%m%dT%H%M%SZ')"
ISO="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
SLUG="$(printf '%s' "$OBJECTIVE" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | cut -c1-48 | sed 's/-$//')"
INBOX="$REPO_ROOT/${SWARM_COORD_DIR}/inbox/lane-$LANE"
mkdir -p "$INBOX"
DISPATCH="$INBOX/${TS}-from-operator-${SLUG}.md"

cat > "$DISPATCH" <<EOF
---
ts: $ISO
from: operator
to: lane-$LANE
type: dispatch
ack_required: true
preferred-agent: $CONSOLE
reason: routed by scripts/lane-dispatch.sh per the lane→console map
---

# Dispatch: $OBJECTIVE

## Objective
$OBJECTIVE

## Console
$CONSOLE, running non-interactively in \`$WT\`.

## Your working directory is the ONLY one you may write to

Every path you write MUST resolve inside \`$WT\`. Do not write to
\`$REPO_ROOT\` — that is the operator's checkout, other lanes read it, and a
stray write there lands outside your branch where nobody is reviewing it.

This is not hypothetical. The project CLAUDE.md names \`$REPO_ROOT\` as the
primary working directory, so a lane that trusts that line writes home instead
of into its worktree. It has already happened: a lane produced its work
correctly on its own branch AND left a stale draft of the same two files in the
operator's checkout, where it sat uncommitted until someone noticed.

Prefer relative paths. If you must use an absolute one, build it from \`$WT\`.

## Validation
Run the suite relevant to what you touched. Remember \`make ci-verify\` is lint,
NOT tests. Land with \`scripts/local-land.sh\` only after local green.
EOF

log "lane $LANE → console $CONSOLE"
dim "worktree:  $WT"
dim "dispatch:  ${DISPATCH#"$REPO_ROOT"/}"

if [ -n "${DRY_RUN:-}${NO_RUN:-}" ]; then
  log "DRY_RUN — dispatch written, console not invoked."
  exit 0
fi

# ── optional prior-context injection (portable hook, fail-soft) ──────────────
# swarm_prior_context (lib/swarm-config.sh) runs the project's SWARM_CONTEXT_CMD
# hook — an Engram query, a notes grep, anything — and returns advisory recall to
# fold into the prompt, or nothing. OFF by default: CONTEXT_BLOCK stays empty and
# the prompt below is byte-identical to having no hook. The fail-soft contract
# lives in the helper: a missing / failing / timing-out / empty command yields
# nothing and NEVER blocks the dispatch. Kept in a sourced lib so it is unit-tested
# in isolation (scripts/tests/test_context_hook.sh) rather than only end-to-end.
CONTEXT_BLOCK="$(swarm_prior_context "$LANE" "$OBJECTIVE")"
[ -n "$CONTEXT_BLOCK" ] && log "injected ${#CONTEXT_BLOCK} chars of prior context (SWARM_CONTEXT_CMD)"

# ── 2. the prompt handed to the console ─────────────────────────────────────
read -r -d '' PROMPT <<EOF || true
You are working lane $LANE of the xNinja development swarm, in a one-shot
non-interactive run. There is no human to ask, so if the objective is
ambiguous, choose the narrowest reasonable reading, state the assumption in
your closeout, and stop rather than widening scope.

Read first: CLAUDE.md, docs/AGENT-SWARM-OPERATIONS.md (your lane's charter),
docs/SWARM-OPERATING-AGREEMENT.md. Load the skills CLAUDE.md maps to what you
are touching BEFORE writing code.
$CONTEXT_BLOCK
Your dispatch: $DISPATCH

OBJECTIVE
$OBJECTIVE

RULES
- Work only in this worktree. Branch from fresh upstream:
  git fetch origin ${SWARM_BASE_BRANCH} && git checkout -b <type>/<subject> origin/${SWARM_BASE_BRANCH}
- git add your exact files. Never -A, never ., never -u.
- make ci-verify is lint, not tests — run the relevant suite yourself.
- Do NOT land. Stop at a committed, pushed branch and report its name.
- Write your closeout to ${SWARM_COORD_DIR}/status/lane-$LANE.md. Edit no other
  lane's status file.
EOF

LOGDIR="$REPO_ROOT/${SWARM_COORD_DIR}/dispatch-logs"
mkdir -p "$LOGDIR"
RUNLOG="$LOGDIR/${TS}-lane-${LANE}-${CONSOLE}.log"

# ── event stream ─────────────────────────────────────────────────────────────
# One structured record per dispatch, appended to a JSONL the operator can tail.
#
# Why here and not OpenTelemetry: Claude Code ships native OTel (it emits cost,
# tokens, commits and tool decisions, and honours TRACEPARENT even under -p), but
# kimi and codex have no equivalent. Wiring only the Claude path would produce a
# dashboard covering one of five lanes while LOOKING complete — the exact class
# of indicator this project spends its time removing. The dispatch layer is the
# one place that sees all five identically.
#
# Deliberately thin: lane, console, worktree, branch, timing, exit, and what the
# branch gained. It does NOT try to report progress mid-run, because nothing here
# can distinguish a console that is thinking from one that is stuck — and a
# progress field that guesses is worse than none.
EVENTS="$REPO_ROOT/${SWARM_COORD_DIR}/lane-events.jsonl"
_json_str() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
emit_event() {
  printf '{"ts":"%s","event":"%s","lane":"%s","console":"%s","worktree":"%s","branch":"%s"%s}\n' \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1" "$LANE" "$CONSOLE" "${WT##*/}" \
    "$(git -C "$WT" rev-parse --abbrev-ref HEAD 2>/dev/null)" "${2:-}" >> "$EVENTS" 2>/dev/null || true
}

preserve_uncommitted_work() {
  local subject="$1"
  local body="$2"

  if [ -n "$(git -C "$WT" status --porcelain 2>/dev/null)" ]; then
    git -C "$WT" add -A 2>/dev/null
    git -C "$WT" -c user.email=lane@local -c user.name="lane-dispatch" \
      commit -q -m "$subject

Committed by lane-dispatch, NOT by the agent. $body" 2>/dev/null \
      && log "uncommitted work preserved as a WIP commit -- review it"
  fi
}

START_EPOCH="$(date +%s)"
BASE_SHA="$(git -C "$WT" rev-parse HEAD 2>/dev/null)"
# ${CONTINUE:-0} rather than $RESUME_FLAG: the flag is resolved further down,
# next to the invocation it belongs to, and reading it here made the script die
# under `set -u` with "RESUME_FLAG: unbound variable". Two commits of mine —
# telemetry and resume — landed separately and nobody checked their order
# together. Moving the resolution up instead LOOKED right and passed `bash -n`
# while splicing the resume assignments into the wrong case block: valid syntax,
# scrambled logic. The smaller fix is the correct one.
emit_event "dispatch_start" ",\"resumed\":$([ "${CONTINUE:-0}" = "1" ] && echo true || echo false),\"timeout_s\":$TIMEOUT"

log "invoking $CONSOLE (timeout ${TIMEOUT}s) — transcript: ${RUNLOG#"$REPO_ROOT"/}"

set +e
# RESUME. A one-shot dispatch that times out loses everything the console had
# not committed — lane k0 spent 1800s analysing 34 branches and returned with an
# empty branch. All three CLIs can continue their previous session in a working
# directory, so a retry should RESUME rather than restart from a blank context.
#
# Set CONTINUE=1 to resume instead of starting fresh. The prompt still goes in;
# on a resumed session it reads as the next turn, which is exactly what a "here
# is what you left unfinished" retry should be.
RESUME_FLAG=""
if [ "${CONTINUE:-0}" = "1" ]; then
  case "$BIN" in
    claude|kimi) RESUME_FLAG="--continue" ;;
    codex)       RESUME_FLAG="resume --last" ;;
  esac
  log "resuming the previous $BIN session in $WT (CONTINUE=1)"
fi

case "$BIN" in
  claude)
    # bypassPermissions, NOT acceptEdits. The dispatch asks the console to
    # branch, commit and push; acceptEdits clears file edits but not the git
    # commands, and with -p there is nobody to approve them. Two lanes did the
    # work and left it uncommitted on the console branch because of this, and
    # the operator had to rescue both by hand. Verified: under
    # bypassPermissions a one-shot run creates a real commit; under acceptEdits
    # the same prompt did not.
    ( cd "$WT" && timeout "$TIMEOUT" claude $RESUME_FLAG -p "$PROMPT" \
        --permission-mode bypassPermissions --output-format text ) 2>&1 | tee "$RUNLOG"
    ;;
  codex)
    if [ -n "$RESUME_FLAG" ]; then
      # Order matters and cost 30 minutes to learn: `codex exec resume --last -C ...`
      # fails with "unexpected argument '-C'", because -C/-s must precede the
      # `resume` SUBCOMMAND, not follow it. The old form left codex sitting on
      # "Reading additional input from stdin..." until the dispatch timed out —
      # 0 commits, no error, 1800s burned.
      #
      # KNOWN HAZARD, not fixed here: `--last` resumes the most recent thread
      # GLOBALLY. With codex, codex2 and codex3 in the pool, all three resume the
      # SAME thread and lose the race with "thread-store conflict: already has an
      # active writer". Resume is only safe here while one codex session runs.
      timeout "$TIMEOUT" codex exec -C "$WT" -s workspace-write $RESUME_FLAG "$PROMPT"  < /dev/null 2>&1 | tee "$RUNLOG"
    else
      timeout "$TIMEOUT" codex exec -C "$WT" -s workspace-write "$PROMPT"  < /dev/null 2>&1 | tee "$RUNLOG"
    fi
    ;;
  kimi2)
    # Second Kimi session. Same binary and flags as `kimi`; what separates them
    # is the worktree, so two lanes can run Kimi concurrently without sharing a
    # tree. Same no-approval-flag rule applies.
    ( cd "$WT" && timeout "$TIMEOUT" kimi $RESUME_FLAG -p "$PROMPT" --output-format text ) 2>&1 | tee "$RUNLOG"
    ;;
  kimi)
    # NO approval flag. kimi rejects BOTH alongside --prompt:
    #   kimi -p ... -y      -> "Cannot combine --prompt with --yolo"
    #   kimi -p ... --auto  -> "Cannot combine --prompt with --auto"
    # --prompt is already one-shot autonomous; approval flags are for the TUI.
    ( cd "$WT" && timeout "$TIMEOUT" kimi $RESUME_FLAG -p "$PROMPT" --output-format text ) 2>&1 | tee "$RUNLOG"
    ;;
esac
RC=${PIPESTATUS[0]}
set -e

# The end record carries the OUTCOME, which is the only thing worth alerting on:
# did it exit clean, did it time out, and did anything actually land on the
# branch. A run that exits 0 having committed nothing is the failure mode that
# went unnoticed twice today.
_END=$?
_ELAPSED=$(( $(date +%s) - START_EPOCH ))
_HEAD="$(git -C "$WT" rev-parse HEAD 2>/dev/null)"
_NEW=$(git -C "$WT" rev-list --count "${BASE_SHA}..HEAD" 2>/dev/null || echo 0)
_DIRTY=$(git -C "$WT" status --porcelain 2>/dev/null | wc -l | tr -d ' ')
emit_event "dispatch_end" ",\"exit\":${_END},\"elapsed_s\":${_ELAPSED},\"commits\":${_NEW:-0},\"uncommitted\":${_DIRTY:-0},\"advanced\":$([ "${_HEAD}" != "${BASE_SHA}" ] && echo true || echo false)"


echo
if [ "$RC" -eq 0 ]; then
  log "lane $LANE finished (exit 0)"
  if [ "${_DIRTY:-0}" != "0" ]; then
    if [ "${_NEW:-0}" = "0" ]; then
      log "lane $LANE exited clean but committed NOTHING; preserving uncommitted work"
    else
      log "lane $LANE exited clean with uncommitted work after ${_NEW} commit(s); preserving it"
    fi
    preserve_uncommitted_work \
      "wip(lane-$LANE): preserved after clean dispatch exit" \
      "The lane exited 0 with working-tree changes left uncommitted; this commit exists so they are recoverable. Review before treating any of it as finished work."
  fi
elif [ "$RC" -eq 124 ]; then
  log "lane $LANE TIMED OUT after ${TIMEOUT}s -- partial work may exist in $WT"
  # A killed lane loses everything it had not committed. That is how three lanes
  # burned 55 minutes each today and returned nothing at all. Preserve whatever
  # reached the working tree as a WIP commit on the lane's OWN branch: the work
  # was produced by the process we just killed, so committing it recovers rather
  # than clobbers. An operator can reset it away; they cannot un-lose it.
  preserve_uncommitted_work \
    "wip(lane-$LANE): preserved on dispatch timeout after ${TIMEOUT}s" \
    "The lane was killed by the wallclock cap with these changes uncommitted; this commit exists so they are recoverable. Review before treating any of it as finished work."
else
  log "lane $LANE exited $RC — see ${RUNLOG#"$REPO_ROOT"/}"
fi

BR="$(git -C "$WT" rev-parse --abbrev-ref HEAD)"
DIRTY_AFTER="$(git -C "$WT" status --porcelain | wc -l | tr -d ' ')"
dim "branch now: $BR   uncommitted: $DIRTY_AFTER"
[ "$DIRTY_AFTER" != "0" ] && dim "review before landing:  git -C $WT status"
exit "$RC"
