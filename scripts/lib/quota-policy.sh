#!/usr/bin/env bash
# quota-policy.sh — answer ONE question from the operator's pasted quota:
# "given the console class requested, which provider has the most weekly
# headroom right now?"
#
# WHY THIS FILE EXISTS. CLI quota lives server-side and no CLI exposes it
# non-interactively: `claude -p "/status"` answers "not available", codex and
# kimi have no equivalent at all. The only source is the operator pasting the
# interactive /status into coordination/quota-observed.md. This file parses
# that paste. It cannot ask the providers — it consumes what a human pasted.
#
# Honesty contract (violating these makes routing WORSE than blind):
#   * Numbers are never invented. Rows whose weekly_used_pct is not a plain
#     integer ("unknown", "~full", a bar description) are skipped.
#   * A row older than 24h is stale — weekly quota resets make it lie about
#     today's headroom — and is skipped.
#   * No usable data -> quota_pick_provider prints the requested class
#     UNCHANGED, so a caller treating the result as "the provider to prefer"
#     keeps its pre-existing strict-class behavior bit-for-bit. The file is
#     optional: without it, nothing changes.
#
# This file is SOURCED, never executed: it sets no options, produces no
# output, and has no side effects beyond defining functions.

# Derive the repo root the same way console-registry.sh derives GH_DIR, so
# source ORDER can never become another invariant to remember.
# (repo/scripts/lib -> up two -> repo root)
: "${QUOTA_POLICY_ROOT:="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"}"

# Path of the paste file; overridable for tests and for an operator who keeps
# the live paste in the main checkout while lanes work in worktrees.
quota_observed_file() {
  printf '%s\n' "${QUOTA_OBSERVED_FILE:-$QUOTA_POLICY_ROOT/${SWARM_COORD_DIR:-coordination}/quota-observed.md}"
}

# YYYY-MM-DD -> epoch seconds of that date's LOCAL MIDNIGHT. GNU date first,
# BSD date as fallback (the swarm runs on macOS). Empty output when the date
# does not parse.
#
# BSD date -j -f FILLS UNSPECIFIED FIELDS WITH THE CURRENT TIME — this was
# measured, not assumed: `date -j -f %Y-%m-%d <today> +%s` returned "now",
# which made a same-day paste flicker between fresh and stale depending on
# whether the parse landed a second before or after `date +%s`. The time is
# therefore given explicitly as 00:00:00; day-granularity data means "fresh
# for the rest of the observed day" either way.
_quota_date_epoch() {
  local d="$1"
  if date -d "$d" +%s 2>/dev/null; then
    return 0
  fi
  date -j -f "%Y-%m-%d %H:%M:%S" "$d 00:00:00" +%s 2>/dev/null
}

# quota_pick_provider <class>
#
#   <class> — a provider binary or a comma-separated list of them: the
#   providers that can serve this work ("claude", or "claude,codex" for a
#   class that several providers can run).
#
# Prints the provider with the MOST weekly headroom (lowest weekly_used_pct)
# among the class's providers whose paste is FRESH (<24h) and NUMERIC. On a
# tie, the provider listed first in <class> wins. With no usable data at all
# (no file, empty table, stale rows, no numbers), prints <class> unchanged —
# the caller's signal to keep its existing behavior.
quota_pick_provider() {
  local requested="${1:-}"
  [ -n "$requested" ] || return 0

  local f
  f="$(quota_observed_file)"
  if [ ! -f "$f" ]; then
    printf '%s\n' "$requested"
    return 0
  fi

  local now
  now="$(date +%s)"

  # Split the class into providers. Quoted $requested with IFS=',' is
  # intentional word-splitting.
  local IFS=','
  # shellcheck disable=SC2206
  local providers=( $requested )
  unset IFS

  local best="" best_pct=101
  local line name pct obs epoch age hit p
  while IFS= read -r line; do
    case "$line" in
      ''|\#*) continue ;;   # blanks, comments, prose
      *\|*)   ;;            # must be a pipe row
      *)      continue ;;
    esac

    name="$(printf '%s' "$line" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$1); print $1}')"

    # Only rows naming a provider the requested class can use.
    hit=0
    for p in "${providers[@]}"; do
      if [ "$name" = "$p" ]; then
        hit=1
        break
      fi
    done
    [ "$hit" = 1 ] || continue

    pct="$(printf '%s' "$line" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2}')"
    obs="$(printf '%s' "$line" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$3); print $3}')"

    # Honesty gate 1: pct must be a plain integer 0-100. "unknown", "~79",
    # "bar near full" are not numbers and are skipped, not guessed.
    case "$pct" in
      ''|*[!0-9]*) continue ;;
    esac
    [ "$pct" -le 100 ] || continue

    # Honesty gate 2: the observation must parse as a date and be fresh —
    # not older than 24h and not from the future either.
    epoch="$(_quota_date_epoch "$obs")"
    [ -n "$epoch" ] || continue
    age=$(( now - epoch ))
    [ "$age" -ge 0 ] && [ "$age" -lt 86400 ] || continue

    if [ "$pct" -lt "$best_pct" ]; then
      best="$name"
      best_pct="$pct"
    fi
  done < "$f"

  if [ -n "$best" ]; then
    printf '%s\n' "$best"
  else
    printf '%s\n' "$requested"
  fi
}
