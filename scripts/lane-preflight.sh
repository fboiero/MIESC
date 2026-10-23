#!/usr/bin/env bash
# lane-preflight.sh — probe EVERY provider's auth BEFORE a fan-out, so a dead
# console surfaces at second 0 instead of after branches are cut.
#
# WHY: 2026-09-13 a 3-lane fan-out prepared a fresh worktree for the Claude lane
# and only THEN died with "OAuth session expired" — the auth failure surfaced
# after the setup cost. lane-dispatch already probes one console per dispatch;
# this runs the SAME probe across all providers up front and reports a table, so
# the operator re-logs the dead one (interactive, operator-only) before spending
# any setup.
#
# Reuses lane-dispatch's exact probe + failure signatures — not a second matcher.
#
# usage: scripts/lane-preflight.sh [kimi] [claude] [codex]   (default: all three)
# exit: 0 iff every requested provider is UP; 1 if any is DOWN (gate a fan-out on it).
set -uo pipefail  # NOT -e: a failed probe is data we report, not a crash.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
GH_DIR="$(dirname "$REPO_ROOT")"
c_b=$'\033[1;36m'; c_r=$'\033[1;31m'; c_g=$'\033[1;32m'; c_d=$'\033[2m'; c_o=$'\033[0m'

PROBE_TIMEOUT="${LANE_PROBE_TIMEOUT:-90}"
# Same failure signatures lane-dispatch.sh uses to reject a misconfigured console.
FAIL_RE='no credential|not configured|no model configured|not logged in|unauthor|OAuth|Cannot combine|command not found|agent .* not found|Usage:'

probe() {
  case "$1" in
    claude) timeout "$PROBE_TIMEOUT" claude -p "Reply with OK." --output-format text 2>&1 ;;
    codex)  timeout "$PROBE_TIMEOUT" codex exec -C "$GH_DIR" -s read-only "Reply with OK." 2>&1 ;;
    kimi)   ( cd "$GH_DIR" && timeout "$PROBE_TIMEOUT" kimi -p "Reply with OK." --output-format text 2>&1 ) ;;
  esac
}

hint() {
  case "$1" in
    claude) echo "run \`claude\` interactively and re-login (OAuth) — the CLI session expired." ;;
    kimi)   echo "run \`kimi\` interactively and /login." ;;
    codex)  echo "run \`codex\` interactively and sign in." ;;
  esac
}

want=("$@"); [ "${#want[@]}" -gt 0 ] || want=(kimi claude codex)
down=0
printf '%s[lane-preflight]%s probing %s (timeout %ss each) ...\n' "$c_b" "$c_o" "${want[*]}" "$PROBE_TIMEOUT"
for console in "${want[@]}"; do
  if ! command -v "$console" >/dev/null 2>&1; then
    printf '  %s✗ %-7s DOWN%s — binary not on PATH\n' "$c_r" "$console" "$c_o"; down=$((down+1)); continue
  fi
  out="$(probe "$console")"; rc=$?
  if [ "$rc" -eq 124 ]; then
    printf '  %s✗ %-7s DOWN%s — probe timed out (${PROBE_TIMEOUT}s): provider unreachable?\n' "$c_r" "$console" "$c_o"; down=$((down+1)); continue
  fi
  if printf '%s' "$out" | grep -qiE "$FAIL_RE"; then
    printf '  %s✗ %-7s DOWN%s — %s\n' "$c_r" "$console" "$c_o" "$(hint "$console")"
    printf '%s      %s%s\n' "$c_d" "$(printf '%s' "$out" | grep -iE 'error|expired|credential|unauthor|not logged|OAuth' | head -1 | cut -c1-100)" "$c_o"
    down=$((down+1)); continue
  fi
  printf '  %s✓ %-7s UP%s\n' "$c_g" "$console" "$c_o"
done

echo
if [ "$down" -gt 0 ]; then
  printf '%s[lane-preflight] %d provider(s) DOWN — re-login before the fan-out (interactive, operator-only).%s\n' "$c_r" "$down" "$c_o"
  exit 1
fi
printf '%s[lane-preflight] all %d providers UP — safe to fan out.%s\n' "$c_g" "${#want[@]}" "$c_o"
