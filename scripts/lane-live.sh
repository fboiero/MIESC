#!/usr/bin/env bash
# lane-live.sh — what every lane is doing right now, from the event stream.
#
# Reads coordination/lane-events.jsonl, which lane-dispatch.sh appends to. It
# reports FACTS the dispatch layer actually observes — running or not, for how
# long, and what landed on the branch — and deliberately reports no "progress
# percentage", because nothing here can tell a console that is thinking from one
# that is wedged, and a progress bar that guesses is worse than no bar.
#
# The distinction that matters and that this surfaces: a lane that exited 0
# having committed NOTHING. That happened twice in one session and both times it
# was read as success.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Per-project glue: coord dir (the event stream lives under it).
. "$REPO_ROOT/scripts/lib/swarm-config.sh"
EVENTS="$REPO_ROOT/${SWARM_COORD_DIR}/lane-events.jsonl"
c_g=$'\033[1;32m'; c_y=$'\033[1;33m'; c_r=$'\033[1;31m'; c_d=$'\033[2m'; c_o=$'\033[0m'

[ -f "$EVENTS" ] || { echo "no events yet — nothing has been dispatched since telemetry landed"; exit 0; }

python3 - "$EVENTS" "$REPO_ROOT" <<'PY'
import functools, json, subprocess, sys, time
from pathlib import Path

events_path, root = Path(sys.argv[1]), Path(sys.argv[2])
runs = {}
for line in events_path.read_text().splitlines():
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        continue  # a truncated tail line is normal while a dispatch is writing
    runs.setdefault(e.get("lane", "?"), []).append(e)

def alive(lane: str) -> bool:
    return subprocess.run(["pgrep", "-f", f"lane-dispatch.sh {lane}"],
                          capture_output=True).returncode == 0

GREEN, YELLOW, RED, DIM, OFF = "\033[1;32m", "\033[1;33m", "\033[1;31m", "\033[2m", "\033[0m"
# The console name alone does not say which provider ran the work — you have to
# remember that claude2 is claude and kimi3 is kimi. That gap is not cosmetic:
# on 2026-09-01 the same console appeared in three lanes whose classes differed,
# and nobody reading this panel could see it.
#
# Ask console-registry.sh itself via its console_binary accessor instead of
# re-parsing the file text. The old textual scan matched a line that STARTS with
# "CONSOLE_REGISTRY=", but the portable registry builds the table inside a
# conditional (indented) with an interpolated worktree prefix, so the scan matched
# nothing and every provider silently rendered "?". Sourcing the lib and calling
# the accessor is robust to how the table is assembled. console is passed as an
# argv, never interpolated into the shell string.
@functools.lru_cache(maxsize=None)
def _provider(console):
    reg = root / "scripts" / "lib" / "console-registry.sh"
    if not reg.exists():
        return "?"
    out = subprocess.run(
        ["bash", "-c", '. "$1" 2>/dev/null && console_binary "$2"', "lane-live", str(reg), console],
        capture_output=True,
        text=True,
    )
    return out.stdout.strip() or "?"

print(f"{DIM}lane   console    provider  state       branch                                  detail{OFF}")
for lane in sorted(runs):
    evs = runs[lane]
    last = evs[-1]
    started = [e for e in evs if e["event"] == "dispatch_start"]
    ended = [e for e in evs if e["event"] == "dispatch_end"]
    branch = (last.get("branch") or "?")[:40]
    console = last.get("console", "?")

    if alive(lane):
        began = time.strptime(started[-1]["ts"], "%Y-%m-%dT%H:%M:%SZ") if started else None
        mins = int((time.time() - time.mktime(began)) / 60) + int(time.timezone / 60) if began else 0
        resumed = " (resumed)" if started and started[-1].get("resumed") else ""
        print(f"{lane:<6} {console:<10} {_provider(console):<9} {YELLOW}running{OFF}     {branch:<38}  {abs(mins)}m{resumed}")
        continue

    if not ended:
        print(f"{lane:<6} {console:<10} {_provider(console):<9} {DIM}unknown{OFF}     {branch:<38}  started, no end record")
        continue

    e = ended[-1]
    rc, commits, dirty = e.get("exit", "?"), e.get("commits", 0), e.get("uncommitted", 0)
    secs = e.get("elapsed_s", 0)
    # exit 0 with nothing committed is the case worth naming out loud.
    if rc == 0 and commits == 0:
        state, note = f"{RED}empty{OFF}      ", "exited clean but committed NOTHING"
    elif rc == 124:
        state, note = f"{RED}timeout{OFF}    ", f"killed at {secs}s — {commits} commit(s) survived"
    elif rc != 0:
        state, note = f"{RED}failed{OFF}     ", f"exit {rc}"
    else:
        state, note = f"{GREEN}done{OFF}       ", f"{commits} commit(s) in {secs//60}m"
    if dirty:
        note += f" · {DIM}{dirty} uncommitted{OFF}"
    print(f"{lane:<6} {console:<10} {_provider(console):<9} {state} {branch:<38}  {note}")
PY
