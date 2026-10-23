#!/usr/bin/env bash
# console-registry.sh — LOCAL execution topology: which console SESSION runs which
# binary in which worktree. This is the per-machine parallelism layout (how many
# concurrent worktrees this host runs per console), deliberately NOT in the shared
# manifest — a different machine can run more or fewer sessions without touching a
# project's authored agreement.
#
# WHAT MOVED TO THE MANIFEST (2026-09-15 portable-loop-engine port). This file used
# to also hold `lane_class` — the lane->console CLASS table — as a hardcoded `case`
# block. That was a second copy of a fact the generated manifest already owns
# (projects[].lanes[].console), and it had drifted: the hardcoded block sent xNinja
# lane 1 to `kimi` while the manifest (from the authored SWARM-AGREEMENT) said
# `codex`. `lane_class` now DELEGATES to lib/manifest.sh::lane_console, so the
# agreement is the single source and this file carries only local topology.
#
# WHAT STAYED LOCAL, AND WHY. `console_binary` returns the EXECUTABLE name a console
# runs (`claude`, `codex`, `kimi`) — the name the dispatch `case` blocks key on and
# invoke. The manifest's consoles[].cli is an identity LABEL ("claude-code"), not an
# exec on PATH; deriving the binary from it would make dispatch invoke a nonexistent
# `claude-code`. So class->exec stays here.
#
# WHY THE SESSION TABLE STILL LIVES ONCE. The table used to be duplicated between
# CONSOLE_REGISTRY here and two hardcoded `case` blocks in lane-run.sh (console_of
# and CONSOLE_ENV). On 2026-09-01 three worktrees were added and the change did
# NOTHING — lane-run.sh's private copy still fell through to `*) echo ""`, and
# pick_wt() discards any worktree whose console it cannot name. Three clean
# worktrees stayed invisible for a day. The table lives here now, once; both
# scripts source it. If you edit a second file to teach the swarm about a worktree,
# the duplication has grown back.
#
# This file is SOURCED, never executed: it sets no options, produces no output, and
# has no side effects beyond defining the table + accessors and pulling in its libs.

_CR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# swarm-config.sh gives SWARM_WT_PREFIX + the manifest/project defaults; manifest.sh
# gives lane_console. Both are idempotent (default-assigns + function defs), so a
# caller that already sourced them pays nothing.
# shellcheck source=/dev/null
. "$_CR_DIR/swarm-config.sh"
# shellcheck source=/dev/null
. "$_CR_DIR/manifest.sh"

# GH_DIR is the directory that holds every per-console worktree. It is a per-MACHINE
# fact: a project's .swarm/swarm.config.sh or the environment should set it. When a
# caller has not, fall back to "up three from this lib dir" — the xNinja layout where
# the repo sits one level below the worktree home — so source ORDER never becomes
# another invariant to remember. A vendored copy at a different depth should set
# GH_DIR explicitly rather than rely on this fallback.
: "${GH_DIR:="$(cd "$_CR_DIR/../../.." && pwd)"}"

# A console is a SESSION, not a binary: kimi, kimi2 and kimi3 are three sessions of
# the same tool, separated only by their worktree. A project may override the whole
# table (fewer/more sessions, a different worktree prefix) by exporting
# CONSOLE_REGISTRY before sourcing; otherwise the default xNinja topology applies,
# with the worktree prefix taken from SWARM_WT_PREFIX (default xn-).
if [ -z "${CONSOLE_REGISTRY:-}" ]; then
  _p="${SWARM_WT_PREFIX:-xn-}"
  #                  name    binary  worktree
  CONSOLE_REGISTRY="
kimi      kimi    ${_p}kimi
kimi2     kimi    ${_p}kimi2
kimi3     kimi    ${_p}kimi3
claude    claude  ${_p}claude
claude2   claude  ${_p}claude2
codex     codex   ${_p}codex
codex2    codex   ${_p}codex2
codex3    codex   ${_p}codex3
"
  unset _p
fi

console_field()      { printf '%s\n' "$CONSOLE_REGISTRY" | awk -v c="$1" -v f="$2" '$1==c {print $f; exit}'; }
console_binary()     { console_field "$1" 2; }
console_worktree()   { d="$(console_field "$1" 3)"; [ -n "$d" ] && echo "$GH_DIR/$d"; }
consoles_of_class()  { printf '%s\n' "$CONSOLE_REGISTRY" | awk -v b="$1" '$2==b {print $1}'; }

# The REVERSE direction, which lane-run.sh needs: given a worktree path or its
# basename, name the console that owns it. This is the lookup whose duplicate copy
# caused the 2026-09-01 outage above, so it belongs in the same file as the table.
console_of_worktree() { printf '%s\n' "$CONSOLE_REGISTRY" | awk -v w="${1##*/}" '$3==w {print $1; exit}'; }

# lane_class <lane> -> the console CLASS its work needs. DERIVED from the manifest
# (lib/manifest.sh::lane_console), the single source; see the header for the drift
# this replaced. Empty when the lane is unknown or the manifest is absent — callers
# already treat empty as "auto-pick an idle console", so a missing manifest degrades
# routing to auto rather than crashing a dispatch.
lane_class() { lane_console "$1"; }
