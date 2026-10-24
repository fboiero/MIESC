#!/usr/bin/env bash
# swarm-config.sh — the per-project glue the portable loop engine needs injected.
#
# The 2026-09-15 review of xNinja's loop scripts found the engine ~90% portable;
# these variables are the ~10% that genuinely differ between projects. Every
# default below reproduces xNinja's original hardcoded behaviour, so with no
# per-project override the engine runs there byte-identically. Another project
# overrides by shipping a `.swarm/swarm.config.sh` (scaffolded by `swarm init`)
# that sets these before the engine sources this file, or by exporting them in the
# environment. Anything NOT here is portable and must not be re-parameterised —
# adding a knob is a cost, not a feature.
#
# This file is SOURCED, never executed. It only assigns defaults (`: "${X:=...}"`),
# so sourcing it twice, or after the project already set a value, is a no-op.

# --- Per-project override -----------------------------------------------------
# A project can drop a `swarm-config.local.sh` next to this file to set its own
# SWARM_* (an absolute SWARM_MANIFEST, its SWARM_PROJECT_ID, a bootstrap command)
# BEFORE the generic defaults below apply. Sourced if present; the defaults then
# fill only what it left unset. This keeps THIS canonical file un-edited per
# project, so a re-copy/re-sync from swarm-ops never clobbers project config — the
# override lives in the local file, which is not part of the canonical surface.
_swarm_cfg_local="$(dirname "${BASH_SOURCE[0]}")/swarm-config.local.sh"
[ -f "$_swarm_cfg_local" ] && . "$_swarm_cfg_local"
unset _swarm_cfg_local

# --- The integration branch ---------------------------------------------------
# Every lane cuts its branch from this and lands back into it. xNinja: develop.
: "${SWARM_BASE_BRANCH:=develop}"

# --- Project identity ---------------------------------------------------------
# The project's stable id in the manifest; drives lib/manifest.sh lane lookups.
# Empty means "single-project manifest" (the first/only project entry).
: "${SWARM_PROJECT_ID:=}"

# --- Project display label (runtime-facing) -----------------------------------
# Human-facing name for this swarm in runtime output: the dispatch prompt and the
# lane-status banner. Defaults to SWARM_PROJECT_ID, else "local". A project with
# brand casing (e.g. xNinja) sets this explicitly in swarm-config.local.sh; it is
# cosmetic (never drives routing), but a wrong label in a dispatch prompt can steer
# a console's priors toward another project's conventions.
: "${SWARM_PROJECT_LABEL:=${SWARM_PROJECT_ID:-local}}"

# --- The verify hook (THE load-bearing per-project fact) ----------------------
# The command that decides "is this merged tree green?", run in the isolated
# landing worktree BEFORE a land is pushed. This is where projects differ most:
# xNinja runs `make ci-verify` (its lint gates). A project with no Makefile sets
# its own (e.g. `npm run verify`, `just check`). A consumer-only repo that lands
# nothing can set it to `true`.
: "${SWARM_VERIFY_CMD:=make ci-verify}"

# Optional one-time provisioning run in a fresh landing worktree (xNinja does an
# `npm ci` in frontend-v2/ so the verify hook can lint the frontend). Empty = skip.
: "${SWARM_LAND_BOOTSTRAP_CMD:=}"

# --- Forge integration (optional) ---------------------------------------------
# CLI used to annotate an MR/PR after a fallback direct-land. xNinja: glab
# (GitLab). A GitHub project uses `gh`. Empty disables the note (land still works).
: "${SWARM_FORGE:=glab}"

# --- Coordination bus ---------------------------------------------------------
# Where the swarm's state lives, relative to the repo root: status/, inbox/,
# scope-leases.md, .console-locks, lane-events.jsonl, .reap-archive, ... A project
# with its own layout re-points this; the subdirectory names are a fixed convention.
: "${SWARM_COORD_DIR:=coordination}"

# --- Worktree topology (per-MACHINE, not per-project) -------------------------
# GH_DIR is the directory holding every per-console worktree; the console<->worktree
# session map lives in console-registry.sh (kimi2 -> ${SWARM_WT_PREFIX}kimi2). This
# is local parallelism topology, deliberately NOT derived from the manifest.
: "${SWARM_WT_PREFIX:=xn-}"
# GH_DIR is left unset here; console-registry.sh derives it from its own location
# when a caller has not set it, so source order never becomes an invariant.

# --- Manifest location --------------------------------------------------------
# Consumed by lib/manifest.sh. A generator-shape project points at its generated
# output; a vendored copy lives under .swarm/.
: "${SWARM_MANIFEST:=.swarm/swarm-manifest.json}"

# --- Spread-first dispatch (OFF by default) -----------------------------------
# Empty (the default) => lane_class returns the lane's single owning console
# (lib/manifest.sh::lane_console) and dispatch is byte-identical to before. When set
# to a comma-separated PROVIDER SET (e.g. "claude,codex,kimi"), lib/console-registry.sh
# ::lane_class returns that set for EVERY lane, so pick_wt + quota_pick_provider route
# the dispatch to the provider with the most weekly headroom — spreading spend across
# all the paid subscriptions instead of pinning each lane to one. The balancing is only
# as good as the pasted quota (coordination/quota-observed.md): stale or absent, it
# degrades to "first free worktree", never worse than the pre-spread behaviour.
: "${SWARM_DISPATCH_SPREAD:=}"

# --- Per-task model routing (OFF by default) ----------------------------------
# "Route each task to the model that fits it." The dispatch passes `--model`/`-m` to
# the chosen CLI ONLY when BOTH a task tier is given AND a model is mapped for that
# (provider, tier); otherwise it passes no model flag and the CLI uses its own default
# — byte-identical to before. SWARM_LANE_TIER names the task's tier (e.g. top|mid|cheap;
# any lowercase-alnum token). The model per (provider, tier) is read by INDIRECT env
# lookup from `SWARM_MODEL_<bin>_<tier>` — e.g. SWARM_MODEL_claude_top=opus,
# SWARM_MODEL_codex_mid=gpt-5-codex, SWARM_MODEL_kimi_cheap=... — so a project sets only
# the tiers it uses, in swarm-config.local.sh, and refines the map as it learns which
# model fits what. No tier, or no mapped model, => no flag.
: "${SWARM_LANE_TIER:=}"

# model_flag_for <bin> <tier> -> the "--model X" / "-m X" flag for (provider, tier), or
# NOTHING. The single source of the per-task model decision (lane-dispatch calls it), kept
# here as a sourced, PURE, unit-testable function instead of inline in the dispatch. It is
# the fail-safe boundary: a tier that is empty, not lowercase-alnum, or has no mapped model
# yields empty so the CLI keeps its own default — and a malformed tier can never splice a
# flag, because it is rejected BEFORE the indirect lookup. Flag spelling is per-CLI
# (claude/kimi: --model; codex: -m). bash 3.2 safe.
model_flag_for() {
  local _bin="$1" _tier="${2:-}" _var _model
  [ -n "$_tier" ] || return 0
  case "$_tier" in *[!a-z0-9]*) return 0 ;; esac
  _var="SWARM_MODEL_${_bin}_${_tier}"
  _model="${!_var:-}"
  [ -n "$_model" ] || return 0
  case "$_bin" in
    claude|kimi) printf '%s\n' "--model $_model" ;;
    codex)       printf '%s\n' "-m $_model" ;;
  esac
}

# --- Optional prior-context injection hook (OFF by default) -------------------
# A project can feed the dispatched console point-in-time recall — an Engram query,
# a notes grep, anything — as ADVISORY background, WITHOUT coupling this portable
# engine to any one memory tool. SWARM_CONTEXT_CMD is a shell command line; when
# non-empty, lane-dispatch runs it with SWARM_CONTEXT_LANE + SWARM_CONTEXT_OBJECTIVE
# exported, caps its stdout, and injects it into the prompt under an advisory
# header. Empty (the default) injects nothing and the prompt is byte-identical to
# having no hook at all. The contract is FAIL-SOFT by design: a missing, failing,
# timing-out, or empty command injects nothing and NEVER blocks a dispatch — prior
# context is a nicety, never a gate. The command lives per-project (e.g. wired from
# swarm-config.local.sh), so the coupling to a specific memory tool stays out of the
# engine. MAX_CHARS caps the injected block; TIMEOUT bounds a slow command.
: "${SWARM_CONTEXT_CMD:=}"
: "${SWARM_CONTEXT_MAX_CHARS:=4000}"
: "${SWARM_CONTEXT_TIMEOUT:=30}"

# swarm_prior_context <lane> <objective> -> the advisory PRIOR CONTEXT block to
# fold into a dispatch prompt, or NOTHING. This function IS the fail-soft contract:
# no hook set, or a hook that fails / times out / prints nothing, returns empty so
# the caller injects nothing and the dispatch proceeds unchanged. The hook runs
# with SWARM_CONTEXT_LANE + SWARM_CONTEXT_OBJECTIVE exported and its stdout byte-
# capped (head -c under `|| true`, so the head-close SIGPIPE cannot escape). The
# leading newline drops the block into the one blank line the prompt already has,
# so an empty return is byte-identical to no hook. Lives here (a sourced lib) so it
# is unit-testable in isolation without standing up a whole dispatch.
swarm_prior_context() {
  [ -n "${SWARM_CONTEXT_CMD:-}" ] || return 0
  local _spc_out _spc_rc
  # Capture stdout AND the hook's REAL exit code. A hook that prints then fails
  # (e.g. `echo half; exit 1`) must inject NOTHING — piping straight into head
  # would keep that partial stdout, so we check the exit code first. The `|| _rc=$?`
  # form also keeps a failing hook from tripping the caller's `set -e` (a bare
  # `x="$(failing)"` assignment would abort the whole dispatch — the opposite
  # fail-soft violation).
  _spc_rc=0
  _spc_out="$(SWARM_CONTEXT_LANE="$1" SWARM_CONTEXT_OBJECTIVE="$2" \
              timeout "${SWARM_CONTEXT_TIMEOUT:-30}" sh -c "$SWARM_CONTEXT_CMD" 2>/dev/null)" \
    || _spc_rc=$?
  [ "$_spc_rc" -eq 0 ] || return 0
  # Byte-cap only after a clean run. `|| true` swallows the head-close SIGPIPE.
  _spc_out="$(printf '%s' "$_spc_out" | head -c "${SWARM_CONTEXT_MAX_CHARS:-4000}" || true)"
  [ -n "$_spc_out" ] || return 0
  printf '\nPRIOR CONTEXT (advisory — point-in-time recall from project memory,\nNOT ground truth; verify against the live tree before acting on any of it):\n%s' "$_spc_out"
}
