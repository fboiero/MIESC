#!/usr/bin/env bash
# swarm-config.local.sh — MIESC's per-project engine config.
#
# Sourced by scripts/lib/swarm-config.sh (canonical, from swarm-ops) BEFORE its
# generic defaults, so this file sets only what differs from those defaults. It is
# NOT part of the swarm-ops canonical surface: a re-copy of swarm-config.sh from
# swarm-ops preserves this file, so the project config never gets clobbered. This
# file is the ADAPTATION SEAM — the ~10% that differs between projects; everything
# else in the engine is byte-identical to the canonical (see
# scripts/verify-engine-vendor.py + scripts/lib/engine-sync-source.json).
#
# swarm-ops's defaults target xNinja (SWARM_BASE_BRANCH=develop, SWARM_FORGE=glab,
# SWARM_VERIFY_CMD=make ci-verify, SWARM_WT_PREFIX=xn-). MIESC differs on each of
# these, so they are overridden below. SWARM_COORD_DIR (coordination) already
# matches, so it is left at the default.

_miesc_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# --- Integration branch -------------------------------------------------------
# MIESC's default branch is `main` (xNinja uses develop). Every lane cuts from and
# lands back into this.
: "${SWARM_BASE_BRANCH:=main}"

# --- Project identity ---------------------------------------------------------
: "${SWARM_PROJECT_ID:=miesc}"
# Runtime display label (dispatch prompt + lane-status banner). Set explicitly for
# brand casing: the generic default is SWARM_PROJECT_ID ("miesc", lowercase). This
# is what makes a MIESC console read "MIESC swarm", not "xNinja swarm". Cosmetic
# only — never drives routing.
: "${SWARM_PROJECT_LABEL:=MIESC}"

# --- Verify hook (THE load-bearing per-project fact) --------------------------
# "Is this merged tree green?", run in the isolated landing worktree BEFORE a land.
# MIESC's own fast pre-commit gate is `make quick-check` (ruff lint + mypy
# typecheck). This is intentionally the FAST gate so the seed is honest about what
# it runs; an operator who wants the stricter gate before landing should raise this
# to `make all-checks && make test` (full format + lint + the pytest suite). It is
# a per-project choice, which is exactly why it lives here and not in the engine.
: "${SWARM_VERIFY_CMD:=make quick-check}"

# --- Forge integration --------------------------------------------------------
# MIESC is hosted on GitHub, so the MR/PR-annotation CLI is `gh`, not xNinja's
# `glab` (GitLab). Empty would disable the note; `gh` keeps it.
: "${SWARM_FORGE:=gh}"

# --- Worktree topology (per-MACHINE) ------------------------------------------
# console<->worktree map: console `claude` -> ${SWARM_WT_PREFIX}claude. MIESC's
# existing sibling checkouts already follow this (MIESC-claude), so the prefix is
# `MIESC-`. GH_DIR is left unset: console-registry.sh derives it as "up three from
# scripts/lib" = the directory that holds the MIESC-* worktrees, which matches this
# machine's layout (…/GitHub/MIESC/scripts/lib -> …/GitHub).
: "${SWARM_WT_PREFIX:=MIESC-}"

# --- Manifest location --------------------------------------------------------
# The authored k0+1-4 lane agreement. Absolute so lib/manifest.sh reads it
# regardless of the caller's CWD (dispatch/status scripts run from many dirs).
: "${SWARM_MANIFEST:=$_miesc_root/coordination/swarm-manifest.json}"

# Deliberately NOT set for MIESC:
#   SWARM_CONTEXT_CMD      — no prior-context memory hook wired (stays fail-soft empty).
#   SWARM_LAND_BOOTSTRAP_CMD — MIESC is a pure-Python package; no frontend npm ci to seed.
