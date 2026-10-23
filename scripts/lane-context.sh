#!/usr/bin/env bash
# lane-context.sh — preview the advisory prior-context a dispatch WOULD inject.
#
# `scripts/lane-dispatch.sh` folds SWARM_CONTEXT_CMD's recall into the prompt it
# hands the console. This shows you exactly that block for a given lane+objective
# through the SAME helper (swarm_prior_context), so the preview is byte-for-byte
# what a real dispatch would inject — WITHOUT claiming a console, writing an inbox
# message, or changing any state. Use it to confirm the hook works and to tune what
# it surfaces before spending a dispatch.
#
# Everything here is READ-ONLY.
#
# Usage:
#   scripts/lane-context.sh <lane> "<objective>"
#   make lane-context LANE=7 OBJ="add a spec for the badge"

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# swarm-config.sh sources the project's local override (which sets SWARM_CONTEXT_CMD)
# and defines swarm_prior_context — the one helper the real dispatch also calls.
. "$REPO_ROOT/scripts/lib/swarm-config.sh"

b=$'\033[1m'; dim=$'\033[2m'; cy=$'\033[1;36m'; yl=$'\033[33m'; off=$'\033[0m'

LANE="${1:-}"; OBJECTIVE="${2:-}"
[ -n "$LANE" ] && [ -n "$OBJECTIVE" ] || {
  printf 'usage: scripts/lane-context.sh <lane> "<objective>"\n' >&2; exit 1; }

if [ -z "${SWARM_CONTEXT_CMD:-}" ]; then
  printf '%sno context hook configured%s — SWARM_CONTEXT_CMD is empty, so a dispatch to lane %s injects nothing.\n' \
    "$yl" "$off" "$LANE"
  exit 0
fi

printf '%shook:%s %s\n' "$dim" "$off" "$SWARM_CONTEXT_CMD"
printf '%slane:%s %s   %sobjective:%s %s\n' "$dim" "$off" "$LANE" "$dim" "$off" "$OBJECTIVE"

BLOCK="$(swarm_prior_context "$LANE" "$OBJECTIVE")"

if [ -z "$BLOCK" ]; then
  printf '%sthe hook returned nothing%s — a dispatch to lane %s would inject NO prior\n' "$yl" "$off" "$LANE"
  printf 'context (empty query, no matches, or a fail-soft skip). The dispatch still runs.\n'
  exit 0
fi

printf '%s── prior context a dispatch to lane %s WOULD inject (%s chars) ──%s\n' \
  "$cy" "$LANE" "${#BLOCK}" "$off"
printf '%s\n' "$BLOCK"
