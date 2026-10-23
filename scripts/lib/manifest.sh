#!/usr/bin/env bash
# manifest.sh — the swarm manifest is the SINGLE SOURCE for two shared facts:
#
#     lane  -> console   (which console CLASS owns a lane, per project)
#     console -> cli     (which binary a console runs)
#
# Both used to be hand-copied into console-registry.sh: `lane_class` held the
# lane->console table and `console_binary` held console->cli. A hand-copied fact
# is a second source of truth, and on 2026-09-15 it had already drifted — the
# hardcoded `lane_class` sent xNinja lane 1 to `kimi` while the generated manifest
# (derived from the authored SWARM-AGREEMENT) said `codex`. Deriving both from the
# manifest here kills that entire class of bug: the agreement is the only place a
# lane's owner is written, the generator stamps it into the manifest, and the loop
# engine reads it. If you find yourself editing a lane->console table in a shell
# script again, the drift has grown back.
#
# This file is SOURCED, never executed. python3 is a hard dependency of swarm-ops
# (the generator + vault builder are python3), so a JSON reader in python is the
# portable choice — no jq assumption. Every accessor is FAIL-SOFT: a missing
# manifest, absent python3, or unknown id prints nothing and the caller decides
# the fallback, so a broken manifest degrades to "unknown" rather than crashing a
# dispatch mid-flight.

# Manifest location and the project whose lanes we resolve. Both overridable by
# swarm-config.sh / the environment; defaults keep a vendored `.swarm/` layout.
: "${SWARM_MANIFEST:=.swarm/swarm-manifest.json}"
: "${SWARM_PROJECT_ID:=}"

# _swarm_manifest_query VERB [ARG] — the ONE python body every accessor shares.
# Reads argv: manifest path, project id, verb, optional arg. Prints the answer or
# nothing. Never exits non-zero on a data miss (only a usage bug would).
_swarm_manifest_query() {
  python3 - "$SWARM_MANIFEST" "$SWARM_PROJECT_ID" "$@" <<'PY'
import json, sys

manifest = sys.argv[1]
project = sys.argv[2]
verb = sys.argv[3] if len(sys.argv) > 3 else ""
arg = sys.argv[4] if len(sys.argv) > 4 else ""

try:
    with open(manifest) as fh:
        m = json.load(fh)
except Exception:
    # Fail-soft: no manifest / unreadable -> the caller falls back.
    sys.exit(0)


def lanes(pid):
    projs = m.get("projects")
    if projs:
        for p in projs:
            if p.get("id") == pid:
                return p.get("lanes", [])
        return []
    # Single-project manifest (e.g. xNinja's own shim output via emit_single_project):
    # lanes live at the top level with no projects[] wrapper. There is only one
    # project, so the project id is moot — return the top-level lanes.
    return m.get("lanes") or []


def current_lane(pid, lane_id):
    for lane in lanes(pid):
        if lane.get("id") == lane_id and lane.get("status") == "current":
            return lane
    return None


if verb == "lane_console":
    lane = current_lane(project, arg)
    if lane:
        print(lane.get("console") or "")
elif verb == "lane_backups":
    lane = current_lane(project, arg)
    if lane:
        print(" ".join(lane.get("backup_consoles", []) or []))
elif verb == "console_cli":
    for c in m.get("consoles", []):
        if c.get("id") == arg:
            print(c.get("cli") or "")
            break
elif verb == "lanes_current":
    print(" ".join(l.get("id", "") for l in lanes(project) if l.get("status") == "current"))
elif verb == "swarm_consoles":
    print(" ".join(c.get("id", "") for c in m.get("consoles", [])))
elif verb == "console_lanes":
    # Invert the load-bearing lanes[].console field (NOT consoles[].owns_lanes) so a
    # console's owned lanes here are exactly the lanes a dispatch to it would honour.
    print(" ".join(l.get("id", "") for l in lanes(project)
                   if l.get("status") == "current" and l.get("console") == arg))
elif verb == "console_backup_lanes":
    print(" ".join(l.get("id", "") for l in lanes(project)
                   if l.get("status") == "current" and arg in (l.get("backup_consoles") or [])))
elif verb == "projects":
    print(" ".join(p.get("id", "") for p in m.get("projects", [])))
PY
}

# lane_console  <lane_id>   -> the console id that owns the lane (empty if unknown)
lane_console()  { _swarm_manifest_query lane_console  "$1"; }

# lane_backups  <lane_id>   -> space-separated backup console ids (fallback order)
lane_backups()  { _swarm_manifest_query lane_backups  "$1"; }

# console_cli   <console>   -> the CLI binary the console runs (kimi/claude/codex)
console_cli()   { _swarm_manifest_query console_cli   "$1"; }

# lanes_current             -> space-separated ids of the project's current lanes
lanes_current() { _swarm_manifest_query lanes_current; }

# swarm_consoles            -> space-separated console ids in the manifest roster
swarm_consoles() { _swarm_manifest_query swarm_consoles; }

# console_lanes <console>   -> space-separated CURRENT lanes the console OWNS,
#   derived by inverting the lanes[].console field the dispatcher honours (never
#   consoles[].owns_lanes) — so an operator board built on this can never disagree
#   with where a dispatch actually lands. Retired lanes are excluded.
console_lanes() { _swarm_manifest_query console_lanes "$1"; }

# console_backup_lanes <console> -> space-separated CURRENT lanes the console backs up
console_backup_lanes() { _swarm_manifest_query console_backup_lanes "$1"; }

# swarm_projects            -> space-separated project ids in the manifest
swarm_projects() { _swarm_manifest_query projects; }
