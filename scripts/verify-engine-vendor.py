#!/usr/bin/env python3
"""Drift-guard for MIESC's adopted swarm-ops loop engine.

The engine libs + lane-* scripts under scripts/ are byte-identical copies of the
swarm-ops canonical (gitlab.xcapit.com/fer/swarm-ops). Copying alone is not
single-source: without this guard a hand-edit to MIESC's copy would silently
diverge from the canonical -- the exact drift the adoption set out to kill. This
pins the copies: an edit to any adopted file fails --verify, forcing the change to
happen in swarm-ops and be re-synced instead.

  --verify (default): recompute each adopted file's sha256 and compare it to the
    committed baseline (scripts/lib/engine-sync-source.json). Exit 1 on any mismatch,
    missing file, or baseline/list disagreement. Needs NO swarm-ops checkout, so it
    runs in CI.

  --write <swarm-ops-checkout>: FIRST prove every adopted file is byte-identical to
    that checkout's version, THEN record the pin (its HEAD sha) + the sha256 map. It
    refuses if any file diverges from swarm-ops, so a baseline can only ever record
    files that actually match the canonical -- never a hand-edited copy.

Deliberately NOT covered:
  * scripts/lib/swarm-config.local.sh -- MIESC's own per-project config (base branch
    main, gh forge, MIESC- worktree prefix, verify gate). Not a swarm-ops file; a
    re-copy of swarm-config.sh from swarm-ops preserves it.
  * scripts/local-land.sh + scripts/land.sh -- the landers. MIESC lands via GitHub
    (gh) with its own flow, so it does NOT vendor xNinja's/develop's landers. The
    engine (dispatch/run/status/reap/live/loop) never EXECUTES them; landing is a
    deliberate, project-specific operator step.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent  # scripts/ -> repo root
BASELINE = REPO / "scripts" / "lib" / "engine-sync-source.json"

# The adopted swarm-ops surface: byte-identical copies kept in lockstep with the
# canonical. Add an entry only when a new file is genuinely adopted from swarm-ops.
ADOPTED = [
    "scripts/lib/console-registry.sh",
    "scripts/lib/swarm-config.sh",
    "scripts/lib/manifest.sh",
    "scripts/lib/quota-policy.sh",
    "scripts/lane-run.sh",
    "scripts/lane-dispatch.sh",
    "scripts/lane-preflight.sh",
    "scripts/lane-reap.sh",
    "scripts/lane-status.sh",
    "scripts/lane-live.sh",
    "scripts/lane-loop.sh",
    "scripts/lane-ready-branches.sh",
    "scripts/lane-context.sh",
]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verify() -> int:
    try:
        base = json.loads(BASELINE.read_text(encoding="utf-8"))
    except OSError:
        print(
            f"error: no baseline at {BASELINE.relative_to(REPO)} -- run "
            f"`python3 scripts/verify-engine-vendor.py --write <swarm-ops-checkout>` first",
            file=sys.stderr,
        )
        return 1

    recorded = base.get("files", {})
    bad: list[str] = []
    for rel in ADOPTED:
        path = REPO / rel
        if not path.exists():
            bad.append(f"  MISSING     {rel}")
            continue
        want = recorded.get(rel)
        got = _sha256(path)
        if want is None:
            bad.append(f"  UNRECORDED  {rel} (adopted but absent from the baseline)")
        elif got != want:
            bad.append(
                f"  DRIFTED     {rel}\n                baseline {want}\n                on disk  {got}"
            )
    for rel in recorded:
        if rel not in ADOPTED:
            bad.append(f"  STALE       {rel} (in the baseline but no longer adopted)")

    if bad:
        print(
            "engine vendor DRIFT -- MIESC's engine copy left the pinned swarm-ops surface:"
        )
        print("\n".join(bad))
        print(
            "\nfix: make the change in swarm-ops (gitlab.xcapit.com/fer/swarm-ops), re-copy the\n"
            "     adopted file(s) into MIESC, then re-pin:\n"
            "       python3 scripts/verify-engine-vendor.py --write <swarm-ops-checkout>"
        )
        return 1

    pin = str(base.get("pinned_commit", "?"))[:8]
    print(
        f"engine vendor OK: {len(ADOPTED)} files match the pinned swarm-ops surface ({pin})."
    )
    return 0


def _write(src: str) -> int:
    src_path = Path(src).resolve()
    if not (src_path / "scripts").is_dir():
        print(
            f"error: {src} is not a swarm-ops checkout (no scripts/)", file=sys.stderr
        )
        return 1

    # A baseline may only record files that ACTUALLY match the canonical: prove
    # byte-identity against swarm-ops before hashing, so --write can never bless a
    # hand-edited MIESC copy.
    diverged: list[str] = []
    files: dict[str, str] = {}
    for rel in ADOPTED:
        ours = REPO / rel
        theirs = src_path / rel
        if not theirs.exists():
            diverged.append(f"  {rel}: absent in swarm-ops")
        elif not ours.exists():
            diverged.append(f"  {rel}: absent in MIESC")
        elif ours.read_bytes() != theirs.read_bytes():
            diverged.append(f"  {rel}: differs from swarm-ops (re-copy it first)")
        else:
            files[rel] = _sha256(ours)

    if diverged:
        print("refusing to write the baseline -- MIESC diverges from swarm-ops:")
        print("\n".join(diverged))
        return 1

    sha = subprocess.run(
        ["git", "-C", str(src_path), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    try:
        url = subprocess.run(
            ["git", "-C", str(src_path), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except subprocess.CalledProcessError:
        url = "(local checkout -- no origin)"

    BASELINE.write_text(
        json.dumps(
            {
                "canonical": url,
                "pinned_commit": sha,
                "note": (
                    "GENERATED by scripts/verify-engine-vendor.py --write. Do not hand-edit. "
                    "To change an adopted engine file, edit swarm-ops, re-copy it into MIESC, "
                    "then re-run --write."
                ),
                "files": {rel: files[rel] for rel in ADOPTED},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(
        f"wrote {BASELINE.relative_to(REPO)}: {len(files)} files pinned to swarm-ops @ {sha[:8]}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        metavar="SWARM_OPS_CHECKOUT",
        help="verify byte-identity against this swarm-ops checkout, then record the baseline",
    )
    args = parser.parse_args()
    return _write(args.write) if args.write else _verify()


if __name__ == "__main__":
    raise SystemExit(main())
