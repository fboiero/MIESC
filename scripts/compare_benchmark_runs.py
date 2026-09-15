#!/usr/bin/env python3
"""
Compare two `miesc evaluate corpus` result JSON files (MEJORAS.md item #7).

Not a comparison against an external agent (no comparable run available this
pass — see MEJORAS.md #7 for the scoping decision) — a before/after diff for
measuring whether a set of MIESC changes actually moved recall/precision/F1,
using the same JSON shape `miesc/cli/commands/evaluate.py` already produces
(`aggregate`/`per_category`), not a new metrics format.

Usage:
    python scripts/compare_benchmark_runs.py baseline.json rerun.json

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict


def _delta(before: float, after: float) -> str:
    d = after - before
    sign = "+" if d >= 0 else ""
    return f"{sign}{d:.4f}"


def _print_row(label: str, before: Dict[str, Any], after: Dict[str, Any]) -> None:
    print(
        f"{label:<28} "
        f"P {before['precision']:.4f} -> {after['precision']:.4f} ({_delta(before['precision'], after['precision'])})  "
        f"R {before['recall']:.4f} -> {after['recall']:.4f} ({_delta(before['recall'], after['recall'])})  "
        f"F1 {before['f1']:.4f} -> {after['f1']:.4f} ({_delta(before['f1'], after['f1'])})"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path, help="Earlier `miesc evaluate corpus -o` output")
    parser.add_argument("rerun", type=Path, help="Later `miesc evaluate corpus -o` output")
    args = parser.parse_args()

    baseline = json.loads(args.baseline.read_text())
    rerun = json.loads(args.rerun.read_text())

    if baseline["aggregate"]["contracts_evaluated"] != rerun["aggregate"]["contracts_evaluated"]:
        print(
            f"WARNING: contract count differs "
            f"({baseline['aggregate']['contracts_evaluated']} vs "
            f"{rerun['aggregate']['contracts_evaluated']}) — comparison may not be apples-to-apples",
            file=sys.stderr,
        )

    print("=== Aggregate ===")
    _print_row("TOTAL", baseline["aggregate"], rerun["aggregate"])
    print()

    print("=== Per category ===")
    categories = sorted(set(baseline["per_category"]) | set(rerun["per_category"]))
    regressions = []
    for cat in categories:
        b = baseline["per_category"].get(cat)
        r = rerun["per_category"].get(cat)
        if not b or not r:
            print(f"{cat:<28} missing in one of the two runs, skipped")
            continue
        _print_row(cat, b, r)
        if r["recall"] < b["recall"]:
            regressions.append(cat)

    print()
    if regressions:
        print(f"RECALL REGRESSIONS in: {', '.join(regressions)}")
    else:
        print("No per-category recall regressions.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
