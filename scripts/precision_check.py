#!/usr/bin/env python3
"""Fast precision/recall harness for SmartBugs (the iteration loop for FP work).

Why: the full layers-1,6,7 benchmark is slow/flaky (smartguard does per-function
Ollama CoT), so it can't be a feedback loop for false-positive tuning. The static
layer (layer 1: slither/aderyn/solhint/...) is where the bulk of category FPs come
from and runs in minutes — fast enough to validate that an FP change reduces FP
*without dropping recall* before committing.

Usage:
    # Run a fresh layer-1 eval and print the breakdown:
    python scripts/precision_check.py --run [--layers 1] [--out result.json]

    # Analyse an existing eval JSON:
    python scripts/precision_check.py result.json

    # Compare two eval JSONs (recall must not drop; FP should fall):
    python scripts/precision_check.py after.json --baseline before.json

Exit code is non-zero if a baseline is given and recall dropped — so it can gate
a change in CI or a pre-commit check.
"""

from __future__ import annotations

import argparse
import collections
import json
import subprocess
import sys
from pathlib import Path

CORPUS = "benchmarks/datasets/smartbugs-curated/dataset"


def _load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _breakdown(d: dict) -> dict:
    agg = d["aggregate"]
    fp = collections.Counter()
    gt = collections.Counter()
    recall_by_cat = collections.defaultdict(lambda: [0, 0])  # cat -> [hit, total]
    for r in d.get("per_contract", []):
        m = r.get("match", {})
        gts = r.get("ground_truth", [])
        gts = gts if isinstance(gts, list) else [gts]
        for c in gts:
            gt[c] += 1
            recall_by_cat[c][1] += 1
            if c in m.get("tp", []):
                recall_by_cat[c][0] += 1
        for c in m.get("fp", []):
            fp[c] += 1
    return {"agg": agg, "fp": fp, "gt": gt, "recall_by_cat": recall_by_cat}


def _run_eval(layers: str, out: str) -> str:
    cmd = [
        sys.executable,
        "-m",
        "miesc",
        "evaluate",
        "corpus",
        CORPUS,
        "--layers",
        layers,
        "--timeout",
        "60",
        "--output",
        out,
        "--jsonl",
        "/dev/null",
    ]
    print(f"running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
    return out


def _print(b: dict, label: str) -> None:
    a = b["agg"]
    print(f"\n=== {label} ===")
    print(
        f"recall={a['recall']:.4f}  precision={a['precision']:.4f}  f1={a.get('f1', 0):.4f}"
        f"  tp={a['tp']} fp={a['fp']} fn={a['fn']}"
    )
    print("FP by category:")
    for cat, n in b["fp"].most_common():
        print(f"  {cat:28} {n:4}")
    print("recall by GT category:")
    for cat, (hit, tot) in sorted(b["recall_by_cat"].items(), key=lambda x: -x[1][1]):
        print(f"  {cat:28} {hit}/{tot}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("result", nargs="?", help="eval JSON to analyse")
    ap.add_argument("--run", action="store_true", help="run a fresh eval first")
    ap.add_argument("--layers", default="1")
    ap.add_argument("--out", default="benchmarks/results/precision_check.json")
    ap.add_argument("--baseline", help="prior eval JSON to diff against")
    args = ap.parse_args()

    path = _run_eval(args.layers, args.out) if args.run else args.result
    if not path:
        ap.error("provide a result JSON or --run")

    cur = _breakdown(_load(path))
    _print(cur, f"current ({Path(path).name})")

    if args.baseline:
        base = _breakdown(_load(args.baseline))
        _print(base, f"baseline ({Path(args.baseline).name})")
        dr = cur["agg"]["recall"] - base["agg"]["recall"]
        dp = cur["agg"]["precision"] - base["agg"]["precision"]
        dfp = cur["agg"]["fp"] - base["agg"]["fp"]
        print("\n=== DELTA vs baseline ===")
        print(f"Δrecall={dr:+.4f}  Δprecision={dp:+.4f}  ΔFP={dfp:+d}")
        if dr < -1e-9:
            print("❌ RECALL DROPPED — do not ship this change.")
            return 1
        print("✅ recall held; precision change is safe to ship.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
