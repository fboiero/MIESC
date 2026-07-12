#!/usr/bin/env python3
"""
Train + persist the recall-safe triage model (src/ml/triage_ranker).

Consolidates the wild-harness anchored labels from the six ground-truth sources into the
classifier dataset format ({"finding": {...}, "context": "...", "label": true/false}; True =
real) and trains GradientBoosting -> models/triage_model.joblib.

The dataset is derived training data (regenerable) and is not committed; the small model
artifact is. Re-collect the wild labels first with scripts/wild_benign_context_eval.py if the
/tmp outputs are gone (see docs/research/WILD_BENIGN_CONTEXT_EVAL_INSTRUCTIONS.md).

Usage:
  python3 scripts/train_triage_model.py                    # build from /tmp wild outputs + train
  python3 scripts/train_triage_model.py --dataset d.jsonl  # train from an existing dataset

Author: Fernando Boiero · License: AGPL-3.0
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

WILD_GLOBS = [
    "/tmp/wild_fsalzano_full.jsonl",
    "/tmp/wild_dappscan_x.jsonl",
    "/tmp/wild_c4_numoen_x.jsonl",
    "/tmp/wild_sherlock_gmx_x.jsonl",
    "/tmp/wild_solidifi.jsonl",
]
DEFAULT_DATASET = "/tmp/triage_dataset.jsonl"


def build_dataset(out: str) -> int:
    """Reshape wild jsonl -> {finding, context, label}; keep bool-labeled, dedup."""
    seen, rows, tp, fp = set(), [], 0, 0
    for g in WILD_GLOBS:
        for path in glob.glob(g):
            for line in open(path, errors="ignore"):
                if not line.strip():
                    continue
                r = json.loads(line)
                if not isinstance(r.get("label"), bool):
                    continue
                key = (r.get("check"), r.get("line"), r.get("contract"), r["label"])
                if key in seen:
                    continue
                seen.add(key)
                rows.append({
                    "finding": {"type": r.get("type", ""), "check": r.get("check", ""),
                                "severity": r.get("severity", "medium") or "medium",
                                "function": r.get("function", ""), "line": r.get("line", 0)},
                    "context": r.get("code", ""), "label": bool(r["label"]),
                })
                tp += r["label"]
                fp += not r["label"]
    with open(out, "w") as fh:
        for o in rows:
            fh.write(json.dumps(o) + "\n")
    print(f"dataset: {len(rows)} samples ({tp} real, {fp} FP) -> {out}")
    return len(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description="Train the recall-safe triage model")
    ap.add_argument("--dataset", default=DEFAULT_DATASET)
    args = ap.parse_args()

    if not os.path.exists(args.dataset):
        if args.dataset == DEFAULT_DATASET:
            n = build_dataset(args.dataset)
            if n < 20:
                print("Not enough labeled data — re-run the wild harness collect first.")
                return 1
        else:
            print(f"dataset not found: {args.dataset}")
            return 1

    from miesc.ml.triage_ranker import train
    print("training triage model (coarse + structural features)...")
    metrics = train(args.dataset)
    for k, v in metrics.items():
        print(f"  {k}: {v}")
    size = os.path.getsize(metrics["model_path"]) if os.path.exists(metrics["model_path"]) else 0
    print(f"  model size: {size/1024:.0f} KB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
