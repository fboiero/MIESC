#!/usr/bin/env python3
"""
MIESC Ablation Study — Layer Contribution Analysis
====================================================

Runs SmartBugs benchmark with different layer configurations to measure
how much each layer contributes to recall independently.

Configurations:
  1. Layer 1 only (static: slither + aderyn)
  2. Layer 1 + 3 (+ symbolic: mythril)
  3. Layer 1 + 5 (+ LLM: smartllm, gptscan)
  4. Layer 1 + 3 + 5 (static + symbolic + LLM)
  5. All available layers

This answers the key research question:
"How much does each analysis technique contribute to vulnerability detection?"

Usage:
    python benchmarks/ablation_study.py --save
    python benchmarks/ablation_study.py --config static_only

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

import argparse
import json
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Import the benchmark runner's core functions
from benchmarks.reproduce_benchmark import (
    find_dataset,
    get_contracts_by_category,
    run_miesc_analysis,
    classify_finding,
)

# Ablation configurations
CONFIGS = {
    "L1_static": {
        "name": "Layer 1: Static Analysis",
        "tools": ["slither", "aderyn"],
        "description": "Slither + Aderyn only",
    },
    "L1_L3_symbolic": {
        "name": "Layer 1 + 3: Static + Symbolic",
        "tools": ["slither", "aderyn", "mythril"],
        "description": "Add Mythril symbolic execution",
    },
    "L1_L5_llm": {
        "name": "Layer 1 + 5: Static + LLM",
        "tools": ["slither", "aderyn", "smartllm", "gptscan"],
        "description": "Add LLM semantic analysis (Ollama)",
    },
    "L1_L3_L5": {
        "name": "Layer 1 + 3 + 5: Static + Symbolic + LLM",
        "tools": ["slither", "aderyn", "mythril", "smartllm", "gptscan"],
        "description": "Three core techniques combined",
    },
    "all_layers": {
        "name": "All available layers",
        "tools": None,  # None = all available
        "description": "Full 9-layer analysis",
    },
}


def run_ablation_config(config_name, config, contracts_by_cat):
    """Run one ablation configuration and return metrics."""
    tools = config["tools"]
    total_tp, total_fp, total_fn = 0, 0, 0
    category_results = {}

    print(f"\n  --- {config['name']} ({config['description']}) ---")

    for category, files in contracts_by_cat.items():
        cat_tp, cat_fn = 0, 0
        cat_fp = 0

        for sol_file in files:
            findings = run_miesc_analysis(sol_file, tools=tools)

            detected = defaultdict(int)
            for f in findings:
                cat = classify_finding(f)
                detected[cat] += 1

            if category in detected:
                cat_tp += 1
            else:
                cat_fn += 1

            for cat_name, count in detected.items():
                if cat_name != category and cat_name != "other":
                    cat_fp += count

        precision = cat_tp / (cat_tp + cat_fp) if (cat_tp + cat_fp) > 0 else 0
        recall = cat_tp / (cat_tp + cat_fn) if (cat_tp + cat_fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        category_results[category] = {
            "tp": cat_tp, "fp": cat_fp, "fn": cat_fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }

        total_tp += cat_tp
        total_fp += cat_fp
        total_fn += cat_fn

    overall_p = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    overall_r = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    overall_f1 = 2 * overall_p * overall_r / (overall_p + overall_r) if (overall_p + overall_r) > 0 else 0

    print(f"    Recall: {overall_r:.1%}  Precision: {overall_p:.1%}  F1: {overall_f1:.1%}  (TP={total_tp} FP={total_fp} FN={total_fn})")

    return {
        "config": config_name,
        "name": config["name"],
        "tools": config["tools"] or "all_available",
        "metrics": {
            "precision": round(overall_p, 4),
            "recall": round(overall_r, 4),
            "f1": round(overall_f1, 4),
            "tp": total_tp, "fp": total_fp, "fn": total_fn,
        },
        "by_category": category_results,
    }


def main():
    parser = argparse.ArgumentParser(description="MIESC Ablation Study")
    parser.add_argument("--config", help="Run single config (L1_static, L1_L3_symbolic, L1_L5_llm, L1_L3_L5, all_layers)")
    parser.add_argument("--save", action="store_true")
    args = parser.parse_args()

    dataset_path = find_dataset()
    contracts_by_cat = get_contracts_by_category(dataset_path)
    total = sum(len(f) for f in contracts_by_cat.values())

    print(f"\n{'='*60}")
    print(f"  MIESC Ablation Study — Layer Contribution Analysis")
    print(f"  {total} contracts, {len(contracts_by_cat)} categories")
    print(f"{'='*60}")

    configs_to_run = {args.config: CONFIGS[args.config]} if args.config else CONFIGS
    start = time.time()
    results = []

    for name, config in configs_to_run.items():
        r = run_ablation_config(name, config, contracts_by_cat)
        results.append(r)

    elapsed = time.time() - start

    # Summary table
    print(f"\n{'='*60}")
    print(f"  ABLATION STUDY SUMMARY")
    print(f"{'='*60}")
    print(f"  {'Configuration':<35} {'Recall':>8} {'Prec':>8} {'F1':>8}")
    print(f"  {'-'*35} {'-'*8} {'-'*8} {'-'*8}")
    for r in results:
        m = r["metrics"]
        print(f"  {r['name']:<35} {m['recall']:>7.1%} {m['precision']:>7.1%} {m['f1']:>7.1%}")
    print(f"\n  Total time: {elapsed:.0f}s")
    print(f"{'='*60}\n")

    if args.save:
        outdir = PROJECT_ROOT / "benchmarks" / "results"
        outdir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        outfile = outdir / f"ablation_study_{ts}.json"
        with open(outfile, "w") as f:
            json.dump({
                "timestamp": ts,
                "miesc_version": "5.1.1",
                "dataset": "SmartBugs-curated",
                "total_contracts": total,
                "execution_time_seconds": round(elapsed, 2),
                "configurations": results,
            }, f, indent=2)
        print(f"  Saved to: {outfile}")


if __name__ == "__main__":
    main()
