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
import os
import statistics
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


# LLM-backed tools: their output is non-deterministic even with a fixed seed,
# so configs including them must be repeated N times to report mean ± SD.
# SOURCE_DATE_EPOCH only fixes artifact timestamps, not LLM sampling.
LLM_TOOLS = {"smartllm", "gptscan"}


def config_is_stochastic(config):
    """True if the config invokes an LLM tool (needs N>1 repetitions)."""
    tools = config["tools"]
    if tools is None:  # None == all available layers, which include the LLM ones
        return True
    return bool(set(tools) & LLM_TOOLS)


def _mean_sd(values):
    """Return (mean, sample-SD) rounded; SD is 0.0 for a single value."""
    mean = statistics.fmean(values)
    sd = statistics.stdev(values) if len(values) > 1 else 0.0
    return round(mean, 4), round(sd, 4)


def aggregate_runs(config_name, config, run_results):
    """Collapse N single-run results into mean ± SD.

    Keeps the ``metrics`` key holding the MEAN (backward compatible with any
    reader of a single-run file) and adds ``metrics_std`` plus the raw
    per-run overall metrics under ``runs``.
    """
    agg_metrics, agg_std = {}, {}
    for key in ("precision", "recall", "f1"):
        mean, sd = _mean_sd([r["metrics"][key] for r in run_results])
        agg_metrics[key] = mean
        agg_std[key] = sd
    for key in ("tp", "fp", "fn"):
        agg_metrics[key] = round(statistics.fmean([r["metrics"][key] for r in run_results]), 1)

    by_cat = {}
    for cat in run_results[0]["by_category"]:
        entry = {}
        for key in ("precision", "recall", "f1"):
            mean, sd = _mean_sd([r["by_category"][cat][key] for r in run_results])
            entry[key] = mean
            entry[f"{key}_sd"] = sd
        for key in ("tp", "fp", "fn"):
            entry[key] = round(statistics.fmean([r["by_category"][cat][key] for r in run_results]), 1)
        by_cat[cat] = entry

    # Per-contract: majority vote across runs (detected in >= half the runs).
    # This gives one stable outcome per contract for the paired McNemar test.
    n = len(run_results)
    per_contract = {}
    for path in run_results[0].get("per_contract", {}):
        hits = sum(1 for r in run_results if r.get("per_contract", {}).get(path))
        per_contract[path] = hits * 2 >= n

    return {
        "config": config_name,
        "name": config["name"],
        "tools": config["tools"] or "all_available",
        "num_runs": len(run_results),
        "stochastic": config_is_stochastic(config),
        "metrics": agg_metrics,
        "metrics_std": agg_std,
        "runs": [r["metrics"] for r in run_results],
        "by_category": by_cat,
        "per_contract": per_contract,
        "per_contract_runs": [r.get("per_contract", {}) for r in run_results],
    }


def run_ablation_config(config_name, config, contracts_by_cat):
    """Run one ablation configuration and return metrics."""
    tools = config["tools"]
    total_tp, total_fp, total_fn = 0, 0, 0
    category_results = {}
    # Per-contract detection outcome (True = the contract's true-category vuln was
    # detected). Needed for the paired McNemar test (P1-A.2): with vs without the
    # intelligence layer over the SAME contracts.
    per_contract = {}

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

            hit = category in detected
            per_contract[str(sol_file)] = hit
            if hit:
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
        "per_contract": per_contract,
    }


def _write_results(outfile, results, total, args, elapsed, partial):
    """Write/checkpoint results. Called after every config so a killed run keeps
    its completed configs instead of losing everything. Atomic (tmp + replace)."""
    payload = {
        "timestamp": outfile.stem.replace("ablation_study_", ""),
        "miesc_version": "5.1.1",
        "dataset": "SmartBugs-curated",
        "total_contracts": total,
        "runs_requested": args.runs,
        "variance_config": args.variance_config,
        "llm_cache_disabled": bool(args.runs > 1),
        "partial": partial,
        "configs_completed": len(results),
        "execution_time_seconds": round(elapsed, 2),
        "configurations": results,
    }
    tmp = outfile.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2))
    tmp.replace(outfile)  # atomic: a kill mid-write can't corrupt the real file


def main():
    parser = argparse.ArgumentParser(description="MIESC Ablation Study")
    parser.add_argument("--config", help="Run single config (L1_static, L1_L3_symbolic, L1_L5_llm, L1_L3_L5, all_layers)")
    parser.add_argument("--save", action="store_true")
    parser.add_argument(
        "--runs", type=int, default=1,
        help="Repetitions for the --variance-config; report mean ± SD. All other "
             "configs run once. Default: 1.",
    )
    parser.add_argument(
        "--variance-config", default="all_layers", choices=list(CONFIGS.keys()),
        help="Which config gets --runs repetitions for variance (default: all_layers, "
             "the headline config).",
    )
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be >= 1")
    if args.runs > 1 and not config_is_stochastic(CONFIGS[args.variance_config]):
        print(f"  WARNING: --variance-config {args.variance_config} is deterministic; "
              f"repeating it yields SD=0 trivially.")
    # A disk cache hit makes repeated LLM runs identical (fake SD=0). Worse, the
    # cache key is (tool:model:contract) with no config, so a variance config would
    # hit results seeded by an earlier config. When measuring variance, force fresh
    # model calls across the WHOLE run.
    if args.runs > 1:
        os.environ["MIESC_DISABLE_LLM_CACHE"] = "1"
        print("  LLM cache DISABLED for this run (variance measurement).")

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

    outfile = None
    if args.save:
        outdir = PROJECT_ROOT / "benchmarks" / "results"
        outdir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        outfile = outdir / f"ablation_study_{ts}.json"

    for name, config in configs_to_run.items():
        # Only the designated variance config repeats; everything else runs once
        # (deterministic, or variance not needed there). Keeps runtime bounded.
        reps = args.runs if (args.runs > 1 and name == args.variance_config) else 1
        if reps > 1:
            print(f"\n  === {config['name']}: {reps} runs (stochastic LLM config) ===")
        run_results = []
        for i in range(reps):
            if reps > 1:
                print(f"  [run {i + 1}/{reps}]")
            run_results.append(run_ablation_config(name, config, contracts_by_cat))
        if len(run_results) == 1:
            results.append(run_results[0])
        else:
            results.append(aggregate_runs(name, config, run_results))
        # Checkpoint after every config so an interrupted run keeps its progress.
        if outfile is not None:
            _write_results(outfile, results, total, args, time.time() - start, partial=True)
            print(f"  [checkpoint] {len(results)}/{len(configs_to_run)} configs → {outfile.name}")

    elapsed = time.time() - start

    # Summary table
    print(f"\n{'='*60}")
    print(f"  ABLATION STUDY SUMMARY")
    print(f"{'='*60}")
    print(f"  {'Configuration':<35} {'Recall':>14} {'Prec':>8} {'F1':>8} {'Runs':>5}")
    print(f"  {'-'*35} {'-'*14} {'-'*8} {'-'*8} {'-'*5}")
    for r in results:
        m = r["metrics"]
        sd = r.get("metrics_std")
        nruns = r.get("num_runs", 1)
        recall_str = f"{m['recall']:.1%} ± {sd['recall']:.1%}" if sd else f"{m['recall']:.1%}"
        print(f"  {r['name']:<35} {recall_str:>14} {m['precision']:>7.1%} {m['f1']:>7.1%} {nruns:>5}")
    print(f"\n  Total time: {elapsed:.0f}s")
    print(f"{'='*60}\n")

    if outfile is not None:
        _write_results(outfile, results, total, args, elapsed, partial=False)
        print(f"  Saved to: {outfile}")


if __name__ == "__main__":
    main()
