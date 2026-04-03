#!/usr/bin/env python3
"""
MIESC - Reproducible SmartBugs Benchmark
=========================================

Reproduces the metrics published in README.md and the arXiv paper.
Run this script to verify MIESC's benchmark results independently.

Dataset: SmartBugs-curated (143 contracts, 207 vulnerabilities)
Reference: Durieux et al., ICSE 2020

Usage:
    python benchmarks/reproduce_benchmark.py
    python benchmarks/reproduce_benchmark.py --tools slither,aderyn
    python benchmarks/reproduce_benchmark.py --save

Requirements:
    - Slither installed (pip install slither-analyzer)
    - SmartBugs dataset at benchmarks/datasets/smartbugs-curated/

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

DATASET_PATH = PROJECT_ROOT / "data" / "benchmarks" / "smartbugs-curated"
ALT_DATASET_PATH = PROJECT_ROOT / "benchmarks" / "datasets" / "smartbugs-curated"
RESULTS_PATH = PROJECT_ROOT / "benchmarks" / "results"

# Ground truth category to SWC mapping
CATEGORY_SWC = {
    "access_control": ["SWC-105", "SWC-115"],
    "arithmetic": ["SWC-101"],
    "bad_randomness": ["SWC-120"],
    "denial_of_service": ["SWC-113", "SWC-128"],
    "front_running": ["SWC-114"],
    "reentrancy": ["SWC-107"],
    "short_addresses": ["SWC-129"],
    "time_manipulation": ["SWC-116"],
    "unchecked_low_level_calls": ["SWC-104"],
}

# Reverse: SWC to category
SWC_TO_CATEGORY = {}
for cat, swcs in CATEGORY_SWC.items():
    for swc in swcs:
        SWC_TO_CATEGORY[swc] = cat


def find_dataset():
    """Find SmartBugs dataset."""
    for path in [DATASET_PATH, ALT_DATASET_PATH]:
        if path.exists():
            return path
    print("ERROR: SmartBugs dataset not found.")
    print(f"Expected at: {DATASET_PATH}")
    print("Download: git clone https://github.com/smartbugs/smartbugs-curated")
    sys.exit(1)


def load_ground_truth(dataset_path):
    """Load ground truth from SmartBugs vulnerabilities.json."""
    vuln_file = dataset_path / "vulnerabilities.json"
    if not vuln_file.exists():
        # Try alternative structure
        for p in dataset_path.rglob("vulnerabilities.json"):
            vuln_file = p
            break

    if not vuln_file.exists():
        print(f"ERROR: vulnerabilities.json not found in {dataset_path}")
        sys.exit(1)

    with open(vuln_file) as f:
        return json.load(f)


def get_contracts_by_category(dataset_path):
    """Get .sol files organized by category."""
    contracts = defaultdict(list)
    for category_dir in sorted(dataset_path.iterdir()):
        if category_dir.is_dir() and not category_dir.name.startswith("."):
            category = category_dir.name
            for sol_file in sorted(category_dir.glob("*.sol")):
                contracts[category].append(sol_file)
    return contracts


def run_miesc_analysis(contract_path, tools=None):
    """Run MIESC analysis on a single contract."""
    try:
        from src.core.optimized_orchestrator import OptimizedOrchestrator
        orch = OptimizedOrchestrator(cache_enabled=False)
        result = orch.analyze(str(contract_path), tools=tools, timeout=60)

        findings = []
        if hasattr(result, "raw_results"):
            for tool_name, tool_result in result.raw_results.items():
                if isinstance(tool_result, dict):
                    for f in tool_result.get("findings", []):
                        f["tool"] = tool_name
                        findings.append(f)
        return findings
    except Exception as e:
        return []


def classify_finding(finding):
    """Map a MIESC finding to a SmartBugs category."""
    # Try SWC ID first
    swc = finding.get("swc_id", finding.get("swc", ""))
    if swc and swc in SWC_TO_CATEGORY:
        return SWC_TO_CATEGORY[swc]

    # Try type/check name
    check = finding.get("check", finding.get("type", finding.get("title", ""))).lower()

    if "reentran" in check:
        return "reentrancy"
    if "overflow" in check or "underflow" in check or "arithmetic" in check:
        return "arithmetic"
    if "timestamp" in check or "block.timestamp" in check:
        return "time_manipulation"
    if "unchecked" in check or "low-level" in check or "call-return" in check:
        return "unchecked_low_level_calls"
    if "access" in check or "authorization" in check or "tx-origin" in check or "suicidal" in check:
        return "access_control"
    if "random" in check or "weak-prng" in check:
        return "bad_randomness"
    if "front" in check or "frontrun" in check or "order" in check:
        return "front_running"
    if "dos" in check or "denial" in check or "unbounded" in check:
        return "denial_of_service"
    if "short" in check or "address" in check:
        return "short_addresses"

    return "other"


def compute_metrics(ground_truth_count, detected_categories, expected_category):
    """Compute TP, FP, FN for a single category."""
    tp = detected_categories.get(expected_category, 0)
    fp = sum(v for k, v in detected_categories.items() if k != expected_category)
    fn = max(0, ground_truth_count - tp)
    return tp, fp, fn


def run_benchmark(tools=None, save=False):
    """Run the full SmartBugs benchmark."""
    dataset_path = find_dataset()
    contracts_by_cat = get_contracts_by_category(dataset_path)

    total_contracts = sum(len(files) for files in contracts_by_cat.values())
    print(f"\n{'='*60}")
    print(f"  MIESC SmartBugs-curated Benchmark")
    print(f"  {total_contracts} contracts, {len(contracts_by_cat)} categories")
    if tools:
        print(f"  Tools: {', '.join(tools)}")
    else:
        print(f"  Tools: all available")
    print(f"{'='*60}\n")

    start_time = time.time()
    total_tp, total_fp, total_fn = 0, 0, 0
    category_results = {}

    for category, files in contracts_by_cat.items():
        cat_tp, cat_fp, cat_fn = 0, 0, 0
        print(f"  [{category}] {len(files)} contracts...", end=" ", flush=True)
        cat_start = time.time()

        for sol_file in files:
            findings = run_miesc_analysis(sol_file, tools=tools)

            # Classify findings
            detected = defaultdict(int)
            for f in findings:
                cat = classify_finding(f)
                detected[cat] += 1

            # Count TP/FP/FN for this contract
            if category in detected:
                cat_tp += 1  # At least one correct finding
            else:
                cat_fn += 1  # Missed this contract's vulnerability

            # FP = findings in wrong categories
            for cat_name, count in detected.items():
                if cat_name != category and cat_name != "other":
                    cat_fp += count

        elapsed = time.time() - cat_start
        precision = cat_tp / (cat_tp + cat_fp) if (cat_tp + cat_fp) > 0 else 0
        recall = cat_tp / (cat_tp + cat_fn) if (cat_tp + cat_fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        category_results[category] = {
            "contracts": len(files),
            "tp": cat_tp, "fp": cat_fp, "fn": cat_fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
        }

        total_tp += cat_tp
        total_fp += cat_fp
        total_fn += cat_fn

        print(f"P={precision:.1%} R={recall:.1%} F1={f1:.1%} ({elapsed:.1f}s)")

    total_time = time.time() - start_time

    # Overall metrics
    overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    overall_f1 = 2 * overall_precision * overall_recall / (overall_precision + overall_recall) if (overall_precision + overall_recall) > 0 else 0

    print(f"\n{'='*60}")
    print(f"  OVERALL RESULTS")
    print(f"{'='*60}")
    print(f"  Precision:  {overall_precision:.2%}")
    print(f"  Recall:     {overall_recall:.2%}")
    print(f"  F1-Score:   {overall_f1:.2%}")
    print(f"  TP: {total_tp}  FP: {total_fp}  FN: {total_fn}")
    print(f"  Time: {total_time:.1f}s ({total_time/total_contracts:.2f}s/contract)")
    print(f"{'='*60}\n")

    if save:
        RESULTS_PATH.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        result = {
            "timestamp": ts,
            "miesc_version": "5.1.1",
            "dataset": "SmartBugs-curated",
            "total_contracts": total_contracts,
            "tools": tools or "all_available",
            "execution_time_seconds": round(total_time, 2),
            "metrics": {
                "precision": round(overall_precision, 4),
                "recall": round(overall_recall, 4),
                "f1_score": round(overall_f1, 4),
                "true_positives": total_tp,
                "false_positives": total_fp,
                "false_negatives": total_fn,
            },
            "by_category": category_results,
        }
        outfile = RESULTS_PATH / f"benchmark_{ts}.json"
        with open(outfile, "w") as f:
            json.dump(result, f, indent=2)
        print(f"  Results saved to: {outfile}\n")

    return overall_precision, overall_recall, overall_f1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MIESC SmartBugs Benchmark")
    parser.add_argument("--tools", help="Comma-separated tool list (default: all available)")
    parser.add_argument("--save", action="store_true", help="Save results to JSON")
    args = parser.parse_args()

    tools = args.tools.split(",") if args.tools else None
    run_benchmark(tools=tools, save=args.save)
