#!/usr/bin/env python3
"""
MIESC Benchmark Regression Checker

Compares current benchmark results against baseline to detect performance regressions.
Fails CI if metrics drop below acceptable threshold.

Usage:
    python check_regression.py results.json --threshold 0.10
    python check_regression.py results.json --baseline baseline.json --threshold 0.05

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Default baseline file location
DEFAULT_BASELINE = Path(__file__).parent / "baseline.json"

# Metrics to check for regression (higher is better)
METRICS_HIGHER_BETTER = ["avg_precision", "avg_recall", "avg_f1", "detection_rate"]

# Metrics to check for regression (lower is better)
METRICS_LOWER_BETTER = ["avg_time_ms"]


def load_json(path: Path) -> Dict[str, Any]:
    """Load JSON file."""
    with open(path) as f:
        return json.load(f)


def extract_metrics(data: Dict[str, Any]) -> Dict[str, float]:
    """Extract key metrics from benchmark results."""
    metrics = {}

    # Handle different result formats
    if "summary" in data:
        summary = data["summary"]
    elif "results" in data and isinstance(data["results"], dict):
        summary = data["results"]
    else:
        summary = data

    # Extract metrics
    for key in METRICS_HIGHER_BETTER + METRICS_LOWER_BETTER:
        if key in summary:
            metrics[key] = float(summary[key])

    # Calculate aggregate if we have tool-level results
    if "tools" in data:
        for metric in METRICS_HIGHER_BETTER:
            values = [t.get(metric, 0) for t in data["tools"].values() if metric in t]
            if values:
                metrics[f"avg_{metric}"] = sum(values) / len(values)

    return metrics


def check_regression(
    current: Dict[str, float],
    baseline: Dict[str, float],
    threshold: float,
) -> Tuple[bool, List[str]]:
    """
    Check for performance regression.

    Args:
        current: Current benchmark metrics
        baseline: Baseline metrics to compare against
        threshold: Maximum allowed regression (0.10 = 10%)

    Returns:
        Tuple of (passed, list of failure messages)
    """
    failures = []
    passed = True

    for metric in METRICS_HIGHER_BETTER:
        if metric in current and metric in baseline:
            base_val = baseline[metric]
            curr_val = current[metric]

            if base_val > 0:
                change = (curr_val - base_val) / base_val

                if change < -threshold:
                    passed = False
                    failures.append(
                        f"REGRESSION: {metric} dropped {abs(change)*100:.1f}% "
                        f"({base_val:.3f} -> {curr_val:.3f})"
                    )
                elif change > threshold:
                    print(f"IMPROVEMENT: {metric} improved {change*100:.1f}%")
                else:
                    print(f"OK: {metric} = {curr_val:.3f} (baseline: {base_val:.3f})")

    for metric in METRICS_LOWER_BETTER:
        if metric in current and metric in baseline:
            base_val = baseline[metric]
            curr_val = current[metric]

            if base_val > 0:
                change = (curr_val - base_val) / base_val

                if change > threshold:
                    passed = False
                    failures.append(
                        f"REGRESSION: {metric} increased {change*100:.1f}% "
                        f"({base_val:.1f}ms -> {curr_val:.1f}ms)"
                    )
                elif change < -threshold:
                    print(f"IMPROVEMENT: {metric} decreased {abs(change)*100:.1f}%")
                else:
                    print(f"OK: {metric} = {curr_val:.1f}ms (baseline: {base_val:.1f}ms)")

    return passed, failures


def main():
    parser = argparse.ArgumentParser(
        description="Check benchmark results for performance regression"
    )
    parser.add_argument(
        "results",
        type=Path,
        help="Path to current benchmark results JSON",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=DEFAULT_BASELINE,
        help="Path to baseline JSON (default: benchmarks/baseline.json)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.10,
        help="Regression threshold as decimal (default: 0.10 = 10%%)",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Update baseline with current results instead of comparing",
    )

    args = parser.parse_args()

    # Load current results
    if not args.results.exists():
        print(f"ERROR: Results file not found: {args.results}")
        sys.exit(1)

    current_data = load_json(args.results)
    current_metrics = extract_metrics(current_data)

    if not current_metrics:
        print("WARNING: No metrics found in results, skipping regression check")
        sys.exit(0)

    # Update baseline mode
    if args.update_baseline:
        print(f"Updating baseline: {args.baseline}")
        with open(args.baseline, "w") as f:
            json.dump(
                {
                    "version": current_data.get("version", "unknown"),
                    "timestamp": current_data.get("timestamp", "unknown"),
                    "metrics": current_metrics,
                },
                f,
                indent=2,
            )
        print("Baseline updated successfully")
        sys.exit(0)

    # Load baseline
    if not args.baseline.exists():
        print(f"WARNING: Baseline not found: {args.baseline}")
        print("Run with --update-baseline to create initial baseline")
        print("Skipping regression check for this run")
        sys.exit(0)

    baseline_data = load_json(args.baseline)
    baseline_metrics = baseline_data.get("metrics", extract_metrics(baseline_data))

    # Compare
    print(f"\n{'='*60}")
    print("MIESC Benchmark Regression Check")
    print(f"Threshold: {args.threshold*100:.0f}%")
    print(f"{'='*60}\n")

    passed, failures = check_regression(current_metrics, baseline_metrics, args.threshold)

    print(f"\n{'='*60}")

    if passed:
        print("PASSED: No performance regression detected")
        sys.exit(0)
    else:
        print("FAILED: Performance regression detected")
        for failure in failures:
            print(f"  - {failure}")
        sys.exit(1)


if __name__ == "__main__":
    main()
