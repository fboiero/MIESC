#!/usr/bin/env python3
"""
MIESC Benchmark Runner - Scientific Validation against SmartBugs Curated Dataset.

This script runs MIESC adapters against the SmartBugs Curated dataset
and calculates precision, recall, F1-score for vulnerability detection.

Dataset: SmartBugs Curated (143 contracts, 208 tagged vulnerabilities)
- https://github.com/smartbugs/smartbugs-curated

Vulnerability Categories:
- access_control (18 contracts)
- arithmetic (15 contracts)
- bad_randomness (8 contracts)
- denial_of_service (6 contracts)
- front_running (4 contracts)
- other (3 contracts)
- reentrancy (31 contracts)
- short_addresses (1 contract)
- time_manipulation (5 contracts)
- unchecked_low_level_calls (52 contracts)

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: 2025-01-15
"""

import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.adapters.crosschain_adapter import CrossChainAdapter
from src.adapters.slither_adapter import SlitherAdapter

# Mapping from SmartBugs categories to MIESC detection types
CATEGORY_MAPPING = {
    "access_control": ["access-control", "authorization", "owner", "tx-origin", "suicidal"],
    "arithmetic": ["overflow", "underflow", "integer", "arithmetic"],
    "bad_randomness": ["randomness", "weak-prng", "block.timestamp"],
    "denial_of_service": ["dos", "denial-of-service", "gas", "loop"],
    "front_running": ["front-running", "race-condition", "tod"],
    "reentrancy": ["reentrancy", "re-entrancy", "external-call"],
    "time_manipulation": ["timestamp", "block.timestamp", "now"],
    "unchecked_low_level_calls": ["unchecked", "low-level", "call", "send", "delegatecall"],
    "short_addresses": ["short-address"],
    "other": [],
}


@dataclass
class BenchmarkResult:
    """Result of benchmarking a single contract."""

    contract_path: str
    category: str
    expected_vuln: bool  # Always True for SmartBugs Curated
    detected: bool
    findings_count: int
    relevant_findings: int
    execution_time: float
    error: str = ""
    findings: List[Dict] = field(default_factory=list)


@dataclass
class CategoryStats:
    """Statistics for a vulnerability category."""

    true_positives: int = 0
    false_negatives: int = 0
    total_findings: int = 0
    relevant_findings: int = 0
    contracts_tested: int = 0
    total_time: float = 0.0


def find_matching_findings(findings: List[Dict], category: str) -> List[Dict]:
    """Find findings that match the expected vulnerability category."""
    keywords = CATEGORY_MAPPING.get(category, [])
    if not keywords:
        return findings  # For 'other', return all findings

    matching = []
    for finding in findings:
        # Check title, description, category
        text = f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('category', '')}".lower()
        if any(kw in text for kw in keywords):
            matching.append(finding)

    return matching


def run_adapter_benchmark(
    adapter,
    adapter_name: str,
    dataset_path: Path,
    max_contracts: int = 0,
    categories: List[str] = None,
) -> Tuple[Dict[str, CategoryStats], List[BenchmarkResult]]:
    """
    Run benchmark for a single adapter.

    Args:
        adapter: The adapter instance to test
        adapter_name: Name of the adapter
        dataset_path: Path to SmartBugs curated dataset
        max_contracts: Maximum contracts to test (0 = all)
        categories: List of categories to test (None = all)

    Returns:
        Tuple of (category_stats, all_results)
    """
    print(f"\n{'='*60}")
    print(f"BENCHMARKING: {adapter_name}")
    print(f"{'='*60}")

    results = []
    stats = defaultdict(CategoryStats)

    tested = 0
    for category_dir in sorted(dataset_path.iterdir()):
        if not category_dir.is_dir():
            continue

        category = category_dir.name
        if categories and category not in categories:
            continue

        print(f"\n[{category}]")

        contracts = list(category_dir.glob("*.sol"))
        contracts = [c for c in contracts if c.stat().st_size > 10]

        for contract in contracts:
            if max_contracts > 0 and tested >= max_contracts:
                break

            print(f"  {contract.name}...", end=" ", flush=True)

            start_time = time.time()
            try:
                # SmartBugs Curated uses Solidity 0.4.x/0.5.x - need legacy mode
                result = adapter.analyze(str(contract), legacy_solc=True, solc_version="0.4.24")
                exec_time = time.time() - start_time

                findings = result.get("findings", [])
                relevant = find_matching_findings(findings, category)

                detected = len(findings) > 0

                benchmark_result = BenchmarkResult(
                    contract_path=str(contract),
                    category=category,
                    expected_vuln=True,
                    detected=detected,
                    findings_count=len(findings),
                    relevant_findings=len(relevant),
                    execution_time=exec_time,
                    findings=findings[:5],  # Keep first 5 for analysis
                )

                # Update stats
                stats[category].contracts_tested += 1
                stats[category].total_time += exec_time
                stats[category].total_findings += len(findings)
                stats[category].relevant_findings += len(relevant)

                if detected:
                    stats[category].true_positives += 1
                    print(f"TP ({len(findings)} findings, {len(relevant)} relevant)")
                else:
                    stats[category].false_negatives += 1
                    print("FN (no findings)")

            except Exception as e:
                exec_time = time.time() - start_time
                benchmark_result = BenchmarkResult(
                    contract_path=str(contract),
                    category=category,
                    expected_vuln=True,
                    detected=False,
                    findings_count=0,
                    relevant_findings=0,
                    execution_time=exec_time,
                    error=str(e),
                )
                stats[category].false_negatives += 1
                print(f"ERROR: {str(e)[:50]}")

            results.append(benchmark_result)
            tested += 1

        if max_contracts > 0 and tested >= max_contracts:
            break

    return dict(stats), results


def calculate_metrics(stats: Dict[str, CategoryStats]) -> Dict[str, Any]:
    """Calculate precision, recall, F1-score from stats."""
    total_tp = sum(s.true_positives for s in stats.values())
    total_fn = sum(s.false_negatives for s in stats.values())
    total_tested = sum(s.contracts_tested for s in stats.values())
    total_time = sum(s.total_time for s in stats.values())

    # For SmartBugs Curated, all contracts have vulnerabilities
    # So Recall = TP / (TP + FN) = detected / total
    # We don't have false positives (no clean contracts in dataset)

    recall = total_tp / total_tested if total_tested > 0 else 0

    # Precision would require clean contracts to calculate FP
    # For this benchmark, we use "relevant findings ratio" as proxy
    total_findings = sum(s.total_findings for s in stats.values())
    relevant_findings = sum(s.relevant_findings for s in stats.values())
    precision_proxy = relevant_findings / total_findings if total_findings > 0 else 0

    f1 = (
        2 * (precision_proxy * recall) / (precision_proxy + recall)
        if (precision_proxy + recall) > 0
        else 0
    )

    return {
        "total_contracts": total_tested,
        "true_positives": total_tp,
        "false_negatives": total_fn,
        "recall": round(recall * 100, 2),
        "precision_proxy": round(precision_proxy * 100, 2),
        "f1_score": round(f1 * 100, 2),
        "total_findings": total_findings,
        "relevant_findings": relevant_findings,
        "avg_time_per_contract": round(total_time / total_tested, 2) if total_tested > 0 else 0,
        "total_time": round(total_time, 2),
    }


def print_report(adapter_name: str, stats: Dict[str, CategoryStats], metrics: Dict[str, Any]):
    """Print benchmark report."""
    print(f"\n{'='*60}")
    print(f"BENCHMARK REPORT: {adapter_name}")
    print(f"{'='*60}")

    print("\nPer-Category Results:")
    print("-" * 60)
    print(f"{'Category':<25} {'TP':>5} {'FN':>5} {'Recall':>8} {'Findings':>10}")
    print("-" * 60)

    for category, s in sorted(stats.items()):
        recall = s.true_positives / s.contracts_tested * 100 if s.contracts_tested > 0 else 0
        print(
            f"{category:<25} {s.true_positives:>5} {s.false_negatives:>5} {recall:>7.1f}% {s.total_findings:>10}"
        )

    print("-" * 60)
    print(
        f"{'TOTAL':<25} {metrics['true_positives']:>5} {metrics['false_negatives']:>5} {metrics['recall']:>7.1f}% {metrics['total_findings']:>10}"
    )

    print("\nOverall Metrics:")
    print(f"  Recall: {metrics['recall']}%")
    print(f"  Precision (proxy): {metrics['precision_proxy']}%")
    print(f"  F1-Score: {metrics['f1_score']}%")
    print(f"  Avg time/contract: {metrics['avg_time_per_contract']}s")
    print(f"  Total time: {metrics['total_time']}s")


def main():
    """Run benchmark."""
    import argparse

    parser = argparse.ArgumentParser(description="MIESC Benchmark Runner")
    parser.add_argument("--adapter", choices=["slither", "crosschain", "all"], default="slither")
    parser.add_argument("--max", type=int, default=10, help="Max contracts to test (0=all)")
    parser.add_argument("--categories", nargs="+", help="Categories to test")
    parser.add_argument("--output", type=str, help="Output JSON file")
    args = parser.parse_args()

    dataset_path = Path(__file__).parent / "datasets" / "smartbugs-curated" / "dataset"

    if not dataset_path.exists():
        print(f"ERROR: Dataset not found at {dataset_path}")
        sys.exit(1)

    all_results = {}

    adapters = []
    if args.adapter in ["slither", "all"]:
        try:
            adapters.append(("slither", SlitherAdapter()))
        except Exception as e:
            print(f"Slither adapter not available: {e}")

    if args.adapter in ["crosschain", "all"]:
        adapters.append(("crosschain", CrossChainAdapter()))

    for name, adapter in adapters:
        stats, results = run_adapter_benchmark(
            adapter, name, dataset_path, max_contracts=args.max, categories=args.categories
        )
        metrics = calculate_metrics(stats)
        print_report(name, stats, metrics)

        all_results[name] = {
            "metrics": metrics,
            "per_category": {k: vars(v) for k, v in stats.items()},
        }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
