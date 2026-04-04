#!/usr/bin/env python3
"""
MIESC - Etherscan Contract Distribution Analysis
=================================================

Runs MIESC on a sample of real-world verified contracts and reports
finding distribution by severity, category, and tool. No ground truth
needed — this measures what MIESC finds "in the wild".

Usage:
    python benchmarks/etherscan_distribution.py --sample 100
    python benchmarks/etherscan_distribution.py --sample 500 --save

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

import argparse
import json
import random
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

DATA_DIR = PROJECT_ROOT / "data" / "datasets" / "etherscan" / "contracts"
RESULTS_DIR = PROJECT_ROOT / "benchmarks" / "results"


def run_quick_analysis(contract_path):
    """Run fast analysis (slither + aderyn only)."""
    try:
        from src.core.optimized_orchestrator import OptimizedOrchestrator
        orch = OptimizedOrchestrator(cache_enabled=True)
        result = orch.analyze(str(contract_path), tools=["slither", "aderyn"], timeout=30)

        findings = []
        if hasattr(result, "raw_results"):
            for tool_name, tool_result in result.raw_results.items():
                if isinstance(tool_result, dict):
                    for f in tool_result.get("findings", []):
                        f.setdefault("tool", tool_name)
                        findings.append(f)
        return findings
    except Exception:
        return []


def main():
    parser = argparse.ArgumentParser(description="Etherscan Distribution Analysis")
    parser.add_argument("--sample", type=int, default=100)
    parser.add_argument("--save", action="store_true")
    args = parser.parse_args()

    if not DATA_DIR.exists():
        print("ERROR: Run build_datasets.py --etherscan first")
        sys.exit(1)

    sol_files = sorted(DATA_DIR.glob("*.sol"))
    print(f"\n{'='*60}")
    print(f"  Etherscan Distribution Analysis")
    print(f"  {len(sol_files)} contracts available, sampling {args.sample}")
    print(f"{'='*60}\n")

    random.seed(42)
    sample = random.sample(sol_files, min(args.sample, len(sol_files)))

    start_time = time.time()
    severity_counts = defaultdict(int)
    category_counts = defaultdict(int)
    tool_counts = defaultdict(int)
    contracts_with_findings = 0
    total_findings = 0
    errors = 0

    for i, f in enumerate(sample):
        if (i + 1) % 10 == 0:
            elapsed = time.time() - start_time
            rate = (i + 1) / elapsed
            eta = (len(sample) - i - 1) / rate if rate > 0 else 0
            print(f"  [{i+1}/{len(sample)}] {rate:.1f} contracts/s, ETA {eta:.0f}s", flush=True)

        findings = run_quick_analysis(f)
        if findings:
            contracts_with_findings += 1
            total_findings += len(findings)

            for finding in findings:
                sev = finding.get("severity", "unknown").lower()
                severity_counts[sev] += 1
                cat = finding.get("check", finding.get("type", "unknown"))
                category_counts[cat] += 1
                tool = finding.get("tool", "unknown")
                tool_counts[tool] += 1
        else:
            errors += 1  # Could be error or clean contract

    elapsed = time.time() - start_time

    print(f"\n{'='*60}")
    print(f"  RESULTS ({len(sample)} contracts, {elapsed:.0f}s)")
    print(f"{'='*60}")
    print(f"  Contracts analyzed:       {len(sample)}")
    print(f"  Contracts with findings:  {contracts_with_findings} ({contracts_with_findings/len(sample)*100:.1f}%)")
    print(f"  Total findings:           {total_findings}")
    print(f"  Avg findings/contract:    {total_findings/len(sample):.1f}")
    print(f"  Analysis speed:           {len(sample)/elapsed:.1f} contracts/s")

    print(f"\n  By severity:")
    for sev in ["critical", "high", "medium", "low", "info", "optimization"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            print(f"    {sev:15s} {count:5d} ({count/total_findings*100:.1f}%)")

    print(f"\n  Top 15 finding categories:")
    for cat, count in sorted(category_counts.items(), key=lambda x: -x[1])[:15]:
        print(f"    {cat:40s} {count:5d}")

    print(f"\n  By tool:")
    for tool, count in sorted(tool_counts.items(), key=lambda x: -x[1]):
        print(f"    {tool:20s} {count:5d}")
    print(f"{'='*60}\n")

    if args.save:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        result = {
            "timestamp": ts,
            "miesc_version": "5.1.1",
            "dataset": "Etherscan verified (SmartBugs-Wild)",
            "sample_size": len(sample),
            "total_available": len(sol_files),
            "execution_time_seconds": round(elapsed, 2),
            "contracts_with_findings": contracts_with_findings,
            "total_findings": total_findings,
            "severity_distribution": dict(severity_counts),
            "top_categories": dict(sorted(category_counts.items(), key=lambda x: -x[1])[:30]),
            "tool_distribution": dict(tool_counts),
        }
        outfile = RESULTS_DIR / f"etherscan_distribution_{ts}.json"
        with open(outfile, "w") as f:
            json.dump(result, f, indent=2)
        print(f"  Saved to: {outfile}")


if __name__ == "__main__":
    main()
