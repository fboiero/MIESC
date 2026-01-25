#!/usr/bin/env python3
"""
MIESC Benchmark Runner
======================

Run detection accuracy benchmarks against known vulnerability datasets.

Usage:
    python scripts/run_benchmark.py                    # Run full benchmark
    python scripts/run_benchmark.py --dataset smartbugs
    python scripts/run_benchmark.py --compare before.json after.json
    python scripts/run_benchmark.py --quick            # Sample only

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

# Add src to path
ROOT_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))
sys.path.insert(0, str(ROOT_DIR))

from src.benchmark import (
    BenchmarkRunner,
    DatasetLoader,
    MetricsCalculator,
    load_smartbugs,
    load_dvd,
)


def print_banner():
    """Print benchmark banner."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║           MIESC Detection Accuracy Benchmark                 ║
║                                                              ║
║  Datasets: SmartBugs Curated, Damn Vulnerable DeFi           ║
║  Metrics: Precision, Recall, F1 Score by category            ║
╚══════════════════════════════════════════════════════════════╝
""")


def run_full_benchmark(args):
    """Run full benchmark on all datasets."""
    print_banner()

    loader = DatasetLoader()
    runner = BenchmarkRunner(timeout=args.timeout)

    # Load datasets based on selection
    contracts = []

    if args.dataset in ["all", "smartbugs"]:
        print("\n[*] Loading SmartBugs Curated dataset...")
        try:
            sb_contracts = loader.load_smartbugs()
            print(f"    Loaded {len(sb_contracts)} contracts")
            contracts.extend(sb_contracts)
        except FileNotFoundError as e:
            print(f"    Warning: {e}")

    if args.dataset in ["all", "dvd"]:
        print("\n[*] Loading Damn Vulnerable DeFi dataset...")
        try:
            dvd_contracts = loader.load_damn_vulnerable_defi()
            print(f"    Loaded {len(dvd_contracts)} challenges")
            contracts.extend(dvd_contracts)
        except FileNotFoundError as e:
            print(f"    Warning: {e}")

    if not contracts:
        print("\n[!] No contracts loaded. Please ensure datasets are downloaded.")
        print("    Run: git clone --depth 1 https://github.com/smartbugs/smartbugs-curated.git data/benchmarks/smartbugs-curated")
        sys.exit(1)

    # Quick mode - sample only
    if args.quick:
        import random
        sample_size = min(20, len(contracts))
        contracts = random.sample(contracts, sample_size)
        print(f"\n[*] Quick mode: sampling {sample_size} contracts")

    # Show stats
    stats = loader.get_statistics()
    print(f"\n[*] Dataset Statistics:")
    print(f"    Total contracts: {stats['total_contracts']}")
    print(f"    Total vulnerabilities: {stats['total_vulnerabilities']}")
    print(f"    Categories: {', '.join(stats['by_category'].keys())}")

    # Run benchmark
    print(f"\n[*] Running benchmark (mode={args.mode}, parallel={not args.sequential})...")
    print("-" * 60)

    results = runner.run(
        contracts,
        parallel=not args.sequential,
        max_workers=args.workers,
        mode=args.mode,
        verbose=True,
    )

    # Print results
    print("\n" + results.summary())

    # Save results
    if args.output:
        output_path = Path(args.output)
        results.save(output_path)
        print(f"\n[+] Results saved to: {output_path}")

    # Save to history
    history_dir = ROOT_DIR / "data" / "benchmark_history"
    history_dir.mkdir(parents=True, exist_ok=True)
    history_file = history_dir / f"benchmark_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    results.save(history_file)
    print(f"[+] History saved to: {history_file}")

    return results


def compare_results(args):
    """Compare two benchmark runs."""
    print_banner()

    calc = MetricsCalculator()

    print(f"\n[*] Loading results...")
    before = calc.load_result(Path(args.before))
    after = calc.load_result(Path(args.after))

    print(f"    Before: {args.before} ({before.timestamp})")
    print(f"    After: {args.after} ({after.timestamp})")

    comparison = calc.compare(before, after)
    print("\n" + comparison.summary())

    if args.output:
        output_path = Path(args.output)
        with open(output_path, "w") as f:
            json.dump(comparison.to_dict(), f, indent=2)
        print(f"\n[+] Comparison saved to: {output_path}")


def list_history(args):
    """List benchmark history."""
    history_dir = ROOT_DIR / "data" / "benchmark_history"

    if not history_dir.exists():
        print("[!] No benchmark history found.")
        return

    files = sorted(history_dir.glob("benchmark_*.json"), reverse=True)

    if not files:
        print("[!] No benchmark runs found.")
        return

    print("\n=== Benchmark History ===\n")
    print(f"{'Run ID':<25} {'Contracts':<12} {'F1 Score':<10} {'Precision':<10} {'Recall':<10}")
    print("-" * 70)

    for f in files[:20]:  # Show last 20
        try:
            with open(f) as fp:
                data = json.load(fp)
            run_id = f.stem.replace("benchmark_", "")
            contracts = data["summary"]["analyzed_contracts"]
            metrics = data["overall_metrics"]
            print(f"{run_id:<25} {contracts:<12} {metrics['f1_score']*100:>6.1f}%    {metrics['precision']*100:>6.1f}%    {metrics['recall']*100:>6.1f}%")
        except Exception as e:
            print(f"{f.stem:<25} Error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="MIESC Detection Accuracy Benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/run_benchmark.py                     # Full benchmark
  python scripts/run_benchmark.py --quick             # Quick sample
  python scripts/run_benchmark.py --dataset smartbugs # SmartBugs only
  python scripts/run_benchmark.py --mode full         # Use full audit mode
  python scripts/run_benchmark.py --compare a.json b.json
  python scripts/run_benchmark.py --history
        """
    )

    parser.add_argument(
        "--dataset", "-d",
        choices=["all", "smartbugs", "dvd"],
        default="all",
        help="Dataset to benchmark (default: all)"
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["quick", "smart", "full"],
        default="smart",
        help="MIESC audit mode (default: smart)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file for results JSON"
    )
    parser.add_argument(
        "--quick", "-q",
        action="store_true",
        help="Quick mode: sample 20 contracts only"
    )
    parser.add_argument(
        "--sequential",
        action="store_true",
        help="Run sequentially (no parallel)"
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=4,
        help="Number of parallel workers (default: 4)"
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=120,
        help="Timeout per contract in seconds (default: 120)"
    )
    parser.add_argument(
        "--compare",
        nargs=2,
        metavar=("BEFORE", "AFTER"),
        help="Compare two benchmark results"
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="Show benchmark history"
    )

    args = parser.parse_args()

    if args.history:
        list_history(args)
    elif args.compare:
        args.before, args.after = args.compare
        compare_results(args)
    else:
        run_full_benchmark(args)


if __name__ == "__main__":
    main()
