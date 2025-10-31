#!/usr/bin/env python3
"""
Xaudit v2.0 - Benchmark Runner
Executes the Xaudit pipeline against public datasets for evaluation
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import subprocess
import multiprocessing
from dataclasses import dataclass, asdict


@dataclass
class BenchmarkResult:
    """Result of running Xaudit on a single contract."""
    contract_path: str
    dataset: str
    execution_time: float
    success: bool
    error_message: Optional[str]
    tools_executed: List[str]
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


class BenchmarkRunner:
    """Run Xaudit pipeline on benchmark datasets."""

    DATASETS = {
        'smartbugs-curated': {
            'path': 'datasets/smartbugs-curated',
            'pattern': '**/*.sol',
            'description': 'SmartBugs Curated (142 annotated contracts)'
        },
        'solidifi-benchmark': {
            'path': 'datasets/solidifi-benchmark',
            'pattern': '**/*.sol',
            'description': 'SolidiFI Benchmark (9,369 injected bugs)'
        },
        'smart-contract-dataset': {
            'path': 'datasets/smart-contract-dataset',
            'pattern': '**/*.sol',
            'description': 'Smart Contract Dataset (12K contracts)'
        },
        'verismart-benchmarks': {
            'path': 'datasets/verismart-benchmarks',
            'pattern': '**/*.sol',
            'description': 'VeriSmart Benchmarks (129 contracts)'
        },
        'not-so-smart-contracts': {
            'path': 'datasets/not-so-smart-contracts',
            'pattern': '**/*.sol',
            'description': 'Not So Smart Contracts (Real examples)'
        }
    }

    def __init__(self, dataset: str, max_contracts: Optional[int] = None,
                 parallel: int = 1, output_dir: str = 'analysis/benchmark'):
        self.dataset = dataset
        self.max_contracts = max_contracts
        self.parallel = parallel
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        if dataset not in self.DATASETS:
            raise ValueError(f"Unknown dataset: {dataset}. Available: {list(self.DATASETS.keys())}")

        self.dataset_info = self.DATASETS[dataset]
        self.dataset_path = Path(self.dataset_info['path'])

        if not self.dataset_path.exists():
            raise FileNotFoundError(
                f"Dataset not found: {self.dataset_path}\n"
                f"Run: bash scripts/download_datasets.sh"
            )

    def find_contracts(self) -> List[Path]:
        """Find all Solidity contracts in the dataset."""
        contracts = list(self.dataset_path.glob(self.dataset_info['pattern']))

        # Filter out test files and mock contracts
        contracts = [c for c in contracts if not any(
            x in c.name.lower() for x in ['test', 'mock', 'interface']
        )]

        if self.max_contracts:
            contracts = contracts[:self.max_contracts]

        return contracts

    def run_xaudit_on_contract(self, contract_path: Path) -> BenchmarkResult:
        """Run Xaudit pipeline on a single contract."""
        print(f"  Analyzing: {contract_path.name}")

        start_time = datetime.now()

        try:
            # Run Xaudit pipeline
            # Note: This assumes xaudit.py exists with proper CLI
            result = subprocess.run(
                [
                    'python', 'xaudit.py',
                    '--target', str(contract_path),
                    '--output', str(self.output_dir / 'results' / contract_path.stem),
                    '--quick',  # Skip time-intensive tools for benchmarking
                    '--no-interactive'
                ],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout per contract
            )

            execution_time = (datetime.now() - start_time).total_seconds()

            if result.returncode == 0:
                # Parse results
                results_json = self.output_dir / 'results' / contract_path.stem / 'report.json'

                if results_json.exists():
                    with open(results_json) as f:
                        data = json.load(f)

                    findings = data.get('findings', [])
                    summary = data.get('summary', {})

                    return BenchmarkResult(
                        contract_path=str(contract_path),
                        dataset=self.dataset,
                        execution_time=execution_time,
                        success=True,
                        error_message=None,
                        tools_executed=summary.get('tools_executed', []),
                        total_findings=len(findings),
                        critical=summary.get('critical_count', 0),
                        high=summary.get('high_count', 0),
                        medium=summary.get('medium_count', 0),
                        low=summary.get('low_count', 0),
                        info=summary.get('info_count', 0)
                    )

            # Execution failed
            return BenchmarkResult(
                contract_path=str(contract_path),
                dataset=self.dataset,
                execution_time=execution_time,
                success=False,
                error_message=result.stderr[:500],
                tools_executed=[],
                total_findings=0,
                critical=0, high=0, medium=0, low=0, info=0
            )

        except subprocess.TimeoutExpired:
            return BenchmarkResult(
                contract_path=str(contract_path),
                dataset=self.dataset,
                execution_time=300.0,
                success=False,
                error_message="Timeout (5 minutes)",
                tools_executed=[],
                total_findings=0,
                critical=0, high=0, medium=0, low=0, info=0
            )
        except Exception as e:
            return BenchmarkResult(
                contract_path=str(contract_path),
                dataset=self.dataset,
                execution_time=(datetime.now() - start_time).total_seconds(),
                success=False,
                error_message=str(e)[:500],
                tools_executed=[],
                total_findings=0,
                critical=0, high=0, medium=0, low=0, info=0
            )

    def run(self) -> Dict:
        """Run benchmark on all contracts."""
        print(f"\n🚀 Xaudit v2.0 Benchmark Runner")
        print(f"================================")
        print(f"Dataset: {self.dataset_info['description']}")
        print(f"Path: {self.dataset_path}")
        print(f"Parallel: {self.parallel} workers")
        print(f"Output: {self.output_dir}")
        print()

        # Find contracts
        contracts = self.find_contracts()
        print(f"📁 Found {len(contracts)} contracts")

        if self.max_contracts:
            print(f"   (Limited to first {self.max_contracts})")

        print()

        # Run analysis
        if self.parallel > 1:
            print(f"⚡ Running in parallel with {self.parallel} workers...")
            with multiprocessing.Pool(self.parallel) as pool:
                results = pool.map(self.run_xaudit_on_contract, contracts)
        else:
            print(f"🔄 Running sequentially...")
            results = [self.run_xaudit_on_contract(c) for c in contracts]

        # Calculate statistics
        stats = self._calculate_statistics(results)

        # Save results
        self._save_results(results, stats)

        # Print summary
        self._print_summary(stats)

        return stats

    def _calculate_statistics(self, results: List[BenchmarkResult]) -> Dict:
        """Calculate benchmark statistics."""
        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success]

        total_findings = sum(r.total_findings for r in successful)
        total_critical = sum(r.critical for r in successful)
        total_high = sum(r.high for r in successful)
        total_medium = sum(r.medium for r in successful)
        total_low = sum(r.low for r in successful)
        total_info = sum(r.info for r in successful)

        total_time = sum(r.execution_time for r in results)
        avg_time = total_time / len(results) if results else 0

        return {
            'dataset': self.dataset,
            'timestamp': datetime.now().isoformat(),
            'contracts': {
                'total': len(results),
                'successful': len(successful),
                'failed': len(failed),
                'success_rate': len(successful) / len(results) * 100 if results else 0
            },
            'findings': {
                'total': total_findings,
                'critical': total_critical,
                'high': total_high,
                'medium': total_medium,
                'low': total_low,
                'info': total_info,
                'avg_per_contract': total_findings / len(successful) if successful else 0
            },
            'performance': {
                'total_time_seconds': total_time,
                'avg_time_per_contract': avg_time,
                'contracts_per_hour': 3600 / avg_time if avg_time > 0 else 0
            },
            'errors': [
                {'contract': r.contract_path, 'error': r.error_message}
                for r in failed
            ]
        }

    def _save_results(self, results: List[BenchmarkResult], stats: Dict):
        """Save benchmark results to files."""
        # Save detailed results
        results_file = self.output_dir / f'{self.dataset}_results.json'
        with open(results_file, 'w') as f:
            json.dump([asdict(r) for r in results], f, indent=2)

        # Save statistics
        stats_file = self.output_dir / f'{self.dataset}_stats.json'
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2)

        # Save summary CSV
        csv_file = self.output_dir / f'{self.dataset}_summary.csv'
        with open(csv_file, 'w') as f:
            f.write('Contract,Success,Time(s),Findings,Critical,High,Medium,Low,Info\n')
            for r in results:
                f.write(f'{Path(r.contract_path).name},{r.success},{r.execution_time:.2f},'
                       f'{r.total_findings},{r.critical},{r.high},{r.medium},{r.low},{r.info}\n')

        print(f"\n💾 Results saved:")
        print(f"   {results_file}")
        print(f"   {stats_file}")
        print(f"   {csv_file}")

    def _print_summary(self, stats: Dict):
        """Print benchmark summary."""
        print(f"\n📊 Benchmark Summary")
        print(f"====================")
        print(f"Dataset: {self.dataset}")
        print()

        print(f"Contracts:")
        print(f"  Total:      {stats['contracts']['total']}")
        print(f"  Successful: {stats['contracts']['successful']}")
        print(f"  Failed:     {stats['contracts']['failed']}")
        print(f"  Success Rate: {stats['contracts']['success_rate']:.2f}%")
        print()

        print(f"Findings:")
        print(f"  Total:        {stats['findings']['total']}")
        print(f"  Critical:     {stats['findings']['critical']}")
        print(f"  High:         {stats['findings']['high']}")
        print(f"  Medium:       {stats['findings']['medium']}")
        print(f"  Low:          {stats['findings']['low']}")
        print(f"  Info:         {stats['findings']['info']}")
        print(f"  Avg/Contract: {stats['findings']['avg_per_contract']:.2f}")
        print()

        print(f"Performance:")
        print(f"  Total Time:   {stats['performance']['total_time_seconds']:.2f}s")
        print(f"  Avg Time:     {stats['performance']['avg_time_per_contract']:.2f}s")
        print(f"  Throughput:   {stats['performance']['contracts_per_hour']:.2f} contracts/hour")
        print()

        if stats['errors']:
            print(f"❌ Errors: {len(stats['errors'])}")
            for err in stats['errors'][:5]:  # Show first 5
                print(f"   {Path(err['contract']).name}: {err['error'][:80]}")
            if len(stats['errors']) > 5:
                print(f"   ... and {len(stats['errors']) - 5} more")


def main():
    parser = argparse.ArgumentParser(
        description='Run Xaudit v2.0 benchmark on public datasets'
    )

    parser.add_argument(
        '--dataset',
        choices=list(BenchmarkRunner.DATASETS.keys()) + ['all'],
        required=True,
        help='Dataset to benchmark'
    )

    parser.add_argument(
        '--max-contracts',
        type=int,
        help='Maximum number of contracts to analyze (default: all)'
    )

    parser.add_argument(
        '--parallel',
        type=int,
        default=1,
        help='Number of parallel workers (default: 1)'
    )

    parser.add_argument(
        '--output',
        default='analysis/benchmark',
        help='Output directory (default: analysis/benchmark)'
    )

    args = parser.parse_args()

    if args.dataset == 'all':
        # Run on all datasets
        all_stats = {}

        for dataset_name in BenchmarkRunner.DATASETS.keys():
            try:
                runner = BenchmarkRunner(
                    dataset=dataset_name,
                    max_contracts=args.max_contracts,
                    parallel=args.parallel,
                    output_dir=args.output
                )
                stats = runner.run()
                all_stats[dataset_name] = stats

            except Exception as e:
                print(f"\n❌ Error running benchmark on {dataset_name}: {e}")
                continue

        # Save combined statistics
        combined_file = Path(args.output) / 'combined_stats.json'
        with open(combined_file, 'w') as f:
            json.dump(all_stats, f, indent=2)

        print(f"\n✅ All benchmarks completed!")
        print(f"📊 Combined statistics: {combined_file}")

    else:
        # Run on single dataset
        runner = BenchmarkRunner(
            dataset=args.dataset,
            max_contracts=args.max_contracts,
            parallel=args.parallel,
            output_dir=args.output
        )
        runner.run()

    print()


if __name__ == '__main__':
    main()
