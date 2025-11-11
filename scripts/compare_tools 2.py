#!/usr/bin/env python3
"""
Xaudit v2.0 - Tool Comparison Script
Compares performance of individual tools and combined pipeline on benchmark datasets
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set
from collections import defaultdict
import pandas as pd


class ToolComparator:
    """Compare detection capabilities of different tools."""

    TOOLS = [
        'solhint',
        'slither',
        'surya',
        'mythril',
        'manticore',
        'echidna',
        'medusa',
        'foundry_fuzz',
        'foundry_invariants',
        'certora'
    ]

    VULNERABILITY_CATEGORIES = [
        'reentrancy',
        'access_control',
        'arithmetic',
        'unchecked_calls',
        'denial_of_service',
        'bad_randomness',
        'front_running',
        'timestamp_dependency',
        'tx_origin',
        'uninitialized_storage'
    ]

    def __init__(self, benchmark_dir: str):
        self.benchmark_dir = Path(benchmark_dir)

        if not self.benchmark_dir.exists():
            raise FileNotFoundError(f"Benchmark directory not found: {self.benchmark_dir}")

    def load_benchmark_results(self, dataset: str) -> List[Dict]:
        """Load results from a benchmark run."""
        results_file = self.benchmark_dir / f'{dataset}_results.json'

        if not results_file.exists():
            raise FileNotFoundError(
                f"Results not found: {results_file}\n"
                f"Run benchmark first: python scripts/run_benchmark.py --dataset {dataset}"
            )

        with open(results_file) as f:
            return json.load(f)

    def analyze_tool_coverage(self, results: List[Dict]) -> Dict:
        """Analyze which tools detected which vulnerabilities."""
        tool_stats = {tool: defaultdict(int) for tool in self.TOOLS}

        for result in results:
            if not result['success']:
                continue

            # Load detailed report for this contract
            contract_name = Path(result['contract_path']).stem
            report_path = self.benchmark_dir / 'results' / contract_name / 'report.json'

            if not report_path.exists():
                continue

            with open(report_path) as f:
                report = json.load(f)

            # Analyze findings by tool
            for finding in report.get('findings', []):
                tool = finding.get('tool', 'unknown')
                severity = finding.get('severity', 'unknown').lower()
                category = finding.get('category', 'other').lower()

                if tool in tool_stats:
                    tool_stats[tool]['total'] += 1
                    tool_stats[tool][f'severity_{severity}'] += 1
                    tool_stats[tool][f'category_{category}'] += 1

        return tool_stats

    def calculate_overlap(self, results: List[Dict]) -> Dict:
        """Calculate overlap between tools (which vulnerabilities are found by multiple tools)."""
        vulnerability_map = defaultdict(set)  # vuln_id -> set of tools that found it

        for result in results:
            if not result['success']:
                continue

            contract_name = Path(result['contract_path']).stem
            report_path = self.benchmark_dir / 'results' / contract_name / 'report.json'

            if not report_path.exists():
                continue

            with open(report_path) as f:
                report = json.load(f)

            for finding in report.get('findings', []):
                tool = finding.get('tool', 'unknown')
                location = finding.get('location', {})
                file_path = location.get('file', 'unknown')
                line = location.get('line', 0)

                # Create unique ID for vulnerability (file + line + severity)
                vuln_id = f"{file_path}:{line}:{finding.get('severity', 'unknown')}"
                vulnerability_map[vuln_id].add(tool)

        # Calculate overlap statistics
        overlap_stats = {
            'unique_vulnerabilities': len(vulnerability_map),
            'single_tool': 0,
            'multiple_tools': 0,
            'all_tools': 0,
            'tool_combinations': defaultdict(int)
        }

        for vuln_id, tools in vulnerability_map.items():
            num_tools = len(tools)

            if num_tools == 1:
                overlap_stats['single_tool'] += 1
            else:
                overlap_stats['multiple_tools'] += 1

            if num_tools == len(self.TOOLS):
                overlap_stats['all_tools'] += 1

            # Count tool combinations
            tool_combo = ','.join(sorted(tools))
            overlap_stats['tool_combinations'][tool_combo] += 1

        return overlap_stats

    def compare_by_category(self, results: List[Dict]) -> pd.DataFrame:
        """Compare tool performance by vulnerability category."""
        category_matrix = {cat: {tool: 0 for tool in self.TOOLS} for cat in self.VULNERABILITY_CATEGORIES}

        for result in results:
            if not result['success']:
                continue

            contract_name = Path(result['contract_path']).stem
            report_path = self.benchmark_dir / 'results' / contract_name / 'report.json'

            if not report_path.exists():
                continue

            with open(report_path) as f:
                report = json.load(f)

            for finding in report.get('findings', []):
                tool = finding.get('tool', 'unknown')
                category = finding.get('category', 'other').lower()

                if tool in self.TOOLS and category in self.VULNERABILITY_CATEGORIES:
                    category_matrix[category][tool] += 1

        # Convert to DataFrame
        df = pd.DataFrame(category_matrix).T
        df['Total'] = df.sum(axis=1)

        return df

    def generate_comparison_report(self, dataset: str) -> Dict:
        """Generate comprehensive comparison report."""
        print(f"\n📊 Tool Comparison - {dataset}")
        print("=" * 60)

        # Load results
        results = self.load_benchmark_results(dataset)
        print(f"Loaded {len(results)} results")

        # Analyze tool coverage
        print("\n1️⃣  Analyzing tool coverage...")
        tool_stats = self.analyze_tool_coverage(results)

        # Calculate overlap
        print("2️⃣  Calculating tool overlap...")
        overlap_stats = self.calculate_overlap(results)

        # Category comparison
        print("3️⃣  Comparing by vulnerability category...")
        category_df = self.compare_by_category(results)

        # Generate report
        report = {
            'dataset': dataset,
            'timestamp': datetime.now().isoformat(),
            'tool_statistics': tool_stats,
            'overlap_analysis': overlap_stats,
            'category_comparison': category_df.to_dict()
        }

        return report

    def print_summary(self, report: Dict):
        """Print comparison summary."""
        print(f"\n📈 Comparison Summary")
        print("=" * 60)

        # Tool statistics
        print("\n🔧 Tool Statistics:")
        print(f"{'Tool':<20} {'Total Findings':<15} {'Critical':<10} {'High':<10}")
        print("-" * 60)

        tool_stats = report['tool_statistics']
        for tool in self.TOOLS:
            stats = tool_stats.get(tool, {})
            total = stats.get('total', 0)
            critical = stats.get('severity_critical', 0)
            high = stats.get('severity_high', 0)
            print(f"{tool:<20} {total:<15} {critical:<10} {high:<10}")

        # Overlap analysis
        print("\n🔍 Overlap Analysis:")
        overlap = report['overlap_analysis']
        print(f"  Total Unique Vulnerabilities: {overlap['unique_vulnerabilities']}")
        print(f"  Found by Single Tool:         {overlap['single_tool']} ({overlap['single_tool']/overlap['unique_vulnerabilities']*100:.1f}%)")
        print(f"  Found by Multiple Tools:      {overlap['multiple_tools']} ({overlap['multiple_tools']/overlap['unique_vulnerabilities']*100:.1f}%)")

        # Top tool combinations
        print("\n🤝 Top Tool Combinations:")
        combos = sorted(
            overlap['tool_combinations'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        for combo, count in combos:
            tools = combo.split(',')
            print(f"  {len(tools)} tools ({', '.join(tools[:3])}{'...' if len(tools) > 3 else ''}): {count}")

        # Category comparison
        print("\n📂 Findings by Category:")
        category_comp = report['category_comparison']
        for category, tools_dict in list(category_comp.items())[:10]:
            total = tools_dict.get('Total', 0)
            if total > 0:
                print(f"  {category:<25} {total:>5} findings")

    def save_report(self, report: Dict, output_dir: Path):
        """Save comparison report."""
        output_dir.mkdir(parents=True, exist_ok=True)

        # Save JSON
        json_file = output_dir / f"comparison_{report['dataset']}.json"
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=2)

        # Save CSV
        csv_file = output_dir / f"tool_stats_{report['dataset']}.csv"
        tool_stats = report['tool_statistics']

        with open(csv_file, 'w') as f:
            f.write('Tool,Total,Critical,High,Medium,Low,Info\n')
            for tool in self.TOOLS:
                stats = tool_stats.get(tool, {})
                f.write(f"{tool},{stats.get('total', 0)},{stats.get('severity_critical', 0)},"
                       f"{stats.get('severity_high', 0)},{stats.get('severity_medium', 0)},"
                       f"{stats.get('severity_low', 0)},{stats.get('severity_informational', 0)}\n")

        # Save category matrix CSV
        category_csv = output_dir / f"category_matrix_{report['dataset']}.csv"
        df = pd.DataFrame(report['category_comparison'])
        df.to_csv(category_csv)

        print(f"\n💾 Reports saved:")
        print(f"   {json_file}")
        print(f"   {csv_file}")
        print(f"   {category_csv}")


def main():
    parser = argparse.ArgumentParser(
        description='Compare tool performance on benchmark datasets'
    )

    parser.add_argument(
        '--dataset',
        help='Dataset to analyze (default: all available)'
    )

    parser.add_argument(
        '--benchmark-dir',
        default='analysis/benchmark',
        help='Benchmark results directory (default: analysis/benchmark)'
    )

    parser.add_argument(
        '--output',
        default='analysis/comparison',
        help='Output directory (default: analysis/comparison)'
    )

    parser.add_argument(
        '--all',
        action='store_true',
        help='Compare all available datasets'
    )

    args = parser.parse_args()

    comparator = ToolComparator(args.benchmark_dir)

    if args.all or args.dataset is None:
        # Find all available datasets
        available = [f.stem.replace('_results', '')
                    for f in Path(args.benchmark_dir).glob('*_results.json')]

        if not available:
            print("❌ No benchmark results found!")
            print(f"   Run: python scripts/run_benchmark.py --dataset <dataset>")
            sys.exit(1)

        print(f"Found {len(available)} datasets: {', '.join(available)}")

        for dataset in available:
            try:
                report = comparator.generate_comparison_report(dataset)
                comparator.print_summary(report)
                comparator.save_report(report, Path(args.output))
            except Exception as e:
                print(f"\n❌ Error processing {dataset}: {e}")
                continue

    else:
        # Process single dataset
        try:
            report = comparator.generate_comparison_report(args.dataset)
            comparator.print_summary(report)
            comparator.save_report(report, Path(args.output))
        except Exception as e:
            print(f"\n❌ Error: {e}")
            sys.exit(1)

    print("\n✅ Comparison complete!")


if __name__ == '__main__':
    main()
