"""
Performance Benchmarking Script for 2025 Security Improvements
================================================================

Measures real-world performance of Aderyn and Medusa adapters.
Compares against baseline tools (Slither for static, Echidna for fuzzing).

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: November 10, 2025
"""

import time
import json
import sys
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.adapters import (
    AderynAdapter,
    MedusaAdapter,
    register_all_adapters
)
from src.core.tool_protocol import ToolStatus


class AdapterBenchmark:
    """Benchmark runner for tool adapters"""

    def __init__(self, output_dir: str = "outputs/benchmarks"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: Dict[str, Any] = {}

    def benchmark_adapter(
        self,
        adapter,
        contract_path: str,
        runs: int = 3,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Benchmark an adapter with multiple runs

        Args:
            adapter: Tool adapter instance
            contract_path: Path to contract or project
            runs: Number of benchmark runs
            **kwargs: Additional adapter configuration

        Returns:
            Dictionary with benchmark results
        """
        metadata = adapter.get_metadata()
        print(f"\n{'='*70}")
        print(f"Benchmarking: {metadata.name} v{metadata.version}")
        print(f"Category: {metadata.category.value}")
        print(f"{'='*70}")

        # Check availability
        status = adapter.is_available()
        if status != ToolStatus.AVAILABLE:
            print(f"❌ {metadata.name} not available: {status.value}")
            return {
                "tool": metadata.name,
                "status": "not_available",
                "availability_status": status.value
            }

        execution_times = []
        findings_counts = []
        all_findings = []

        for run in range(runs):
            print(f"\n  Run {run + 1}/{runs}...")

            start_time = time.time()
            try:
                result = adapter.analyze(contract_path, **kwargs)
                execution_time = time.time() - start_time

                execution_times.append(execution_time)

                findings = result.get("findings", [])
                findings_counts.append(len(findings))

                if run == 0:  # Store findings from first run
                    all_findings = findings

                print(f"    ⏱️  Time: {execution_time:.2f}s")
                print(f"    🔍 Findings: {len(findings)}")

            except Exception as e:
                print(f"    ❌ Error: {e}")
                return {
                    "tool": metadata.name,
                    "status": "error",
                    "error": str(e)
                }

        # Calculate statistics
        avg_time = sum(execution_times) / len(execution_times)
        min_time = min(execution_times)
        max_time = max(execution_times)
        avg_findings = sum(findings_counts) / len(findings_counts)

        # Group findings by severity
        severity_breakdown = {}
        for finding in all_findings:
            severity = finding.get("severity", "unknown")
            severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1

        benchmark_result = {
            "tool": metadata.name,
            "version": metadata.version,
            "category": metadata.category.value,
            "status": "success",
            "runs": runs,
            "performance": {
                "avg_execution_time_seconds": round(avg_time, 2),
                "min_execution_time_seconds": round(min_time, 2),
                "max_execution_time_seconds": round(max_time, 2),
                "execution_times": [round(t, 2) for t in execution_times]
            },
            "findings": {
                "avg_count": round(avg_findings, 1),
                "counts_per_run": findings_counts,
                "severity_breakdown": severity_breakdown
            },
            "contract": str(contract_path)
        }

        print(f"\n  ✅ Benchmark Complete:")
        print(f"     Avg Time: {avg_time:.2f}s")
        print(f"     Avg Findings: {avg_findings:.1f}")
        print(f"     Severity Breakdown: {severity_breakdown}")

        return benchmark_result

    def compare_tools(
        self,
        tool1_result: Dict[str, Any],
        tool2_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Compare two tool benchmark results"""

        if tool1_result["status"] != "success" or tool2_result["status"] != "success":
            return {"comparison": "N/A - One or both tools unavailable"}

        tool1_time = tool1_result["performance"]["avg_execution_time_seconds"]
        tool2_time = tool2_result["performance"]["avg_execution_time_seconds"]

        speedup = tool2_time / tool1_time if tool1_time > 0 else 0

        tool1_findings = tool1_result["findings"]["avg_count"]
        tool2_findings = tool2_result["findings"]["avg_count"]

        findings_diff = tool1_findings - tool2_findings
        findings_diff_pct = (findings_diff / tool2_findings * 100) if tool2_findings > 0 else 0

        comparison = {
            "tool1": tool1_result["tool"],
            "tool2": tool2_result["tool"],
            "performance": {
                "tool1_avg_time": tool1_time,
                "tool2_avg_time": tool2_time,
                "speedup_factor": round(speedup, 2),
                "faster_tool": tool1_result["tool"] if tool1_time < tool2_time else tool2_result["tool"],
                "time_saved_seconds": abs(tool1_time - tool2_time),
                "time_saved_percentage": abs((tool1_time - tool2_time) / tool2_time * 100) if tool2_time > 0 else 0
            },
            "findings": {
                "tool1_avg_findings": tool1_findings,
                "tool2_avg_findings": tool2_findings,
                "findings_difference": findings_diff,
                "findings_difference_pct": round(findings_diff_pct, 1),
                "more_findings": tool1_result["tool"] if tool1_findings > tool2_findings else tool2_result["tool"]
            }
        }

        return comparison

    def generate_report(self, results: List[Dict[str, Any]]) -> str:
        """Generate markdown benchmark report"""

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        report = f"""# MIESC 2025 Security Improvements - Benchmark Report

**Generated**: {timestamp}
**Author**: Fernando Boiero <fboiero@frvm.utn.edu.ar>

## Executive Summary

This report presents performance benchmarks for the 2025 security improvements to MIESC, specifically focusing on the new Aderyn (static analysis) and Medusa (fuzzing) adapters.

"""

        # Individual tool results
        report += "## Individual Tool Performance\n\n"

        for result in results:
            if result["status"] == "success":
                report += f"### {result['tool']} v{result['version']}\n\n"
                report += f"**Category**: {result['category']}\n\n"
                report += "**Performance Metrics**:\n"
                report += f"- Average Execution Time: {result['performance']['avg_execution_time_seconds']}s\n"
                report += f"- Min/Max Time: {result['performance']['min_execution_time_seconds']}s / {result['performance']['max_execution_time_seconds']}s\n"
                report += f"- Average Findings: {result['findings']['avg_count']}\n\n"

                if result['findings']['severity_breakdown']:
                    report += "**Severity Breakdown**:\n"
                    for severity, count in result['findings']['severity_breakdown'].items():
                        report += f"- {severity.capitalize()}: {count}\n"
                    report += "\n"

            else:
                report += f"### {result['tool']}\n\n"
                report += f"**Status**: {result['status']}\n"
                if "error" in result:
                    report += f"**Error**: {result['error']}\n"
                report += "\n"

        # Comparisons section (if we have comparison data)
        if "comparisons" in self.results:
            report += "## Tool Comparisons\n\n"
            for comp in self.results["comparisons"]:
                if "comparison" in comp and comp["comparison"] == "N/A - One or both tools unavailable":
                    continue

                report += f"### {comp['tool1']} vs {comp['tool2']}\n\n"
                report += "**Performance**:\n"
                perf = comp["performance"]
                report += f"- {comp['tool1']}: {perf['tool1_avg_time']}s\n"
                report += f"- {comp['tool2']}: {perf['tool2_avg_time']}s\n"
                report += f"- Speedup: {perf['speedup_factor']}x\n"
                report += f"- Faster Tool: {perf['faster_tool']}\n"
                report += f"- Time Saved: {perf['time_saved_seconds']:.2f}s ({perf['time_saved_percentage']:.1f}%)\n\n"

                report += "**Findings**:\n"
                findings = comp["findings"]
                report += f"- {comp['tool1']}: {findings['tool1_avg_findings']} findings\n"
                report += f"- {comp['tool2']}: {findings['tool2_avg_findings']} findings\n"
                report += f"- Difference: {findings['findings_difference']} ({findings['findings_difference_pct']:.1f}%)\n"
                report += f"- More Findings: {findings['more_findings']}\n\n"

        return report

    def save_results(self, filename: str = "benchmark_results.json"):
        """Save benchmark results to JSON file"""
        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n✅ Results saved to: {filepath}")


def main():
    """Main benchmark execution"""
    print("="*70)
    print("MIESC 2025 Security Improvements - Performance Benchmark")
    print("="*70)

    # Register all adapters
    print("\nRegistering adapters...")
    report = register_all_adapters()
    print(f"✅ Registered {report['registered']} adapters")

    # Test contract path
    test_contract = Path(__file__).parent.parent / "contracts" / "test_suite" / "VulnerableBank.sol"

    if not test_contract.exists():
        print(f"❌ Test contract not found: {test_contract}")
        return

    benchmark = AdapterBenchmark()

    # Benchmark Aderyn (Static Analysis)
    print("\n" + "="*70)
    print("PHASE 1: Static Analysis Benchmarks")
    print("="*70)

    aderyn_adapter = AderynAdapter()
    aderyn_result = benchmark.benchmark_adapter(
        aderyn_adapter,
        str(test_contract),
        runs=3
    )

    # Benchmark Medusa (Fuzzing)
    print("\n" + "="*70)
    print("PHASE 2: Fuzzing Benchmarks")
    print("="*70)

    medusa_adapter = MedusaAdapter()
    medusa_result = benchmark.benchmark_adapter(
        medusa_adapter,
        str(test_contract.parent),  # Medusa needs project directory
        runs=3,
        test_limit=1000,  # Reduced for benchmarking
        timeout=60
    )

    # Store results
    benchmark.results = {
        "timestamp": datetime.now().isoformat(),
        "test_contract": str(test_contract),
        "results": [aderyn_result, medusa_result]
    }

    # Generate and save report
    print("\n" + "="*70)
    print("GENERATING REPORT")
    print("="*70)

    markdown_report = benchmark.generate_report([aderyn_result, medusa_result])

    # Save markdown report
    report_filename = f"benchmark_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    report_path = benchmark.output_dir / report_filename
    with open(report_path, 'w') as f:
        f.write(markdown_report)
    print(f"✅ Markdown report saved to: {report_path}")

    # Save JSON results
    json_filename = f"benchmark_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    benchmark.save_results(json_filename)

    print("\n" + "="*70)
    print("BENCHMARK COMPLETE")
    print("="*70)
    print(f"\nResults available at: {benchmark.output_dir}")


if __name__ == "__main__":
    main()
