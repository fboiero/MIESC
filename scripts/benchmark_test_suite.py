#!/usr/bin/env python3
"""
MIESC Test Suite Benchmark Script
Analyzes test contracts and collects performance statistics

Usage:
    python scripts/benchmark_test_suite.py

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: November 8, 2025
Version: 3.3.0
"""

import time
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from miesc.core.analyzer import MIESCAnalyzer
except ImportError:
    # Fallback: just use subprocess to call slither directly
    MIESCAnalyzer = None


class BenchmarkResults:
    """Store and format benchmark results"""

    def __init__(self):
        self.start_time = time.time()
        self.contract_results = []
        self.total_findings = 0
        self.total_high = 0
        self.total_medium = 0
        self.total_low = 0
        self.total_info = 0

    def add_contract(self, contract_path: str, duration: float, findings: List[Dict]):
        """Add contract analysis results"""
        high = sum(1 for f in findings if f.get('severity') == 'High')
        medium = sum(1 for f in findings if f.get('severity') == 'Medium')
        low = sum(1 for f in findings if f.get('severity') == 'Low')
        info = sum(1 for f in findings if f.get('severity') == 'Informational')

        self.contract_results.append({
            'contract': Path(contract_path).name,
            'path': contract_path,
            'duration': duration,
            'total_findings': len(findings),
            'high': high,
            'medium': medium,
            'low': low,
            'info': info
        })

        self.total_findings += len(findings)
        self.total_high += high
        self.total_medium += medium
        self.total_low += low
        self.total_info += info

    def get_total_duration(self) -> float:
        """Get total benchmark duration"""
        return time.time() - self.start_time

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'timestamp': datetime.now().isoformat(),
            'total_duration': self.get_total_duration(),
            'contracts_analyzed': len(self.contract_results),
            'total_findings': self.total_findings,
            'severity_breakdown': {
                'high': self.total_high,
                'medium': self.total_medium,
                'low': self.total_low,
                'informational': self.total_info
            },
            'contract_results': self.contract_results
        }

    def print_summary(self):
        """Print human-readable summary"""
        print("\n" + "="*80)
        print("MIESC v3.3.0 - Test Suite Benchmark Results")
        print("="*80)
        print(f"\nTimestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Duration: {self.get_total_duration():.2f}s")
        print(f"Contracts Analyzed: {len(self.contract_results)}")
        print(f"\nTotal Findings: {self.total_findings}")
        print(f"  - High:          {self.total_high}")
        print(f"  - Medium:        {self.total_medium}")
        print(f"  - Low:           {self.total_low}")
        print(f"  - Informational: {self.total_info}")

        print("\n" + "-"*80)
        print("Per-Contract Results:")
        print("-"*80)
        print(f"{'Contract':<25} {'Duration':<10} {'Total':<8} {'High':<6} {'Med':<6} {'Low':<6} {'Info':<6}")
        print("-"*80)

        for result in self.contract_results:
            print(f"{result['contract']:<25} "
                  f"{result['duration']:>8.2f}s "
                  f"{result['total_findings']:>6} "
                  f"{result['high']:>6} "
                  f"{result['medium']:>6} "
                  f"{result['low']:>6} "
                  f"{result['info']:>6}")

        print("-"*80)

        # Calculate averages
        if self.contract_results:
            avg_duration = sum(r['duration'] for r in self.contract_results) / len(self.contract_results)
            avg_findings = self.total_findings / len(self.contract_results)
            print(f"\nAverage per contract:")
            print(f"  - Duration: {avg_duration:.2f}s")
            print(f"  - Findings: {avg_findings:.1f}")

        print("="*80 + "\n")


def check_dependencies() -> Tuple[bool, List[str]]:
    """Check if required security tools are available"""
    tools = {
        'slither': 'slither --version',
        'myth': 'myth version',
        'manticore': 'manticore --version',
        'aderyn': 'aderyn --version'
    }

    available = []
    missing = []

    print("Checking security tool availability...")
    for tool, cmd in tools.items():
        try:
            result = subprocess.run(
                cmd.split(),
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                available.append(tool)
                print(f"  ✅ {tool}")
            else:
                missing.append(tool)
                print(f"  ❌ {tool} (not working)")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            missing.append(tool)
            print(f"  ❌ {tool} (not installed)")

    return len(available) > 0, available


def run_tests() -> bool:
    """Run MIESC test suite"""
    print("\n" + "="*80)
    print("Running MIESC Test Suite")
    print("="*80 + "\n")

    try:
        result = subprocess.run(
            ['python', '-m', 'pytest', 'tests/', '-v', '--tb=short'],
            capture_output=True,
            text=True,
            timeout=300
        )

        print(result.stdout)
        if result.stderr:
            print(result.stderr)

        success = result.returncode == 0
        if success:
            print("\n✅ All tests passed!")
        else:
            print("\n❌ Some tests failed")

        return success
    except subprocess.TimeoutExpired:
        print("\n⏱️ Tests timed out after 5 minutes")
        return False
    except Exception as e:
        print(f"\n❌ Error running tests: {e}")
        return False


def analyze_test_contracts() -> BenchmarkResults:
    """Analyze all test contracts and collect statistics"""
    print("\n" + "="*80)
    print("Analyzing Test Contracts")
    print("="*80 + "\n")

    contracts_dir = Path("contracts/test_suite")
    contract_files = sorted(contracts_dir.glob("*.sol"))

    if not contract_files:
        print(f"❌ No contracts found in {contracts_dir}")
        return BenchmarkResults()

    print(f"Found {len(contract_files)} contracts to analyze\n")

    results = BenchmarkResults()

    for contract_path in contract_files:
        print(f"Analyzing: {contract_path.name}...")

        try:
            start_time = time.time()

            if MIESCAnalyzer:
                # Use MIESC Analyzer
                analyzer = MIESCAnalyzer(
                    contract_path=str(contract_path),
                    enable_slither=True,
                    enable_mythril=False,  # Skip Mythril for speed
                    enable_manticore=False,  # Skip Manticore (not installed)
                    enable_aderyn=False  # Skip Aderyn (might not be installed)
                )

                # Run analysis
                analysis_result = analyzer.analyze()

                # Extract findings
                findings = []
                if analysis_result and 'findings' in analysis_result:
                    findings = analysis_result['findings']
            else:
                # Fallback: Use slither directly via subprocess
                result = subprocess.run(
                    ['slither', str(contract_path), '--json', '-'],
                    capture_output=True,
                    text=True,
                    timeout=120
                )

                findings = []
                if result.returncode == 0 or result.stdout:
                    try:
                        slither_output = json.loads(result.stdout)
                        if 'results' in slither_output:
                            detectors = slither_output['results'].get('detectors', [])
                            findings = [{'tool': 'slither', 'severity': d.get('impact', 'Unknown')}
                                        for d in detectors]
                    except json.JSONDecodeError:
                        pass

            duration = time.time() - start_time
            results.add_contract(str(contract_path), duration, findings)

            print(f"  ✅ Completed in {duration:.2f}s - {len(findings)} findings")

        except subprocess.TimeoutExpired:
            print(f"  ⏱️  Timeout after 120s")
            results.add_contract(str(contract_path), 0, [])
        except Exception as e:
            print(f"  ❌ Error: {str(e)[:100]}")
            results.add_contract(str(contract_path), 0, [])

    return results


def save_results(results: BenchmarkResults):
    """Save results to JSON file"""
    output_dir = Path("benchmark_results")
    output_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = output_dir / f"benchmark_{timestamp}.json"

    with open(output_file, 'w') as f:
        json.dump(results.to_dict(), f, indent=2)

    print(f"\n📊 Results saved to: {output_file}")

    # Also save as latest
    latest_file = output_dir / "benchmark_latest.json"
    with open(latest_file, 'w') as f:
        json.dump(results.to_dict(), f, indent=2)

    print(f"📊 Latest results: {latest_file}")


def main():
    """Main benchmark execution"""
    print("\n" + "="*80)
    print("MIESC v3.3.0 - Comprehensive Benchmark Suite")
    print("="*80)
    print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80 + "\n")

    # Check dependencies
    has_tools, available_tools = check_dependencies()
    if not has_tools:
        print("\n❌ No security tools available. Install at least Slither to run benchmarks.")
        return 1

    print(f"\n✅ Available tools: {', '.join(available_tools)}\n")

    # Run tests
    tests_passed = run_tests()
    if not tests_passed:
        print("\n⚠️  Tests failed, but continuing with contract analysis...")

    # Analyze test contracts
    results = analyze_test_contracts()

    # Print summary
    results.print_summary()

    # Save results
    save_results(results)

    print("\n" + "="*80)
    print("Benchmark Complete!")
    print("="*80 + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
