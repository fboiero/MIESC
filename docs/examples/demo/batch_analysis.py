#!/usr/bin/env python3
"""
MIESC Batch Analysis Script

Flexible script for analyzing single contracts or directories of contracts.
Can be customized to use different analysis tools and generate various reports.

Usage:
    python batch_analysis.py <contract_file.sol>
    python batch_analysis.py <directory_with_contracts/>
    python batch_analysis.py <directory/> --export results.json
    python batch_analysis.py <directory/> --tool slither
    python batch_analysis.py <directory/> --parallel 4

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
UNDEF - IUA Córdoba | Maestría en Ciberdefensa
"""

import sys
import os
import json
import time
import subprocess
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class BatchAnalyzer:
    """Batch analyzer for smart contracts"""

    def __init__(self, tool: str = "slither", parallel: int = 1, verbose: bool = False):
        self.tool = tool
        self.parallel = parallel
        self.verbose = verbose
        self.results: List[Dict[str, Any]] = []
        self.start_time = datetime.now()

    def find_contracts(self, path: str) -> List[Path]:
        """Find all Solidity contracts in path (file or directory)"""
        path_obj = Path(path)

        if not path_obj.exists():
            print(f"{Colors.RED}✗ Error: Path does not exist: {path}{Colors.ENDC}")
            sys.exit(1)

        if path_obj.is_file():
            if path_obj.suffix == '.sol':
                return [path_obj]
            else:
                print(f"{Colors.RED}✗ Error: File is not a Solidity contract: {path}{Colors.ENDC}")
                sys.exit(1)

        # Directory - find all .sol files
        contracts = list(path_obj.rglob('*.sol'))
        return sorted(contracts)

    def analyze_contract(self, contract_path: Path) -> Dict[str, Any]:
        """Analyze a single contract"""
        result = {
            'contract': str(contract_path),
            'name': contract_path.name,
            'tool': self.tool,
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'findings': [],
            'error': None,
            'duration': 0
        }

        start = time.time()

        try:
            if self.verbose:
                print(f"{Colors.CYAN}  → Analyzing: {contract_path.name}{Colors.ENDC}")

            if self.tool == "slither":
                result = self._run_slither(contract_path, result)
            elif self.tool == "aderyn":
                result = self._run_aderyn(contract_path, result)
            elif self.tool == "miesc":
                result = self._run_miesc(contract_path, result)
            else:
                result['error'] = f"Unknown tool: {self.tool}"

            result['duration'] = time.time() - start
            result['success'] = True

        except Exception as e:
            result['duration'] = time.time() - start
            result['error'] = str(e)
            if self.verbose:
                print(f"{Colors.RED}    ✗ Error: {e}{Colors.ENDC}")

        return result

    def _run_slither(self, contract_path: Path, result: Dict) -> Dict:
        """Run Slither analysis"""
        cmd = ["slither", str(contract_path), "--json", "-"]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            # Parse JSON output
            if proc.stdout:
                try:
                    data = json.loads(proc.stdout)
                    if 'results' in data and 'detectors' in data['results']:
                        result['findings'] = data['results']['detectors']
                        result['finding_count'] = len(data['results']['detectors'])
                except json.JSONDecodeError:
                    result['error'] = "Failed to parse Slither JSON output"

            result['exit_code'] = proc.returncode

        except subprocess.TimeoutExpired:
            result['error'] = "Analysis timeout (120s)"
        except FileNotFoundError:
            result['error'] = "Slither not found - install with: pip install slither-analyzer"

        return result

    def _run_aderyn(self, contract_path: Path, result: Dict) -> Dict:
        """Run Aderyn analysis"""
        cmd = ["aderyn", str(contract_path)]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            result['output'] = proc.stdout
            result['exit_code'] = proc.returncode

            # Count findings in output
            if proc.stdout:
                finding_count = proc.stdout.count('[High]') + proc.stdout.count('[Medium]') + proc.stdout.count('[Low]')
                result['finding_count'] = finding_count

        except subprocess.TimeoutExpired:
            result['error'] = "Analysis timeout (120s)"
        except FileNotFoundError:
            result['error'] = "Aderyn not found"

        return result

    def _run_miesc(self, contract_path: Path, result: Dict) -> Dict:
        """Run full MIESC analysis (placeholder - integrate with actual MIESC)"""
        # This is a placeholder - integrate with actual MIESC orchestrator
        result['error'] = "MIESC integration not yet implemented - use slither or aderyn for now"
        return result

    def run_batch(self, contracts: List[Path]) -> None:
        """Run batch analysis on all contracts"""
        total = len(contracts)

        print(f"\n{Colors.BOLD}{Colors.BLUE}╔═══════════════════════════════════════════════════════════════╗{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.BLUE}║           MIESC BATCH ANALYSIS - Multi-Layer Security         ║{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.BLUE}╚═══════════════════════════════════════════════════════════════╝{Colors.ENDC}\n")

        print(f"{Colors.YELLOW}[*] Configuration:{Colors.ENDC}")
        print(f"    • Tool: {self.tool}")
        print(f"    • Contracts: {total}")
        print(f"    • Parallel workers: {self.parallel}")
        print(f"    • Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print()

        if self.parallel > 1:
            self._run_parallel(contracts)
        else:
            self._run_sequential(contracts)

        self._print_summary()

    def _run_sequential(self, contracts: List[Path]) -> None:
        """Run analyses sequentially"""
        total = len(contracts)

        for i, contract in enumerate(contracts, 1):
            print(f"{Colors.CYAN}[{i}/{total}] Analyzing: {contract.name}{Colors.ENDC}")
            result = self.analyze_contract(contract)
            self.results.append(result)

            if result['success']:
                finding_count = result.get('finding_count', 0)
                duration = result['duration']
                print(f"{Colors.GREEN}    ✓ Complete - {finding_count} findings in {duration:.2f}s{Colors.ENDC}\n")
            else:
                print(f"{Colors.RED}    ✗ Failed: {result.get('error', 'Unknown error')}{Colors.ENDC}\n")

    def _run_parallel(self, contracts: List[Path]) -> None:
        """Run analyses in parallel"""
        total = len(contracts)
        completed = 0

        with ThreadPoolExecutor(max_workers=self.parallel) as executor:
            future_to_contract = {
                executor.submit(self.analyze_contract, contract): contract
                for contract in contracts
            }

            for future in as_completed(future_to_contract):
                contract = future_to_contract[future]
                completed += 1

                try:
                    result = future.result()
                    self.results.append(result)

                    finding_count = result.get('finding_count', 0)
                    duration = result['duration']

                    if result['success']:
                        print(f"{Colors.GREEN}[{completed}/{total}] ✓ {contract.name} - {finding_count} findings ({duration:.2f}s){Colors.ENDC}")
                    else:
                        print(f"{Colors.RED}[{completed}/{total}] ✗ {contract.name} - {result.get('error', 'Failed')}{Colors.ENDC}")

                except Exception as e:
                    print(f"{Colors.RED}[{completed}/{total}] ✗ {contract.name} - Exception: {e}{Colors.ENDC}")

        print()

    def _print_summary(self) -> None:
        """Print analysis summary"""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()

        successful = sum(1 for r in self.results if r['success'])
        failed = len(self.results) - successful
        total_findings = sum(r.get('finding_count', 0) for r in self.results if r['success'])

        print(f"{Colors.BOLD}{Colors.YELLOW}═══════════════════════════════════════════════════════════════{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.YELLOW}                        ANALYSIS SUMMARY                       {Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.YELLOW}═══════════════════════════════════════════════════════════════{Colors.ENDC}\n")

        print(f"{Colors.CYAN}Contracts Analyzed:{Colors.ENDC}")
        print(f"  • Total: {len(self.results)}")
        print(f"  • {Colors.GREEN}Successful: {successful}{Colors.ENDC}")
        print(f"  • {Colors.RED}Failed: {failed}{Colors.ENDC}")
        print()

        print(f"{Colors.CYAN}Security Findings:{Colors.ENDC}")
        print(f"  • Total findings: {total_findings}")
        if successful > 0:
            print(f"  • Average per contract: {total_findings/successful:.1f}")
        print()

        print(f"{Colors.CYAN}Performance:{Colors.ENDC}")
        print(f"  • Total duration: {duration:.2f}s")
        if len(self.results) > 0:
            print(f"  • Average per contract: {duration/len(self.results):.2f}s")
        print()

        # Show top vulnerable contracts
        if successful > 0:
            print(f"{Colors.CYAN}Top Vulnerable Contracts:{Colors.ENDC}")
            sorted_results = sorted(
                [r for r in self.results if r['success']],
                key=lambda x: x.get('finding_count', 0),
                reverse=True
            )[:5]

            for r in sorted_results:
                count = r.get('finding_count', 0)
                name = r['name']
                if count > 0:
                    print(f"  • {name}: {Colors.RED}{count} findings{Colors.ENDC}")

        print()

    def export_results(self, output_path: str) -> None:
        """Export results to JSON file"""
        export_data = {
            'metadata': {
                'tool': self.tool,
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'total_contracts': len(self.results),
                'successful': sum(1 for r in self.results if r['success']),
                'total_findings': sum(r.get('finding_count', 0) for r in self.results if r['success'])
            },
            'results': self.results
        }

        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2)

        print(f"{Colors.GREEN}✓ Results exported to: {output_path}{Colors.ENDC}")


def main():
    parser = argparse.ArgumentParser(
        description='MIESC Batch Analysis - Analyze single contracts or entire directories',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a single contract
  python batch_analysis.py contract.sol

  # Analyze all contracts in a directory
  python batch_analysis.py test_contracts/

  # Use Aderyn instead of Slither
  python batch_analysis.py test_contracts/ --tool aderyn

  # Run with 4 parallel workers
  python batch_analysis.py test_contracts/ --parallel 4

  # Export results to JSON
  python batch_analysis.py test_contracts/ --export results.json

  # Verbose output
  python batch_analysis.py test_contracts/ --verbose

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
UNDEF - IUA Córdoba | Maestría en Ciberdefensa
        """
    )

    parser.add_argument(
        'path',
        help='Contract file (.sol) or directory containing contracts'
    )

    parser.add_argument(
        '--tool',
        choices=['slither', 'aderyn', 'miesc'],
        default='slither',
        help='Analysis tool to use (default: slither)'
    )

    parser.add_argument(
        '--parallel',
        type=int,
        default=1,
        help='Number of parallel workers (default: 1)'
    )

    parser.add_argument(
        '--export',
        metavar='FILE',
        help='Export results to JSON file'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose output'
    )

    args = parser.parse_args()

    # Create analyzer
    analyzer = BatchAnalyzer(
        tool=args.tool,
        parallel=args.parallel,
        verbose=args.verbose
    )

    # Find contracts
    contracts = analyzer.find_contracts(args.path)

    if not contracts:
        print(f"{Colors.YELLOW}⚠ No Solidity contracts found in: {args.path}{Colors.ENDC}")
        sys.exit(0)

    # Run batch analysis
    analyzer.run_batch(contracts)

    # Export if requested
    if args.export:
        analyzer.export_results(args.export)


if __name__ == '__main__':
    main()
