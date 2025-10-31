#!/usr/bin/env python3
"""
MIESC Hacker-Style Batch Demo
Execute full multi-agent analysis (like hacker_demo.py) on multiple contracts

This script runs the complete MIESC demonstration with all 17 agents
on every contract in a directory, providing hacker-style visual output.

Usage:
    python hacker_batch_demo.py test_contracts/not-so-smart-contracts/reentrancy/
    python hacker_batch_demo.py vulnerable_contracts/
    python hacker_batch_demo.py contract.sol  # Single contract
    python hacker_batch_demo.py test_contracts/ --export results.json

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
UNDEF - IUA Córdoba | Maestría en Ciberdefensa
"""

import sys
import os
import time
import json
import argparse
import subprocess
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

class Colors:
    """ANSI color codes"""
    BRIGHT_GREEN = '\033[92m\033[1m'
    BRIGHT_RED = '\033[91m\033[1m'
    BRIGHT_CYAN = '\033[96m\033[1m'
    BRIGHT_YELLOW = '\033[93m\033[1m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    MAGENTA = '\033[95m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ENDC = '\033[0m'

BATCH_BANNER = """
███╗   ███╗██╗███████╗███████╗ ██████╗
████╗ ████║██║██╔════╝██╔════╝██╔════╝
██╔████╔██║██║█████╗  ███████╗██║
██║╚██╔╝██║██║██╔══╝  ╚════██║██║
██║ ╚═╝ ██║██║███████╗███████║╚██████╗
╚═╝     ╚═╝╚═╝╚══════╝╚══════╝ ╚═════╝

    ██████╗  █████╗ ████████╗ ██████╗██╗  ██╗
    ██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██║  ██║
    ██████╔╝███████║   ██║   ██║     ███████║
    ██╔══██╗██╔══██║   ██║   ██║     ██╔══██║
    ██████╔╝██║  ██║   ██║   ╚██████╗██║  ██║
    ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝

      MULTI-AGENT BATCH ANALYSIS SYSTEM
         17 Agents × N Contracts
"""

def print_banner():
    """Print hacker-style batch banner"""
    print(f"{Colors.BRIGHT_CYAN}{BATCH_BANNER}{Colors.ENDC}")
    time.sleep(0.5)

def typing_print(text: str, delay: float = 0.02, color: str = Colors.ENDC):
    """Print with typing effect"""
    for char in text:
        sys.stdout.write(color + char + Colors.ENDC)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def print_section(title: str):
    """Print section header"""
    print(f"\n{Colors.BRIGHT_YELLOW}{'═' * 70}{Colors.ENDC}")
    print(f"{Colors.BRIGHT_YELLOW}{title:^70}{Colors.ENDC}")
    print(f"{Colors.BRIGHT_YELLOW}{'═' * 70}{Colors.ENDC}\n")

def find_contracts(path: str) -> List[Path]:
    """Find all Solidity contracts"""
    path_obj = Path(path)
    
    if not path_obj.exists():
        print(f"{Colors.RED}✗ Path not found: {path}{Colors.ENDC}")
        sys.exit(1)
    
    if path_obj.is_file():
        return [path_obj] if path_obj.suffix == '.sol' else []
    
    contracts = list(path_obj.rglob('*.sol'))
    return sorted(contracts)

def run_hacker_demo_on_contract(contract_path: Path, script_path: str) -> Dict[str, Any]:
    """Run hacker_demo.py on a single contract"""
    result = {
        'contract': str(contract_path),
        'name': contract_path.name,
        'start_time': datetime.now().isoformat(),
        'success': False,
        'vulnerabilities': 0,
        'duration': 0,
        'error': None
    }
    
    start_time = time.time()
    
    try:
        # Run hacker_demo.py with the contract
        cmd = ['python3', script_path, str(contract_path)]
        
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout per contract
        )
        
        result['duration'] = time.time() - start_time
        result['exit_code'] = proc.returncode
        result['success'] = (proc.returncode == 0)
        
        # Try to extract vulnerability count from output
        if 'Total Vulnerabilities:' in proc.stdout:
            for line in proc.stdout.split('\n'):
                if 'Total Vulnerabilities:' in line:
                    try:
                        result['vulnerabilities'] = int(line.split(':')[-1].strip())
                    except:
                        pass
        
    except subprocess.TimeoutExpired:
        result['error'] = "Analysis timeout (5 minutes)"
        result['duration'] = time.time() - start_time
    except Exception as e:
        result['error'] = str(e)
        result['duration'] = time.time() - start_time
    
    return result

def print_contract_header(index: int, total: int, contract: Path):
    """Print header for each contract"""
    print(f"\n{Colors.BRIGHT_CYAN}{'─' * 70}{Colors.ENDC}")
    print(f"{Colors.BRIGHT_CYAN}[{index}/{total}] TARGET: {contract.name}{Colors.ENDC}")
    print(f"{Colors.DIM}     Path: {contract}{Colors.ENDC}")
    print(f"{Colors.BRIGHT_CYAN}{'─' * 70}{Colors.ENDC}")

def print_contract_result(result: Dict[str, Any]):
    """Print result for each contract"""
    if result['success']:
        vuln_count = result['vulnerabilities']
        duration = result['duration']
        
        if vuln_count > 10:
            icon = f"{Colors.BRIGHT_RED}⚠ CRITICAL{Colors.ENDC}"
        elif vuln_count > 5:
            icon = f"{Colors.RED}⚠ HIGH{Colors.ENDC}"
        elif vuln_count > 0:
            icon = f"{Colors.YELLOW}⚠ MEDIUM{Colors.ENDC}"
        else:
            icon = f"{Colors.GREEN}✓ CLEAN{Colors.ENDC}"
        
        print(f"\n{icon} {Colors.BOLD}{result['name']}{Colors.ENDC}")
        print(f"   Vulnerabilities: {vuln_count}")
        print(f"   Duration: {duration:.2f}s")
    else:
        print(f"\n{Colors.RED}✗ FAILED: {result['name']}{Colors.ENDC}")
        if result['error']:
            print(f"   Error: {result['error']}")

def print_summary(results: List[Dict[str, Any]], total_time: float):
    """Print final summary"""
    print_section("BATCH ANALYSIS COMPLETE")
    
    total = len(results)
    successful = sum(1 for r in results if r['success'])
    failed = total - successful
    total_vulns = sum(r.get('vulnerabilities', 0) for r in results if r['success'])
    
    print(f"{Colors.BRIGHT_GREEN}═══════════════════════════════════════════════════════════════════{Colors.ENDC}")
    print(f"{Colors.BRIGHT_GREEN}                       FINAL STATISTICS                             {Colors.ENDC}")
    print(f"{Colors.BRIGHT_GREEN}═══════════════════════════════════════════════════════════════════{Colors.ENDC}\n")
    
    print(f"{Colors.CYAN}Contracts Analyzed:{Colors.ENDC}")
    print(f"  • Total:      {total}")
    print(f"  • {Colors.GREEN}Successful: {successful}{Colors.ENDC}")
    print(f"  • {Colors.RED}Failed:     {failed}{Colors.ENDC}")
    print()
    
    print(f"{Colors.CYAN}Vulnerability Summary:{Colors.ENDC}")
    print(f"  • Total vulnerabilities found: {Colors.BRIGHT_RED}{total_vulns}{Colors.ENDC}")
    if successful > 0:
        print(f"  • Average per contract: {total_vulns/successful:.1f}")
    print()
    
    print(f"{Colors.CYAN}Performance:{Colors.ENDC}")
    print(f"  • Total analysis time: {total_time:.2f}s ({total_time/60:.1f} minutes)")
    if total > 0:
        print(f"  • Average per contract: {total_time/total:.2f}s")
    print()
    
    # Top vulnerable contracts
    if successful > 0:
        print(f"{Colors.CYAN}Top Vulnerable Contracts:{Colors.ENDC}")
        sorted_results = sorted(
            [r for r in results if r['success']],
            key=lambda x: x.get('vulnerabilities', 0),
            reverse=True
        )[:10]
        
        for i, r in enumerate(sorted_results, 1):
            vuln_count = r.get('vulnerabilities', 0)
            if vuln_count > 0:
                severity = "CRITICAL" if vuln_count > 10 else "HIGH" if vuln_count > 5 else "MEDIUM"
                color = Colors.BRIGHT_RED if vuln_count > 10 else Colors.RED if vuln_count > 5 else Colors.YELLOW
                print(f"  {i:2d}. {r['name']:30s} {color}{vuln_count:3d} ({severity}){Colors.ENDC}")
    
    print(f"\n{Colors.BRIGHT_GREEN}═══════════════════════════════════════════════════════════════════{Colors.ENDC}")
    print(f"{Colors.BRIGHT_GREEN}Analysis complete! All contracts processed with full agent suite.{Colors.ENDC}")
    print(f"{Colors.BRIGHT_GREEN}═══════════════════════════════════════════════════════════════════{Colors.ENDC}\n")

def main():
    parser = argparse.ArgumentParser(
        description='MIESC Hacker-Style Batch Demo - Full multi-agent analysis on multiple contracts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze all contracts in a directory
  python hacker_batch_demo.py test_contracts/not-so-smart-contracts/reentrancy/
  
  # Analyze a single contract
  python hacker_batch_demo.py contract.sol
  
  # Export results
  python hacker_batch_demo.py test_contracts/ --export results.json

This script runs the complete hacker_demo.py (all 17 agents, full visual output)
on every contract found in the specified path.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
UNDEF - IUA Córdoba | Maestría en Ciberdefensa
        """
    )
    
    parser.add_argument(
        'path',
        help='Contract file (.sol) or directory containing contracts'
    )
    
    parser.add_argument(
        '--export',
        metavar='FILE',
        help='Export results to JSON file'
    )
    
    parser.add_argument(
        '--hacker-demo',
        default='docs/examples/demo/hacker_demo.py',
        help='Path to hacker_demo.py script (default: docs/examples/demo/hacker_demo.py)'
    )
    
    args = parser.parse_args()
    
    # Check if hacker_demo.py exists
    if not Path(args.hacker_demo).exists():
        print(f"{Colors.RED}✗ hacker_demo.py not found at: {args.hacker_demo}{Colors.ENDC}")
        print(f"{Colors.YELLOW}  Make sure you're running from the MIESC root directory{Colors.ENDC}")
        sys.exit(1)
    
    # Print banner
    print_banner()
    time.sleep(1)
    
    # Find contracts
    print_section("SCANNING FOR CONTRACTS")
    typing_print(f"{Colors.CYAN}[*] Scanning directory: {args.path}{Colors.ENDC}", 0.02)
    contracts = find_contracts(args.path)
    
    if not contracts:
        print(f"{Colors.RED}✗ No Solidity contracts found in: {args.path}{Colors.ENDC}")
        sys.exit(1)
    
    print(f"{Colors.GREEN}✓ Found {len(contracts)} contracts{Colors.ENDC}")
    time.sleep(1)
    
    # Show what will be analyzed
    print_section("MULTI-AGENT ANALYSIS PLAN")
    print(f"{Colors.CYAN}Each contract will be analyzed with:{Colors.ENDC}")
    print(f"  • {Colors.BOLD}17 specialized security agents{Colors.ENDC}")
    print(f"  • {Colors.BOLD}6 analysis layers{Colors.ENDC} (static, dynamic, symbolic, formal, AI, policy)")
    print(f"  • {Colors.BOLD}15+ security tools{Colors.ENDC} (Slither, Mythril, Echidna, Manticore, GPT-4, etc.)")
    print(f"  • {Colors.BOLD}Full visual output{Colors.ENDC} with agent initialization and execution logs")
    print()
    print(f"{Colors.YELLOW}⚠ This will take approximately {len(contracts) * 2:.0f}-{len(contracts) * 5:.0f} minutes{Colors.ENDC}")
    print(f"{Colors.DIM}  (Estimate: 2-5 minutes per contract){Colors.ENDC}")
    time.sleep(2)
    
    # Start batch analysis
    print_section("STARTING BATCH ANALYSIS")
    batch_start_time = time.time()
    results = []
    
    for i, contract in enumerate(contracts, 1):
        print_contract_header(i, len(contracts), contract)
        
        typing_print(f"{Colors.CYAN}[*] Initializing multi-agent system...{Colors.ENDC}", 0.01)
        typing_print(f"{Colors.CYAN}[*] Loading 17 specialized agents...{Colors.ENDC}", 0.01)
        typing_print(f"{Colors.GREEN}[✓] Ready to analyze: {contract.name}{Colors.ENDC}", 0.01)
        print()
        
        # Run analysis
        result = run_hacker_demo_on_contract(contract, args.hacker_demo)
        results.append(result)
        
        # Print result
        print_contract_result(result)
        time.sleep(0.5)
    
    batch_total_time = time.time() - batch_start_time
    
    # Print summary
    print_summary(results, batch_total_time)
    
    # Export if requested
    if args.export:
        export_data = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_contracts': len(results),
                'successful': sum(1 for r in results if r['success']),
                'failed': sum(1 for r in results if not r['success']),
                'total_vulnerabilities': sum(r.get('vulnerabilities', 0) for r in results if r['success']),
                'total_duration': batch_total_time,
                'analysis_type': 'full_multi_agent_batch'
            },
            'results': results
        }
        
        with open(args.export, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"{Colors.GREEN}✓ Results exported to: {args.export}{Colors.ENDC}\n")
    
    print(f"{Colors.CYAN}{'═' * 70}{Colors.ENDC}")
    print(f"{Colors.CYAN}Thank you for using MIESC Batch Analysis System!{Colors.ENDC}")
    print(f"{Colors.DIM}For more information: https://github.com/fboiero/MIESC{Colors.ENDC}")
    print(f"{Colors.CYAN}{'═' * 70}{Colors.ENDC}\n")

if __name__ == '__main__':
    main()
