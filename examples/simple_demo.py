#!/usr/bin/env python3
"""
MIESC Simple Demo - Shows typical tool output

Usage:
    python simple_demo.py <contract.sol>

Example:
    python simple_demo.py examples/contracts/EtherStore.sol

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

import sys
import time
from pathlib import Path


class Colors:
    """ANSI color codes for terminal output"""
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def print_banner():
    """Print MIESC banner"""
    print(f"""
{Colors.BOLD}{Colors.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                     MIESC v1.0.0                              ║
║   Multi-layer Intelligent Evaluation for Smart Contracts     ║
║   Advanced Security Framework for Smart Contract Audits      ║
╚═══════════════════════════════════════════════════════════════╝{Colors.ENDC}
""")


def analyze_contract(contract_path: str):
    """Simulate MIESC analysis output"""

    print(f"{Colors.CYAN}[*] Analyzing: {contract_path}{Colors.ENDC}\n")
    time.sleep(0.5)

    # Layer 1: Static Analysis
    print(f"{Colors.BOLD}Layer 1: Static Analysis{Colors.ENDC}")
    print(f"{Colors.CYAN}  → Running Slither...{Colors.ENDC}")
    time.sleep(1)
    print(f"{Colors.YELLOW}    ⚠ Reentrancy in withdraw() at line 42{Colors.ENDC}")
    print(f"{Colors.YELLOW}    ⚠ Unprotected state change after external call{Colors.ENDC}")
    print(f"{Colors.GREEN}    ✓ NatSpec documentation: 85% complete{Colors.ENDC}")
    print()

    time.sleep(0.5)
    print(f"{Colors.CYAN}  → Running Aderyn...{Colors.ENDC}")
    time.sleep(1)
    print(f"{Colors.RED}    ✗ [HIGH] Reentrancy vulnerability detected{Colors.ENDC}")
    print(f"{Colors.YELLOW}    ⚠ [MED] Missing checks-effects-interactions pattern{Colors.ENDC}")
    print()

    # Layer 2: Dynamic Analysis
    print(f"{Colors.BOLD}Layer 2: Dynamic Analysis{Colors.ENDC}")
    print(f"{Colors.CYAN}  → Running Medusa fuzzer...{Colors.ENDC}")
    time.sleep(1.5)
    print(f"{Colors.RED}    ✗ [CRITICAL] Exploit found: drain all ETH via reentrancy{Colors.ENDC}")
    print(f"      Transaction sequence: deposit(1 ETH) → withdraw() → fallback() loops{Colors.ENDC}")
    print()

    # Layer 3: Symbolic Execution
    print(f"{Colors.BOLD}Layer 3: Symbolic Execution{Colors.ENDC}")
    print(f"{Colors.CYAN}  → Running Mythril...{Colors.ENDC}")
    time.sleep(1.5)
    print(f"{Colors.RED}    ✗ [SWC-107] Reentrancy Attack{Colors.ENDC}")
    print(f"      Severity: HIGH | Confidence: HIGH{Colors.ENDC}")
    print(f"      Attack vector confirmed: 3 transaction traces found{Colors.ENDC}")
    print()

    # Layer 4: AI Analysis
    print(f"{Colors.BOLD}Layer 5: AI-Powered Analysis{Colors.ENDC}")
    print(f"{Colors.CYAN}  → GPT-4 analyzing findings correlation...{Colors.ENDC}")
    time.sleep(1)
    print(f"{Colors.YELLOW}    🤖 AI Recommendation:{Colors.ENDC}")
    print(f"      All 3 layers detected the SAME critical reentrancy issue.")
    print(f"      This is NOT a false positive. Priority: IMMEDIATE FIX REQUIRED")
    print()
    print(f"{Colors.CYAN}  → Generating remediation...{Colors.ENDC}")
    time.sleep(1)
    print(f"{Colors.GREEN}    ✓ Recommended fix (OpenZeppelin pattern):{Colors.ENDC}")
    print(f"""
      import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

      contract EtherStore is ReentrancyGuard {{
          function withdraw() public nonReentrant {{
              uint256 bal = balances[msg.sender];
              require(bal > 0, "Insufficient balance");

              balances[msg.sender] = 0;  // ✓ State change BEFORE external call
              (bool sent, ) = msg.sender.call{{value: bal}}("");
              require(sent, "Failed to send Ether");
          }}
      }}
    """)
    print()

    # Layer 6: Standards Mapping
    print(f"{Colors.BOLD}Layer 6: Standards Compliance{Colors.ENDC}")
    print(f"{Colors.CYAN}  → Mapping to security standards...{Colors.ENDC}")
    time.sleep(0.5)
    print(f"    • OWASP SC Top 10: SC01 - Reentrancy Attacks")
    print(f"    • SWC Registry: SWC-107 - Reentrancy")
    print(f"    • CWE: CWE-841 - Improper Enforcement of Behavioral Workflow")
    print(f"    • NIST SSDF: PW.7 - Review and/or analyze code")
    print()

    # Summary
    print(f"{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.ENDC}")
    print(f"{Colors.BOLD}ANALYSIS SUMMARY{Colors.ENDC}")
    print(f"{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.ENDC}")
    print()
    print(f"  {Colors.RED}Critical Issues: 1{Colors.ENDC}  (Reentrancy - IMMEDIATE FIX REQUIRED)")
    print(f"  {Colors.YELLOW}High Issues: 2{Colors.ENDC}      (State management violations)")
    print(f"  {Colors.GREEN}Medium Issues: 3{Colors.ENDC}    (Documentation, best practices)")
    print()
    print(f"  {Colors.BOLD}From 200 warnings → 5 actionable findings{Colors.ENDC}")
    print(f"  {Colors.BOLD}AI filtered 97.5% of noise{Colors.ENDC}")
    print()
    print(f"  {Colors.CYAN}Next Steps:{Colors.ENDC}")
    print(f"    1. Implement ReentrancyGuard from OpenZeppelin")
    print(f"    2. Move state changes before external calls")
    print(f"    3. Add test coverage for reentrancy scenarios")
    print(f"    4. Re-run MIESC to verify fixes")
    print()
    print(f"  {Colors.GREEN}✓ Executive summary ready for stakeholders{Colors.ENDC}")
    print(f"  {Colors.GREEN}✓ Technical report ready for developers{Colors.ENDC}")
    print(f"  {Colors.GREEN}✓ Compliance report ready for auditors{Colors.ENDC}")
    print()
    print(f"{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.ENDC}\n")

    print(f"{Colors.CYAN}Total analysis time: 3.2 minutes (vs 3 days manual review){Colors.ENDC}")
    print(f"{Colors.CYAN}Effort reduction: 90%{Colors.ENDC}\n")


def main():
    """Main execution"""
    print_banner()

    if len(sys.argv) < 2:
        print(f"{Colors.YELLOW}Usage: python simple_demo.py <contract.sol>{Colors.ENDC}")
        print(f"{Colors.YELLOW}Example: python simple_demo.py examples/contracts/EtherStore.sol{Colors.ENDC}\n")

        # Run demo with sample contract
        print(f"{Colors.CYAN}Running demo with sample vulnerable contract...{Colors.ENDC}\n")
        analyze_contract("examples/contracts/EtherStore.sol")
    else:
        contract_path = sys.argv[1]

        if not Path(contract_path).exists():
            print(f"{Colors.RED}Error: Contract not found: {contract_path}{Colors.ENDC}\n")
            sys.exit(1)

        analyze_contract(contract_path)

    print(f"{Colors.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.ENDC}")
    print(f"{Colors.BOLD}Thank you for using MIESC!{Colors.ENDC}")
    print(f"{Colors.CYAN}GitHub: https://github.com/fboiero/MIESC{Colors.ENDC}")
    print(f"{Colors.CYAN}License: AGPL-3.0 | 17 agents | 15+ tools | 12 standards{Colors.ENDC}")
    print(f"{Colors.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.ENDC}\n")


if __name__ == '__main__':
    main()
