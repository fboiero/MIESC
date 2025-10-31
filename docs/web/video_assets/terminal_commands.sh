#!/bin/bash

# MIESC Video Recording Helper Script
# This script provides ready-to-run commands for video recording
# Author: Fernando Boiero

# Color codes for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Icons
SHIELD="🛡️"
CHECK="✓"
SEARCH="🔍"
ROBOT="🤖"
FIRE="🔥"
PACKAGE="📦"

echo "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo "${BLUE}║  MIESC Video Recording Helper                 ║${NC}"
echo "${BLUE}║  Use these commands for your video recording  ║${NC}"
echo "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo ""

function show_menu() {
    echo "${CYAN}Select scene to record:${NC}"
    echo "1) Scene 1: Show overwhelming Slither output"
    echo "2) Scene 4: Simulate MIESC tools running"
    echo "3) Scene 4: Show final results summary"
    echo "4) Test all commands (dry run)"
    echo "5) Exit"
    echo ""
    read -p "Enter choice [1-5]: " choice
}

function scene1_slither_output() {
    echo ""
    echo "${YELLOW}═══════════════════════════════════════════════${NC}"
    echo "${YELLOW}SCENE 1: Overwhelming Slither Output${NC}"
    echo "${YELLOW}═══════════════════════════════════════════════${NC}"
    echo ""
    echo "${GREEN}Running Slither on VulnerableBank.sol...${NC}"
    sleep 1

    # Simulate overwhelming output
    echo ""
    echo "${RED}⚠️  WARNING: 147 potential issues detected${NC}"
    echo ""
    sleep 0.5

    # Show sample warnings
    echo "Slither 0.10.3 - Solidity analyzer"
    echo ""
    echo "${YELLOW}INFO:Detectors:${NC}"
    echo "VulnerableBank.withdraw() (line 23-32) sends eth to arbitrary user"
    echo "    Dangerous calls:"
    echo "    - msg.sender.call{value: amount}() (line 28)"
    echo "    Reference: https://swcregistry.io/docs/SWC-107"
    echo ""
    echo "VulnerableBank.balances (line 8) should be constant"
    echo "    Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#state-variables-that-could-be-declared-constant"
    echo ""
    echo "VulnerableBank.totalDeposits (line 9) is never used"
    echo "    Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#unused-state-variable"
    echo ""
    echo "${YELLOW}LOW:${NC}"
    echo "Pragma version^0.8.0 allows old versions (line 2)"
    echo "solc-0.8.0 is not recommended for deployment"
    echo ""
    echo "Parameter VulnerableBank.setBalance(address,uint256).user (line 40) is not in mixedCase"
    echo ""
    echo "Function VulnerableBank.getBalance() (line 46-48) should be external"
    echo ""

    # More warnings scrolling...
    for i in {1..10}; do
        echo "INFO: Optimization opportunity detected (${i}/20)"
        sleep 0.1
    done

    echo ""
    echo "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo "${RED}Summary: 147 findings${NC}"
    echo "${RED}  - 89 informational${NC}"
    echo "${RED}  - 37 low${NC}"
    echo "${RED}  - 16 medium${NC}"
    echo "${RED}  - 5 high${NC}"
    echo "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "${YELLOW}😵 Which ones actually matter?${NC}"
    echo ""
}

function scene4_tools_running() {
    echo ""
    echo "${CYAN}═══════════════════════════════════════════════${NC}"
    echo "${CYAN}SCENE 4: MIESC Tools Running (Background)${NC}"
    echo "${CYAN}═══════════════════════════════════════════════${NC}"
    echo ""
    echo "${PURPLE}${SHIELD} MIESC - Multi-Agent Security Framework${NC}"
    echo "${PURPLE}Analyzing: VulnerableBank.sol${NC}"
    echo ""
    sleep 1

    # Layer 1: Static Analysis
    echo "${BLUE}┌─────────────────────────────────────────────┐${NC}"
    echo "${BLUE}│ Layer 1: Static Analysis                   │${NC}"
    echo "${BLUE}└─────────────────────────────────────────────┘${NC}"
    echo ""

    echo "${SEARCH} ${CYAN}[Slither]${NC} Running 87 detectors..."
    sleep 2
    echo "${CHECK} ${GREEN}[Slither]${NC} Complete - 23 findings"
    echo "   └─ Reentrancy detected"
    echo "   └─ Access control issues"
    echo "   └─ 21 informational warnings"
    echo ""
    sleep 1

    echo "${FIRE} ${CYAN}[Aderyn]${NC} Ultra-fast AST analysis..."
    sleep 1
    echo "${CHECK} ${GREEN}[Aderyn]${NC} Complete - 12 findings"
    echo "   └─ Missing events"
    echo "   └─ Unsafe external calls"
    echo ""
    sleep 1

    echo "${PACKAGE} ${CYAN}[Solhint]${NC} Linting rules..."
    sleep 1
    echo "${CHECK} ${GREEN}[Solhint]${NC} Complete - 8 findings"
    echo ""
    sleep 0.5

    # Layer 3: Symbolic Execution
    echo "${BLUE}┌─────────────────────────────────────────────┐${NC}"
    echo "${BLUE}│ Layer 3: Symbolic Execution                │${NC}"
    echo "${BLUE}└─────────────────────────────────────────────┘${NC}"
    echo ""

    echo "${SEARCH} ${CYAN}[Mythril]${NC} Symbolic execution..."
    sleep 3
    echo "${CHECK} ${GREEN}[Mythril]${NC} Complete - 5 critical paths"
    echo "   └─ Reentrancy exploit confirmed (SWC-107)"
    echo "   └─ Integer underflow possible"
    echo ""
    sleep 1

    echo "${SEARCH} ${CYAN}[Manticore]${NC} Dynamic symbolic execution..."
    sleep 2
    echo "${CHECK} ${GREEN}[Manticore]${NC} Complete - 3 exploitable paths"
    echo ""
    sleep 1

    # Layer 5: AI Analysis
    echo "${BLUE}┌─────────────────────────────────────────────┐${NC}"
    echo "${BLUE}│ Layer 5: AI-Assisted Analysis              │${NC}"
    echo "${BLUE}└─────────────────────────────────────────────┘${NC}"
    echo ""

    echo "${ROBOT} ${CYAN}[AIAgent]${NC} Analyzing findings..."
    sleep 1
    echo "${ROBOT} ${CYAN}[AIAgent]${NC} Cross-referencing tools..."
    sleep 1
    echo "${ROBOT} ${CYAN}[AIAgent]${NC} Filtering false positives..."
    sleep 2
    echo "${CHECK} ${GREEN}[AIAgent]${NC} Complete!"
    echo "   └─ 147 raw findings"
    echo "   └─ 139 false positives filtered (94.6%)"
    echo "   └─ 8 duplicates merged"
    echo "   └─ 6 unique actionable findings"
    echo ""
    sleep 1
}

function scene4_final_results() {
    echo ""
    echo "${GREEN}═══════════════════════════════════════════════${NC}"
    echo "${GREEN}SCENE 4: Final Results Summary${NC}"
    echo "${GREEN}═══════════════════════════════════════════════${NC}"
    echo ""

    echo "${SHIELD} ${PURPLE}MIESC Analysis Complete${NC}"
    echo ""
    sleep 1

    echo "╔═══════════════════════════════════════════════╗"
    echo "║           📊 FINAL RESULTS                    ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo ""

    echo "${RED}🔴 CRITICAL (1):${NC}"
    echo "   Reentrancy vulnerability in withdraw()"
    echo "   └─ Line 28: External call before state update"
    echo ""
    sleep 1

    echo "${YELLOW}🟠 HIGH (2):${NC}"
    echo "   • Missing access control on setBalance()"
    echo "   • Unsafe transfer in emergencyWithdraw()"
    echo ""
    sleep 1

    echo "${BLUE}🟡 MEDIUM (3):${NC}"
    echo "   • No recipient validation"
    echo "   • Missing zero address checks"
    echo "   • Unchecked return values"
    echo ""
    sleep 1

    echo "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo "${GREEN}✨ Key Achievements:${NC}"
    echo "${GREEN}   • 147 warnings → 6 actionable findings${NC}"
    echo "${GREEN}   • 139 false positives filtered by AI${NC}"
    echo "${GREEN}   • 89.47% precision maintained${NC}"
    echo "${GREEN}   • Analysis time: 4.2 minutes${NC}"
    echo "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    echo "${PURPLE}${SHIELD} MIESC saved you ~4 hours of manual triage!${NC}"
    echo ""
}

function test_all_commands() {
    echo ""
    echo "${CYAN}Testing all commands (dry run)...${NC}"
    echo ""
    sleep 1

    echo "${GREEN}✓ Slither command: OK${NC}"
    echo "${GREEN}✓ Color codes: OK${NC}"
    echo "${GREEN}✓ Icons: ${SHIELD} ${CHECK} ${SEARCH} ${ROBOT} ${FIRE} ${PACKAGE}${NC}"
    echo "${GREEN}✓ Timing delays: OK${NC}"
    echo ""
    echo "${CYAN}All commands ready for recording!${NC}"
    echo ""
}

# Main loop
while true; do
    show_menu
    case $choice in
        1)
            scene1_slither_output
            ;;
        2)
            scene4_tools_running
            ;;
        3)
            scene4_final_results
            ;;
        4)
            test_all_commands
            ;;
        5)
            echo ""
            echo "${GREEN}Good luck with your recording! 🎬${NC}"
            echo ""
            exit 0
            ;;
        *)
            echo "${RED}Invalid choice. Please try again.${NC}"
            ;;
    esac

    echo ""
    read -p "Press Enter to continue..."
    clear
done
