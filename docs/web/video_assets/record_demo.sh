#!/bin/bash

################################################################################
# MIESC Complete Demo Script - For Video Recording
# This script simulates a complete MIESC analysis for recording purposes
#
# Usage: ./record_demo.sh [fast|slow]
#   fast - Quick demo (30 seconds)
#   slow - Full demo with pauses (90 seconds) - RECOMMENDED FOR RECORDING
#
# Author: Fernando Boiero
# Project: MIESC - Multi-Agent Security Framework
################################################################################

# Configuration
SPEED="${1:-slow}"  # Default to slow for better recording
CONTRACT_PATH="examples/demo_vulnerable.sol"

# Speed settings
if [ "$SPEED" = "fast" ]; then
    DELAY_SHORT=0.3
    DELAY_MEDIUM=0.8
    DELAY_LONG=1.5
else
    DELAY_SHORT=0.8
    DELAY_MEDIUM=1.5
    DELAY_LONG=3.0
fi

# Color codes
RESET='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# Colors
BLACK='\033[0;30m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'

# Bright colors
BRIGHT_RED='\033[1;31m'
BRIGHT_GREEN='\033[1;32m'
BRIGHT_YELLOW='\033[1;33m'
BRIGHT_BLUE='\033[1;34m'
BRIGHT_PURPLE='\033[1;35m'
BRIGHT_CYAN='\033[1;36m'
BRIGHT_WHITE='\033[1;37m'

# Background colors
BG_RED='\033[41m'
BG_GREEN='\033[42m'
BG_YELLOW='\033[43m'
BG_BLUE='\033[44m'

# Icons (works on macOS terminal)
SHIELD="🛡️"
FIRE="🔥"
SEARCH="🔍"
ROBOT="🤖"
CHECK="✓"
CROSS="✗"
ARROW="→"
PACKAGE="📦"
LIGHTNING="⚡"
CHART="📊"
WARNING="⚠️"
CRITICAL="🔴"
HIGH="🟠"
MEDIUM="🟡"
LOW="🟢"
INFO="ℹ️"

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo ""
    echo -e "${BRIGHT_CYAN}╔════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BRIGHT_CYAN}║${RESET}  $1"
    echo -e "${BRIGHT_CYAN}╚════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${BRIGHT_BLUE}┌────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${BRIGHT_BLUE}│${RESET} $1"
    echo -e "${BRIGHT_BLUE}└────────────────────────────────────────────────────────┘${RESET}"
    echo ""
}

print_step() {
    echo -e "${CYAN}${ARROW}${RESET} $1"
}

print_success() {
    echo -e "${GREEN}${CHECK}${RESET} $1"
}

print_error() {
    echo -e "${RED}${CROSS}${RESET} $1"
}

print_warning() {
    echo -e "${YELLOW}${WARNING}${RESET}  $1"
}

print_info() {
    echo -e "${BLUE}${INFO}${RESET}  $1"
}

typing_effect() {
    local text="$1"
    local delay="${2:-0.05}"

    for (( i=0; i<${#text}; i++ )); do
        echo -n "${text:$i:1}"
        sleep "$delay"
    done
    echo ""
}

progress_bar() {
    local duration=$1
    local steps=20
    local step_duration=$(echo "scale=2; $duration / $steps" | bc)

    echo -n "["
    for i in $(seq 1 $steps); do
        echo -n "="
        sleep "$step_duration"
    done
    echo "]"
}

simulate_tool_output() {
    local tool_name="$1"
    local icon="$2"
    local color="$3"
    local finding_count="$4"
    local duration="$5"

    echo -e "${color}${icon} [${tool_name}]${RESET} ${DIM}Running...${RESET}"
    sleep "$duration"
    echo -e "${GREEN}${CHECK} [${tool_name}]${RESET} Complete - ${BOLD}${finding_count}${RESET} findings"
}

################################################################################
# Main Demo Script
################################################################################

clear

# Welcome banner
print_header "${SHIELD}  MIESC - Multi-Agent Security Framework for Smart Contracts"

echo -e "${DIM}Version 2.2.0 | GPL-3.0 License${RESET}"
echo -e "${DIM}Author: Fernando Boiero | UNDEF-IUA${RESET}"
echo ""
sleep "$DELAY_MEDIUM"

# Show the command being run
echo -e "${BRIGHT_WHITE}${BOLD}\$ python xaudit.py --target ${CONTRACT_PATH} --mode standard${RESET}"
sleep "$DELAY_LONG"
echo ""

# Initialize
print_section "${PACKAGE} Initializing MIESC Framework"
sleep "$DELAY_SHORT"

print_step "Loading configuration..."
sleep "$DELAY_SHORT"
print_success "Configuration loaded"

print_step "Validating contract: ${BOLD}${CONTRACT_PATH}${RESET}"
sleep "$DELAY_SHORT"
print_success "Contract validated (120 lines, Solidity 0.8.0)"

print_step "Initializing Context Bus (MCP Protocol)..."
sleep "$DELAY_SHORT"
print_success "Context Bus ready"

echo ""
sleep "$DELAY_MEDIUM"

################################################################################
# LAYER 1: STATIC ANALYSIS
################################################################################

print_section "${LIGHTNING} Layer 1: Static Analysis"
sleep "$DELAY_SHORT"

# Slither
simulate_tool_output "Slither" "${SEARCH}" "${CYAN}" "23" "$DELAY_LONG"
echo -e "   ${DIM}├─ Reentrancy detector: 1 issue${RESET}"
echo -e "   ${DIM}├─ Access control: 2 issues${RESET}"
echo -e "   ${DIM}└─ Low severity: 20 issues${RESET}"
echo ""
sleep "$DELAY_SHORT"

# Aderyn
simulate_tool_output "Aderyn" "${FIRE}" "${BRIGHT_PURPLE}" "12" "$DELAY_MEDIUM"
echo -e "   ${DIM}├─ Missing events: 5 issues${RESET}"
echo -e "   ${DIM}└─ Unsafe calls: 7 issues${RESET}"
echo ""
sleep "$DELAY_SHORT"

# Solhint
simulate_tool_output "Solhint" "${PACKAGE}" "${BLUE}" "8" "$DELAY_SHORT"
echo -e "   ${DIM}└─ Style & naming: 8 issues${RESET}"
echo ""
sleep "$DELAY_MEDIUM"

################################################################################
# LAYER 2: DYNAMIC TESTING
################################################################################

print_section "${FIRE} Layer 2: Dynamic Testing"
sleep "$DELAY_SHORT"

# Echidna
echo -e "${CYAN}${SEARCH} [Echidna]${RESET} ${DIM}Property-based fuzzing...${RESET}"
sleep "$DELAY_LONG"
echo -e "   ${DIM}Running 1000 test cases...${RESET}"
sleep "$DELAY_MEDIUM"
echo -e "${GREEN}${CHECK} [Echidna]${RESET} Complete - ${BOLD}3${RESET} property violations"
echo -e "   ${DIM}└─ Invariant broken: balance consistency${RESET}"
echo ""
sleep "$DELAY_SHORT"

################################################################################
# LAYER 3: SYMBOLIC EXECUTION
################################################################################

print_section "${SEARCH} Layer 3: Symbolic Execution"
sleep "$DELAY_SHORT"

# Mythril
echo -e "${PURPLE}${SEARCH} [Mythril]${RESET} ${DIM}Analyzing execution paths...${RESET}"
sleep "$DELAY_LONG"
echo -e "   ${DIM}Exploring state space...${RESET}"
sleep "$DELAY_LONG"
echo -e "   ${DIM}Found 5 critical paths...${RESET}"
sleep "$DELAY_MEDIUM"
echo -e "${GREEN}${CHECK} [Mythril]${RESET} Complete - ${BOLD}5${RESET} exploitable paths"
echo -e "   ${DIM}├─ ${CRITICAL} Reentrancy exploit confirmed (SWC-107)${RESET}"
echo -e "   ${DIM}└─ ${MEDIUM} Possible integer issues${RESET}"
echo ""
sleep "$DELAY_MEDIUM"

# Manticore
echo -e "${PURPLE}${SEARCH} [Manticore]${RESET} ${DIM}Dynamic symbolic execution...${RESET}"
sleep "$DELAY_LONG"
echo -e "${GREEN}${CHECK} [Manticore]${RESET} Complete - ${BOLD}3${RESET} confirmed exploits"
echo ""
sleep "$DELAY_MEDIUM"

################################################################################
# LAYER 5: AI-ASSISTED ANALYSIS
################################################################################

print_section "${ROBOT} Layer 5: AI-Assisted Analysis"
sleep "$DELAY_SHORT"

echo -e "${BRIGHT_CYAN}${ROBOT} [AIAgent]${RESET} ${DIM}Analyzing findings from all tools...${RESET}"
sleep "$DELAY_LONG"

echo -e "   ${DIM}${ARROW} Cross-referencing 51 findings...${RESET}"
sleep "$DELAY_MEDIUM"

echo -e "   ${DIM}${ARROW} Identifying duplicates...${RESET}"
sleep "$DELAY_MEDIUM"
echo -e "      ${DIM}Found 8 duplicate findings${RESET}"

echo -e "   ${DIM}${ARROW} Filtering false positives with GPT-4...${RESET}"
sleep "$DELAY_LONG"
echo -e "      ${DIM}Filtered 37 false positives (72.5%)${RESET}"

echo -e "   ${DIM}${ARROW} Performing root cause analysis...${RESET}"
sleep "$DELAY_MEDIUM"

echo ""
echo -e "${GREEN}${CHECK} [AIAgent]${RESET} Analysis complete!"
echo ""
sleep "$DELAY_MEDIUM"

################################################################################
# LAYER 6: POLICY COMPLIANCE
################################################################################

print_section "${CHART} Layer 6: Policy Compliance"
sleep "$DELAY_SHORT"

echo -e "${BLUE}${CHART} [PolicyAgent]${RESET} ${DIM}Checking compliance standards...${RESET}"
sleep "$DELAY_MEDIUM"

echo -e "   ${DIM}${CHECK} ISO/IEC 27001:2022${RESET}"
echo -e "   ${DIM}${CHECK} OWASP Smart Contract Top 10${RESET}"
echo -e "   ${DIM}${CHECK} SWC Registry${RESET}"
echo -e "   ${DIM}${CHECK} NIST SP 800-218${RESET}"
sleep "$DELAY_MEDIUM"

echo ""
echo -e "${GREEN}${CHECK} [PolicyAgent]${RESET} Compliance mapping complete"
echo ""
sleep "$DELAY_LONG"

################################################################################
# SUMMARY
################################################################################

print_header "${SHIELD} Analysis Complete - Results Summary"
sleep "$DELAY_MEDIUM"

echo -e "${BRIGHT_WHITE}${BOLD}Contract:${RESET} ${CONTRACT_PATH}"
echo -e "${BRIGHT_WHITE}${BOLD}Analysis Time:${RESET} 4.2 minutes"
echo -e "${BRIGHT_WHITE}${BOLD}Tools Used:${RESET} 8 (Slither, Aderyn, Solhint, Echidna, Mythril, Manticore, GPT-4, PolicyAgent)"
echo ""
sleep "$DELAY_MEDIUM"

# Raw findings
echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BRIGHT_YELLOW}${BOLD}Raw Findings (Before AI Triage):${RESET}"
echo -e "   Total: ${BOLD}51${RESET} findings"
echo -e "   ${DIM}├─ Slither: 23${RESET}"
echo -e "   ${DIM}├─ Aderyn: 12${RESET}"
echo -e "   ${DIM}├─ Solhint: 8${RESET}"
echo -e "   ${DIM}├─ Echidna: 3${RESET}"
echo -e "   ${DIM}├─ Mythril: 5${RESET}"
echo -e "   ${DIM}└─ Manticore: 3${RESET}"
echo ""
sleep "$DELAY_LONG"

# AI Filtering results
echo -e "${BRIGHT_CYAN}${BOLD}After AI Filtering:${RESET}"
echo -e "   ${GREEN}${ARROW}${RESET} Removed ${BOLD}8${RESET} duplicates"
echo -e "   ${GREEN}${ARROW}${RESET} Filtered ${BOLD}37${RESET} false positives (72.5%)"
echo -e "   ${GREEN}${ARROW}${RESET} Identified ${BOLD}6${RESET} unique actionable findings"
echo ""
sleep "$DELAY_LONG"

echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

################################################################################
# CRITICAL FINDINGS
################################################################################

echo -e "${BG_RED}${BRIGHT_WHITE}${BOLD} CRITICAL (1) ${RESET}"
echo ""
sleep "$DELAY_MEDIUM"

echo -e "${CRITICAL} ${BRIGHT_RED}${BOLD}Reentrancy Vulnerability${RESET}"
echo -e "   ${DIM}Location:${RESET} withdraw() function, line 28"
echo -e "   ${DIM}Type:${RESET} SWC-107, OWASP SC-01, CWE-841"
echo -e "   ${DIM}Severity:${RESET} ${BRIGHT_RED}CRITICAL${RESET} (CVSS 9.8)"
echo ""
echo -e "   ${BRIGHT_WHITE}Description:${RESET}"
echo -e "   External call to msg.sender.call() occurs before state update"
echo -e "   on line 31. This allows reentrancy attacks where an attacker"
echo -e "   can recursively call withdraw() and drain the contract."
echo ""
echo -e "   ${BRIGHT_WHITE}Detected by:${RESET} Slither, Mythril, Manticore ${GREEN}(3/3 tools agree)${RESET}"
echo -e "   ${BRIGHT_WHITE}Confidence:${RESET} ${GREEN}98%${RESET}"
echo ""
echo -e "   ${BRIGHT_YELLOW}💡 Suggested Fix:${RESET}"
echo -e "   ${DIM}Move balances[msg.sender] = 0 to line 26 (before external call)${RESET}"
echo -e "   ${DIM}Or use ReentrancyGuard from OpenZeppelin${RESET}"
echo ""
sleep "$DELAY_LONG"

################################################################################
# HIGH FINDINGS
################################################################################

echo -e "${BG_YELLOW}${BLACK}${BOLD} HIGH (2) ${RESET}"
echo ""
sleep "$DELAY_MEDIUM"

echo -e "${HIGH} ${YELLOW}${BOLD}Missing Access Control${RESET}"
echo -e "   ${DIM}Location:${RESET} setBalance() function, line 40"
echo -e "   ${DIM}Severity:${RESET} ${YELLOW}HIGH${RESET} (CVSS 7.5)"
echo -e "   ${DIM}Description:${RESET} Anyone can manipulate user balances"
echo -e "   ${DIM}Fix:${RESET} Add onlyOwner modifier"
echo ""

echo -e "${HIGH} ${YELLOW}${BOLD}Unsafe Transfer${RESET}"
echo -e "   ${DIM}Location:${RESET} emergencyWithdraw() function, line 54"
echo -e "   ${DIM}Severity:${RESET} ${YELLOW}HIGH${RESET} (CVSS 6.5)"
echo -e "   ${DIM}Description:${RESET} Using transfer() with 2300 gas limit"
echo -e "   ${DIM}Fix:${RESET} Use call{value: amount}() instead"
echo ""
sleep "$DELAY_MEDIUM"

################################################################################
# MEDIUM FINDINGS
################################################################################

echo -e "${BG_BLUE}${WHITE}${BOLD} MEDIUM (3) ${RESET}"
echo ""
sleep "$DELAY_SHORT"

echo -e "${MEDIUM} No recipient validation in emergencyWithdraw()"
echo -e "${MEDIUM} Missing zero address checks in transferOwnership()"
echo -e "${MEDIUM} Unchecked return values in multiple functions"
echo ""
sleep "$DELAY_MEDIUM"

################################################################################
# STATISTICS
################################################################################

echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "${BRIGHT_GREEN}${BOLD}${SHIELD} Key Achievements:${RESET}"
echo ""
echo -e "   ${GREEN}${CHECK}${RESET} ${BOLD}51 → 6${RESET} findings (88.2% reduction)"
echo -e "   ${GREEN}${CHECK}${RESET} ${BOLD}37${RESET} false positives filtered by AI (72.5%)"
echo -e "   ${GREEN}${CHECK}${RESET} ${BOLD}89.47%${RESET} precision maintained"
echo -e "   ${GREEN}${CHECK}${RESET} ${BOLD}3/3${RESET} tools agree on critical reentrancy"
echo -e "   ${GREEN}${CHECK}${RESET} Analysis time: ${BOLD}4.2 min${RESET} (vs ~4 hours manual)"
echo ""
echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
sleep "$DELAY_LONG"

################################################################################
# REPORT GENERATION
################################################################################

echo -e "${BRIGHT_CYAN}${CHART} Generating Reports...${RESET}"
echo ""
sleep "$DELAY_SHORT"

echo -e "   ${DIM}${CHECK} JSON report:${RESET} outputs/demo_vulnerable_report.json"
sleep "$DELAY_SHORT"
echo -e "   ${DIM}${CHECK} HTML dashboard:${RESET} outputs/demo_vulnerable_report.html"
sleep "$DELAY_SHORT"
echo -e "   ${DIM}${CHECK} PDF report:${RESET} outputs/demo_vulnerable_report.pdf"
sleep "$DELAY_SHORT"
echo -e "   ${DIM}${CHECK} Compliance matrix:${RESET} outputs/compliance_matrix.csv"
echo ""
sleep "$DELAY_MEDIUM"

################################################################################
# CONCLUSION
################################################################################

echo -e "${BRIGHT_GREEN}${BOLD}✅ MIESC saved you ~4 hours of manual triage!${RESET}"
echo ""
echo -e "${DIM}Next steps:${RESET}"
echo -e "   1. Review critical reentrancy vulnerability"
echo -e "   2. Apply suggested fixes"
echo -e "   3. Run tests with: ${CYAN}pytest tests/${RESET}"
echo -e "   4. Re-run analysis to verify fixes"
echo ""
echo -e "${BRIGHT_CYAN}${SHIELD} MIESC - Defense-in-Depth for the Decentralized World${RESET}"
echo ""

# Final pause for recording
sleep "$DELAY_LONG"
