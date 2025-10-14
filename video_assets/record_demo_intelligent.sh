#!/bin/bash

################################################################################
# MIESC Intelligent Multi-Agent Demo - For Video Recording
# Enhanced version with AI agent interpretation and smart reporting
#
# This version shows:
# - Each agent explaining what it found
# - AI interpretation of results
# - Smart report generation with insights
# - Clear multi-agent communication
#
# Usage: ./record_demo_intelligent.sh [fast|slow]
#
# Author: Fernando Boiero
# Project: MIESC - Multi-Agent Security Framework
################################################################################

# Configuration
SPEED="${1:-slow}"
CONTRACT_PATH="examples/demo_vulnerable.sol"

# Speed settings
if [ "$SPEED" = "fast" ]; then
    DELAY_SHORT=0.3
    DELAY_MEDIUM=0.8
    DELAY_LONG=1.5
    DELAY_AGENT_THINK=0.5
else
    DELAY_SHORT=0.8
    DELAY_MEDIUM=1.5
    DELAY_LONG=3.0
    DELAY_AGENT_THINK=2.0
fi

# Color codes
RESET='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'
ITALIC='\033[3m'

# Colors
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

# Icons
SHIELD="🛡️"
BRAIN="🧠"
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
MICROSCOPE="🔬"
LIGHTBULB="💡"
MEMO="📝"
MAGNIFYING="🔎"
TARGET="🎯"

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

print_agent_thinking() {
    local agent_name="$1"
    local icon="$2"
    local color="$3"

    echo ""
    echo -e "${color}${icon} ${BOLD}[${agent_name} - AI Analysis]${RESET}"
    echo -e "${DIM}   ${BRAIN} Agent is interpreting findings...${RESET}"
    sleep "$DELAY_AGENT_THINK"
}

print_agent_insight() {
    local insight="$1"
    echo -e "${BRIGHT_WHITE}   ${LIGHTBULB} ${ITALIC}\"${insight}\"${RESET}"
}

print_agent_summary() {
    local summary="$1"
    echo -e "${CYAN}   ${MEMO} Summary: ${summary}${RESET}"
}

################################################################################
# Main Demo Script
################################################################################

clear

# Welcome banner
print_header "${SHIELD}  MIESC - Multi-Agent Security Framework for Smart Contracts"

echo -e "${DIM}Version 2.2.0 | GPL-3.0 License${RESET}"
echo -e "${DIM}Multi-Agent Architecture with AI-Powered Analysis${RESET}"
echo ""
sleep "$DELAY_MEDIUM"

# Show the command
echo -e "${BRIGHT_WHITE}${BOLD}\$ python xaudit.py --target ${CONTRACT_PATH} --mode standard${RESET}"
sleep "$DELAY_LONG"
echo ""

# Initialize
print_section "${PACKAGE} Initializing Multi-Agent System"
sleep "$DELAY_SHORT"

echo -e "${CYAN}${ARROW}${RESET} Loading CoordinatorAgent (MCP Protocol)..."
sleep "$DELAY_SHORT"
echo -e "${GREEN}${CHECK}${RESET} CoordinatorAgent ready - Managing 8 specialized agents"

echo -e "${CYAN}${ARROW}${RESET} Initializing Context Bus for agent communication..."
sleep "$DELAY_SHORT"
echo -e "${GREEN}${CHECK}${RESET} Context Bus active - Agents can share findings"

echo -e "${CYAN}${ARROW}${RESET} Validating contract: ${BOLD}${CONTRACT_PATH}${RESET}"
sleep "$DELAY_SHORT"
echo -e "${GREEN}${CHECK}${RESET} Contract loaded (120 lines, Solidity 0.8.0)"

echo ""
sleep "$DELAY_MEDIUM"

################################################################################
# LAYER 1: STATIC ANALYSIS AGENTS
################################################################################

print_section "${LIGHTNING} Layer 1: Static Analysis Agents"
sleep "$DELAY_SHORT"

# === SLITHER AGENT ===
echo -e "${CYAN}┌─ SlitherAgent ──────────────────────────────────────┐${RESET}"
echo -e "${CYAN}${SEARCH} [SlitherAgent]${RESET} ${DIM}Running 87 pattern detectors...${RESET}"
sleep "$DELAY_LONG"
echo -e "${GREEN}${CHECK} [SlitherAgent]${RESET} Scan complete - ${BOLD}23${RESET} findings detected"
echo -e "   ${DIM}├─ Reentrancy pattern: 1 match${RESET}"
echo -e "   ${DIM}├─ Access control issues: 2 matches${RESET}"
echo -e "   ${DIM}└─ Style/optimization: 20 suggestions${RESET}"

# Agent AI interpretation
print_agent_thinking "SlitherAgent" "${BRAIN}" "${BRIGHT_CYAN}"
print_agent_insight "I detected a classic reentrancy pattern at line 28. The contract calls an external address before updating its internal state, which is a well-known vulnerability pattern that led to the DAO hack. This is definitely exploitable."
print_agent_summary "Found 1 critical reentrancy, 2 access control gaps, 20 minor issues"
echo -e "${CYAN}└─────────────────────────────────────────────────────┘${RESET}"
echo ""
sleep "$DELAY_MEDIUM"

# === ADERYN AGENT ===
echo -e "${PURPLE}┌─ AderynAgent ───────────────────────────────────────┐${RESET}"
echo -e "${FIRE} [AderynAgent]${RESET} ${DIM}Ultra-fast Rust-based AST analysis...${RESET}"
sleep "$DELAY_MEDIUM"
echo -e "${GREEN}${CHECK} [AderynAgent]${RESET} Analysis complete - ${BOLD}12${RESET} findings"
echo -e "   ${DIM}├─ Missing event emissions: 5 functions${RESET}"
echo -e "   ${DIM}└─ Unsafe external calls: 7 locations${RESET}"

print_agent_thinking "AderynAgent" "${BRAIN}" "${BRIGHT_PURPLE}"
print_agent_insight "The contract lacks proper event emissions for critical state changes. This makes it hard to track what's happening on-chain. Also, I see multiple external calls that don't follow the Checks-Effects-Interactions pattern."
print_agent_summary "12 findings focused on best practices and call safety"
echo -e "${PURPLE}└─────────────────────────────────────────────────────┘${RESET}"
echo ""
sleep "$DELAY_MEDIUM"

# === SOLHINT AGENT ===
echo -e "${BLUE}┌─ SolhintAgent ──────────────────────────────────────┐${RESET}"
echo -e "${PACKAGE} [SolhintAgent]${RESET} ${DIM}Checking 200+ linting rules...${RESET}"
sleep "$DELAY_SHORT"
echo -e "${GREEN}${CHECK} [SolhintAgent]${RESET} Linting complete - ${BOLD}8${RESET} issues"

print_agent_thinking "SolhintAgent" "${BRAIN}" "${BRIGHT_BLUE}"
print_agent_insight "Code quality could be improved. I found naming convention violations and some functions that should be marked external for gas optimization. Nothing critical, but following standards matters for maintainability."
print_agent_summary "8 code quality and style improvements recommended"
echo -e "${BLUE}└─────────────────────────────────────────────────────┘${RESET}"
echo ""
sleep "$DELAY_MEDIUM"

################################################################################
# LAYER 3: SYMBOLIC EXECUTION AGENTS
################################################################################

print_section "${SEARCH} Layer 3: Symbolic Execution Agents"
sleep "$DELAY_SHORT"

# === MYTHRIL AGENT ===
echo -e "${PURPLE}┌─ MythrilAgent ──────────────────────────────────────┐${RESET}"
echo -e "${MICROSCOPE} [MythrilAgent]${RESET} ${DIM}Exploring all possible execution paths...${RESET}"
sleep "$DELAY_LONG"
echo -e "   ${DIM}Analyzing state space with Z3 SMT solver...${RESET}"
sleep "$DELAY_LONG"
echo -e "   ${DIM}Found 5 unique execution paths...${RESET}"
sleep "$DELAY_MEDIUM"
echo -e "${GREEN}${CHECK} [MythrilAgent]${RESET} Symbolic execution complete - ${BOLD}5${RESET} critical paths"
echo -e "   ${DIM}├─ ${CRITICAL} Reentrancy exploit: CONFIRMED${RESET}"
echo -e "   ${DIM}├─ Attack scenario: Recursive callback possible${RESET}"
echo -e "   ${DIM}└─ SWC-107 classification${RESET}"

print_agent_thinking "MythrilAgent" "${BRAIN}" "${BRIGHT_PURPLE}"
print_agent_insight "I mathematically proved the reentrancy vulnerability is exploitable. I traced 5 different execution paths and in 3 of them, an attacker can drain the entire contract balance by calling withdraw() recursively. This is not theoretical—it's a real exploit."
print_agent_summary "CRITICAL: Reentrancy is mathematically proven exploitable"
echo -e "${PURPLE}└─────────────────────────────────────────────────────┘${RESET}"
echo ""
sleep "$DELAY_LONG"

# === MANTICORE AGENT ===
echo -e "${PURPLE}┌─ ManticoreAgent ────────────────────────────────────┐${RESET}"
echo -e "${MICROSCOPE} [ManticoreAgent]${RESET} ${DIM}Dynamic symbolic execution...${RESET}"
sleep "$DELAY_LONG"
echo -e "${GREEN}${CHECK} [ManticoreAgent]${RESET} Execution complete - ${BOLD}3${RESET} exploits confirmed"

print_agent_thinking "ManticoreAgent" "${BRAIN}" "${BRIGHT_PURPLE}"
print_agent_insight "I simulated actual attacks and confirmed 3 different ways to exploit the reentrancy. I also found that the access control issue in setBalance() allows anyone to manipulate balances—that's a second critical vulnerability."
print_agent_summary "3 confirmed exploit paths, 2 critical vulnerabilities"
echo -e "${PURPLE}└─────────────────────────────────────────────────────┘${RESET}"
echo ""
sleep "$DELAY_MEDIUM"

################################################################################
# LAYER 5: AI COORDINATOR AGENT
################################################################################

print_section "${ROBOT} Layer 5: AI Coordinator Agent (GPT-4)"
sleep "$DELAY_SHORT"

echo -e "${BRIGHT_CYAN}┌─ AICoordinatorAgent (GPT-4 Powered) ────────────────┐${RESET}"
echo ""
echo -e "${ROBOT} ${BOLD}[AICoordinatorAgent]${RESET} ${DIM}Analyzing findings from all agents...${RESET}"
sleep "$DELAY_MEDIUM"

echo -e "   ${DIM}${ARROW} Collecting data from 5 specialized agents...${RESET}"
sleep "$DELAY_MEDIUM"
echo -e "      ${GREEN}${CHECK}${RESET} ${DIM}SlitherAgent: 23 findings${RESET}"
echo -e "      ${GREEN}${CHECK}${RESET} ${DIM}AderynAgent: 12 findings${RESET}"
echo -e "      ${GREEN}${CHECK}${RESET} ${DIM}SolhintAgent: 8 findings${RESET}"
echo -e "      ${GREEN}${CHECK}${RESET} ${DIM}MythrilAgent: 5 critical paths${RESET}"
echo -e "      ${GREEN}${CHECK}${RESET} ${DIM}ManticoreAgent: 3 exploits${RESET}"

echo ""
echo -e "   ${DIM}${ARROW} Cross-referencing findings across agents...${RESET}"
sleep "$DELAY_LONG"
echo -e "      ${YELLOW}${TARGET}${RESET} ${DIM}Reentrancy mentioned by: SlitherAgent, MythrilAgent, ManticoreAgent${RESET}"
echo -e "      ${GREEN}${CHECK}${RESET} ${DIM}3/3 agents agree - HIGH CONFIDENCE${RESET}"

echo ""
echo -e "   ${DIM}${ARROW} Identifying duplicate findings...${RESET}"
sleep "$DELAY_MEDIUM"
echo -e "      ${DIM}Found 8 duplicate reports (same issue, different tools)${RESET}"
echo -e "      ${GREEN}${CHECK}${RESET} ${DIM}Merged into unique findings${RESET}"

echo ""
echo -e "   ${DIM}${ARROW} Filtering false positives with LLM reasoning...${RESET}"
sleep "$DELAY_LONG"
echo -e "      ${DIM}Analyzing 51 total findings...${RESET}"
sleep "$DELAY_MEDIUM"
echo -e "      ${YELLOW}${CROSS}${RESET} ${DIM}Filtered 37 false positives (72.5%)${RESET}"
echo -e "      ${GREEN}${CHECK}${RESET} ${DIM}Retained 6 actionable findings${RESET}"

echo ""
echo -e "   ${DIM}${ARROW} Performing deep root cause analysis...${RESET}"
sleep "$DELAY_LONG"

echo ""
print_agent_thinking "AICoordinatorAgent" "${BRAIN}" "${BRIGHT_CYAN}"
echo -e "${BRIGHT_WHITE}   ${LIGHTBULB} ${ITALIC}\"After analyzing all agent reports, I've identified a critical security flaw:${RESET}"
echo -e "${BRIGHT_WHITE}   ${LIGHTBULB} ${ITALIC}The withdraw() function violates the Checks-Effects-Interactions pattern.${RESET}"
echo -e "${BRIGHT_WHITE}   ${LIGHTBULB} ${ITALIC}Three independent agents (Slither, Mythril, Manticore) all flagged this,${RESET}"
echo -e "${BRIGHT_WHITE}   ${LIGHTBULB} ${ITALIC}and symbolic execution mathematically proved it's exploitable.${RESET}"
echo ""
echo -e "${BRIGHT_WHITE}   ${LIGHTBULB} ${ITALIC}The root cause is architectural: external calls before state updates.${RESET}"
echo -e "${BRIGHT_WHITE}   ${LIGHTBULB} ${ITALIC}This allowed the DAO hack in 2016 and costs millions in DeFi today.${RESET}"
echo ""
echo -e "${BRIGHT_WHITE}   ${LIGHTBULB} ${ITALIC}I'm prioritizing this as CRITICAL with 98% confidence.\"${RESET}"

echo ""
print_agent_summary "51 findings → 6 actionable | 37 FPs filtered | 3/3 agent consensus on critical"
echo ""
echo -e "${GREEN}${CHECK}${RESET} ${BOLD}[AICoordinatorAgent]${RESET} Cross-agent analysis complete!"
echo -e "${BRIGHT_CYAN}└──────────────────────────────────────────────────────┘${RESET}"
echo ""
sleep "$DELAY_LONG"

################################################################################
# INTELLIGENT REPORT GENERATION
################################################################################

print_section "${CHART} Intelligent Report Generation"
sleep "$DELAY_SHORT"

echo -e "${BRIGHT_PURPLE}┌─ ReportAgent (AI-Powered Insights) ─────────────────┐${RESET}"
echo ""
echo -e "${MEMO} ${BOLD}[ReportAgent]${RESET} ${DIM}Generating executive summary...${RESET}"
sleep "$DELAY_MEDIUM"

echo ""
echo -e "${BRIGHT_WHITE}${BOLD}═══ EXECUTIVE SUMMARY ═══${RESET}"
echo ""
echo -e "${BRIGHT_CYAN}${SHIELD} Contract Security Assessment${RESET}"
echo -e "${DIM}Contract: VulnerableBank.sol | 120 LOC | Solidity 0.8.0${RESET}"
echo -e "${DIM}Analysis Method: Multi-Agent Defense-in-Depth (6 layers)${RESET}"
echo -e "${DIM}Agents Deployed: 8 specialized security agents + AI coordinator${RESET}"
echo ""
sleep "$DELAY_MEDIUM"

echo -e "${BRIGHT_YELLOW}${BOLD}🎯 KEY FINDINGS:${RESET}"
echo ""
echo -e "${BRIGHT_RED}${BOLD}Critical Risk Identified:${RESET}"
echo -e "   ${CRITICAL} Reentrancy vulnerability with confirmed exploit path"
echo -e "   ${DIM}└─ Unanimous agreement across 3 agents (100% confidence)${RESET}"
echo ""
sleep "$DELAY_MEDIUM"

echo -e "${BRIGHT_CYAN}${BOLD}${BRAIN} AI INSIGHTS:${RESET}"
echo ""
echo -e "${BRIGHT_WHITE}   1. Pattern Recognition:${RESET}"
echo -e "      ${DIM}This vulnerability follows the classic DAO hack pattern from 2016.${RESET}"
echo -e "      ${DIM}Historical attacks using this: $360M+ stolen across DeFi${RESET}"
echo ""
echo -e "${BRIGHT_WHITE}   2. Risk Assessment:${RESET}"
echo -e "      ${DIM}Exploitation difficulty: LOW (script kiddie level)${RESET}"
echo -e "      ${DIM}Impact: MAXIMUM (full contract drainage possible)${RESET}"
echo -e "      ${DIM}CVSS Score: 9.8/10 (Critical)${RESET}"
echo ""
echo -e "${BRIGHT_WHITE}   3. Business Impact:${RESET}"
echo -e "      ${DIM}If deployed with $1M TVL: Complete loss possible${RESET}"
echo -e "      ${DIM}Reputation damage: Severe${RESET}"
echo -e "      ${DIM}Legal liability: High (negligence)${RESET}"
echo ""
sleep "$DELAY_LONG"

echo -e "${BRIGHT_GREEN}${BOLD}${LIGHTBULB} RECOMMENDED ACTIONS:${RESET}"
echo ""
echo -e "   ${GREEN}${CHECK}${RESET} ${BOLD}IMMEDIATE (Within 24h):${RESET}"
echo -e "      ${DIM}1. Do NOT deploy this contract to mainnet${RESET}"
echo -e "      ${DIM}2. Move balances[msg.sender] = 0 to line 26${RESET}"
echo -e "      ${DIM}3. Add ReentrancyGuard from OpenZeppelin${RESET}"
echo ""
echo -e "   ${YELLOW}${WARNING}${RESET} ${BOLD}SHORT-TERM (Within 1 week):${RESET}"
echo -e "      ${DIM}4. Add onlyOwner modifier to setBalance()${RESET}"
echo -e "      ${DIM}5. Replace transfer() with call{value}()${RESET}"
echo -e "      ${DIM}6. Add zero-address validation${RESET}"
echo ""
echo -e "   ${BLUE}${INFO}${RESET} ${BOLD}LONG-TERM (Best Practices):${RESET}"
echo -e "      ${DIM}7. Implement comprehensive event emissions${RESET}"
echo -e "      ${DIM}8. Follow formal verification process${RESET}"
echo -e "      ${DIM}9. Get professional audit before mainnet${RESET}"
echo ""
sleep "$DELAY_LONG"

echo -e "${BRIGHT_WHITE}${BOLD}📊 ANALYSIS STATISTICS:${RESET}"
echo ""
echo -e "   ${DIM}Agents Consulted: 8${RESET}"
echo -e "   ${DIM}Total Scans Run: 51${RESET}"
echo -e "   ${DIM}False Positives Filtered: 37 (72.5%)${RESET}"
echo -e "   ${DIM}Actionable Findings: 6${RESET}"
echo -e "   ${DIM}Critical: 1 | High: 2 | Medium: 3${RESET}"
echo -e "   ${DIM}Agent Agreement on Critical: 100% (3/3)${RESET}"
echo -e "   ${DIM}AI Confidence Score: 98%${RESET}"
echo -e "   ${DIM}Analysis Time: 4.2 minutes${RESET}"
echo -e "   ${DIM}Time Saved vs Manual: ~3.8 hours (90%)${RESET}"
echo ""
sleep "$DELAY_MEDIUM"

echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "${GREEN}${CHECK}${RESET} ${BOLD}Report files generated:${RESET}"
echo -e "   ${DIM}├─ outputs/executive_summary.pdf${RESET}"
echo -e "   ${DIM}├─ outputs/technical_report.json${RESET}"
echo -e "   ${DIM}├─ outputs/dashboard.html${RESET}"
echo -e "   ${DIM}└─ outputs/compliance_matrix.csv${RESET}"
echo ""
echo -e "${BRIGHT_PURPLE}└──────────────────────────────────────────────────────┘${RESET}"
echo ""
sleep "$DELAY_MEDIUM"

################################################################################
# FINAL SUMMARY
################################################################################

print_header "${SHIELD} Multi-Agent Analysis Complete"
sleep "$DELAY_MEDIUM"

echo -e "${BRIGHT_GREEN}${BOLD}✅ SUCCESS: AI-powered multi-agent analysis completed!${RESET}"
echo ""
echo -e "${BRIGHT_CYAN}${BRAIN} ${BOLD}What Made This Analysis Smart:${RESET}"
echo ""
echo -e "   ${GREEN}${CHECK}${RESET} ${BOLD}8 Specialized Agents${RESET} each contributed unique insights"
echo -e "   ${GREEN}${CHECK}${RESET} ${BOLD}AI Coordination${RESET} cross-referenced findings for accuracy"
echo -e "   ${GREEN}${CHECK}${RESET} ${BOLD}LLM Reasoning${RESET} filtered 37 false positives automatically"
echo -e "   ${GREEN}${CHECK}${RESET} ${BOLD}Root Cause Analysis${RESET} identified architectural flaws"
echo -e "   ${GREEN}${CHECK}${RESET} ${BOLD}Risk Quantification${RESET} assessed business impact"
echo -e "   ${GREEN}${CHECK}${RESET} ${BOLD}Actionable Recommendations${RESET} with clear priorities"
echo ""
echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "${BRIGHT_YELLOW}${LIGHTBULB} ${BOLD}The MIESC Advantage:${RESET}"
echo ""
echo -e "   ${YELLOW}${ARROW}${RESET} Traditional Tools: 51 warnings, you triage manually"
echo -e "   ${GREEN}${ARROW}${RESET} ${BOLD}MIESC:${RESET} 6 prioritized findings with AI explanations"
echo ""
echo -e "   ${YELLOW}${ARROW}${RESET} Traditional: \"Reentrancy detected\" (generic warning)"
echo -e "   ${GREEN}${ARROW}${RESET} ${BOLD}MIESC:${RESET} \"Reentrancy proven exploitable by 3 agents, CVSS 9.8,\n               fix: move state update to line 26, similar to DAO hack\""
echo ""
echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "${BRIGHT_CYAN}${SHIELD} MIESC - Where AI Agents Collaborate to Secure Web3${RESET}"
echo ""

sleep "$DELAY_LONG"
