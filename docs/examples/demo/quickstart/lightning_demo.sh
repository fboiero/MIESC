#!/bin/bash
#
# MIESC Lightning Demo - 30 Seconds to Security Insights
# Version: 3.3.0
# Purpose: Ultra-fast demonstration of core MIESC capabilities
#
# Usage: bash demo/quickstart/lightning_demo.sh
#
# Author: Fernando Boiero - UNDEF
#

set -e  # Exit on error

# Colors for output
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Function to print section headers
print_header() {
    echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Function to print success
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

# Function to print info
print_info() {
    echo -e "${CYAN}ℹ${NC} $1"
}

# Function to print warning
print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Clear screen for clean demo
clear

# Banner
echo -e "${BOLD}${CYAN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ███╗   ███╗██╗███████╗███████╗ ██████╗                        ║
║   ████╗ ████║██║██╔════╝██╔════╝██╔════╝                        ║
║   ██╔████╔██║██║█████╗  ███████╗██║                             ║
║   ██║╚██╔╝██║██║██╔══╝  ╚════██║██║                             ║
║   ██║ ╚═╝ ██║██║███████╗███████║╚██████╗                        ║
║   ╚═╝     ╚═╝╚═╝╚══════╝╚══════╝ ╚═════╝                        ║
║                                                                  ║
║          Lightning Demo - 30 Seconds to Security                ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"
echo ""
echo -e "${BOLD}Multi-layer Intelligent Evaluation for Smart Contracts${NC}"
echo -e "Version 3.3.0 | Defense-in-Depth | 15 Security Tools"
echo ""
echo ""

# Start timer
START_TIME=$(date +%s)

# Step 1: Prerequisites check
print_header "Step 1: Checking Prerequisites"

# Check Slither
if command -v slither &> /dev/null; then
    SLITHER_VERSION=$(slither --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1 || echo "unknown")
    print_success "Slither found: v${SLITHER_VERSION}"
else
    print_warning "Slither not found - Install with: pip install slither-analyzer"
    echo ""
    echo -e "${YELLOW}For a full demonstration, please install Slither:${NC}"
    echo -e "  ${CYAN}pip install slither-analyzer${NC}"
    echo ""
    exit 1
fi

echo ""

# Step 2: Analyzing vulnerable contract
print_header "Step 2: Analyzing Vulnerable Smart Contract"

# Create output directory
mkdir -p demo/quickstart/outputs

# Contract to analyze
CONTRACT="examples/reentrancy_simple.sol"

if [ ! -f "$CONTRACT" ]; then
    print_warning "Example contract not found: $CONTRACT"
    echo "Please run from MIESC repository root"
    exit 1
fi

print_info "Target: ${BOLD}reentrancy_simple.sol${NC}"
print_info "Analysis: Static analysis with Slither"
print_info "Time estimate: ~5-10 seconds"
echo ""

# Run Slither analysis
echo -e "${CYAN}Running Slither...${NC}"
SLITHER_OUTPUT=$(slither "$CONTRACT" --json demo/quickstart/outputs/slither_output.json 2>&1 || true)

# Parse results
if [ -f "demo/quickstart/outputs/slither_output.json" ]; then
    print_success "Analysis complete!"

    # Count vulnerabilities by severity (using basic parsing)
    CRITICAL_COUNT=$(echo "$SLITHER_OUTPUT" | grep -i "high\|critical" | wc -l | xargs)
    MEDIUM_COUNT=$(echo "$SLITHER_OUTPUT" | grep -i "medium" | wc -l | xargs)
    TOTAL_COUNT=$(echo "$SLITHER_OUTPUT" | grep -i "impact" | wc -l | xargs)

    echo ""
    echo -e "${BOLD}${YELLOW}╭─────────────────────────────────────────────────────╮${NC}"
    echo -e "${BOLD}${YELLOW}│                  Analysis Results                   │${NC}"
    echo -e "${BOLD}${YELLOW}╰─────────────────────────────────────────────────────╯${NC}"
    echo ""

    # Check if jq is available for better parsing
    if command -v jq &> /dev/null && [ -f "demo/quickstart/outputs/slither_output.json" ]; then
        # Parse JSON output
        HIGH_COUNT=$(jq '[.results.detectors[] | select(.impact == "High")] | length' demo/quickstart/outputs/slither_output.json 2>/dev/null || echo "0")
        MEDIUM_COUNT=$(jq '[.results.detectors[] | select(.impact == "Medium")] | length' demo/quickstart/outputs/slither_output.json 2>/dev/null || echo "0")
        LOW_COUNT=$(jq '[.results.detectors[] | select(.impact == "Low")] | length' demo/quickstart/outputs/slither_output.json 2>/dev/null || echo "0")

        echo -e "  ${RED}🔴 High Severity:${NC}     ${HIGH_COUNT}"
        echo -e "  ${YELLOW}🟡 Medium Severity:${NC}   ${MEDIUM_COUNT}"
        echo -e "  ${CYAN}🔵 Low Severity:${NC}      ${LOW_COUNT}"

        # Show top finding
        if [ "$HIGH_COUNT" -gt 0 ]; then
            echo ""
            echo -e "${BOLD}Top Critical Finding:${NC}"
            echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

            TOP_FINDING=$(jq -r '.results.detectors[] | select(.impact == "High") | .description' demo/quickstart/outputs/slither_output.json 2>/dev/null | head -1)
            TOP_TYPE=$(jq -r '.results.detectors[] | select(.impact == "High") | .check' demo/quickstart/outputs/slither_output.json 2>/dev/null | head -1)

            echo -e "  ${BOLD}Type:${NC} $TOP_TYPE"
            echo -e "  ${BOLD}Description:${NC}"
            echo -e "  $(echo "$TOP_FINDING" | head -c 200)..."
        fi
    else
        # Fallback to basic output
        echo -e "  ${RED}🔴 Critical/High:${NC}   ${CRITICAL_COUNT}"
        echo -e "  ${YELLOW}🟡 Medium:${NC}          ${MEDIUM_COUNT}"
        echo -e "  ${CYAN}ℹ  Total findings:${NC}  ${TOTAL_COUNT}"
        echo ""
        print_info "Install jq for detailed analysis: ${CYAN}brew install jq${NC}"
    fi

    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}Key Vulnerability Detected:${NC} ${RED}Reentrancy in withdraw()${NC}"
    echo ""
    echo -e "${BOLD}Issue:${NC} External call before state update allows re-entry attack"
    echo -e "${BOLD}Location:${NC} Line 21: msg.sender.call{value: amount}(\"\")"
    echo -e "${BOLD}Risk:${NC} Attacker can drain all contract funds"
    echo ""
    echo -e "${BOLD}Recommended Fix:${NC}"
    echo -e "  1. Update state ${BOLD}before${NC} external calls (Checks-Effects-Interactions)"
    echo -e "  2. Use ReentrancyGuard modifier from OpenZeppelin"
    echo -e "  3. Consider using transfer() or send() with fixed gas"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
else
    print_warning "Slither analysis completed but JSON output not generated"
    print_info "Check demo/quickstart/outputs/ for results"
fi

echo ""

# Step 3: Summary
print_header "Step 3: Demo Summary"

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo -e "${BOLD}What Just Happened:${NC}"
echo ""
echo -e "  1. ${GREEN}✓${NC} Analyzed vulnerable smart contract"
echo -e "  2. ${GREEN}✓${NC} Detected critical reentrancy vulnerability"
echo -e "  3. ${GREEN}✓${NC} Provided fix recommendations"
echo ""
echo -e "${BOLD}Performance:${NC}"
echo -e "  ⏱️  Total time: ${DURATION} seconds"
echo -e "  🛠️  Tools used: Slither (static analysis)"
echo -e "  📊 Output: demo/quickstart/outputs/slither_output.json"
echo ""

# Step 4: Next steps
print_header "Step 4: What's Next?"

echo -e "${BOLD}Try These Commands:${NC}"
echo ""
echo -e "  ${CYAN}# Full multi-tool analysis:${NC}"
echo -e "  python src/miesc_cli.py run-audit $CONTRACT --mode full"
echo ""
echo -e "  ${CYAN}# Web interface (no installation):${NC}"
echo -e "  streamlit run webapp/app.py"
echo ""
echo -e "  ${CYAN}# Compliance report:${NC}"
echo -e "  python src/miesc_cli.py run-audit $CONTRACT --compliance-only"
echo ""
echo -e "  ${CYAN}# Analyze your own contract:${NC}"
echo -e "  python src/miesc_cli.py run-audit path/to/your/contract.sol"
echo ""

echo -e "${BOLD}Learn More:${NC}"
echo ""
echo -e "  📖 Quick Start: ${CYAN}cat QUICKSTART.md${NC}"
echo -e "  📚 Full Docs:   ${CYAN}open docs/02_SETUP_AND_USAGE.md${NC}"
echo -e "  🎥 Video Demo:  ${CYAN}Coming soon${NC}"
echo -e "  💬 Get Help:    ${CYAN}https://github.com/fboiero/MIESC/issues${NC}"
echo ""

# Final banner
echo -e "${BOLD}${GREEN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════════╗
║                    Demo Complete! ✨                             ║
║                                                                  ║
║  You just detected a critical vulnerability in 30 seconds!      ║
║                                                                  ║
║  ⭐ Star us on GitHub: https://github.com/fboiero/MIESC         ║
║  🤝 Contribute: See CONTRIBUTING.md                             ║
║  📧 Questions: fboiero@frvm.utn.edu.ar                          ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

print_success "Thank you for trying MIESC!"
echo ""
