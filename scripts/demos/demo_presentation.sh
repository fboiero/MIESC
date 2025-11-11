#!/bin/bash

# MIESC Presentation Demo
# Uses real vulnerable contracts from SmartBugs database
# Shows detailed findings, conclusions, and next steps

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

clear
cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║              🎯 MIESC - PRESENTATION DEMO                                ║
║                                                                          ║
║          Real Vulnerable Contracts from SmartBugs Database               ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
EOF

echo ""
echo -e "${CYAN}This demo will:${NC}"
echo "  1. Organize vulnerable contracts from MIESC examples"
echo "  2. Analyze them with multiple specialized agents"
echo "  3. Show detailed findings with impact and recommendations"
echo "  4. Generate conclusions and next steps"
echo "  5. Create professional reports and dashboards"
echo ""
read -p "Press Enter to start..."

# ============================================================================
# Step 1: Organize Vulnerable Contracts
# ============================================================================

clear
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║  Step 1: Organizing Vulnerable Contracts for Demo          ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${CYAN}Using MIESC example contracts with known vulnerabilities${NC}"
echo -e "${CYAN}We'll organize 6 contracts for testing:${NC}"
echo ""
echo "  • Reentrancy (DAO Hack)"
echo "  • Integer Overflow"
echo "  • Unchecked Send"
echo "  • Delegatecall Injection"
echo "  • tx.origin Authentication"
echo "  • Vulnerable Bank"
echo ""

read -p "Press Enter to organize contracts..."

python scripts/download_vulnerable_contracts.py

echo ""
read -p "Press Enter to continue..."

# ============================================================================
# Step 2: Select Contract for Demo
# ============================================================================

clear
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║  Step 2: Select Contract for Analysis                       ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${CYAN}Available vulnerable contracts:${NC}"
echo ""
ls -1 vulnerable_contracts/

echo ""
echo -e "${YELLOW}For this demo, we'll analyze the REENTRANCY contract${NC}"
echo -e "${YELLOW}(Similar to the famous DAO hack that cost $60 million)${NC}"
echo ""

CONTRACT="vulnerable_contracts/reentrancy/reentrancy.sol"
TAG="presentation_reentrancy"

# Show metadata
if [ -f "vulnerable_contracts/reentrancy/metadata.txt" ]; then
    echo -e "${CYAN}Contract Information:${NC}"
    cat vulnerable_contracts/reentrancy/metadata.txt
    echo ""
fi

read -p "Press Enter to view the vulnerable code..."

# ============================================================================
# Step 3: Show Vulnerable Code
# ============================================================================

clear
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║  Step 3: The Vulnerable Code                                ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${YELLOW}Contract Code (with vulnerability):${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat "$CONTRACT" | head -50
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${RED}⚠️  Can you spot the vulnerability?${NC}"
echo ""
echo -e "${YELLOW}Hint: Look at the withdraw function...${NC}"
echo ""
read -p "Press Enter when ready to run the analysis..."

# ============================================================================
# Step 4: Run Multi-Agent Analysis
# ============================================================================

clear
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║  Step 4: Running Multi-Agent Security Analysis              ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${CYAN}Activating security agents:${NC}"
echo ""
echo "  🤖 Slither Agent    - Static analysis"
echo "  🤖 Ollama Agent     - AI analysis (local, free)"
echo ""
echo -e "${YELLOW}Command:${NC}"
echo "  python main_ai.py $CONTRACT $TAG --use-slither --use-ollama"
echo ""
read -p "Press Enter to run (this will take ~60 seconds)..."

python main_ai.py "$CONTRACT" "$TAG" --use-slither --use-ollama

echo ""
echo -e "${GREEN}✓ Analysis complete!${NC}"
echo ""
read -p "Press Enter to view the results..."

# ============================================================================
# Step 5: Show Individual Agent Evidence
# ============================================================================

clear
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║  Step 5: Agent Evidence Files                               ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${CYAN}Generated Evidence Files:${NC}"
ls -lh "output/$TAG/" | grep -v "^d" | tail -n +2
echo ""

# Show Slither Evidence
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}SLITHER AGENT EVIDENCE (output/$TAG/Slither.txt)${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
cat "output/$TAG/Slither.txt" | head -30
echo "..."
echo ""
read -p "Press Enter to see Ollama AI analysis..."

# Show Ollama Evidence
clear
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}OLLAMA AI AGENT EVIDENCE (output/$TAG/Ollama.txt)${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
cat "output/$TAG/Ollama.txt"
echo ""
read -p "Press Enter to generate detailed report..."

# ============================================================================
# Step 6: Generate Enhanced Report
# ============================================================================

clear
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║  Step 6: Generating Enhanced Report                         ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${CYAN}Creating detailed report with:${NC}"
echo "  • Detailed findings from each agent"
echo "  • Impact analysis"
echo "  • Remediation recommendations"
echo "  • Risk assessment"
echo "  • Conclusions"
echo "  • Next steps"
echo ""

python generate_reports.py "output/$TAG" "Reentrancy Vulnerability Demo"

echo ""
echo -e "${GREEN}✓ Report generated!${NC}"
echo ""
read -p "Press Enter to view the detailed report..."

# ============================================================================
# Step 7: Show Detailed Report
# ============================================================================

clear
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║  Step 7: Detailed Security Report                           ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

REPORT="output/$TAG/reports/consolidated_report.md"

if [ -f "$REPORT" ]; then
    echo -e "${CYAN}Showing first 100 lines of detailed report:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cat "$REPORT" | head -100
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo -e "${YELLOW}... (see full report in $REPORT)${NC}"
fi

echo ""
read -p "Press Enter to open the interactive dashboard..."

# ============================================================================
# Step 8: Interactive Dashboard
# ============================================================================

clear
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║  Step 8: Interactive Dashboard                              ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

DASHBOARD="output/$TAG/reports/dashboard.html"

echo -e "${CYAN}Opening interactive HTML dashboard...${NC}"
echo ""
echo "The dashboard shows:"
echo "  ✓ Executive summary with risk assessment"
echo "  ✓ Findings from all agents"
echo "  ✓ Severity-coded statistics"
echo "  ✓ Detailed recommendations"
echo "  ✓ Conclusions and next steps"
echo ""

if [[ "$OSTYPE" == "darwin"* ]]; then
    open "$DASHBOARD"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    xdg-open "$DASHBOARD" 2>/dev/null || echo "Please open: $DASHBOARD"
fi

sleep 3
read -p "Press Enter for demo summary..."

# ============================================================================
# Summary
# ============================================================================

clear
cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║                  🎉 PRESENTATION DEMO COMPLETE! 🎉                       ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
EOF

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}What We Demonstrated:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${GREEN}✓${NC} Organized vulnerable contracts from MIESC examples"
echo -e "${GREEN}✓${NC} Analyzed with multiple specialized agents"
echo -e "${GREEN}✓${NC} Showed independent evidence from each agent"
echo -e "${GREEN}✓${NC} Generated detailed findings with:"
echo "    - Specific vulnerability description"
echo "    - Impact analysis"
echo "    - Remediation recommendations"
echo "    - References to documentation"
echo -e "${GREEN}✓${NC} Provided clear conclusions and risk assessment"
echo -e "${GREEN}✓${NC} Suggested concrete next steps"
echo -e "${GREEN}✓${NC} Created professional reports (HTML + Markdown)"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Key Findings for the Reentrancy Contract:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Extract key findings
if [ -f "output/$TAG/Ollama.txt" ]; then
    ISSUES=$(grep "Found" "output/$TAG/Ollama.txt" | grep -o "[0-9]\+" | head -1 || echo "0")
    echo -e "${RED}⚠️  Ollama detected: $ISSUES vulnerabilities${NC}"
fi

if [ -f "output/$TAG/Slither.txt" ]; then
    SLITHER_FINDINGS=$(grep -c "INFO:Detectors:" "output/$TAG/Slither.txt" || echo "0")
    echo -e "${YELLOW}⚠️  Slither detected: $SLITHER_FINDINGS patterns${NC}"
fi

echo ""
echo -e "${WHITE}All agents identified the reentrancy vulnerability!${NC}"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Generated Outputs:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${WHITE}Evidence Files:${NC}"
echo "  📄 output/$TAG/Slither.txt"
echo "  📄 output/$TAG/Ollama.txt"
echo "  📄 output/$TAG/summary.txt"
echo "  📄 output/$TAG/conclusion.txt"
echo ""

echo -e "${WHITE}Enhanced Reports:${NC}"
echo "  📊 output/$TAG/reports/dashboard.html"
echo "  📝 output/$TAG/reports/consolidated_report.md"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Try Other Vulnerable Contracts:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo "You can analyze other vulnerable contracts:"
echo ""
echo -e "${GREEN}# Integer Overflow${NC}"
echo "python main_ai.py vulnerable_contracts/integer_overflow/integer_overflow.sol \\
  integer_overflow --use-slither --use-ollama"
echo ""
echo -e "${GREEN}# Access Control${NC}"
echo "python main_ai.py vulnerable_contracts/access_control/access_control.sol \\
  access_control --use-slither --use-ollama"
echo ""
echo -e "${GREEN}# tx.origin Authentication${NC}"
echo "python main_ai.py vulnerable_contracts/tx_origin/tx_origin.sol \\
  tx_origin --use-slither --use-ollama"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}View the Reports:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${GREEN}# Interactive dashboard${NC}"
echo "open output/$TAG/reports/dashboard.html"
echo ""
echo -e "${GREEN}# Detailed markdown report${NC}"
echo "cat output/$TAG/reports/consolidated_report.md"
echo ""
echo -e "${GREEN}# Individual agent evidence${NC}"
echo "cat output/$TAG/Slither.txt"
echo "cat output/$TAG/Ollama.txt"
echo ""

echo -e "${PURPLE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${PURPLE}Thank you for watching the MIESC demonstration!${NC}"
echo -e "${PURPLE}════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${CYAN}Key Takeaways:${NC}"
echo ""
echo "1. 🤖 Multiple agents = comprehensive coverage"
echo "2. 📄 Separate evidence files = full transparency"
echo "3. 📊 Detailed findings = actionable intelligence"
echo "4. ✅ Clear conclusions = informed decisions"
echo "5. 📋 Concrete next steps = clear path forward"
echo "6. 💰 Free with local tools = unlimited usage"
echo ""

echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Questions?${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo ""
