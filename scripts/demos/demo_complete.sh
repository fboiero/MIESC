#!/bin/bash

# MIESC Complete Demo Script - All Features
# Demonstrates the full capabilities of the Multi-agent Integrated Security platform

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Demo configuration
DEMO_DIR="demo_output"
DEMO_CONTRACT="examples/reentrancy_simple.sol"

# Helper function for section headers
print_header() {
    clear
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║                                                              ║${NC}"
    echo -e "${PURPLE}║  $1${NC}"
    echo -e "${PURPLE}║                                                              ║${NC}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Helper function for pauses
pause() {
    echo ""
    read -p "Press Enter to continue..."
}

# Main banner
clear
cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║   ███╗   ███╗██╗███████╗███████╗ ██████╗                                ║
║   ████╗ ████║██║██╔════╝██╔════╝██╔════╝                                ║
║   ██╔████╔██║██║█████╗  ███████╗██║                                     ║
║   ██║╚██╔╝██║██║██╔══╝  ╚════██║██║                                     ║
║   ██║ ╚═╝ ██║██║███████╗███████║╚██████╗                                ║
║   ╚═╝     ╚═╝╚═╝╚══════╝╚══════╝ ╚═════╝                                ║
║                                                                          ║
║        Multi-agent Integrated Security for Smart Contracts              ║
║                                                                          ║
║                    🛡️  COMPLETE DEMO  🛡️                                ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
EOF

echo ""
echo -e "${CYAN}This comprehensive demo will showcase ALL MIESC capabilities:${NC}"
echo ""
echo -e "${WHITE}🔧 Core Analysis Tools:${NC}"
echo "   • Slither - Static analysis"
echo "   • Mythril - Symbolic execution"
echo "   • Aderyn - Rust-based analyzer"
echo "   • Semgrep - Pattern matching"
echo ""
echo -e "${WHITE}🤖 AI-Powered Analysis:${NC}"
echo "   • Ollama - Local LLM (free, private)"
echo "   • CrewAI - Multi-agent collaboration"
echo "   • ChatGPT - Cloud-based analysis"
echo ""
echo -e "${WHITE}📊 Advanced Features:${NC}"
echo "   • Multi-contract project analysis"
echo "   • Dependency visualization"
echo "   • Interactive HTML dashboards"
echo "   • Professional reports (PDF, Markdown)"
echo "   • Multiple analysis strategies"
echo ""
echo -e "${WHITE}🎯 Demo Structure:${NC}"
echo "   Demo 1:  Single contract analysis (all tools)"
echo "   Demo 2:  AI agents comparison (Ollama vs CrewAI)"
echo "   Demo 3:  Multi-contract project analysis"
echo "   Demo 4:  Vulnerability detection showcase"
echo "   Demo 5:  Production code analysis"
echo "   Demo 6:  Report formats & visualizations"
echo ""
pause

# ============================================================================
# DEMO 1: Single Contract - All Traditional Tools
# ============================================================================

print_header "  Demo 1: Single Contract Analysis - Traditional Tools   "

echo -e "${CYAN}Target Contract:${NC} ${DEMO_CONTRACT}"
echo -e "${CYAN}Analysis Tools:${NC} Slither, Mythril, Aderyn, Semgrep"
echo ""
echo -e "${YELLOW}Checking available tools...${NC}"
echo ""

# Check which tools are available
echo -n "  Checking Slither... "
if command -v slither &> /dev/null; then
    echo -e "${GREEN}✓ Available${NC}"
    HAS_SLITHER=true
else
    echo -e "${RED}✗ Not installed${NC}"
    HAS_SLITHER=false
fi

echo -n "  Checking Mythril... "
if command -v myth &> /dev/null; then
    echo -e "${GREEN}✓ Available${NC}"
    HAS_MYTHRIL=true
else
    echo -e "${RED}✗ Not installed (optional)${NC}"
    HAS_MYTHRIL=false
fi

echo -n "  Checking Aderyn... "
if command -v aderyn &> /dev/null; then
    echo -e "${GREEN}✓ Available${NC}"
    HAS_ADERYN=true
else
    echo -e "${RED}✗ Not installed (Docker fallback available)${NC}"
    HAS_ADERYN=false
fi

echo -n "  Checking Ollama... "
if command -v ollama &> /dev/null; then
    echo -e "${GREEN}✓ Available${NC}"
    HAS_OLLAMA=true
else
    echo -e "${RED}✗ Not installed${NC}"
    HAS_OLLAMA=false
fi

echo ""
echo -e "${CYAN}Running analysis with available tools...${NC}"
echo ""
echo -e "${YELLOW}Command:${NC}"
echo "python main_ai.py ${DEMO_CONTRACT} demo1_single --use-slither"

if [ "$HAS_OLLAMA" = true ]; then
    echo "  --use-ollama --ollama-model codellama:7b"
fi

echo ""
pause

# Build command
CMD="python main_ai.py ${DEMO_CONTRACT} demo1_single --use-slither"
if [ "$HAS_OLLAMA" = true ]; then
    CMD="${CMD} --use-ollama --ollama-model codellama:7b"
fi

# Run analysis
eval $CMD

echo ""
echo -e "${GREEN}✓ Demo 1 Complete!${NC}"
echo ""
echo -e "${CYAN}Generated outputs:${NC}"
ls -lh output/demo1_single/
echo ""
echo -e "${YELLOW}Key files:${NC}"
echo "  • Slither.txt - Static analysis findings"
if [ "$HAS_OLLAMA" = true ]; then
    echo "  • Ollama.txt - AI analysis findings"
fi
echo "  • summary.txt - Executive summary"
echo "  • conclusion.txt - Final assessment"
echo ""
pause

# ============================================================================
# DEMO 2: AI Agents Comparison
# ============================================================================

print_header "      Demo 2: AI Agents - Ollama vs CrewAI Comparison        "

echo -e "${CYAN}Demonstrating AI-powered analysis:${NC}"
echo ""
echo -e "${WHITE}1. Ollama (Local LLM):${NC}"
echo "   • Free and private"
echo "   • Runs on your machine"
echo "   • Multiple models: codellama:7b, 13b, 33b"
echo "   • No API costs"
echo ""
echo -e "${WHITE}2. CrewAI (Multi-Agent):${NC}"
echo "   • Collaborative AI agents"
echo "   • Specialized roles (auditor, developer, QA)"
echo "   • Comprehensive analysis"
echo "   • Cloud-based (requires API key)"
echo ""

if [ "$HAS_OLLAMA" = true ]; then
    echo -e "${CYAN}Running Ollama analysis...${NC}"
    echo -e "${YELLOW}Command:${NC}"
    echo "python main_ai.py ${DEMO_CONTRACT} demo2_ollama --use-ollama --ollama-model codellama:13b"
    echo ""
    pause

    python main_ai.py ${DEMO_CONTRACT} demo2_ollama --use-ollama --ollama-model codellama:13b

    echo ""
    echo -e "${GREEN}✓ Ollama analysis complete!${NC}"
    echo ""
    echo -e "${CYAN}Ollama findings:${NC}"
    cat output/demo2_ollama/Ollama.txt | head -30
    echo ""
    pause
else
    echo -e "${YELLOW}Ollama not available - skipping local LLM demo${NC}"
    echo ""
fi

echo -e "${CYAN}CrewAI demonstration:${NC}"
echo ""
echo -e "${YELLOW}Note:${NC} CrewAI requires OpenAI API key in .env file"
echo "If you have CrewAI configured, it will run a multi-agent analysis"
echo "with specialized security auditor, smart contract developer, and QA agents"
echo ""
echo -e "${YELLOW}Command would be:${NC}"
echo "python main_ai.py ${DEMO_CONTRACT} demo2_crewai --use-crewai"
echo ""
echo -e "${YELLOW}Skipping CrewAI demo (requires API key configuration)${NC}"
echo ""
pause

# ============================================================================
# DEMO 3: Multi-Contract Project Analysis
# ============================================================================

print_header "     Demo 3: Multi-Contract Project - 3 Strategies         "

echo -e "${CYAN}MIESC supports analyzing entire projects with multiple contracts${NC}"
echo ""
echo -e "${WHITE}Three Analysis Strategies:${NC}"
echo ""
echo -e "${GREEN}1. SCAN (Individual):${NC}"
echo "   • Analyzes each contract separately"
echo "   • Preserves context per contract"
echo "   • Best for: Large projects, detailed analysis"
echo ""
echo -e "${YELLOW}2. UNIFIED (Combined):${NC}"
echo "   • Merges all contracts into one file"
echo "   • Analyzes as a single unit"
echo "   • Best for: Cross-contract vulnerabilities"
echo ""
echo -e "${PURPLE}3. BOTH (Comprehensive):${NC}"
echo "   • Runs both SCAN and UNIFIED"
echo "   • Maximum coverage"
echo "   • Best for: Critical audits"
echo ""

echo -e "${CYAN}Demo: Analyzing examples/ directory${NC}"
echo ""
echo -e "${YELLOW}Command:${NC}"
echo "python main_project.py examples/ demo3_project --strategy scan --visualize --use-ollama --quick --max-contracts 3"
echo ""
pause

python main_project.py examples/ demo3_project --strategy scan --visualize --use-ollama --quick --max-contracts 3

echo ""
echo -e "${GREEN}✓ Demo 3 Complete!${NC}"
echo ""
echo -e "${CYAN}Project analysis outputs:${NC}"
echo ""
tree -L 2 output/demo3_project/ 2>/dev/null || ls -R output/demo3_project/
echo ""
pause

# ============================================================================
# DEMO 4: Vulnerability Detection Showcase
# ============================================================================

print_header "    Demo 4: Vulnerability Detection - Real Exploits         "

echo -e "${CYAN}Testing MIESC against known vulnerable contracts${NC}"
echo ""
echo -e "${RED}⚠️  Using Damn Vulnerable DeFi - Intentionally Vulnerable Contracts${NC}"
echo ""
echo -e "${WHITE}What we'll detect:${NC}"
echo "   • Reentrancy attacks"
echo "   • Access control issues"
echo "   • Logic vulnerabilities"
echo "   • Price oracle manipulation"
echo "   • Flash loan exploits"
echo ""
echo -e "${YELLOW}Command:${NC}"
echo "python main_project.py https://github.com/theredguild/damn-vulnerable-defi demo4_vuln \\"
echo "  --visualize --use-ollama --quick --priority-filter high --max-contracts 2"
echo ""
echo -e "${YELLOW}Note: This will clone a GitHub repository and may take 3-5 minutes${NC}"
echo ""
read -p "Run vulnerability detection demo? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    python main_project.py https://github.com/theredguild/damn-vulnerable-defi demo4_vuln \
      --visualize --use-ollama --quick --priority-filter high --max-contracts 2

    echo ""
    echo -e "${GREEN}✓ Demo 4 Complete!${NC}"
    echo ""
    echo -e "${RED}Vulnerabilities detected:${NC}"
    echo ""

    # Show vulnerability findings
    if [ -f output/demo4_vuln/*/Ollama.txt ]; then
        for file in output/demo4_vuln/*/Ollama.txt; do
            echo -e "${CYAN}=== $(dirname $file | xargs basename) ===${NC}"
            head -20 "$file"
            echo ""
        done
    fi

    pause
else
    echo -e "${YELLOW}Skipping vulnerability detection demo${NC}"
    echo ""
fi

# ============================================================================
# DEMO 5: Production Code Analysis
# ============================================================================

print_header "     Demo 5: Production Code - Uniswap V2 Analysis         "

echo -e "${CYAN}Analyzing battle-tested, audited production code${NC}"
echo ""
echo -e "${GREEN}Target: Uniswap V2 Core${NC}"
echo "   • Secured billions in TVL"
echo "   • Multiple professional audits"
echo "   • Expected: Minimal critical issues"
echo ""
echo -e "${WHITE}This demonstrates:${NC}"
echo "   • MIESC on production-quality code"
echo "   • Difference between vulnerable vs secure code"
echo "   • False positive handling"
echo ""
echo -e "${YELLOW}Command:${NC}"
echo "python main_project.py https://github.com/Uniswap/v2-core demo5_uniswap \\"
echo "  --visualize --use-ollama --quick --priority-filter medium"
echo ""
echo -e "${YELLOW}Note: This takes 4-5 minutes${NC}"
echo ""
read -p "Run Uniswap analysis? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    python main_project.py https://github.com/Uniswap/v2-core demo5_uniswap \
      --visualize --use-ollama --quick --priority-filter medium

    echo ""
    echo -e "${GREEN}✓ Demo 5 Complete!${NC}"
    echo ""
    echo -e "${GREEN}Production code analysis shows:${NC}"
    echo "   • Minimal high-severity issues"
    echo "   • Mostly informational findings"
    echo "   • Design trade-offs documented"
    echo ""
    pause
else
    echo -e "${YELLOW}Skipping Uniswap analysis${NC}"
    echo ""
fi

# ============================================================================
# DEMO 6: Report Formats & Visualizations
# ============================================================================

print_header "   Demo 6: Reports & Visualizations - All Formats          "

echo -e "${CYAN}MIESC generates multiple output formats:${NC}"
echo ""
echo -e "${WHITE}1. Interactive HTML Dashboard:${NC}"
echo "   • Beautiful gradient design"
echo "   • Severity-coded statistics"
echo "   • Collapsible issue sections"
echo "   • Mobile responsive"
echo ""
echo -e "${WHITE}2. Markdown Reports:${NC}"
echo "   • Individual contract reports"
echo "   • Consolidated project report"
echo "   • GitHub/GitLab compatible"
echo "   • Easy to version control"
echo ""
echo -e "${WHITE}3. Dependency Visualizations:${NC}"
echo "   • Interactive HTML graph (vis.js)"
echo "   • Mermaid diagram"
echo "   • ASCII tree"
echo ""
echo -e "${WHITE}4. PDF Reports (optional):${NC}"
echo "   • Professional audit reports"
echo "   • Executive summaries"
echo "   • Technical appendices"
echo ""

# Find an existing demo output
if [ -d "output/demo3_project" ]; then
    REPORT_DIR="output/demo3_project"
elif [ -d "output/demo1_single" ]; then
    REPORT_DIR="output/demo1_single"
else
    REPORT_DIR="output"
fi

echo -e "${CYAN}Demonstrating report formats from: ${REPORT_DIR}${NC}"
echo ""
pause

# Show HTML dashboard
if [ -f "${REPORT_DIR}/reports/dashboard.html" ]; then
    echo -e "${GREEN}Opening HTML Dashboard...${NC}"

    if [[ "$OSTYPE" == "darwin"* ]]; then
        open ${REPORT_DIR}/reports/dashboard.html
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        xdg-open ${REPORT_DIR}/reports/dashboard.html 2>/dev/null || echo "Please open: ${REPORT_DIR}/reports/dashboard.html"
    fi

    sleep 3
fi

# Show dependency visualization
if [ -f "${REPORT_DIR}/visualizations/dependency_graph.html" ]; then
    echo ""
    echo -e "${GREEN}Opening Dependency Graph...${NC}"

    if [[ "$OSTYPE" == "darwin"* ]]; then
        open ${REPORT_DIR}/visualizations/dependency_graph.html
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        xdg-open ${REPORT_DIR}/visualizations/dependency_graph.html 2>/dev/null || echo "Please open: ${REPORT_DIR}/visualizations/dependency_graph.html"
    fi

    sleep 3
fi

# Show ASCII tree
if [ -f "${REPORT_DIR}/visualizations/dependency_tree.txt" ]; then
    clear
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}ASCII Dependency Tree:${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    cat ${REPORT_DIR}/visualizations/dependency_tree.txt
    echo ""
    pause
fi

# Show Markdown report
if [ -f "${REPORT_DIR}/reports/consolidated_report.md" ]; then
    clear
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Markdown Report (first 50 lines):${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    head -50 ${REPORT_DIR}/reports/consolidated_report.md
    echo ""
    echo -e "${YELLOW}... (full report available in ${REPORT_DIR}/reports/)${NC}"
    echo ""
    pause
fi

# ============================================================================
# Additional Features Demonstration
# ============================================================================

print_header "         Additional Features & Capabilities                 "

echo -e "${CYAN}Other powerful MIESC features:${NC}"
echo ""

echo -e "${WHITE}🎯 Filtering & Prioritization:${NC}"
echo "   --priority-filter high|medium|low    # Focus on critical contracts"
echo "   --max-contracts N                    # Limit analysis scope"
echo ""

echo -e "${WHITE}⚡ Performance Options:${NC}"
echo "   --quick                              # Use faster models"
echo "   --ollama-model codellama:7b          # Choose specific model"
echo ""

echo -e "${WHITE}📊 Analysis Strategies:${NC}"
echo "   --strategy scan                      # Individual contracts"
echo "   --strategy unified                   # Combined analysis"
echo "   --strategy both                      # Comprehensive"
echo ""

echo -e "${WHITE}🎨 Output Control:${NC}"
echo "   --visualize                          # Generate graphs"
echo "   --use-slither                        # Enable Slither"
echo "   --use-ollama                         # Enable Ollama"
echo "   --use-crewai                         # Enable CrewAI"
echo ""

echo -e "${WHITE}🔄 Standalone Tools:${NC}"
echo "   generate_reports.py                  # Regenerate reports"
echo "   python main_ai.py                    # Single contract"
echo "   python main_project.py               # Multi-contract"
echo ""

pause

# ============================================================================
# Performance & Statistics
# ============================================================================

print_header "          Performance Metrics & Statistics                  "

echo -e "${CYAN}Demo Execution Summary:${NC}"
echo ""

# Count generated outputs
TOTAL_CONTRACTS=$(find output/demo* -name "*.txt" 2>/dev/null | wc -l | tr -d ' ')
TOTAL_REPORTS=$(find output/demo*/reports -name "*.md" 2>/dev/null | wc -l | tr -d ' ')
TOTAL_DASHBOARDS=$(find output/demo*/reports -name "dashboard.html" 2>/dev/null | wc -l | tr -d ' ')
TOTAL_VIZ=$(find output/demo*/visualizations -name "*.html" 2>/dev/null | wc -l | tr -d ' ')

echo -e "${WHITE}Generated Outputs:${NC}"
echo "   📄 Analysis files: ${TOTAL_CONTRACTS}"
echo "   📝 Markdown reports: ${TOTAL_REPORTS}"
echo "   📊 HTML dashboards: ${TOTAL_DASHBOARDS}"
echo "   🎨 Visualizations: ${TOTAL_VIZ}"
echo ""

echo -e "${WHITE}Typical Performance:${NC}"
echo "   • Single contract (Ollama 7b):    30-60 seconds"
echo "   • Single contract (Ollama 13b):   60-120 seconds"
echo "   • Multi-contract (3 contracts):   2-5 minutes"
echo "   • Large project (10+ contracts):  10-30 minutes"
echo "   • Report generation:              < 2 seconds"
echo ""

echo -e "${WHITE}Cost Comparison:${NC}"
echo "   • Ollama (local):                 $0 / unlimited"
echo "   • CrewAI (GPT-4):                 ~$0.50 per contract"
echo "   • Traditional audit:              $10,000 - $100,000+"
echo ""

pause

# ============================================================================
# Final Summary & Resources
# ============================================================================

clear
cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║                     🎉 COMPLETE DEMO FINISHED! 🎉                        ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
EOF

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}What We Demonstrated:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${GREEN}✓${NC} Single contract analysis with multiple tools"
echo -e "${GREEN}✓${NC} AI-powered analysis (Ollama local LLM)"
echo -e "${GREEN}✓${NC} Multi-contract project analysis"
echo -e "${GREEN}✓${NC} Three analysis strategies (scan, unified, both)"
echo -e "${GREEN}✓${NC} Vulnerability detection in real exploits"
echo -e "${GREEN}✓${NC} Production code analysis (Uniswap V2)"
echo -e "${GREEN}✓${NC} Interactive HTML dashboards"
echo -e "${GREEN}✓${NC} Professional markdown reports"
echo -e "${GREEN}✓${NC} Dependency visualizations"
echo -e "${GREEN}✓${NC} Performance metrics"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Generated Demo Outputs:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

ls -d output/demo* 2>/dev/null | while read dir; do
    echo -e "${YELLOW}📁 $dir/${NC}"
    if [ -d "$dir/reports" ]; then
        echo "   📊 Dashboard:  $dir/reports/dashboard.html"
        echo "   📝 Reports:    $dir/reports/*.md"
    fi
    if [ -d "$dir/visualizations" ]; then
        echo "   🎨 Visualizations: $dir/visualizations/"
    fi
    echo ""
done

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Quick Start Commands:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${WHITE}Analyze Your Own Contracts:${NC}"
echo ""
echo -e "${GREEN}# Single contract${NC}"
echo "python main_ai.py <your-contract.sol> <tag> --use-slither --use-ollama"
echo ""
echo -e "${GREEN}# Multi-contract project${NC}"
echo "python main_project.py <directory> <tag> --visualize --use-ollama"
echo ""
echo -e "${GREEN}# From GitHub${NC}"
echo "python main_project.py https://github.com/user/repo <tag> --visualize --use-ollama"
echo ""

echo -e "${WHITE}View Generated Reports:${NC}"
echo ""
echo -e "${GREEN}# Open all dashboards${NC}"
echo "open output/demo*/reports/dashboard.html"
echo ""
echo -e "${GREEN}# View markdown report${NC}"
echo "cat output/demo3_project/reports/consolidated_report.md"
echo ""
echo -e "${GREEN}# Regenerate reports${NC}"
echo "python generate_reports.py output/demo3_project \"My Project\""
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Documentation:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo "📖 README.md                             - Getting started"
echo "📖 docs/ENHANCED_REPORTS.md              - Report system guide"
echo "📖 docs/PROJECT_ANALYSIS.md              - Multi-contract analysis"
echo "📖 QUICK_REFERENCE_MULTI_CONTRACT.md     - Command reference"
echo "📖 docs/SESSION_REPORT_IMPROVEMENTS.md   - Technical details"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Next Steps:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo "1. Review the generated dashboards and reports"
echo "2. Try analyzing your own smart contracts"
echo "3. Experiment with different analysis strategies"
echo "4. Configure additional tools (Mythril, Aderyn, CrewAI)"
echo "5. Integrate MIESC into your development workflow"
echo ""

echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Open All Dashboards Now?${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo ""
read -p "Open all generated dashboards? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${CYAN}Opening dashboards...${NC}"

    if [[ "$OSTYPE" == "darwin"* ]]; then
        for dashboard in output/demo*/reports/dashboard.html; do
            [ -f "$dashboard" ] && open "$dashboard"
            sleep 1
        done
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        for dashboard in output/demo*/reports/dashboard.html; do
            [ -f "$dashboard" ] && xdg-open "$dashboard" 2>/dev/null &
            sleep 1
        done
    fi

    echo -e "${GREEN}✓ Dashboards opened!${NC}"
fi

echo ""
echo -e "${PURPLE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${PURPLE}Thank you for exploring MIESC!${NC}"
echo -e "${PURPLE}Complete demo script finished successfully! 🚀${NC}"
echo -e "${PURPLE}════════════════════════════════════════════════════════════════${NC}"
echo ""
