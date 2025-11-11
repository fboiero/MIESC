#!/bin/bash

# MIESC Demo Script - Enhanced Reporting System
# Demonstrates multi-contract analysis and interactive reporting

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Demo banner
clear
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║                                                              ║${NC}"
echo -e "${PURPLE}║          🛡️  MIESC - Enhanced Reporting Demo  🛡️            ║${NC}"
echo -e "${PURPLE}║                                                              ║${NC}"
echo -e "${PURPLE}║  Multi-agent Integrated Security for Smart Contracts        ║${NC}"
echo -e "${PURPLE}║                                                              ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}This demo will showcase:${NC}"
echo -e "  ✨ Multi-contract project analysis"
echo -e "  🔍 Vulnerability detection with Ollama AI"
echo -e "  📊 Interactive HTML dashboards"
echo -e "  📝 Professional markdown reports"
echo -e "  🎨 Dependency visualizations"
echo ""
read -p "Press Enter to start the demo..."

# ============================================================================
# DEMO 1: Quick Analysis - Local Examples
# ============================================================================

clear
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Demo 1: Quick Analysis - Local Contracts                   ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Analyzing local example contracts with:${NC}"
echo -e "  • Fast analysis (codellama:7b)"
echo -e "  • Dependency visualization"
echo -e "  • Automated reporting"
echo ""
echo -e "${YELLOW}Command:${NC}"
echo "python main_project.py examples/ demo_local --visualize --use-ollama --quick --max-contracts 3"
echo ""
read -p "Press Enter to run..."

python main_project.py examples/ demo_local --visualize --use-ollama --quick --max-contracts 3

echo ""
echo -e "${GREEN}✓ Demo 1 Complete!${NC}"
echo ""
echo -e "${CYAN}Generated files:${NC}"
ls -lh output/demo_local/reports/ 2>/dev/null || echo "Reports directory created"
echo ""
read -p "Press Enter to view the dashboard..."

# Open dashboard
if [[ "$OSTYPE" == "darwin"* ]]; then
    open output/demo_local/reports/dashboard.html
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    xdg-open output/demo_local/reports/dashboard.html 2>/dev/null || echo "Please open: output/demo_local/reports/dashboard.html"
else
    echo -e "${YELLOW}Please open: output/demo_local/reports/dashboard.html${NC}"
fi

sleep 3
read -p "Press Enter to continue to Demo 2..."

# ============================================================================
# DEMO 2: Vulnerability Detection - Intentionally Vulnerable Contracts
# ============================================================================

clear
echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║  Demo 2: Vulnerability Detection                            ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Analyzing intentionally vulnerable contracts:${NC}"
echo -e "  🎯 Repository: Damn Vulnerable DeFi"
echo -e "  🔍 Focus: High-priority contracts only"
echo -e "  🤖 AI: Ollama codellama:7b"
echo ""
echo -e "${YELLOW}Command:${NC}"
echo "python main_project.py https://github.com/theredguild/damn-vulnerable-defi demo_vulnerable \\"
echo "  --visualize --use-ollama --quick --priority-filter high --max-contracts 2"
echo ""
echo -e "${YELLOW}Note: This will clone the repository and may take 3-5 minutes...${NC}"
read -p "Press Enter to run (or Ctrl+C to skip)..."

python main_project.py https://github.com/theredguild/damn-vulnerable-defi demo_vulnerable \
  --visualize --use-ollama --quick --priority-filter high --max-contracts 2

echo ""
echo -e "${GREEN}✓ Demo 2 Complete!${NC}"
echo ""
echo -e "${RED}Vulnerabilities should be detected in the dashboard!${NC}"
echo ""
read -p "Press Enter to view the vulnerability dashboard..."

# Open vulnerability dashboard
if [[ "$OSTYPE" == "darwin"* ]]; then
    open output/demo_vulnerable/reports/dashboard.html
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    xdg-open output/demo_vulnerable/reports/dashboard.html 2>/dev/null || echo "Please open: output/demo_vulnerable/reports/dashboard.html"
else
    echo -e "${YELLOW}Please open: output/demo_vulnerable/reports/dashboard.html${NC}"
fi

sleep 3
read -p "Press Enter to continue to Demo 3..."

# ============================================================================
# DEMO 3: Production Code Analysis
# ============================================================================

clear
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Demo 3: Production Code - Uniswap V2                       ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Analyzing production-grade, audited smart contracts:${NC}"
echo -e "  🏆 Repository: Uniswap V2 Core"
echo -e "  ✅ Status: Audited, production-ready"
echo -e "  🔍 Expected: Few to no critical issues"
echo ""
echo -e "${YELLOW}Command:${NC}"
echo "python main_project.py https://github.com/Uniswap/v2-core demo_uniswap \\"
echo "  --visualize --use-ollama --quick --priority-filter medium"
echo ""
echo -e "${YELLOW}Note: This will take 4-5 minutes...${NC}"
read -p "Press Enter to run (or Ctrl+C to skip)..."

python main_project.py https://github.com/Uniswap/v2-core demo_uniswap \
  --visualize --use-ollama --quick --priority-filter medium

echo ""
echo -e "${GREEN}✓ Demo 3 Complete!${NC}"
echo ""
echo -e "${CYAN}Production code should show minimal critical issues!${NC}"
echo ""
read -p "Press Enter to view the Uniswap dashboard..."

# Open Uniswap dashboard
if [[ "$OSTYPE" == "darwin"* ]]; then
    open output/demo_uniswap/reports/dashboard.html
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    xdg-open output/demo_uniswap/reports/dashboard.html 2>/dev/null || echo "Please open: output/demo_uniswap/reports/dashboard.html"
else
    echo -e "${YELLOW}Please open: output/demo_uniswap/reports/dashboard.html${NC}"
fi

sleep 3
read -p "Press Enter to continue to Demo 4..."

# ============================================================================
# DEMO 4: Report Regeneration
# ============================================================================

clear
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║  Demo 4: Standalone Report Generation                       ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Regenerating enhanced reports from existing analysis:${NC}"
echo -e "  📊 Feature: Standalone report generator"
echo -e "  🔄 Use case: Update reports without re-running analysis"
echo -e "  ⚡ Speed: Instant (< 2 seconds)"
echo ""
echo -e "${YELLOW}Command:${NC}"
echo "python generate_reports.py output/demo_local \"MIESC Local Demo\""
echo ""
read -p "Press Enter to run..."

python generate_reports.py output/demo_local "MIESC Local Demo"

echo ""
echo -e "${GREEN}✓ Demo 4 Complete!${NC}"
echo ""
echo -e "${CYAN}Reports regenerated successfully!${NC}"
echo ""
sleep 2

# ============================================================================
# DEMO 5: Visualizations
# ============================================================================

clear
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Demo 5: Dependency Visualizations                          ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}MIESC generates multiple visualization formats:${NC}"
echo ""
echo -e "  1. ${GREEN}Interactive HTML${NC} - vis.js powered graph"
echo -e "  2. ${YELLOW}Mermaid Diagram${NC} - GitHub/GitLab compatible"
echo -e "  3. ${BLUE}ASCII Tree${NC} - Console-friendly view"
echo ""
echo -e "${YELLOW}Available visualizations:${NC}"
ls -lh output/demo_local/visualizations/ 2>/dev/null
echo ""
read -p "Press Enter to view interactive dependency graph..."

# Open dependency graph
if [[ "$OSTYPE" == "darwin"* ]]; then
    open output/demo_local/visualizations/dependency_graph.html
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    xdg-open output/demo_local/visualizations/dependency_graph.html 2>/dev/null || echo "Please open: output/demo_local/visualizations/dependency_graph.html"
else
    echo -e "${YELLOW}Please open: output/demo_local/visualizations/dependency_graph.html${NC}"
fi

sleep 3
read -p "Press Enter to view ASCII tree..."

clear
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}ASCII Dependency Tree:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
cat output/demo_local/visualizations/dependency_tree.txt
echo ""
read -p "Press Enter to continue..."

# ============================================================================
# Final Summary
# ============================================================================

clear
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║                                                              ║${NC}"
echo -e "${PURPLE}║                  🎉 Demo Complete! 🎉                        ║${NC}"
echo -e "${PURPLE}║                                                              ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Summary of what we demonstrated:${NC}"
echo ""
echo -e "${GREEN}✓${NC} Multi-contract project analysis"
echo -e "${GREEN}✓${NC} Vulnerability detection in intentionally vulnerable code"
echo -e "${GREEN}✓${NC} Production code analysis (Uniswap V2)"
echo -e "${GREEN}✓${NC} Interactive HTML dashboards"
echo -e "${GREEN}✓${NC} Professional markdown reports"
echo -e "${GREEN}✓${NC} Dependency visualizations (HTML, Mermaid, ASCII)"
echo -e "${GREEN}✓${NC} Standalone report generation"
echo ""
echo -e "${CYAN}Generated Outputs:${NC}"
echo ""
echo "📁 output/demo_local/        - Local examples analysis"
echo "📁 output/demo_vulnerable/   - Vulnerable contracts (DVD)"
echo "📁 output/demo_uniswap/      - Production code (Uniswap)"
echo ""
echo -e "${CYAN}Key Files to Review:${NC}"
echo ""
echo "📊 */reports/dashboard.html           - Interactive dashboard"
echo "📝 */reports/consolidated_report.md   - Complete findings"
echo "🎨 */visualizations/dependency_graph.html - Dependencies"
echo ""
echo -e "${YELLOW}Quick Commands:${NC}"
echo ""
echo "# Open all dashboards"
echo -e "${GREEN}open output/demo_*/reports/dashboard.html${NC}"
echo ""
echo "# View a markdown report"
echo -e "${GREEN}cat output/demo_local/reports/consolidated_report.md${NC}"
echo ""
echo "# Analyze your own contracts"
echo -e "${GREEN}python main_project.py <your-contracts> <tag> --visualize --use-ollama${NC}"
echo ""
echo -e "${CYAN}Documentation:${NC}"
echo ""
echo "📖 docs/ENHANCED_REPORTS.md              - Complete feature guide"
echo "📖 docs/PROJECT_ANALYSIS.md              - Multi-contract analysis"
echo "📖 QUICK_REFERENCE_MULTI_CONTRACT.md     - Command reference"
echo "📖 docs/SESSION_REPORT_IMPROVEMENTS.md   - Implementation details"
echo ""
echo -e "${PURPLE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${PURPLE}Thank you for watching the MIESC demo!${NC}"
echo -e "${PURPLE}════════════════════════════════════════════════════════════════${NC}"
echo ""

# Optional: Open all dashboards
echo -e "${YELLOW}Would you like to open all generated dashboards? (y/n)${NC}"
read -p "> " open_all

if [[ "$open_all" == "y" || "$open_all" == "Y" ]]; then
    echo -e "${CYAN}Opening all dashboards...${NC}"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        open output/demo_local/reports/dashboard.html 2>/dev/null
        sleep 1
        open output/demo_vulnerable/reports/dashboard.html 2>/dev/null
        sleep 1
        open output/demo_uniswap/reports/dashboard.html 2>/dev/null
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        xdg-open output/demo_local/reports/dashboard.html 2>/dev/null &
        sleep 1
        xdg-open output/demo_vulnerable/reports/dashboard.html 2>/dev/null &
        sleep 1
        xdg-open output/demo_uniswap/reports/dashboard.html 2>/dev/null &
    else
        echo -e "${YELLOW}Please manually open:${NC}"
        echo "  - output/demo_local/reports/dashboard.html"
        echo "  - output/demo_vulnerable/reports/dashboard.html"
        echo "  - output/demo_uniswap/reports/dashboard.html"
    fi
    echo -e "${GREEN}✓ Dashboards opened!${NC}"
fi

echo ""
echo -e "${CYAN}Demo script completed successfully! 🚀${NC}"
echo ""
