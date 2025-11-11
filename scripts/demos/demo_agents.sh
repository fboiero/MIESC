#!/bin/bash

# MIESC Demo - Multi-Agent Analysis Showcase
# Shows each agent's individual results clearly

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
║              🤖 MIESC - MULTI-AGENT ANALYSIS DEMO 🤖                     ║
║                                                                          ║
║              Demonstrating Each Security Analysis Agent                 ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
EOF

echo ""
echo -e "${CYAN}MIESC integrates multiple specialized security agents:${NC}"
echo ""
echo -e "${WHITE}Available Agents:${NC}"
echo ""
echo -e "${GREEN}✓ Slither Agent${NC}        - Static analysis (87 detectors)"
echo -e "${GREEN}✓ Mythril Agent${NC}        - Symbolic execution"
echo -e "${GREEN}✓ Aderyn Agent${NC}         - Fast Rust-based analysis"
echo -e "${GREEN}✓ Semgrep Agent${NC}        - Pattern matching"
echo -e "${GREEN}✓ Ollama Agent${NC}         - Local AI (FREE)"
echo -e "${YELLOW}○ CrewAI Agent${NC}        - Multi-agent AI (requires API key)"
echo -e "${YELLOW}○ ChatGPT Agent${NC}       - Cloud AI (requires API key)"
echo ""
echo -e "${CYAN}This demo will show results from each available agent separately${NC}"
echo ""
read -p "Press Enter to start..."

# ============================================================================
# Check Available Agents
# ============================================================================

clear
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║  Step 1: Checking Available Agents                          ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

HAS_SLITHER=false
HAS_MYTHRIL=false
HAS_ADERYN=false
HAS_SEMGREP=false
HAS_OLLAMA=false

echo -e "${CYAN}Scanning for installed security tools...${NC}"
echo ""

# Check Slither
echo -n "  [1/5] Checking Slither Agent... "
if command -v slither &> /dev/null; then
    VERSION=$(slither --version 2>&1 | head -1)
    echo -e "${GREEN}✓ Found${NC} ($VERSION)"
    HAS_SLITHER=true
else
    echo -e "${RED}✗ Not installed${NC}"
fi

# Check Mythril
echo -n "  [2/5] Checking Mythril Agent... "
if command -v myth &> /dev/null; then
    VERSION=$(myth version 2>&1 | grep "Mythril" | head -1)
    echo -e "${GREEN}✓ Found${NC}"
    HAS_MYTHRIL=true
else
    echo -e "${YELLOW}○ Not installed (optional)${NC}"
fi

# Check Aderyn
echo -n "  [3/5] Checking Aderyn Agent... "
if command -v aderyn &> /dev/null; then
    echo -e "${GREEN}✓ Found${NC}"
    HAS_ADERYN=true
else
    echo -e "${YELLOW}○ Not installed (optional)${NC}"
fi

# Check Semgrep
echo -n "  [4/5] Checking Semgrep Agent... "
if command -v semgrep &> /dev/null; then
    echo -e "${GREEN}✓ Found${NC}"
    HAS_SEMGREP=true
else
    echo -e "${YELLOW}○ Not installed (optional)${NC}"
fi

# Check Ollama
echo -n "  [5/5] Checking Ollama Agent... "
if command -v ollama &> /dev/null; then
    echo -e "${GREEN}✓ Found${NC}"
    # Check for models
    if ollama list | grep -q "codellama:7b"; then
        echo "         └─ Model: codellama:7b available"
        HAS_OLLAMA=true
    else
        echo -e "         ${YELLOW}└─ Warning: codellama:7b not found${NC}"
        echo "            Run: ollama pull codellama:7b"
    fi
else
    echo -e "${YELLOW}○ Not installed (optional)${NC}"
fi

echo ""
echo -e "${CYAN}Summary:${NC}"
AGENT_COUNT=0
[ "$HAS_SLITHER" = true ] && ((AGENT_COUNT++))
[ "$HAS_MYTHRIL" = true ] && ((AGENT_COUNT++))
[ "$HAS_ADERYN" = true ] && ((AGENT_COUNT++))
[ "$HAS_SEMGREP" = true ] && ((AGENT_COUNT++))
[ "$HAS_OLLAMA" = true ] && ((AGENT_COUNT++))

echo "  Available agents: ${AGENT_COUNT}/5"
echo ""

if [ $AGENT_COUNT -eq 0 ]; then
    echo -e "${RED}Error: No agents available. Please install at least Slither.${NC}"
    echo "  pip install slither-analyzer"
    exit 1
fi

read -p "Press Enter to continue..."

# ============================================================================
# Single Contract Analysis - Show Each Agent
# ============================================================================

clear
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║  Step 2: Single Contract - Individual Agent Results         ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

CONTRACT="examples/reentrancy_simple.sol"
TAG="demo_agents_single"

echo -e "${CYAN}Target Contract:${NC} $CONTRACT"
echo ""
echo -e "${CYAN}This contract has a known reentrancy vulnerability${NC}"
echo ""

# Show contract
echo -e "${WHITE}Contract Code:${NC}"
echo "─────────────────────────────────────────────────────────"
cat "$CONTRACT" | head -30
echo "─────────────────────────────────────────────────────────"
echo ""

echo -e "${YELLOW}Running analysis with all available agents...${NC}"
echo ""

# Build command
CMD="python main_ai.py $CONTRACT $TAG"

if [ "$HAS_SLITHER" = true ]; then
    CMD="$CMD --use-slither"
fi

if [ "$HAS_OLLAMA" = true ]; then
    CMD="$CMD --use-ollama --ollama-model codellama:7b"
fi

echo -e "${CYAN}Command:${NC}"
echo "  $CMD"
echo ""
read -p "Press Enter to run..."

# Run analysis
eval $CMD

echo ""
echo -e "${GREEN}✓ Analysis complete!${NC}"
echo ""

# ============================================================================
# Show Individual Agent Results
# ============================================================================

clear
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║  Step 3: Viewing Individual Agent Results                   ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

OUTPUT_DIR="output/$TAG"

echo -e "${CYAN}Generated outputs in: $OUTPUT_DIR${NC}"
echo ""
ls -lh "$OUTPUT_DIR/" | grep -v "^d" | tail -n +2
echo ""

# Show each agent's results
AGENT_NUM=1

# ============================================================================
# SLITHER AGENT RESULTS
# ============================================================================

if [ "$HAS_SLITHER" = true ] && [ -f "$OUTPUT_DIR/Slither.txt" ]; then
    clear
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  AGENT #${AGENT_NUM}: SLITHER - Static Analysis Engine               ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "${CYAN}What Slither Does:${NC}"
    echo "  • Static code analysis (no execution)"
    echo "  • 87 built-in vulnerability detectors"
    echo "  • Fast: analyzes in seconds"
    echo "  • Detects: reentrancy, access control, arithmetic issues"
    echo ""

    echo -e "${YELLOW}Slither Agent Results:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cat "$OUTPUT_DIR/Slither.txt" | head -50
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Count findings
    FINDINGS=$(grep -c "INFO:Detectors:" "$OUTPUT_DIR/Slither.txt" || echo "0")
    echo ""
    echo -e "${WHITE}Summary:${NC}"
    echo "  Total findings: $FINDINGS"
    echo "  Output file: $OUTPUT_DIR/Slither.txt"
    echo ""

    ((AGENT_NUM++))
    read -p "Press Enter to see next agent..."
fi

# ============================================================================
# MYTHRIL AGENT RESULTS
# ============================================================================

if [ "$HAS_MYTHRIL" = true ] && [ -f "$OUTPUT_DIR/Mythril.txt" ]; then
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  AGENT #${AGENT_NUM}: MYTHRIL - Symbolic Execution Engine            ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "${CYAN}What Mythril Does:${NC}"
    echo "  • Symbolic execution (explores all paths)"
    echo "  • Analyzes EVM bytecode"
    echo "  • Slower but more thorough"
    echo "  • Detects: complex exploits, edge cases"
    echo ""

    echo -e "${YELLOW}Mythril Agent Results:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cat "$OUTPUT_DIR/Mythril.txt"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo -e "${WHITE}Summary:${NC}"
    echo "  Output file: $OUTPUT_DIR/Mythril.txt"
    echo ""

    ((AGENT_NUM++))
    read -p "Press Enter to see next agent..."
fi

# ============================================================================
# OLLAMA AGENT RESULTS
# ============================================================================

if [ "$HAS_OLLAMA" = true ] && [ -f "$OUTPUT_DIR/Ollama.txt" ]; then
    clear
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║  AGENT #${AGENT_NUM}: OLLAMA - Local AI Analysis (CodeLlama)         ║${NC}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "${CYAN}What Ollama Does:${NC}"
    echo "  • AI-powered code analysis"
    echo "  • Runs locally (100% private)"
    echo "  • FREE - no API costs"
    echo "  • Detects: logic bugs, best practices, design issues"
    echo "  • Model: CodeLlama 7B"
    echo ""

    echo -e "${YELLOW}Ollama Agent Results:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cat "$OUTPUT_DIR/Ollama.txt"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Extract findings count
    ISSUES=$(grep "Found" "$OUTPUT_DIR/Ollama.txt" | grep -o "[0-9]\+" | head -1 || echo "0")
    echo ""
    echo -e "${WHITE}Summary:${NC}"
    echo "  Issues found: $ISSUES"
    echo "  Output file: $OUTPUT_DIR/Ollama.txt"
    echo "  Cost: $0.00 (local execution)"
    echo ""

    ((AGENT_NUM++))
    read -p "Press Enter to continue..."
fi

# ============================================================================
# Combined Summary
# ============================================================================

clear
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║  Step 4: Combined Multi-Agent Summary                       ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${CYAN}All Agent Results Combined:${NC}"
echo ""

# Create summary table
echo "┌─────────────────┬──────────────┬─────────────────────────────┐"
echo "│ Agent           │ Status       │ Key Findings                │"
echo "├─────────────────┼──────────────┼─────────────────────────────┤"

if [ "$HAS_SLITHER" = true ]; then
    FINDINGS=$(grep -c "INFO:Detectors:" "$OUTPUT_DIR/Slither.txt" || echo "0")
    echo "│ Slither         │ ✓ Completed  │ $FINDINGS findings detected     │"
fi

if [ "$HAS_MYTHRIL" = true ] && [ -f "$OUTPUT_DIR/Mythril.txt" ]; then
    echo "│ Mythril         │ ✓ Completed  │ Symbolic analysis done      │"
fi

if [ "$HAS_OLLAMA" = true ]; then
    ISSUES=$(grep "Found" "$OUTPUT_DIR/Ollama.txt" | grep -o "[0-9]\+" | head -1 || echo "0")
    echo "│ Ollama (AI)     │ ✓ Completed  │ $ISSUES issues identified       │"
fi

echo "└─────────────────┴──────────────┴─────────────────────────────┘"
echo ""

echo -e "${WHITE}Individual Evidence Files:${NC}"
echo ""
ls -1 "$OUTPUT_DIR"/*.txt 2>/dev/null | while read file; do
    AGENT=$(basename "$file" .txt)
    SIZE=$(wc -l < "$file")
    echo "  📄 $AGENT.txt ($SIZE lines)"
done

echo ""
echo -e "${CYAN}You can view each agent's detailed output:${NC}"
echo ""
if [ "$HAS_SLITHER" = true ]; then
    echo "  cat $OUTPUT_DIR/Slither.txt  # Static analysis findings"
fi
if [ "$HAS_OLLAMA" = true ]; then
    echo "  cat $OUTPUT_DIR/Ollama.txt   # AI analysis findings"
fi
if [ "$HAS_MYTHRIL" = true ] && [ -f "$OUTPUT_DIR/Mythril.txt" ]; then
    echo "  cat $OUTPUT_DIR/Mythril.txt  # Symbolic execution findings"
fi

echo ""
read -p "Press Enter to see multi-contract analysis..."

# ============================================================================
# Multi-Contract Analysis
# ============================================================================

clear
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║  Step 5: Multi-Contract Project Analysis                    ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${CYAN}Now analyzing multiple contracts with all agents:${NC}"
echo ""
echo -e "${YELLOW}Command:${NC}"
echo "  python main_project.py examples/ demo_agents_multi \\"
echo "    --visualize --use-ollama --quick --max-contracts 2"
echo ""

read -p "Press Enter to run..."

python main_project.py examples/ demo_agents_multi \
  --visualize --use-ollama --quick --max-contracts 2

echo ""
echo -e "${GREEN}✓ Multi-contract analysis complete!${NC}"
echo ""

# ============================================================================
# Show Multi-Contract Evidence
# ============================================================================

clear
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║  Step 6: Multi-Contract Evidence Structure                  ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${CYAN}Output Structure - Evidence for Each Contract:${NC}"
echo ""

tree -L 2 output/demo_agents_multi/ 2>/dev/null || ls -R output/demo_agents_multi/ | head -40

echo ""
echo -e "${CYAN}Each contract analyzed has individual agent outputs:${NC}"
echo ""

# Show first contract's evidence
FIRST_CONTRACT=$(find output/demo_agents_multi -name "*.txt" -path "*/*/Slither.txt" | head -1 | xargs dirname)
if [ -n "$FIRST_CONTRACT" ]; then
    CONTRACT_NAME=$(basename "$FIRST_CONTRACT")
    echo -e "${YELLOW}Example: $CONTRACT_NAME/${NC}"
    ls -lh "$FIRST_CONTRACT/" | grep -v "^d" | tail -n +2

    echo ""
    echo -e "${WHITE}Agent Evidence Available:${NC}"
    for file in "$FIRST_CONTRACT"/*.txt; do
        if [ -f "$file" ]; then
            AGENT=$(basename "$file" .txt)
            LINES=$(wc -l < "$file")
            echo "  📄 $AGENT: $LINES lines of analysis"
        fi
    done
fi

echo ""
read -p "Press Enter to view consolidated dashboard..."

# ============================================================================
# Open Dashboard
# ============================================================================

clear
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║  Step 7: Interactive Dashboard                              ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${CYAN}The dashboard consolidates all agent findings:${NC}"
echo ""
echo "  ✓ Slither findings (static analysis)"
echo "  ✓ Ollama findings (AI analysis)"
echo "  ✓ Mythril findings (symbolic execution)"
echo "  ✓ Severity categorization"
echo "  ✓ Detailed recommendations"
echo ""

DASHBOARD="output/demo_agents_multi/reports/dashboard.html"

if [ -f "$DASHBOARD" ]; then
    echo -e "${GREEN}Opening dashboard...${NC}"
    echo ""

    if [[ "$OSTYPE" == "darwin"* ]]; then
        open "$DASHBOARD"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        xdg-open "$DASHBOARD" 2>/dev/null || echo "Please open: $DASHBOARD"
    fi

    sleep 2
fi

echo ""
echo -e "${CYAN}Dashboard features:${NC}"
echo "  • Combined statistics from all agents"
echo "  • Color-coded by severity"
echo "  • Individual agent sections"
echo "  • Click to expand findings"
echo "  • Professional presentation"
echo ""

read -p "Press Enter for final summary..."

# ============================================================================
# Final Summary
# ============================================================================

clear
cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║                  🎉 MULTI-AGENT DEMO COMPLETE! 🎉                        ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
EOF

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}What We Demonstrated:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${GREEN}✓${NC} Multiple specialized security agents working together"
echo -e "${GREEN}✓${NC} Individual evidence files for each agent"
echo -e "${GREEN}✓${NC} Clear separation of results by agent type"
echo -e "${GREEN}✓${NC} Single contract analysis with all agents"
echo -e "${GREEN}✓${NC} Multi-contract project analysis"
echo -e "${GREEN}✓${NC} Consolidated dashboard with all findings"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Available Agents Recap:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${WHITE}Core Agents (Always Available):${NC}"
if [ "$HAS_SLITHER" = true ]; then
    echo -e "  ${GREEN}✓ Slither${NC}       - Static analysis, 87 detectors, instant"
fi

echo ""
echo -e "${WHITE}Optional Agents (Install for Enhanced Coverage):${NC}"
if [ "$HAS_MYTHRIL" = true ]; then
    echo -e "  ${GREEN}✓ Mythril${NC}       - Symbolic execution, deep analysis"
else
    echo -e "  ${YELLOW}○ Mythril${NC}       - pip install mythril"
fi

if [ "$HAS_ADERYN" = true ]; then
    echo -e "  ${GREEN}✓ Aderyn${NC}        - Ultra-fast Rust analyzer"
else
    echo -e "  ${YELLOW}○ Aderyn${NC}        - cargo install aderyn"
fi

if [ "$HAS_SEMGREP" = true ]; then
    echo -e "  ${GREEN}✓ Semgrep${NC}       - Pattern matching, custom rules"
else
    echo -e "  ${YELLOW}○ Semgrep${NC}       - pip install semgrep"
fi

echo ""
echo -e "${WHITE}AI Agents (Advanced Analysis):${NC}"
if [ "$HAS_OLLAMA" = true ]; then
    echo -e "  ${GREEN}✓ Ollama${NC}        - Local AI, FREE, private (CodeLlama)"
else
    echo -e "  ${YELLOW}○ Ollama${NC}        - Install from ollama.ai"
fi
echo -e "  ${YELLOW}○ CrewAI${NC}        - Multi-agent AI (requires API key)"
echo -e "  ${YELLOW}○ ChatGPT${NC}       - Cloud AI (requires API key)"

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Evidence Files Generated:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${WHITE}Single Contract Analysis:${NC}"
echo "  output/demo_agents_single/"
if [ "$HAS_SLITHER" = true ]; then
    echo "    ├── Slither.txt    ← Static analysis evidence"
fi
if [ "$HAS_OLLAMA" = true ]; then
    echo "    ├── Ollama.txt     ← AI analysis evidence"
fi
if [ "$HAS_MYTHRIL" = true ] && [ -f "output/demo_agents_single/Mythril.txt" ]; then
    echo "    ├── Mythril.txt    ← Symbolic execution evidence"
fi
echo "    ├── summary.txt    ← Executive summary"
echo "    └── conclusion.txt ← Final assessment"

echo ""
echo -e "${WHITE}Multi-Contract Analysis:${NC}"
echo "  output/demo_agents_multi/"
echo "    ├── reports/"
echo "    │   ├── dashboard.html           ← Consolidated view"
echo "    │   └── consolidated_report.md   ← All findings"
echo "    ├── ContractA/"
echo "    │   ├── Slither.txt    ← Evidence from Slither"
echo "    │   ├── Ollama.txt     ← Evidence from Ollama"
echo "    │   └── ..."
echo "    └── ContractB/"
echo "        └── ..."

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}View Individual Agent Results:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

if [ "$HAS_SLITHER" = true ]; then
    echo -e "${GREEN}# Slither findings:${NC}"
    echo "  cat output/demo_agents_single/Slither.txt"
    echo ""
fi

if [ "$HAS_OLLAMA" = true ]; then
    echo -e "${GREEN}# Ollama AI analysis:${NC}"
    echo "  cat output/demo_agents_single/Ollama.txt"
    echo ""
fi

if [ "$HAS_MYTHRIL" = true ]; then
    echo -e "${GREEN}# Mythril symbolic execution:${NC}"
    echo "  cat output/demo_agents_single/Mythril.txt"
    echo ""
fi

echo -e "${GREEN}# Interactive dashboard (all agents combined):${NC}"
echo "  open output/demo_agents_multi/reports/dashboard.html"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Next Steps:${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo "1. Review individual agent outputs in output/ directories"
echo "2. Compare findings from different agents"
echo "3. Install additional agents for more coverage"
echo "4. Analyze your own contracts"
echo "5. Share evidence files with your team"
echo ""

echo -e "${PURPLE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${PURPLE}Thank you for exploring MIESC's multi-agent architecture!${NC}"
echo -e "${PURPLE}════════════════════════════════════════════════════════════════${NC}"
echo ""
