#!/bin/bash

# Quick test script to verify demo is ready
# Run this before your presentation to ensure everything works

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  MIESC Demo Pre-Flight Check               ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
echo ""

# Test 1: Check Ollama
echo -e "${YELLOW}[1/7]${NC} Checking Ollama..."
if command -v ollama &> /dev/null; then
    if ollama list | grep -q "codellama"; then
        echo -e "  ${GREEN}✓${NC} Ollama installed with CodeLlama model"
    else
        echo -e "  ${YELLOW}⚠${NC}  Ollama installed but CodeLlama not found"
        echo "      Run: ollama pull codellama:13b"
    fi
else
    echo -e "  ${YELLOW}⚠${NC}  Ollama not installed (optional for demo)"
fi

# Test 2: Check Slither
echo -e "${YELLOW}[2/7]${NC} Checking Slither..."
if command -v slither &> /dev/null; then
    echo -e "  ${GREEN}✓${NC} Slither installed: $(slither --version 2>&1 | head -1)"
else
    echo -e "  ${RED}✗${NC} Slither not installed"
    echo "      Run: pip install slither-analyzer"
    exit 1
fi

# Test 3: Check Foundry
echo -e "${YELLOW}[3/7]${NC} Checking Foundry..."
if command -v forge &> /dev/null; then
    if forge config --json &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} Foundry config valid"
    else
        echo -e "  ${RED}✗${NC} Foundry config error"
        exit 1
    fi
else
    echo -e "  ${YELLOW}⚠${NC}  Foundry not installed (optional)"
fi

# Test 4: Check examples
echo -e "${YELLOW}[4/7]${NC} Checking example contracts..."
if [ -d "examples" ] && [ -f "examples/reentrancy_simple.sol" ]; then
    COUNT=$(ls examples/*.sol 2>/dev/null | wc -l | xargs)
    echo -e "  ${GREEN}✓${NC} Found $COUNT Solidity files in examples/"
else
    echo -e "  ${RED}✗${NC} Examples directory not found"
    exit 1
fi

# Test 5: Organize contracts
echo -e "${YELLOW}[5/7]${NC} Organizing vulnerable contracts..."
if python scripts/download_vulnerable_contracts.py > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} Vulnerable contracts organized"
else
    echo -e "  ${RED}✗${NC} Failed to organize contracts"
    exit 1
fi

# Test 6: Quick analysis test (Slither only for speed)
echo -e "${YELLOW}[6/7]${NC} Testing analysis pipeline (Slither only)..."
rm -rf output/quick_test 2>/dev/null
if python main_ai.py vulnerable_contracts/reentrancy/reentrancy.sol quick_test --use-slither > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} Analysis completed successfully"
else
    echo -e "  ${RED}✗${NC} Analysis failed"
    exit 1
fi

# Test 7: Test report generation
echo -e "${YELLOW}[7/7]${NC} Testing report generation..."
if python generate_reports.py output/quick_test "Quick Test" > /dev/null 2>&1; then
    if [ -f "output/quick_test/reports/dashboard.html" ] && [ -f "output/quick_test/reports/consolidated_report.md" ]; then
        echo -e "  ${GREEN}✓${NC} Reports generated successfully"

        # Check if report has conclusions
        if grep -q "## 🎯 Conclusions" output/quick_test/reports/consolidated_report.md; then
            echo -e "  ${GREEN}✓${NC} Reports include conclusions and next steps"
        else
            echo -e "  ${YELLOW}⚠${NC}  Reports missing conclusions section"
        fi
    else
        echo -e "  ${RED}✗${NC} Report files not created"
        exit 1
    fi
else
    echo -e "  ${RED}✗${NC} Report generation failed"
    exit 1
fi

# Summary
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✅ ALL TESTS PASSED!                      ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Your demo is ready!${NC}"
echo ""
echo "Quick commands to remember:"
echo ""
echo -e "  ${YELLOW}# Full automated demo${NC}"
echo "  ./demo_presentation.sh"
echo ""
echo -e "  ${YELLOW}# Manual quick demo${NC}"
echo "  python main_ai.py vulnerable_contracts/reentrancy/reentrancy.sol demo --use-slither --use-ollama"
echo "  python generate_reports.py output/demo \"Demo\""
echo "  open output/demo/reports/dashboard.html"
echo ""
echo -e "  ${YELLOW}# View test reports${NC}"
echo "  open output/quick_test/reports/dashboard.html"
echo "  cat output/quick_test/reports/consolidated_report.md"
echo ""
echo -e "${GREEN}Good luck with your presentation! 🚀${NC}"
echo ""
