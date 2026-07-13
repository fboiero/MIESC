#!/bin/bash
# =============================================================================
# MIESC v6.0.0 — Full Security Audit Demo
# =============================================================================
# This script demonstrates the complete MIESC workflow:
#   1. Doctor check (tool availability)
#   2. Quick scan (single contract)
#   3. Multi-contract audit
#   4. Technical markdown report
#   5. Premium PDF report with AI interpretation + PoC exploits
#   6. SARIF export for GitHub Security
#   7. CSV export for spreadsheet analysis
#
# Prerequisites:
#   pip install miesc==6.0.0
#   ollama serve & ollama pull qwen2.5-coder:14b
# =============================================================================

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
BOLD='\033[1m'

banner() {
    echo ""
    echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
    echo ""
}

pause() {
    echo ""
    echo -e "${YELLOW}  Press Enter to continue...${NC}"
    read -r
}

# Setup
DEMO_DIR=$(mktemp -d)/miesc-demo
mkdir -p "$DEMO_DIR"
cd "$DEMO_DIR"

CONTRACTS_DIR="$(dirname "$0")/../examples/contracts"
if [ ! -d "$CONTRACTS_DIR" ]; then
    CONTRACTS_DIR="/Users/fboiero/Documents/GitHub/MIESC/examples/contracts"
fi

cp "$CONTRACTS_DIR/VulnerableDeFi.sol" .
cp "$CONTRACTS_DIR/EtherStore.sol" .
cp "$CONTRACTS_DIR/FlashLoanAttack.sol" .

clear

banner "MIESC v6.0.0 — Multi-layer Smart Contract Security Audit"

echo -e "  ${GREEN}MIESC${NC} orchestrates ${BOLD}35 analysis modules${NC} across ${BOLD}9 defense layers${NC}"
echo -e "  to provide comprehensive pre-audit triage for smart contracts."
echo ""
echo -e "  📦 pip install miesc"
echo -e "  🐳 docker run ghcr.io/fboiero/miesc:6.0.0"
echo -e "  🔗 https://github.com/fboiero/MIESC"
echo ""
echo -e "  Today we'll audit 3 intentionally vulnerable contracts:"
echo -e "    • VulnerableDeFi.sol  — DeFi vault with rug pull, weak RNG, no slippage"
echo -e "    • EtherStore.sol      — Classic reentrancy vulnerability"
echo -e "    • FlashLoanAttack.sol — Flash loan attack pattern"

pause

# ═══════════════════════════════════════════════════════════
# STEP 1: Doctor
# ═══════════════════════════════════════════════════════════
banner "STEP 1: Check Tool Availability"

echo -e "  ${GREEN}\$${NC} miesc doctor"
echo ""
miesc doctor 2>/dev/null

pause

# ═══════════════════════════════════════════════════════════
# STEP 2: Quick Scan
# ═══════════════════════════════════════════════════════════
banner "STEP 2: Quick Scan — VulnerableDeFi.sol"

echo -e "  ${GREEN}\$${NC} miesc scan VulnerableDeFi.sol -o scan_results.json"
echo ""
miesc scan VulnerableDeFi.sol -o scan_results.json 2>/dev/null

echo ""
echo -e "  ${GREEN}✓${NC} Results saved to scan_results.json"
echo -e "  ${GREEN}✓${NC} $(python3 -c "import json; d=json.load(open('scan_results.json')); print(f'{len(d[\"findings\"])} findings detected')")"

pause

# ═══════════════════════════════════════════════════════════
# STEP 3: Multi-contract Audit
# ═══════════════════════════════════════════════════════════
banner "STEP 3: Audit Multiple Contracts"

for contract in EtherStore.sol FlashLoanAttack.sol; do
    echo -e "  ${GREEN}\$${NC} miesc scan $contract"
    miesc scan "$contract" 2>/dev/null | grep -E "HIGH|CRITICAL|TOTAL|issues"
    echo ""
done

pause

# ═══════════════════════════════════════════════════════════
# STEP 4: Technical Report
# ═══════════════════════════════════════════════════════════
banner "STEP 4: Generate Technical Report (Markdown)"

echo -e "  ${GREEN}\$${NC} miesc report scan_results.json -t technical -f markdown -o report.md"
echo ""
miesc report scan_results.json -t technical -f markdown -o report.md 2>/dev/null

echo -e "  ${GREEN}✓${NC} Technical report: $(wc -l < report.md) lines"
echo ""
echo -e "  ${BLUE}--- Report Preview ---${NC}"
head -25 report.md
echo -e "  ${BLUE}--- (truncated) ---${NC}"

pause

# ═══════════════════════════════════════════════════════════
# STEP 5: Premium PDF with AI + PoC
# ═══════════════════════════════════════════════════════════
banner "STEP 5: Premium PDF Report (AI + PoC Exploits)"

echo -e "  ${GREEN}\$${NC} miesc report scan_results.json -t premium -f pdf --llm-interpret -o audit_report.pdf"
echo ""
echo -e "  ${YELLOW}Generating AI interpretation with Ollama (qwen2.5-coder:14b)...${NC}"
echo -e "  ${YELLOW}Generating Foundry PoC exploit templates...${NC}"
echo ""
miesc report scan_results.json -t premium -f pdf \
  --llm-interpret \
  --client "VulnerableDeFi Protocol" \
  --auditor "Fernando Boiero — UTN FRVM" \
  -o audit_report.pdf 2>/dev/null

echo ""
echo -e "  ${GREEN}✓${NC} Premium PDF: $(ls -lh audit_report.pdf | awk '{print $5}')"
echo -e "  ${GREEN}✓${NC} Includes: CVSS scoring, risk matrix, attack scenarios, PoC code"

pause

# ═══════════════════════════════════════════════════════════
# STEP 6: SARIF Export
# ═══════════════════════════════════════════════════════════
banner "STEP 6: Export for GitHub Security (SARIF)"

echo -e "  ${GREEN}\$${NC} miesc export scan_results.json -f sarif -o findings.sarif"
echo ""
miesc export scan_results.json -f sarif -o findings.sarif 2>/dev/null

SARIF_COUNT=$(python3 -c "import json; d=json.load(open('findings.sarif')); print(len(d['runs'][0]['results']))")
echo -e "  ${GREEN}✓${NC} SARIF 2.1.0: $SARIF_COUNT results"
echo -e "  ${GREEN}✓${NC} Upload to GitHub: gh api repos/OWNER/REPO/code-scanning/sarifs -f sarif=@findings.sarif"

pause

# ═══════════════════════════════════════════════════════════
# STEP 7: CSV Export
# ═══════════════════════════════════════════════════════════
banner "STEP 7: CSV Export for Spreadsheet Analysis"

echo -e "  ${GREEN}\$${NC} miesc export scan_results.json -f csv -o findings.csv"
echo ""
miesc export scan_results.json -f csv -o findings.csv 2>/dev/null

echo -e "  ${GREEN}✓${NC} CSV: $(wc -l < findings.csv) rows"
echo ""
cat findings.csv

pause

# ═══════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════
banner "AUDIT COMPLETE — Generated Artifacts"

echo "  ┌─────────────────────────┬────────────┬──────────────────────────┐"
echo "  │ File                    │ Size       │ Purpose                  │"
echo "  ├─────────────────────────┼────────────┼──────────────────────────┤"
for f in scan_results.json report.md audit_report.pdf findings.sarif findings.csv; do
    if [ -f "$f" ]; then
        SIZE=$(ls -lh "$f" | awk '{print $5}')
        case "$f" in
            *.json) PURPOSE="Raw findings + metadata" ;;
            *.md)   PURPOSE="Technical markdown report" ;;
            *.pdf)  PURPOSE="Premium PDF (AI + PoC)" ;;
            *.sarif) PURPOSE="GitHub Security integration" ;;
            *.csv)  PURPOSE="Spreadsheet analysis" ;;
        esac
        printf "  │ %-23s │ %10s │ %-24s │\n" "$f" "$SIZE" "$PURPOSE"
    fi
done
echo "  └─────────────────────────┴────────────┴──────────────────────────┘"

echo ""
echo -e "  ${GREEN}MIESC v6.0.0${NC} — Multi-layer Intelligent Evaluation for Smart Contracts"
echo -e "  ${BLUE}https://github.com/fboiero/MIESC${NC}"
echo -e "  ${BLUE}pip install miesc${NC}"
echo ""
echo -e "  Demo files saved in: ${BOLD}$DEMO_DIR${NC}"

# Open PDF
open audit_report.pdf 2>/dev/null || true
