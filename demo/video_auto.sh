#!/bin/bash
# MIESC v5.1.1 — Automated Demo Recording
# Run with: asciinema rec -c ./demo/video_auto.sh demo/miesc-demo.cast

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

slow_type() {
    echo ""
    echo -ne "  ${GREEN}\$${NC} "
    for ((i=0; i<${#1}; i++)); do
        echo -n "${1:$i:1}"
        sleep 0.03
    done
    echo ""
    sleep 0.5
}

banner() {
    echo ""
    echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
    echo ""
    sleep 1
}

# Setup
DEMO_DIR=$(mktemp -d)/miesc-demo
mkdir -p "$DEMO_DIR"
cd "$DEMO_DIR"

CONTRACTS="/Users/fboiero/Documents/GitHub/MIESC/examples/contracts"
cp "$CONTRACTS/VulnerableDeFi.sol" .
cp "$CONTRACTS/EtherStore.sol" .
cp "$CONTRACTS/FlashLoanAttack.sol" .

clear
sleep 1

banner "MIESC v5.1.1 — Smart Contract Security Audit Demo"

echo -e "  ${GREEN}MIESC${NC} orchestrates ${BOLD}35 analysis modules${NC} across ${BOLD}9 defense layers${NC}"
echo -e "  for comprehensive pre-audit triage of smart contracts."
echo ""
echo -e "  Today: audit ${BOLD}VulnerableDeFi.sol${NC} — a DeFi vault with"
echo -e "  selfdestruct, unchecked delegatecall, and weak randomness."
sleep 3

# Step 1
banner "STEP 1: Check Tool Availability"
slow_type "miesc doctor"
miesc doctor 2>/dev/null
sleep 2

# Step 2
banner "STEP 2: Quick Scan — VulnerableDeFi.sol"
slow_type "miesc scan VulnerableDeFi.sol -o results.json"
miesc scan VulnerableDeFi.sol -o results.json 2>/dev/null
sleep 1
echo ""
echo -e "  ${GREEN}✓${NC} $(python3 -c "import json; d=json.load(open('results.json')); print(f'{len(d[\"findings\"])} findings saved to results.json')")"
sleep 2

# Step 3
banner "STEP 3: Scan More Contracts"
for c in EtherStore.sol FlashLoanAttack.sol; do
    slow_type "miesc scan $c"
    miesc scan "$c" 2>/dev/null | grep -E "HIGH|CRITICAL|TOTAL|issues"
    echo ""
    sleep 1
done
sleep 1

# Step 4
banner "STEP 4: Technical Report (Markdown)"
slow_type "miesc report results.json -t technical -f markdown -o report.md"
miesc report results.json -t technical -f markdown -o report.md 2>/dev/null
echo ""
echo -e "  ${GREEN}✓${NC} Technical report: $(wc -l < report.md) lines"
echo ""
echo -e "  ${BLUE}Preview:${NC}"
head -20 report.md
sleep 3

# Step 5
banner "STEP 5: Premium PDF Report (AI + PoC Exploits)"
slow_type "miesc report results.json -t premium -f pdf --llm-interpret --client 'VulnerableDeFi Protocol' --auditor 'Fernando Boiero' -o audit.pdf"
echo -e "  ${YELLOW}Generating AI analysis with Ollama (qwen2.5-coder:14b)...${NC}"
miesc report results.json -t premium -f pdf \
  --llm-interpret \
  --client "VulnerableDeFi Protocol" \
  --auditor "Fernando Boiero — UTN FRVM" \
  -o audit.pdf 2>/dev/null
echo ""
echo -e "  ${GREEN}✓${NC} Premium PDF: $(ls -lh audit.pdf | awk '{print $5}') — includes CVSS, risk matrix, PoC code"
sleep 2

# Step 6
banner "STEP 6: SARIF Export (GitHub Security)"
slow_type "miesc export results.json -f sarif -o findings.sarif"
miesc export results.json -f sarif -o findings.sarif 2>/dev/null
SARIF_COUNT=$(python3 -c "import json; d=json.load(open('findings.sarif')); print(len(d['runs'][0]['results']))")
echo -e "  ${GREEN}✓${NC} SARIF 2.1.0: $SARIF_COUNT results — ready for GitHub Security tab"
sleep 2

# Step 7
banner "STEP 7: CSV Export"
slow_type "miesc export results.json -f csv -o findings.csv"
miesc export results.json -f csv -o findings.csv 2>/dev/null
echo ""
cat findings.csv
sleep 2

# Summary
banner "AUDIT COMPLETE"
echo ""
echo "  ┌─────────────────────┬──────────┬────────────────────────────┐"
echo "  │ File                │ Size     │ Purpose                    │"
echo "  ├─────────────────────┼──────────┼────────────────────────────┤"
for f in results.json report.md audit.pdf findings.sarif findings.csv; do
    SIZE=$(ls -lh "$f" 2>/dev/null | awk '{print $5}')
    case "$f" in
        *.json) P="Raw findings + metadata" ;;
        *.md)   P="Technical markdown report" ;;
        *.pdf)  P="Premium PDF (AI + PoC)" ;;
        *.sarif) P="GitHub Security integration" ;;
        *.csv)  P="Spreadsheet analysis" ;;
    esac
    printf "  │ %-19s │ %8s │ %-26s │\n" "$f" "$SIZE" "$P"
done
echo "  └─────────────────────┴──────────┴────────────────────────────┘"
echo ""
echo -e "  ${BOLD}MIESC v5.1.1${NC} — https://github.com/fboiero/MIESC"
echo -e "  ${GREEN}pip install miesc${NC}"
echo ""
sleep 5
