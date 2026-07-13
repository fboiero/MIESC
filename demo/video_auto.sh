#!/bin/bash
# MIESC v6.0.0 — Automated Demo Recording
# Run with: asciinema rec -c ./demo/video_auto.sh demo/miesc-demo.cast
# Or direct: ./demo/video_auto.sh

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

# Alias so we show "miesc" but it works even with broken PATH
MIESC="python3 -m miesc.cli.main"

show_cmd() {
    # Display a pretty command but run with the alias
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

SRC="/Users/fboiero/Documents/GitHub/MIESC"
export PYTHONPATH="$SRC:$PYTHONPATH"
cp "$SRC/examples/contracts/VulnerableDeFi.sol" .
cp "$SRC/examples/contracts/EtherStore.sol" .
cp "$SRC/examples/contracts/FlashLoanAttack.sol" .

clear
sleep 1

banner "MIESC v6.0.0 — Smart Contract Security Audit Demo"

echo -e "  ${GREEN}MIESC${NC} orchestrates ${BOLD}35 analysis modules${NC} across ${BOLD}9 defense layers${NC}"
echo -e "  for comprehensive pre-audit triage of smart contracts."
echo ""
echo -e "  Today: full security audit of ${BOLD}VulnerableDeFi.sol${NC}"
echo -e "  A DeFi vault with selfdestruct, unchecked delegatecall,"
echo -e "  and weak randomness."
sleep 3

# ══════════════ STEP 1 ══════════════
banner "STEP 1: Check Tool Availability"
show_cmd "miesc doctor"
$MIESC doctor 2>/dev/null
sleep 2

# ══════════════ STEP 2 ══════════════
banner "STEP 2: Quick Scan — VulnerableDeFi.sol"
show_cmd "miesc scan VulnerableDeFi.sol -o results.json"
$MIESC scan VulnerableDeFi.sol -o results.json 2>/dev/null
sleep 1
echo ""
FCOUNT=$(python3 -c "import json; d=json.load(open('results.json')); print(len(d['findings']))")
echo -e "  ${GREEN}✓${NC} $FCOUNT findings saved to results.json"
sleep 2

# ══════════════ STEP 3 ══════════════
banner "STEP 3: Scan More Contracts"
for c in EtherStore.sol FlashLoanAttack.sol; do
    show_cmd "miesc scan $c"
    $MIESC scan "$c" 2>/dev/null | grep -E "HIGH|CRITICAL|TOTAL|issues"
    echo ""
    sleep 1
done
sleep 1

# ══════════════ STEP 4 ══════════════
banner "STEP 4: Technical Report (Markdown)"
show_cmd "miesc report results.json -t technical -f markdown -o report.md"
$MIESC report results.json -t technical -f markdown -o report.md 2>/dev/null
echo ""
echo -e "  ${GREEN}✓${NC} Technical report: $(wc -l < report.md | tr -d ' ') lines"
echo ""
echo -e "  ${BLUE}--- Preview ---${NC}"
head -20 report.md
echo -e "  ${BLUE}--- (truncated) ---${NC}"
sleep 3

# ══════════════ STEP 5 ══════════════
banner "STEP 5: Premium PDF Report (AI + PoC Exploits)"
show_cmd "miesc report results.json -t premium -f pdf --llm-interpret -o audit.pdf"
echo -e "  ${YELLOW}Generating AI analysis with Ollama...${NC}"
$MIESC report results.json -t premium -f pdf \
  --llm-interpret \
  --client "VulnerableDeFi Protocol" \
  --auditor "Fernando Boiero — UTN FRVM" \
  -o audit.pdf 2>/dev/null
echo ""
echo -e "  ${GREEN}✓${NC} Premium PDF: $(ls -lh audit.pdf | awk '{print $5}')"
echo -e "  ${GREEN}✓${NC} Includes: CVSS scoring, risk matrix, PoC exploit code"
sleep 2

# ══════════════ STEP 6 ══════════════
banner "STEP 6: SARIF Export (GitHub Security)"
show_cmd "miesc export results.json -f sarif -o findings.sarif"
$MIESC export results.json -f sarif -o findings.sarif 2>/dev/null
SARIF_N=$(python3 -c "import json; d=json.load(open('findings.sarif')); print(len(d['runs'][0]['results']))")
echo -e "  ${GREEN}✓${NC} SARIF 2.1.0: $SARIF_N results"
sleep 2

# ══════════════ STEP 7 ══════════════
banner "STEP 7: CSV Export"
show_cmd "miesc export results.json -f csv -o findings.csv"
$MIESC export results.json -f csv -o findings.csv 2>/dev/null
echo ""
cat findings.csv
sleep 2

# ══════════════ SUMMARY ══════════════
banner "AUDIT COMPLETE — Generated Artifacts"
echo ""
echo "  ┌─────────────────────┬──────────┬────────────────────────────┐"
echo "  │ File                │ Size     │ Purpose                    │"
echo "  ├─────────────────────┼──────────┼────────────────────────────┤"
for f in results.json report.md audit.pdf findings.sarif findings.csv; do
    SIZE=$(ls -lh "$f" 2>/dev/null | awk '{print $5}')
    case "$f" in
        *.json)  P="Raw findings + metadata" ;;
        *.md)    P="Technical markdown report" ;;
        *.pdf)   P="Premium PDF (AI + PoC)" ;;
        *.sarif) P="GitHub Security integration" ;;
        *.csv)   P="Spreadsheet analysis" ;;
    esac
    printf "  │ %-19s │ %8s │ %-26s │\n" "$f" "$SIZE" "$P"
done
echo "  └─────────────────────┴──────────┴────────────────────────────┘"
echo ""
echo -e "  ${BOLD}MIESC v6.0.0${NC} — Multi-layer Intelligent Evaluation for Smart Contracts"
echo -e "  ${GREEN}pip install miesc${NC} | ${BLUE}https://github.com/fboiero/MIESC${NC}"
echo ""
sleep 5
