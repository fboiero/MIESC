#!/bin/bash
# =============================================================================
# FOUNDRY INVARIANT TESTING SCRIPT
# =============================================================================
# Ejecuta invariant testing con Foundry
# Universidad de la Defensa Nacional (UNDEF) - IUA Córdoba
# Maestría en Ciberdefensa
# =============================================================================

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}  ${BOLD}FOUNDRY - INVARIANT TESTING${NC}                               ${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if foundry is installed
if ! command -v forge &> /dev/null; then
    echo -e "${RED}Error: Foundry not installed${NC}"
    echo -e "${YELLOW}Install: curl -L https://foundry.paradigm.xyz | bash${NC}"
    exit 1
fi

# Configuration
RUNS="${1:-1000}"          # Number of runs per invariant
DEPTH="${2:-100}"          # Call depth
OUTPUT_DIR="analysis/foundry/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUTPUT_DIR"

echo -e "${BOLD}Configuration:${NC}"
echo -e "  Runs per invariant: ${YELLOW}$RUNS${NC}"
echo -e "  Max call depth: ${YELLOW}$DEPTH${NC}"
echo -e "  Output: ${CYAN}$OUTPUT_DIR${NC}"
echo ""

# =============================================================================
# Run Invariant Tests
# =============================================================================

echo -e "${MAGENTA}${BOLD}▶ EJECUTANDO INVARIANT TESTS${NC}"
echo ""

# Test reentrancy invariants
echo -e "${YELLOW}[1/2] Testing Reentrancy Invariants...${NC}"
forge test \
    --match-path "analysis/foundry/invariants/InvariantReentrancy.t.sol" \
    --fuzz-runs "$RUNS" \
    --fuzz-max-test-rejects 100000 \
    -vvv \
    | tee "$OUTPUT_DIR/invariant_reentrancy_${TIMESTAMP}.log"

REENTRANCY_EXIT=$?

echo ""

# Test access control invariants
echo -e "${YELLOW}[2/2] Testing Access Control Invariants...${NC}"
forge test \
    --match-path "analysis/foundry/invariants/InvariantAccessControl.t.sol" \
    --fuzz-runs "$RUNS" \
    --fuzz-max-test-rejects 100000 \
    -vvv \
    | tee "$OUTPUT_DIR/invariant_access_${TIMESTAMP}.log"

ACCESS_EXIT=$?

echo ""

# =============================================================================
# Summary
# =============================================================================

echo -e "${CYAN}${BOLD}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║${NC}  ${BOLD}INVARIANT TESTING - RESULTADOS${NC}                           ${CYAN}${BOLD}║${NC}"
echo -e "${CYAN}${BOLD}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ $REENTRANCY_EXIT -eq 0 ]; then
    echo -e "  ${GREEN}✓${NC} Reentrancy Invariants: ${GREEN}PASSED${NC}"
else
    echo -e "  ${RED}✗${NC} Reentrancy Invariants: ${RED}FAILED${NC} (Expected - contract is vulnerable)"
fi

if [ $ACCESS_EXIT -eq 0 ]; then
    echo -e "  ${GREEN}✓${NC} Access Control Invariants: ${GREEN}PASSED${NC}"
else
    echo -e "  ${RED}✗${NC} Access Control Invariants: ${RED}FAILED${NC}"
fi

echo ""
echo -e "${BOLD}Logs guardados en:${NC} ${CYAN}$OUTPUT_DIR${NC}"
echo ""

# =============================================================================
# Coverage Report (optional)
# =============================================================================

echo -e "${MAGENTA}${BOLD}▶ GENERANDO REPORTE DE COBERTURA${NC}"
echo ""

forge coverage \
    --match-path "analysis/foundry/invariants/*.sol" \
    --report summary \
    | tee "$OUTPUT_DIR/coverage_${TIMESTAMP}.txt"

echo ""
echo -e "${GREEN}✓ Invariant testing completado${NC}"
