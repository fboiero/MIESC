#!/bin/bash
# =============================================================================
# SOLHINT LINTING SCRIPT
# =============================================================================
# Ejecuta linting y security checks con Solhint
# Universidad de la Defensa Nacional (UNDEF) - IUA Córdoba
# Maestría en Ciberdefensa
# =============================================================================

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# Verificar instalación
check_solhint() {
    if ! command -v solhint &> /dev/null; then
        echo -e "${RED}Error: Solhint no está instalado${NC}"
        echo -e "${YELLOW}Instalar con: npm install -g solhint${NC}"
        exit 1
    fi
}

# Main
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo -e "${CYAN}${BOLD}  SOLHINT - LINTING Y SECURITY CHECKS${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo ""

check_solhint

TARGET="${1:-src/contracts/**/*.sol}"
CONFIG="analysis/solhint/.solhintrc"

echo -e "${BOLD}Target:${NC} $TARGET"
echo -e "${BOLD}Config:${NC} $CONFIG"
echo ""

echo -e "${YELLOW}Ejecutando Solhint...${NC}"
solhint -c "$CONFIG" "$TARGET" || true

echo ""
echo -e "${GREEN}✓ Análisis completado${NC}"
