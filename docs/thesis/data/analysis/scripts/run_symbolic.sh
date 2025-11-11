#!/bin/bash
# =============================================================================
# SYMBOLIC ANALYSIS PIPELINE
# =============================================================================
# Ejecuta análisis simbólico completo: Mythril + Manticore
# Universidad de la Defensa Nacional (UNDEF) - IUA Córdoba
# Maestría en Ciberdefensa
# =============================================================================

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# Configuración
CONTRACT_PATH="${1}"
QUICK_MODE="${2:-false}"
RESULTS_DIR="analysis/symbolic_results"

# Función de ayuda
show_help() {
    echo -e "${CYAN}${BOLD}Symbolic Analysis Pipeline${NC}"
    echo ""
    echo "Usage: $0 <contract_path> [quick]"
    echo ""
    echo "Arguments:"
    echo "  contract_path    Path to Solidity contract"
    echo "  quick            Optional: use quick mode (faster, less thorough)"
    echo ""
    echo "Examples:"
    echo "  $0 src/contracts/vulnerable/reentrancy/VulnerableVault.sol"
    echo "  $0 src/contracts/MyContract.sol quick"
}

# Validar argumentos
if [ -z "$CONTRACT_PATH" ]; then
    show_help
    exit 1
fi

if [ ! -f "$CONTRACT_PATH" ]; then
    echo -e "${RED}Error: Contract not found: $CONTRACT_PATH${NC}"
    exit 1
fi

# Crear directorio de resultados
mkdir -p "$RESULTS_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CONTRACT_NAME=$(basename "$CONTRACT_PATH" .sol)

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}  ${BOLD}${CYAN}SYMBOLIC ANALYSIS PIPELINE${NC}                            ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}  ${DIM}Mythril + Manticore${NC}                                        ${BLUE}║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}Contract:${NC} $CONTRACT_PATH"
echo -e "${BOLD}Mode:${NC} $([ "$QUICK_MODE" = "quick" ] && echo "Quick (fast)" || echo "Full (thorough)")"
echo -e "${BOLD}Timestamp:${NC} $TIMESTAMP"
echo ""

# =============================================================================
# FASE 1: MYTHRIL
# =============================================================================

echo -e "${MAGENTA}${BOLD}▶ FASE 1: MYTHRIL (SMT Solving)${NC}"
echo -e "${DIM}──────────────────────────────────────────────────────────────${NC}"
echo ""

MYTHRIL_OUTPUT="$RESULTS_DIR/${CONTRACT_NAME}_mythril_${TIMESTAMP}.json"

if [ -f "analysis/mythril/run_mythril.sh" ]; then
    echo -e "${YELLOW}Ejecutando Mythril...${NC}"

    if [ "$QUICK_MODE" = "quick" ]; then
        timeout 300 analysis/mythril/run_mythril.sh \
            -j -t 300 -o "$MYTHRIL_OUTPUT" "$CONTRACT_PATH" || true
    else
        timeout 600 analysis/mythril/run_mythril.sh \
            -j -o "$MYTHRIL_OUTPUT" "$CONTRACT_PATH" || true
    fi

    echo ""

    if [ -f "$MYTHRIL_OUTPUT" ]; then
        echo -e "${GREEN}✓ Mythril completado${NC}"
        echo -e "${DIM}Resultados: $MYTHRIL_OUTPUT${NC}"

        # Mostrar resumen
        echo -e "${CYAN}Resumen:${NC}"
        python3 -c "
import json
try:
    with open('$MYTHRIL_OUTPUT') as f:
        data = json.load(f)
        issues = data.get('issues', [])
        print(f'  Vulnerabilidades encontradas: {len(issues)}')
        for issue in issues[:3]:
            print(f'  - {issue.get(\"title\", \"Unknown\")} (Severity: {issue.get(\"severity\", \"?\")})' )
except:
    print('  Error parsing JSON')
" || echo "  Ver archivo para detalles"
    else
        echo -e "${YELLOW}⚠ Mythril no generó resultados${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Mythril script not found, skipping${NC}"
fi

echo ""

# =============================================================================
# FASE 2: MANTICORE
# =============================================================================

echo -e "${MAGENTA}${BOLD}▶ FASE 2: MANTICORE (Symbolic Execution)${NC}"
echo -e "${DIM}──────────────────────────────────────────────────────────────${NC}"
echo ""

MANTICORE_OUTPUT="$RESULTS_DIR/${CONTRACT_NAME}_manticore_${TIMESTAMP}.json"

echo -e "${YELLOW}Ejecutando Manticore...${NC}"

if [ "$QUICK_MODE" = "quick" ]; then
    python3 src/manticore_tool.py "$CONTRACT_PATH" --quick > "$MANTICORE_OUTPUT" 2>&1 || true
else
    timeout 1200 python3 src/manticore_tool.py "$CONTRACT_PATH" > "$MANTICORE_OUTPUT" 2>&1 || true
fi

echo ""

if [ -f "$MANTICORE_OUTPUT" ]; then
    echo -e "${GREEN}✓ Manticore completado${NC}"
    echo -e "${DIM}Resultados: $MANTICORE_OUTPUT${NC}"

    # Mostrar resumen
    echo -e "${CYAN}Resumen:${NC}"
    python3 -c "
import json
try:
    with open('$MANTICORE_OUTPUT') as f:
        data = json.load(f)
        print(f'  Estados explorados: {data.get(\"states_explored\", 0)}')
        print(f'  Findings: {len(data.get(\"findings\", []))}')
        print(f'  Status: {data.get(\"status\", \"unknown\")}')
except:
    print('  Ver archivo para detalles')
" || echo "  Ver archivo para detalles"
else
    echo -e "${YELLOW}⚠ Manticore no generó resultados${NC}"
fi

echo ""

# =============================================================================
# CONSOLIDACIÓN
# =============================================================================

echo -e "${BLUE}${BOLD}▶ CONSOLIDANDO RESULTADOS${NC}"
echo -e "${DIM}──────────────────────────────────────────────────────────────${NC}"
echo ""

CONSOLIDATED="$RESULTS_DIR/${CONTRACT_NAME}_symbolic_consolidated_${TIMESTAMP}.json"

python3 << EOF
import json
import os

results = {
    'contract': '$CONTRACT_PATH',
    'timestamp': '$TIMESTAMP',
    'mode': '$QUICK_MODE',
    'tools': {},
    'summary': {
        'total_findings': 0,
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0
    }
}

# Cargar Mythril
if os.path.exists('$MYTHRIL_OUTPUT'):
    try:
        with open('$MYTHRIL_OUTPUT') as f:
            mythril_data = json.load(f)
            results['tools']['mythril'] = mythril_data
            issues = mythril_data.get('issues', [])
            results['summary']['total_findings'] += len(issues)

            for issue in issues:
                severity = issue.get('severity', 'low').lower()
                if severity == 'high':
                    results['summary']['high'] += 1
                elif severity == 'medium':
                    results['summary']['medium'] += 1
                else:
                    results['summary']['low'] += 1
    except:
        pass

# Cargar Manticore
if os.path.exists('$MANTICORE_OUTPUT'):
    try:
        with open('$MANTICORE_OUTPUT') as f:
            manticore_data = json.load(f)
            results['tools']['manticore'] = manticore_data
            findings = manticore_data.get('findings', [])
            results['summary']['total_findings'] += len(findings)
    except:
        pass

# Guardar consolidado
with open('$CONSOLIDATED', 'w') as f:
    json.dump(results, f, indent=2)

print("Consolidated results saved to: $CONSOLIDATED")
EOF

echo ""

# =============================================================================
# RESUMEN FINAL
# =============================================================================

echo -e "${GREEN}${BOLD}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║${NC}  ${WHITE}ANÁLISIS SIMBÓLICO COMPLETADO${NC}                            ${GREEN}${BOLD}║${NC}"
echo -e "${GREEN}${BOLD}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${BOLD}Resultados guardados en:${NC}"
echo -e "  ${CYAN}$RESULTS_DIR/${NC}"
echo ""

echo -e "${BOLD}Archivos generados:${NC}"
[ -f "$MYTHRIL_OUTPUT" ] && echo -e "  ${GREEN}✓${NC} Mythril:   $(basename $MYTHRIL_OUTPUT)"
[ -f "$MANTICORE_OUTPUT" ] && echo -e "  ${GREEN}✓${NC} Manticore: $(basename $MANTICORE_OUTPUT)"
[ -f "$CONSOLIDATED" ] && echo -e "  ${GREEN}✓${NC} Consolidated: $(basename $CONSOLIDATED)"
echo ""

# Mostrar resumen consolidado
if [ -f "$CONSOLIDATED" ]; then
    echo -e "${CYAN}${BOLD}Resumen Consolidado:${NC}"
    python3 -c "
import json
with open('$CONSOLIDATED') as f:
    data = json.load(f)
    summary = data['summary']
    print(f'  Total Findings: {summary[\"total_findings\"]}')
    print(f'  Critical: {summary.get(\"critical\", 0)}')
    print(f'  High: {summary[\"high\"]}')
    print(f'  Medium: {summary[\"medium\"]}')
    print(f'  Low: {summary[\"low\"]}')
"
fi

echo ""
echo -e "${DIM}Análisis simbólico completado - $(date)${NC}"
