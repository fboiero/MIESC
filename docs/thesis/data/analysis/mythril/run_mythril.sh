#!/bin/bash
# =============================================================================
# MYTHRIL ANALYSIS SCRIPT
# =============================================================================
# Ejecuta análisis simbólico con Mythril en contratos Solidity
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
NC='\033[0m'
BOLD='\033[1m'

# Configuración
RESULTS_DIR="analysis/mythril/results"
TIMEOUT=600  # 10 minutos por contrato

# Función de ayuda
show_help() {
    echo -e "${CYAN}${BOLD}Mythril Analysis Script${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS] <contract_path>"
    echo ""
    echo "Options:"
    echo "  -t, --timeout SECONDS    Set analysis timeout (default: 600)"
    echo "  -o, --output FILE        Output file path"
    echo "  -j, --json               Output in JSON format"
    echo "  -v, --verbose            Verbose output"
    echo "  -h, --help               Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 src/contracts/vulnerable/reentrancy/VulnerableVault.sol"
    echo "  $0 -j -o results.json src/contracts/MyContract.sol"
}

# Verificar instalación de Mythril
check_mythril() {
    if ! command -v myth &> /dev/null; then
        echo -e "${RED}Error: Mythril no está instalado${NC}"
        echo -e "${YELLOW}Instalar con: pip install mythril${NC}"
        exit 1
    fi
}

# Análisis con Mythril
run_analysis() {
    local contract="$1"
    local output_format="${2:-text}"
    local output_file="${3:-}"

    echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}  MYTHRIL - ANÁLISIS SIMBÓLICO${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${BOLD}Contrato:${NC} $contract"
    echo -e "${BOLD}Timeout:${NC} ${TIMEOUT}s"
    echo -e "${BOLD}Formato:${NC} $output_format"
    echo ""

    # Crear directorio de resultados
    mkdir -p "$RESULTS_DIR"

    # Timestamp para archivo de salida
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    CONTRACT_NAME=$(basename "$contract" .sol)

    if [ -z "$output_file" ]; then
        if [ "$output_format" = "json" ]; then
            output_file="$RESULTS_DIR/${CONTRACT_NAME}_${TIMESTAMP}.json"
        else
            output_file="$RESULTS_DIR/${CONTRACT_NAME}_${TIMESTAMP}.txt"
        fi
    fi

    echo -e "${YELLOW}Ejecutando Mythril...${NC}"
    echo -e "${BLUE}$ myth analyze --solv 0.8.20 $contract${NC}"
    echo ""

    # Ejecutar Mythril
    if [ "$output_format" = "json" ]; then
        timeout $TIMEOUT myth analyze \
            --solv 0.8.20 \
            --parallel-solving \
            -o json \
            "$contract" > "$output_file" 2>&1 || true
    else
        timeout $TIMEOUT myth analyze \
            --solv 0.8.20 \
            --parallel-solving \
            "$contract" | tee "$output_file" || true
    fi

    # Verificar resultado
    if [ -f "$output_file" ] && [ -s "$output_file" ]; then
        echo ""
        echo -e "${GREEN}✓ Análisis completado${NC}"
        echo -e "${BOLD}Resultado guardado en:${NC} $output_file"
        echo ""

        # Mostrar resumen
        if [ "$output_format" = "text" ]; then
            echo -e "${CYAN}${BOLD}Resumen de Vulnerabilidades:${NC}"
            grep -E "==== |SWC ID" "$output_file" | head -20 || echo "No se encontraron vulnerabilidades críticas"
        else
            echo -e "${CYAN}${BOLD}Resumen JSON:${NC}"
            cat "$output_file" | jq '.issues | length' 2>/dev/null || echo "Ver archivo JSON para detalles"
        fi
    else
        echo -e "${RED}✗ Error en el análisis${NC}"
        echo "El análisis falló o no produjo resultados"
        exit 1
    fi
}

# Main
main() {
    local contract=""
    local output_format="text"
    local output_file=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -o|--output)
                output_file="$2"
                shift 2
                ;;
            -j|--json)
                output_format="json"
                shift
                ;;
            -v|--verbose)
                set -x
                shift
                ;;
            -*)
                echo -e "${RED}Error: Opción desconocida $1${NC}"
                show_help
                exit 1
                ;;
            *)
                contract="$1"
                shift
                ;;
        esac
    done

    # Validar argumentos
    if [ -z "$contract" ]; then
        echo -e "${RED}Error: Se requiere especificar un contrato${NC}"
        show_help
        exit 1
    fi

    if [ ! -f "$contract" ]; then
        echo -e "${RED}Error: Archivo no encontrado: $contract${NC}"
        exit 1
    fi

    # Ejecutar análisis
    check_mythril
    run_analysis "$contract" "$output_format" "$output_file"
}

main "$@"
