#!/bin/bash
# =============================================================================
# MIESC v4.0.0 - Demo para Defensa de Tesis
# Multi-layer Intelligent Evaluation for Smart Contracts
# Autor: Fernando Boiero - UNDEF/IUA
# =============================================================================

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Directorio base
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONTRACTS_DIR="$PROJECT_DIR/contracts/audit"

# Funciones de utilidad
print_header() {
    clear
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                       ║"
    echo "║   ███╗   ███╗██╗███████╗███████╗ ██████╗    ██╗   ██╗██╗  ██╗        ║"
    echo "║   ████╗ ████║██║██╔════╝██╔════╝██╔════╝    ██║   ██║██║  ██║        ║"
    echo "║   ██╔████╔██║██║█████╗  ███████╗██║         ██║   ██║███████║        ║"
    echo "║   ██║╚██╔╝██║██║██╔══╝  ╚════██║██║         ╚██╗ ██╔╝╚════██║        ║"
    echo "║   ██║ ╚═╝ ██║██║███████╗███████║╚██████╗     ╚████╔╝      ██║        ║"
    echo "║   ╚═╝     ╚═╝╚═╝╚══════╝╚══════╝ ╚═════╝      ╚═══╝       ╚═╝        ║"
    echo "║                                                                       ║"
    echo "║   Multi-layer Intelligent Evaluation for Smart Contracts              ║"
    echo "║   Defense-in-Depth Security Analysis Framework                        ║"
    echo "║                                                                       ║"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}  $1${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

wait_for_enter() {
    echo ""
    echo -e "${CYAN}Presione ENTER para continuar...${NC}"
    read -r
}

# Demo 1: Verificar herramientas disponibles
demo_doctor() {
    print_section "DEMO 1: Verificacion de Herramientas (miesc doctor)"

    echo -e "${WHITE}MIESC integra 25 herramientas de seguridad en 7 capas de defensa.${NC}"
    echo -e "${WHITE}Verifiquemos cuales estan disponibles en este sistema:${NC}"
    echo ""

    wait_for_enter

    miesc doctor

    wait_for_enter
}

# Demo 2: Analisis rapido con Slither
demo_quick_scan() {
    print_section "DEMO 2: Analisis Rapido (miesc scan)"

    echo -e "${WHITE}El comando 'scan' ejecuta analisis estatico rapido (~30 segundos).${NC}"
    echo -e "${WHITE}Analizaremos un contrato con vulnerabilidad de REENTRANCY:${NC}"
    echo ""
    echo -e "${BLUE}Contrato: VulnerableBank.sol${NC}"
    echo ""

    # Mostrar fragmento del codigo vulnerable
    echo -e "${RED}Codigo vulnerable (lineas 30-43):${NC}"
    echo -e "${CYAN}"
    sed -n '30,43p' "$CONTRACTS_DIR/VulnerableBank.sol"
    echo -e "${NC}"

    wait_for_enter

    echo -e "${GREEN}Ejecutando: miesc scan contracts/audit/VulnerableBank.sol${NC}"
    echo ""

    cd "$PROJECT_DIR"
    miesc scan contracts/audit/VulnerableBank.sol --verbose 2>&1 || true

    wait_for_enter
}

# Demo 3: Auditoria completa 7 capas
demo_full_audit() {
    print_section "DEMO 3: Auditoria Completa 7 Capas (miesc audit)"

    echo -e "${WHITE}La auditoria completa ejecuta las 7 capas de defensa:${NC}"
    echo ""
    echo -e "  ${CYAN}Capa 1:${NC} Analisis Estatico (Slither, Aderyn, Solhint)"
    echo -e "  ${CYAN}Capa 2:${NC} Testing Dinamico (Echidna, Medusa, Foundry)"
    echo -e "  ${CYAN}Capa 3:${NC} Ejecucion Simbolica (Mythril, Manticore)"
    echo -e "  ${CYAN}Capa 4:${NC} Verificacion Formal (Certora, Halmos, SMTChecker)"
    echo -e "  ${CYAN}Capa 5:${NC} Analisis de Dependencias (npm audit, cargo audit)"
    echo -e "  ${CYAN}Capa 6:${NC} Revision Experta Asistida por IA (SmartLLM)"
    echo -e "  ${CYAN}Capa 7:${NC} Validacion de Cumplimiento (ERC standards)"
    echo ""

    wait_for_enter

    echo -e "${GREEN}Ejecutando: miesc audit contracts/audit/VulnerableBank.sol --layers 1,2${NC}"
    echo -e "${YELLOW}(Ejecutamos solo capas 1 y 2 por tiempo)${NC}"
    echo ""

    cd "$PROJECT_DIR"
    timeout 120 miesc audit contracts/audit/VulnerableBank.sol --layers 1,2 --verbose 2>&1 || true

    wait_for_enter
}

# Demo 4: API REST para integracion
demo_api() {
    print_section "DEMO 4: API REST MCP-Compatible"

    echo -e "${WHITE}MIESC expone una API REST compatible con Model Context Protocol (MCP).${NC}"
    echo -e "${WHITE}Esto permite integracion con agentes de IA como Claude, GPT, etc.${NC}"
    echo ""
    echo -e "${CYAN}Endpoints disponibles:${NC}"
    echo "  POST /api/v1/analyze     - Iniciar analisis"
    echo "  GET  /api/v1/status/{id} - Estado del analisis"
    echo "  GET  /api/v1/results/{id} - Obtener resultados"
    echo "  GET  /api/v1/tools       - Listar herramientas"
    echo "  GET  /api/v1/health      - Estado del servicio"
    echo ""
    echo -e "${YELLOW}Para iniciar el servidor:${NC}"
    echo -e "${GREEN}  miesc api --port 8080${NC}"
    echo ""

    wait_for_enter
}

# Demo 5: Uso programatico con Python
demo_python_api() {
    print_section "DEMO 5: API de Python"

    echo -e "${WHITE}MIESC se puede usar como libreria Python:${NC}"
    echo ""
    echo -e "${CYAN}from miesc import analyze, quick_scan${NC}"
    echo ""
    echo -e "${CYAN}# Analisis rapido${NC}"
    echo -e "${CYAN}results = quick_scan('contract.sol')${NC}"
    echo ""
    echo -e "${CYAN}# Auditoria completa${NC}"
    echo -e "${CYAN}results = analyze('contract.sol', layers=[1,2,3])${NC}"
    echo ""
    echo -e "${CYAN}# Acceder a hallazgos${NC}"
    echo -e "${CYAN}for finding in results['findings']:${NC}"
    echo -e "${CYAN}    print(f\"{finding['severity']}: {finding['title']}\")${NC}"
    echo ""

    wait_for_enter

    echo -e "${GREEN}Ejecutando ejemplo en Python...${NC}"
    echo ""

    python3 << 'EOF'
import sys
sys.path.insert(0, '.')

# Importar MIESC
try:
    from miesc import __version__
    print(f"MIESC version: {__version__}")
    print("API disponible: analyze(), quick_scan()")
    print("\nEjemplo de resultado normalizado:")

    ejemplo = {
        "severity": "HIGH",
        "title": "Reentrancy Vulnerability",
        "description": "External call before state update",
        "location": "VulnerableBank.sol:35",
        "tool": "slither",
        "layer": 1,
        "cwe": "CWE-841",
        "swc": "SWC-107"
    }

    import json
    print(json.dumps(ejemplo, indent=2))

except Exception as e:
    print(f"Error: {e}")
EOF

    wait_for_enter
}

# Demo 6: Resultados y metricas
demo_metrics() {
    print_section "DEMO 6: Metricas y Resultados"

    echo -e "${WHITE}MIESC normaliza los hallazgos de todas las herramientas:${NC}"
    echo ""
    echo -e "${RED}  CRITICAL${NC} - Vulnerabilidades explotables inmediatamente"
    echo -e "${YELLOW}  HIGH${NC}     - Riesgo significativo de perdida de fondos"
    echo -e "${BLUE}  MEDIUM${NC}   - Problemas que requieren atencion"
    echo -e "${GREEN}  LOW${NC}      - Mejores practicas y optimizaciones"
    echo -e "${CYAN}  INFO${NC}     - Sugerencias informativas"
    echo ""
    echo -e "${WHITE}Cada hallazgo incluye:${NC}"
    echo "  - Mapeo a CWE (Common Weakness Enumeration)"
    echo "  - Mapeo a SWC (Smart Contract Weakness Classification)"
    echo "  - Ubicacion exacta en el codigo (archivo:linea)"
    echo "  - Herramienta que lo detecto"
    echo "  - Recomendaciones de remediacion"
    echo ""

    wait_for_enter
}

# Menu principal
main_menu() {
    while true; do
        print_header

        echo -e "${WHITE}Seleccione una demo:${NC}"
        echo ""
        echo -e "  ${CYAN}1${NC} - Verificar herramientas (miesc doctor)"
        echo -e "  ${CYAN}2${NC} - Analisis rapido (miesc scan)"
        echo -e "  ${CYAN}3${NC} - Auditoria completa 7 capas (miesc audit)"
        echo -e "  ${CYAN}4${NC} - API REST MCP-Compatible"
        echo -e "  ${CYAN}5${NC} - API de Python"
        echo -e "  ${CYAN}6${NC} - Metricas y resultados"
        echo -e "  ${CYAN}A${NC} - Ejecutar TODAS las demos"
        echo -e "  ${CYAN}Q${NC} - Salir"
        echo ""
        echo -n -e "${GREEN}Opcion: ${NC}"
        read -r choice

        case $choice in
            1) demo_doctor ;;
            2) demo_quick_scan ;;
            3) demo_full_audit ;;
            4) demo_api ;;
            5) demo_python_api ;;
            6) demo_metrics ;;
            [Aa])
                demo_doctor
                demo_quick_scan
                demo_full_audit
                demo_api
                demo_python_api
                demo_metrics
                ;;
            [Qq])
                echo ""
                echo -e "${GREEN}Gracias por usar MIESC!${NC}"
                echo ""
                exit 0
                ;;
            *)
                echo -e "${RED}Opcion invalida${NC}"
                sleep 1
                ;;
        esac
    done
}

# Verificar que estamos en el directorio correcto
if [ ! -f "$PROJECT_DIR/pyproject.toml" ]; then
    echo -e "${RED}Error: No se encontro el proyecto MIESC${NC}"
    echo "Ejecute este script desde el directorio del proyecto"
    exit 1
fi

# Ejecutar menu principal
main_menu
