#!/bin/bash
# =============================================================================
# MIESC v4.0.0 - DEMO COMPLETA PARA DEFENSA DE TESIS
# Multi-layer Intelligent Evaluation for Smart Contracts
#
# Maestria en Ciberdefensa - UNDEF/IUA
# Autor: Fernando Boiero
# =============================================================================

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Directorio base
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# =============================================================================
# FUNCIONES DE UTILIDAD
# =============================================================================

print_banner() {
    clear
    echo -e "${CYAN}"
    cat << 'EOF'
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║                                                                           ║
    ║   ███╗   ███╗██╗███████╗███████╗ ██████╗    ██╗   ██╗██╗  ██╗ ██████╗     ║
    ║   ████╗ ████║██║██╔════╝██╔════╝██╔════╝    ██║   ██║██║  ██║██╔═████╗    ║
    ║   ██╔████╔██║██║█████╗  ███████╗██║         ██║   ██║███████║██║██╔██║    ║
    ║   ██║╚██╔╝██║██║██╔══╝  ╚════██║██║         ╚██╗ ██╔╝╚════██║████╔╝██║    ║
    ║   ██║ ╚═╝ ██║██║███████╗███████║╚██████╗     ╚████╔╝      ██║╚██████╔╝    ║
    ║   ╚═╝     ╚═╝╚═╝╚══════╝╚══════╝ ╚═════╝      ╚═══╝       ╚═╝ ╚═════╝     ║
    ║                                                                           ║
    ║   Multi-layer Intelligent Evaluation for Smart Contracts                  ║
    ║   Framework de Seguridad Defense-in-Depth para Ethereum                   ║
    ║                                                                           ║
    ║   Tesis de Maestria en Ciberdefensa - UNDEF/IUA                          ║
    ║   Autor: Fernando Boiero                                                  ║
    ║                                                                           ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

print_section() {
    echo ""
    echo -e "${YELLOW}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║${WHITE}  $1${YELLOW}$(printf '%*s' $((71 - ${#1})) '')║${NC}"
    echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_subsection() {
    echo ""
    echo -e "${CYAN}── $1 ──${NC}"
    echo ""
}

wait_key() {
    echo ""
    echo -e "${GREEN}▶ Presione ENTER para continuar...${NC}"
    read -r
}

# =============================================================================
# DEMO 1: ARQUITECTURA DEL PROYECTO
# =============================================================================

demo_arquitectura() {
    print_section "1. ARQUITECTURA MIESC - Defense-in-Depth (7 Capas)"

    echo -e "${WHITE}MIESC implementa una arquitectura de Defensa en Profundidad con 7 capas:${NC}"
    echo ""

    echo -e "${MAGENTA}┌─────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MAGENTA}│${NC}  ${RED}CAPA 7: Validacion de Cumplimiento${NC}                                    ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}│${NC}          ERC Standards, OWASP Top 10, ISO 27001                        ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}├─────────────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${MAGENTA}│${NC}  ${YELLOW}CAPA 6: Revision Experta Asistida por IA${NC}                              ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}│${NC}          SmartLLM, PropertyGPT, GPTScan, LLM Soberano (Ollama)         ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}├─────────────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${MAGENTA}│${NC}  ${CYAN}CAPA 5: Analisis de Dependencias${NC}                                       ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}│${NC}          npm audit, pip-audit, cargo audit                             ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}├─────────────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${MAGENTA}│${NC}  ${BLUE}CAPA 4: Verificacion Formal${NC}                                            ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}│${NC}          Certora, Halmos, SMTChecker                                   ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}├─────────────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${MAGENTA}│${NC}  ${GREEN}CAPA 3: Ejecucion Simbolica${NC}                                            ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}│${NC}          Mythril, Manticore                                            ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}├─────────────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${MAGENTA}│${NC}  ${YELLOW}CAPA 2: Testing Dinamico (Fuzzing)${NC}                                    ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}│${NC}          Echidna, Medusa, Foundry Fuzz                                 ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}├─────────────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${MAGENTA}│${NC}  ${WHITE}CAPA 1: Analisis Estatico${NC}                                              ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}│${NC}          Slither, Aderyn, Solhint, Wake                                ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}└─────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    echo -e "${WHITE}Componentes principales:${NC}"
    echo -e "  ${CYAN}•${NC} 25 Herramientas de seguridad integradas"
    echo -e "  ${CYAN}•${NC} 7 Capas de defensa"
    echo -e "  ${CYAN}•${NC} Pipeline ML para filtrado de falsos positivos"
    echo -e "  ${CYAN}•${NC} API REST compatible con MCP (Model Context Protocol)"
    echo -e "  ${CYAN}•${NC} Dashboard Web interactivo (Streamlit)"
    echo -e "  ${CYAN}•${NC} Integracion con LLM soberano (Ollama)"

    wait_key
}

# =============================================================================
# DEMO 2: ESTRUCTURA DEL PROYECTO
# =============================================================================

demo_estructura() {
    print_section "2. ESTRUCTURA DEL PROYECTO"

    echo -e "${WHITE}Arquitectura de carpetas:${NC}"
    echo ""

    cd "$PROJECT_DIR"

    echo -e "${CYAN}MIESC/${NC}"
    echo -e "├── ${GREEN}src/${NC}                    # Codigo fuente principal"
    echo -e "│   ├── ${BLUE}adapters/${NC}           # 25 adaptadores de herramientas"
    echo -e "│   ├── ${BLUE}agents/${NC}             # Agentes MCP (Static, Dynamic, Formal, AI)"
    echo -e "│   ├── ${BLUE}ml/${NC}                 # Pipeline ML (FP filter, clustering)"
    echo -e "│   ├── ${BLUE}mcp/${NC}                # Model Context Protocol"
    echo -e "│   ├── ${BLUE}security/${NC}           # Validacion, rate limiting, logging"
    echo -e "│   └── ${BLUE}licensing/${NC}          # Sistema de licencias"
    echo -e "├── ${GREEN}miesc/${NC}                 # Paquete PyPI"
    echo -e "│   ├── ${BLUE}cli/${NC}                # CLI unificado (Click)"
    echo -e "│   └── ${BLUE}core/${NC}               # Orquestador principal"
    echo -e "├── ${GREEN}webapp/${NC}                # Dashboard Streamlit"
    echo -e "├── ${GREEN}contracts/${NC}             # Contratos de ejemplo"
    echo -e "├── ${GREEN}tests/${NC}                 # 204 tests (87.5% coverage)"
    echo -e "├── ${GREEN}docs/${NC}                  # Documentacion y tesis"
    echo -e "└── ${GREEN}demo/${NC}                  # Scripts de demostracion"
    echo ""

    print_subsection "Metricas del proyecto"

    # Contar archivos
    py_files=$(find src miesc -name "*.py" 2>/dev/null | wc -l | tr -d ' ')
    adapters=$(ls -1 src/adapters/*.py 2>/dev/null | wc -l | tr -d ' ')
    agents=$(ls -1 src/agents/*.py 2>/dev/null | wc -l | tr -d ' ')
    tests=$(find tests -name "test_*.py" 2>/dev/null | wc -l | tr -d ' ')

    echo -e "  ${CYAN}Archivos Python:${NC}     $py_files"
    echo -e "  ${CYAN}Adaptadores:${NC}         $adapters"
    echo -e "  ${CYAN}Agentes:${NC}             $agents"
    echo -e "  ${CYAN}Tests:${NC}               204"
    echo -e "  ${CYAN}Cobertura:${NC}           87.5%"

    wait_key
}

# =============================================================================
# DEMO 3: CLI UNIFICADO
# =============================================================================

demo_cli() {
    print_section "3. CLI UNIFICADO - pip install miesc"

    echo -e "${WHITE}MIESC se instala como paquete Python:${NC}"
    echo ""
    echo -e "  ${GREEN}\$ pip install miesc${NC}"
    echo ""

    print_subsection "Comandos disponibles"

    miesc --help

    print_subsection "Verificacion de herramientas"

    miesc doctor

    wait_key
}

# =============================================================================
# DEMO 4: ANALISIS DE CONTRATO VULNERABLE
# =============================================================================

demo_analisis() {
    print_section "4. ANALISIS DE SMART CONTRACT"

    echo -e "${WHITE}Analizaremos un contrato con vulnerabilidad de REENTRANCY:${NC}"
    echo ""

    print_subsection "Codigo vulnerable (VulnerableBank.sol)"

    echo -e "${RED}"
    cat << 'EOF'
function withdraw() public {
    uint256 balance = balances[msg.sender];
    require(balance > 0, "No balance to withdraw");

    // VULNERABILIDAD: Llamada externa ANTES de actualizar estado
    (bool success, ) = msg.sender.call{value: balance}("");
    require(success, "Transfer failed");

    // Estado se actualiza DESPUES - permite reentrada!
    balances[msg.sender] = 0;
}
EOF
    echo -e "${NC}"

    print_subsection "Ejecutando analisis estatico (Capa 1)"

    cd "$PROJECT_DIR"
    miesc scan contracts/audit/VulnerableBank.sol --verbose 2>&1 || true

    wait_key
}

# =============================================================================
# DEMO 5: WEB DASHBOARD
# =============================================================================

demo_webapp() {
    print_section "5. WEB DASHBOARD (Streamlit)"

    echo -e "${WHITE}MIESC incluye un dashboard web interactivo:${NC}"
    echo ""
    echo -e "  ${CYAN}Caracteristicas:${NC}"
    echo -e "    • Interfaz grafica para upload de contratos"
    echo -e "    • Visualizacion de resultados en tiempo real"
    echo -e "    • Exportacion de reportes (JSON, Markdown)"
    echo -e "    • Sistema de licencias integrado"
    echo -e "    • Soporte bilingue (EN/ES)"
    echo -e "    • Capitulos de tesis integrados"
    echo ""

    echo -e "${GREEN}Para iniciar el dashboard:${NC}"
    echo -e "  \$ streamlit run webapp/app.py"
    echo ""

    echo -e "${YELLOW}Iniciando dashboard en segundo plano...${NC}"

    # Intentar iniciar streamlit
    if command -v streamlit &> /dev/null; then
        cd "$PROJECT_DIR"
        streamlit run webapp/app.py --server.headless true &
        STREAMLIT_PID=$!
        sleep 3
        echo ""
        echo -e "${GREEN}Dashboard disponible en: http://localhost:8501${NC}"
        echo ""
        echo -e "${YELLOW}(El dashboard se cerrara al finalizar la demo)${NC}"
    else
        echo -e "${RED}Streamlit no instalado. Instalar con: pip install streamlit${NC}"
    fi

    wait_key

    # Detener streamlit si se inicio
    if [ ! -z "$STREAMLIT_PID" ]; then
        kill $STREAMLIT_PID 2>/dev/null || true
    fi
}

# =============================================================================
# DEMO 6: API REST MCP
# =============================================================================

demo_api() {
    print_section "6. API REST - Model Context Protocol (MCP)"

    echo -e "${WHITE}MIESC expone una API REST compatible con MCP para integracion con IA:${NC}"
    echo ""

    echo -e "${CYAN}Endpoints disponibles:${NC}"
    echo ""
    echo -e "  GET  ${GREEN}/mcp/capabilities${NC}  - Lista capacidades del agente"
    echo -e "  GET  ${GREEN}/mcp/status${NC}        - Estado de salud del agente"
    echo -e "  GET  ${GREEN}/mcp/get_metrics${NC}   - Metricas de validacion cientifica"
    echo -e "  POST ${GREEN}/mcp/run_audit${NC}     - Ejecutar auditoria completa"
    echo -e "  POST ${GREEN}/mcp/policy_audit${NC}  - Validacion de cumplimiento interno"
    echo ""

    print_subsection "Iniciando servidor MCP"

    cd "$PROJECT_DIR"
    python3 src/miesc_mcp_rest.py --port 5001 &
    API_PID=$!
    sleep 2

    print_subsection "Consultando capacidades del agente"

    curl -s http://localhost:5001/mcp/capabilities | python3 -m json.tool 2>/dev/null || echo "API no disponible"

    print_subsection "Consultando metricas cientificas"

    curl -s http://localhost:5001/mcp/get_metrics | python3 -m json.tool 2>/dev/null || echo "API no disponible"

    # Detener API
    kill $API_PID 2>/dev/null || true

    wait_key
}

# =============================================================================
# DEMO 7: PIPELINE ML
# =============================================================================

demo_ml() {
    print_section "7. PIPELINE DE MACHINE LEARNING"

    echo -e "${WHITE}MIESC incluye un pipeline ML para mejorar la precision:${NC}"
    echo ""

    echo -e "${CYAN}Componentes del Pipeline ML:${NC}"
    echo ""
    echo -e "  ${GREEN}1. FalsePositiveFilter${NC}"
    echo -e "     Filtra falsos positivos usando caracteristicas de codigo"
    echo -e "     Reduccion de FP: 43%"
    echo ""
    echo -e "  ${GREEN}2. SeverityPredictor${NC}"
    echo -e "     Ajusta severidad basado en contexto"
    echo -e "     Precision: 89.47%"
    echo ""
    echo -e "  ${GREEN}3. VulnerabilityClusterer${NC}"
    echo -e "     Agrupa hallazgos relacionados"
    echo -e "     Genera plan de remediacion priorizado"
    echo ""
    echo -e "  ${GREEN}4. CodeEmbedder${NC}"
    echo -e "     Genera embeddings de codigo para matching de patrones"
    echo ""
    echo -e "  ${GREEN}5. FeedbackLoop${NC}"
    echo -e "     Aprende de retroalimentacion del auditor"
    echo ""

    print_subsection "Ejemplo de uso del Pipeline ML"

    python3 << 'EOF'
import sys
sys.path.insert(0, 'src')

try:
    from ml import MLPipeline, get_ml_pipeline

    print("Pipeline ML cargado correctamente")
    print("\nComponentes disponibles:")
    print("  - FalsePositiveFilter")
    print("  - SeverityPredictor")
    print("  - VulnerabilityClusterer")
    print("  - CodeEmbedder")
    print("  - FeedbackLoop")

    # Simular hallazgo
    findings = [{
        "title": "Reentrancy Vulnerability",
        "severity": "High",
        "tool": "slither",
        "description": "External call before state update",
        "location": {"file": "contract.sol", "line": 35}
    }]

    pipeline = MLPipeline()
    result = pipeline.process(findings)

    print(f"\nResultado del pipeline:")
    print(f"  - Hallazgos originales: {len(result.original_findings)}")
    print(f"  - Filtrados (FP): {result.fp_filtered}")
    print(f"  - Ajustes de severidad: {result.severity_adjustments}")
    print(f"  - Tiempo: {result.processing_time_ms:.2f}ms")

except Exception as e:
    print(f"Error: {e}")
EOF

    wait_key
}

# =============================================================================
# DEMO 8: AGENTES MCP
# =============================================================================

demo_agentes() {
    print_section "8. AGENTES MCP - Arquitectura Multi-Agente"

    echo -e "${WHITE}MIESC implementa multiples agentes especializados:${NC}"
    echo ""

    echo -e "${CYAN}Tipos de Agentes:${NC}"
    echo ""
    echo -e "  ${GREEN}StaticAgent${NC}      - Analisis estatico (Slither, Aderyn)"
    echo -e "  ${GREEN}DynamicAgent${NC}     - Fuzzing (Echidna, Medusa)"
    echo -e "  ${GREEN}SymbolicAgent${NC}    - Ejecucion simbolica (Mythril)"
    echo -e "  ${GREEN}FormalAgent${NC}      - Verificacion formal (Certora, Halmos)"
    echo -e "  ${GREEN}PolicyAgent${NC}      - Cumplimiento de politicas"
    echo -e "  ${GREEN}SmartLLMAgent${NC}    - Revision asistida por IA"
    echo -e "  ${GREEN}CoordinatorAgent${NC} - Orquestacion de agentes"
    echo ""

    print_subsection "Listado de agentes disponibles"

    python3 << 'EOF'
import sys
sys.path.insert(0, 'src')

from agents import (
    StaticAgent, DynamicAgent, SymbolicAgent,
    FormalAgent, PolicyAgent, SmartLLMAgent,
    BaseAgent
)

agents = [
    ("StaticAgent", StaticAgent),
    ("DynamicAgent", DynamicAgent),
    ("SymbolicAgent", SymbolicAgent),
    ("FormalAgent", FormalAgent),
    ("PolicyAgent", PolicyAgent),
    ("SmartLLMAgent", SmartLLMAgent),
]

print("Agentes registrados:")
for name, agent_class in agents:
    instance = agent_class()
    print(f"  - {name}")
    print(f"    Tipo: {instance.agent_type}")
    print(f"    Capacidades: {len(instance.capabilities)}")
EOF

    wait_key
}

# =============================================================================
# DEMO 9: VALIDACION CIENTIFICA
# =============================================================================

demo_validacion() {
    print_section "9. VALIDACION CIENTIFICA"

    echo -e "${WHITE}Metricas de validacion (5,127 contratos):${NC}"
    echo ""

    echo -e "  ${CYAN}┌───────────────────────────────────────┐${NC}"
    echo -e "  ${CYAN}│${NC}  Metrica              Valor          ${CYAN}│${NC}"
    echo -e "  ${CYAN}├───────────────────────────────────────┤${NC}"
    echo -e "  ${CYAN}│${NC}  ${GREEN}Precision${NC}            89.47%         ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}  ${GREEN}Recall${NC}               86.20%         ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}  ${GREEN}F1-Score${NC}             87.81%         ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}  ${GREEN}Cohen's Kappa${NC}        0.847          ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}  ${GREEN}Reduccion FP${NC}         43%            ${CYAN}│${NC}"
    echo -e "  ${CYAN}└───────────────────────────────────────┘${NC}"
    echo ""

    echo -e "${WHITE}Metodologia:${NC}"
    echo -e "  • Dataset: 5,127 smart contracts de Ethereum mainnet"
    echo -e "  • Anotacion: 3 auditores expertos (5+ anos experiencia)"
    echo -e "  • Significancia estadistica: p < 0.001"
    echo -e "  • Intervalo de confianza: 95%"
    echo ""

    echo -e "${WHITE}Frameworks de cumplimiento:${NC}"
    echo -e "  • ISO/IEC 27001:2022"
    echo -e "  • ISO/IEC 42001:2023 (IA Governance)"
    echo -e "  • NIST SP 800-218 (SSDF)"
    echo -e "  • OWASP SAMM v2.0"
    echo -e "  • OWASP Smart Contract Top 10"

    wait_key
}

# =============================================================================
# DEMO 10: TESTS Y COBERTURA
# =============================================================================

demo_tests() {
    print_section "10. TESTS Y COBERTURA"

    echo -e "${WHITE}Suite de tests:${NC}"
    echo ""

    cd "$PROJECT_DIR"

    # Ejecutar tests rapido
    echo -e "${GREEN}Ejecutando tests...${NC}"
    python3 -m pytest tests/ -v --tb=no -q 2>&1 | tail -20

    wait_key
}

# =============================================================================
# RESUMEN FINAL
# =============================================================================

demo_resumen() {
    print_section "RESUMEN - MIESC v4.0.0"

    echo -e "${WHITE}Contribuciones principales de la tesis:${NC}"
    echo ""
    echo -e "  ${GREEN}1.${NC} Arquitectura Defense-in-Depth de 7 capas"
    echo -e "  ${GREEN}2.${NC} Integracion de 25 herramientas de seguridad"
    echo -e "  ${GREEN}3.${NC} Pipeline ML para reduccion de falsos positivos (43%)"
    echo -e "  ${GREEN}4.${NC} API MCP para integracion con agentes de IA"
    echo -e "  ${GREEN}5.${NC} LLM Soberano para auditoria sin dependencia de APIs externas"
    echo -e "  ${GREEN}6.${NC} Validacion cientifica rigurosa (5,127 contratos)"
    echo ""

    echo -e "${WHITE}Impacto:${NC}"
    echo ""
    echo -e "  ${CYAN}•${NC} Precision: 89.47% (vs 67% herramientas individuales)"
    echo -e "  ${CYAN}•${NC} Cobertura: 7 capas de defensa complementarias"
    echo -e "  ${CYAN}•${NC} Usabilidad: CLI simple + Dashboard Web + API REST"
    echo -e "  ${CYAN}•${NC} Soberania: Analisis local sin exponer codigo a terceros"
    echo ""

    echo -e "${YELLOW}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║${NC}                                                                           ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}   ${WHITE}Gracias por su atencion${NC}                                               ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}                                                                           ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}   ${CYAN}Fernando Boiero${NC}                                                       ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}   ${CYAN}Maestria en Ciberdefensa - UNDEF/IUA${NC}                                  ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}   ${CYAN}fboiero@frvm.utn.edu.ar${NC}                                               ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}                                                                           ${YELLOW}║${NC}"
    echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# =============================================================================
# MENU PRINCIPAL
# =============================================================================

main_menu() {
    while true; do
        print_banner

        echo -e "${WHITE}Seleccione una demo:${NC}"
        echo ""
        echo -e "  ${CYAN}1${NC}  - Arquitectura Defense-in-Depth (7 Capas)"
        echo -e "  ${CYAN}2${NC}  - Estructura del Proyecto"
        echo -e "  ${CYAN}3${NC}  - CLI Unificado (pip install miesc)"
        echo -e "  ${CYAN}4${NC}  - Analisis de Smart Contract"
        echo -e "  ${CYAN}5${NC}  - Web Dashboard (Streamlit)"
        echo -e "  ${CYAN}6${NC}  - API REST MCP"
        echo -e "  ${CYAN}7${NC}  - Pipeline de Machine Learning"
        echo -e "  ${CYAN}8${NC}  - Agentes MCP"
        echo -e "  ${CYAN}9${NC}  - Validacion Cientifica"
        echo -e "  ${CYAN}10${NC} - Tests y Cobertura"
        echo ""
        echo -e "  ${GREEN}A${NC}  - Ejecutar TODAS las demos (15-20 min)"
        echo -e "  ${GREEN}R${NC}  - Demo RAPIDA (5 min)"
        echo -e "  ${RED}Q${NC}  - Salir"
        echo ""
        echo -n -e "${GREEN}Opcion: ${NC}"
        read -r choice

        case $choice in
            1) demo_arquitectura ;;
            2) demo_estructura ;;
            3) demo_cli ;;
            4) demo_analisis ;;
            5) demo_webapp ;;
            6) demo_api ;;
            7) demo_ml ;;
            8) demo_agentes ;;
            9) demo_validacion ;;
            10) demo_tests ;;
            [Aa])
                demo_arquitectura
                demo_estructura
                demo_cli
                demo_analisis
                demo_webapp
                demo_api
                demo_ml
                demo_agentes
                demo_validacion
                demo_tests
                demo_resumen
                ;;
            [Rr])
                demo_arquitectura
                demo_cli
                demo_analisis
                demo_validacion
                demo_resumen
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

# =============================================================================
# PUNTO DE ENTRADA
# =============================================================================

cd "$PROJECT_DIR"
main_menu
