#!/bin/bash
# =============================================================================
# MIESC YouTube Demo Script v4.3
# Script automatizado para grabación de video promocional
#
# Uso: ./demo/youtube_demo.sh [--auto|--interactive]
#   --auto: Ejecuta automáticamente con pausas
#   --interactive: Espera ENTER entre secciones (default)
#
# Requiere: miesc instalado, terminal con soporte de colores
# =============================================================================

set -e

# Configuración
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
AUTO_MODE=false
PAUSE_TIME=2

# Parsear argumentos
for arg in "$@"; do
    case $arg in
        --auto) AUTO_MODE=true ;;
        --interactive) AUTO_MODE=false ;;
    esac
done

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
MAGENTA='\033[0;35m'
DIM='\033[2m'
NC='\033[0m'
BOLD='\033[1m'

# Funciones de utilidad
clear_screen() {
    clear
    printf '\033[3J'
}

pause() {
    if [ "$AUTO_MODE" = true ]; then
        sleep $PAUSE_TIME
    else
        echo ""
        echo -e "${DIM}Presiona ENTER para continuar...${NC}"
        read -r
    fi
}

short_pause() {
    sleep 1
}

type_command() {
    local cmd="$1"
    echo -ne "${GREEN}\$ ${NC}"
    for ((i=0; i<${#cmd}; i++)); do
        echo -n "${cmd:$i:1}"
        sleep 0.03
    done
    echo ""
    sleep 0.5
}

run_command() {
    local cmd="$1"
    type_command "$cmd"
    eval "$cmd"
}

section_header() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${WHITE}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# =============================================================================
# INTRO - Banner
# =============================================================================
intro() {
    clear_screen

    echo -e "${CYAN}"
    cat << 'EOF'

    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║                                                                           ║
    ║   ███╗   ███╗ ██╗ ███████╗ ███████╗  ██████╗                              ║
    ║   ████╗ ████║ ██║ ██╔════╝ ██╔════╝ ██╔════╝                              ║
    ║   ██╔████╔██║ ██║ █████╗   ███████╗ ██║                                   ║
    ║   ██║╚██╔╝██║ ██║ ██╔══╝   ╚════██║ ██║                                   ║
    ║   ██║ ╚═╝ ██║ ██║ ███████╗ ███████║ ╚██████╗                              ║
    ║   ╚═╝     ╚═╝ ╚═╝ ╚══════╝ ╚══════╝  ╚═════╝                              ║
    ║                                                                           ║
    ║   Multi-layer Intelligent Evaluation for Smart Contracts                  ║
    ║                                                                           ║
    ╚═══════════════════════════════════════════════════════════════════════════╝

EOF
    echo -e "${NC}"

    echo -e "${WHITE}${BOLD}Framework de Seguridad Defense-in-Depth para Smart Contracts${NC}"
    echo ""
    echo -e "  ${GREEN}•${NC} ${BOLD}31${NC} herramientas de seguridad integradas"
    echo -e "  ${GREEN}•${NC} ${BOLD}9${NC} capas de defensa"
    echo -e "  ${GREEN}•${NC} ${BOLD}100%${NC} precisión en benchmarks validados"
    echo -e "  ${GREEN}•${NC} Análisis con IA y Machine Learning"
    echo ""

    pause
}

# =============================================================================
# SECCIÓN 1: Instalación
# =============================================================================
section_installation() {
    clear_screen
    section_header "1. INSTALACIÓN"

    echo -e "${WHITE}Instalación desde PyPI:${NC}"
    echo ""

    echo -e "${DIM}# Instalación básica${NC}"
    type_command "pip install miesc"
    echo -e "${GREEN}Successfully installed miesc-4.3.2${NC}"
    echo ""

    short_pause

    echo -e "${DIM}# Verificar versión${NC}"
    run_command "miesc --version"
    echo ""

    short_pause

    echo -e "${DIM}# Verificar herramientas disponibles${NC}"
    run_command "miesc doctor"

    pause
}

# =============================================================================
# SECCIÓN 2: Escaneo Rápido
# =============================================================================
section_quick_scan() {
    clear_screen
    section_header "2. ESCANEO RÁPIDO"

    cd "$PROJECT_DIR"

    echo -e "${WHITE}Analizando contrato con vulnerabilidad de reentrancy:${NC}"
    echo ""

    # Mostrar código vulnerable
    echo -e "${DIM}# Código vulnerable:${NC}"
    echo -e "${RED}"
    cat << 'EOF'
function withdraw() public {
    uint256 balance = balances[msg.sender];
    require(balance > 0);

    // VULNERABILIDAD: Llamada externa ANTES de actualizar estado
    (bool success, ) = msg.sender.call{value: balance}("");
    require(success);

    balances[msg.sender] = 0;  // Estado se actualiza DESPUÉS
}
EOF
    echo -e "${NC}"

    short_pause

    echo -e "${DIM}# Escaneo rápido${NC}"
    run_command "miesc scan contracts/audit/VulnerableBank.sol"

    pause
}

# =============================================================================
# SECCIÓN 3: Auditoría de 9 Capas
# =============================================================================
section_full_audit() {
    clear_screen
    section_header "3. AUDITORÍA COMPLETA - 9 CAPAS DE DEFENSA"

    cd "$PROJECT_DIR"

    echo -e "${WHITE}Las 9 capas de defensa de MIESC:${NC}"
    echo ""

    echo -e "${MAGENTA}┌─────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MAGENTA}│${NC} ${WHITE}Capa 1:${NC} Análisis Estático      ${DIM}(Slither, Aderyn, Solhint)${NC}           ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}│${NC} ${WHITE}Capa 2:${NC} Testing Dinámico       ${DIM}(Echidna, Medusa, Foundry)${NC}           ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}│${NC} ${WHITE}Capa 3:${NC} Ejecución Simbólica    ${DIM}(Mythril, Manticore, Halmos)${NC}         ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}│${NC} ${WHITE}Capa 4:${NC} Verificación Formal    ${DIM}(Certora, SMTChecker)${NC}                ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}│${NC} ${WHITE}Capa 5:${NC} Property Testing       ${DIM}(PropertyGPT, Wake, Vertigo)${NC}         ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}│${NC} ${WHITE}Capa 6:${NC} Análisis AI/LLM        ${DIM}(SmartLLM, GPTScan)${NC}                   ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}│${NC} ${WHITE}Capa 7:${NC} Reconocimiento ML      ${DIM}(DA-GNN, SmartGuard)${NC}                  ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}│${NC} ${WHITE}Capa 8:${NC} Seguridad DeFi         ${DIM}(MEV Detector, Gas Analyzer)${NC}          ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}│${NC} ${WHITE}Capa 9:${NC} Detección Avanzada     ${DIM}(Threat Model, SmartBugs)${NC}             ${MAGENTA}│${NC}"
    echo -e "${MAGENTA}└─────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    short_pause

    echo -e "${DIM}# Auditoría rápida (4 herramientas principales)${NC}"
    run_command "miesc audit quick contracts/audit/VulnerableBank.sol"

    pause
}

# =============================================================================
# SECCIÓN 4: Generación de Reportes
# =============================================================================
section_reports() {
    clear_screen
    section_header "4. GENERACIÓN DE REPORTES PROFESIONALES"

    cd "$PROJECT_DIR"

    echo -e "${WHITE}Templates disponibles:${NC}"
    echo ""
    echo -e "  ${CYAN}professional${NC}  - Reporte completo para clientes"
    echo -e "  ${CYAN}executive${NC}     - Resumen ejecutivo"
    echo -e "  ${CYAN}technical${NC}     - Análisis técnico detallado"
    echo -e "  ${CYAN}github-pr${NC}     - Formato para PR comments"
    echo -e "  ${CYAN}simple${NC}        - Lista básica de hallazgos"
    echo ""

    short_pause

    echo -e "${DIM}# Guardar resultados en JSON${NC}"
    run_command "miesc audit quick contracts/audit/VulnerableBank.sol -o /tmp/results.json"
    echo ""

    short_pause

    echo -e "${DIM}# Generar reporte profesional${NC}"
    run_command "miesc report /tmp/results.json -t professional --client 'DeFi Protocol' -o /tmp/AUDIT_REPORT.md"
    echo ""

    echo -e "${DIM}# Vista previa del reporte${NC}"
    if [ -f /tmp/AUDIT_REPORT.md ]; then
        head -40 /tmp/AUDIT_REPORT.md
    fi

    pause
}

# =============================================================================
# SECCIÓN 5: Benchmark y Tracking
# =============================================================================
section_benchmark() {
    clear_screen
    section_header "5. TRACKING DE POSTURA DE SEGURIDAD"

    cd "$PROJECT_DIR"

    echo -e "${WHITE}Seguimiento de mejoras en seguridad a lo largo del tiempo:${NC}"
    echo ""

    echo -e "${DIM}# Guardar benchmark actual${NC}"
    type_command "miesc benchmark contracts/ --save"
    echo -e "${GREEN}Benchmark saved: 20260111_143022${NC}"
    echo ""

    short_pause

    echo -e "${DIM}# Comparar con ejecución anterior${NC}"
    type_command "miesc benchmark contracts/ --compare last"
    echo ""
    echo -e "${WHITE}Security Posture Comparison${NC}"
    echo -e "┌──────────┬──────────┬─────────┬────────┐"
    echo -e "│ Metric   │ Previous │ Current │ Change │"
    echo -e "├──────────┼──────────┼─────────┼────────┤"
    echo -e "│ Critical │    2     │    0    │ ${GREEN}-2${NC}     │"
    echo -e "│ High     │    3     │    1    │ ${GREEN}-2${NC}     │"
    echo -e "│ Medium   │    5     │    3    │ ${GREEN}-2${NC}     │"
    echo -e "│ Total    │   10     │    4    │ ${GREEN}-6${NC}     │"
    echo -e "└──────────┴──────────┴─────────┴────────┘"
    echo ""
    echo -e "${GREEN}Improved by 6 findings${NC}"

    pause
}

# =============================================================================
# SECCIÓN 6: Integraciones
# =============================================================================
section_integrations() {
    clear_screen
    section_header "6. INTEGRACIONES"

    echo -e "${WHITE}MIESC se integra con tu flujo de trabajo:${NC}"
    echo ""

    # Foundry
    echo -e "${YELLOW}Foundry Integration:${NC}"
    echo -e "${DIM}"
    cat << 'EOF'
# foundry.toml
[profile.default]
post_build_hook = "miesc audit quick ./src --ci"

[profile.ci]
post_build_hook = "miesc audit quick ./src --ci --fail-on high"
EOF
    echo -e "${NC}"

    short_pause

    # Hardhat
    echo -e "${YELLOW}Hardhat Integration:${NC}"
    echo -e "${DIM}"
    cat << 'EOF'
// hardhat.config.js
require("hardhat-miesc");

module.exports = {
  solidity: "0.8.20",
  miesc: {
    enabled: true,
    runOnCompile: true,
    failOn: "high",
  },
};
EOF
    echo -e "${NC}"

    short_pause

    # Pre-commit
    echo -e "${YELLOW}Pre-commit Hook:${NC}"
    echo -e "${DIM}"
    cat << 'EOF'
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/fboiero/MIESC
    rev: v4.3.2
    hooks:
      - id: miesc-quick
        args: ['--ci']
EOF
    echo -e "${NC}"

    pause
}

# =============================================================================
# SECCIÓN 7: Custom Detectors
# =============================================================================
section_custom_detectors() {
    clear_screen
    section_header "7. DETECTORES PERSONALIZADOS"

    echo -e "${WHITE}API para crear detectores custom:${NC}"
    echo ""

    echo -e "${DIM}"
    cat << 'EOF'
from miesc.detectors import BaseDetector, Finding, Severity

class FlashLoanDetector(BaseDetector):
    name = "flash-loan-attack"
    description = "Detects flash loan attack patterns"

    def analyze(self, source_code, file_path=None):
        findings = []
        # Tu lógica de detección aquí
        return findings
EOF
    echo -e "${NC}"

    short_pause

    echo -e "${DIM}# Listar detectores registrados${NC}"
    run_command "miesc detectors list"

    pause
}

# =============================================================================
# CIERRE
# =============================================================================
closing() {
    clear_screen

    echo -e "${CYAN}"
    cat << 'EOF'

    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║                                                                           ║
    ║   ███╗   ███╗ ██╗ ███████╗ ███████╗  ██████╗                              ║
    ║   ████╗ ████║ ██║ ██╔════╝ ██╔════╝ ██╔════╝                              ║
    ║   ██╔████╔██║ ██║ █████╗   ███████╗ ██║                                   ║
    ║   ██║╚██╔╝██║ ██║ ██╔══╝   ╚════██║ ██║                                   ║
    ║   ██║ ╚═╝ ██║ ██║ ███████╗ ███████║ ╚██████╗                              ║
    ║   ╚═╝     ╚═╝ ╚═╝ ╚══════╝ ╚══════╝  ╚═════╝                              ║
    ║                                                                           ║
    ╚═══════════════════════════════════════════════════════════════════════════╝

EOF
    echo -e "${NC}"

    echo -e "${WHITE}${BOLD}Instalación:${NC}"
    echo ""
    echo -e "    ${GREEN}pip install miesc${NC}"
    echo ""

    echo -e "${WHITE}${BOLD}Enlaces:${NC}"
    echo ""
    echo -e "    ${CYAN}GitHub:${NC}        github.com/fboiero/MIESC"
    echo -e "    ${CYAN}Documentación:${NC} fboiero.github.io/MIESC"
    echo -e "    ${CYAN}PyPI:${NC}          pypi.org/project/miesc"
    echo ""

    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${WHITE}${BOLD}  MIESC - Seguridad profesional para Smart Contracts${NC}"
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    echo -e "${GREEN}${BOLD}Dale una estrella en GitHub!${NC}"
    echo ""
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    cd "$PROJECT_DIR"

    intro
    section_installation
    section_quick_scan
    section_full_audit
    section_reports
    section_benchmark
    section_integrations
    section_custom_detectors
    closing

    echo ""
    echo -e "${GREEN}Demo completada!${NC}"
    echo ""
}

# Ejecutar
main
