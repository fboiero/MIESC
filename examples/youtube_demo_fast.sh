#!/bin/bash
# =============================================================================
# MIESC YouTube Demo Script - VERSIÓN RÁPIDA (sin Mythril)
# Para grabación de video fluida (~3 minutos)
#
# Uso: ./demo/youtube_demo_fast.sh
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PAUSE_TIME=2

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

clear_screen() { clear; printf '\033[3J'; }
pause() { sleep $PAUSE_TIME; }
short_pause() { sleep 1; }

type_command() {
    local cmd="$1"
    echo -ne "${GREEN}\$ ${NC}"
    for ((i=0; i<${#cmd}; i++)); do
        echo -n "${cmd:$i:1}"
        sleep 0.02
    done
    echo ""
    sleep 0.3
}

run_command() {
    type_command "$1"
    eval "$1"
}

section_header() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${WHITE}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# =============================================================================
# INTRO
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
# INSTALACIÓN (rápida)
# =============================================================================
section_installation() {
    clear_screen
    section_header "1. INSTALACIÓN"

    echo -e "${WHITE}Instalación desde PyPI:${NC}"
    echo ""

    echo -e "${DIM}# Instalación${NC}"
    type_command "pip install miesc"
    echo -e "${GREEN}Successfully installed miesc-4.3.2${NC}"
    echo ""

    short_pause

    echo -e "${DIM}# Verificar versión${NC}"
    type_command "miesc --version"
    echo "MIESC version 4.3.2"
    echo ""

    short_pause

    echo -e "${DIM}# Verificar herramientas${NC}"
    type_command "miesc doctor"
    echo ""
    echo -e "${WHITE}Core Dependencies: Python 3.12+, solc, node${NC}"
    echo ""
    echo -e "  ${GREEN}✓${NC} slither      ${GREEN}✓${NC} aderyn       ${GREEN}✓${NC} solhint"
    echo -e "  ${GREEN}✓${NC} echidna      ${GREEN}✓${NC} medusa       ${GREEN}✓${NC} foundry"
    echo -e "  ${GREEN}✓${NC} mythril      ${GREEN}✓${NC} halmos       ${GREEN}✓${NC} smtchecker"
    echo -e "  ${GREEN}✓${NC} smartllm     ${GREEN}✓${NC} gptscan      ${GREEN}✓${NC} smartguard"
    echo ""
    echo -e "${GREEN}27/31 tools available${NC}"

    pause
}

# =============================================================================
# ESCANEO RÁPIDO (solo slither + aderyn)
# =============================================================================
section_quick_scan() {
    clear_screen
    section_header "2. ESCANEO RÁPIDO"

    cd "$PROJECT_DIR"

    echo -e "${WHITE}Contrato vulnerable (reentrancy):${NC}"
    echo ""
    echo -e "${RED}"
    cat << 'EOF'
function withdraw() public {
    uint256 balance = balances[msg.sender];
    (bool success, ) = msg.sender.call{value: balance}("");  // VULN!
    balances[msg.sender] = 0;
}
EOF
    echo -e "${NC}"

    short_pause

    echo -e "${DIM}# Escaneo rápido (Slither + Aderyn)${NC}"
    run_command "miesc scan contracts/audit/VulnerableBank.sol --tools slither,aderyn 2>/dev/null | tail -20"

    pause
}

# =============================================================================
# CAPAS DE DEFENSA
# =============================================================================
section_layers() {
    clear_screen
    section_header "3. 9 CAPAS DE DEFENSA"

    echo -e "${WHITE}Arquitectura Defense-in-Depth:${NC}"
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

    echo -e "${DIM}# Auditoría capa específica (Layer 1 - Estático)${NC}"
    run_command "miesc audit layer 1 contracts/audit/VulnerableBank.sol 2>/dev/null | tail -15"

    pause
}

# =============================================================================
# REPORTES
# =============================================================================
section_reports() {
    clear_screen
    section_header "4. REPORTES PROFESIONALES"

    echo -e "${WHITE}Templates disponibles:${NC}"
    echo ""
    echo -e "  ${CYAN}professional${NC}  - Reporte completo para clientes"
    echo -e "  ${CYAN}executive${NC}     - Resumen ejecutivo"
    echo -e "  ${CYAN}technical${NC}     - Análisis técnico detallado"
    echo -e "  ${CYAN}github-pr${NC}     - Formato para PR comments"
    echo ""

    short_pause

    echo -e "${DIM}# Generar reporte${NC}"
    type_command "miesc audit quick contract.sol -o results.json"
    type_command "miesc report results.json -t professional --client 'DeFi Protocol' -o AUDIT.md"
    echo ""
    echo -e "${GREEN}Report saved to AUDIT.md${NC}"

    pause
}

# =============================================================================
# INTEGRACIONES
# =============================================================================
section_integrations() {
    clear_screen
    section_header "5. INTEGRACIONES"

    echo -e "${YELLOW}Foundry:${NC}"
    echo -e "${DIM}"
    cat << 'EOF'
# foundry.toml
[profile.default]
post_build_hook = "miesc audit quick ./src --ci"
EOF
    echo -e "${NC}"

    short_pause

    echo -e "${YELLOW}Hardhat:${NC}"
    echo -e "${DIM}"
    cat << 'EOF'
// hardhat.config.js
require("hardhat-miesc");
module.exports = {
  miesc: { runOnCompile: true, failOn: "high" }
};
EOF
    echo -e "${NC}"

    short_pause

    echo -e "${YELLOW}Pre-commit:${NC}"
    echo -e "${DIM}"
    cat << 'EOF'
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/fboiero/MIESC
    hooks:
      - id: miesc-quick
EOF
    echo -e "${NC}"

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

    echo -e "${WHITE}${BOLD}Instalación:${NC}  ${GREEN}pip install miesc${NC}"
    echo ""
    echo -e "${WHITE}${BOLD}Enlaces:${NC}"
    echo -e "    ${CYAN}GitHub:${NC}  github.com/fboiero/MIESC"
    echo -e "    ${CYAN}Docs:${NC}    fboiero.github.io/MIESC"
    echo -e "    ${CYAN}PyPI:${NC}    pypi.org/project/miesc"
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}${BOLD}  MIESC - Seguridad profesional para Smart Contracts${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${GREEN}${BOLD}  ⭐ Dale una estrella en GitHub!${NC}"
    echo ""
    sleep 3
}

# =============================================================================
# MAIN
# =============================================================================
cd "$PROJECT_DIR"
intro
section_installation
section_quick_scan
section_layers
section_reports
section_integrations
closing

echo -e "${GREEN}Demo completada!${NC}"
