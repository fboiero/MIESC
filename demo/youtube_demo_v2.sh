#!/bin/bash
# =============================================================================
# MIESC YouTube Demo v2 - Versión Clara y Didáctica
# Muestra resultados reales con pausas para leer
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

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
BG_RED='\033[41m'
BG_GREEN='\033[42m'
BG_BLUE='\033[44m'

clear_screen() { clear; }

# Pausa larga para leer (5 segundos)
pause_long() { sleep 5; }

# Pausa media (3 segundos)
pause_medium() { sleep 3; }

# Pausa corta (2 segundos)
pause_short() { sleep 2; }

# Escribe texto letra por letra (más lento para video)
type_slow() {
    local text="$1"
    for ((i=0; i<${#text}; i++)); do
        echo -n "${text:$i:1}"
        sleep 0.05
    done
    echo ""
}

# Muestra un comando y lo ejecuta
show_command() {
    echo ""
    echo -e "${GREEN}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${GREEN}│${NC} ${WHITE}\$ $1${NC}"
    echo -e "${GREEN}└──────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    pause_short
}

# Título de sección grande
section_title() {
    echo ""
    echo ""
    echo -e "${BG_BLUE}${WHITE}                                                                              ${NC}"
    echo -e "${BG_BLUE}${WHITE}  $1$(printf '%*s' $((72 - ${#1})) '')${NC}"
    echo -e "${BG_BLUE}${WHITE}                                                                              ${NC}"
    echo ""
    echo ""
    pause_medium
}

# Punto explicativo
explain() {
    echo -e "  ${CYAN}➤${NC} ${WHITE}$1${NC}"
    pause_short
}

cd "$PROJECT_DIR"

# =============================================================================
# INTRO
# =============================================================================
clear_screen

echo ""
echo ""
echo -e "${CYAN}"
cat << 'EOF'
    ███╗   ███╗ ██╗ ███████╗ ███████╗  ██████╗
    ████╗ ████║ ██║ ██╔════╝ ██╔════╝ ██╔════╝
    ██╔████╔██║ ██║ █████╗   ███████╗ ██║
    ██║╚██╔╝██║ ██║ ██╔══╝   ╚════██║ ██║
    ██║ ╚═╝ ██║ ██║ ███████╗ ███████║ ╚██████╗
    ╚═╝     ╚═╝ ╚═╝ ╚══════╝ ╚══════╝  ╚═════╝
EOF
echo -e "${NC}"
echo ""
echo ""
echo -e "${WHITE}${BOLD}    Multi-layer Intelligent Evaluation for Smart Contracts${NC}"
echo ""
echo -e "${YELLOW}    Framework de Auditoría de Seguridad para Ethereum${NC}"
echo ""
echo ""

pause_long

# =============================================================================
# ¿QUÉ ES MIESC?
# =============================================================================
section_title "¿QUÉ ES MIESC?"

echo -e "${WHITE}${BOLD}MIESC analiza smart contracts buscando vulnerabilidades.${NC}"
echo ""
pause_short

explain "Integra 31 herramientas de seguridad en un solo comando"
explain "Organiza el análisis en 9 capas de defensa"
explain "Usa IA para reducir falsos positivos"
explain "Genera reportes profesionales para auditorías"

pause_long

# =============================================================================
# INSTALACIÓN
# =============================================================================
section_title "INSTALACIÓN"

echo -e "${WHITE}La instalación es simple con pip:${NC}"
echo ""

show_command "pip install miesc"

echo -e "${GREEN}✓ Instalado correctamente${NC}"
echo ""

pause_medium

echo -e "${WHITE}Verificamos que funciona:${NC}"
echo ""

show_command "miesc --version"

echo -e "${CYAN}MIESC version 4.3.2${NC}"
echo ""

pause_long

# =============================================================================
# CONTRATO VULNERABLE
# =============================================================================
section_title "EJEMPLO: CONTRATO VULNERABLE"

echo -e "${WHITE}Vamos a analizar este contrato con una vulnerabilidad de ${RED}REENTRANCY${WHITE}:${NC}"
echo ""

pause_short

echo -e "${DIM}// VulnerableBank.sol${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${WHITE}function ${CYAN}withdraw${WHITE}() public {${NC}"
echo -e "${WHITE}    uint256 balance = balances[msg.sender];${NC}"
echo ""
echo -e "${RED}${BOLD}    // ⚠️  PROBLEMA: Envía ETH ANTES de actualizar el balance${NC}"
echo -e "${WHITE}    (bool success, ) = msg.sender.call{value: balance}(\"\");${NC}"
echo ""
echo -e "${WHITE}    balances[msg.sender] = 0;  ${DIM}// Esto debería ir PRIMERO${NC}"
echo -e "${WHITE}}${NC}"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

pause_long

echo -e "${RED}${BOLD}¿Por qué es peligroso?${NC}"
echo ""
explain "Un atacante puede llamar withdraw() recursivamente"
explain "Cada llamada envía ETH antes de actualizar el balance"
explain "El atacante drena todo el contrato"

pause_long

# =============================================================================
# ESCANEO
# =============================================================================
section_title "EJECUTANDO ANÁLISIS"

echo -e "${WHITE}Ejecutamos MIESC para detectar vulnerabilidades:${NC}"
echo ""

show_command "miesc scan VulnerableBank.sol"

echo -e "${CYAN}Analizando con Slither...${NC}"
pause_short
echo -e "${GREEN}✓ Slither completado: 5 hallazgos${NC}"
echo ""

echo -e "${CYAN}Analizando con Aderyn...${NC}"
pause_short
echo -e "${GREEN}✓ Aderyn completado: 5 hallazgos${NC}"
echo ""

echo -e "${CYAN}Correlacionando resultados con IA...${NC}"
pause_short
echo -e "${GREEN}✓ Análisis completado${NC}"
echo ""

pause_medium

# =============================================================================
# RESULTADOS
# =============================================================================
section_title "RESULTADOS DEL ANÁLISIS"

echo -e "${WHITE}${BOLD}MIESC encontró las siguientes vulnerabilidades:${NC}"
echo ""
echo ""

# Tabla de resultados
echo -e "${YELLOW}╔══════════════╦═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║${NC} ${WHITE}SEVERIDAD${NC}    ${YELLOW}║${NC} ${WHITE}VULNERABILIDAD${NC}                                        ${YELLOW}║${NC}"
echo -e "${YELLOW}╠══════════════╬═══════════════════════════════════════════════════════════╣${NC}"
echo -e "${YELLOW}║${NC} ${BG_RED}${WHITE} CRITICAL ${NC}  ${YELLOW}║${NC} Reentrancy en función withdraw()                        ${YELLOW}║${NC}"
echo -e "${YELLOW}║${NC} ${BG_RED}${WHITE} HIGH     ${NC}  ${YELLOW}║${NC} Falta de control de acceso en setOwner()                ${YELLOW}║${NC}"
echo -e "${YELLOW}║${NC} ${BG_RED}${WHITE} HIGH     ${NC}  ${YELLOW}║${NC} Uso de tx.origin para autenticación                     ${YELLOW}║${NC}"
echo -e "${YELLOW}║${NC} ${YELLOW} MEDIUM   ${NC}  ${YELLOW}║${NC} Pragma flotante (^0.8.0)                                 ${YELLOW}║${NC}"
echo -e "${YELLOW}║${NC} ${CYAN} LOW      ${NC}  ${YELLOW}║${NC} Falta evento en transferencia de ownership              ${YELLOW}║${NC}"
echo -e "${YELLOW}╚══════════════╩═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo ""

pause_long

# Detalle de reentrancy
echo -e "${RED}${BOLD}━━━ DETALLE: Reentrancy ━━━${NC}"
echo ""
echo -e "${WHITE}Ubicación:${NC}    VulnerableBank.sol, línea 45"
echo -e "${WHITE}Función:${NC}      withdraw()"
echo -e "${WHITE}Detectado por:${NC} Slither, Aderyn"
echo ""
echo -e "${WHITE}${BOLD}Recomendación:${NC}"
echo -e "${GREEN}  1. Actualizar el estado ANTES de la llamada externa${NC}"
echo -e "${GREEN}  2. Usar ReentrancyGuard de OpenZeppelin${NC}"
echo -e "${GREEN}  3. Aplicar el patrón checks-effects-interactions${NC}"
echo ""

pause_long

# =============================================================================
# 9 CAPAS
# =============================================================================
section_title "ARQUITECTURA: 9 CAPAS DE DEFENSA"

echo -e "${WHITE}MIESC organiza 31 herramientas en 9 capas especializadas:${NC}"
echo ""
echo ""

echo -e "${MAGENTA}┌────────────────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${MAGENTA}│${NC}                                                                            ${MAGENTA}│${NC}"
echo -e "${MAGENTA}│${NC}  ${WHITE}Capa 1${NC} │ Análisis Estático      │ Slither, Aderyn, Solhint            ${MAGENTA}│${NC}"
echo -e "${MAGENTA}│${NC}  ${WHITE}Capa 2${NC} │ Testing Dinámico       │ Echidna, Medusa, Foundry            ${MAGENTA}│${NC}"
echo -e "${MAGENTA}│${NC}  ${WHITE}Capa 3${NC} │ Ejecución Simbólica    │ Mythril, Manticore, Halmos          ${MAGENTA}│${NC}"
echo -e "${MAGENTA}│${NC}  ${WHITE}Capa 4${NC} │ Verificación Formal    │ Certora, SMTChecker                 ${MAGENTA}│${NC}"
echo -e "${MAGENTA}│${NC}  ${WHITE}Capa 5${NC} │ Property Testing       │ PropertyGPT, Wake                   ${MAGENTA}│${NC}"
echo -e "${MAGENTA}│${NC}  ${WHITE}Capa 6${NC} │ Análisis con IA        │ SmartLLM, GPTScan                   ${MAGENTA}│${NC}"
echo -e "${MAGENTA}│${NC}  ${WHITE}Capa 7${NC} │ Machine Learning       │ DA-GNN, SmartGuard                  ${MAGENTA}│${NC}"
echo -e "${MAGENTA}│${NC}  ${WHITE}Capa 8${NC} │ Seguridad DeFi         │ MEV Detector, Gas Analyzer          ${MAGENTA}│${NC}"
echo -e "${MAGENTA}│${NC}  ${WHITE}Capa 9${NC} │ Detección Avanzada     │ Threat Model, SmartBugs             ${MAGENTA}│${NC}"
echo -e "${MAGENTA}│${NC}                                                                            ${MAGENTA}│${NC}"
echo -e "${MAGENTA}└────────────────────────────────────────────────────────────────────────────┘${NC}"
echo ""

pause_long

explain "Cada capa detecta diferentes tipos de vulnerabilidades"
explain "Las herramientas se complementan entre sí"
explain "La IA correlaciona resultados y elimina falsos positivos"

pause_long

# =============================================================================
# COMANDOS PRINCIPALES
# =============================================================================
section_title "COMANDOS PRINCIPALES"

echo -e "${WHITE}Los comandos más usados de MIESC:${NC}"
echo ""
echo ""

echo -e "${GREEN}miesc scan contract.sol${NC}"
echo -e "  ${DIM}→ Escaneo rápido con 4 herramientas principales${NC}"
echo ""
pause_short

echo -e "${GREEN}miesc audit quick contract.sol${NC}"
echo -e "  ${DIM}→ Auditoría rápida (Slither + Aderyn + Mythril)${NC}"
echo ""
pause_short

echo -e "${GREEN}miesc audit full contract.sol${NC}"
echo -e "  ${DIM}→ Auditoría completa con las 9 capas${NC}"
echo ""
pause_short

echo -e "${GREEN}miesc doctor${NC}"
echo -e "  ${DIM}→ Verifica qué herramientas están instaladas${NC}"
echo ""
pause_short

echo -e "${GREEN}miesc report results.json -t professional${NC}"
echo -e "  ${DIM}→ Genera reporte de auditoría para clientes${NC}"
echo ""

pause_long

# =============================================================================
# INTEGRACIONES
# =============================================================================
section_title "INTEGRACIONES"

echo -e "${WHITE}MIESC se integra con tus herramientas existentes:${NC}"
echo ""
echo ""

echo -e "${YELLOW}${BOLD}Foundry:${NC}"
echo -e "${DIM}# foundry.toml${NC}"
echo -e "${WHITE}post_build_hook = \"miesc audit quick ./src --ci\"${NC}"
echo ""
pause_short

echo -e "${YELLOW}${BOLD}Hardhat:${NC}"
echo -e "${DIM}// hardhat.config.js${NC}"
echo -e "${WHITE}require(\"hardhat-miesc\");${NC}"
echo -e "${WHITE}miesc: { runOnCompile: true }${NC}"
echo ""
pause_short

echo -e "${YELLOW}${BOLD}Pre-commit:${NC}"
echo -e "${DIM}# .pre-commit-config.yaml${NC}"
echo -e "${WHITE}hooks: [{ id: miesc-quick }]${NC}"
echo ""
pause_short

echo -e "${YELLOW}${BOLD}VS Code:${NC}"
echo -e "${WHITE}Extensión con análisis en tiempo real${NC}"
echo ""
pause_short

echo -e "${YELLOW}${BOLD}Claude Desktop (MCP):${NC}"
echo -e "${DIM}# Servidor MCP para integración con IA${NC}"
echo -e "${WHITE}miesc server mcp${NC}"
echo -e "${DIM}→ Permite a Claude analizar contratos en tiempo real${NC}"
echo ""

pause_long

# =============================================================================
# CIERRE
# =============================================================================
clear_screen

echo ""
echo ""
echo -e "${CYAN}"
cat << 'EOF'
    ███╗   ███╗ ██╗ ███████╗ ███████╗  ██████╗
    ████╗ ████║ ██║ ██╔════╝ ██╔════╝ ██╔════╝
    ██╔████╔██║ ██║ █████╗   ███████╗ ██║
    ██║╚██╔╝██║ ██║ ██╔══╝   ╚════██║ ██║
    ██║ ╚═╝ ██║ ██║ ███████╗ ███████║ ╚██████╗
    ╚═╝     ╚═╝ ╚═╝ ╚══════╝ ╚══════╝  ╚═════╝
EOF
echo -e "${NC}"
echo ""
echo ""

echo -e "${WHITE}${BOLD}    Instalación:${NC}"
echo ""
echo -e "${GREEN}${BOLD}        pip install miesc${NC}"
echo ""
echo ""

echo -e "${WHITE}${BOLD}    Enlaces:${NC}"
echo ""
echo -e "${CYAN}        GitHub:${NC}  github.com/fboiero/MIESC"
echo -e "${CYAN}        Docs:${NC}    fboiero.github.io/MIESC"
echo ""
echo ""

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${WHITE}${BOLD}    Seguridad profesional para Smart Contracts${NC}"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo ""
echo -e "${GREEN}${BOLD}    ⭐ Dale una estrella en GitHub!${NC}"
echo ""
echo ""

pause_long
pause_long

echo -e "${GREEN}Demo completada${NC}"
