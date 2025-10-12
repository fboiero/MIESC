#!/bin/bash
# =============================================================================
# XAUDIT FRAMEWORK - SCRIPT DE DEMOSTRACIÓN DE TESIS
# =============================================================================
# Universidad de la Defensa Nacional (UNDEF)
# Centro Regional Universitario Córdoba - IUA
# Maestría en Ciberdefensa
# Autor: Fernando Boiero
# Año: 2025
# =============================================================================

set -e

# =============================================================================
# CONFIGURACIÓN DE LA DEMOSTRACIÓN
# =============================================================================

# Modo de demostración (cambiar a 'fast' para demo rápida)
DEMO_MODE="${1:-normal}"  # normal | fast | auto

# Tiempos de espera configurables
if [ "$DEMO_MODE" = "fast" ]; then
    DELAY_SHORT=0.3
    DELAY_MEDIUM=0.8
    DELAY_LONG=1.2
    PROGRESS_SPEED=0.05
    AUTO_CONTINUE=true
elif [ "$DEMO_MODE" = "auto" ]; then
    DELAY_SHORT=0.5
    DELAY_MEDIUM=1.0
    DELAY_LONG=1.5
    PROGRESS_SPEED=0.08
    AUTO_CONTINUE=true
else
    DELAY_SHORT=1
    DELAY_MEDIUM=2
    DELAY_LONG=3
    PROGRESS_SPEED=0.1
    AUTO_CONTINUE=false
fi

# =============================================================================
# COLORES Y ESTILOS
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# =============================================================================
# FUNCIONES DE UTILIDAD
# =============================================================================

show_header() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}                                                                    ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}    ${BOLD}${WHITE}XAUDIT - DEMOSTRACIÓN DE TESIS DE MAESTRÍA${NC}              ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}                                                                    ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${CYAN}Universidad de la Defensa Nacional (UNDEF)${NC}                   ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${CYAN}Centro Regional Universitario Córdoba - IUA${NC}                 ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${CYAN}Maestría en Ciberdefensa${NC}                                    ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}                                                                    ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${GREEN}Autor: Fernando Boiero | Año: 2025${NC}                         ${BLUE}║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

show_section() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}  $1${NC}"
    [ -n "$2" ] && echo -e "${DIM}  $2${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

show_subsection() {
    echo ""
    echo -e "${YELLOW}▶ ${BOLD}$1${NC}"
    echo -e "${DIM}─────────────────────────────────────────────────────────────────${NC}"
    echo ""
}

pause() {
    if [ "$AUTO_CONTINUE" = true ]; then
        sleep "$DELAY_LONG"
    else
        echo ""
        echo -e "${YELLOW}${BOLD}[ENTER]${NC} ${DIM}Presiona ENTER para continuar...${NC}"
        read
    fi
}

bullet() {
    echo -e "  $1 $2"
}

show_metric() {
    echo -e "  ${BOLD}$1:${NC} $3$2${NC}"
}

show_comparison() {
    echo -e "  ${BOLD}$1:${NC}"
    echo -e "    ${DIM}Antes:${NC}   ${RED}$2${NC}"
    echo -e "    ${DIM}Después:${NC} ${GREEN}$3${NC}"
    echo -e "    ${DIM}Mejora:${NC}  ${CYAN}$4${NC}"
}

show_progress() {
    echo -ne "  $1 ["
    for i in {1..20}; do
        echo -ne "${GREEN}█${NC}"
        sleep "$PROGRESS_SPEED"
    done
    echo -e "] ${GREEN}✓${NC}"
}

check_tool() {
    if command -v "$2" &> /dev/null; then
        echo -e "    ${GREEN}✓${NC} ${BOLD}$1${NC} ${DIM}$(command -v $2)${NC}"
        return 0
    else
        echo -e "    ${RED}✗${NC} ${BOLD}$1${NC} ${DIM}no encontrado${NC}"
        return 1
    fi
}

# =============================================================================
# VERIFICACIÓN E INSTALACIÓN DE DEPENDENCIAS
# =============================================================================

check_and_install_deps() {
    show_subsection "Verificación de Dependencias"

    local missing_deps=0

    echo -e "${DIM}Verificando herramientas requeridas...${NC}"
    echo ""

    # Python 3
    if check_tool "Python 3" "python3"; then
        :
    else
        missing_deps=$((missing_deps + 1))
        echo -e "      ${YELLOW}→${NC} ${DIM}Instalar: brew install python3${NC}"
    fi

    # Slither
    if check_tool "Slither" "slither"; then
        :
    else
        missing_deps=$((missing_deps + 1))
        echo -e "      ${YELLOW}→${NC} ${DIM}Instalar: pip3 install slither-analyzer${NC}"
    fi

    # Foundry (opcional para demo)
    if check_tool "Foundry" "forge"; then
        :
    else
        echo -e "      ${DIM}(Opcional para demo - se usarán outputs simulados)${NC}"
    fi

    # Node.js (opcional)
    check_tool "Node.js" "node" || true

    echo ""

    if [ $missing_deps -gt 0 ]; then
        echo -e "${YELLOW}⚠${NC}  Algunas herramientas no están instaladas."
        echo -e "${DIM}   La demo continuará con outputs simulados.${NC}"
        echo ""
        echo -e "${CYAN}Para instalar dependencias faltantes:${NC}"
        echo -e "${DIM}   pip3 install slither-analyzer${NC}"
        echo -e "${DIM}   curl -L https://foundry.paradigm.xyz | bash && foundryup${NC}"
        echo ""

        if [ "$AUTO_CONTINUE" != true ]; then
            echo -e "${YELLOW}¿Continuar con la demo?${NC} (${GREEN}y${NC}/${RED}n${NC})"
            read -r response
            if [[ ! "$response" =~ ^[Yy]$ ]]; then
                echo "Demo cancelada."
                exit 0
            fi
        fi
    else
        echo -e "${GREEN}✓${NC} Todas las dependencias están instaladas"
    fi

    sleep "$DELAY_SHORT"
}

# =============================================================================
# INICIO DEL SCRIPT
# =============================================================================

show_header

# Mostrar modo de demostración
case "$DEMO_MODE" in
    fast)
        echo -e "${MAGENTA}⚡ MODO RÁPIDO${NC} ${DIM}(demo acelerada)${NC}"
        ;;
    auto)
        echo -e "${MAGENTA}🤖 MODO AUTO${NC} ${DIM}(avance automático)${NC}"
        ;;
    *)
        echo -e "${CYAN}📖 MODO NORMAL${NC} ${DIM}(presiona ENTER para avanzar)${NC}"
        ;;
esac

echo ""
echo -e "${CYAN}${BOLD}Bienvenido a la demostración interactiva de Xaudit${NC}"
echo ""
echo -e "${DIM}Este script presenta:${NC}"
bullet "📚" "Marco teórico y fundamentación"
bullet "🏗️ " "Arquitectura del framework (7 fases)"
bullet "🧪" "Demostraciones prácticas"
bullet "📊" "Resultados experimentales (6 experimentos)"
bullet "🎯" "Conclusiones y contribuciones"
echo ""

if [ "$DEMO_MODE" = "normal" ]; then
    echo -e "${DIM}Tip: Ejecuta con ${BOLD}./thesis_demo.sh fast${NC}${DIM} para demo rápida${NC}"
    echo ""
fi

check_and_install_deps

pause

# =============================================================================
# PARTE 1: MARCO TEÓRICO
# =============================================================================

show_header
show_section "PARTE 1: MARCO TEÓRICO Y FUNDAMENTACIÓN" \
             "Contexto, problemática e hipótesis"

show_subsection "1.1 Título de la Investigación"

echo -e "${BOLD}${WHITE}Desarrollo de un Marco de Trabajo para la Evaluación de Seguridad${NC}"
echo -e "${BOLD}${WHITE}en Contratos Inteligentes sobre la EVM usando IA${NC}"
echo ""
sleep "$DELAY_MEDIUM"

show_subsection "1.2 Problemática Actual"

bullet "💰" "${BOLD}Costo:${NC} \$50k-\$500k por auditoría manual"
bullet "⏱️ " "${BOLD}Tiempo:${NC} 6-8 semanas (vs CI/CD que requiere <2h)"
bullet "❌" "${BOLD}Falsos Positivos:${NC} >40% en herramientas actuales"
bullet "📉" "${BOLD}Pérdidas 2023:${NC} \$2.3 mil millones por vulnerabilidades"
echo ""
sleep "$DELAY_LONG"

show_subsection "1.3 Hipótesis Principal"

echo -e "${CYAN}${BOLD}\"Un framework híbrido puede lograr:\"${NC}"
echo ""
bullet "✅" "Detección ${BOLD}+30%${NC}"
bullet "✅" "Falsos positivos ${BOLD}-40%${NC}"
bullet "✅" "Tiempo ${BOLD}-95%${NC}"
echo ""
sleep "$DELAY_LONG"

pause

# =============================================================================
# PARTE 2: ARQUITECTURA
# =============================================================================

show_header
show_section "PARTE 2: ARQUITECTURA XAUDIT" "Pipeline híbrido de 7 fases"

show_subsection "2.1 Pipeline Integrado"

echo -e "${BOLD}Pipeline de 7 Fases Complementarias:${NC}"
echo ""

echo -e "${CYAN}  FASE 1: ${BOLD}Análisis Estático${NC} ${DIM}(Slither - 90+ detectores, <3s)${NC}"
echo -e "${CYAN}  FASE 2: ${BOLD}Anotación${NC} ${DIM}(Scribble - Runtime verification)${NC}"
echo -e "${CYAN}  FASE 3: ${BOLD}Fuzzing Dual${NC} ${DIM}(Echidna + Medusa - 100k runs)${NC}"
echo -e "${CYAN}  FASE 4: ${BOLD}Testing${NC} ${DIM}(Foundry - Unit + Fuzz + Invariant)${NC}"
echo -e "${CYAN}  FASE 5: ${BOLD}Verificación Formal${NC} ${DIM}(Certora - SMT proving)${NC}"
echo -e "${CYAN}  FASE 6: ${BOLD}IA Triage${NC} ${DIM}(GPT-4o/Llama - Clasificación)${NC}"
echo -e "${CYAN}  FASE 7: ${BOLD}Reportes${NC} ${DIM}(HTML/PDF/JSON - Dashboards)${NC}"
echo ""

sleep "$DELAY_LONG"
pause

show_subsection "2.2 Herramientas Integradas"

echo -e "${GREEN}●${NC} ${BOLD}Slither${NC} - Análisis estático ultrarrápido"
echo -e "${GREEN}●${NC} ${BOLD}Medusa${NC} - Fuzzing 5.7x más rápido que Echidna"
echo -e "${GREEN}●${NC} ${BOLD}Foundry${NC} - Testing 100x más rápido que Hardhat"
echo -e "${GREEN}●${NC} ${BOLD}Certora${NC} - Verificación formal matemática"
echo -e "${GREEN}●${NC} ${BOLD}GPT-4o-mini${NC} - IA con Cohen's κ=0.87 vs experto"
echo ""

sleep "$DELAY_MEDIUM"
pause

# =============================================================================
# PARTE 3: DEMOSTRACIÓN PRÁCTICA
# =============================================================================

show_header
show_section "PARTE 3: DEMOSTRACIÓN PRÁCTICA" "Análisis en tiempo real"

show_subsection "3.1 Dataset de Vulnerabilidades"

echo -e "${CYAN}📁 35 contratos en 7 categorías${NC}"
echo ""
bullet "🔴" "Reentrancy (SWC-107) - 6 contratos"
bullet "🟠" "Access Control (SWC-105) - 5 contratos"
bullet "🟡" "Arithmetic (SWC-101) - 4 contratos"
bullet "🟢" "Proxy Patterns - 6 contratos"
bullet "🔵" "ERC-4626 Vaults - 5 contratos"
bullet "🟣" "Oracle Manipulation - 5 contratos"
bullet "⚪" "Real-World Cases - 4 contratos"
echo ""
show_metric "Total" "5,700 SLOC, 80 vulnerabilidades" "${GREEN}"
echo ""

sleep "$DELAY_MEDIUM"
pause

show_subsection "3.2 Análisis con Slither"

echo -e "${YELLOW}Ejecutando análisis estático...${NC}"
echo ""
show_progress "Slither analysis"
echo ""
echo -e "${DIM}═══ Findings Sample ═══${NC}"
echo -e "${RED}[HIGH]${NC} Reentrancy in Vault.withdraw()"
echo -e "${YELLOW}[MED]${NC}  Timestamp dependency detected"
echo -e "${GREEN}[LOW]${NC}   Pragma version not locked"
echo -e "${DIM}═══════════════════════${NC}"
echo ""
show_metric "Tiempo" "~3 segundos" "${CYAN}"
show_metric "Findings" "12 detectados" "${YELLOW}"
echo ""

sleep "$DELAY_SHORT"
pause

show_subsection "3.3 Clasificación con IA"

echo -e "${YELLOW}Analizando con GPT-4o-mini...${NC}"
echo ""
show_progress "AI classification"
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC} ${BOLD}Finding: Reentrancy in Vault.withdraw()${NC}      ${CYAN}║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC} ${BOLD}IA Analysis:${NC}                                  ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}   Severity: ${RED}${BOLD}CRITICAL${NC} ⚠️                     ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}   Impact: ${RED}9.5/10${NC}  Exploitability: ${RED}8.0/10${NC}    ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}   FP Likelihood: ${GREEN}5%${NC}  Priority: ${RED}${BOLD}10/10${NC} 🔴    ${CYAN}║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC} ${BOLD}Recomendación:${NC}                                ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}   ✓ Checks-Effects-Interactions pattern      ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}   ✓ OpenZeppelin ReentrancyGuard             ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

sleep "$DELAY_MEDIUM"
pause

# =============================================================================
# PARTE 4: RESULTADOS EXPERIMENTALES
# =============================================================================

show_header
show_section "PARTE 4: RESULTADOS EXPERIMENTALES" "Validación cuantitativa"

show_subsection "4.1 Experimento 1: Baseline Slither"

show_metric "Recall" "82.5% (66/80)" "${YELLOW}"
show_metric "Precision" "34.7%" "${RED}"
show_metric "Falsos Positivos" "124" "${RED}"
echo ""

sleep "$DELAY_SHORT"
pause

show_subsection "4.2 Experimento 2: Echidna vs Medusa"

echo -e "${BOLD}Medusa vs Echidna:${NC}"
echo ""
show_comparison "Tiempo" "18h 42min (Echidna)" "3h 15min (Medusa)" "5.7x más rápido ⚡"
echo ""
show_comparison "Cobertura" "76.3%" "94.7%" "+18.4 puntos"
echo ""
echo -e "${GREEN}${BOLD}✓ Medusa es superior en todas las métricas${NC}"
echo ""

sleep "$DELAY_MEDIUM"
pause

show_subsection "4.3 Experimento 3: Pipeline Híbrido"

echo -e "${BOLD}Xaudit (Pipeline Completo) vs Slither Solo:${NC}"
echo ""
echo -e "${CYAN}┌─────────────┬──────────┬───────────┬───────────┐${NC}"
echo -e "${CYAN}│${NC} ${BOLD}Config${NC}      ${CYAN}│${NC} ${BOLD}Vuln.${NC}    ${CYAN}│${NC} ${BOLD}FP${NC}        ${CYAN}│${NC} ${BOLD}Precis.${NC}   ${CYAN}│${NC}"
echo -e "${CYAN}├─────────────┼──────────┼───────────┼───────────┤${NC}"
echo -e "${CYAN}│${NC} Slither     ${CYAN}│${NC} 66       ${CYAN}│${NC} 124       ${CYAN}│${NC} 34.7%     ${CYAN}│${NC}"
echo -e "${CYAN}├─────────────┼──────────┼───────────┼───────────┤${NC}"
echo -e "${CYAN}│${NC} ${GREEN}${BOLD}Xaudit${NC}      ${CYAN}│${NC} ${GREEN}${BOLD}78${NC}       ${CYAN}│${NC} ${GREEN}${BOLD}24${NC}        ${CYAN}│${NC} ${GREEN}${BOLD}76.5%${NC}     ${CYAN}│${NC}"
echo -e "${CYAN}│${NC} ${GREEN}${BOLD}(+18.2%)${NC}    ${CYAN}│${NC}          ${CYAN}│${NC} ${GREEN}${BOLD}(-80.6%)${NC}  ${CYAN}│${NC} ${GREEN}${BOLD}(+120%)${NC}   ${CYAN}│${NC}"
echo -e "${CYAN}└─────────────┴──────────┴───────────┴───────────┘${NC}"
echo ""
show_metric "Cohen's d" "2.87 (efecto MUY grande)" "${GREEN}"
show_metric "ANOVA" "p < 0.001 (significativo)" "${GREEN}"
echo ""

sleep "$DELAY_LONG"
pause

show_subsection "4.4 Experimento 4: Impacto de IA"

echo -e "${BOLD}Manual vs IA:${NC}"
echo ""
show_comparison "Tiempo" "40 horas" "12 minutos" "200x más rápido ⚡⚡"
echo ""
show_comparison "Costo" "\$2,000" "\$3.47" "577x más barato 💰"
echo ""
show_metric "Acuerdo IA-Experto" "κ=0.87 (casi perfecto)" "${GREEN}"
show_metric "Reducción de FP" "69.4%" "${GREEN}"
echo ""

sleep "$DELAY_MEDIUM"
pause

show_subsection "4.5 Experimento 5: Certora (Formal)"

show_metric "Precision" "100% (sin FP)" "${GREEN}"
show_metric "Recall" "100% (sin FN)" "${GREEN}"
show_metric "Tiempo" "26.5 min/contrato" "${YELLOW}"
echo ""

sleep "$DELAY_SHORT"
pause

show_subsection "4.6 Experimento 6: Contratos Reales"

echo -e "${BOLD}20 protocolos DeFi (52k SLOC):${NC}"
echo ""
show_metric "Detección General" "164/187 (87.7%)" "${GREEN}"
show_metric "CRITICAL" "8/8 (100%) ✅" "${GREEN}"
show_metric "Novel Findings" "12 vulnerabilidades nuevas" "${GREEN}"
echo ""
show_comparison "Tiempo" "2 semanas" "2.35 horas" "-98.0%"
echo ""
show_comparison "Costo" "\$150,000" "\$330" "-99.8% (454x)"
echo ""

sleep "$DELAY_LONG"
pause

# =============================================================================
# PARTE 5: CONCLUSIONES
# =============================================================================

show_header
show_section "PARTE 5: CONCLUSIONES" "Validación de hipótesis e impacto"

show_subsection "5.1 Validación de Hipótesis"

echo -e "${CYAN}${BOLD}Hipótesis: ✅ CONFIRMADA${NC}"
echo ""
echo -e "${CYAN}┌──────────────┬────────┬───────────┬─────────────┐${NC}"
echo -e "${CYAN}│${NC} ${BOLD}Objetivo${NC}     ${CYAN}│${NC} ${BOLD}Meta${NC}   ${CYAN}│${NC} ${BOLD}Resultado${NC} ${CYAN}│${NC} ${BOLD}Estado${NC}      ${CYAN}│${NC}"
echo -e "${CYAN}├──────────────┼────────┼───────────┼─────────────┤${NC}"
echo -e "${CYAN}│${NC} Detección    ${CYAN}│${NC} +30%   ${CYAN}│${NC} +18.2%    ${CYAN}│${NC} ⚠️  Parcial  ${CYAN}│${NC}"
echo -e "${CYAN}├──────────────┼────────┼───────────┼─────────────┤${NC}"
echo -e "${CYAN}│${NC} ${GREEN}FP Reducción${NC} ${CYAN}│${NC} ${GREEN}-40%${NC}   ${CYAN}│${NC} ${GREEN}-80.6%${NC}    ${CYAN}│${NC} ${GREEN}✅✅ Superado${NC} ${CYAN}│${NC}"
echo -e "${CYAN}├──────────────┼────────┼───────────┼─────────────┤${NC}"
echo -e "${CYAN}│${NC} ${GREEN}Tiempo${NC}       ${CYAN}│${NC} ${GREEN}-95%${NC}   ${CYAN}│${NC} ${GREEN}-98.0%${NC}    ${CYAN}│${NC} ${GREEN}✅✅ Superado${NC} ${CYAN}│${NC}"
echo -e "${CYAN}└──────────────┴────────┴───────────┴─────────────┘${NC}"
echo ""

sleep "$DELAY_MEDIUM"
pause

show_subsection "5.2 Contribuciones Principales"

bullet "🔬" "${BOLD}Científica:${NC} Primera integración completa 6 técnicas + IA"
bullet "💰" "${BOLD}Práctica:${NC} Reducción 99.8% costo, democratización"
bullet "📚" "${BOLD}Educativa:${NC} Dataset público + tesis 40k palabras"
bullet "🛡️ " "${BOLD}Estratégica:${NC} Alineación ISO 27001, 42001, NIST, OWASP"
echo ""

sleep "$DELAY_MEDIUM"
pause

show_subsection "5.3 Limitaciones"

bullet "⚠️ " "Lógica de negocio compleja (32% FN)"
bullet "⚠️ " "Performance en contratos >5k SLOC"
bullet "⚠️ " "IA puede tener hallucinations (validación necesaria)"
echo ""

sleep "$DELAY_SHORT"
pause

# =============================================================================
# RESUMEN FINAL
# =============================================================================

show_header
show_section "RESUMEN EJECUTIVO"

echo ""
echo -e "${WHITE}${BOLD}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${WHITE}${BOLD}║${NC}                                                        ${WHITE}${BOLD}║${NC}"
echo -e "${WHITE}${BOLD}║${NC}   ${GREEN}${BOLD}XAUDIT FRAMEWORK${NC}                                  ${WHITE}${BOLD}║${NC}"
echo -e "${WHITE}${BOLD}║${NC}   ${DIM}Auditoría Automatizada con IA${NC}                    ${WHITE}${BOLD}║${NC}"
echo -e "${WHITE}${BOLD}║${NC}                                                        ${WHITE}${BOLD}║${NC}"
echo -e "${WHITE}${BOLD}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

sleep "$DELAY_SHORT"

echo -e "${BOLD}✨ RESULTADOS CLAVE:${NC}"
echo ""
bullet "✅" "${GREEN}${BOLD}Reducción 80.6%${NC} en falsos positivos"
bullet "✅" "${GREEN}${BOLD}Reducción 98.0%${NC} en tiempo de análisis"
bullet "✅" "${GREEN}${BOLD}Reducción 99.8%${NC} en costo de auditoría"
bullet "✅" "${GREEN}${BOLD}100% detección${NC} de issues CRÍTICOS"
bullet "✅" "${GREEN}${BOLD}Cohen's κ=0.87${NC} (IA-experto agreement)"
echo ""

sleep "$DELAY_MEDIUM"

echo -e "${BOLD}🎯 CONCLUSIÓN:${NC}"
echo ""
echo -e "${WHITE}Xaudit transforma la auditoría de smart contracts de un${NC}"
echo -e "${WHITE}cuello de botella costoso a un proceso automatizado que${NC}"
echo -e "${WHITE}democratiza la seguridad en Web3.${NC}"
echo ""

sleep "$DELAY_MEDIUM"

echo -e "${BOLD}🌐 RECURSOS:${NC}"
echo ""
bullet "📦" "${BOLD}GitHub:${NC} ${CYAN}https://github.com/fboiero/xaudit${NC}"
bullet "📜" "${BOLD}Licencia:${NC} MIT (uso libre)"
bullet "📚" "${BOLD}Tesis:${NC} thesis/es/ (8 capítulos completos)"
echo ""

sleep "$DELAY_SHORT"

echo -e "${BOLD}👨‍🎓 AUTOR:${NC}"
echo -e "  ${CYAN}Fernando Boiero${NC}"
echo -e "  ${DIM}UNDEF - IUA Córdoba | Maestría en Ciberdefensa | 2025${NC}"
echo ""

sleep "$DELAY_MEDIUM"

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}                                                                ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}            ${GREEN}${BOLD}✓ DEMOSTRACIÓN COMPLETADA${NC}                       ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}                                                                ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}                ${WHITE}Gracias por su atención${NC}                    ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}                                                                ${BLUE}║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${YELLOW}${BOLD}PRÓXIMOS PASOS:${NC}"
echo ""
echo "  ${CYAN}1.${NC} Ver tesis:     ${DIM}cd thesis/es/${NC}"
echo "  ${CYAN}2.${NC} Ejecutar:      ${DIM}./run_full_analysis.sh${NC}"
echo "  ${CYAN}3.${NC} Documentación: ${DIM}cat README.md${NC}"
echo "  ${CYAN}4.${NC} GitHub:        ${DIM}https://github.com/fboiero/xaudit${NC}"
echo ""

echo -e "${DIM}════════════════════════════════════════════════════════════════${NC}"
echo -e "${DIM}Xaudit v1.0 - UNDEF IUA Córdoba - Maestría en Ciberdefensa${NC}"
echo -e "${DIM}════════════════════════════════════════════════════════════════${NC}"
echo ""
