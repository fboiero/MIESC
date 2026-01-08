#!/bin/bash
# ============================================================================
# MIESC Installation Validation Script
# ============================================================================
# Este script valida la instalacion completa de MIESC y genera un reporte
# de validacion con los resultados del analisis de contratos de prueba.
#
# Uso: ./scripts/validate_installation.sh
# ============================================================================

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Directorio base
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_DIR/validation_results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Contadores
TESTS_PASSED=0
TESTS_FAILED=0
WARNINGS=0

# Funciones de utilidad
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
    ((TESTS_PASSED++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARNINGS++))
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    ((TESTS_FAILED++))
}

log_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

# ============================================================================
# FASE 1: Verificacion del Entorno
# ============================================================================

log_header "FASE 1: Verificacion del Entorno"

# Verificar Python
log_info "Verificando Python..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
    log_success "Python $PYTHON_VERSION encontrado"
else
    log_error "Python 3 no encontrado"
    exit 1
fi

# Verificar pip
log_info "Verificando pip..."
if command -v pip &> /dev/null; then
    PIP_VERSION=$(pip --version 2>&1 | cut -d' ' -f2)
    log_success "pip $PIP_VERSION encontrado"
else
    log_error "pip no encontrado"
fi

# Verificar Git
log_info "Verificando Git..."
if command -v git &> /dev/null; then
    GIT_VERSION=$(git --version 2>&1 | cut -d' ' -f3)
    log_success "Git $GIT_VERSION encontrado"
else
    log_warning "Git no encontrado (opcional para uso)"
fi

# Verificar Node.js (opcional)
log_info "Verificando Node.js..."
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version 2>&1)
    log_success "Node.js $NODE_VERSION encontrado"
else
    log_warning "Node.js no encontrado (necesario para solhint)"
fi

# ============================================================================
# FASE 2: Verificacion de MIESC
# ============================================================================

log_header "FASE 2: Verificacion de MIESC"

# Verificar comando miesc
log_info "Verificando comando miesc..."
if command -v miesc &> /dev/null; then
    MIESC_VERSION=$(miesc --version 2>&1 | head -1)
    log_success "MIESC instalado: $MIESC_VERSION"
else
    log_error "Comando miesc no encontrado. Ejecutar: pip install -e ."
    exit 1
fi

# Verificar importaciones de Python
log_info "Verificando modulos de Python..."
if python3 -c "from miesc.cli.main import app" 2>/dev/null; then
    log_success "Modulo CLI cargado correctamente"
else
    log_error "Error al cargar modulo CLI"
fi

if python3 -c "from src.core.result_aggregator import ResultAggregator" 2>/dev/null; then
    log_success "Modulos core cargados correctamente"
else
    log_error "Error al cargar modulos core"
fi

# ============================================================================
# FASE 3: Verificacion de Herramientas
# ============================================================================

log_header "FASE 3: Verificacion de Herramientas de Analisis"

# Slither
log_info "Verificando Slither..."
if command -v slither &> /dev/null; then
    SLITHER_VERSION=$(slither --version 2>&1 | head -1)
    log_success "Slither instalado: $SLITHER_VERSION"
else
    log_warning "Slither no instalado (pip install slither-analyzer)"
fi

# Solhint
log_info "Verificando Solhint..."
if command -v solhint &> /dev/null; then
    SOLHINT_VERSION=$(solhint --version 2>&1 | head -1)
    log_success "Solhint instalado: $SOLHINT_VERSION"
else
    log_warning "Solhint no instalado (npm install -g solhint)"
fi

# Mythril (opcional)
log_info "Verificando Mythril..."
if command -v myth &> /dev/null; then
    log_success "Mythril instalado"
else
    log_warning "Mythril no instalado (opcional)"
fi

# solc
log_info "Verificando compilador Solidity..."
if command -v solc &> /dev/null; then
    SOLC_VERSION=$(solc --version 2>&1 | grep -o "Version: [0-9.]*" | cut -d' ' -f2)
    log_success "solc instalado: $SOLC_VERSION"
else
    log_warning "solc no instalado (pip install solc-select)"
fi

# ============================================================================
# FASE 4: Analisis de Contratos de Prueba
# ============================================================================

log_header "FASE 4: Analisis de Contratos de Prueba"

# Crear directorio de resultados
mkdir -p "$RESULTS_DIR"
log_info "Directorio de resultados: $RESULTS_DIR"

# Lista de contratos a analizar
CONTRACTS=(
    "test_contracts/VulnerableBank.sol"
    "test_contracts/AccessControl.sol"
    "test_contracts/EtherStore.sol"
    "test_contracts/DeFiVault.sol"
)

cd "$PROJECT_DIR"

for contract in "${CONTRACTS[@]}"; do
    if [ -f "$contract" ]; then
        name=$(basename "$contract" .sol)
        log_info "Analizando: $name..."

        output_file="$RESULTS_DIR/${name}_${TIMESTAMP}.json"

        if miesc audit quick "$contract" -o "$output_file" 2>/dev/null; then
            if [ -f "$output_file" ]; then
                findings=$(python3 -c "import json; d=json.load(open('$output_file')); print(d.get('summary',{}).get('total_findings', 'N/A'))" 2>/dev/null || echo "N/A")
                log_success "$name analizado - Hallazgos: $findings"
            else
                log_warning "$name - Archivo de salida no generado"
            fi
        else
            log_warning "$name - Analisis completado con warnings"
        fi
    else
        log_warning "Contrato no encontrado: $contract"
    fi
done

# ============================================================================
# FASE 5: Generar Reporte Consolidado
# ============================================================================

log_header "FASE 5: Generacion de Reporte Consolidado"

# Generar reporte batch si hay contratos
if [ -d "test_contracts" ] && [ "$(ls -A test_contracts/*.sol 2>/dev/null)" ]; then
    log_info "Generando reporte batch..."

    BATCH_REPORT="$RESULTS_DIR/batch_report_${TIMESTAMP}.json"

    if miesc audit batch test_contracts/ --profile quick -o "$BATCH_REPORT" 2>/dev/null; then
        log_success "Reporte batch generado: $BATCH_REPORT"

        # Convertir a Markdown
        MARKDOWN_REPORT="$RESULTS_DIR/VALIDATION_REPORT_${TIMESTAMP}.md"
        if miesc export "$BATCH_REPORT" -f markdown -o "$MARKDOWN_REPORT" 2>/dev/null; then
            log_success "Reporte Markdown generado: $MARKDOWN_REPORT"
        else
            log_warning "No se pudo generar reporte Markdown"
        fi
    else
        log_warning "No se pudo generar reporte batch"
    fi
fi

# ============================================================================
# FASE 6: Resumen Final
# ============================================================================

log_header "RESUMEN DE VALIDACION"

echo ""
echo -e "Fecha de validacion: $(date)"
echo -e "Directorio del proyecto: $PROJECT_DIR"
echo -e "Resultados guardados en: $RESULTS_DIR"
echo ""
echo -e "${GREEN}Tests exitosos: $TESTS_PASSED${NC}"
echo -e "${YELLOW}Warnings: $WARNINGS${NC}"
echo -e "${RED}Tests fallidos: $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  VALIDACION COMPLETADA EXITOSAMENTE${NC}"
    echo -e "${GREEN}========================================${NC}"
    exit 0
else
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}  VALIDACION COMPLETADA CON ERRORES${NC}"
    echo -e "${RED}========================================${NC}"
    exit 1
fi
