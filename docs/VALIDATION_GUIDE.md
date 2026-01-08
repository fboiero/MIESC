# MIESC - Guia de Validacion e Instalacion

**MIESC v4.2.3** - Multi-layer Intelligent Evaluation for Smart Contracts
**Autor:** Fernando Boiero (fboiero@frvm.utn.edu.ar)
**Institucion:** Maestria en Ciberdefensa, UNDEF-IUA Argentina
**Fecha de Validacion:** Enero 2026

---

## Tabla de Contenidos

1. [Requisitos Previos](#1-requisitos-previos)
2. [Clonacion del Repositorio](#2-clonacion-del-repositorio)
3. [Instalacion](#3-instalacion)
4. [Verificacion de la Instalacion](#4-verificacion-de-la-instalacion)
5. [Ejecucion de Analisis](#5-ejecucion-de-analisis)
6. [Contratos de Prueba](#6-contratos-de-prueba)
7. [Generacion de Reportes](#7-generacion-de-reportes)
8. [Resultados de Validacion](#8-resultados-de-validacion)
9. [Resolucion de Problemas](#9-resolucion-de-problemas)

---

## 1. Requisitos Previos

### 1.1 Sistema Operativo
- Linux (Ubuntu 20.04+, Debian 11+)
- macOS (12.0+)
- Windows con WSL2

### 1.2 Software Requerido

| Software | Version Minima | Comando de Verificacion |
|----------|---------------|------------------------|
| Python | 3.12+ | `python3 --version` |
| pip | 23.0+ | `pip --version` |
| Git | 2.30+ | `git --version` |
| Node.js | 18.0+ | `node --version` |
| npm | 9.0+ | `npm --version` |

### 1.3 Herramientas Opcionales (Recomendadas)

```bash
# Compilador Solidity
pip install solc-select
solc-select install 0.8.20
solc-select use 0.8.20

# Verificar instalacion
solc --version
```

---

## 2. Clonacion del Repositorio

### 2.1 Clonar via HTTPS

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC
```

### 2.2 Clonar via SSH (requiere configuracion de llaves SSH)

```bash
git clone git@github.com:fboiero/MIESC.git
cd MIESC
```

### 2.3 Verificar Clonacion Exitosa

```bash
# Verificar estructura del proyecto
ls -la

# Salida esperada:
# drwxr-xr-x  docs/
# drwxr-xr-x  miesc/
# drwxr-xr-x  src/
# drwxr-xr-x  tests/
# drwxr-xr-x  test_contracts/
# -rw-r--r--  pyproject.toml
# -rw-r--r--  README.md
# ...

# Verificar version del proyecto
cat pyproject.toml | grep version
# Salida: version = "4.2.3"
```

---

## 3. Instalacion

### 3.1 Crear Entorno Virtual (Recomendado)

```bash
# Crear entorno virtual
python3 -m venv venv

# Activar entorno virtual
# En Linux/macOS:
source venv/bin/activate

# En Windows:
# venv\Scripts\activate

# Verificar activacion (debe mostrar (venv) en el prompt)
which python
# Salida: /path/to/MIESC/venv/bin/python
```

### 3.2 Instalar MIESC

```bash
# Instalar en modo desarrollo con todas las dependencias
pip install -e ".[dev,symbolic,llm,metrics,cli]"

# Alternativa: Instalacion minima
pip install -e .
```

### 3.3 Instalar Herramientas de Analisis Estatico

```bash
# Slither (Analisis estatico principal)
pip install slither-analyzer

# Solhint (Linter de Solidity)
npm install -g solhint

# Aderyn (Analisis estatico en Rust) - Opcional
# Requiere Rust instalado
cargo install aderyn
```

### 3.4 Verificar Instalacion del CLI

```bash
# Verificar que el comando miesc esta disponible
miesc --version

# Salida esperada:
# MIESC v4.2.3 - Multi-layer Intelligent Evaluation for Smart Contracts
```

---

## 4. Verificacion de la Instalacion

### 4.1 Ejecutar Diagnostico del Sistema

```bash
miesc doctor
```

**Salida Esperada:**
```
MIESC System Diagnostics
========================

[OK] Python 3.12.x detected
[OK] MIESC v4.2.3 installed
[OK] Slither v0.10.x available
[OK] Solhint v5.x.x available
[WARN] Mythril not installed (optional)
[WARN] Echidna not installed (optional)

Tools Available: 4/32
Layers Active: 1, 5, 6, 7

System Status: OPERATIONAL
```

### 4.2 Verificar Herramientas Disponibles

```bash
miesc tools list
```

**Salida Esperada:**
```
Available Tools
===============

Layer 1 - Static Analysis:
  [OK] slither      - Smart contract static analyzer
  [OK] solhint      - Solidity linter
  [--] aderyn       - Rust-based static analyzer (not installed)
  [--] wake         - Static analyzer (not installed)

Layer 2 - Dynamic Testing:
  [--] echidna      - Property-based fuzzer (not installed)
  [--] medusa       - Parallel fuzzer (not installed)
  [--] foundry      - Development framework (not installed)

Layer 3 - Symbolic Execution:
  [--] mythril      - Security analyzer (not installed)
  [--] manticore    - Symbolic executor (not installed)

...

Total: X tools available out of 32
```

### 4.3 Verificar Importaciones de Python

```bash
python3 -c "from miesc.cli.main import app; print('CLI loaded successfully')"
python3 -c "from src.core.result_aggregator import ResultAggregator; print('Core modules loaded')"
python3 -c "from src.adapters import get_available_adapters; print(f'Adapters: {len(get_available_adapters())} available')"
```

---

## 5. Ejecucion de Analisis

### 5.1 Analisis Rapido (Quick Scan)

El analisis rapido utiliza las herramientas mas rapidas disponibles (~30 segundos).

```bash
# Analisis rapido de un contrato
miesc audit quick test_contracts/VulnerableBank.sol

# Con salida a archivo JSON
miesc audit quick test_contracts/VulnerableBank.sol -o results/quick_scan.json

# Con formato Markdown
miesc audit quick test_contracts/VulnerableBank.sol -o results/quick_scan.md -f markdown
```

### 5.2 Analisis Completo (Full Audit)

El analisis completo ejecuta todas las capas disponibles (~3-5 minutos).

```bash
# Analisis completo
miesc audit full test_contracts/VulnerableBank.sol -o results/full_audit.json

# Especificar capas
miesc audit full test_contracts/VulnerableBank.sol -l 1,2,3 -o results/layers_123.json
```

### 5.3 Analisis por Perfil

```bash
# Ver perfiles disponibles
miesc audit profile list

# Ejecutar perfil especifico
miesc audit profile security test_contracts/VulnerableBank.sol
miesc audit profile defi test_contracts/DeFiVault.sol
miesc audit profile token test_contracts/AccessControl.sol
```

### 5.4 Analisis de Herramienta Individual

```bash
# Solo Slither
miesc audit single slither test_contracts/VulnerableBank.sol

# Solo Solhint
miesc audit single solhint test_contracts/VulnerableBank.sol
```

### 5.5 Analisis en Lote (Batch)

```bash
# Analizar todos los contratos en un directorio
miesc audit batch test_contracts/ --profile quick -o results/batch_report.json

# Con procesamiento paralelo
miesc audit batch contracts/audit/ --profile balanced -j 4 -o results/audit_batch.json
```

---

## 6. Contratos de Prueba

### 6.1 Contratos Incluidos

El repositorio incluye contratos de prueba con vulnerabilidades conocidas:

| Contrato | Ubicacion | Vulnerabilidades |
|----------|-----------|------------------|
| VulnerableBank.sol | test_contracts/ | Reentrancy, Access Control |
| AccessControl.sol | test_contracts/ | Missing Access Control |
| EtherStore.sol | test_contracts/ | Reentrancy |
| DeFiVault.sol | test_contracts/ | Flash Loan, Price Oracle |
| UnsafeToken.sol | contracts/audit/ | Integer Overflow |
| FlashLoanVault.sol | contracts/audit/ | Flash Loan Attack |
| NFTMarketplace.sol | contracts/audit/ | Front-running |

### 6.2 Dataset SmartBugs Curated

Para evaluacion exhaustiva, el repositorio incluye el dataset SmartBugs:

```bash
# Ubicacion
ls benchmarks/datasets/smartbugs-curated/dataset/

# Categorias disponibles:
# - bad_randomness/ (8 contratos)
# - reentrancy/ (15 contratos)
# - unchecked_low_level_calls/ (20+ contratos)
```

### 6.3 Analizar Contratos de Prueba

```bash
# Crear directorio de resultados
mkdir -p results/validation

# Analizar cada contrato de prueba
for contract in test_contracts/*.sol; do
    name=$(basename "$contract" .sol)
    echo "Analizando: $name"
    miesc audit quick "$contract" -o "results/validation/${name}_report.json"
done
```

---

## 7. Generacion de Reportes

### 7.1 Formatos de Salida Disponibles

| Formato | Extension | Uso |
|---------|-----------|-----|
| JSON | .json | Procesamiento programatico |
| SARIF | .sarif.json | GitHub Code Scanning |
| Markdown | .md | Documentacion legible |
| HTML | .html | Visualizacion web |
| CSV | .csv | Hojas de calculo |

### 7.2 Generar Reportes en Multiples Formatos

```bash
# Ejecutar analisis
miesc audit full test_contracts/VulnerableBank.sol -o results/analysis.json

# Convertir a otros formatos
miesc export results/analysis.json -f markdown -o results/REPORT.md
miesc export results/analysis.json -f sarif -o results/report.sarif.json
miesc export results/analysis.json -f html -o results/report.html
miesc export results/analysis.json -f csv -o results/findings.csv
```

### 7.3 Estructura del Reporte JSON

```json
{
  "metadata": {
    "version": "4.2.3",
    "timestamp": "2026-01-08T12:00:00Z",
    "contract": "VulnerableBank.sol",
    "analysis_duration": "45.2s"
  },
  "summary": {
    "total_findings": 5,
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 1,
    "tools_executed": ["slither", "solhint"]
  },
  "findings": [
    {
      "id": "MIESC-001",
      "title": "Reentrancy vulnerability",
      "severity": "Critical",
      "tool": "slither",
      "location": {
        "file": "VulnerableBank.sol",
        "line": 42
      },
      "description": "...",
      "recommendation": "...",
      "references": ["SWC-107", "CWE-841"]
    }
  ]
}
```

### 7.4 Generar Reporte HTML Interactivo

```bash
# Usar el dashboard web
python -m src.utils.web_dashboard --results results/ --output dashboard/

# Abrir en navegador
open dashboard/index.html  # macOS
xdg-open dashboard/index.html  # Linux
```

---

## 8. Resultados de Validacion

### 8.1 Metricas de Rendimiento (Dataset SmartBugs)

| Metrica | Valor |
|---------|-------|
| Precision | 100% |
| Recall | 70% |
| F1-Score | 82.35% |
| Contratos Analizados | 50 |
| Vulnerabilidades Detectadas | 35/50 |
| Falsos Positivos | 0 |

### 8.2 Tiempos de Ejecucion

| Tipo de Analisis | Tiempo Promedio |
|------------------|-----------------|
| Quick Scan | ~30 segundos |
| Balanced Profile | ~2 minutos |
| Full Audit | ~5 minutos |
| Batch (10 contratos) | ~3 minutos |

### 8.3 Ejemplo de Validacion Completa

```bash
#!/bin/bash
# Script de validacion completa

echo "=== MIESC Validation Script ==="
echo "Fecha: $(date)"
echo ""

# 1. Verificar instalacion
echo "1. Verificando instalacion..."
miesc --version
miesc doctor

# 2. Crear directorio de resultados
mkdir -p validation_results

# 3. Analizar contratos de prueba
echo ""
echo "2. Analizando contratos de prueba..."

contracts=(
    "test_contracts/VulnerableBank.sol"
    "test_contracts/AccessControl.sol"
    "test_contracts/EtherStore.sol"
    "test_contracts/DeFiVault.sol"
)

for contract in "${contracts[@]}"; do
    name=$(basename "$contract" .sol)
    echo "  - Analizando: $name"
    miesc audit quick "$contract" -o "validation_results/${name}.json" 2>/dev/null
done

# 4. Generar reporte consolidado
echo ""
echo "3. Generando reportes..."
miesc audit batch test_contracts/ --profile quick -o validation_results/batch_report.json

# 5. Convertir a formatos legibles
miesc export validation_results/batch_report.json -f markdown -o validation_results/FINAL_REPORT.md

echo ""
echo "=== Validacion Completada ==="
echo "Resultados en: validation_results/"
ls -la validation_results/
```

---

## 9. Resolucion de Problemas

### 9.1 Error: "miesc: command not found"

```bash
# Verificar que el entorno virtual esta activado
source venv/bin/activate

# Reinstalar
pip install -e .

# Verificar PATH
echo $PATH | grep -o "[^:]*miesc[^:]*"
```

### 9.2 Error: "No module named 'miesc'"

```bash
# Verificar instalacion
pip show miesc

# Reinstalar en modo editable
pip install -e .
```

### 9.3 Error: "Slither not found"

```bash
# Instalar Slither
pip install slither-analyzer

# Verificar instalacion
slither --version

# Si usa un entorno virtual, asegurarse de instalarlo dentro
source venv/bin/activate
pip install slither-analyzer
```

### 9.4 Error: "solc not found"

```bash
# Instalar solc-select
pip install solc-select

# Instalar version de Solidity
solc-select install 0.8.20
solc-select use 0.8.20

# Verificar
solc --version
```

### 9.5 Warnings de Herramientas No Instaladas

Los warnings sobre herramientas no instaladas son normales. MIESC funciona con las herramientas disponibles:

```
[WARN] Mythril not installed - Layer 3 will be skipped
[WARN] Echidna not installed - Layer 2 will be skipped
```

Para instalar herramientas adicionales:

```bash
# Mythril (Analisis simbolico)
pip install mythril

# Echidna (Fuzzing) - Requiere binario
# Descargar de: https://github.com/crytic/echidna/releases

# Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

---

## Apendice A: Comandos de Referencia Rapida

```bash
# Instalacion
git clone https://github.com/fboiero/MIESC.git && cd MIESC
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev,cli]"

# Verificacion
miesc --version
miesc doctor
miesc tools list

# Analisis
miesc audit quick contract.sol
miesc audit full contract.sol -o report.json
miesc audit profile security contract.sol
miesc audit batch ./contracts/ --profile quick

# Reportes
miesc export report.json -f markdown -o REPORT.md
miesc export report.json -f html -o report.html

# Servidor
miesc server rest --port 5001
```

---

## Apendice B: Estructura de Directorios del Proyecto

```
MIESC/
├── miesc/                  # Paquete principal CLI
│   ├── cli/               # Comandos CLI
│   ├── api/               # REST API
│   └── core/              # Logica central
├── src/                   # Modulos fuente
│   ├── adapters/          # Adaptadores de herramientas (32)
│   ├── core/              # Infraestructura core
│   ├── ml/                # Machine Learning
│   ├── security/          # Modulos de seguridad
│   └── utils/             # Utilidades
├── tests/                 # Tests unitarios
├── test_contracts/        # Contratos de prueba
├── contracts/audit/       # Contratos de auditoria
├── benchmarks/            # Datasets de evaluacion
├── docs/                  # Documentacion
├── examples/              # Scripts de ejemplo
└── results/               # Resultados (generado)
```

---

**Documento generado automaticamente por MIESC v4.2.3**
**Ultima actualizacion:** Enero 2026
