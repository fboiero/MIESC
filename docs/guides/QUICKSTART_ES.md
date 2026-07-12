# MIESC - Guia de Inicio Rapido

Guia rapida para instalar y usar MIESC desde la linea de comandos.

## Requisitos

- Python 3.12+
- Git

## 1. Instalacion

```bash
# Desde PyPI (recomendado)
pip install miesc

# Con todas las funciones
pip install miesc[full]

# Desde codigo fuente (desarrollo)
git clone https://github.com/fboiero/MIESC.git
cd MIESC
pip install -e .              # Instalacion minima (solo CLI)
pip install -e .[cli]         # Con salida mejorada (Rich)
pip install -e .[full]        # Todas las funciones
```

## 2. Verificar Instalacion

```bash
# Verificar version
miesc --version

# Verificar herramientas disponibles (muestra 50 herramientas en 9 capas)
miesc doctor
```

## 3. Comandos de Auditoria

### Escaneo Rapido de Triaje (~30 segundos)

```bash
# Escaneo rapido de un contrato
miesc scan MiContrato.sol

# Escaneo con reporte JSON
miesc scan MiContrato.sol -o reporte.json

# Modo CI/CD (codigo de salida 1 si hay issues criticos/altos)
miesc scan MiContrato.sol --ci
```

### Auditoria Rapida (3 herramientas)

```bash
miesc audit quick MiContrato.sol
miesc audit quick MiContrato.sol -o reporte.json
```

### Auditoria Completa - 9 Capas, 50 Herramientas

```bash
# Auditoria de seguridad completa con las 9 capas de defensa
miesc audit full MiContrato.sol -o auditoria_completa.json

# Ejecutar solo capas especificas
miesc audit full MiContrato.sol --layers 1,2,3
```

### Auditoria Batch (Multiples Contratos)

```bash
# Auditar todos los contratos en una carpeta
miesc audit batch ./contracts/ -o reporte_batch.json

# Escaneo recursivo de subcarpetas
miesc audit batch ./contracts/ -r -o reporte.json

# Con workers en paralelo para mayor velocidad
miesc audit batch ./contracts/ -j 4 -o reporte.json
```

## 4. Las 9 Capas de Defensa

MIESC analiza contratos a traves de **9 capas de defensa especializadas**:

| Capa | Nombre | Herramientas | Descripcion |
|------|--------|--------------|-------------|
| 1 | Analisis Estatico | Slither, Aderyn, Solhint | Patrones de codigo, vulnerabilidades |
| 2 | Testing Dinamico | Echidna, Medusa, Foundry, DogeFuzz | Fuzzing, testing de propiedades |
| 3 | Ejecucion Simbolica | Mythril, Manticore, Halmos | Exploracion de caminos, SMT solving |
| 4 | Verificacion Formal | Certora, SMTChecker | Pruebas matematicas |
| 5 | Analisis con IA | SmartLLM, GPTScan, LLMSmartAudit, GPTLens | Deteccion potenciada por LLM |
| 6 | Deteccion ML | DA-GNN, SmartBugs-ML, SmartGuard, Peculiar | Clasificadores ML |
| 7 | Analisis Especializado | Threat Model, Gas Analyzer, MEV Detector, DeFi | Chequeos de dominio |
| 8 | Seguridad Cross-Chain y ZK | Cross-Chain, ZK Circuit, Bridge Monitor, Circom | Bridge/ZK (experimental) |
| 9 | Ensemble Avanzado de IA | LLMBugScanner, Audit Consensus, Exploit Synthesizer | Consenso multi-LLM |

### Ejecutar Capas Especificas

```bash
# Solo analisis estatico (Capa 1)
miesc audit full contrato.sol --layers 1

# Estatico + Simbolico (Capas 1 y 3)
miesc audit full contrato.sol --layers 1,3

# Todas las capas (por defecto)
miesc audit full contrato.sol --layers 1,2,3,4,5,6,7,8,9
```

## 5. Formatos de Salida

```bash
# JSON (por defecto)
miesc scan contrato.sol -o reporte.json

# SARIF (para integracion con GitHub/IDE)
miesc audit quick contrato.sol -f sarif -o reporte.sarif

# Markdown
miesc audit quick contrato.sol -f markdown -o reporte.md
```

## 6. Integracion CI/CD

```bash
# Salir con codigo 1 si hay issues de severidad critica o alta
miesc scan contrato.sol --ci

# Para auditorias batch
miesc audit batch ./contracts/ --fail-on critical,high
```

## 7. Ejemplo Completo

```bash
# 1. Navegar al proyecto
cd mi_proyecto

# 2. Escaneo rapido del contrato principal
miesc scan contracts/Token.sol

# 3. Auditoria completa con las 9 capas
miesc audit full contracts/Token.sol -o reporte_auditoria.json

# 4. Auditoria batch de todo el proyecto
miesc audit batch contracts/ -r -o auditoria_proyecto_completo.json
```

## 8. Opciones Utiles

```bash
# Ayuda general
miesc --help

# Ayuda especifica de comandos
miesc scan --help
miesc audit --help
miesc audit full --help
miesc audit batch --help

# Ejecutar como modulo de Python
python -m miesc scan MiContrato.sol
python -m miesc audit full MiContrato.sol
```

## 9. Solucion de Problemas

```bash
# Verificar herramientas instaladas y su estado
miesc doctor

# Ejecutar con salida de depuracion
MIESC_DEBUG=1 miesc scan contrato.sol

# Verificar version de Python (debe ser 3.12+)
python --version

# Listar todas las herramientas disponibles
miesc tools list
```

## Documentacion

- Documentacion completa: https://fboiero.github.io/MIESC
- GitHub: https://github.com/fboiero/MIESC
- Video demostrativo: https://youtu.be/pLa_McNBRRw
