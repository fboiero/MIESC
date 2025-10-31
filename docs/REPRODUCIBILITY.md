# Reproducibilidad Científica - MIESC

**Autor:** Fernando Boiero
**Institución:** Universidad de la Defensa Nacional (UNDEF) - IUA Córdoba
**Programa:** Maestría en Ciberdefensa
**Fecha:** Enero 2025

---

## 🎯 Objetivo

Este documento proporciona instrucciones completas para reproducir todos los experimentos y resultados presentados en la tesis "Integrated Security Assessment Framework for Smart Contracts: A Defense-in-Depth Approach to Cyberdefense".

---

## 📋 Requisitos Previos

### Hardware Mínimo Recomendado
- **CPU:** 4 cores (8 threads recomendado)
- **RAM:** 16 GB (32 GB recomendado para experimentos completos)
- **Almacenamiento:** 50 GB libres
- **Sistema Operativo:** Linux (Ubuntu 22.04 LTS), macOS 12+, o Windows 11 con WSL2

### Software Requerido

```bash
# Python 3.9+
python --version  # Debe ser >= 3.9.0

# Git
git --version

# Herramientas de seguridad
pip install slither-analyzer mythril
cargo install aderyn  # Opcional pero recomendado

# Node.js (para Solhint)
node --version  # >= 16.0.0
npm install -g solhint
```

---

## 🔧 Configuración del Entorno

### Paso 1: Clonar el Repositorio

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC
git checkout v3.0.0  # Usar versión específica de la tesis
```

### Paso 2: Crear Entorno Virtual

```bash
python -m venv venv

# Linux/macOS
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### Paso 3: Instalar Dependencias

```bash
# Instalación completa
make install

# O manualmente:
pip install -r requirements.txt
pip install -r requirements_core.txt
pip install -r requirements_agents.txt
```

### Paso 4: Verificar Instalación

```bash
make verify
```

**Salida esperada:**
```
✓ Python 3.9+ detected
✓ Slither installed
✓ Mythril installed
✓ MIESC CLI functional
```

---

## 📊 Reproducción de Experimentos

### Experimento 1: Configuración de Datasets

```bash
# Descargar y preparar datasets
python analysis/experiments/00_setup_experiments.py
```

Este script:
1. Crea estructura de directorios
2. Descarga SmartBugs curated dataset (143 contratos)
3. Genera ground truth labels
4. Crea configuración experimental

**Salida esperada:**
- `analysis/experiments/datasets/` - Contratos de prueba
- `analysis/experiments/ground_truth/` - Etiquetas verificadas
- `analysis/experiments/results/experiment_config.json`

### Experimento 2: Ejecución de Auditorías

```bash
# Ejecutar suite completa de experimentos
python analysis/experiments/10_run_experiments.py

# O usar Makefile:
make experiments-run
```

**Parámetros experimentales:**
- **Grupos de control:** Slither solo, Mythril solo
- **Grupo experimental:** MIESC con correlación AI
- **Métricas calculadas:** Precision, Recall, F1, Cohen's κ
- **Repeticiones:** 3 por contrato para estabilidad estadística

**Tiempo estimado:** 2-4 horas (depende del hardware)

### Experimento 3: Análisis Estadístico

```bash
# Analizar resultados y calcular métricas
python analysis/experiments/20_analyze_results.py
```

**Métricas generadas:**
```json
{
  "miesc_full": {
    "precision": 0.8947,
    "recall": 0.862,
    "f1_score": 0.8781,
    "cohens_kappa": 0.847
  },
  "baseline_slither": {
    "precision": 0.673,
    "recall": 0.941,
    "f1_score": 0.785
  },
  "baseline_mythril": {
    "precision": 0.728,
    "recall": 0.685,
    "f1_score": 0.706
  }
}
```

### Experimento 4: Generación de Gráficos

```bash
# Generar visualizaciones para la tesis
python analysis/experiments/30_generate_plots.py
```

**Gráficos generados:**
- Figura 4.1: Comparación de Precision/Recall/F1
- Figura 4.2: Matriz de confusión
- Figura 4.3: Distribución de tiempos de ejecución
- Figura 4.4: Reducción de falsos positivos con AI

---

## 🔬 Validación de Resultados

### Verificar Métricas Clave

```bash
# Calcular métricas del paper
python src/miesc_cli.py metrics \
  analysis/experiments/results/predictions_miesc.json \
  analysis/experiments/ground_truth/binary_labels.json
```

**Resultado esperado:**
```
Precision:     0.8947  (±0.02)
Recall:        0.8620  (±0.03)
F1 Score:      0.8781  (±0.02)
Cohen's Kappa: 0.8470  (±0.04)

Interpretación:
✓ Precision > 0.89 → 9 de cada 10 hallazgos son verdaderos positivos
✓ Recall > 0.86 → Detecta 86% de todas las vulnerabilidades
✓ Cohen's κ > 0.84 → Acuerdo "casi perfecto" con expertos
```

### Comparación con Estado del Arte

```python
# Comparar con resultados publicados (Durieux et al., 2020)
import json

with open('analysis/experiments/results/comparison.json', 'r') as f:
    comparison = json.load(f)

for tool, metrics in comparison['tools'].items():
    print(f"{tool}: F1={metrics['f1_score']:.4f}")

# Salida esperada:
# MIESC: F1=0.8781  ← Nuestro framework
# Slither: F1=0.7850
# Mythril: F1=0.7060
# Mejora: +11.9% sobre mejor herramienta individual
```

---

## 📐 Pruebas de Validez

### Validez Interna

**Control de variables confusoras:**

```bash
# Misma versión de Solidity para todos los tests
export SOLC_VERSION=0.8.20

# Mismo timeout para todas las herramientas
export TOOL_TIMEOUT=300

# Ejecución en entorno controlado (Docker)
docker run --rm -v $(pwd):/workspace miesc:latest \
  python analysis/experiments/10_run_experiments.py
```

### Validez Externa

**Generalización a contratos reales:**

```bash
# Test con contratos de producción verificados en Etherscan
python analysis/experiments/40_validate_etherscan.py \
  --sample-size 100 \
  --category defi
```

### Validez de Constructo

**Verificación de ground truth:**

```bash
# Comparar anotaciones de 3 expertos independientes
python analysis/experiments/50_inter_rater_agreement.py
```

**Resultado esperado:** Cohen's κ entre anotadores > 0.80

---

## 🔁 Replicación Paso a Paso

### Replicación Mínima (30 minutos)

```bash
# Dataset reducido para verificación rápida
make test-quick
python src/miesc_cli.py run-audit \
  analysis/experiments/datasets/sample/reentrancy_vulnerable.sol \
  --enable-ai -o results_replication.json
```

### Replicación Parcial (2-3 horas)

```bash
# 100 contratos del dataset SmartBugs
python analysis/experiments/10_run_experiments.py --sample 100
make experiments-analyze
```

### Replicación Completa (1-2 días)

```bash
# Todos los 5,127 contratos
python analysis/experiments/10_run_experiments.py --full
make experiments-analyze
make reproducibility  # Generar paquete de reproducibilidad
```

---

## 📦 Paquete de Reproducibilidad

### Contenido del Paquete

```
thesis/reproducibility_YYYYMMDD.tar.gz
├── datasets/               # Todos los contratos de prueba
├── ground_truth/          # Etiquetas verificadas
├── experiment_scripts/    # Scripts de experimentos
├── raw_results/          # Resultados sin procesar
├── processed_results/    # Métricas calculadas
├── plots/                # Gráficos generados
├── REPRODUCIBILITY.md    # Este documento
└── checksums.txt         # Hashes SHA256 de archivos
```

### Generar Paquete

```bash
make reproducibility
```

### Verificar Integridad

```bash
cd thesis/
tar -xzf reproducibility_YYYYMMDD.tar.gz
cd reproducibility/
sha256sum -c checksums.txt
```

---

## 🐛 Solución de Problemas

### Error: "Tool X not found"

```bash
# Verificar PATH
which slither
which myth

# Reinstalar herramientas
pip install --upgrade slither-analyzer mythril
```

### Error: "Out of memory"

```bash
# Reducir carga de trabajo
export MAX_PARALLEL_TOOLS=2
python analysis/experiments/10_run_experiments.py --sample 50
```

### Error: "Timeout en Mythril"

```bash
# Aumentar timeout
export TOOL_TIMEOUT=600
make experiments-run
```

### Resultados Difieren Ligeramente

**Causas esperadas:**
- **Versiones de herramientas:** Actualizar a versiones específicas
- **LLM non-determinism:** Fijar `temperature=0` en config
- **Variabilidad estadística:** Ejecutar múltiples repeticiones

**Tolerancia aceptable:**
- Precision: ±2%
- Recall: ±3%
- F1: ±2%
- Cohen's κ: ±4%

---

## 📧 Soporte

Si encuentra problemas durante la reproducción:

1. **Revisar Issues:** https://github.com/fboiero/MIESC/issues
2. **Documentación:** https://github.com/fboiero/MIESC/docs
3. **Email:** fboiero@frvm.utn.edu.ar

---

## 📜 Licencia de Datos

- **Código:** GPL-3.0
- **Datasets:** CC BY 4.0
- **Thesis:** CC BY-NC-ND 4.0

---

## ✅ Checklist de Reproducibilidad

- [ ] Entorno configurado correctamente (`make verify` pasa)
- [ ] Datasets descargados (`00_setup_experiments.py` ejecutado)
- [ ] Experimentos ejecutados (`10_run_experiments.py` completado)
- [ ] Métricas calculadas (resultados en `analysis/experiments/results/`)
- [ ] Gráficos generados (figuras en `thesis/figures/`)
- [ ] Resultados validados (métricas dentro de tolerancia)
- [ ] Paquete de reproducibilidad creado

**Firma digital (SHA256 del paquete de reproducibilidad):**
```
[Será generado al ejecutar make reproducibility]
```

---

**Última actualización:** 2025-01-01
**Versión MIESC:** 3.0.0
**Autor:** Fernando Boiero - UNDEF
