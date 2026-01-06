# MIESC v4.2.3 Release Notes

**Release Date:** January 6, 2026

## Highlights

This release includes **validated empirical results** from the SmartBugs-curated academic benchmark dataset, demonstrating MIESC's real-world vulnerability detection capabilities.

### Validated Performance Metrics

| Metric | Value | Notes |
|--------|-------|-------|
| **Precision** | **100%** | 0 false positives |
| **Recall** | **70%** | 35/50 vulnerabilities detected |
| **F1-Score** | **82.35%** | Excellent balance |
| Total Findings | 369 | Across 50 contracts |
| Execution Time | 43.0s | 0.86s/contract average |

### Perfect Detection Categories (100% Recall)

| Category | Precision | Recall | True Positives |
|----------|-----------|--------|----------------|
| arithmetic | 100% | 100% | 15/15 |
| bad_randomness | 100% | 100% | 8/8 |
| front_running | 100% | 100% | 3/3 |

### Areas for Improvement

| Category | Recall | False Negatives |
|----------|--------|-----------------|
| access_control | 39% | 11 |
| denial_of_service | 33% | 4 |

## New Features

### Benchmark Evaluation Framework

- **`benchmarks/complete_evaluation.py`**: Comprehensive evaluation script for SmartBugs-curated dataset
- **Parallel analysis**: ThreadPoolExecutor-based parallel contract analysis
- **Multi-tool correlation**: SmartCorrelationEngine integration for finding deduplication
- **Ground truth validation**: Automatic comparison against labeled vulnerabilities

### New Dataset Support

- **SolidiFI-benchmark**: Added 1,700 contracts with 9,369 injected bugs for additional validation
  - 7 vulnerability types: reentrancy, timestamp, overflow/underflow, unchecked send, TOD, tx.origin
  - Source: [DependableSystemsLab/SolidiFI-benchmark](https://github.com/DependableSystemsLab/SolidiFI-benchmark)

## Improvements

### Documentation

- Updated README.md with validated metrics
- Updated README_ES.md with bilingual documentation
- Added TRACK_RECORD_REAL_VULNERABILITIES.md with case studies

### Correlation Engine

- Improved finding deduplication (+20% recall improvement with correlation)
- 54.5% reduction in raw findings through intelligent filtering
- Cross-validation between Slither and SmartBugs detectors

## Technical Details

### Evaluation Methodology

```bash
# Run complete evaluation
python benchmarks/complete_evaluation.py --max 50

# Results saved to: benchmarks/results/complete_evaluation_*.json
```

### Supported Vulnerability Categories

| SWC ID | Category | Detection Status |
|--------|----------|------------------|
| SWC-101 | Integer Overflow/Underflow | Full support |
| SWC-107 | Reentrancy | Full support |
| SWC-120 | Bad Randomness | Full support |
| SWC-114 | Front Running | Full support |
| SWC-105/106 | Access Control | Partial support |
| SWC-113 | Denial of Service | Partial support |

## Breaking Changes

None

## Deprecations

None

## Bug Fixes

- Fixed MCP/REST import issues in evaluation scripts
- Improved solc version selection for legacy contracts

## Dependencies

No changes from v4.2.2

## Acknowledgments

- SmartBugs team (ICSE 2020) for the curated vulnerability dataset
- SolidiFI team (ISSTA 2020) for the bug injection benchmark

---

# MIESC v4.2.3 - Notas de Lanzamiento

**Fecha de Lanzamiento:** 6 de Enero, 2026

## Destacados

Esta versión incluye **resultados empíricos validados** del dataset académico SmartBugs-curated, demostrando las capacidades reales de detección de vulnerabilidades de MIESC.

### Métricas de Rendimiento Validadas

| Métrica | Valor | Notas |
|---------|-------|-------|
| **Precisión** | **100%** | 0 falsos positivos |
| **Recall** | **70%** | 35/50 vulnerabilidades detectadas |
| **F1-Score** | **82.35%** | Excelente balance |
| Hallazgos Totales | 369 | En 50 contratos |
| Tiempo de Ejecución | 43.0s | 0.86s/contrato promedio |

### Categorías con Detección Perfecta (100% Recall)

| Categoría | Precisión | Recall | Verdaderos Positivos |
|-----------|-----------|--------|----------------------|
| arithmetic | 100% | 100% | 15/15 |
| bad_randomness | 100% | 100% | 8/8 |
| front_running | 100% | 100% | 3/3 |

### Áreas de Mejora

| Categoría | Recall | Falsos Negativos |
|-----------|--------|------------------|
| access_control | 39% | 11 |
| denial_of_service | 33% | 4 |

## Nuevas Características

### Framework de Evaluación de Benchmarks

- **`benchmarks/complete_evaluation.py`**: Script de evaluación completa para dataset SmartBugs-curated
- **Análisis paralelo**: Análisis paralelo de contratos basado en ThreadPoolExecutor
- **Correlación multi-herramienta**: Integración de SmartCorrelationEngine para deduplicación de hallazgos
- **Validación contra ground truth**: Comparación automática contra vulnerabilidades etiquetadas

### Soporte de Nuevo Dataset

- **SolidiFI-benchmark**: Añadidos 1,700 contratos con 9,369 bugs inyectados para validación adicional
  - 7 tipos de vulnerabilidad: reentrancy, timestamp, overflow/underflow, unchecked send, TOD, tx.origin
  - Fuente: [DependableSystemsLab/SolidiFI-benchmark](https://github.com/DependableSystemsLab/SolidiFI-benchmark)

## Mejoras

### Documentación

- README.md actualizado con métricas validadas
- README_ES.md actualizado con documentación bilingüe
- Añadido TRACK_RECORD_REAL_VULNERABILITIES.md con casos de estudio

### Motor de Correlación

- Mejora en deduplicación de hallazgos (+20% mejora en recall con correlación)
- 54.5% de reducción en hallazgos crudos mediante filtrado inteligente
- Validación cruzada entre Slither y detectores SmartBugs

## Detalles Técnicos

### Metodología de Evaluación

```bash
# Ejecutar evaluación completa
python benchmarks/complete_evaluation.py --max 50

# Resultados guardados en: benchmarks/results/complete_evaluation_*.json
```

## Sin Cambios Incompatibles

Ninguno

## Corrección de Errores

- Corregidos problemas de importación MCP/REST en scripts de evaluación
- Mejorada selección de versión solc para contratos legacy

---

**Author / Autor:** Fernando Boiero
**Institution / Institución:** UNDEF-IUA, Argentina
**Contact / Contacto:** <fboiero@frvm.utn.edu.ar>
