# MIESC v4.7.0 - Plan de Mejoras de Precisión

## Objetivo Principal

**Aumentar la precisión de 26.7% a 60%+** manteniendo recall en 85%+

## Estado Actual (v4.6.0)

| Métrica | Actual | Objetivo v4.7.0 |
|---------|--------|-----------------|
| **Recall** | 85.7% | 85%+ (mantener) |
| **Precisión** | 26.7% | 60%+ |
| **F1 Score** | 40.7% | 70%+ |

## Análisis del Problema

### Fuente de Falsos Positivos

1. **Patrones regex sin contexto semántico** - Detectan sintaxis, no vulnerabilidades reales
2. **Falta de validación con herramientas externas** - SlitherValidator creado pero no ejecuta Slither real
3. **Sin ejecución simbólica** - No se verifica si los paths son alcanzables
4. **Sin análisis de invariantes** - No se detectan controles implícitos

---

## Fase 1: Integración Real de Slither

### 1.1 Ejecutar Slither Real

**Archivo:** `src/ml/slither_validator.py` (ya existe infraestructura)

**Cambios:**
- Verificar instalación de Slither
- Ejecutar Slither en contratos del benchmark
- Cruzar resultados con detecciones de patrones

```python
# Ya implementado, necesita:
# 1. Asegurar que Slither esté instalado
# 2. Probar en contratos SolidiFI
# 3. Ajustar umbrales de confianza basados en resultados
```

**Impacto esperado:** +15-20% precisión

### 1.2 Filtrado por Confianza Cruzada

**Regla:** Hallazgos confirmados por Slither → confianza +25%
**Regla:** Hallazgos no confirmados por Slither → confianza -20%

---

## Fase 2: Integración de Mythril

### 2.1 Adapter de Mythril

**Nuevo archivo:** `src/adapters/mythril_adapter.py`

```python
class MythrilAdapter:
    """Ejecuta análisis simbólico con Mythril."""

    def analyze(self, contract_path: str) -> List[Finding]:
        """Ejecuta Mythril y retorna hallazgos."""
        pass

    def verify_path_reachability(self, finding: Finding) -> bool:
        """Verifica si un path de vulnerabilidad es alcanzable."""
        pass
```

**Beneficio:** Confirma si vulnerabilidades son explotables

**Impacto esperado:** +10-15% precisión

### 2.2 Cross-Validation Mythril + Slither

Hallazgos confirmados por ambas herramientas → confianza 95%+

---

## Fase 3: ML para Reducción de FP

### 3.1 Clasificador de Falsos Positivos

**Nuevo archivo:** `src/ml/fp_classifier.py`

```python
class FPClassifier:
    """Clasificador ML para filtrar falsos positivos."""

    def __init__(self):
        self.model = None  # XGBoost o RandomForest

    def extract_features(self, finding: Finding, source: str) -> np.array:
        """Extrae features del hallazgo y contexto."""
        features = [
            finding.confidence,
            len(finding.affected_lines),
            self._count_modifiers(source),
            self._has_reentrancy_guard(source),
            self._solidity_version(source),
            # ... más features
        ]
        return np.array(features)

    def predict_fp_probability(self, finding: Finding, source: str) -> float:
        """Predice probabilidad de ser falso positivo."""
        features = self.extract_features(finding, source)
        return self.model.predict_proba(features)[0][1]
```

**Dataset de entrenamiento:**
- SolidiFI ground truth (etiquetados)
- SmartBugs dataset
- Resultados de auditorías reales

**Impacto esperado:** +10-15% precisión

---

## Fase 4: Verificación Formal Ligera

### 4.1 Integración Echidna (Fuzzing)

**Nuevo archivo:** `src/adapters/echidna_adapter.py`

```python
class EchidnaAdapter:
    """Ejecuta fuzzing con Echidna para validar vulnerabilidades."""

    def generate_test(self, finding: Finding) -> str:
        """Genera test de fuzzing para una vulnerabilidad."""
        pass

    def run_fuzz(self, contract: str, test: str, timeout: int = 60) -> bool:
        """Ejecuta Echidna y retorna si encontró violación."""
        pass
```

**Beneficio:** Confirma vulnerabilidades con tests concretos

### 4.2 Invariantes Básicos

Detectar y verificar invariantes comunes:
- `balance >= 0`
- `totalSupply == sum(balances)`
- `owner != address(0)`

---

## Orden de Implementación

### Sprint 1: Quick Wins
1. [x] Probar SlitherValidator con benchmark real (Slither no instalado - infraestructura lista)
2. [x] Ajustar umbrales de confianza
3. [x] Filtrar por confianza mínima 0.5

**Meta:** Precisión 35%+

### Sprint 2: Mythril
1. [x] Crear MythrilAdapter (existente, mejorado con validate_finding)
2. [x] Integrar con pipeline de análisis (validate_findings_with_mythril)
3. [ ] Cross-validation Slither + Mythril (pendiente - requiere Slither)

**Meta:** Precisión 45%+

### Sprint 3: ML
1. [x] Crear dataset de entrenamiento (rule-based weights from benchmark)
2. [x] Implementar FPClassifier (src/ml/fp_classifier.py)
3. [x] Entrenar y evaluar modelo (17 tests passing)

**Meta:** Precisión 55%+

### Sprint 4: Polish
1. [ ] Echidna integration (opcional)
2. [x] Benchmark con FP classifier integrado
3. [ ] Documentación

**Meta:** Precisión 60%+

## Notas de Implementación

### FP Classifier Limitaciones en SolidiFI

El benchmark SolidiFI usa contratos intencionalmente vulnerables SIN guards:
- No tienen ReentrancyGuard
- No tienen Solidity 0.8+
- No tienen SafeMath

Por lo tanto, el FP classifier no puede mejorar la precisión en este benchmark
específico. En contratos de producción con guards, será más efectivo.

### Resultados Actuales

| Modo | Precisión | Recall | F1 |
|------|-----------|--------|-----|
| v4.6.0 base | 26.7% | 85.7% | 40.7% |
| v4.7.0 + FP filter | 26.7% | 85.7% | 40.7% |
| v4.7.0 + min-conf 0.4 | 25.5% | 24.9% | 25.2% |

Para mejorar precisión significativamente se requiere:
1. Slither real para cross-validation
2. Mythril para confirmación simbólica

---

## Dependencias

```bash
# Slither (ya requerido)
pip install slither-analyzer

# Mythril
pip install mythril

# ML
pip install scikit-learn xgboost

# Echidna (opcional, binario)
# https://github.com/crytic/echidna/releases
```

---

## Archivos a Crear/Modificar

| Archivo | Acción | Prioridad |
|---------|--------|-----------|
| `src/adapters/mythril_adapter.py` | Crear | Alta |
| `src/ml/fp_classifier.py` | Crear | Media |
| `src/adapters/echidna_adapter.py` | Crear | Baja |
| `src/ml/slither_validator.py` | Modificar | Alta |
| `src/ml/correlation_engine.py` | Modificar | Media |
| `benchmarks/solidifi_benchmark.py` | Modificar | Alta |

---

## Métricas de Éxito

| Sprint | Precisión | Recall | F1 |
|--------|-----------|--------|-----|
| Actual | 26.7% | 85.7% | 40.7% |
| Sprint 1 | 35% | 85% | 50% |
| Sprint 2 | 45% | 85% | 58% |
| Sprint 3 | 55% | 85% | 67% |
| Final | **60%+** | **85%+** | **70%+** |

---

## Verificación

```bash
# Test SlitherValidator
python -c "
from src.ml.slither_validator import SlitherValidator
v = SlitherValidator()
print(f'Slither available: {v.is_available}')
"

# Benchmark con filtro de confianza
python benchmarks/solidifi_benchmark.py --quick --min-confidence 0.5

# Benchmark high-precision mode
python benchmarks/solidifi_benchmark.py --quick --high-precision
```
