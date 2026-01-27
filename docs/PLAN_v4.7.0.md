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

### Sprint 1: Quick Wins ✅
1. [x] Probar SlitherValidator con benchmark real
2. [x] Ajustar umbrales de confianza
3. [x] Filtrar por confianza mínima

**Resultado:** Precisión 27.8% con min-conf 0.7 (+1.1%)

### Sprint 2: Mythril ✅
1. [x] Crear MythrilAdapter (existente, mejorado con validate_finding)
2. [x] Integrar con pipeline de análisis (validate_findings_with_mythril)
3. [x] Mythril en benchmark (--mythril flag)
4. [x] Cross-validation con Mythril funcional

**Resultado:** Mythril funciona pero muy lento (2+ min/contrato).

### Sprint 3: ML ✅
1. [x] Crear dataset de entrenamiento (rule-based weights)
2. [x] Implementar FPClassifier (src/ml/fp_classifier.py)
3. [x] 17 tests passing

**Resultado:** FP Classifier no mejora SolidiFI (contratos sin guards)

### Sprint 4: Slither Cross-Validation ✅
1. [x] Implementar cross_validate_with_slither()
2. [x] Agregar CLI flags --slither, --slither-timeout
3. [x] Integrar en benchmark

**Resultado:** Slither no puede compilar contratos SolidiFI (pragma 0.4-0.5)

### Sprint 5: Slither con solc-select ✅
1. [x] Instalar solc-select (pip install solc-select)
2. [x] Configurar múltiples versiones solc (0.4.26, 0.5.17)
3. [x] Modificar SlitherValidator para auto-detectar versión
4. [x] Cross-validation selectiva por tipo de vulnerabilidad
5. [x] Re-evaluar benchmark con Slither funcionando

**Resultado Final:**
| Configuración | Precisión | Recall | F1 |
|--------------|-----------|--------|-----|
| Baseline | 26.7% | 85.7% | 40.7% |
| Slither + conf 0.50 | **35.5%** | 67.1% | **46.4%** |

**Meta original 60%+ no alcanzable** sin sacrificar >50% de recall.

## Notas de Implementación

### FP Classifier Limitaciones en SolidiFI

El benchmark SolidiFI usa contratos intencionalmente vulnerables SIN guards:
- No tienen ReentrancyGuard
- No tienen Solidity 0.8+
- No tienen SafeMath

Por lo tanto, el FP classifier no puede mejorar la precisión en este benchmark
específico. En contratos de producción con guards, será más efectivo.

### Resultados Actuales (con Slither funcionando)

| Modo | Precisión | Recall | F1 | Notas |
|------|-----------|--------|-----|-------|
| v4.6.0 base | 26.7% | 85.7% | 40.7% | Línea base |
| v4.7.0 + Slither + conf 0.45 | 27.6% | 85.4% | 41.8% | Bajo impacto |
| v4.7.0 + Slither + conf 0.48 | 27.7% | 85.3% | 41.8% | Bajo impacto |
| **v4.7.0 + Slither + conf 0.50** | **35.5%** | **67.1%** | **46.4%** | **Mejor F1** |

### Análisis de Resultados con Slither

La cross-validación con Slither funciona correctamente después de:
1. Instalar solc-select con versiones 0.4.26 y 0.5.17
2. Corregir detección de versión Solidity (address payable → 0.5+)
3. Aplicar penalización selectiva solo a tipos que Slither puede detectar

**Hallazgos clave:**
- Slither confirma ~44% de las detecciones (36/81 en reentrancy)
- Con umbral 0.50: Precisión sube +8.8% pero Recall baja -18.6%
- Trade-off: Mayor precisión requiere sacrificar recall
- Tipos sin cobertura Slither (overflow, TOD) mantienen recall original

### Problema Resuelto: Incompatibilidad de Versiones Solidity

**Solución implementada:**
```bash
# Instalar solc-select para múltiples versiones
pip install solc-select
solc-select install 0.4.26 0.5.17 0.6.12 0.7.6 0.8.20
```

**Corrección en SlitherValidator:** Auto-detecta `address payable` y usa 0.5.17 en vez de 0.4.26.

### Limitaciones Identificadas

1. **FP Classifier:** Contratos SolidiFI no tienen guards → classifier no puede mejorar precisión
2. **Mythril:** Muy lento (2+ min/contrato) para benchmark completo
3. **Trade-off precisión/recall:** No se puede alcanzar 60% precisión sin perder >20% recall
4. **Cobertura Slither:** No detecta overflow/underflow ni TOD efectivamente

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
