# Metodología de Investigación - Xaudit Framework

## 1. Enfoque de Investigación

Esta investigación adopta un enfoque **mixto experimental-aplicado** que combina:

- **Investigación experimental**: Evaluación controlada de herramientas de auditoría
- **Desarrollo de sistemas**: Implementación del framework Xaudit
- **Estudio comparativo**: Análisis de efectividad entre técnicas

## 2. Marco Metodológico del Framework Xaudit

### 2.1 Pipeline de Análisis Híbrido

```
┌─────────────────────────────────────────────────────────────────┐
│                    ENTRADA: Smart Contract                       │
└────────────────────────────┬────────────────────────────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    ▼                    ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   ANÁLISIS   │    │   ANÁLISIS   │    │  VERIFICACIÓN│
│   ESTÁTICO   │    │   DINÁMICO   │    │    FORMAL    │
└──────────────┘    └──────────────┘    └──────────────┘
│ - Slither    │    │ - Echidna    │    │ - Certora    │
│ - Solhint    │    │ - Medusa     │    │ - Scribble   │
│ - Mythril    │    │ - Foundry    │    │ - K Framework│
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │                   │                    │
       └───────────────────┼────────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  IA ASSISTANT   │
                  │  - Triage       │
                  │  - Priorización │
                  │  - Resumen      │
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ REPORTE FINAL   │
                  └─────────────────┘
```

### 2.2 Fases del Análisis

#### Fase 1: Análisis Estático (Static Analysis)
**Herramienta principal**: Slither

**Proceso**:
1. Parseo del código Solidity a SlithIR
2. Ejecución de 90+ detectores built-in
3. Análisis de dependencias y herencia
4. Detección de patrones inseguros

**Salida**:
```json
{
  "detector": "reentrancy-eth",
  "severity": "high",
  "confidence": "high",
  "description": "...",
  "locations": [...]
}
```

**Métricas**:
- Número de vulnerabilidades por categoría
- Severidad (high/medium/low/info)
- Confianza del detector
- Tiempo de ejecución

#### Fase 2: Anotación de Propiedades (Property Annotation)
**Herramienta**: Scribble

**Proceso**:
1. Definición de invariantes en anotaciones
2. Instrumentación del código Solidity
3. Generación de código verificable

**Ejemplo de anotación**:
```solidity
/// #if_succeeds {:msg "Balance must increase"}
///     balances[msg.sender] == old(balances[msg.sender]) + amount;
function deposit(uint256 amount) public { ... }
```

#### Fase 3: Fuzzing Avanzado (Property-Based Testing)
**Herramientas**: Echidna + Medusa

**Echidna (Property-Based)**:
```yaml
# echidna/config.yaml
testMode: property
testLimit: 100000
shrinkLimit: 5000
deployer: 0x00a329c0648769A73afAc7F9381E08FB43dBEA72
```

**Medusa (Coverage-Guided)**:
```json
{
  "fuzzing": {
    "workers": 10,
    "workerResetLimit": 50,
    "testLimit": 100000
  }
}
```

**Métricas**:
- Cobertura de código alcanzada
- Propiedades violadas
- Secuencias de transacciones para reproducción
- Tiempo de fuzzing

#### Fase 4: Testing Diferencial (Differential Testing)
**Herramienta**: Foundry

**Proceso**:
1. Tests unitarios (forge test)
2. Tests de invariantes (invariant testing)
3. Fuzz testing integrado
4. Tests de integración

**Ejemplo**:
```solidity
// test/Invariant.t.sol
function invariant_totalSupplyEqualsSumOfBalances() public {
    assertEq(token.totalSupply(), sumOfBalances);
}
```

#### Fase 5: Verificación Formal (Formal Verification)
**Herramienta**: Certora Prover (CVL)

**Proceso**:
1. Especificación de propiedades en CVL
2. Verificación exhaustiva mediante SMT solving
3. Generación de contraejemplos

**Ejemplo CVL**:
```cvl
rule transferMonotonicity(address from, address to, uint256 amount) {
    env e;
    uint256 balanceBefore = balanceOf(to);
    transfer(e, to, amount);
    uint256 balanceAfter = balanceOf(to);
    assert balanceAfter >= balanceBefore;
}
```

#### Fase 6: Análisis Asistido por IA
**Componente**: AI Assistant (GPT-4 / Llama)

**Funciones**:
1. **Triage automático**: Clasificación de findings por riesgo real
2. **Deduplicación**: Identificación de hallazgos redundantes
3. **Contextualización**: Análisis del impacto en lógica de negocio
4. **Generación de PoC**: Creación de exploits demostrativos
5. **Recomendaciones**: Sugerencias de mitigación

**Prompt Engineering**:
```python
system_prompt = """
Eres un auditor experto en smart contracts de Ethereum.
Analiza los siguientes findings y:
1. Identifica falsos positivos
2. Prioriza por impacto real
3. Sugiere exploits concretos
4. Propón mitigaciones
"""
```

### 2.3 Integración CI/CD

**Workflow automatizado**:
```yaml
# .github/workflows/audit.yml
name: Security Audit Pipeline
on: [push, pull_request]
jobs:
  static-analysis:
    - Slither
  fuzzing:
    - Echidna (30 min timeout)
    - Medusa (parallel)
  testing:
    - Foundry tests + coverage
  formal:
    - Certora (if specs exist)
  ai-triage:
    - Consolidate results
    - Generate report
```

## 3. Metodología Experimental

### 3.1 Dataset de Contratos

**Categorías**:
1. **Contratos Vulnerables Sintéticos**
   - Reentrancy (SWC-107)
   - Integer Overflow (SWC-101)
   - Access Control (SWC-105)
   - Uninitialized Proxy (SWC-109)
   - ERC-4626 Inflation Attack
   - Oracle Manipulation

2. **Contratos Reales**
   - Extraídos de auditorías públicas
   - Casos históricos (The DAO, Parity, etc.)

**Estructura**:
```
src/contracts/
├── vulnerable/
│   ├── reentrancy/
│   ├── overflow/
│   ├── access-control/
│   ├── proxy/
│   ├── erc4626/
│   └── oracle/
└── real-world/
    ├── dao/
    ├── defi/
    └── nft/
```

### 3.2 Variables y Métricas

**Variables Independientes**:
- Tipo de contrato
- Complejidad (líneas de código, funciones)
- Presencia de vulnerabilidades conocidas

**Variables Dependientes**:
- **Precisión** (Precision): TP / (TP + FP)
- **Recall** (Sensibilidad): TP / (TP + FN)
- **F1-Score**: 2 * (Precision * Recall) / (Precision + Recall)
- **Tiempo de ejecución** (segundos)
- **Cobertura de código** (%)

**Métricas Comparativas**:
```python
metrics = {
    "true_positives": count,
    "false_positives": count,
    "false_negatives": count,
    "execution_time": seconds,
    "code_coverage": percentage,
    "cost_reduction": percentage  # vs. auditoría manual
}
```

### 3.3 Experimentos Planificados

**Experimento 1**: Comparación Slither vs. Manual
- Objetivo: Evaluar precisión de detectores estáticos
- Contratos: 50 contratos vulnerables conocidos
- Métrica: Tasa de detección por categoría SWC

**Experimento 2**: Fuzzing (Echidna vs. Medusa)
- Objetivo: Comparar efectividad de fuzzing
- Contratos: 20 contratos con propiedades definidas
- Métrica: Tiempo hasta vulnerabilidad, cobertura

**Experimento 3**: Pipeline Híbrido vs. Herramienta Individual
- Objetivo: Validar valor agregado del framework Xaudit
- Contratos: Dataset completo (100+ contratos)
- Métrica: F1-Score, reducción de falsos positivos

**Experimento 4**: Impacto de IA en Triage
- Objetivo: Medir mejora en priorización con IA
- Contratos: Resultados de Slither (500+ findings)
- Métrica: Tiempo de revisión manual, precisión en clasificación

### 3.4 Protocolo de Evaluación

**Proceso**:
1. **Preparación**
   - Selección de contratos
   - Configuración de herramientas
   - Definición de ground truth

2. **Ejecución**
   - Ejecución automatizada vía CI/CD
   - Captura de logs y métricas
   - Almacenamiento de resultados en JSON

3. **Análisis**
   - Cálculo de métricas
   - Análisis estadístico (t-test, ANOVA)
   - Generación de gráficos

4. **Validación**
   - Revisión manual de falsos positivos/negativos
   - Reproducción de exploits
   - Verificación de mitigaciones

## 4. Consideraciones Éticas y Limitaciones

**Aspectos Éticos**:
- Uso responsable de vulnerabilidades descubiertas
- Divulgación coordinada (responsible disclosure)
- Anonimización de contratos reales

**Limitaciones**:
- Dependencia de calidad de anotaciones en verificación formal
- Costo computacional de fuzzing exhaustivo
- Restricciones de API en herramientas comerciales (Certora)
- Sesgos en datasets de entrenamiento de IA

## 5. Cronograma de Investigación

| Fase | Duración | Actividades |
|------|----------|-------------|
| Fase 1 | 2 semanas | Configuración de herramientas y dataset |
| Fase 2 | 3 semanas | Experimentos individuales (Slither, Echidna, etc.) |
| Fase 3 | 4 semanas | Integración del pipeline Xaudit |
| Fase 4 | 2 semanas | Experimentos comparativos |
| Fase 5 | 3 semanas | Análisis de resultados y escritura |
| Fase 6 | 1 semana | Revisión y ajustes finales |

**Total**: ~15 semanas

## 6. Referencias Metodológicas

- Luu et al. (2016) - Making Smart Contracts Smarter
- Tsankov et al. (2018) - Securify: Practical Security Analysis
- Grieco et al. (2020) - Echidna: Effective, Usable, and Fast Fuzzing
- Certora (2023) - Formal Verification of Smart Contracts
- NIST (2024) - Secure Software Development Framework

---

**Última actualización**: Octubre 2025
**Autor**: Fernando Boiero
**Contacto**: fboiero@frvm.utn.edu.ar
