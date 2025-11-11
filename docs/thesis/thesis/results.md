# Resultados y Análisis

## Estado: ⏳ PENDIENTE DE EJECUCIÓN EXPERIMENTAL

Este documento se completará con los resultados una vez ejecutados los experimentos.

---

## Estructura de Resultados

### 1. Resultados por Experimento

#### 1.1 Experimento 1: Análisis Estático (Slither)

**Hallazgos Principales**:
- *Pendiente*

**Tabla de Resultados**:
| Categoría SWC | TP | FP | FN | Precision | Recall | F1-Score |
|---------------|----|----|----|-----------| -------|----------|
| Reentrancy | - | - | - | - | - | - |
| Overflow | - | - | - | - | - | - |
| Access Control | - | - | - | - | - | - |
| ... | - | - | - | - | - | - |

**Gráficos**:
```
[Pendiente: Gráfico de barras - Precision/Recall por categoría]
[Pendiente: Confusion matrix]
```

**Análisis**:
- *A completar*

---

#### 1.2 Experimento 2: Fuzzing Comparativo

**Hallazgos Principales**:
- *Pendiente*

**Tabla Comparativa**:
| Métrica | Echidna | Medusa | Diferencia |
|---------|---------|--------|------------|
| Avg Coverage (%) | - | - | - |
| Avg Time to Bug (s) | - | - | - |
| Properties Violated | - | - | - |
| Total Execution Time (hr) | - | - | - |

**Gráficos**:
```
[Pendiente: Coverage over time plot]
[Pendiente: Box plot - Time to vulnerability]
```

**Análisis**:
- *A completar*

---

#### 1.3 Experimento 3: Pipeline Híbrido (Xaudit)

**Hallazgos Principales**:
- *Pendiente*

**Tabla de Rendimiento**:
| Framework | Precision | Recall | F1 | Time (avg) | Cost |
|-----------|-----------|--------|----|------------|------|
| Slither only | - | - | - | - | - |
| Echidna only | - | - | - | - | - |
| Foundry only | - | - | - | - | - |
| **Xaudit (full)** | **-** | **-** | **-** | **-** | **-** |

**Test Estadístico**:
```
H0: μ(Xaudit F1) = μ(Slither F1)
t-test: t = -, p = -
Conclusión: [Rechazar/No rechazar] H0 (α = 0.05)
```

**Gráficos**:
```
[Pendiente: Radar chart - Metrics comparison]
[Pendiente: ROC curve for each tool]
```

**Análisis**:
- *A completar*

---

#### 1.4 Experimento 4: IA en Triage

**Hallazgos Principales**:
- *Pendiente*

**Tabla de Impacto**:
| Métrica | Sin IA | Con IA | Mejora (%) |
|---------|--------|--------|------------|
| Tiempo revisión (hrs) | - | - | - |
| Precisión clasificación | - | - | - |
| FP descartados | - | - | - |
| Satisfacción (1-5) | - | - | - |

**Casos de Éxito**:
```
[Ejemplo 1: Finding complejo correctamente clasificado]
[Ejemplo 2: Falso positivo detectado por IA]
```

**Gráficos**:
```
[Pendiente: Time savings chart]
[Pendiente: Confusion matrix - IA classification]
```

**Análisis**:
- *A completar*

---

#### 1.5 Experimento 5: Verificación Formal (Certora)

**Hallazgos Principales**:
- *Pendiente*

**Tabla de Verificación**:
| Contrato | Total Rules | Verified | Violated | Timeouts | Time (min) | CU Cost |
|----------|-------------|----------|----------|----------|------------|---------|
| ERC4626 | - | - | - | - | - | - |
| UniswapV2 | - | - | - | - | - | - |
| ... | - | - | - | - | - | - |

**Reglas Violadas** (ejemplos):
```cvl
// Ejemplo de regla violada con contraejemplo
rule example() { ... }
// Counterexample: ...
```

**Gráficos**:
```
[Pendiente: Pie chart - Rule outcomes]
[Pendiente: Scatter plot - Complexity vs Time]
```

**Análisis**:
- *A completar*

---

#### 1.6 Experimento 6: Contratos Reales

**Hallazgos Principales**:
- *Pendiente*

**Tabla Comparativa con Auditorías**:
| Contrato | Audit Findings | Xaudit Findings | Overlap | New | Missed | Match % |
|----------|----------------|-----------------|---------|-----|--------|---------|
| Compound V3 | - | - | - | - | - | - |
| Aave V3 | - | - | - | - | - | - |
| ... | - | - | - | - | - | - |

**Vulnerabilidades Nuevas Encontradas**:
- *Lista de nuevos findings no reportados en auditoría oficial*

**Vulnerabilidades Perdidas**:
- *Análisis de por qué fueron omitidas por Xaudit*

**Gráficos**:
```
[Pendiente: Venn diagram - Overlap findings]
[Pendiente: Severity distribution comparison]
```

**Análisis**:
- *A completar*

---

### 2. Análisis Agregado

#### 2.1 Rendimiento General del Framework

**Métricas Consolidadas**:
```
Total contratos analizados: -
Total vulnerabilidades detectadas: -
Precisión promedio: - %
Recall promedio: - %
F1-Score promedio: -
Tiempo promedio de análisis: - min
```

**Distribución por Severidad**:
| Severidad | Count | % del Total |
|-----------|-------|-------------|
| Critical | - | - |
| High | - | - |
| Medium | - | - |
| Low | - | - |
| Info | - | - |

**Gráficos**:
```
[Pendiente: Overall metrics dashboard]
[Pendiente: Severity pyramid]
```

---

#### 2.2 Análisis de Costos

**Comparación de Costos**:
| Método | Tiempo | Costo Computacional | Costo Humano | Total (USD) |
|--------|--------|---------------------|--------------|-------------|
| Auditoría Manual | ~40 hrs | - | $8,000 | $8,000 |
| Xaudit (automated) | ~2 hrs | $50 | $400 (revisión) | $450 |
| **Ahorro** | **95%** | **-** | **95%** | **94%** |

*Nota: Costos estimados basados en tarifas de mercado 2025*

**Gráficos**:
```
[Pendiente: Cost comparison bar chart]
[Pendiente: Time breakdown pie chart]
```

---

#### 2.3 Análisis de Limitaciones

**Falsos Positivos**:
- Categorías con mayor tasa de FP
- Razones comunes (análisis cualitativo)
- Propuestas de mejora

**Falsos Negativos**:
- Tipos de vulnerabilidades omitidas
- Limitaciones de las herramientas
- Casos edge detectables solo manualmente

**Tabla de Limitaciones**:
| Limitación | Impacto | Mitigación Propuesta |
|------------|---------|----------------------|
| - | - | - |

---

### 3. Validación de Hipótesis

#### Hipótesis Principal
**H1**: *El framework Xaudit (análisis híbrido + IA) supera significativamente a herramientas individuales en detección de vulnerabilidades.*

**Resultado**:
- F1-Score Xaudit: -
- F1-Score mejor herramienta individual: -
- Diferencia: - (p = -)
- **Conclusión**: [Aceptada/Rechazada]

#### Hipótesis Secundaria 1
**H2**: *La incorporación de IA reduce el tiempo de triage manual en al menos 50%.*

**Resultado**:
- Tiempo sin IA: - hrs
- Tiempo con IA: - hrs
- Reducción: - %
- **Conclusión**: [Aceptada/Rechazada]

#### Hipótesis Secundaria 2
**H3**: *El fuzzing combinado (Echidna + Medusa) logra mayor cobertura que fuzzing individual.*

**Resultado**:
- Cobertura Echidna: - %
- Cobertura Medusa: - %
- Cobertura combinada: - %
- **Conclusión**: [Aceptada/Rechazada]

---

### 4. Casos de Estudio Destacados

#### Caso 1: [Nombre del Contrato]
**Descripción**: *Breve descripción*

**Vulnerabilidad Encontrada**:
```solidity
// Código vulnerable
function vulnerable() public {
    ...
}
```

**Análisis Xaudit**:
- Detectada por: [Slither/Echidna/Certora]
- Severidad: [Critical/High/Medium/Low]
- PoC generado por IA:
```solidity
// Exploit PoC
```

**Mitigación Sugerida**:
```solidity
// Código corregido
function secure() public {
    ...
}
```

---

#### Caso 2: [Nombre del Contrato]
*[Estructura similar]*

---

### 5. Contribuciones Científicas

**Principales Aportes**:

1. **Framework Xaudit**
   - Primer framework open-source que integra análisis estático, fuzzing, y verificación formal con IA
   - Pipeline CI/CD automatizado para auditoría continua

2. **Dataset de Vulnerabilidades**
   - 100+ contratos vulnerables categorizados por SWC
   - Casos reales anonimizados con ground truth

3. **Metodología de Evaluación**
   - Protocolo reproducible para benchmark de herramientas
   - Métricas estandarizadas (precision/recall/F1)

4. **Análisis de IA en Seguridad**
   - Evaluación empírica del impacto de LLMs en triage
   - Prompts especializados para análisis de contratos

**Publicaciones Derivadas** (potenciales):
- [ ] Paper en conferencia (IEEE S&P, CCS, NDSS)
- [ ] Dataset publicado en repositorio académico
- [ ] Herramienta open-source (GitHub)

---

### 6. Discusión

#### 6.1 Interpretación de Resultados
*A completar con análisis crítico de findings*

#### 6.2 Comparación con Estado del Arte
*Comparar con papers recientes (Slither, Mythril, Manticore, etc.)*

#### 6.3 Implicaciones Prácticas
*Para la industria blockchain y auditorías*

#### 6.4 Limitaciones del Estudio
- Tamaño del dataset
- Sesgos en selección de contratos
- Generalización a otros dominios (L2s, ZK contracts)

#### 6.5 Amenazas a la Validez
- **Interna**: Configuración de herramientas, expertise del evaluador
- **Externa**: Representatividad del dataset
- **Constructo**: Definición de vulnerabilidad
- **Conclusión**: Interpretación estadística

---

### 7. Recomendaciones

#### Para Desarrolladores
- *Mejores prácticas derivadas del estudio*

#### Para Auditores
- *Cómo integrar Xaudit en workflow*

#### Para Investigadores
- *Líneas de investigación futuras*

---

## Anexos

### Anexo A: Datos Crudos
```
/analysis/results/
├── slither_results.csv
├── echidna_results.csv
├── medusa_results.csv
├── certora_results.csv
└── consolidated.json
```

### Anexo B: Scripts de Análisis
```python
# Análisis estadístico (ejemplo)
import pandas as pd
import scipy.stats as stats

df = pd.read_csv('results.csv')
# ...
```

### Anexo C: Gráficos Adicionales
*Pendiente*

---

**Última actualización**: Pendiente (post-experimentación)
**Autor**: Fernando Boiero
**Institución**: Universidad Tecnológica Nacional - FRVM
**Contacto**: fboiero@frvm.utn.edu.ar
