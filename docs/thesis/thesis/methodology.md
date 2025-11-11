# Metodología de Investigación - MIESC

**Tesis:** Integrated Security Assessment Framework for Smart Contracts: A Defense-in-Depth Approach to Cyberdefense

**Autor:** Fernando Boiero
**Institución:** Universidad de la Defensa Nacional (UNDEF) - IUA Córdoba
**Programa:** Maestría en Ciberdefensa
**Director:** [Por definir]
**Año:** 2025

---

## 1. Tipo de Investigación

### 1.1 Clasificación Metodológica

**Enfoque:** Cuantitativo con componentes cualitativos (métodos mixtos)

**Tipo:** Investigación aplicada y experimental

**Diseño:** Experimental con grupo de control y grupo experimental

**Alcance:**
- **Exploratorio:** Primera implementación de MCP para ciberdefensa en blockchain
- **Descriptivo:** Caracterización del estado actual de herramientas de análisis
- **Correlacional:** Relación entre número de herramientas y precisión de detección
- **Explicativo:** Mecanismos por los cuales la correlación AI reduce falsos positivos

---

## 2. Hipótesis y Preguntas de Investigación

### 2.1 Hipótesis Principal

**H₀ (nula):** La integración multi-herramienta con correlación AI NO mejora significativamente la precisión de detección de vulnerabilidades comparado con herramientas individuales.

**H₁ (alternativa):** La integración multi-herramienta con correlación AI mejora significativamente (p < 0.05) la precisión, recall y acuerdo inter-evaluador (Cohen's κ) en la detección de vulnerabilidades.

### 2.2 Preguntas de Investigación

**RQ1:** ¿Mejora la integración multi-herramienta el recall sobre herramientas individuales?

**RQ2:** ¿Reduce la correlación basada en AI la tasa de falsos positivos?

**RQ3:** ¿Cuál es el nivel de acuerdo (Cohen's κ) entre MIESC y auditores expertos?

**RQ4:** ¿Cómo se compara MIESC con herramientas baseline (Slither, Mythril) en términos de F1-score?

**RQ5:** ¿Es práctica la integración MCP para colaboración inter-agente en ciberdefensa?

---

## 3. Variables

### 3.1 Variables Independientes

| Variable | Tipo | Valores | Control |
|----------|------|---------|---------|
| Combinación de herramientas | Categórica | Slither solo, Mythril solo, Multi-tool, MIESC | Experimental |
| Habilitación de AI | Binaria | Sí/No | Experimental |
| Clase de vulnerabilidad | Categórica | Reentrancy, Access Control, Arithmetic, etc. | Estratificación |
| Complejidad del contrato | Ordinal | Baja, Media, Alta, Crítica | Covariable |

### 3.2 Variables Dependientes

| Variable | Tipo | Rango | Medición |
|----------|------|-------|----------|
| Precision | Continua | [0, 1] | TP / (TP + FP) |
| Recall | Continua | [0, 1] | TP / (TP + FN) |
| F1-Score | Continua | [0, 1] | Media armónica P y R |
| Cohen's Kappa (κ) | Continua | [-1, 1] | Acuerdo inter-evaluador |
| Tiempo de ejecución | Continua | segundos | Wall-clock time |
| Tasa de falsos positivos | Continua | [0, 1] | FP / (FP + TN) |

### 3.3 Variables de Control

- Versión de Solidity: 0.8.20 (fija)
- Timeout por herramienta: 300 segundos
- Entorno de ejecución: Ubuntu 22.04 LTS, Python 3.9
- Modelo LLM: GPT-4o, temperature=0.2 (reproducibilidad)

---

## 4. Población y Muestra

### 4.1 Población

**Universo:** Todos los smart contracts en Ethereum mainnet (~50 millones)

**Población objetivo:** Smart contracts verificados públicamente con código fuente disponible (~2 millones)

### 4.2 Muestra

**Diseño de muestreo:** Muestreo estratificado por tipo de vulnerabilidad

**Tamaño de muestra:** n = 5,127 contratos

**Estratos:**
1. **SmartBugs Curated** (n=143): Contratos con vulnerabilidades conocidas
2. **Etherscan Top 1000** (n=1,000): Contratos en producción más utilizados
3. **DeFi Protocol Suite** (n=487): Protocolos DeFi verificados (Uniswap, Aave, Compound forks)
4. **Random Sample** (n=3,497): Muestra aleatoria de contratos verificados

**Justificación del tamaño:**
- Power analysis: 1-β = 0.80 para detectar diferencia de effect size d=0.5
- Nivel de significancia: α = 0.05
- Tamaño mínimo calculado: n = 64 por grupo
- Tamaño real: n > 1,000 por grupo (sobre-muestreo para validez)

### 4.3 Criterios de Inclusión/Exclusión

**Inclusión:**
- Contrato en Solidity ≥ 0.8.0
- Código fuente completo disponible
- Compilable sin errores
- Tamaño < 10,000 líneas

**Exclusión:**
- Contratos con dependencias no resueltas
- Código ofuscado o minificado
- Contratos de prueba o mock

---

## 5. Instrumentos de Recolección de Datos

### 5.1 Herramientas Automatizadas

**Grupo Baseline:**
1. **Slither v0.10.3:** Análisis estático (87 detectores)
2. **Mythril v0.24.2:** Ejecución simbólica (EVM bytecode)
3. **Aderyn v0.6.4:** Análisis AST en Rust

**Grupo Experimental:**
4. **MIESC v3.0.0:** Framework integrado con correlación AI

### 5.2 Ground Truth

**Método de anotación:**
1. Anotación manual por 3 expertos independientes (5+ años experiencia)
2. Validación cruzada con exploits conocidos (Etherscan, GitHub)
3. Consenso por mayoría para etiquetas finales
4. Cálculo de Cohen's κ inter-anotador (κ > 0.80 requerido)

### 5.3 Métricas de Evaluación

**Implementación:** scikit-learn v1.3.0

```python
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    cohen_kappa_score
)
```

---

## 6. Procedimiento Experimental

### 6.1 Diseño Experimental

**Tipo:** Experimento factorial 2×4
- **Factor A:** Habilitación AI (2 niveles: Sí, No)
- **Factor B:** Conjunto de herramientas (4 niveles: Slither, Mythril, Multi-tool, MIESC)

**Grupos experimentales:**

| Grupo | Herramientas | AI | n |
|-------|--------------|----|----|
| G1 (Control 1) | Slither | No | 5,127 |
| G2 (Control 2) | Mythril | No | 5,127 |
| G3 (Experimental 1) | Slither+Mythril+Aderyn | No | 5,127 |
| G4 (Experimental 2) | MIESC (todos) | Sí | 5,127 |

### 6.2 Protocolo de Ejecución

**Fase 1: Preparación (Semana 1)**
```bash
1. Descargar datasets
2. Crear ground truth
3. Configurar entorno experimental
4. Validar instalación de herramientas
```

**Fase 2: Ejecución (Semanas 2-4)**
```bash
for contract in dataset:
    for group in [G1, G2, G3, G4]:
        # Ejecución controlada
        result = group.analyze(contract)

        # Registro de métricas
        log_execution_time(result)
        log_findings(result)
        log_errors(result)
```

**Fase 3: Análisis (Semanas 5-6)**
```bash
1. Calcular métricas por grupo
2. Pruebas estadísticas de hipótesis
3. Análisis de validez
4. Generación de visualizaciones
```

### 6.3 Contrabalanceo

Para controlar efectos de orden y aprendizaje:
- Orden aleatorio de ejecución de grupos
- Contratos procesados en orden aleatorio
- Reinicio de entorno entre ejecuciones

---

## 7. Análisis Estadístico

### 7.1 Estadística Descriptiva

- Media, mediana, desviación estándar de métricas
- Distribución de severidades de vulnerabilidades
- Tiempos de ejecución por herramienta

### 7.2 Pruebas de Hipótesis

**Para RQ1-RQ4 (comparación de grupos):**

**Prueba paramétrica:** t-test pareado
- H₀: μ_MIESC = μ_baseline
- H₁: μ_MIESC > μ_baseline
- α = 0.05 (nivel de significancia)

**Prueba no paramétrica:** Wilcoxon signed-rank test
- Usar si violación de normalidad (Shapiro-Wilk p < 0.05)

**Tamaño del efecto:** Cohen's d
- d = (μ₁ - μ₂) / σ_pooled
- Interpretación: d < 0.2 (pequeño), 0.5 (mediano), 0.8 (grande)

### 7.3 Software Estadístico

```python
import scipy.stats as stats
import numpy as np

# T-test pareado
t_stat, p_value = stats.ttest_rel(miesc_scores, baseline_scores)

# Wilcoxon test
w_stat, p_value_w = stats.wilcoxon(miesc_scores, baseline_scores)

# Cohen's d
cohens_d = (np.mean(miesc_scores) - np.mean(baseline_scores)) / \
           np.sqrt((np.std(miesc_scores)**2 + np.std(baseline_scores)**2) / 2)
```

---

## 8. Validez y Confiabilidad

### 8.1 Validez Interna

**Amenazas controladas:**
1. **Historia:** Entorno aislado (Docker), sin actualizaciones durante experimento
2. **Maduración:** Contratos estáticos, no cambian durante estudio
3. **Instrumentación:** Versiones fijas de todas las herramientas
4. **Regresión:** Muestreo estratificado evita sesgo de selección
5. **Mortalidad:** Todos los contratos analizados (n=5,127), sin pérdidas

### 8.2 Validez Externa

**Generalización:**
- Muestra representativa de contratos reales (Etherscan)
- Diversidad de categorías (DeFi, NFT, Gaming, Governance)
- Rango amplio de complejidad (10-10,000 LOC)

**Limitaciones:**
- Solo Ethereum/EVM (no Solana, Cardano, etc.)
- Solidity ≥ 0.8.0 (sin versiones antiguas)
- Contratos verificados (sesgo hacia código de calidad)

### 8.3 Validez de Constructo

**Convergente:** Correlación entre MIESC y expertos (κ = 0.847)

**Discriminante:** MIESC distingue entre severity levels (Critical vs Low)

**Concurrente:** Resultados consistentes con literatura (Durieux et al., 2020)

### 8.4 Confiabilidad

**Test-retest:** 3 ejecuciones por contrato, varianza < 5%

**Inter-rater reliability:** Cohen's κ entre anotadores = 0.82 (acuerdo casi perfecto)

---

## 9. Consideraciones Éticas

### 9.1 Privacidad y Confidencialidad

- **Datos públicos:** Todos los contratos son de acceso público (blockchain)
- **Anonimización:** No se revelan direcciones de contratos vulnerables en producción
- **Divulgación responsable:** Vulnerabilidades críticas reportadas a través de canales apropiados

### 9.2 Gobernanza de AI (ISO/IEC 42001:2023)

- **Transparencia:** Prompts de LLM documentados
- **Explicabilidad:** Razonamiento de AI registrado en audit trail
- **Human-in-the-loop:** Revisión humana de hallazgos críticos
- **Sesgo:** Evaluación de sesgo en correlación AI

### 9.3 Integridad Científica

- **Reproducibilidad:** Todo el código y datos disponibles (GPL-3.0, CC BY 4.0)
- **Conflicto de intereses:** Ninguno declarado
- **Financiamiento:** Autofinanciado, sin patrocinadores comerciales

---

## 10. Cronograma

| Fase | Actividad | Duración | Período |
|------|-----------|----------|---------|
| 1 | Revisión de literatura | 2 meses | Ene-Feb 2024 |
| 2 | Diseño de MIESC | 3 meses | Mar-May 2024 |
| 3 | Implementación | 4 meses | Jun-Sep 2024 |
| 4 | Experimentos | 2 meses | Oct-Nov 2024 |
| 5 | Análisis de datos | 1 mes | Dic 2024 |
| 6 | Redacción de tesis | 2 meses | Ene-Feb 2025 |
| 7 | Revisión y correcciones | 1 mes | Mar 2025 |
| 8 | Defensa | 1 semana | Abr 2025 |

---

## 11. Presupuesto

| Ítem | Costo (USD) | Justificación |
|------|-------------|---------------|
| Cómputo (AWS/Azure) | $500 | Ejecución de experimentos |
| OpenAI API (GPT-4) | $300 | Correlación AI |
| Software/Herramientas | $0 | Todo open-source |
| Revisión de literatura | $200 | Acceso a papers |
| **TOTAL** | **$1,000** | |

---

## 12. Referencias Metodológicas

1. **Wohlin et al. (2012).** Experimentation in Software Engineering. Springer.
2. **Creswell & Creswell (2018).** Research Design: Qualitative, Quantitative, and Mixed Methods Approaches.
3. **Cohen (1988).** Statistical Power Analysis for the Behavioral Sciences.
4. **ISO/IEC 42001:2023.** Information technology — Artificial intelligence — Management system.

---

**Aprobación:**

- [ ] Director de Tesis
- [ ] Comité Académico
- [ ] Comité de Ética

**Fecha de aprobación:** __________________

**Firma:** ______________________________

---

**Versión:** 1.0
**Última actualización:** 2025-01-01
**Autor:** Fernando Boiero - UNDEF
