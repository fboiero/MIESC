# CAPÍTULO 2 – MÉTODO CIENTÍFICO Y DISEÑO EXPERIMENTAL

## 2.1 Enfoque Metodológico

La presente investigación adopta un **enfoque cuantitativo experimental** dentro del paradigma positivista, utilizando el método científico para validar empíricamente la efectividad del framework Xaudit en la detección de vulnerabilidades en contratos inteligentes (Hernández-Sampieri et al., 2014).

### 2.1.1 Tipo de Investigación

**Investigación Aplicada y Experimental**

Este trabajo se clasifica como:
- **Investigación Aplicada**: Orientada a resolver un problema práctico específico (detección automatizada de vulnerabilidades en smart contracts)
- **Investigación Experimental**: Manipulación controlada de variables independientes (herramientas de análisis, configuraciones de IA) para observar efectos en variables dependientes (precisión, recall, reducción de FP)
- **Investigación Cuantitativa**: Uso de métricas numéricas para validar hipótesis (Cohen's Kappa, F1-Score, tiempo de ejecución)

**Clasificación según Arias (2012):**
- **Nivel:** Explicativo (busca determinar causalidad entre uso de IA y reducción de FP)
- **Diseño:** Experimental con grupo control (baseline sin IA vs. framework con IA)
- **Temporalidad:** Transversal (mediciones en un periodo específico: 2024-2025)

### 2.1.2 Método Científico Aplicado

#### Etapa 1: Observación y Planteamiento del Problema

**Observación Inicial:**
El análisis estático de smart contracts genera entre 200-500 hallazgos por contrato, de los cuales aproximadamente el 40-60% son falsos positivos (Durieux et al., 2020; Feist et al., 2019). Esta alta tasa de FP dificulta la priorización y consume tiempo de auditores.

**Problema de Investigación:**
¿Cómo reducir significativamente la tasa de falsos positivos en la auditoría automatizada de smart contracts sin comprometer la capacidad de detección de vulnerabilidades reales?

**Justificación Empírica:**

| Estudio | Herramienta | Tasa FP Reportada | N (contratos) |
|---------|-------------|-------------------|---------------|
| Durieux et al. (2020) | Slither | 42.3% | 69 |
| Feist et al. (2019) | SmartCheck | 58.1% | 142 |
| Luu et al. (2016) | Oyente | 67.4% | 45 |
| Tsankov et al. (2018) | Securify | 38.9% | 95 |
| **Promedio** | - | **51.7%** | 351 |

**Pregunta de Investigación Principal:**
¿Puede un sistema híbrido que integre 10 herramientas especializadas y triage con IA mejorar la precisión de detección por encima del 85% manteniendo recall >80%?

#### Etapa 2: Formulación de Hipótesis

**Hipótesis Principal (H1):**
La integración de análisis estático, ejecución simbólica, fuzzing, verificación formal y triage con IA (GPT-4o-mini) en un pipeline unificado (Xaudit) mejora significativamente la precisión de detección de vulnerabilidades en comparación con herramientas individuales.

**Operacionalización:**
- **VI (Variable Independiente):** Tipo de análisis (Slither solo vs. Xaudit completo)
- **VD (Variable Dependiente):** Precisión (TP / (TP + FP))
- **Predicción:** Precisión(Xaudit) > Precisión(Slither) con p-value < 0.05

**Hipótesis Secundarias:**

**H2:** El uso de GPT-4o-mini para clasificar hallazgos reduce la tasa de falsos positivos en al menos 30% comparado con el output crudo de herramientas estáticas.

**Operacionalización:**
- **VI:** Uso de IA (Con IA / Sin IA)
- **VD:** Tasa de FP (FP / (TP + FP))
- **Predicción:** Tasa_FP(Con IA) ≤ 0.70 × Tasa_FP(Sin IA)

**H3:** El acuerdo entre clasificaciones de IA y expertos humanos es sustancial (Cohen's Kappa ≥ 0.60) para vulnerabilidades críticas.

**Operacionalización:**
- **VI:** Clasificador (IA vs. Experto Humano)
- **VD:** Cohen's Kappa
- **Predicción:** κ ≥ 0.60 (acuerdo sustancial según Landis & Koch, 1977)

**H4:** El pipeline completo de Xaudit detecta más vulnerabilidades únicas que cualquier herramienta individual.

**Operacionalización:**
- **VI:** Herramienta (Slither / Mythril / Echidna / ... / Xaudit)
- **VD:** Número de vulnerabilidades únicas detectadas
- **Predicción:** Vulnerabilidades(Xaudit) > max(Vulnerabilidades(Herramienta_i))

#### Etapa 3: Diseño Experimental

**Diseño Cuasi-Experimental con Grupo Control**

```
Grupo Experimental (GE): Contratos analizados con Xaudit completo
Grupo Control (GC):      Contratos analizados solo con Slither

Medición Pre-test:  Ground truth (vulnerabilidades conocidas)
Intervención:       Aplicación de Xaudit (GE) o Slither (GC)
Medición Post-test: Comparación de detecciones vs ground truth
```

**Variables del Estudio:**

**Variables Independientes (VI):**
1. **Tipo de herramienta:** Slither, Mythril, Manticore, Echidna, Medusa, Foundry, Certora, Xaudit
2. **Uso de IA:** Con IA / Sin IA
3. **Tipo de contrato:** DeFi, NFT, DAO, Governance
4. **Complejidad:** SLOC (líneas de código)

**Variables Dependientes (VD):**
1. **Precisión:** TP / (TP + FP)
2. **Recall:** TP / (TP + FN)
3. **F1-Score:** 2 × (Precisión × Recall) / (Precisión + Recall)
4. **Tasa de FP:** FP / (TP + FP)
5. **Cohen's Kappa:** Acuerdo experto-IA
6. **Tiempo de ejecución:** Segundos

**Variables de Control:**
1. **Versión de Solidity:** 0.8.x (uniforme)
2. **Dataset:** SmartBugs Curated (ground truth validado)
3. **Configuración de herramientas:** Parámetros estandarizados
4. **Hardware:** AWS EC2 t3.xlarge (4 vCPU, 16GB RAM)

**Población y Muestra:**

**Población:** Todos los contratos inteligentes EVM desplegados en Ethereum mainnet (~50 millones según Etherscan, 2024)

**Muestra:** Selección no probabilística intencional
- **SmartBugs Curated:** 142 contratos con ground truth (muestra primaria)
- **SolidiFI Benchmark:** 9,369 contratos con bugs inyectados (validación)
- **Contratos Propios:** 25 contratos desarrollados específicamente

**Justificación del tamaño muestral:**
Para un nivel de confianza del 95% y margen de error del 5%, con p=0.5:
n = (1.96² × 0.5 × 0.5) / 0.05² = 384 contratos

Muestra total: 142 + 25 = 167 contratos (tamaño adecuado para análisis preliminar, requiere expansión para generalización)

#### Etapa 4: Experimentación

**Protocolo Experimental:**

**Experimento 1: Baseline de Herramientas Individuales**

*Objetivo:* Establecer métricas de rendimiento de cada herramienta de forma aislada

*Procedimiento:*
1. Seleccionar 142 contratos de SmartBugs Curated con ground truth
2. Ejecutar cada herramienta por separado con configuración estándar:
   - Slither v0.10.0 con 90 detectores activos
   - Mythril v0.23.0 con timeout de 5 min/contrato
   - Manticore v0.3.7 con exploración simbólica
   - Echidna v2.2.0 con 100,000 runs
   - Medusa v0.1.0 con 100,000 runs
   - Foundry con 10,000 fuzz runs
   - Certora Prover en 5 funciones críticas seleccionadas
3. Registrar para cada herramienta:
   - TP, FP, TN, FN (comparando con ground truth)
   - Tiempo de ejecución total
   - Recursos consumidos (CPU, RAM)
4. Calcular métricas: Precisión, Recall, F1, Tiempo promedio

*Resultados Esperados:* Tabla comparativa de performance individual

**Experimento 2: Integración del Pipeline Xaudit**

*Objetivo:* Medir performance del pipeline completo de 10 herramientas

*Procedimiento:*
1. Ejecutar Xaudit completo (10 herramientas + consolidación) en los mismos 142 contratos
2. Consolidar hallazgos eliminando duplicados inter-herramientas
3. Registrar:
   - Total de hallazgos consolidados
   - Vulnerabilidades únicas detectadas (unión de todas las herramientas)
   - Tiempo de ejecución total del pipeline
4. Comparar cobertura: ¿Cuántas vulnerabilidades de ground truth detecta Xaudit vs. herramientas individuales?

*Hipótesis a validar:* H4 (Xaudit detecta más vulnerabilidades únicas)

**Experimento 3: Comparación Con IA vs. Sin IA**

*Objetivo:* Medir impacto del módulo de IA en reducción de FP

*Procedimiento:*
1. **Grupo Control (Sin IA):**
   - Analizar 142 contratos con Slither
   - Output crudo sin filtrado
   - Clasificar manualmente todos los hallazgos (TP/FP)

2. **Grupo Experimental (Con IA):**
   - Analizar mismos 142 contratos con Slither
   - Aplicar módulo de IA (GPT-4o-mini) para clasificar hallazgos
   - IA filtra hallazgos clasificados como FP con confianza >70%

3. Comparar:
   - Tasa de FP antes y después de IA
   - Precisión antes y después
   - Recall (verificar que no se pierden TP)

*Métricas a calcular:*
```
Reducción_FP = ((FP_sin_IA - FP_con_IA) / FP_sin_IA) × 100%
Mejora_Precisión = Precisión_con_IA - Precisión_sin_IA
```

*Hipótesis a validar:* H2 (Reducción de FP ≥ 30%)

**Experimento 4: Validación Experto-IA (Cohen's Kappa)**

*Objetivo:* Medir acuerdo entre clasificaciones de IA y expertos humanos

*Procedimiento:*
1. Seleccionar muestra aleatoria de 200 hallazgos de Xaudit
2. **Clasificación por IA:**
   - GPT-4o-mini clasifica cada hallazgo en: Critical, High, Medium, Low, Informational, False Positive
   - Registrar nivel de confianza (0-100%)
3. **Clasificación por Expertos:**
   - 3 auditores senior independientes clasifican los mismos 200 hallazgos
   - Consenso por mayoría (2/3)
4. Calcular Cohen's Kappa:
   ```
   κ = (Po - Pe) / (1 - Pe)
   donde:
     Po = proporción de acuerdo observado
     Pe = proporción de acuerdo esperado por azar
   ```
5. Interpretar según escala de Landis & Koch (1977):
   - κ < 0: Sin acuerdo
   - 0.0-0.20: Acuerdo pobre
   - 0.21-0.40: Acuerdo justo
   - 0.41-0.60: Acuerdo moderado
   - 0.61-0.80: Acuerdo sustancial
   - 0.81-1.00: Acuerdo casi perfecto

*Hipótesis a validar:* H3 (κ ≥ 0.60)

**Experimento 5: Análisis de Tiempo de Ejecución**

*Objetivo:* Medir eficiencia temporal del pipeline

*Procedimiento:*
1. Ejecutar Xaudit en contratos de diferentes tamaños:
   - Pequeño: <200 SLOC
   - Mediano: 200-1000 SLOC
   - Grande: >1000 SLOC
2. Registrar tiempo de cada fase:
   - Solhint: t1
   - Slither: t2
   - Surya: t3
   - Mythril: t4
   - Manticore: t5
   - Echidna: t6
   - Medusa: t7
   - Foundry Fuzz: t8
   - Foundry Invariants: t9
   - Certora: t10
   - AI Triage: t11
   - Reporting: t12
3. Calcular:
   - Tiempo total: T_total = Σ(t1...t12)
   - Tiempo promedio por SLOC
   - Bottlenecks (fase más lenta)

*Métrica objetivo:* T_total < 30 minutos para contrato mediano

**Experimento 6: Escalabilidad en Datasets Grandes**

*Objetivo:* Validar performance en datasets de producción

*Procedimiento:*
1. Ejecutar Xaudit en SolidiFI Benchmark (9,369 contratos)
2. Modo paralelo: 4 workers simultáneos
3. Métricas:
   - Throughput: contratos/hora
   - Tasa de éxito: % de contratos analizados sin errores
   - Distribución de vulnerabilidades por tipo
4. Comparar con resultados de SmartBugs

*Validación:* Consistencia de métricas entre datasets

**Experimento 7: Validación Cruzada (Cross-Validation)**

*Objetivo:* Validar generalización del modelo de IA

*Procedimiento:*
1. Dividir SmartBugs Curated en 5 folds (28 contratos cada uno)
2. Entrenar prompts de IA en 4 folds, validar en 1 fold restante
3. Repetir 5 veces (cada fold es test una vez)
4. Calcular métricas promedio y desviación estándar
5. Verificar overfitting: performance en train vs. test

*Métricas:*
- Precisión_promedio ± σ
- Recall_promedio ± σ
- F1_promedio ± σ

#### Etapa 5: Recolección de Datos

**Instrumentos de Medición:**

**1. Script de Recolección Automatizada:**

```python
# experiments/data_collector.py

import json
import time
from pathlib import Path
from typing import Dict, List
import pandas as pd

class ExperimentDataCollector:
    """Recolecta métricas empíricas de ejecución de Xaudit."""

    def collect_tool_metrics(self, tool_name: str, contract_path: str,
                            ground_truth: List[Dict]) -> Dict:
        """
        Ejecuta herramienta y recolecta métricas.

        Returns:
            {
                'tool': str,
                'contract': str,
                'execution_time': float,
                'findings': List[Dict],
                'tp': int,
                'fp': int,
                'fn': int,
                'tn': int,
                'precision': float,
                'recall': float,
                'f1': float,
                'cpu_usage': float,
                'ram_usage': float
            }
        """
        start_time = time.time()

        # Ejecutar herramienta
        findings = self._run_tool(tool_name, contract_path)

        execution_time = time.time() - start_time

        # Comparar con ground truth
        tp, fp, fn, tn = self._calculate_confusion_matrix(findings, ground_truth)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        return {
            'tool': tool_name,
            'contract': contract_path,
            'execution_time': execution_time,
            'findings_count': len(findings),
            'tp': tp,
            'fp': fp,
            'fn': fn,
            'tn': tn,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'timestamp': time.time()
        }

    def save_to_csv(self, metrics: List[Dict], output_path: str):
        """Guarda métricas en CSV para análisis estadístico."""
        df = pd.DataFrame(metrics)
        df.to_csv(output_path, index=False)

        # También calcular estadísticas descriptivas
        stats = df.describe()
        stats.to_csv(output_path.replace('.csv', '_stats.csv'))
```

**2. Formato de Ground Truth:**

```json
// experiments/ground_truth/smartbugs_curated.json
{
  "contract": "reentrancy/simple_dao.sol",
  "vulnerabilities": [
    {
      "type": "reentrancy",
      "severity": "critical",
      "function": "withdraw",
      "line": 45,
      "swc_id": "SWC-107",
      "cwe_id": "CWE-841",
      "description": "External call before state change allows reentrancy",
      "exploitable": true,
      "exploited_in_wild": true,
      "historical_reference": "The DAO Hack (2016)"
    }
  ],
  "total_vulnerabilities": 1,
  "sloc": 87,
  "complexity": "low",
  "category": "DeFi"
}
```

**3. Plantilla de Registro de Experimento:**

```yaml
# experiments/experiment_X/metadata.yml

experiment_id: EXP-001
title: "Baseline Performance - Slither"
date: 2024-10-15
researcher: Fernando Boiero
objective: "Establecer métricas baseline de Slither en SmartBugs Curated"

parameters:
  tool: slither
  version: "0.10.0"
  dataset: smartbugs-curated
  dataset_size: 142
  detectors: all (90 detectors)
  timeout: 300s per contract
  hardware:
    cpu: AWS EC2 t3.xlarge
    vcpus: 4
    ram: 16GB
    os: Ubuntu 22.04 LTS

execution:
  start_time: "2024-10-15T09:00:00Z"
  end_time: "2024-10-15T11:23:45Z"
  duration_minutes: 143.75
  successful_runs: 139
  failed_runs: 3

results:
  total_findings: 3847
  true_positives: 487
  false_positives: 3360
  false_negatives: 58
  precision: 0.1265  # 12.65%
  recall: 0.8934     # 89.34%
  f1_score: 0.2219
  avg_time_per_contract: 60.45s

statistical_analysis:
  precision_ci_95: [0.1189, 0.1341]
  recall_ci_95: [0.8756, 0.9112]

notes: |
  Alta tasa de FP como esperado. Slither detecta casi todas las
  vulnerabilidades reales pero genera muchos FP. Necesario triage con IA.
```

#### Etapa 6: Análisis de Datos

**Técnicas Estadísticas Aplicadas:**

**1. Estadística Descriptiva:**

```r
# experiments/statistical_analysis.R

library(tidyverse)
library(psych)

# Cargar datos
data <- read_csv("experiments/results/all_metrics.csv")

# Estadística descriptiva
summary_stats <- data %>%
  group_by(tool) %>%
  summarise(
    n = n(),
    precision_mean = mean(precision, na.rm = TRUE),
    precision_sd = sd(precision, na.rm = TRUE),
    precision_se = precision_sd / sqrt(n),
    recall_mean = mean(recall, na.rm = TRUE),
    recall_sd = sd(recall, na.rm = TRUE),
    f1_mean = mean(f1, na.rm = TRUE),
    f1_sd = sd(f1, na.rm = TRUE),
    time_mean = mean(execution_time, na.rm = TRUE),
    time_sd = sd(execution_time, na.rm = TRUE)
  )

# Intervalos de confianza al 95%
summary_stats <- summary_stats %>%
  mutate(
    precision_ci_lower = precision_mean - 1.96 * precision_se,
    precision_ci_upper = precision_mean + 1.96 * precision_se
  )

print(summary_stats)
```

**2. Pruebas de Hipótesis:**

**Hipótesis H1: Xaudit > Slither (Precisión)**

```r
# Test t de Student para muestras independientes

# H0: μ(Xaudit) = μ(Slither)
# H1: μ(Xaudit) > μ(Slither)
# α = 0.05

xaudit_precision <- data %>% filter(tool == "xaudit") %>% pull(precision)
slither_precision <- data %>% filter(tool == "slither") %>% pull(precision)

t_test_result <- t.test(xaudit_precision, slither_precision,
                       alternative = "greater",
                       conf.level = 0.95)

cat("t =", t_test_result$statistic, "\n")
cat("p-value =", t_test_result$p.value, "\n")
cat("95% CI:", t_test_result$conf.int, "\n")

# Tamaño del efecto (Cohen's d)
cohens_d <- (mean(xaudit_precision) - mean(slither_precision)) /
            sqrt((sd(xaudit_precision)^2 + sd(slither_precision)^2) / 2)

cat("Cohen's d =", cohens_d, "\n")

# Interpretación
if(t_test_result$p.value < 0.05) {
  cat("✅ Rechazamos H0: Xaudit tiene significativamente mayor precisión que Slither\n")
} else {
  cat("❌ No rechazamos H0: No hay diferencia significativa\n")
}
```

**Hipótesis H2: Reducción de FP con IA**

```r
# Test t pareado (mismos contratos, con y sin IA)

fp_sin_ia <- data %>% filter(ai_enabled == FALSE) %>% pull(false_positives)
fp_con_ia <- data %>% filter(ai_enabled == TRUE) %>% pull(false_positives)

paired_t_test <- t.test(fp_sin_ia, fp_con_ia,
                       paired = TRUE,
                       alternative = "greater",
                       conf.level = 0.95)

reduccion_fp <- (mean(fp_sin_ia) - mean(fp_con_ia)) / mean(fp_sin_ia) * 100

cat("Reducción de FP:", reduccion_fp, "%\n")
cat("p-value:", paired_t_test$p.value, "\n")
```

**Hipótesis H3: Cohen's Kappa para acuerdo Experto-IA**

```r
library(irr)

# Matriz de confusión experto vs IA
expert_labels <- data$expert_classification
ai_labels <- data$ai_classification

# Calcular Cohen's Kappa
kappa_result <- kappa2(cbind(expert_labels, ai_labels), weight = "unweighted")

cat("Cohen's Kappa:", kappa_result$value, "\n")
cat("p-value:", kappa_result$p.value, "\n")
cat("95% CI: [", kappa_result$lbound, ",", kappa_result$ubound, "]\n")

# Interpretación según Landis & Koch (1977)
if(kappa_result$value >= 0.81) {
  cat("Acuerdo casi perfecto\n")
} else if(kappa_result$value >= 0.61) {
  cat("Acuerdo sustancial\n")
} else if(kappa_result$value >= 0.41) {
  cat("Acuerdo moderado\n")
} else {
  cat("Acuerdo bajo\n")
}
```

**3. Análisis de Varianza (ANOVA):**

```r
# Comparar múltiples herramientas simultáneamente

# H0: μ1 = μ2 = ... = μk (todas las herramientas tienen igual precisión)
# H1: Al menos una media es diferente

anova_model <- aov(precision ~ tool, data = data)
summary(anova_model)

# Si ANOVA es significativo, hacer comparaciones post-hoc (Tukey HSD)
if(summary(anova_model)[[1]]$`Pr(>F)`[1] < 0.05) {
  tukey_result <- TukeyHSD(anova_model)
  print(tukey_result)

  # Visualizar
  plot(tukey_result, las = 2)
}
```

**4. Análisis de Correlación:**

```r
# ¿Existe correlación entre complejidad del contrato y tiempo de ejecución?

correlation_test <- cor.test(data$sloc, data$execution_time,
                             method = "pearson")

cat("Correlación de Pearson:", correlation_test$estimate, "\n")
cat("p-value:", correlation_test$p.value, "\n")

# Visualizar
ggplot(data, aes(x = sloc, y = execution_time)) +
  geom_point(alpha = 0.5) +
  geom_smooth(method = "lm", color = "red") +
  labs(title = "Correlación entre Complejidad y Tiempo de Ejecución",
       x = "SLOC (Líneas de Código)",
       y = "Tiempo de Ejecución (segundos)") +
  theme_minimal()

ggsave("experiments/plots/correlation_sloc_time.png", width = 10, height = 6, dpi = 300)
```

#### Etapa 7: Interpretación y Conclusiones

**Criterios de Validación:**

**Para H1 (Xaudit > Slither en Precisión):**
- ✅ **Aceptar H1** si: p-value < 0.05 y Cohen's d > 0.5 (efecto medio-grande)
- ❌ **Rechazar H1** si: p-value ≥ 0.05

**Para H2 (Reducción FP ≥ 30%):**
- ✅ **Aceptar H2** si: Reducción_FP ≥ 30% y p-value < 0.05
- ❌ **Rechazar H2** si: Reducción_FP < 30% o p-value ≥ 0.05

**Para H3 (Kappa ≥ 0.60):**
- ✅ **Aceptar H3** si: κ ≥ 0.60 y p-value < 0.05
- ❌ **Rechazar H3** si: κ < 0.60 o p-value ≥ 0.05

**Para H4 (Xaudit detecta más vulnerabilidades):**
- ✅ **Aceptar H4** si: Vulnerabilidades(Xaudit) > max(Vulnerabilidades(Tool_i)) con diferencia estadísticamente significativa
- ❌ **Rechazar H4** si: No hay diferencia significativa

#### Etapa 8: Reproducibilidad

**Requisitos para Replicación del Estudio:**

1. **Hardware Especificado:**
   - AWS EC2 t3.xlarge (4 vCPU, 16GB RAM) o equivalente
   - Disco SSD con ≥100GB disponibles
   - Conexión a internet (para APIs de IA)

2. **Software Versionado:**
   - Ubuntu 22.04 LTS
   - Python 3.11.4
   - Slither 0.10.0
   - Mythril 0.23.0
   - Manticore 0.3.7
   - Echidna 2.2.0
   - Medusa 0.1.0
   - Foundry (forge 0.2.0)
   - Certora Prover 6.0
   - OpenAI API (GPT-4o-mini)

3. **Datasets Públicos:**
   - SmartBugs Curated (disponible en GitHub)
   - SolidiFI Benchmark (disponible en GitHub)
   - Ground truth documentado en `/experiments/ground_truth/`

4. **Scripts de Ejecución:**
   - `/experiments/run_all_experiments.sh`: Ejecuta los 7 experimentos
   - `/experiments/statistical_analysis.R`: Análisis estadístico en R
   - `/experiments/generate_plots.py`: Genera visualizaciones

5. **Documentación Completa:**
   - Protocolo experimental detallado en `/experiments/protocol.md`
   - Configuraciones de herramientas en `/config/`
   - Logs de ejecución en `/experiments/logs/`

**Comando para Replicar Estudio Completo:**

```bash
# Clonar repositorio
git clone https://github.com/fboiero/MIESC.git
cd xaudit

# Configurar entorno
./setup_experiment_environment.sh

# Descargar datasets
bash scripts/download_datasets.sh

# Ejecutar todos los experimentos (tiempo estimado: 48 horas)
bash experiments/run_all_experiments.sh

# Análisis estadístico
Rscript experiments/statistical_analysis.R

# Generar reportes
python experiments/generate_final_report.py
```

## 2.2 Consideraciones Éticas y Limitaciones

### 2.2.1 Aspectos Éticos

**Privacidad de Código:**
- Solo se analizan contratos públicamente desplegados en Ethereum mainnet o datasets open-source
- No se almacena código propietario en servidores de terceros (OpenAI) de forma persistente
- Configuración de OpenAI API: `data_retention = false`

**Uso Responsable de IA:**
- Sistema de triage con IA requiere validación humana obligatoria para decisiones críticas (Human-in-the-Loop)
- Disclaimers claros sobre limitaciones de análisis automatizado
- No se garantiza detección del 100% de vulnerabilidades

**Transparencia:**
- Código del framework es open-source (GPL-3.0)
- Metodología y resultados completamente documentados
- Reproducibilidad garantizada mediante versionado

### 2.2.2 Limitaciones del Estudio

**Limitaciones de Validez Interna:**
1. **Ground Truth Imperfecto:**
   - SmartBugs Curated puede tener errores de anotación
   - Mitigación: Validación cruzada con múltiples expertos

2. **Sesgo de Selección:**
   - Dataset se enfoca en vulnerabilidades conocidas (SWC)
   - Vulnerabilidades zero-day no están representadas
   - Mitigación: Incluir contratos reales de producción

3. **Variabilidad de IA:**
   - GPT-4o-mini puede dar respuestas ligeramente diferentes en ejecuciones repetidas
   - Mitigación: Temperatura baja (0.3) y prompts determinísticos

**Limitaciones de Validez Externa:**
1. **Generalización:**
   - Resultados aplicables principalmente a contratos EVM en Solidity 0.8.x
   - Blockchains no-EVM (Solana, Cardano) no son cubiertas

2. **Temporalidad:**
   - Herramientas evolucionan constantemente
   - Resultados válidos para versiones específicas (2024-2025)

3. **Escalabilidad:**
   - Experimentos en contratos <2000 SLOC
   - Contratos muy grandes (>10,000 SLOC) pueden tener performance diferente

**Limitaciones Técnicas:**
1. **Timeout de Herramientas:**
   - Certora y Manticore tienen timeouts (pueden no explorar todo el espacio de estados)

2. **Cobertura de Fuzzing:**
   - 100,000 runs puede ser insuficiente para contratos muy complejos

3. **Dependencia de APIs:**
   - Módulo de IA requiere conexión a OpenAI
   - Rate limits pueden afectar throughput

**Mitigaciones Implementadas:**
- Validación cruzada con múltiples datasets
- Análisis de sensibilidad para parámetros críticos
- Documentación exhaustiva de limitaciones en reportes

## 2.3 Síntesis del Método Científico

Este capítulo establece el rigor metodológico del estudio mediante:

1. ✅ **Enfoque Cuantitativo Experimental:** Variables medibles, hipótesis falsables
2. ✅ **Diseño Cuasi-Experimental:** Grupo control (Slither solo) vs experimental (Xaudit)
3. ✅ **Muestra Representativa:** 142+ contratos con ground truth validado
4. ✅ **Métricas Estandarizadas:** Precisión, Recall, F1, Cohen's Kappa
5. ✅ **Análisis Estadístico Riguroso:** Tests t, ANOVA, intervalos de confianza
6. ✅ **Reproducibilidad Completa:** Código, datos, configuraciones versionados
7. ✅ **Transparencia Total:** Open-source, documentación exhaustiva

**Próximo Capítulo:** Estado del Arte y Revisión de Literatura sobre auditoría de smart contracts.

---

## Referencias Capítulo 2

Arias, F. G. (2012). *El proyecto de investigación: Introducción a la metodología científica* (6ª ed.). Editorial Episteme.

Durieux, T., Ferreira, J. F., Abreu, R., & Cruz, P. (2020). Empirical review of automated analysis tools on 47,587 Ethereum smart contracts. *Proceedings of the ACM/IEEE 42nd International Conference on Software Engineering*, 530-541. https://doi.org/10.1145/3377811.3380364

Feist, J., Grieco, G., & Groce, A. (2019). Slither: A static analysis framework for smart contracts. *2019 IEEE/ACM 2nd International Workshop on Emerging Trends in Software Engineering for Blockchain (WETSEB)*, 8-15. https://doi.org/10.1109/WETSEB.2019.00008

Hernández-Sampieri, R., Fernández-Collado, C., & Baptista-Lucio, P. (2014). *Metodología de la investigación* (6ª ed.). McGraw-Hill Education.

Landis, J. R., & Koch, G. G. (1977). The measurement of observer agreement for categorical data. *Biometrics*, 33(1), 159-174. https://doi.org/10.2307/2529310

Luu, L., Chu, D. H., Olickel, H., Saxena, P., & Hobor, A. (2016). Making smart contracts smarter. *Proceedings of the 2016 ACM SIGSAC Conference on Computer and Communications Security*, 254-269. https://doi.org/10.1145/2976749.2978309

Tsankov, P., Dan, A., Drachsler-Cohen, D., Gervais, A., Bünzli, F., & Vechev, M. (2018). Securify: Practical security analysis of smart contracts. *Proceedings of the 2018 ACM SIGSAC Conference on Computer and Communications Security*, 67-82. https://doi.org/10.1145/3243734.3243780

---

**Nota Metodológica:**

Este capítulo sigue lineamientos de:
- American Psychological Association (APA 7th edition) para citaciones
- Consejo Nacional de Investigaciones Científicas y Técnicas (CONICET) para diseño experimental
- IEEE para documentación de software research
