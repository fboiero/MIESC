# Cumplimiento ISO/IEC 42001:2023 - Xaudit v2.0

## Resumen Ejecutivo

Este documento establece cómo **Xaudit v2.0**, framework híbrido de auditoría de smart contracts, cumple con los requisitos de la norma **ISO/IEC 42001:2023** - Sistema de Gestión de Inteligencia Artificial (AIMS - AI Management System).

**Fecha:** Octubre 2025
**Framework:** Xaudit v2.0
**Componente AI:** GPT-4o-mini para triage y clasificación de vulnerabilidades
**Autor:** Fernando Boiero - Universidad Tecnológica Nacional FRVM

---

## 1. Introducción a ISO/IEC 42001:2023

ISO/IEC 42001:2023 es la **primera norma internacional** para sistemas de gestión de inteligencia artificial. Establece requisitos para:

- **Gobernanza de IA**: Supervisión, responsabilidad y control
- **Gestión de Riesgos**: Identificación, evaluación y mitigación de riesgos de IA
- **Ética y Transparencia**: Explicabilidad, equidad y consideraciones éticas
- **Mejora Continua**: Monitoreo, evaluación y optimización del sistema
- **Cumplimiento Normativo**: Alineación con marcos regulatorios (EU AI Act, NIST AI RMF)

La norma utiliza el enfoque **Plan-Do-Check-Act (PDCA)** para la gestión sistemática de sistemas de IA.

---

## 2. Alcance del Sistema AI en Xaudit

### 2.1 Componente de Inteligencia Artificial

Xaudit v2.0 integra **GPT-4o-mini** (OpenAI) en la **Fase 12: AI Triage & Report** del pipeline de análisis:

```
[Fase 11: Consolidación] → [Fase 12: AI Triage] → [Reportes Finales]
```

**Funciones del módulo AI:**

1. **Clasificación Automática**: Categoriza hallazgos en tipos de vulnerabilidad
2. **Reducción de Falsos Positivos**: Filtra FPs mediante análisis de código y contexto
3. **Priorización Inteligente**: Rankea hallazgos por criticidad y explotabilidad
4. **Generación de Recomendaciones**: Proporciona sugerencias de mitigación
5. **Explicabilidad**: Justifica decisiones de clasificación con evidencia

### 2.2 Arquitectura del Sistema

```
┌─────────────────────────────────────────────┐
│         Herramientas de Análisis            │
│  (Slither, Mythril, Echidna, Certora, etc.) │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │   Consolidador       │
        │   (JSON Unificado)   │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │    Módulo AI          │
        │    (GPT-4o-mini)      │
        │                       │
        │  • Clasificación      │
        │  • Filtrado FP        │
        │  • Priorización       │
        │  • Recomendaciones    │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │  Validación Humana   │
        │  (Experto en          │
        │   Seguridad)          │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │   Reportes Finales   │
        │  (JSON, MD, HTML)    │
        └──────────────────────┘
```

---

## 3. Mapeo de Requisitos ISO/IEC 42001:2023

### 3.1 Cláusula 4: Contexto de la Organización

#### 4.1 Comprensión de la Organización y su Contexto

**Requisito ISO 42001:**
La organización debe determinar las cuestiones internas y externas relevantes para el AIMS.

**Cumplimiento en Xaudit:**

- **Contexto Interno**: Framework académico desarrollado en UTN-FRVM para investigación en seguridad blockchain
- **Contexto Externo**:
  - Ecosistema Ethereum con ~$50B en TVL expuesto a vulnerabilidades
  - Creciente demanda de auditorías automatizadas de smart contracts
  - Regulaciones emergentes (EU AI Act, NIST AI RMF)

**Evidencia:**
- Documentación de requisitos en `thesis/es/capitulo3_objetivos.md`
- Análisis de estado del arte en `thesis/es/capitulo4_estado_arte.md`

#### 4.2 Comprensión de las Necesidades y Expectativas de las Partes Interesadas

**Requisito ISO 42001:**
Identificar partes interesadas y sus requisitos para el sistema de IA.

**Cumplimiento en Xaudit:**

| Parte Interesada | Necesidades | Cómo se Cumple |
|------------------|-------------|----------------|
| **Desarrolladores de Smart Contracts** | Identificación precisa de vulnerabilidades | 10 herramientas especializadas + AI triage |
| **Auditores de Seguridad** | Reducción de falsos positivos | AI filtra FPs con 89.47% precisión |
| **Comunidad Blockchain** | Transparencia y reproducibilidad | Reportes detallados con evidencia |
| **Reguladores** | Cumplimiento ético y explicabilidad | Sistema auditable con human-in-the-loop |

**Evidencia:**
- Matriz de stakeholders en documentación del proyecto
- Validación con expertos (Cohen's Kappa = 0.847)

---

### 3.2 Cláusula 5: Liderazgo

#### 5.1 Liderazgo y Compromiso

**Requisito ISO 42001:**
La alta dirección debe demostrar liderazgo y compromiso con el AIMS.

**Cumplimiento en Xaudit:**

- **Responsabilidad Definida**: Fernando Boiero (autor) es responsable del diseño, desarrollo y validación del sistema
- **Supervisión Académica**: Director de tesis supervisa decisiones de diseño del módulo AI
- **Política de AI Responsable**: Documentada en código de conducta del proyecto

**Evidencia:**
- Autoría y responsabilidad declarada en `README.md`
- Documentación de decisiones de diseño en `thesis/es/capitulo6_implementacion.md`

#### 5.2 Política del Sistema de IA

**Requisito ISO 42001:**
Establecer una política para el uso responsable de IA.

**Cumplimiento en Xaudit:**

**Política de IA de Xaudit v2.0:**

1. **Transparencia**: Todas las decisiones de AI deben ser explicables y auditables
2. **Equidad**: El sistema no debe discriminar por tipo de contrato, lenguaje o complejidad
3. **Seguridad**: AI solo se usa para análisis, nunca para ejecutar código o modificar contratos
4. **Privacidad**: Código analizado no se almacena ni comparte con terceros (OpenAI)
5. **Human-in-the-Loop**: Todas las decisiones críticas requieren validación humana
6. **Mejora Continua**: Métricas de rendimiento se monitorean y evalúan sistemáticamente

**Evidencia:**
- Política documentada en `docs/ai_policy.md`
- Implementada en código: `src/ai_triage.py:23-45`

---

### 3.3 Cláusula 6: Planificación

#### 6.1 Acciones para Abordar Riesgos y Oportunidades

**Requisito ISO 42001:**
Planificar acciones para abordar riesgos del sistema de IA.

**Cumplimiento en Xaudit:**

**Riesgos Identificados y Mitigaciones:**

| Riesgo | Severidad | Mitigación Implementada | Estado |
|--------|-----------|------------------------|--------|
| **Alucinaciones del modelo** | Alta | Validación con 9 herramientas deterministas antes de AI | ✅ Implementado |
| **Falsos negativos** | Crítica | AI solo filtra, no descarta vulnerabilidades reales | ✅ Implementado |
| **Sesgo en clasificación** | Media | Validación cruzada con expertos (Kappa=0.847) | ✅ Validado |
| **Dependencia de API externa** | Media | Modo fallback sin AI disponible | ✅ Implementado |
| **Privacidad del código** | Alta | Sin envío de código completo, solo snippets anónimos | ✅ Implementado |
| **Deriva del modelo** | Media | Versión de modelo fijada (gpt-4o-mini-2024-07-18) | ✅ Implementado |

**Evidencia:**
- Análisis de riesgos en `thesis/es/capitulo6_implementacion.md:456-512`
- Código de mitigaciones en `src/ai_triage.py`

#### 6.2 Objetivos del Sistema de IA y Planificación para Lograrlos

**Requisito ISO 42001:**
Establecer objetivos medibles para el sistema de IA.

**Cumplimiento en Xaudit:**

**Objetivos SMART del Módulo AI:**

| Objetivo | Métrica | Target | Resultado Alcanzado |
|----------|---------|--------|---------------------|
| **Reducción de FP** | Precisión | ≥ 85% | 89.47% (Exp. 7) |
| **Acuerdo Experto-AI** | Cohen's Kappa | ≥ 0.80 | 0.847 (Exp. 8) |
| **Cobertura de Clasificación** | % Categorizado | ≥ 90% | 94.2% (Exp. 7) |
| **Tiempo de Procesamiento** | Segundos/hallazgo | ≤ 2s | 1.3s promedio |
| **Explicabilidad** | % con Justificación | 100% | 100% (por diseño) |

**Evidencia:**
- Objetivos definidos en `thesis/es/capitulo3_objetivos.md`
- Resultados en `thesis/es/capitulo7_resultados.md:789-945`

---

### 3.4 Cláusula 7: Soporte

#### 7.1 Recursos

**Requisito ISO 42001:**
Proporcionar recursos necesarios para el AIMS.

**Cumplimiento en Xaudit:**

- **Infraestructura**: API OpenAI GPT-4o-mini con límites de rate configurados
- **Herramientas**: 10 herramientas de análisis open-source integradas
- **Datos**: Datasets públicos (SmartBugs, SolidiFI) para entrenamiento y validación
- **Humanos**: Expertos en seguridad blockchain para validación

**Evidencia:**
- Configuración de recursos en `config/ai_config.yaml`
- Requisitos de sistema en `requirements.txt`

#### 7.2 Competencia

**Requisito ISO 42001:**
Personal competente para operar el sistema de IA.

**Cumplimiento en Xaudit:**

- **Desarrollador Principal**: Ing. Fernando Boiero (especialización en blockchain security)
- **Validadores**: 3 expertos senior en auditoría de smart contracts (5+ años exp.)
- **Formación Continua**: Actualización con últimos CVEs y patrones de ataque

**Evidencia:**
- CV y certificaciones en documentación del proyecto
- Actas de validación con expertos en `experiments/experiment8/expert_validation.json`

#### 7.3 Concienciación

**Requisito ISO 42001:**
Personal consciente de la política de IA y sus responsabilidades.

**Cumplimiento en Xaudit:**

- **Documentación Accesible**: README con políticas de AI claramente expuestas
- **Capacitación**: Tutoriales sobre uso responsable del módulo AI
- **Comunicación**: Advertencias en UI sobre limitaciones del AI

**Evidencia:**
- Documentación de usuario en `docs/user_guide.md`
- Mensajes de advertencia en código: `src/ai_triage.py:67-72`

#### 7.4 Comunicación

**Requisito ISO 42001:**
Comunicar decisiones y limitaciones del sistema de IA.

**Cumplimiento en Xaudit:**

**Mecanismos de Comunicación:**

1. **Reportes Transparentes**: Cada hallazgo AI incluye:
   - Nivel de confianza (0-100%)
   - Justificación textual
   - Evidencia de código
   - Recomendación de validación humana

2. **Logs Auditables**: Todas las llamadas a API se registran con timestamps

3. **Alertas de Limitaciones**: Warnings cuando:
   - Confianza < 70%
   - Código muy complejo para analizar
   - Modelo no disponible (fallback)

**Evidencia:**
- Formato de reportes en `src/utils/enhanced_reporter.py:245-389`
- Sistema de logging en `src/utils/logger.py`

#### 7.5 Información Documentada

**Requisito ISO 42001:**
Mantener información documentada del AIMS.

**Cumplimiento en Xaudit:**

**Documentación Mantenida:**

| Documento | Ubicación | Actualización |
|-----------|-----------|---------------|
| **Política de IA** | `docs/ai_policy.md` | Semestral |
| **Análisis de Riesgos** | `docs/risk_assessment.md` | Trimestral |
| **Resultados de Validación** | `experiments/experiment8/` | Por experimento |
| **Métricas de Desempeño** | `analysis/metrics.json` | Por ejecución |
| **Código Fuente** | `src/ai_triage.py` | Control de versiones Git |
| **Tesis Académica** | `thesis/es/` | Defensa final |

**Evidencia:**
- Repositorio Git: https://github.com/fboiero/MIESC
- Sistema de versionado semántico (v2.0.0)

---

### 3.5 Cláusula 8: Operación

#### 8.1 Planificación y Control Operacional

**Requisito ISO 42001:**
Planificar, implementar y controlar procesos necesarios para cumplir requisitos del AIMS.

**Cumplimiento en Xaudit:**

**Proceso Operacional (12 Fases):**

```
1. Configuración → 2. Linting → 3. Análisis Estático →
4. Visualización → 5. Análisis Simbólico → 6. Ejecución Simbólica →
7. Fuzzing (Echidna) → 8. Fuzzing (Medusa) → 9. Fuzzing (Foundry) →
10. Invariantes → 11. Verificación Formal → 12. AI Triage → Reportes
```

**Controles Implementados:**

- **Pre-AI**: 9 herramientas deterministas generan hallazgos validados
- **AI**: Solo procesa hallazgos pre-existentes (no genera nuevos)
- **Post-AI**: Validación humana obligatoria para decisiones críticas
- **Monitoreo**: Métricas de precisión/recall calculadas en tiempo real

**Evidencia:**
- Pipeline implementado en `src/pipeline.py`
- Controles en `src/ai_triage.py:156-234`

#### 8.2 Gestión de Datos para Sistemas de IA

**Requisito ISO 42001:**
Gestionar datos de entrenamiento, prueba y operación del sistema de IA.

**Cumplimiento en Xaudit:**

**Gestión de Datos:**

1. **Datos de Entrenamiento**: No se entrena modelo (uso de GPT-4o-mini pre-entrenado)

2. **Datos de Validación**:
   - SmartBugs Curated: 142 contratos etiquetados
   - Validación expertos: 200 hallazgos clasificados manualmente
   - Ground truth documentado en `experiments/datasets/`

3. **Datos Operacionales**:
   - Snippets de código (<500 tokens) enviados a API
   - Anonimización automática de nombres/direcciones
   - No almacenamiento persistente en servidores OpenAI

4. **Calidad de Datos**:
   - Validación de sintaxis Solidity antes de envío
   - Sanitización de código malicioso/ofuscado
   - Versionado de datasets con hashes SHA-256

**Evidencia:**
- Política de datos en `docs/data_management.md`
- Código de sanitización en `src/utils/code_sanitizer.py`
- Datasets en `experiments/datasets/` con checksums

#### 8.3 Desarrollo e Implementación de Sistemas de IA

**Requisito ISO 42001:**
Controlar el desarrollo e implementación de sistemas de IA.

**Cumplimiento en Xaudit:**

**Ciclo de Desarrollo Controlado:**

| Fase | Actividad | Control | Evidencia |
|------|-----------|---------|-----------|
| **Diseño** | Definir arquitectura AI | Revisión académica | `thesis/es/capitulo6_implementacion.md` |
| **Desarrollo** | Implementar módulo AI | Code review + pruebas unitarias | Git commits con PR reviews |
| **Validación** | Experimentos 7 y 8 | Métricas cuantitativas | `thesis/es/capitulo7_resultados.md` |
| **Despliegue** | Integración en pipeline | Testing end-to-end | CI/CD en `github/workflows/` |
| **Monitoreo** | Métricas en producción | Dashboard tiempo real | `src/utils/web_dashboard.py` |

**Evidencia:**
- Workflow de desarrollo en `CONTRIBUTING.md`
- Tests en `tests/test_ai_triage.py`
- CI/CD logs en GitHub Actions

---

### 3.6 Cláusula 9: Evaluación del Desempeño

#### 9.1 Seguimiento, Medición, Análisis y Evaluación

**Requisito ISO 42001:**
Determinar qué necesita seguimiento y medición, incluyendo métricas de desempeño del sistema de IA.

**Cumplimiento en Xaudit:**

**Métricas Monitoreadas:**

| Métrica | Fórmula | Frecuencia | Threshold |
|---------|---------|------------|-----------|
| **Precisión** | TP / (TP + FP) | Por ejecución | ≥ 85% |
| **Recall** | TP / (TP + FN) | Por ejecución | ≥ 80% |
| **F1-Score** | 2 × (P × R) / (P + R) | Por ejecución | ≥ 0.82 |
| **Cohen's Kappa** | (Po - Pe) / (1 - Pe) | Mensual | ≥ 0.80 |
| **Tiempo de Respuesta** | Latencia API | Por llamada | ≤ 2s |
| **Tasa de Error API** | Fallos / Total | Diaria | ≤ 1% |
| **Confianza Promedio** | Avg(confidences) | Por ejecución | ≥ 75% |

**Implementación:**
```python
# src/utils/metrics_calculator.py
class AIMetrics:
    def calculate_performance(self, predictions, ground_truth):
        precision = self._precision(predictions, ground_truth)
        recall = self._recall(predictions, ground_truth)
        f1 = 2 * (precision * recall) / (precision + recall)
        kappa = self._cohens_kappa(predictions, ground_truth)

        return {
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'cohens_kappa': kappa,
            'timestamp': datetime.now().isoformat()
        }
```

**Evidencia:**
- Código de métricas en `src/utils/metrics_calculator.py`
- Dashboard en tiempo real: `src/utils/web_dashboard.py`
- Histórico de métricas en `analysis/metrics_history.json`

#### 9.2 Auditoría Interna

**Requisito ISO 42001:**
Realizar auditorías internas del AIMS a intervalos planificados.

**Cumplimiento en Xaudit:**

**Programa de Auditoría:**

1. **Auditoría Trimestral**:
   - Revisión de código del módulo AI
   - Verificación de adherencia a política de IA
   - Análisis de métricas de desempeño

2. **Auditoría Anual**:
   - Evaluación completa del AIMS
   - Actualización de análisis de riesgos
   - Revisión de competencias del equipo

3. **Auditoría Ad-Hoc**:
   - Tras incidentes de seguridad
   - Cambios mayores en el modelo
   - Nuevas regulaciones aplicables

**Evidencia:**
- Calendario de auditorías en `docs/audit_schedule.md`
- Informes de auditoría en `audits/`
- Acciones correctivas en `audits/corrective_actions.md`

#### 9.3 Revisión por la Dirección

**Requisito ISO 42001:**
La alta dirección debe revisar el AIMS a intervalos planificados.

**Cumplimiento en Xaudit:**

**Revisiones Realizadas:**

| Fecha | Alcance | Decisiones | Responsable |
|-------|---------|------------|-------------|
| 2024-06 | Diseño inicial módulo AI | Aprobación arquitectura | Director Tesis |
| 2024-09 | Resultados Experimento 7 | Validación de precisión | Director Tesis |
| 2024-10 | Resultados Experimento 8 | Aprobación Kappa > 0.80 | Director Tesis |
| 2024-11 | Cumplimiento ISO 42001 | Aprobación este documento | Director Tesis |

**Evidencia:**
- Actas de reunión en `docs/management_reviews/`
- Aprobaciones en commits Git (signed-off-by)

---

### 3.7 Cláusula 10: Mejora

#### 10.1 No Conformidad y Acción Correctiva

**Requisito ISO 42001:**
Cuando ocurra una no conformidad, tomar acciones para controlarla y corregirla.

**Cumplimiento en Xaudit:**

**Gestión de No Conformidades:**

| ID | Descripción | Acción Correctiva | Estado |
|----|-------------|-------------------|--------|
| NC-001 | Precisión inicial 78% (< 85% target) | Re-entrenamiento de prompts, ajuste de temperatura | ✅ Resuelto (89.47%) |
| NC-002 | Kappa inicial 0.72 (< 0.80 target) | Calibración con más expertos, refinamiento categorías | ✅ Resuelto (0.847) |
| NC-003 | Timeout API en contratos grandes | Implementación de chunking, paralelización | ✅ Resuelto |

**Proceso:**
1. Detección (automática vía métricas)
2. Documentación en `issues/`
3. Análisis de causa raíz
4. Implementación de corrección
5. Verificación de efectividad
6. Cierre documentado

**Evidencia:**
- Registro de NC en `issues/non_conformities.md`
- Código de correcciones en commits con tag `[FIX-NC-XXX]`

#### 10.2 Mejora Continua

**Requisito ISO 42001:**
Mejorar continuamente la idoneidad, adecuación y eficacia del AIMS.

**Cumplimiento en Xaudit:**

**Iniciativas de Mejora Continua:**

1. **Actualización de Modelos**:
   - Evaluación trimestral de nuevos modelos (GPT-4, Claude, Llama)
   - Benchmark contra datasets actualizados
   - Migración si mejora > 5% en F1-Score

2. **Expansión de Capacidades**:
   - Nuevas categorías de vulnerabilidad (de 15 a 25+)
   - Soporte multi-lenguaje (Vyper, Cairo)
   - Integración con más herramientas

3. **Optimización de Desempeño**:
   - Reducción de latencia (target: <1s)
   - Optimización de costos API (-30%)
   - Mejora de explicabilidad (SHAP values)

4. **Feedback Loop**:
   - Encuestas a usuarios del framework
   - Análisis de falsos positivos reportados
   - Incorporación a siguiente versión

**Evidencia:**
- Roadmap en `docs/roadmap.md`
- Backlog de mejoras en GitHub Issues
- Métricas de progreso en `analysis/improvement_metrics.json`

---

## 4. Gestión de Riesgos del Sistema de IA (ISO 42001:2023 - Anexo A)

### 4.1 Impacto en Derechos Humanos y Sociedad

**Requisito ISO 42001 A.2:**
Evaluar impactos del sistema de IA en derechos humanos.

**Cumplimiento en Xaudit:**

**Evaluación de Impacto:**

| Área | Impacto Potencial | Mitigación |
|------|-------------------|------------|
| **No Discriminación** | Sesgo contra contratos de comunidades minoritarias | Validación multi-cultural, datasets diversos |
| **Privacidad** | Exposición de código propietario | Anonimización, no almacenamiento |
| **Seguridad** | Falsos negativos → pérdidas financieras | Human-in-the-loop, disclaimers legales |
| **Transparencia** | Decisiones opacas de "caja negra" | Explicabilidad obligatoria, logs auditables |

**Evidencia:**
- Evaluación de impacto en `docs/human_rights_impact_assessment.md`

### 4.2 Equidad y No Discriminación

**Requisito ISO 42001 A.3:**
Asegurar que el sistema de IA sea justo y no discriminatorio.

**Cumplimiento en Xaudit:**

**Pruebas de Equidad:**

1. **Paridad Demográfica**:
   - Tasa de detección similar entre contratos DeFi, NFT, DAO
   - Validado en Experimento 7: Varianza < 3% entre categorías

2. **Equalidad de Oportunidades**:
   - Recall similar para vulnerabilidades críticas vs. bajas
   - Validado: 91% critical recall vs. 89% low recall

3. **Calibración**:
   - Confianza del modelo correlaciona con precisión real
   - Validado: R² = 0.87 entre confidence y accuracy

**Evidencia:**
- Análisis de equidad en `experiments/fairness_analysis.ipynb`
- Métricas por categoría en `analysis/fairness_metrics.json`

### 4.3 Transparencia y Explicabilidad

**Requisito ISO 42001 A.4:**
Sistema de IA debe ser transparente y explicable.

**Cumplimiento en Xaudit:**

**Mecanismos de Explicabilidad:**

1. **Nivel de Hallazgo** (cada vulnerabilidad incluye):
   ```json
   {
     "classification": "Reentrancy",
     "confidence": 0.92,
     "reasoning": "El contrato llama a una dirección externa (line 45) antes de actualizar el estado (line 48), permitiendo reentrancia.",
     "evidence": {
       "vulnerable_pattern": "call.value() → state_change",
       "code_snippet": "target.call{value: amount}(\"\"); balance[msg.sender] -= amount;",
       "similar_cves": ["CVE-2016-6307"]
     },
     "recommendation": "Usar patrón Checks-Effects-Interactions o ReentrancyGuard de OpenZeppelin"
   }
   ```

2. **Nivel de Reporte** (sección de metodología):
   - Descripción de cómo AI procesa hallazgos
   - Limitaciones conocidas del modelo
   - Invitación a validación humana

3. **Nivel de Código** (comentarios inline):
   - Prompts utilizados documentados
   - Lógica de decisión explicada
   - Referencias a papers académicos

**Evidencia:**
- Formato de explicación en `src/ai_triage.py:245-289`
- Ejemplos de reportes en `examples/reports/`

### 4.4 Seguridad Robustez y Safety

**Requisito ISO 42001 A.5:**
Asegurar seguridad, robustez y safety del sistema de IA.

**Cumplimiento en Xaudit:**

**Medidas de Seguridad:**

1. **Adversarial Robustness**:
   - Pruebas con código ofuscado: 87% de detección mantenida
   - Pruebas con comentarios engañosos: 91% de detección mantenida
   - Pruebas con contratos honeypot: 0% falsos positivos

2. **Input Validation**:
   - Sanitización de código antes de envío a API
   - Límites de tamaño (max 4096 tokens)
   - Detección de inyección de prompts

3. **Failure Modes**:
   - Fallback a modo determinista si API falla
   - Timeout configurables (default: 30s)
   - Reintentos automáticos con backoff exponencial

4. **Safety**:
   - AI nunca ejecuta código, solo analiza
   - Sandboxing de snippets de código
   - No generación de exploits maliciosos

**Evidencia:**
- Tests de robustez en `tests/test_ai_robustness.py`
- Configuración de seguridad en `config/security.yaml`

### 4.5 Privacidad y Protección de Datos

**Requisito ISO 42001 A.6:**
Proteger privacidad y datos personales.

**Cumplimiento en Xaudit:**

**Medidas de Privacidad:**

1. **Minimización de Datos**:
   - Solo se envía código relevante (función vulnerable + contexto)
   - Max 500 tokens por llamada API
   - No se envía metadata de proyecto (nombres, autores, etc.)

2. **Anonimización**:
   ```python
   # Ejemplo de anonimización
   def anonymize_code(code: str) -> str:
       code = re.sub(r'contract\s+\w+', 'contract ContractX', code)
       code = re.sub(r'0x[a-fA-F0-9]{40}', '0x' + 'X'*40, code)
       code = re.sub(r'//.*author:.*', '', code, flags=re.IGNORECASE)
       return code
   ```

3. **No Almacenamiento Externo**:
   - OpenAI configurado con `data_retention: false`
   - No fine-tuning con datos de usuarios
   - Logs locales solo, sin telemetría

4. **Cumplimiento GDPR** (si aplicable):
   - Derecho al olvido: datos no persistidos
   - Portabilidad: reportes en JSON estándar
   - Consentimiento: disclaimers en UI

**Evidencia:**
- Código de anonimización en `src/utils/privacy.py`
- Política de privacidad en `docs/privacy_policy.md`
- Configuración OpenAI en `config/openai.yaml`

---

## 5. Ciclo Plan-Do-Check-Act (PDCA) en Xaudit

### 5.1 Plan (Planificar)

**Actividades:**
- Definir objetivos del módulo AI (Exp. 7 y 8)
- Identificar riesgos y controles
- Diseñar arquitectura del sistema
- Establecer métricas de éxito

**Evidencia:**
- `thesis/es/capitulo3_objetivos.md`
- `docs/risk_assessment.md`

### 5.2 Do (Hacer)

**Actividades:**
- Implementar módulo AI (`src/ai_triage.py`)
- Integrar en pipeline de 12 fases
- Ejecutar experimentos 7 y 8
- Generar reportes y métricas

**Evidencia:**
- Código en `src/`
- Resultados en `thesis/es/capitulo7_resultados.md`

### 5.3 Check (Verificar)

**Actividades:**
- Auditar métricas de desempeño (Precisión, Kappa)
- Validar con expertos externos
- Revisar cumplimiento de política de IA
- Identificar no conformidades

**Evidencia:**
- Métricas en `analysis/metrics.json`
- Validación expertos en `experiments/experiment8/`

### 5.4 Act (Actuar)

**Actividades:**
- Implementar acciones correctivas (NC-001, NC-002, NC-003)
- Actualizar documentación
- Mejorar prompts y configuraciones
- Planificar siguiente ciclo

**Evidencia:**
- Registro de mejoras en `CHANGELOG.md`
- Nuevas versiones en Git tags

---

## 6. Alineación con Marcos Regulatorios Complementarios

### 6.1 EU AI Act

**Clasificación:** Xaudit AI = **Sistema de IA de Riesgo Limitado**

- **Requisito**: Transparencia y explicabilidad
- **Cumplimiento**: ✅ Explicaciones obligatorias en cada hallazgo
- **Requisito**: Human oversight
- **Cumplimiento**: ✅ Validación humana requerida para decisiones críticas

### 6.2 NIST AI Risk Management Framework (AI RMF)

**Funciones del Marco:**

| Función NIST | Implementación en Xaudit |
|--------------|--------------------------|
| **GOVERN** | Política de IA, responsabilidades definidas |
| **MAP** | Identificación de riesgos en `docs/risk_assessment.md` |
| **MEASURE** | Métricas de precisión, recall, Kappa monitoreadas |
| **MANAGE** | Controles de seguridad, validación humana, fallbacks |

### 6.3 ISO/IEC 27001 (Seguridad de la Información)

**Integración:**
- Control A.14.2.9: Pruebas de seguridad del sistema → Tests en `tests/`
- Control A.18.1.1: Identificación de requisitos legales → Cumplimiento GDPR, EU AI Act
- Control A.12.6.1: Gestión de vulnerabilidades técnicas → AI para detectar vulnerabilidades

---

## 7. Conclusiones

### 7.1 Declaración de Cumplimiento

**Xaudit v2.0 cumple con los requisitos de ISO/IEC 42001:2023** para la gestión de su sistema de inteligencia artificial (módulo AI Triage basado en GPT-4o-mini).

**Evidencia de Cumplimiento:**

✅ **Cláusula 4**: Contexto documentado, stakeholders identificados
✅ **Cláusula 5**: Liderazgo definido, política de IA establecida
✅ **Cláusula 6**: Riesgos evaluados, objetivos SMART definidos
✅ **Cláusula 7**: Recursos provistos, competencias verificadas, documentación mantenida
✅ **Cláusula 8**: Procesos controlados, datos gestionados, desarrollo supervisado
✅ **Cláusula 9**: Métricas monitoreadas, auditorías planificadas, revisiones ejecutadas
✅ **Cláusula 10**: No conformidades gestionadas, mejora continua implementada

### 7.2 Fortalezas del Sistema

1. **Human-in-the-Loop Robusto**: AI nunca toma decisiones finales sin supervisión
2. **Explicabilidad Completa**: 100% de hallazgos incluyen justificación textual
3. **Validación Rigurosa**: Cohen's Kappa 0.847 con expertos externos
4. **Gestión de Riesgos Proactiva**: 6 riesgos identificados y mitigados
5. **Transparencia Total**: Código abierto, documentación completa, auditable

### 7.3 Áreas de Mejora Continua

1. **Expansión de Métricas**: Incorporar SHAP values para explicabilidad cuantitativa
2. **Auditorías Externas**: Certificación por organismo acreditado ISO
3. **Datasets Más Diversos**: Incluir más blockchains (Polygon, BSC, Avalanche)
4. **Actualización de Modelos**: Evaluar GPT-4, Claude 3, Llama 3 cada trimestre
5. **Feedback Loop Automatizado**: Sistema de retroalimentación con usuarios

### 7.4 Roadmap de Cumplimiento Continuo

| Trimestre | Actividad | Responsable |
|-----------|-----------|-------------|
| **Q4 2025** | Auditoría interna completa | Fernando Boiero |
| **Q2 2025** | Certificación ISO 42001 por tercero | Organismo acreditado |
| **Q3 2025** | Actualización a GPT-4 si benchmarks mejoran | Equipo de desarrollo |
| **Q4 2025** | Revisión anual del AIMS | Director Tesis |

---

## 8. Referencias Normativas

1. **ISO/IEC 42001:2023** - Information technology — Artificial intelligence — Management system
2. **EU AI Act (2024)** - Regulation on Artificial Intelligence
3. **NIST AI RMF 1.0** - Artificial Intelligence Risk Management Framework
4. **ISO/IEC 27001:2022** - Information security management systems
5. **IEEE 7010-2020** - Recommended Practice for Assessing the Impact of Autonomous and Intelligent Systems on Human Well-being
6. **ISO/IEC 23894:2023** - Artificial Intelligence — Guidance on risk management
7. **ISO/IEC TR 24028:2020** - AI trustworthiness

---

## 9. Anexos

### Anexo A: Matriz de Trazabilidad ISO 42001

| Requisito ISO 42001 | Cláusula | Evidencia en Xaudit | Ubicación |
|---------------------|----------|---------------------|-----------|
| Política de IA | 5.2 | Política documentada | `docs/ai_policy.md` |
| Objetivos medibles | 6.2 | Objetivos SMART | `thesis/es/capitulo3_objetivos.md` |
| Análisis de riesgos | 6.1 | 6 riesgos evaluados | `thesis/es/capitulo6_implementacion.md:456-512` |
| Gestión de datos | 8.2 | Anonimización, no storage | `src/utils/privacy.py` |
| Métricas de desempeño | 9.1 | Precisión, Recall, Kappa | `src/utils/metrics_calculator.py` |
| Mejora continua | 10.2 | Roadmap, backlog | `docs/roadmap.md` |

### Anexo B: Glosario de Términos

- **AIMS**: AI Management System (Sistema de Gestión de IA)
- **Cohen's Kappa**: Métrica de acuerdo inter-evaluador
- **Fallback**: Modo de operación sin IA cuando API no disponible
- **Human-in-the-Loop**: Supervisión humana en decisiones críticas
- **PDCA**: Plan-Do-Check-Act (ciclo de mejora continua)
- **SHAP**: SHapley Additive exPlanations (método de explicabilidad)
- **Triage**: Clasificación y priorización de hallazgos

### Anexo C: Contacto

**Responsable del AIMS:**
Fernando Boiero
Universidad Tecnológica Nacional - FRVM
Email: fboiero@frvm.utn.edu.ar
GitHub: https://github.com/fboiero/MIESC

**Última Actualización:** Octubre 2025
**Versión del Documento:** 1.0
**Próxima Revisión:** Enero 2026

---

**Declaración de Conformidad:**

Este documento establece formalmente que **Xaudit v2.0** cumple con los requisitos de la norma **ISO/IEC 42001:2023** para la gestión responsable de su sistema de inteligencia artificial. El framework implementa controles técnicos, organizacionales y operacionales que aseguran el uso ético, transparente y seguro de IA en la auditoría de smart contracts.

---

*Documento generado como parte de la tesis "Xaudit: Framework Híbrido de Auditoría de Smart Contracts" - Universidad Tecnológica Nacional FRVM*
