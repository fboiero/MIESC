# TESIS DE MAESTRÍA EN CIBERDEFENSA

## DESARROLLO DE UN MARCO DE TRABAJO PARA LA EVALUACIÓN DE SEGURIDAD EN CONTRATOS INTELIGENTES SOBRE LA MÁQUINA VIRTUAL DE ETHEREUM UTILIZANDO INTELIGENCIA ARTIFICIAL

**Universidad de la Defensa Nacional (UNDEF)**
**Centro Regional Universitario Córdoba - IUA**
**Maestría en Ciberdefensa**
**Autor:** Fernando Boiero
**Año:** 2025

---

## ÍNDICE GENERAL

### CAPÍTULOS PRINCIPALES

1. **[INTRODUCCIÓN](./capitulo1_introduccion.md)**
   - 1.1 Contexto General
   - 1.2 Problemática Actual
   - 1.3 Hipótesis de Investigación
   - 1.4 Objetivos
   - 1.5 Alcance
   - 1.6 Justificación
   - 1.7 Estructura del Documento

2. **[MARCO DE CIBERDEFENSA](./capitulo2_ciberdefensa.md)**
   - 2.1 Ciberdefensa en Entornos Descentralizados
   - 2.2 Referenciales Normativos (ISO/IEC 27001, 42001, NIST, OWASP)
   - 2.3 Estrategias de Defensa en Profundidad
   - 2.4 Consideraciones Éticas y Regulatorias
   - 2.5 Alineación con Estrategias Nacionales

3. **[MARCO TEÓRICO TÉCNICO](./capitulo3_marco_teorico.md)**
   - 3.1 Arquitectura de la EVM
   - 3.2 Evolución de Estándares ERC
   - 3.3 Patrones de Seguridad y Vulnerabilidades
   - 3.4 Frameworks de Auditoría
   - 3.5 Clasificación SWC y CWE

4. **[ESTADO DEL ARTE EN HERRAMIENTAS](./capitulo4_estado_arte.md)**
   - 4.1 Análisis Estático (Slither)
   - 4.2 Fuzzing (Echidna, Medusa)
   - 4.3 Testing Avanzado (Foundry)
   - 4.4 Runtime Verification (Scribble)
   - 4.5 Verificación Formal (Certora)
   - 4.6 Comparativa y Limitaciones

5. **[METODOLOGÍA PROPUESTA - XAUDIT](./capitulo5_metodologia.md)**
   - 5.1 Descripción General del Framework
   - 5.2 Pipeline Híbrido de Análisis
   - 5.3 Arquitectura del Sistema
   - 5.4 Módulo de Inteligencia Artificial
   - 5.5 Integración CI/CD
   - 5.6 Formato de Reportes

6. **[IMPLEMENTACIÓN Y EXPERIMENTOS](./capitulo6_implementacion.md)**
   - 6.1 Entorno Experimental
   - 6.2 Dataset de Contratos
   - 6.3 Configuración de Herramientas
   - 6.4 Ejecución del Pipeline
   - 6.5 Métricas de Evaluación
   - 6.6 Diseño Experimental

7. **[RESULTADOS Y ANÁLISIS](./capitulo7_resultados.md)**
   - 7.1 Resultados del Experimento 1: Slither
   - 7.2 Resultados del Experimento 2: Fuzzing Comparativo
   - 7.3 Resultados del Experimento 3: Pipeline Híbrido
   - 7.4 Resultados del Experimento 4: Impacto de IA
   - 7.5 Resultados del Experimento 5: Certora
   - 7.6 Resultados del Experimento 6: Casos Reales
   - 7.7 Análisis de Casos Críticos
   - 7.8 Validación de Hipótesis

8. **[CONCLUSIONES Y TRABAJO FUTURO](./capitulo8_conclusiones.md)**
   - 8.1 Evaluación de la Hipótesis Principal
   - 8.2 Logro de Objetivos
   - 8.3 Contribuciones de la Investigación
   - 8.4 Limitaciones del Modelo
   - 8.5 Trabajo Futuro
   - 8.6 Impacto en Ciberdefensa

### ANEXOS

- **[ANEXO A - Contratos Analizados](./anexo_a_contratos.md)**
  - Código fuente completo de contratos vulnerables
  - Clasificación por tipo de vulnerabilidad (SWC)
  - Exploits sintéticos

- **[ANEXO B - Configuración CI/CD](./anexo_b_cicd.md)**
  - GitHub Actions workflows
  - Scripts de automatización
  - Configuración de runners

- **[ANEXO C - Propiedades y Scripts](./anexo_c_propiedades.md)**
  - Anotaciones Scribble
  - Propiedades Echidna
  - Especificaciones Certora (CVL)

- **[ANEXO D - Resultados Experimentales](./anexo_d_datos.md)**
  - Tablas de resultados completos
  - Datos crudos (JSON/CSV)
  - Gráficos y visualizaciones

- **[ANEXO E - Código Fuente del Módulo IA](./anexo_e_codigo_ia.md)**
  - Implementación completa del asistente de IA
  - Prompts utilizados
  - Estrategias de clasificación

---

## RESUMEN EJECUTIVO

Esta tesis desarrolla **Xaudit**, un framework automatizado para la evaluación de seguridad de contratos inteligentes sobre la Máquina Virtual de Ethereum (EVM). La investigación integra técnicas de análisis estático (Slither), fuzzing property-based (Echidna) y coverage-guided (Medusa), testing diferencial (Foundry), verificación formal (Certora) e inteligencia artificial para triage y clasificación de vulnerabilidades.

### Problemática
Las auditorías manuales de smart contracts son costosas (USD $50,000-$500,000), lentas (4-8 semanas) y propensas a errores humanos. Las herramientas individuales generan altos volúmenes de falsos positivos (>50%) sin priorización contextual.

### Hipótesis
Un pipeline híbrido que combine múltiples técnicas de análisis con asistencia de IA mejora significativamente la detección de vulnerabilidades críticas (+30%), reduce falsos positivos (-40%) y disminuye el tiempo de análisis (-95%) respecto a métodos tradicionales.

### Metodología
- **Paradigma:** Experimental cuantitativo
- **Dataset:** 30+ contratos vulnerables diseñados ad-hoc + 20 casos reales
- **Métricas:** Precision, Recall, F1-Score, tiempo de análisis, cobertura
- **Referenciales:** ISO/IEC 27001:2022, ISO/IEC 42001:2023, NIST SSDF, OWASP SCSVS

### Resultados Principales
1. **Detección mejorada:** Pipeline híbrido detecta 34% más vulnerabilidades que Slither individual
2. **Reducción de FP:** IA reduce falsos positivos en 43% mediante clasificación contextual
3. **Eficiencia temporal:** Análisis completo en <2 horas vs. 4-8 semanas manual
4. **Cobertura:** 94.7% de cobertura de código mediante fuzzing coverage-guided
5. **Open-source:** Framework publicado para uso académico e industrial

### Contribuciones
1. **Científica:** Primera integración completa de análisis estático, dinámico, formal e IA para EVM
2. **Práctica:** Reducción de costos de auditoría preliminar en >90%
3. **Educativa:** Material didáctico para enseñanza de seguridad en smart contracts
4. **Estratégica:** Herramienta para protección de infraestructura crítica blockchain

---

## PALABRAS CLAVE

Smart Contracts, Ethereum, EVM, Ciberdefensa, Seguridad, Auditoría, Análisis Estático, Fuzzing, Verificación Formal, Inteligencia Artificial, Slither, Echidna, Medusa, Foundry, Certora, DevSecOps, ISO 27001, ISO 42001, NIST SSDF, DeFi

---

## ALINEACIÓN CON MAESTRÍA EN CIBERDEFENSA

Esta investigación se alinea con los ejes temáticos de la Maestría en Ciberdefensa de UNDEF - IUA Córdoba:

1. **Seguridad de Sistemas:** Análisis de vulnerabilidades en sistemas descentralizados
2. **Criptografía Aplicada:** Fundamentos criptográficos de blockchain y smart contracts
3. **Gestión de Riesgos:** Framework de evaluación y priorización de riesgos
4. **Normativas y Regulaciones:** Alineación con ISO 27001, ISO 42001, NIST
5. **Investigación Aplicada:** Desarrollo de herramienta open-source con validación experimental

---

## ESTADO DE COMPLETITUD

| Capítulo | Estado | Progreso |
|----------|--------|----------|
| Capítulo 1 - Introducción | ✅ Completo | 100% |
| Capítulo 2 - Marco de Ciberdefensa | ✅ Completo | 100% |
| Capítulo 3 - Marco Teórico | ✅ Completo | 100% |
| Capítulo 4 - Estado del Arte | ✅ Completo | 100% |
| Capítulo 5 - Metodología | ✅ Completo | 100% |
| Capítulo 6 - Implementación | ✅ Completo | 100% |
| Capítulo 7 - Resultados | ✅ Completo | 100% |
| Capítulo 8 - Conclusiones | ✅ Completo | 100% |
| **TOTAL** | **✅ COMPLETO** | **100%** |

---

**Universidad de la Defensa Nacional (UNDEF)**
**Centro Regional Universitario Córdoba - IUA**
**Maestría en Ciberdefensa**
**2025**
