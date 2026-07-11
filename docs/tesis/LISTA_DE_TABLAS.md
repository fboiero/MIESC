# Lista de Tablas

> Este índice refleja las tablas efectivamente presentes en el cuerpo de la tesis
> (37 tablas). Los números de página son estimados sobre el documento fuente y se
> regeneran automáticamente en la compilación final a PDF.

---

## Capítulo 1: Introducción

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| 1.1 | Incidentes históricos críticos en smart contracts | Exploits mayores con año, protocolo, pérdidas en USD y tipo de vulnerabilidad | 12 |

---

## Capítulo 2: Marco Teórico

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| 2.1 | Funciones del Marco NIST de Ciberseguridad | Identificar, Proteger, Detectar, Responder, Recuperar aplicadas al dominio | 25 |
| 2.2 | Propiedades de blockchain desde perspectiva de ciberdefensa | Inmutabilidad, transparencia, descentralización y sus implicancias de seguridad | 28 |
| 2.3 | Categorías SWC críticas para ciberdefensa | SWC-ID priorizados por severidad e impacto en infraestructura | 34 |
| 2.4 | Mapeo SWC a CWE | Correspondencia entre debilidades SWC y el catálogo CWE | 38 |
| 2.5 | Tipos de fuzzing en smart contracts | Property-based, coverage-guided y sus casos de aplicación | 42 |
| 2.6 | Comparación de técnicas de verificación | Estático, simbólico, fuzzing y formal: soundness, completeness, escalabilidad | 46 |

---

## Capítulo 3: Estado del Arte

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| 3.1 | Incidentes de seguridad históricos en contratos inteligentes | Incidentes documentados con pérdida, vulnerabilidad y referencia | 65 |
| 3.2 | Distribución de vulnerabilidades en contratos Ethereum (Zhou et al., 2023) | Frecuencia por SWC-ID sobre 47.587 contratos desplegados | 68 |
| 3.3 | Comparativa de herramientas según Durieux et al. (2020) | Recall por herramienta individual sobre corpus estandarizado | 74 |
| 3.4 | Brechas identificadas y soluciones de MIESC | Gaps del estado del arte y la solución implementada por MIESC | 96 |

---

## Capítulo 4: Desarrollo e Implementación

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| 4.1 | Métricas cuantitativas del proyecto MIESC v4.0.0 | LOC, complejidad, mantenibilidad, cobertura, herramientas y capas | 99 |
| 4.2 | Análisis de complementariedad de técnicas por tipo de vulnerabilidad | Qué técnica detecta cada clase de vulnerabilidad | 112 |
| 4.3 | Extracto del mapeo de clasificaciones nativas a estándares | Traducción de hallazgos de herramientas a SWC/CWE/OWASP | 128 |
| 4.4 | Resultados del análisis de VulnerableBank por capa | Detección por capa sobre el contrato de ejemplo | 140 |
| 4.5 | Interfaces de MIESC y sus casos de uso | CLI, API REST, MCP y sus escenarios de uso | 158 |

---

## Capítulo 5: Resultados Experimentales

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| 5.1 | Especificaciones del ambiente de pruebas | Hardware (CPU, RAM, GPU), software (OS, Python, Solidity) y configuración | 165 |
| 5.2 | Corpus de contratos de prueba | Contratos con nombre, LOC, complejidad y vulnerabilidades conocidas | 168 |
| 5.3 | Estado de disponibilidad de herramientas integradas | Herramientas con estado (OK/Parcial/Error) y notas de compatibilidad | 172 |
| 5.4 | Problemas de integración y soluciones implementadas | Problemas encontrados con descripción, impacto y solución aplicada | 176 |
| 5.5 | Corpus de prueba (`data/audit/`) | Contratos del corpus real con 29 vulnerabilidades documentadas | 180 |
| 5.6 | Detección de MIESC (configuración estático + patrón, capas 1/6/7) | Hallazgos por contrato en la configuración estático + patrón | 182 |
| 5.7 | MIESC vs Slither sobre el corpus real (29 vulnerabilidades) | Comparativa de detección type-aware MIESC frente a Slither | 185 |
| 5.8 | Detección type-aware por modelo y ensemble (unión) | Recall type-aware por modelo LLM y ensemble por unión | 188 |
| 5.9 | Análisis de hallazgos duplicados | Estadísticas de deduplicación: total raw, únicos, tasa de reducción | 196 |
| 5.10 | Validación de mapeo taxonómico | Accuracy del mapeo automático SWC→CWE validado manualmente | 198 |
| 5.11 | Tiempos de ejecución por capa (promedio de 10 ejecuciones) | Media, mediana, p95 y máximo para cada capa en segundos | 202 |
| 5.12 | Consumo de recursos durante auditoría completa | CPU%, RAM (GB), GPU% por fase de análisis | 205 |
| 5.13 | Comparativa de costo operativo | TCO mensual/anual para configuraciones: local, cloud, híbrida | 208 |

---

## Capítulo 6: Justificación del Uso de IA y LLMs Soberanos

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| 6.1 | Valor en riesgo por tipo de contrato | Clasificación por tipo de protocolo (DeFi, NFT, DAO) y TVL promedio | 215 |
| 6.2 | Estructura de costos de APIs comerciales (noviembre 2024) | Costo input/output y por auditoría de proveedores frontier | 219 |
| 6.2b | Niveles de apertura de modelos y su desempeño medido en EVMBench | Tres niveles (frontier, open-weight hosteado, open-weight local) con recall, precisión, F1 y costo | 221 |
| 6.3 | Modelos soportados por MIESC | Modelos locales y open-weight con parámetros, VRAM y licencia | 224 |
| 6.4 | Comparativa de capacidades para análisis de código | Capacidades frontier vs local por dimensión | 232 |
| 6.5 | Herramientas LLM en MIESC | SmartLLM, ThreatModel, GPTScan: modelo base, backend, capacidades | 236 |

---

## Capítulo 7: Justificación del Model Context Protocol (MCP)

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| 7.1 | Comparación de flujos de trabajo | Auditoría manual vs integrada por MCP: pasos, tiempo y errores potenciales | 245 |

---

## Capítulo 8: Conclusiones y Trabajos Futuros

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| 8.1 | Evaluación del cumplimiento de objetivos | Objetivos con indicador de cumplimiento, evidencia y referencia | 275 |

---

**Total de tablas:** 37
