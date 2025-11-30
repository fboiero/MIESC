# Lista de Tablas

---

## Capítulo 1: Introducción

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| 1.1 | Incidentes históricos críticos en smart contracts (2016-2024) | Resumen de 15 exploits mayores con fecha, protocolo afectado, pérdidas en USD y tipo de vulnerabilidad | 12 |
| 1.2 | Preguntas de investigación y objetivos asociados | Mapeo de RQ1-RQ5 a objetivos específicos y métodos de validación | 18 |
| 1.3 | Estructura del documento y contribuciones por capítulo | Desglose de cada capítulo con contribución principal y páginas estimadas | 21 |

---

## Capítulo 2: Marco Teórico

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| 2.1 | Definiciones de ciberdefensa según organismos internacionales | Comparativa NATO, NIST, ENISA, UNDEF con elementos comunes y diferencias | 25 |
| 2.2 | Clasificación de infraestructuras críticas que utilizan blockchain | Sectores (financiero, energético, salud, gobierno) con ejemplos y nivel de adopción | 28 |
| 2.3 | Taxonomía de actores de amenaza en el ecosistema blockchain | Categorías (hackers, estados-nación, insiders, competidores) con motivaciones y capacidades | 31 |
| 2.4 | Opcodes de la EVM relevantes para seguridad | Lista de opcodes críticos (CALL, DELEGATECALL, SELFDESTRUCT, etc.) con riesgos asociados | 35 |
| 2.5 | Categorías de vulnerabilidades según SWC Registry (v1.0) | 37 categorías con ID, nombre, descripción breve y severidad típica | 38 |
| 2.6 | Mapeo completo SWC a CWE para vulnerabilidades de smart contracts | Tabla de correspondencia con 33 mapeos validados | 41 |
| 2.7 | OWASP Smart Contract Top 10 (2023) | 10 categorías con descripción, impacto y ejemplos de mitigación | 44 |
| 2.8 | Comparativa de técnicas de análisis de seguridad | Matriz: técnica vs características (soundness, completeness, escalabilidad, automatización) | 52 |
| 2.9 | Limitaciones teóricas de cada técnica de análisis | Trade-offs fundamentales: falsos positivos vs negativos, cobertura vs tiempo | 55 |
| 2.10 | Patrones de diseño aplicables a frameworks de seguridad | 8 patrones GoF relevantes con aplicación en MIESC | 58 |
| 2.11 | Principios SOLID y su implementación en MIESC | Mapeo de cada principio a componentes específicos del framework | 60 |

---

## Capítulo 3: Estado del Arte

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| 3.1 | Cronología de incidentes de seguridad en smart contracts | 20 incidentes principales ordenados cronológicamente con análisis de causa raíz | 65 |
| 3.2 | Distribución de vulnerabilidades en contratos Ethereum (2023) | Estadísticas de frecuencia basadas en dataset de 47,587 contratos (Durieux et al.) | 68 |
| 3.3 | Comparativa de herramientas de análisis estático | Slither, Solhint, Securify, SmartCheck: características, precisión, velocidad | 72 |
| 3.4 | Comparativa de herramientas de fuzzing | Echidna, Medusa, Harvey, ContractFuzzer: estrategias, cobertura, limitaciones | 78 |
| 3.5 | Comparativa de herramientas de ejecución simbólica | Mythril, Manticore, Oyente, MAIAN: profundidad, timeouts, vulnerabilidades detectables | 82 |
| 3.6 | Comparativa de herramientas de verificación formal | Certora, SMTChecker, VerX, KEVM: expresividad, soundness, usabilidad | 86 |
| 3.7 | Comparativa de herramientas basadas en IA/ML | GPTScan, SmartLLM, DeepScan: modelos, precisión reportada, limitaciones | 90 |
| 3.8 | Benchmark Durieux et al. (2020): resumen de resultados | Métricas agregadas para 9 herramientas sobre corpus estandarizado | 92 |
| 3.9 | Brechas identificadas y soluciones propuestas por MIESC | 8 brechas con descripción del gap y solución implementada | 94 |
| 3.10 | Matriz de capacidades: herramientas existentes vs MIESC | Comparativa feature-by-feature con checkmarks | 96 |

---

## Capítulo 4: Desarrollo e Implementación

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| 4.1 | Resumen de las 7 capas Defense-in-Depth de MIESC | Capa, nombre, propósito, herramientas integradas, tiempo típico | 99 |
| 4.2 | Herramientas integradas en Capa 1 (Análisis Estático) | Slither, Aderyn, Solhint: versión, licencia, detectores, fortalezas/debilidades | 105 |
| 4.3 | Detectores de Slither mapeados a SWC-ID | 93 detectores con SWC-ID correspondiente y severidad | 109 |
| 4.4 | Herramientas integradas en Capa 2 (Testing Dinámico) | Echidna, Medusa, DogeFuzz, Foundry: características y configuración | 112 |
| 4.5 | Propiedades de Echidna soportadas por MIESC | Tipos de propiedades (invariantes, assertions, revert) con ejemplos | 116 |
| 4.6 | Herramientas integradas en Capa 3 (Ejecución Simbólica) | Mythril, Manticore, Halmos: estrategias de exploración y límites | 118 |
| 4.7 | Configuración de timeout por herramienta simbólica | Valores default y recomendados según complejidad del contrato | 122 |
| 4.8 | Herramientas integradas en Capa 4 (Invariant Testing) | Halmos, Kontrol: integración con Foundry y tipos de invariantes | 124 |
| 4.9 | Herramientas integradas en Capa 5 (Verificación Formal) | SMTChecker, Certora, Wake: capacidades de especificación y prueba | 130 |
| 4.10 | Engines de SMTChecker y sus características | CHC, BMC, All: soundness, completeness, aplicabilidad | 134 |
| 4.11 | Herramientas integradas en Capa 6 (Property Testing IA) | PropertyGPT, DA-GNN: arquitectura de modelos y métricas | 136 |
| 4.12 | Herramientas integradas en Capa 7 (Análisis IA) | SmartLLM, GPTScan, ThreatModel: modelos base y prompts | 142 |
| 4.13 | Modelos LLM soportados por MIESC | DeepSeek-Coder, CodeLlama, GPT-4: parámetros, requisitos VRAM, precisión | 146 |
| 4.14 | Esquema de normalización de hallazgos | Campos obligatorios y opcionales con tipos de datos y validaciones | 151 |
| 4.15 | Mapeo de severidades entre herramientas | Conversión de niveles de severidad de cada herramienta al esquema unificado | 153 |
| 4.16 | Endpoints de la API REST de MIESC | 12 endpoints con método HTTP, path, parámetros y respuesta | 158 |
| 4.17 | Códigos de error de la API REST | Códigos HTTP y mensajes de error con causas y soluciones | 159 |
| 4.18 | Tools expuestos por servidor MCP | 8 tools con nombre, descripción, parámetros y ejemplo de uso | 163 |
| 4.19 | Resources expuestos por servidor MCP | 4 resources con URI, tipo MIME y contenido | 164 |

---

## Capítulo 5: Resultados Experimentales

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| 5.1 | Especificaciones del ambiente de pruebas | Hardware (CPU, RAM, GPU), software (OS, Python, Solidity) y configuración | 165 |
| 5.2 | Corpus de contratos de prueba | 15 contratos con nombre, LOC, complejidad ciclomática, vulnerabilidades conocidas | 168 |
| 5.3 | Vulnerabilidades inyectadas en corpus de prueba | Mapeo contrato → vulnerabilidades con ground truth para validación | 171 |
| 5.4 | Estado de disponibilidad de herramientas integradas | 25 herramientas con estado (OK/Parcial/Error) y notas de compatibilidad | 172 |
| 5.5 | Problemas de integración y soluciones implementadas | 12 problemas encontrados con descripción, impacto y solución aplicada | 176 |
| 5.6 | Resultados de detección por contrato | Matriz contrato × herramienta con conteo de hallazgos | 182 |
| 5.7 | Distribución de hallazgos por severidad | Totales CRITICAL/HIGH/MEDIUM/LOW/INFO por herramienta y agregado | 185 |
| 5.8 | Hallazgos detectados por capa | Conteo y porcentaje de hallazgos únicos aportados por cada capa | 188 |
| 5.9 | Métricas de detección por categoría SWC | Precision, Recall, F1-Score para cada SWC-ID evaluado | 191 |
| 5.10 | Comparativa MIESC vs herramientas individuales | Métricas agregadas: TP, FP, FN, Precision, Recall, F1 | 192 |
| 5.11 | Análisis de hallazgos duplicados | Estadísticas de deduplicación: total raw, únicos, tasa de reducción | 196 |
| 5.12 | Validación de mapeo taxonómico | Accuracy del mapeo automático SWC→CWE validado manualmente | 198 |
| 5.13 | Tiempos de ejecución por capa | Media, mediana, p95, máximo para cada capa en segundos | 202 |
| 5.14 | Desglose de tiempo por herramienta | Tiempo promedio de ejecución para cada una de las 25 herramientas | 203 |
| 5.15 | Consumo de recursos durante auditoría completa | CPU%, RAM (GB), GPU% por fase de análisis | 205 |
| 5.16 | Comparativa de costo operativo | TCO mensual/anual para configuraciones: local, cloud, híbrida | 208 |
| 5.17 | Resumen de respuestas a preguntas de investigación | RQ1-RQ5 con respuesta sintética y evidencia de soporte | 212 |

---

## Capítulo 6: Justificación del Uso de IA y LLMs Soberanos

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| 6.1 | Valor en riesgo típico en auditorías de smart contracts | Clasificación por tipo de protocolo (DeFi, NFT, DAO) y TVL promedio | 215 |
| 6.2 | Términos de servicio de APIs de LLM comerciales | Comparativa OpenAI, Anthropic, Google: retención datos, uso para training, jurisdicción | 219 |
| 6.3 | Costo por auditoría con APIs comerciales | Estimación de tokens/auditoría y costo en USD para GPT-4, Claude, Gemini | 220 |
| 6.4 | Incidentes de filtración de datos en servicios de IA | 5 casos documentados con fecha, servicio, datos expuestos, impacto | 226 |
| 6.5 | Matriz de riesgos: API comercial vs LLM soberano | 8 categorías de riesgo con probabilidad e impacto para cada opción | 228 |
| 6.6 | Herramientas LLM implementadas en MIESC | SmartLLM, ThreatModel, GPTScan: modelo base, backend, capacidades | 232 |
| 6.7 | Requisitos de hardware para LLM local | Modelos 7B/13B/34B: VRAM, RAM, almacenamiento, throughput esperado | 236 |
| 6.8 | Comparativa de precisión: API comercial vs LLM local | Métricas por categoría de vulnerabilidad con intervalos de confianza | 238 |
| 6.9 | Árbol de decisión para selección de backend | Criterios de decisión con pesos y recomendación resultante | 240 |
| 6.10 | Análisis TCO a 3 años: escenarios de uso | 4 escenarios (bajo/medio/alto volumen, enterprise) con costos desglosados | 242 |

---

## Capítulo 7: Justificación del Model Context Protocol (MCP)

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| 7.1 | Alternativas de integración consideradas | REST API, gRPC, GraphQL, Plugin nativo, MCP: pros/contras de cada una | 245 |
| 7.2 | Características del Model Context Protocol | Especificación de capacidades: tools, resources, prompts, sampling | 250 |
| 7.3 | Comparativa de complejidad de implementación | LOC, dependencias, tiempo de desarrollo para cada alternativa | 254 |
| 7.4 | Comparativa de métodos de integración con asistentes IA | Latencia, mantenibilidad, extensibilidad, compatibilidad | 258 |
| 7.5 | Tools implementados en servidor MCP de MIESC | 8 tools con schema JSON-RPC y ejemplos de invocación | 260 |
| 7.6 | Resources implementados en servidor MCP de MIESC | 4 resources con URI template y formato de respuesta | 261 |
| 7.7 | Comparación de flujos de trabajo: manual vs MCP | Pasos, tiempo, errores potenciales para auditoría típica | 265 |
| 7.8 | Métricas de rendimiento del servidor MCP | Latencia p50/p95/p99, throughput, conexiones concurrentes | 268 |
| 7.9 | Compatibilidad con clientes MCP | Claude Desktop, Continue, otros: versión mínima, features soportados | 270 |

---

## Capítulo 8: Conclusiones y Trabajos Futuros

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| 8.1 | Evaluación del cumplimiento de objetivos | 5 objetivos con indicador de cumplimiento, evidencia y referencia | 275 |
| 8.2 | Resumen de contribuciones del trabajo | 6 contribuciones principales con descripción y relevancia | 278 |
| 8.3 | Limitaciones identificadas del trabajo | 8 limitaciones con descripción, impacto y posible mitigación | 280 |
| 8.4 | Línea 1: Mejora de cobertura de vulnerabilidades | Tareas propuestas con prioridad, esfuerzo estimado y dependencias | 282 |
| 8.5 | Línea 2: Mejora de modelos de IA | Tareas de fine-tuning, nuevos modelos, evaluación | 286 |
| 8.6 | Línea 3: Soporte multi-chain | Tareas para Solana, Soroban, Cairo con análisis de viabilidad | 290 |
| 8.7 | Línea 4: Verificación formal avanzada | Tareas de síntesis de invariantes, integración Certora, pruebas formales | 294 |
| 8.8 | Línea 5: Integración con ecosistema de desarrollo | Tareas para GitHub Actions, GitLab CI, IDE plugins | 298 |
| 8.9 | Línea 6: Auditoría continua y runtime monitoring | Tareas para monitoreo on-chain, alertas, respuesta automática | 302 |
| 8.10 | Cronograma propuesto de trabajos futuros | Diagrama de Gantt textual con hitos Q1-Q4 2025-2027 | 306 |

---

## Apéndice A: Salidas de Herramientas

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| A.1 | Salidas de Slither para VulnerableBank.sol | Hallazgos completos en formato estructurado | 315 |
| A.2 | Salidas de Mythril para VulnerableBank.sol | Vulnerabilidades con evidencia simbólica | 320 |
| A.3 | Salidas de Echidna para VulnerableBank.sol | Propiedades violadas con secuencias de transacciones | 325 |
| A.4 | Salidas de SMTChecker para VulnerableBank.sol | Warnings y contraejemplos | 328 |
| A.5 | Salidas de Halmos para VulnerableBank.sol | Resultados de invariant testing | 330 |
| A.6 | Salidas de SmartLLM para VulnerableBank.sol | Análisis generado por IA | 332 |

---

## Apéndice B: Evolución Arquitectónica

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| B.1 | Evolución de versiones de MIESC | Changelog completo v0.1 a v4.0 con features principales | 340 |
| B.2 | Métricas de código por versión | LOC, complejidad, cobertura de tests para cada release | 344 |
| B.3 | Decisiones arquitectónicas documentadas (ADRs) | 10 ADRs principales con contexto, decisión y consecuencias | 348 |

---

## Apéndice C: Model Context Protocol

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| C.1 | Especificación completa de tools MCP | Schema JSON detallado para cada tool | 350 |
| C.2 | Especificación completa de resources MCP | Schema de resources con ejemplos de respuesta | 352 |
| C.3 | Mensajes de error del servidor MCP | Códigos de error JSON-RPC con descripción y recovery | 354 |

---

## Apéndice D: Tablas Comparativas Extendidas

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| D.1 | Matriz completa de herramientas por capa | 25 herramientas × 15 características con checkmarks detallados | 360 |
| D.2 | Capacidades de detección por SWC-ID | 37 SWC-IDs × 25 herramientas con nivel de soporte | 365 |
| D.3 | Comparativa de rendimiento detallada | Benchmarks completos para todas las combinaciones | 370 |
| D.4 | Matriz de cobertura de vulnerabilidades | Cruce de vulnerabilidades × capas con efectividad | 375 |
| D.5 | Comparativa de consumo de recursos | CPU/RAM/GPU por herramienta en diferentes escenarios | 378 |

---

## Apéndice G: Salidas Completas de Herramientas

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| G.1 | Configuración de ejecución para cada herramienta | Parámetros utilizados en las pruebas experimentales | 380 |
| G.2 | Resumen estadístico de salidas por herramienta | Conteos de hallazgos por severidad para corpus completo | 382 |

---

## Apéndice H: Fundamentos Técnicos

| Tabla | Título | Descripción | Pág. |
|-------|--------|-------------|------|
| H.1 | Operadores SlithIR y su semántica | Lista completa de operadores IR con descripción | 410 |
| H.2 | Teorías SMT utilizadas en verificación formal | QF_BV, QF_AUFBV, etc. con capacidades y limitaciones | 416 |
| H.3 | Hiperparámetros de modelos ML en MIESC | DA-GNN, embeddings: configuración óptima encontrada | 420 |
| H.4 | Prompts utilizados para análisis con LLM | Templates de prompts para cada tipo de análisis | 424 |

---

## Resumen Estadístico

| Sección | Cantidad de Tablas |
|---------|---------------------|
| Capítulo 1: Introducción | 3 |
| Capítulo 2: Marco Teórico | 11 |
| Capítulo 3: Estado del Arte | 10 |
| Capítulo 4: Desarrollo e Implementación | 19 |
| Capítulo 5: Resultados Experimentales | 17 |
| Capítulo 6: Justificación IA/LLMs | 10 |
| Capítulo 7: Justificación MCP | 9 |
| Capítulo 8: Conclusiones | 10 |
| Apéndice A: Salidas | 6 |
| Apéndice B: Evolución | 3 |
| Apéndice C: MCP | 3 |
| Apéndice D: Comparativas | 5 |
| Apéndice G: Salidas Completas | 2 |
| Apéndice H: Fundamentos | 4 |
| **Total** | **112** |

---

*Nota: Los números de página son indicativos y corresponden a la versión compilada final del documento. Todas las tablas incluyen títulos descriptivos, fuentes cuando corresponde, y están referenciadas en el texto.*

*Convenciones de numeración: X.Y donde X es el número de capítulo/apéndice e Y es el número secuencial dentro de esa sección.*
