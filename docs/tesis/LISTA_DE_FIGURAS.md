# Lista de Figuras

---

## Capítulo 1: Introducción

| Figura | Título | Descripción | Pág. |
|--------|--------|-------------|------|
| 1.1 | Evolución de pérdidas económicas por exploits en DeFi (2016-2024) | Gráfico de barras mostrando el incremento exponencial de pérdidas, desde $50M en 2016 hasta $3.8B en 2022, con detalle de incidentes críticos | 14 |
| 1.2 | Distribución de pérdidas por tipo de vulnerabilidad | Diagrama de torta con categorías: Reentrancy (34%), Flash Loans (28%), Access Control (18%), Oracle Manipulation (12%), Otros (8%) | 16 |
| 1.3 | Ciclo de vida de un smart contract y ventanas de vulnerabilidad | Diagrama de flujo desde desarrollo hasta producción, identificando puntos de intervención de MIESC | 19 |
| 1.4 | Estructura general del documento de tesis | Mapa conceptual mostrando la relación entre capítulos y su contribución al objetivo general | 22 |

---

## Capítulo 2: Marco Teórico

| Figura | Título | Descripción | Pág. |
|--------|--------|-------------|------|
| 2.1 | El ciberespacio como quinto dominio de operaciones militares | Diagrama de Venn mostrando intersección con dominios tradicionales (tierra, mar, aire, espacio) según doctrina NATO/UNDEF | 26 |
| 2.2 | Cadena de valor de blockchain como infraestructura crítica | Diagrama de capas desde infraestructura física hasta aplicaciones DeFi, identificando dependencias críticas | 29 |
| 2.3 | Modelo de amenazas STRIDE adaptado para ecosistema blockchain | Matriz de amenazas (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation) aplicada a smart contracts | 32 |
| 2.4 | Arquitectura de la Ethereum Virtual Machine (EVM) | Diagrama técnico mostrando stack, memory, storage, y flujo de ejecución de bytecode | 36 |
| 2.5 | Taxonomía de vulnerabilidades en smart contracts | Árbol jerárquico con tres niveles: Solidity, EVM, Blockchain, y sus subcategorías | 39 |
| 2.6 | Ciclo de vida de una vulnerabilidad: desde introducción hasta explotación | Línea temporal con fases: Introducción → Latencia → Descubrimiento → Explotación/Mitigación | 40 |
| 2.7 | Técnicas de análisis estático: Control Flow Graph (CFG) | Ejemplo de CFG para función withdraw() vulnerable a reentrancy | 47 |
| 2.8 | Técnicas de análisis estático: Data Flow Analysis | Diagrama de propagación de taint desde fuentes (msg.sender) hasta sinks (call.value) | 48 |
| 2.9 | Árbol de ejecución simbólica para análisis de caminos | Ejemplo con bifurcaciones condicionales y constraints acumulados en cada nodo | 49 |
| 2.10 | Proceso de fuzzing con feedback de cobertura (AFL-style) | Ciclo: Seed Selection → Mutation → Execution → Coverage Feedback → Corpus Update | 51 |
| 2.11 | Arquitectura de SMT Solver para verificación formal | Flujo desde predicados de primer orden hasta decisión SAT/UNSAT con contraejemplos | 54 |
| 2.12 | Patrón Adapter aplicado a integración de herramientas heterogéneas | Diagrama UML mostrando interfaz ToolAdapter y adaptadores concretos | 57 |
| 2.13 | Principios SOLID aplicados al diseño de MIESC | Matriz de principios vs componentes del framework con checkmarks de cumplimiento | 59 |
| 2.14 | Modelo Defense-in-Depth: 7 capas de protección | Diagrama de capas concéntricas desde el contrato hacia defensas externas | 62 |

---

## Capítulo 3: Estado del Arte

| Figura | Título | Descripción | Pág. |
|--------|--------|-------------|------|
| 3.1 | Línea temporal de incidentes críticos en smart contracts (2016-2024) | Timeline con magnitud de pérdidas y tipo de vulnerabilidad explotada | 66 |
| 3.2 | Distribución de vulnerabilidades por categoría SWC Registry | Histograma de frecuencia de las 37 categorías SWC en contratos auditados | 69 |
| 3.3 | Taxonomía de vulnerabilidades según origen: código vs diseño vs entorno | Diagrama de Venn con ejemplos representativos en cada intersección | 71 |
| 3.4 | Arquitectura interna de Slither | Diagrama de módulos: Parser → SlithIR → Detectors → Printers | 74 |
| 3.5 | Flujo de análisis de ejecución simbólica en Mythril | Pipeline: Bytecode → CFG → Symbolic Execution → Constraint Solving → Report | 76 |
| 3.6 | Arquitectura de fuzzing property-based en Echidna | Ciclo de generación de secuencias de transacciones y verificación de invariantes | 80 |
| 3.7 | Pipeline de verificación formal en Certora Prover | Flujo: Solidity + CVL → SMT → Counterexample/Proof | 84 |
| 3.8 | Arquitectura de análisis con LLMs: GPTScan y SmartLLM | Diagrama de componentes: Preprocesamiento → Prompt Engineering → LLM → Postprocesamiento | 88 |
| 3.9 | Mapa de brechas identificadas en el estado del arte | Matriz de capacidades vs herramientas existentes, resaltando gaps que MIESC aborda | 93 |
| 3.10 | Comparativa visual de cobertura de vulnerabilidades por herramienta | Heatmap de SWC-IDs vs herramientas con intensidad de color por precisión | 95 |

---

## Capítulo 4: Desarrollo e Implementación

| Figura | Título | Descripción | Pág. |
|--------|--------|-------------|------|
| 4.1 | Arquitectura general de MIESC v4.0.0 | Vista de alto nivel con 7 capas, coordinador central, y flujos de datos | 98 |
| 4.2 | Diagrama de capas Defense-in-Depth implementado en MIESC | Representación 3D de capas con herramientas asignadas a cada nivel | 100 |
| 4.3 | Flujo de datos entre capas del framework | Diagrama de secuencia mostrando propagación de hallazgos y correlación | 102 |
| 4.4 | Diagrama de clases: Interfaz ToolAdapter y sus implementaciones | UML con herencia y métodos principales (analyze, normalize, get_capabilities) | 104 |
| 4.5 | Detalle de Capa 1: Arquitectura de Análisis Estático | Componentes: Slither, Aderyn, Solhint con flujos de entrada/salida | 106 |
| 4.6 | Flujo de integración del adaptador de Slither | Secuencia: Input → SlitherAdapter → JSON Parser → Normalizer → Output | 108 |
| 4.7 | Diagrama de clases de detectores Slither mapeados | Jerarquía de AbstractDetector con ejemplos concretos | 110 |
| 4.8 | Detalle de Capa 2: Arquitectura de Testing Dinámico (Fuzzing) | Componentes: Echidna, Medusa, DogeFuzz con estrategias de mutación | 113 |
| 4.9 | Arquitectura de integración con Echidna | Flujo: Contract → Config → Echidna → Property Results → Normalizer | 115 |
| 4.10 | Algoritmo de power scheduling en DogeFuzz | Diagrama de flujo del algoritmo de selección de seeds basado en cobertura | 117 |
| 4.11 | Detalle de Capa 3: Arquitectura de Ejecución Simbólica | Componentes: Mythril, Manticore con gestión de estados simbólicos | 119 |
| 4.12 | Flujo de análisis simbólico en Mythril | Pipeline detallado con manejo de path explosion y timeouts | 121 |
| 4.13 | Detalle de Capa 4: Arquitectura de Invariant Testing | Componentes: Halmos, Kontrol con verificación bounded | 125 |
| 4.14 | Integración de Halmos con Foundry | Diagrama de interoperabilidad test harness → Halmos → SMT | 127 |
| 4.15 | Detalle de Capa 5: Arquitectura de Verificación Formal | Componentes: SMTChecker, Certora con especificaciones CVL | 131 |
| 4.16 | Flujo de verificación con SMTChecker engines (CHC, BMC) | Comparación de estrategias Horn Clauses vs Bounded Model Checking | 133 |
| 4.17 | Ejemplo de especificación CVL para propiedad de balance | Código CVL anotado con explicación de invariantes | 135 |
| 4.18 | Detalle de Capa 6: Arquitectura de Property Testing con IA | Componentes: PropertyGPT, DA-GNN con flujos de generación | 137 |
| 4.19 | Pipeline de PropertyGPT para generación de especificaciones | Flujo: Contract → LLM → CVL Draft → Refinement → Final Spec | 139 |
| 4.20 | Arquitectura de DA-GNN para detección de vulnerabilidades | Red neuronal: Contract → CFG+DFG → Graph Embedding → Classifier | 141 |
| 4.21 | Detalle de Capa 7: Arquitectura de Análisis con IA | Componentes: SmartLLM, ThreatModel, GPTScan con RAG | 143 |
| 4.22 | Arquitectura de integración con Ollama para LLM soberano | Diagrama de despliegue: MIESC → Ollama API → Model (deepseek-coder) | 145 |
| 4.23 | Pipeline RAG (Retrieval-Augmented Generation) en SmartLLM | Flujo: Query → Retriever (ERC KB) → Context Augmentation → LLM → Response | 147 |
| 4.24 | Sistema de normalización de hallazgos multi-herramienta | Diagrama de transformación: Raw Finding → Normalized Schema → Unified Report | 150 |
| 4.25 | Esquema JSON de hallazgo normalizado | Estructura de datos con campos obligatorios y opcionales | 152 |
| 4.26 | Algoritmo de deduplicación basado en similitud semántica | Flujo: Findings → Embedding → Clustering → Representative Selection | 154 |
| 4.27 | Arquitectura de la API REST de MIESC | Diagrama de endpoints con métodos HTTP y esquemas de request/response | 156 |
| 4.28 | Diagrama de secuencia: flujo completo de auditoría | Interacción entre cliente, API, coordinador, y 7 capas de análisis | 160 |
| 4.29 | Arquitectura del servidor MCP de MIESC | Componentes: JSON-RPC Handler, Tool Registry, Resource Provider | 162 |

---

## Capítulo 5: Resultados Experimentales

| Figura | Título | Descripción | Pág. |
|--------|--------|-------------|------|
| 5.1 | Diseño experimental del estudio de validación | Diagrama metodológico: Variables independientes/dependientes, controles | 166 |
| 5.2 | Distribución del corpus de contratos por complejidad | Histograma de LOC (líneas de código) del corpus de prueba | 170 |
| 5.3 | Captura de salida de Slither para VulnerableBank.sol | Screenshot de terminal con hallazgos coloreados por severidad | 174 |
| 5.4 | Captura de salida de Mythril para VulnerableBank.sol | Screenshot mostrando vulnerabilidades con evidencia simbólica | 178 |
| 5.5 | Captura de salida de SMTChecker para VulnerableBank.sol | Screenshot con warnings de verificación formal | 180 |
| 5.6 | Salida del pipeline completo de MIESC (JSON) | Extracto de reporte JSON con hallazgos normalizados | 184 |
| 5.7 | Estructura detallada de hallazgo normalizado | Diagrama de campos con ejemplo de reentrancy detectada | 186 |
| 5.8 | Respuesta de API REST de MIESC | Screenshot de respuesta JSON con métricas de auditoría | 190 |
| 5.9 | Distribución de hallazgos por severidad (gráfico de barras) | Comparativa CRITICAL/HIGH/MEDIUM/LOW/INFO entre herramientas | 194 |
| 5.10 | Matriz de confusión agregada para detección de vulnerabilidades | Heatmap de TP/FP/TN/FN por categoría SWC | 196 |
| 5.11 | Contribución de cada capa a la detección total | Gráfico de barras apiladas mostrando hallazgos únicos por capa | 200 |
| 5.12 | Diagrama de Venn: solapamiento de detecciones entre capas | Visualización de hallazgos compartidos vs únicos entre capas 1-3-5 | 202 |
| 5.13 | Comparativa de F1-Score: MIESC vs herramientas individuales | Gráfico de barras con intervalos de confianza | 204 |
| 5.14 | Tiempos de ejecución por capa (boxplot) | Distribución de tiempos con outliers identificados | 206 |
| 5.15 | Curva ROC para clasificación de severidad | Comparativa de área bajo la curva (AUC) por método | 208 |
| 5.16 | Análisis de sensibilidad: impacto de timeout en detección | Gráfico de líneas: recall vs timeout para capas 3 y 5 | 210 |

---

## Capítulo 6: Justificación del Uso de IA y LLMs Soberanos

| Figura | Título | Descripción | Pág. |
|--------|--------|-------------|------|
| 6.1 | Flujo de datos en análisis con API de LLM comercial | Diagrama mostrando datos sensibles que atraviesan fronteras organizacionales | 218 |
| 6.2 | Vectores de riesgo en uso de APIs comerciales para ciberdefensa | Matriz de amenazas: exfiltración, dependencia, costos, compliance | 222 |
| 6.3 | Arquitectura de LLM soberano implementada en MIESC | Diagrama de despliegue on-premise con Ollama y modelos locales | 224 |
| 6.4 | Comparativa de latencia: API comercial vs LLM local | Gráfico de barras con p50, p95, p99 de tiempos de respuesta | 230 |
| 6.5 | Flujo de análisis con LLM soberano (air-gapped) | Diagrama mostrando aislamiento completo de datos sensibles | 234 |
| 6.6 | Árbol de decisión para selección de backend LLM | Flowchart: sensibilidad datos → requisitos latencia → presupuesto → recomendación | 240 |
| 6.7 | Análisis TCO: LLM local vs API comercial (proyección 3 años) | Gráfico de líneas acumulativas con punto de break-even | 242 |
| 6.8 | Comparativa de precisión: GPT-4 vs DeepSeek-Coder local | Scatter plot con regresión para diferentes categorías de vulnerabilidad | 244 |

---

## Capítulo 7: Justificación del Model Context Protocol (MCP)

| Figura | Título | Descripción | Pág. |
|--------|--------|-------------|------|
| 7.1 | Arquitectura de integración MCP en ecosistema Claude | Diagrama de componentes: Claude Desktop → MCP Client → MIESC Server | 248 |
| 7.2 | Comparativa de arquitecturas: REST vs MCP vs Plugin nativo | Diagrama lado a lado mostrando complejidad y acoplamiento | 250 |
| 7.3 | Secuencia de interacción MCP: handshake y tool invocation | Diagrama de secuencia con mensajes JSON-RPC detallados | 252 |
| 7.4 | Componentes del servidor MCP de MIESC | Diagrama de módulos: Transport → Protocol → Tools → Resources | 256 |
| 7.5 | Flujo de auditoría interactiva con Claude vía MCP | Storyboard de interacción usuario → Claude → MIESC → resultados | 262 |
| 7.6 | Configuración de MCP en Claude Desktop | Screenshot anotado de archivo de configuración JSON | 266 |
| 7.7 | Métricas de latencia de herramientas MCP | Histograma de tiempos de respuesta por tool_id | 268 |
| 7.8 | Diagrama de estados del servidor MCP | FSM: Initializing → Ready → Processing → Error/Recovery | 270 |

---

## Capítulo 8: Conclusiones y Trabajos Futuros

| Figura | Título | Descripción | Pág. |
|--------|--------|-------------|------|
| 8.1 | Diagrama de cumplimiento de objetivos de investigación | Checklist visual con evidencia de cumplimiento por objetivo | 276 |
| 8.2 | Contribuciones del trabajo vs brechas del estado del arte | Matriz de mapeo: brecha identificada → solución implementada | 280 |
| 8.3 | Arquitectura propuesta para soporte multi-chain | Diagrama extendido: EVM + Solana + Soroban con adaptadores específicos | 292 |
| 8.4 | Pipeline propuesto de síntesis automática de invariantes | Flujo: Contract → AST Analysis → Pattern Matching → Invariant Generation | 296 |
| 8.5 | Propuesta de integración con GitHub Actions para CI/CD | Diagrama de workflow: Push → MIESC Analysis → PR Gate → Deploy | 300 |
| 8.6 | Arquitectura conceptual de MIESC Runtime Monitor | Componentes: On-chain Monitor → Event Detector → Alert System | 304 |
| 8.7 | Roadmap de desarrollo de MIESC (2025-2027) | Diagrama de Gantt con hitos principales y dependencias | 308 |
| 8.8 | Modelo de madurez propuesto para adopción de MIESC | Pirámide de niveles: Ad-hoc → Repetible → Definido → Gestionado → Optimizado | 310 |

---

## Apéndice A: Interfaz Web y Reportes

| Figura | Título | Descripción | Pág. |
|--------|--------|-------------|------|
| A.1 | Captura de pantalla: página principal de interfaz web MIESC | Dashboard con métricas de seguridad y accesos rápidos | 318 |
| A.2 | Captura de pantalla: formulario de carga de contrato | Interfaz de upload con opciones de configuración | 320 |
| A.3 | Captura de pantalla: reporte de auditoría en formato web | Vista de hallazgos con filtros y ordenamiento | 322 |
| A.4 | Captura de pantalla: gráficos interactivos de severidad | Visualización Plotly con tooltips detallados | 324 |
| A.5 | Ejemplo de reporte PDF generado por MIESC | Primera página del reporte ejecutivo | 326 |
| A.6 | Flujo de trabajo del desarrollador con MIESC | Diagrama completo mostrando 4 interfaces (CLI, Web UI, REST API, MCP), 7 capas de análisis, normalización y métricas de rendimiento | 328 |

---

## Apéndice B: Evolución Arquitectónica

| Figura | Título | Descripción | Pág. |
|--------|--------|-------------|------|
| B.1 | Evolución arquitectónica de MIESC: xAudit v0.1 a MIESC v4.0 | Timeline con hitos de desarrollo y cambios arquitectónicos | 342 |
| B.2 | Diagrama de clases simplificado del core de MIESC | UML con clases principales y relaciones | 346 |
| B.3 | Métricas de complejidad ciclomática por versión | Gráfico de evolución de complejidad del código | 348 |

---

## Apéndice C: Model Context Protocol

| Figura | Título | Descripción | Pág. |
|--------|--------|-------------|------|
| C.1 | Diagrama de secuencia MCP detallado: ciclo completo | Interacción completa desde conexión hasta cierre | 354 |
| C.2 | Estructura de mensajes MCP: request/response/notification | Esquemas JSON con campos obligatorios y opcionales | 356 |
| C.3 | Diagrama de despliegue del servidor MCP | Arquitectura de contenedores y networking | 358 |

---

## Apéndice G: Salidas de Herramientas

| Figura | Título | Descripción | Pág. |
|--------|--------|-------------|------|
| G.1 | Salida completa de Slither: VulnerableBank.sol | Terminal output con todos los detectores ejecutados | 380 |
| G.2 | Salida completa de Mythril: VulnerableBank.sol | Reporte de ejecución simbólica con traces | 384 |
| G.3 | Salida completa de Echidna: VulnerableBank.sol | Log de fuzzing con propiedades violadas | 388 |
| G.4 | Salida completa de SMTChecker: VulnerableBank.sol | Warnings y contraejemplos del verificador | 392 |
| G.5 | Salida completa de Halmos: invariant testing | Resultados de verificación bounded | 396 |
| G.6 | Salida del análisis IA (SmartLLM): VulnerableBank.sol | Reporte generado por LLM con explicaciones | 400 |

---

## Apéndice H: Fundamentos Técnicos

| Figura | Título | Descripción | Pág. |
|--------|--------|-------------|------|
| H.1 | Representación SlithIR de función vulnerable | Código IR anotado con análisis de flujo | 410 |
| H.2 | Árbol de ejecución simbólica expandido | Ejemplo detallado con 8 niveles de profundidad | 414 |
| H.3 | Algoritmo de power scheduling: pseudocódigo visual | Flowchart del algoritmo de DogeFuzz | 418 |
| H.4 | Gramática de CVL (Certora Verification Language) | Diagrama de sintaxis BNF simplificado | 422 |
| H.5 | Arquitectura de Graph Neural Network (DA-GNN) | Diagrama de capas: Input → GCN → Attention → Output | 426 |
| H.6 | Pipeline RAG completo con vectores de embedding | Flujo detallado de retrieval y augmentation | 430 |

---

## Resumen Estadístico

| Sección | Cantidad de Figuras |
|---------|---------------------|
| Capítulo 1: Introducción | 4 |
| Capítulo 2: Marco Teórico | 14 |
| Capítulo 3: Estado del Arte | 10 |
| Capítulo 4: Desarrollo e Implementación | 29 |
| Capítulo 5: Resultados Experimentales | 16 |
| Capítulo 6: Justificación IA/LLMs | 8 |
| Capítulo 7: Justificación MCP | 8 |
| Capítulo 8: Conclusiones | 8 |
| Apéndice A: Interfaz Web | 6 |
| Apéndice B: Evolución | 3 |
| Apéndice C: MCP | 3 |
| Apéndice G: Salidas | 6 |
| Apéndice H: Fundamentos | 6 |
| **Total** | **121** |

---

*Nota: Los números de página son indicativos y corresponden a la versión compilada final del documento. Todas las figuras incluyen títulos descriptivos, fuentes cuando corresponde, y están referenciadas en el texto.*

*Convenciones de numeración: X.Y donde X es el número de capítulo/apéndice e Y es el número secuencial dentro de esa sección.*
