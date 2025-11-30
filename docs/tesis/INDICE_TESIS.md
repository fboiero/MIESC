# MIESC: Framework Multi-capa para Seguridad de Smart Contracts

## Tesis de Maestría en Ciberdefensa

**Autor:** Ing. Fernando Boiero
**Director:** Mg. Eduardo Casanovas
**Universidad de la Defensa Nacional (UNDEF)**
**Centro Regional Universitario Córdoba - Instituto Universitario Aeronáutico (IUA)**
**Fecha:** Noviembre 2025

---

## Índice General

### Sección Preliminar

*Archivo: SECCION_PRELIMINAR.md*

- Resumen
- Abstract
- Dedicatoria
- Agradecimientos
- Declaración de Autoría
- Declaración de Originalidad del Software

### Índices

*Archivos: LISTA_DE_TABLAS.md, LISTA_DE_FIGURAS.md, LISTA_DE_ACRONIMOS.md, GLOSARIO.md*

- Lista de Tablas (112 tablas)
- Lista de Figuras (120 figuras)
- Lista de Acrónimos y Abreviaturas (78 acrónimos)
- Glosario de Términos (95 términos)

---

### Capítulo 1: Introducción

*Archivo: CAPITULO_INTRODUCCION.md*

1.1 Contexto y Motivación
   - 1.1.1 La Emergencia del Ciberespacio como Dominio de Operaciones
   - 1.1.2 La Amenaza a los Smart Contracts
   - 1.1.3 La Fragmentación del Ecosistema de Herramientas
   - 1.1.4 La Necesidad de Soberanía de Datos
1.2 Planteamiento del Problema
   - 1.2.1 Problema Principal
   - 1.2.2 Problemas Específicos
1.3 Objetivos
   - 1.3.1 Objetivo General
   - 1.3.2 Objetivos Específicos
1.4 Preguntas de Investigación
1.5 Hipótesis
1.6 Justificación
   - 1.6.1 Relevancia para la Ciberdefensa
   - 1.6.2 Relevancia Académica
   - 1.6.3 Relevancia Práctica
1.7 Alcance y Limitaciones
1.8 Metodología
1.9 Contribuciones
1.10 Estructura del Documento
1.11 Referencias del Capítulo

---

### Capítulo 2: Marco Teórico

*Archivo: CAPITULO_MARCO_TEORICO.md*

2.1 Ciberdefensa y Seguridad de Infraestructuras Críticas
   - 2.1.1 Definición de Ciberdefensa
   - 2.1.2 Blockchain como Infraestructura Crítica
   - 2.1.3 Modelo de Amenazas para Blockchain
   - 2.1.4 Relevancia para la Defensa Nacional
2.2 Blockchain y Smart Contracts
   - 2.2.1 Fundamentos de Blockchain
   - 2.2.2 Smart Contracts: Definición y Características
   - 2.2.3 Ethereum Virtual Machine (EVM)
   - 2.2.4 Lenguaje Solidity
2.3 Taxonomía de Vulnerabilidades
   - 2.3.1 Smart Contract Weakness Classification (SWC)
   - 2.3.2 Common Weakness Enumeration (CWE)
   - 2.3.3 OWASP Smart Contract Top 10
   - 2.3.4 Mapeo entre Taxonomías
2.4 Técnicas de Análisis de Seguridad
   - 2.4.1 Análisis Estático
   - 2.4.2 Análisis Dinámico (Fuzzing)
   - 2.4.3 Ejecución Simbólica
   - 2.4.4 Verificación Formal
2.5 Patrones de Diseño de Software
   - 2.5.1 Patrón Adapter
   - 2.5.2 Principios SOLID
   - 2.5.3 Defense-in-Depth
2.6 Inteligencia Artificial en Ciberseguridad
   - 2.6.1 Large Language Models (LLMs) en Seguridad
   - 2.6.2 Retrieval Augmented Generation (RAG)
   - 2.6.3 Model Context Protocol (MCP)
   - 2.6.4 Soberanía de Datos en IA
2.7 Normalización y Taxonomías
2.8 Referencias del Capítulo

---

### Capítulo 3: Estado del Arte

*Archivo: CAPITULO_ESTADO_DEL_ARTE.md*

3.1 Introducción
3.2 Contexto y Relevancia del Problema
   - 3.2.1 Impacto Económico de las Vulnerabilidades
   - 3.2.2 Taxonomía de Vulnerabilidades
3.3 Técnicas de Análisis de Seguridad
   - 3.3.1 Análisis Estático
   - 3.3.2 Ejecución Simbólica
   - 3.3.3 Fuzzing
   - 3.3.4 Verificación Formal
3.4 Análisis Comparativo de Herramientas Existentes
   - 3.4.1 Análisis con Inteligencia Artificial
3.5 Identificación de Brechas en el Estado del Arte
   - 3.5.1 Brecha 1: Fragmentación de Herramientas
   - 3.5.2 Brecha 2: Ausencia de Enfoque Multi-Técnica
   - 3.5.3 Brecha 3: Falta de Normalización
   - 3.5.4 Brecha 4: Dependencia de Servicios Comerciales
   - 3.5.5 Brecha 5: Obsolescencia y Compatibilidad
   - 3.5.6 Brecha 6: Ausencia de Orquestación
3.6 Síntesis y Justificación de MIESC
3.7 Referencias del Capítulo

---

### Capítulo 4: Desarrollo e Implementación

*Archivo: CAPITULO_DESARROLLO.md*

4.1 Metodología de Desarrollo
4.2 Arquitectura del Sistema
   - 4.2.1 Visión General
   - 4.2.2 Arquitectura de 7 Capas
   - 4.2.3 Patrón Adapter
   - 4.2.4 Flujo de Datos
4.3 Capa 1: Análisis Estático
   - 4.3.1 Slither
   - 4.3.2 Solhint
   - 4.3.3 Securify2
   - 4.3.4 Semgrep
4.4 Capa 2: Testing Dinámico (Fuzzing)
   - 4.4.1 Echidna
   - 4.4.2 Foundry Fuzz
   - 4.4.3 Medusa
   - 4.4.4 Vertigo
4.5 Capa 3: Ejecución Simbólica
   - 4.5.1 Mythril
   - 4.5.2 Manticore
   - 4.5.3 Oyente
4.6 Capa 4: Testing de Invariantes
   - 4.6.1 Scribble
   - 4.6.2 Halmos
4.7 Capa 5: Verificación Formal
   - 4.7.1 SMTChecker
   - 4.7.2 Certora Prover
4.8 Capa 6: Property Testing
   - 4.8.1 PropertyGPT
   - 4.8.2 Aderyn
   - 4.8.3 Wake
4.9 Capa 7: Análisis con IA
   - 4.9.1 GPTScan
   - 4.9.2 SmartLLM
   - 4.9.3 LLMSmartAudit
   - 4.9.4 ThreatModel
   - 4.9.5 GasGauge
   - 4.9.6 UpgradeGuard
   - 4.9.7 BestPractices
4.10 Sistema de Normalización
   - 4.10.1 Estructura de Hallazgos
   - 4.10.2 Mapeo a Taxonomías
   - 4.10.3 Algoritmo de Deduplicación
4.11 API REST y Servidor MCP
   - 4.11.1 Diseño de la API
   - 4.11.2 Endpoints Disponibles
   - 4.11.3 Servidor MCP
4.12 Referencias del Capítulo

---

### Capítulo 5: Resultados Experimentales

*Archivo: CAPITULO_RESULTADOS.md*

5.1 Metodología de Evaluación
   - 5.1.1 Diseño Experimental
   - 5.1.2 Preguntas de Investigación
   - 5.1.3 Ambiente Experimental
   - 5.1.4 Corpus de Prueba
5.2 Resultados: Integración de Herramientas (RQ1)
   - 5.2.1 Estado de Disponibilidad
   - 5.2.2 Desafíos de Integración Resueltos
   - 5.2.3 Evidencia de Funcionamiento
5.3 Resultados: Detección de Vulnerabilidades (RQ2)
   - 5.3.1 Análisis del Corpus de Prueba
   - 5.3.2 Distribución de Severidades
   - 5.3.3 Detección por Capa
   - 5.3.4 Comparación con Herramientas Individuales
5.4 Resultados: Normalización y Deduplicación (RQ3)
   - 5.4.1 Efectividad de la Deduplicación
   - 5.4.2 Validación del Mapeo Taxonómico
5.5 Resultados: Viabilidad en Producción (RQ4)
   - 5.5.1 Tiempos de Ejecución
   - 5.5.2 Consumo de Recursos
   - 5.5.3 Análisis de Costo
5.6 Análisis de Validez
5.7 Discusión
5.8 Limitaciones
5.9 Referencias del Capítulo

---

### Capítulo 6: Justificación del Uso de IA y LLMs Soberanos

*Archivo: CAPITULO_JUSTIFICACION_IA_LLM_SOBERANO.md*

6.1 Introducción
   - 6.1.1 Contexto del Problema
6.2 Problemática de APIs de LLM Comerciales
   - 6.2.1 Riesgos de Confidencialidad
   - 6.2.2 Caso de Estudio: Filtración de Código en LLMs
   - 6.2.3 Costos Operativos
6.3 Solución: LLMs Soberanos con Ollama
   - 6.3.1 Arquitectura de Ejecución Local
   - 6.3.2 Componentes del Sistema
   - 6.3.3 Garantías de Privacidad
6.4 Justificación Técnica
   - 6.4.1 Soberanía de Datos
   - 6.4.2 Cumplimiento Normativo
   - 6.4.3 Consideraciones de Seguridad
   - 6.4.4 Análisis de Costo-Beneficio
6.5 Implementación en MIESC
   - 6.5.1 Herramientas que Utilizan LLM Soberano
   - 6.5.2 Arquitectura de Integración
   - 6.5.3 Código de Ejemplo
   - 6.5.4 Verificación de Seguridad
6.6 Comparativa: LLM Soberano vs Alternativas
6.7 Limitaciones y Mitigaciones
6.8 Cumplimiento con DPGA
6.9 Conclusiones
6.10 Referencias del Capítulo

---

### Capítulo 7: Justificación del Model Context Protocol (MCP)

*Archivo: CAPITULO_JUSTIFICACION_MCP.md*

7.1 Introducción al MCP
   - 7.1.1 Contexto y Motivación
   - 7.1.2 Por qué MCP para MIESC
7.2 Arquitectura del MCP Server de MIESC
   - 7.2.1 Diseño General
   - 7.2.2 Componentes del Servidor
   - 7.2.3 Flujo de Comunicación
7.3 Justificación Técnica del MCP
   - 7.3.1 Beneficios de la Arquitectura MCP
   - 7.3.2 Comparación con Alternativas
   - 7.3.3 Seguridad del MCP
7.4 Implementación del MCP Server
   - 7.4.1 Estructura del Servidor
   - 7.4.2 Código del Servidor Principal
   - 7.4.3 Configuración para Claude Desktop
7.5 Casos de Uso
   - 7.5.1 Auditoría Interactiva
   - 7.5.2 Análisis Específico
   - 7.5.3 Consulta de Documentación
7.6 Ventajas sobre Integraciones Tradicionales
7.7 Limitaciones y Consideraciones
7.8 Roadmap de Integración MCP
7.9 Conclusiones
7.10 Referencias del Capítulo

---

### Capítulo 8: Conclusiones y Trabajos Futuros

*Archivo: CAPITULO_TRABAJOS_FUTUROS.md*

8.1 Conclusiones
   - 8.1.1 Síntesis del Trabajo Realizado
   - 8.1.2 Objetivos Alcanzados
   - 8.1.3 Contribuciones Principales
   - 8.1.4 Validación de Hipótesis
8.2 Limitaciones del Trabajo
   - 8.2.1 Limitaciones Técnicas
   - 8.2.2 Limitaciones Metodológicas
8.3 Trabajos Futuros
   - 8.3.1 Línea 1: Extensión de Cobertura de Vulnerabilidades
   - 8.3.2 Línea 2: Mejora de Modelos de IA
   - 8.3.3 Línea 3: Soporte Multi-Chain
   - 8.3.4 Línea 4: Verificación Formal Avanzada
   - 8.3.5 Línea 5: Integración con Ecosistema de Desarrollo
   - 8.3.6 Línea 6: Auditoría Continua en Producción
8.4 Impacto Esperado
   - 8.4.1 Impacto Académico
   - 8.4.2 Impacto Industrial
   - 8.4.3 Impacto Social
8.5 Reflexiones Finales
8.6 Referencias del Capítulo

---

### Apéndices

#### Apéndice A: Salidas de las 25 Herramientas

*Archivo: APENDICE_SALIDAS_HERRAMIENTAS.md*

- A.1-A.4 Capa 1: Análisis Estático (Slither, Solhint, Securify2, Semgrep)
- A.5-A.8 Capa 2: Testing Dinámico (Echidna, Foundry, Medusa, Vertigo)
- A.9-A.11 Capa 3: Ejecución Simbólica (Mythril, Manticore, Oyente)
- A.12-A.13 Capa 4: Testing de Invariantes (Scribble, Halmos)
- A.14-A.15 Capa 5: Verificación Formal (SMTChecker, Certora)
- A.16-A.18 Capa 6: Property Testing (PropertyGPT, Aderyn, Wake)
- A.19-A.25 Capa 7: Análisis IA (GPTScan, SmartLLM, LLMSmartAudit, ThreatModel, GasGauge, UpgradeGuard, BestPractices)

#### Apéndice B: Evolución Arquitectónica

*Archivo: EVOLUCION_ARQUITECTONICA.md*

- B.1 Fase 1: xAudit v0.1 (Monolítico)
- B.2 Fase 2: xAudit v0.5 (Modular)
- B.3 Fase 3: MIESC v1.0 (Multi-herramienta)
- B.4 Fase 4: MIESC v2.0 (Capas)
- B.5 Fase 5: MIESC v3.0 (IA Local)
- B.6 Fase 6: MIESC v3.5 (MCP)
- B.7 Fase 7: MIESC v4.0 (Defense-in-Depth)

#### Apéndice C: Arquitectura del Servidor MCP

*Archivo: ARQUITECTURA_MCP_SERVER.md*

- C.1 Diagrama de Arquitectura
- C.2 Definición de Herramientas (Tools)
- C.3 Definición de Recursos (Resources)
- C.4 Flujo de Comunicación
- C.5 Ejemplos de Uso
- C.6 Consideraciones de Seguridad

#### Apéndice D: Tablas Comparativas

*Archivo: TABLAS_COMPARATIVAS.md*

- D.1 Herramientas por Capa
- D.2 Capacidades de Detección por SWC
- D.3 Comparativa de Rendimiento
- D.4 Matriz de Cobertura

#### Apéndice E: Código Fuente Representativo

*Archivo: APENDICE_CODIGO_FUENTE.md*

- E.1 Introducción
- E.2 Interfaz Base de Adaptadores
- E.3 Implementación del Adaptador de Slither
- E.4 Sistema de Normalización
- E.5 Orquestador de Pipeline
- E.6 Servidor MCP
- E.7 Integración con Ollama
- E.8 Estructura del Proyecto

#### Apéndice F: Glosario

*Archivo: GLOSARIO.md*

- 95 términos técnicos definidos

#### Apéndice G: Salidas Detalladas de Herramientas

*Archivo: APENDICE_SALIDAS_DETALLADAS.md* (incluido en APENDICE_SALIDAS_HERRAMIENTAS.md)

- G.1 Contrato de Prueba: VulnerableBank.sol
- G.2 Salidas Nativas de cada herramienta
- G.3 Hallazgos Normalizados (JSON)
- G.4 Salida del Pipeline Completo
- G.5 Respuesta de API REST
- G.6 Interacción con MCP

#### Apéndice H: Fundamentos Técnicos de las Técnicas de Análisis

*Archivo: APENDICE_TECNICAS_ANALISIS.md*

- H.1 Introducción
- H.2 Capa 1: Análisis Estático
  - H.2.1 Representación Intermedia (IR)
  - H.2.2 SlithIR
  - H.2.3 Análisis de Flujo de Datos
  - H.2.4 Taint Tracking
- H.3 Capa 2: Testing Dinámico (Fuzzing)
  - H.3.1 Tipos de Fuzzing
  - H.3.2 Arquitectura de Echidna
  - H.3.3 DogeFuzz: Coverage-Guided Fuzzing
  - H.3.4 Power Scheduling
- H.4 Capa 3: Ejecución Simbólica
  - H.4.1 Estados Simbólicos
  - H.4.2 Árbol de Ejecución
  - H.4.3 Algoritmo de Mythril
  - H.4.4 SMT Solving
- H.5 Capa 4: Invariant Testing
  - H.5.1 Tipos de Invariantes
  - H.5.2 Verificación con Halmos
  - H.5.3 Bounded Model Checking
- H.6 Capa 5: Verificación Formal
  - H.6.1 Lógica de Hoare
  - H.6.2 CVL (Certora Verification Language)
  - H.6.3 SMTChecker Engines
- H.7 Capa 6: Property Testing con IA
  - H.7.1 PropertyGPT Pipeline
  - H.7.2 DA-GNN: Detección basada en Grafos
- H.8 Capa 7: Análisis con IA
  - H.8.1 SmartLLM con RAG
  - H.8.2 Prompt Engineering
- H.9 Comparación de Técnicas
- H.10 Referencias Técnicas

---

### Referencias Bibliográficas

*Archivo: REFERENCIAS_BIBLIOGRAFICAS.md*

- 85+ referencias en formato APA 7ma edición
- Organizadas alfabéticamente
- Incluye referencias de ciberdefensa, blockchain, seguridad y IA

---

## Resumen Ejecutivo de Capítulos

| Capítulo | Páginas Est. | Descripción |
|----------|--------------|-------------|
| Sección Preliminar | 8-10 | Resumen, Abstract, Agradecimientos, Declaraciones |
| Índices | 25-30 | 112 Tablas, 120 Figuras, 78 Acrónimos, 95 Términos |
| 1. Introducción | 15-18 | Contexto, objetivos, preguntas de investigación |
| 2. Marco Teórico | 25-30 | Fundamentos teóricos con enfoque en ciberdefensa |
| 3. Estado del Arte | 20-25 | Revisión sistemática de literatura |
| 4. Desarrollo | 45-50 | Diseño e implementación de MIESC v4.0.0 |
| 5. Resultados | 35-40 | Evaluación empírica y discusión |
| 6. Justificación IA | 20-25 | Argumentación de LLMs soberanos |
| 7. Justificación MCP | 20-25 | Argumentación de Model Context Protocol |
| 8. Conclusiones | 18-22 | Síntesis y trabajo futuro |
| Apéndices | 70-85 | Material suplementario (A-H) |
| Referencias | 12-15 | Bibliografía APA (85+ referencias) |
| **Total** | **320-380** | |

---

## Documentos de la Tesis

### Sección Preliminar
1. `PORTADA_TESIS.md` - Portada institucional UNDEF/IUA
2. `SECCION_PRELIMINAR.md` - Resumen, Abstract, Agradecimientos, Declaraciones

### Índices
3. `LISTA_DE_TABLAS.md` - 112 tablas
4. `LISTA_DE_FIGURAS.md` - 120 figuras
5. `LISTA_DE_ACRONIMOS.md` - 78 acrónimos
6. `GLOSARIO.md` - 95 términos

### Capítulos
7. `CAPITULO_INTRODUCCION.md` - Capítulo 1
8. `CAPITULO_MARCO_TEORICO.md` - Capítulo 2
9. `CAPITULO_ESTADO_DEL_ARTE.md` - Capítulo 3
10. `CAPITULO_DESARROLLO.md` - Capítulo 4
11. `CAPITULO_RESULTADOS.md` - Capítulo 5
12. `CAPITULO_JUSTIFICACION_IA_LLM_SOBERANO.md` - Capítulo 6
13. `CAPITULO_JUSTIFICACION_MCP.md` - Capítulo 7
14. `CAPITULO_TRABAJOS_FUTUROS.md` - Capítulo 8

### Apéndices
15. `APENDICE_SALIDAS_HERRAMIENTAS.md` - Apéndice A: Salidas de las 25 herramientas
16. `EVOLUCION_ARQUITECTONICA.md` - Apéndice B: Historia del proyecto (xAudit → MIESC v4.0)
17. `ARQUITECTURA_MCP_SERVER.md` - Apéndice C: Arquitectura del servidor MCP
18. `TABLAS_COMPARATIVAS.md` - Apéndice D: Tablas comparativas
19. `APENDICE_CODIGO_FUENTE.md` - Apéndice E: Código fuente representativo
20. `GLOSARIO.md` - Apéndice F: Glosario de 95 términos
21. `APENDICE_TECNICAS_ANALISIS.md` - Apéndice H: Fundamentos técnicos de análisis

### Referencias
22. `REFERENCIAS_BIBLIOGRAFICAS.md` - 85+ referencias APA

---

## Estadísticas del Documento

| Métrica | Valor |
|---------|-------|
| Capítulos principales | 8 |
| Apéndices | 8 (A-H) |
| Total de tablas | 112 |
| Total de figuras | 120 |
| Total de acrónimos | 78 |
| Total de términos en glosario | 95 |
| Total de referencias | 85+ |
| Páginas estimadas | 320-380 |
| Archivos markdown | 22 |

---

*Documento actualizado: 2025-11-29*
*MIESC v4.0.0*
*Maestría en Ciberdefensa - UNDEF/IUA*
