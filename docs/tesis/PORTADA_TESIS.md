# UNIVERSIDAD DE LA DEFENSA NACIONAL (UNDEF)

## Centro Regional Universitario Córdoba
## Instituto Universitario Aeronáutico (IUA)

---

# MAESTRÍA EN CIBERDEFENSA

---

## Trabajo Final de Maestría

# MIESC: Framework Multi-capa de Integración de Herramientas para Seguridad de Smart Contracts

## Multi-layer Integration Framework for Smart Contract Security

---

**Autor:** Ing. Fernando Boiero

**Director:** Mg. Eduardo Casanovas

---

**Córdoba, Argentina**

**Noviembre 2024**

---

## Resumen

El presente trabajo propone MIESC (Multi-layer Integration for Ethereum Smart Contract Security), un framework de código abierto que integra 25 herramientas de análisis de seguridad en una arquitectura de 7 capas basada en el principio de Defense-in-Depth. El framework aborda la problemática de la fragmentación de herramientas existentes, la heterogeneidad de sus salidas y la necesidad de soberanía de datos en auditorías de smart contracts.

MIESC implementa: (1) un sistema de adaptadores basado en el patrón Adapter para integrar herramientas heterogéneas; (2) un esquema de normalización que mapea hallazgos a taxonomías estándar (SWC, CWE, OWASP); (3) un backend de inteligencia artificial soberano basado en Ollama para análisis semántico sin transmisión de código a servicios externos; y (4) una interfaz conversacional mediante Model Context Protocol (MCP) para integración con asistentes de IA.

La evaluación experimental sobre un corpus de 4 contratos con 29 vulnerabilidades documentadas muestra que MIESC exhibe un perfil recall-first: cubre el 100% de las vulnerabilidades documentadas, con una detección type-aware (del tipo/SWC correcto) del 48% con capas estático y de patrón. Combinar herramientas estáticas no supera a Slither por si sola; la mejora real proviene de agregar una capa de razonamiento LLM, que eleva la detección type-aware del 48% al 72%. El proceso de deduplicación reduce los hallazgos brutos en un 68% (385&rarr;123), y el costo operativo es de $0 gracias a la ejecución completamente local.

**Palabras clave:** Smart Contracts, Seguridad Blockchain, Análisis Estático, Ejecución Simbólica, Verificación Formal, Inteligencia Artificial, Defense-in-Depth, Ciberdefensa.

---

## Abstract

This work proposes MIESC (Multi-layer Integration for Ethereum Smart Contract Security), an open-source framework that integrates 25 security analysis tools in a 7-layer architecture based on the Defense-in-Depth principle. The framework addresses the fragmentation of existing tools, the heterogeneity of their outputs, and the need for data sovereignty in smart contract audits.

MIESC implements: (1) an adapter system based on the Adapter pattern to integrate heterogeneous tools; (2) a normalization schema that maps findings to standard taxonomies (SWC, CWE, OWASP); (3) a sovereign artificial intelligence backend based on Ollama for semantic analysis without transmitting code to external services; and (4) a conversational interface through Model Context Protocol (MCP) for integration with AI assistants.

Experimental evaluation on a corpus of 4 contracts with 29 documented vulnerabilities shows that MIESC exhibits a recall-first profile: it covers 100% of the documented vulnerabilities, with a type-aware detection (of the correct type/SWC) of 48% using static and pattern layers. Combining static tools does not surpass Slither alone; the real improvement comes from adding an LLM reasoning layer, which raises type-aware detection from 48% to 72%. The deduplication process reduces raw findings by 68% (385&rarr;123), and the operational cost is $0 thanks to fully local execution.

**Keywords:** Smart Contracts, Blockchain Security, Static Analysis, Symbolic Execution, Formal Verification, Artificial Intelligence, Defense-in-Depth, Cyber Defense.

---

## Datos Institucionales

**Universidad:** Universidad de la Defensa Nacional (UNDEF)

**Facultad/Instituto:** Centro Regional Universitario Córdoba - Instituto Universitario Aeronáutico (IUA)

**Programa:** Maestría en Ciberdefensa

**Tipo de trabajo:** Trabajo Final de Maestría

**Área de conocimiento:** Ciberseguridad, Seguridad en Blockchain, Seguridad de Software

**Línea de investigación:** Seguridad en Tecnologías Emergentes

---

## Declaración de Originalidad

Declaro que este trabajo es de mi autoría, que no ha sido presentado previamente para ningún grado o calificación profesional, y que he consultado las referencias bibliográficas que se incluyen en este documento.

El contenido de este trabajo es resultado de mi investigación, excepto donde se indica lo contrario mediante citas.

---

**Firma del Autor:** ________________________________

**Fecha:** ________________________________

---

## Dedicatoria

[Espacio reservado para dedicatoria]

---

## Agradecimientos

[Espacio reservado para agradecimientos]

---

*UNDEF - IUA - CRU Córdoba*
*2024*
