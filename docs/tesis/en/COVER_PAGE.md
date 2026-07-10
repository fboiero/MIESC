# NATIONAL DEFENSE UNIVERSITY (UNDEF)

## Cordoba Regional University Center
## Aeronautical University Institute (IUA)

---

# MASTER'S IN CYBER DEFENSE

---

## Master's Thesis

# MIESC: Multi-layer Integration Framework for Smart Contract Security

## Framework de Integración Multi-capa para Seguridad de Smart Contracts

---

**Author:** Eng. Fernando Boiero

**Advisor:** M.Sc. Eduardo Casanovas

---

**Cordoba, Argentina**

**November 2024**

---

## Abstract

This work proposes MIESC (Multi-layer Integration for Ethereum Smart Contract Security), an open-source framework that integrates 25 security analysis tools in a 7-layer architecture based on the Defense-in-Depth principle. The framework addresses the fragmentation of existing tools, the heterogeneity of their outputs, and the need for data sovereignty in smart contract audits.

MIESC implements: (1) an adapter system based on the Adapter pattern to integrate heterogeneous tools; (2) a normalization schema that maps findings to standard taxonomies (SWC, CWE, OWASP); (3) a sovereign artificial intelligence backend based on Ollama for semantic analysis without transmitting code to external services; and (4) a conversational interface through Model Context Protocol (MCP) for integration with AI assistants.

Experimental evaluation on a corpus of 4 contracts with 29 documented vulnerabilities shows that MIESC exhibits a recall-first profile: it covers 100% of the documented vulnerabilities, with a type-aware detection (of the correct type/SWC) of 48% using static and pattern layers. Combining static tools does not surpass Slither alone; the real improvement comes from adding an LLM reasoning layer, which raises type-aware detection from 48% to 72%. The deduplication process reduces raw findings by 68% (385&rarr;123), and the operational cost is $0 thanks to fully local execution.

**Keywords:** Smart Contracts, Blockchain Security, Static Analysis, Symbolic Execution, Formal Verification, Artificial Intelligence, Defense-in-Depth, Cyber Defense.

---

## Resumen

El presente trabajo propone MIESC (Multi-layer Integration for Ethereum Smart Contract Security), un framework de código abierto que integra 25 herramientas de análisis de seguridad en una arquitectura de 7 capas basada en el principio de Defense-in-Depth. El framework aborda la problemática de la fragmentación de herramientas existentes, la heterogeneidad de sus salidas y la necesidad de soberanía de datos en auditorías de smart contracts.

MIESC implementa: (1) un sistema de adaptadores basado en el patrón Adapter para integrar herramientas heterogéneas; (2) un esquema de normalización que mapea hallazgos a taxonomías estándar (SWC, CWE, OWASP); (3) un backend de inteligencia artificial soberano basado en Ollama para análisis semántico sin transmisión de código a servicios externos; y (4) una interfaz conversacional mediante Model Context Protocol (MCP) para integración con asistentes de IA.

La evaluación experimental sobre un corpus de 4 contratos con 29 vulnerabilidades documentadas muestra que MIESC exhibe un perfil recall-first: cubre el 100% de las vulnerabilidades documentadas, con una detección type-aware (del tipo/SWC correcto) del 48% con capas estático y de patrón. Combinar herramientas estáticas no supera a Slither por sí sola; la mejora real proviene de agregar una capa de razonamiento LLM, que eleva la detección type-aware del 48% al 72%. El proceso de deduplicación reduce los hallazgos brutos en un 68% (385&rarr;123), y el costo operativo es de $0 gracias a la ejecución completamente local.

**Palabras clave:** Smart Contracts, Seguridad Blockchain, Análisis Estático, Ejecución Simbólica, Verificación Formal, Inteligencia Artificial, Defense-in-Depth, Ciberdefensa.

---

## Institutional Information

**University:** National Defense University (UNDEF)

**Faculty/Institute:** Cordoba Regional University Center - Aeronautical University Institute (IUA)

**Program:** Master's in Cyber Defense

**Document Type:** Master's Thesis

**Knowledge Area:** Cybersecurity, Blockchain Security, Software Security

**Research Line:** Security in Emerging Technologies

---

## Declaration of Originality

I declare that this work is my own authorship, that it has not been previously submitted for any degree or professional qualification, and that I have consulted the bibliographic references included in this document.

The content of this work is the result of my research, except where otherwise indicated by citations.

---

**Author's Signature:** ________________________________

**Date:** ________________________________

---

## Dedication

[Space reserved for dedication]

---

## Acknowledgments

[Space reserved for acknowledgments]

---

*Document generated as part of the Master's Thesis in Cyber Defense*
*UNDEF - IUA - CRU Cordoba*
*2024*
