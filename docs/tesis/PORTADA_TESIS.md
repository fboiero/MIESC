# UNIVERSIDAD DE LA DEFENSA NACIONAL (UNDEF)

## Centro Regional Universitario Cordoba
## Instituto Universitario Aeronautico (IUA)

---

# MAESTRIA EN CIBERDEFENSA

---

## Trabajo Final de Maestria

# MIESC: Framework Multi-capa de Integracion de Herramientas para Seguridad de Smart Contracts

## Multi-layer Integration Framework for Smart Contract Security

---

**Autor:** Ing. Fernando Boiero

**Director:** Mg. Eduardo Casanovas

---

**Cordoba, Argentina**

**Noviembre 2024**

---

## Resumen

El presente trabajo propone MIESC (Multi-layer Integration for Ethereum Smart Contract Security), un framework de codigo abierto que integra 25 herramientas de analisis de seguridad en una arquitectura de 7 capas basada en el principio de Defense-in-Depth. El framework aborda la problematica de la fragmentacion de herramientas existentes, la heterogeneidad de sus salidas y la necesidad de soberania de datos en auditorias de smart contracts.

MIESC implementa: (1) un sistema de adaptadores basado en el patron Adapter para integrar herramientas heterogeneas; (2) un esquema de normalizacion que mapea hallazgos a taxonomias estandar (SWC, CWE, OWASP); (3) un backend de inteligencia artificial soberano basado en Ollama para analisis semantico sin transmision de codigo a servicios externos; y (4) una interfaz conversacional mediante Model Context Protocol (MCP) para integracion con asistentes de IA.

La evaluacion experimental sobre un corpus de contratos con vulnerabilidades conocidas demuestra que MIESC alcanza un recall del 100% en la deteccion de vulnerabilidades, representando una mejora del 40.8% respecto a la mejor herramienta individual. El proceso de deduplicacion reduce los hallazgos brutos en un 66%, y el costo operativo es de $0 gracias a la ejecucion completamente local.

**Palabras clave:** Smart Contracts, Seguridad Blockchain, Analisis Estatico, Ejecucion Simbolica, Verificacion Formal, Inteligencia Artificial, Defense-in-Depth, Ciberdefensa.

---

## Abstract

This work proposes MIESC (Multi-layer Integration for Ethereum Smart Contract Security), an open-source framework that integrates 25 security analysis tools in a 7-layer architecture based on the Defense-in-Depth principle. The framework addresses the fragmentation of existing tools, the heterogeneity of their outputs, and the need for data sovereignty in smart contract audits.

MIESC implements: (1) an adapter system based on the Adapter pattern to integrate heterogeneous tools; (2) a normalization schema that maps findings to standard taxonomies (SWC, CWE, OWASP); (3) a sovereign artificial intelligence backend based on Ollama for semantic analysis without transmitting code to external services; and (4) a conversational interface through Model Context Protocol (MCP) for integration with AI assistants.

Experimental evaluation on a corpus of contracts with known vulnerabilities demonstrates that MIESC achieves 100% recall in vulnerability detection, representing a 40.8% improvement over the best individual tool. The deduplication process reduces raw findings by 66%, and the operational cost is $0 thanks to fully local execution.

**Keywords:** Smart Contracts, Blockchain Security, Static Analysis, Symbolic Execution, Formal Verification, Artificial Intelligence, Defense-in-Depth, Cyber Defense.

---

## Datos Institucionales

**Universidad:** Universidad de la Defensa Nacional (UNDEF)

**Facultad/Instituto:** Centro Regional Universitario Cordoba - Instituto Universitario Aeronautico (IUA)

**Programa:** Maestria en Ciberdefensa

**Tipo de trabajo:** Trabajo Final de Maestria

**Area de conocimiento:** Ciberseguridad, Seguridad en Blockchain, Seguridad de Software

**Linea de investigacion:** Seguridad en Tecnologias Emergentes

---

## Declaracion de Originalidad

Declaro que este trabajo es de mi autoria, que no ha sido presentado previamente para ningun grado o calificacion profesional, y que he consultado las referencias bibliograficas que se incluyen en este documento.

El contenido de este trabajo es resultado de mi investigacion, excepto donde se indica lo contrario mediante citas.

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

*Documento generado como parte del Trabajo Final de Maestria en Ciberdefensa*
*UNDEF - IUA - CRU Cordoba*
*2024*
