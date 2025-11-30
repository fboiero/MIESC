# Sección Preliminar

---

## Información Institucional

**MAESTRÍA EN CIBERDEFENSA**

**TESIS DE POSGRADO**

**MIESC: MARCO INTEGRADO PARA EVALUACIÓN DE SEGURIDAD EN CONTRATOS INTELIGENTES**

*Framework Multi-capa de 7 Capas con 25 Herramientas de Análisis, IA Soberana y Model Context Protocol*

**Autor:** Ing. Fernando Boiero

**Director de Tesis:** Mg. Eduardo Casanovas

**Institución:** Universidad de la Defensa Nacional (UNDEF) - Instituto Universitario Aeronáutico (IUA)

**Lugar y Fecha:** Córdoba, Provincia de Córdoba, Noviembre 2025

---

## Resumen

El presente trabajo de Maestría en Ciberdefensa presenta MIESC (Multi-layer Integration for Ethereum Smart Contract Security), un framework de código abierto que implementa una arquitectura de defensa en profundidad de 7 capas para la auditoría automatizada de contratos inteligentes en blockchain Ethereum.

La investigación aborda la problemática de la fragmentación de herramientas de análisis de seguridad existentes, la heterogeneidad de sus formatos de salida, y la dependencia de servicios comerciales que comprometen la soberanía de datos en auditorías de código fuente confidencial. Desde la perspectiva de ciberdefensa, los sistemas blockchain constituyen infraestructuras críticas emergentes cuya seguridad tiene implicaciones directas para la soberanía tecnológica y la protección de activos digitales.

MIESC integra 25 herramientas de seguridad organizadas en 7 capas complementarias: (1) análisis estático, (2) testing dinámico mediante fuzzing, (3) ejecución simbólica, (4) testing de invariantes, (5) verificación formal, (6) property testing, y (7) análisis con inteligencia artificial. El framework implementa el patrón de diseño Adapter para unificar interfaces heterogéneas y un esquema de normalización que mapea hallazgos a taxonomías estándar (SWC, CWE, OWASP).

Una contribución distintiva es la implementación de un backend de IA soberano basado en Ollama, que permite análisis semántico de código sin transmisión a servicios externos, garantizando la confidencialidad del código auditado. Adicionalmente, se desarrolló un servidor Model Context Protocol (MCP) que habilita la interacción con asistentes de IA modernos como Claude, manteniendo el procesamiento completamente local.

La evaluación experimental sobre un corpus de contratos con vulnerabilidades conocidas demuestra que MIESC alcanza un recall del 100% en detección de vulnerabilidades, representando una mejora del 40.8% respecto a la mejor herramienta individual (Slither). El proceso de deduplicación reduce los hallazgos duplicados en un 66%, mejorando la calidad de los reportes de auditoría. El costo operativo del framework es de $0 gracias a la ejecución completamente local.

El trabajo contribuye al campo de la ciberdefensa al proporcionar una herramienta de código abierto que: (1) aplica el principio de Defense-in-Depth a un dominio emergente, (2) garantiza soberanía de datos en análisis de seguridad, (3) democratiza el acceso a auditorías de smart contracts sin barreras de costo, y (4) establece un marco extensible para la investigación en seguridad de blockchain.

**Palabras clave:** Smart Contracts, Seguridad Blockchain, Ciberdefensa, Defense-in-Depth, Análisis Estático, Ejecución Simbólica, Verificación Formal, Fuzzing, Inteligencia Artificial, LLM Soberano, Model Context Protocol, Ethereum.

---

## Abstract

This Master's thesis in Cyber Defense presents MIESC (Multi-layer Integration for Ethereum Smart Contract Security), an open-source framework that implements a 7-layer defense-in-depth architecture for automated security auditing of smart contracts on the Ethereum blockchain.

The research addresses the fragmentation of existing security analysis tools, the heterogeneity of their output formats, and the dependency on commercial services that compromise data sovereignty in confidential source code audits. From a cyber defense perspective, blockchain systems constitute emerging critical infrastructure whose security has direct implications for technological sovereignty and digital asset protection.

MIESC integrates 25 security tools organized into 7 complementary layers: (1) static analysis, (2) dynamic testing through fuzzing, (3) symbolic execution, (4) invariant testing, (5) formal verification, (6) property testing, and (7) artificial intelligence analysis. The framework implements the Adapter design pattern to unify heterogeneous interfaces and a normalization schema that maps findings to standard taxonomies (SWC, CWE, OWASP).

A distinctive contribution is the implementation of a sovereign AI backend based on Ollama, which enables semantic code analysis without transmission to external services, ensuring the confidentiality of audited code. Additionally, a Model Context Protocol (MCP) server was developed that enables interaction with modern AI assistants like Claude while maintaining entirely local processing.

Experimental evaluation on a corpus of contracts with known vulnerabilities demonstrates that MIESC achieves 100% recall in vulnerability detection, representing a 40.8% improvement over the best individual tool (Slither). The deduplication process reduces duplicate findings by 66%, improving audit report quality. The framework's operational cost is $0 due to entirely local execution.

This work contributes to the cyber defense field by providing an open-source tool that: (1) applies the Defense-in-Depth principle to an emerging domain, (2) guarantees data sovereignty in security analysis, (3) democratizes access to smart contract audits without cost barriers, and (4) establishes an extensible framework for blockchain security research.

**Keywords:** Smart Contracts, Blockchain Security, Cyber Defense, Defense-in-Depth, Static Analysis, Symbolic Execution, Formal Verification, Fuzzing, Artificial Intelligence, Sovereign LLM, Model Context Protocol, Ethereum.

---

## Dedicatoria

A mi familia, por su apoyo incondicional en cada etapa de este camino académico y profesional.

A la comunidad blockchain, por inspirar esta investigación y demostrar que la tecnología descentralizada puede transformar la forma en que establecemos confianza digital.

A la comunidad open source, cuyo espíritu colaborativo y compromiso con el conocimiento libre ha hecho posible este trabajo. En ese mismo espíritu, MIESC será publicado como software libre para contribuir al ecosistema de seguridad en blockchain.

---

## Agradecimientos

A mi familia, por su apoyo incondicional en cada uno de estos hitos académicos y profesionales.

A mi director de tesis, Mg. Eduardo Casanovas, por su guía experta, paciencia y dedicación durante el desarrollo de esta investigación.

Al Instituto Universitario Aeronáutico (IUA) y la Universidad de la Defensa Nacional (UNDEF), por proporcionar el marco académico de excelencia y los recursos necesarios.

Al equipo de Xcapit, por brindarme un espacio, tiempo y la confianza para desarrollar este framework dentro de nuestra organización.

A la comunidad de código abierto que desarrolla y mantiene las herramientas de seguridad integradas en MIESC, cuyo trabajo desinteresado hace posible el avance de la seguridad informática.

A Trail of Bits, ConsenSys, Certora, y demás organizaciones que han desarrollado herramientas de análisis de smart contracts, sentando las bases sobre las cuales este trabajo construye.

A Anthropic, por el desarrollo del Model Context Protocol que ha permitido la integración innovadora entre MIESC y asistentes de IA.

A Meta AI y la comunidad Ollama, por democratizar el acceso a modelos de lenguaje de código abierto, habilitando la implementación de IA soberana.

A mis compañeros de la Maestría, por el intercambio de ideas y el apoyo mutuo durante este proceso formativo.

Este trabajo no hubiera sido posible sin la contribución de cada uno de ustedes.

---

## Declaración de Herramientas Tecnológicas

En la elaboración de este documento se utilizó asistencia de inteligencia artificial (Claude de Anthropic) para tareas de edición, condensación de contenido y formato, siempre bajo supervisión y validación del autor. La investigación, experimentación, análisis de resultados y conclusiones son producto del trabajo original del autor.

---

## Licencia y Disponibilidad

Este trabajo de investigación y el software MIESC (Marco Integrado para Evaluación de Seguridad en Contratos Inteligentes) se publican bajo los siguientes términos:

### Licencia del Documento

Esta tesis está disponible bajo licencia **Creative Commons Atribución 4.0 Internacional (CC BY 4.0)**. Se permite copiar, distribuir, exhibir y ejecutar el trabajo, así como hacer obras derivadas, bajo las siguientes condiciones:

- **Atribución:** Se debe dar crédito apropiado al autor original
- Se debe proporcionar un enlace a la licencia
- Se debe indicar si se realizaron cambios

### Licencia del Software

El código fuente de MIESC se publica bajo licencia **GNU Affero General Public License v3.0 (AGPL-3.0)**. Esta licencia garantiza que el software permanezca libre y de código abierto, requiriendo que cualquier versión modificada también sea publicada bajo AGPL-3.0. Esto incluye modificaciones utilizadas en servicios web, asegurando que los usuarios de servicios en red basados en MIESC tengan acceso al código fuente.

### Repositorios y Recursos

**Código Fuente:**
- GitHub: https://github.com/fboiero/MIESC
- Contenido: Implementación completa del framework MIESC, scripts de análisis, dataset de evaluación (anonimizado), documentación técnica

**Sitio Web del Proyecto:**
- https://fboiero.github.io/MIESC/
- Contenido: Documentación interactiva, guías de uso y ejemplos, resultados de benchmarks

### Contacto del Autor

- **Nombre:** Fernando Boiero
- **Email:** fboiero@frvm.utn.edu.ar
- **LinkedIn:** https://www.linkedin.com/in/fboiero/
- **ORCID:** 0009-0005-7935-2758

El autor alienta la colaboración y contribución de la comunidad para mejorar continuamente el framework MIESC y avanzar en el estado del arte de la seguridad en contratos inteligentes.

---

## Declaración de Autoría

Declaro bajo juramento que el presente Trabajo Final de Maestría titulado "MIESC: Framework Multi-capa de Integración de Herramientas para Seguridad de Smart Contracts" es de mi exclusiva autoría.

Declaro que:

1. Este trabajo no ha sido presentado previamente para la obtención de ningún otro grado académico o título profesional.

2. La investigación contenida en este documento es resultado de mi trabajo personal, excepto donde se indica explícitamente mediante citas y referencias bibliográficas.

3. Todo el código fuente desarrollado es de mi autoría, y las herramientas de terceros utilizadas se encuentran debidamente identificadas y referenciadas.

4. He cumplido con las normas de integridad académica establecidas por la Universidad de la Defensa Nacional.

5. He consultado y citado todas las fuentes bibliográficas utilizadas, siguiendo el formato APA 7ma edición.

Por lo tanto, asumo la responsabilidad total por el contenido de este trabajo ante cualquier reclamo de plagio o uso indebido de propiedad intelectual.

---

**Firma del Autor:** ________________________________

**Ing. Fernando Boiero**

**DNI:** ________________________________

**Lugar y Fecha:** Córdoba, Argentina, Noviembre 2025

---

## Declaración de Originalidad del Software

El software MIESC (Multi-layer Integration for Ethereum Smart Contract Security) desarrollado como parte de este trabajo de tesis:

1. **Es de código abierto** y se distribuye bajo licencia AGPL-3.0, garantizando que el software permanezca libre y de código abierto.

2. **Integra 25 herramientas de terceros** organizadas en 7 capas, que mantienen sus licencias originales:
   - **Capa 1 - Análisis Estático:** Slither (AGPL-3.0), Solhint (MIT), Securify2 (Apache-2.0), Semgrep (LGPL-2.1)
   - **Capa 2 - Testing Dinámico:** Echidna (AGPL-3.0), Foundry (MIT/Apache-2.0), Medusa (AGPL-3.0), Vertigo (MIT)
   - **Capa 3 - Ejecución Simbólica:** Mythril (MIT), Manticore (AGPL-3.0), Oyente (BSD-3)
   - **Capa 4 - Testing de Invariantes:** Scribble (Apache-2.0), Halmos (MIT)
   - **Capa 5 - Verificación Formal:** SMTChecker (GPL-3.0), Certora Prover (Commercial)
   - **Capa 6 - Property Testing:** PropertyGPT (MIT), Aderyn (MIT), Wake (MIT)
   - **Capa 7 - Análisis con IA:** GPTScan, SmartLLM, LLMSmartAudit, ThreatModel, GasGauge, UpgradeGuard, BestPractices

3. **Los 25 adaptadores e integraciones** desarrollados específicamente para MIESC son de autoría propia.

4. **El servidor MCP** y los componentes de integración con IA soberana (Ollama) son desarrollos originales de este trabajo.

5. **El código está disponible públicamente** para revisión, auditoría y contribuciones de la comunidad.

---

**Repositorio:** https://github.com/fboiero/MIESC

**Licencia:** GNU Affero General Public License v3.0 (AGPL-3.0)

**Copyright:** (c) 2025 Fernando Boiero

---

*Documento actualizado: 2025-11-29*
*MIESC v4.0.0 - 25 herramientas en 7 capas Defense-in-Depth*
