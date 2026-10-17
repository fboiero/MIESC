# Capítulo 1: Introducción

## MIESC: Un Enfoque de Ciberdefensa para la Seguridad de Smart Contracts

## 1.1 Contexto y Motivación

### 1.1.1 La Emergencia del Ciberespacio como Dominio de Operaciones

El ciberespacio se ha consolidado como el quinto dominio de operaciones militares y de seguridad nacional, junto con tierra, mar, aire y espacio (Joint Chiefs of Staff, 2018). En este contexto, la protección de infraestructuras digitales críticas constituye una responsabilidad fundamental del Estado y un área prioritaria de la ciberdefensa (Libicki, 2009).

La tecnología blockchain, inicialmente concebida como infraestructura para sistemas de pago descentralizados (Nakamoto, 2008), ha evolucionado hasta sostener aplicaciones críticas en sectores estratégicos. Los sistemas financieros descentralizados (DeFi) gestionan más de $50 mil millones en activos digitales; las cadenas de suministro gubernamentales la emplean para la trazabilidad de materiales estratégicos y de defensa; los sistemas de identidad digital la usan para credenciales soberanas y documentos oficiales; la votación electrónica la aplica a procesos democráticos y consultas ciudadanas; y la tokenización de activos reales la convierte en infraestructura financiera regulada. Según Govea et al. (2024), estos sistemas constituyen potenciales infraestructuras críticas cuya seguridad tiene implicaciones directas para la soberanía y la seguridad nacional.

### 1.1.2 La Amenaza a los Smart Contracts

Los smart contracts son programas autónomos que se ejecutan en blockchains y gestionan activos digitales de valor económico real (Szabo, 1996; Atzei et al., 2017). A diferencia del software tradicional, presentan cuatro características que los vuelven particularmente críticos desde la perspectiva de la ciberdefensa. Son inmutables: una vez desplegados, sus vulnerabilidades no pueden corregirse de manera trivial. Son transparentes: el código es público, lo que permite a los adversarios estudiar sus debilidades. Gestionan valor directo, cuya pérdida es inmediata e irreversible. Y se ejecutan de forma autónoma, sin intervención humana que pueda detener un ataque en curso.

El impacto económico de las vulnerabilidades en smart contracts es significativo. Según Chainalysis (2024):

> "Las pérdidas acumuladas por explotación de vulnerabilidades en smart contracts superan los $7.8 mil millones entre 2016 y 2024, con un incremento del 58% en ataques sofisticados durante el último año." (traducción propia)

**Tabla 1.1.** Incidentes históricos críticos en smart contracts

| Año | Incidente | Pérdida | Vulnerabilidad |
|-----|-----------|---------|----------------|
| 2016 | The DAO | $60M | Reentrancy (SWC-107) |
| 2017 | Parity Wallet | $150M (fondos congelados) | Access Control (SWC-105/106) |
| 2018 | BEC Token | Colapso de la cotización del token (sin monto directo verificable) | Integer Overflow (SWC-101) |
| 2021 | Cream Finance | $130M | Oracle Manipulation |
| 2022 | Wormhole | $320M | Signature Verification |
| 2022 | Ronin Bridge | $625M | Private Key Compromise |
| 2023 | Euler Finance | $197M | Flash Loan + Reentrancy |

### 1.1.3 La Fragmentación del Ecosistema de Herramientas

El campo de la seguridad de smart contracts ha visto surgir numerosas herramientas especializadas, cada una con fortalezas y limitaciones propias (Ivanov et al., 2023). Esa abundancia, sin embargo, no se traduce en una capacidad de análisis integrada, sino en un ecosistema fragmentado en tres sentidos. En primer lugar, los enfoques son heterogéneos: conviven analizadores estáticos (Slither, Solhint), fuzzers (Echidna, Medusa), ejecutores simbólicos (Mythril, Manticore), verificadores formales (Certora, Halmos) y analizadores basados en IA (GPTScan). En segundo lugar, sus salidas son incompatibles: una misma vulnerabilidad recibe nombres distintos según la herramienta, los niveles de severidad no son consistentes y los formatos de reporte difieren. En tercer lugar, la cobertura de cada herramienta es incompleta: ninguna detecta por sí sola todas las vulnerabilidades y, en la evaluación empírica de Durieux et al. (2020), la mejor de ellas identifica apenas el 27% de las vulnerabilidades anotadas, y las nueve combinadas, el 42%. Es este último aspecto el que motiva de manera directa el enfoque combinado que propone este trabajo.

### 1.1.4 La Necesidad de Soberanía de Datos

En el contexto de la ciberdefensa, la confidencialidad del código auditado es crítica. Según Zhang et al. (2025), el uso de servicios de IA en la nube para el análisis de código presenta cuatro riesgos: la exposición de propiedad intelectual, al enviarse el código fuente a terceros; la dependencia de servicios externos, con la consiguiente pérdida de capacidad operativa si el servicio deja de estar disponible; el incumplimiento normativo, dado que GDPR, LGPD y las regulaciones nacionales restringen la transmisión de datos sensibles; y la falta de trazabilidad, por la imposibilidad de auditar el procesamiento realizado.

## 1.2 Planteamiento del Problema

### 1.2.1 Problema Principal

Las organizaciones que desarrollan o auditan smart contracts se enfrentan a un ecosistema fragmentado de herramientas de seguridad, cada una con capacidades parciales, salidas heterogéneas y requisitos de configuración propios. Esta fragmentación tiene consecuencias concretas sobre la auditoría. Ejecutar manualmente múltiples herramientas aumenta el tiempo y el costo del proceso; como cada una reporta la misma vulnerabilidad de manera distinta, los resultados son inconsistentes; dado que ninguna cubre todas las vulnerabilidades, persisten falsos negativos; y la necesidad de consolidar hallazgos provenientes de fuentes diversas dificulta, finalmente, la toma de decisiones.

### 1.2.2 Problemas Específicos

**P1:** No existe un framework que integre de forma coherente las principales herramientas de análisis de seguridad de smart contracts.

**P2:** Las salidas de las herramientas existentes utilizan nomenclaturas y formatos incompatibles, dificultando la correlación y deduplicación de hallazgos.

**P3:** Las soluciones existentes que utilizan IA dependen de servicios externos (OpenAI, Anthropic), comprometiendo la confidencialidad del código analizado.

**P4:** No existe una arquitectura que aplique el principio de Defense-in-Depth a la seguridad de smart contracts.

## 1.3 Objetivos

### 1.3.1 Objetivo General

Diseñar e implementar MIESC (Multi-layer Integration for Ethereum Smart Contract Security), un framework de código abierto que integre múltiples herramientas de análisis de seguridad en una arquitectura de capas basada en Defense-in-Depth, con un modo de ejecución completamente local que preserva la soberanía de datos.

### 1.3.2 Objetivos Específicos

**OE1: Integración de Herramientas**
Integrar al menos 20 herramientas de análisis de seguridad de smart contracts, cubriendo las categorías de análisis estático, fuzzing, ejecución simbólica, verificación formal y análisis basado en IA.

**OE2: Normalización de Salidas**
Diseñar un esquema de normalización que mapee los hallazgos de todas las herramientas a taxonomías estándar (SWC, CWE, OWASP), permitiendo correlación y deduplicación efectiva.

**OE3: Arquitectura Defense-in-Depth**
Implementar una arquitectura de 7 capas donde cada capa proporcione capacidades complementarias de detección, siguiendo el principio de Defense-in-Depth.

**OE4: Soberanía de Datos**
Implementar un backend de IA soberano basado en Ollama que permita análisis semántico sin transmisión de código a servicios externos.

**OE5: Interfaz Conversacional**
Desarrollar un servidor MCP (Model Context Protocol) que permita interacción con asistentes de IA modernos (Claude, GPT) manteniendo el servidor y las herramientas en la infraestructura local; el contenido que el servidor devuelve al asistente queda sujeto a la política de datos del proveedor del cliente.

## 1.4 Preguntas de Investigación

El presente trabajo busca responder las siguientes preguntas de investigación:

**RQ1:** ¿Es posible integrar herramientas heterogéneas de análisis de seguridad de smart contracts en un framework unificado mediante el patrón Adapter?

**RQ2:** ¿Una arquitectura de capas basada en Defense-in-Depth mejora la tasa de detección de vulnerabilidades respecto a herramientas individuales?

**RQ3:** ¿Cuál es el impacto de la normalización y deduplicación en la calidad de los reportes de seguridad?

**RQ4:** ¿Es viable operar MIESC en producción —tiempo de ejecución, recursos y costo— y qué calidad de análisis semántico ofrece un LLM local (Ollama) frente a los servicios comerciales?

## 1.5 Hipótesis

**H1:** Un framework que integre múltiples herramientas de análisis de seguridad mediante el patrón Adapter puede alcanzar una tasa de detección superior a cualquier herramienta individual.

**H2:** La normalización de hallazgos a taxonomías estándar (SWC, CWE) permite reducir significativamente los hallazgos duplicados sin pérdida de información.

**H3:** La ejecución de LLMs locales mediante Ollama proporciona capacidades de análisis semántico comparables a servicios comerciales, con costo operativo cercano a cero.

Las tres hipótesis se someten a prueba en el Capítulo 5 y se evalúan una por una en la sección 8.1.4. Conviene anticipar que el resultado no fue el esperado en dos de ellas: la combinación de herramientas estáticas no superó a la mejor de ellas, de modo que H1 solo se sostiene cuando se incorpora razonamiento semántico, y H3 no se sostiene tal como está formulada, porque la configuración completamente local quedó por debajo de los modelos comerciales en el corpus evaluado (§5.3.3–5.3.4). Ese resultado, lejos de invalidar el trabajo, reorienta su argumento central.

## 1.6 Justificación

### 1.6.1 Relevancia para la Ciberdefensa

El trabajo se inscribe en el campo de la ciberdefensa por cuatro razones. Los sistemas blockchain gestionan una proporción creciente de activos y procesos críticos, de modo que su protección forma parte de la protección de infraestructuras críticas. La dependencia de herramientas y servicios extranjeros para auditarlos compromete, a su vez, la autonomía operativa, lo que vincula el problema con la soberanía tecnológica. Un framework integrado, por otra parte, acelera la detección de vulnerabilidades y la respuesta ante ellas. Por último, la propuesta traslada a un dominio emergente un principio central de la ciberdefensa: la defensa en profundidad.

### 1.6.2 Relevancia Académica

En el plano académico, el trabajo muestra la viabilidad del patrón Adapter para integrar sistemas heterogéneos, propone un esquema de normalización reproducible basado en taxonomías estándar, evalúa empíricamente las capacidades de los LLM locales para el análisis de código y aplica, sometiéndolo a validación, el principio de Defense-in-Depth en un dominio no tradicional.

### 1.6.3 Relevancia Práctica

En el plano práctico, MIESC se ofrece como una herramienta de código abierto disponible para organizaciones y auditores. Cuando los modelos de IA se ejecutan localmente, el costo operativo de ese componente es nulo; la automatización del proceso de auditoría mejora su eficiencia; y, al no transmitirse el código a terceros en ese modo, se facilita el cumplimiento de las exigencias normativas de confidencialidad.

## 1.7 Alcance y Limitaciones

### 1.7.1 Alcance

El presente trabajo incluye:

1. **Blockchain objetivo:** Ethereum y blockchains compatibles con EVM
2. **Lenguaje:** Smart contracts escritos en Solidity (versiones 0.4.x a 0.8.x)
3. **Herramientas:** Integración de 25 herramientas de análisis
4. **Interfaces:** API REST y servidor MCP
5. **Evaluación:** Corpus de contratos con vulnerabilidades conocidas

### 1.7.2 Limitaciones

El trabajo no incluye:

1. **Otras blockchains:** Solana, Cardano, Polkadot (trabajo futuro)
2. **Otros lenguajes:** Vyper, Move, Rust (trabajo futuro)
3. **Monitoreo en producción:** Análisis post-deployment (trabajo futuro)
4. **Auditorías manuales:** El framework complementa, no reemplaza, revisión humana

## 1.8 Metodología

### 1.8.1 Tipo de Investigación

Investigación aplicada de carácter experimental, con desarrollo de artefacto de software y validación empírica.

### 1.8.2 Metodología de Desarrollo

Se adopta un enfoque iterativo-incremental:

1. **Fase 1:** Investigación y selección de herramientas
2. **Fase 2:** Diseño de arquitectura y esquema de normalización
3. **Fase 3:** Implementación de adaptadores
4. **Fase 4:** Integración de componentes de IA
5. **Fase 5:** Evaluación experimental
6. **Fase 6:** Documentación y publicación

### 1.8.3 Metodología de Evaluación

La evaluación incluye:

1. **Métricas de detección:** Precisión, Recall, F1-Score
2. **Comparación con baseline:** Herramientas individuales
3. **Análisis de deduplicación:** Reducción de hallazgos
4. **Evaluación cualitativa:** usabilidad y tiempo de auditoría (prevista en el diseño; no se realizó un estudio formal de usabilidad, véase §5.8)

## 1.9 Contribuciones

Las principales contribuciones del presente trabajo son:

**C1:** MIESC, un framework de código abierto que integra 25 herramientas de análisis de seguridad

**C2:** Arquitectura de 7 capas basada en Defense-in-Depth para seguridad de smart contracts

**C3:** Esquema de normalización basado en SWC/CWE/OWASP

**C4:** Implementación de backend de IA soberano con Ollama

**C5:** Servidor MCP para integración con asistentes de IA modernos

**C6:** Evaluación empírica sobre corpus de vulnerabilidades conocidas

**C7:** Por último, el trabajo sostiene una tesis de alcance más general: que el control sobre la herramienta —pesos abiertos y ejecución auditable— constituye un requisito de primer orden del análisis de seguridad, y no una mera preferencia. Esta tesis se fundamenta en cuatro planos (Capítulo 6, sección 6.6.3): el doctrinal, propio de la ciberdefensa; el científico, vinculado a la reproducibilidad pericial; el epistemológico, relativo a la autoría y la rendición de cuentas; y el filosófico, a partir de Illich, Floridi, Stallman y Winner. Cuenta, además, con un respaldo empírico acotado: bajo el protocolo de matcher laxo, un modelo de pesos abiertos registra la mayor precisión y F1 de la comparación con un costo entre 15 y 69 veces menor, aunque ese protocolo es una estimación optimista que no habilita un ranking confiable de proveedores. El ordenamiento bajo el juez oficial queda planteado como trabajo futuro (Capítulo 8).

## 1.10 Estructura del Documento

El documento se organiza en ocho capítulos. Tras esta introducción, que presenta el contexto, el problema, los objetivos y la metodología, el Capítulo 2 desarrolla el marco teórico: los fundamentos de ciberdefensa y blockchain, las taxonomías de vulnerabilidades, las técnicas de análisis y los patrones de diseño que sustentan la propuesta. El Capítulo 3 revisa el estado del arte —herramientas existentes y estudios comparativos— e identifica las brechas que motivan el trabajo. El Capítulo 4 describe el desarrollo e implementación de MIESC: su arquitectura, el diseño de las capas y la implementación de los adaptadores. El Capítulo 5 presenta los resultados experimentales, con las métricas de detección, la comparación con el baseline y el análisis estadístico de las diferencias. Los Capítulos 6 y 7 exponen la justificación de dos decisiones arquitectónicas: el uso de IA y LLM soberanos, y la incorporación del servidor MCP. El Capítulo 8 sintetiza las conclusiones, evalúa las hipótesis y las contribuciones, y traza las líneas de trabajo futuro, incluidas las publicaciones derivadas. Los apéndices reúnen las salidas de las herramientas, la evolución arquitectónica y las tablas comparativas.

## 1.11 Referencias del Capítulo

Atzei, N., Bartoletti, M., & Cimoli, T. (2017). A survey of attacks on Ethereum smart contracts (SoK). In *International Conference on Principles of Security and Trust* (pp. 164-186). Springer. https://doi.org/10.1007/978-3-662-54455-6_8

Chainalysis. (2024). *The 2024 Crypto Crime Report*. Chainalysis Inc.

Durieux, T., Ferreira, J. F., Abreu, R., & Cruz, P. (2020). Empirical review of automated analysis tools on 47,587 Ethereum smart contracts. In *Proceedings of the ACM/IEEE 42nd International Conference on Software Engineering* (pp. 530-541). ACM. https://doi.org/10.1145/3377811.3380364

Ivanov, N., Li, C., Yan, Q., Sun, Z., Cao, Z., & Luo, X. (2023). Security defense for smart contracts: A comprehensive survey. *arXiv preprint arXiv:2302.07347*. https://arxiv.org/abs/2302.07347

Joint Chiefs of Staff. (2018). *Cyberspace Operations (JP 3-12)*. U.S. Department of Defense.

Libicki, M. C. (2009). *Cyberdeterrence and Cyberwar*. RAND Corporation.

Nakamoto, S. (2008). Bitcoin: A peer-to-peer electronic cash system. https://bitcoin.org/bitcoin.pdf

Szabo, N. (1996). Smart contracts: Building blocks for digital markets. *Extropy, 16*(16), 1-10.

Zhang, J., Bu, H., Wen, H., Liu, Y., Fei, H., Xi, R., Li, L., Yang, Y., Zhu, H., & Meng, D. (2025). When LLMs meet cybersecurity: A systematic literature review. *Cybersecurity, 8*(1), Article 55. https://doi.org/10.1186/s42400-025-00361-w
