# Capítulo 2: Marco Teórico

## Fundamentos de Ciberdefensa y Seguridad en Smart Contracts

## 2.1 Ciberdefensa y Seguridad de Infraestructuras Críticas

### 2.1.1 Definición de Ciberdefensa

La ciberdefensa se define como el conjunto de acciones, medios y procedimientos tanto ofensivos como defensivos, destinados a asegurar el uso propio del ciberespacio y negarlo al enemigo (Joint Chiefs of Staff, 2018). En el contexto de las operaciones militares modernas, el ciberespacio constituye el quinto dominio de operaciones junto con tierra, mar, aire y espacio (Libicki, 2009).

Según el Marco de Ciberseguridad del NIST (National Institute of Standards and Technology, 2024), las capacidades de ciberdefensa se organizan en cinco funciones principales:

**Tabla 2.1.** Funciones del Marco NIST de Ciberseguridad

| Función | Descripción | Aplicación en Smart Contracts |
|---------|-------------|-------------------------------|
| **Identificar** | Comprender el contexto de riesgo | Inventario de activos digitales, dependencias |
| **Proteger** | Implementar salvaguardas | Controles de acceso, validación de entradas |
| **Detectar** | Identificar incidentes | Monitoreo de transacciones, análisis de código |
| **Responder** | Actuar ante incidentes | Pausar contratos, mecanismos de emergencia |
| **Recuperar** | Restaurar capacidades | Actualización de contratos, migración |

### 2.1.2 Blockchain como Infraestructura Crítica

La adopción creciente de blockchain en sectores estratégicos como finanzas, energía, logística y gobierno ha convertido esta tecnología en una infraestructura crítica potencial (Govea et al., 2024). Según Sayeed et al. (2020), los sistemas blockchain empleados en las finanzas descentralizadas, en las cadenas de suministro gubernamentales, en los sistemas de identidad digital y en los procesos de votación electrónica —sectores descritos en la sección 1.1.1— constituyen activos cuya protección es responsabilidad del Estado en el marco de la defensa nacional.

### 2.1.3 Relevancia para la Defensa Nacional

La protección de infraestructuras basadas en blockchain tiene implicaciones directas para la seguridad nacional (Govea et al., 2024):

> "Los ataques a smart contracts representan una amenaza emergente para la seguridad económica de las naciones, con pérdidas que superan los $7.8 mil millones entre 2016 y 2024" (Chainalysis, 2024; traducción propia).

Los vectores de amenaza identificados abarcan un espectro amplio de actores. Los actores estatales, organizados como grupos APT, tienen capacidad para explotar vulnerabilidades en contratos que gestionan activos soberanos; el crimen organizado aprovecha esas mismas vulnerabilidades para el lavado de activos; y el hacktivismo dirige ataques con motivación política contra protocolos DeFi. A ellos se suman las amenazas internas, provenientes de desarrolladores maliciosos o negligentes. La Figura 2.1 sistematiza esta taxonomía.

**Figura 2.1.** Taxonomía de amenazas a sistemas blockchain

![Figura 2.1 - Taxonomía de amenazas a sistemas blockchain](figures/Figura%201.%20Taxonomía%20de%20amenazas%20a%20sistemas%20blockchain.svg)

## 2.2 Blockchain y Smart Contracts

### 2.2.1 Definición de Blockchain

Una blockchain es una estructura de datos distribuida que consiste en una cadena de bloques enlazados criptográficamente, donde cada bloque contiene un conjunto de transacciones validadas (Nakamoto, 2008). En el contexto de ciberdefensa, las propiedades de blockchain presentan una dualidad:

**Tabla 2.2.** Propiedades de blockchain desde perspectiva de ciberdefensa

| Propiedad | Ventaja Defensiva | Riesgo Asociado |
|-----------|-------------------|-----------------|
| Inmutabilidad | Integridad garantizada de registros | Vulnerabilidades desplegadas son permanentes |
| Descentralización | Resistencia a ataques de punto único | Dificultad para respuesta coordinada |
| Transparencia | Auditabilidad pública | Atacantes pueden analizar código fuente |
| Determinismo | Comportamiento predecible | Explotación reproducible |
| Finalidad (*finality*) | Irreversibilidad de transacciones | Ataques exitosos no pueden revertirse |

### 2.2.2 Smart Contracts

Un smart contract es un programa computacional que se ejecuta de forma automática cuando se cumplen condiciones predefinidas (Szabo, 1996). Según la definición formal de Atzei et al. (2017):

> "Un smart contract es un programa determinista que se ejecuta en un ambiente de ejecución distribuido (la blockchain), maneja activos digitales, y cuyo comportamiento está completamente determinado por su código y el estado de la blockchain." (traducción propia)

Como se adelantó en la sección 1.1.2, cuatro características lo vuelven crítico desde la perspectiva de la seguridad: una vez desplegado opera sin intervención humana, gestiona activos digitales con valor real, expone su bytecode —y con frecuencia su código fuente— a los adversarios, y solo puede modificarse mediante patrones especiales de actualización.

### 2.2.3 Ethereum Virtual Machine (EVM)

La EVM es el entorno de ejecución para smart contracts en Ethereum y blockchains compatibles (Wood, 2014). Según Hildenbrandt et al. (2018), su semántica formal comprende una arquitectura basada en pila, de hasta 1024 elementos; un sistema de gas en el que cada operación consume unidades computacionales; un almacenamiento en tres niveles —*storage* persistente, *memory* temporal y la propia pila— y opcodes de llamada (CALL, DELEGATECALL, STATICCALL) con modelos de seguridad distintos.

## 2.3 Taxonomía de Vulnerabilidades

### 2.3.1 Smart Contract Weakness Classification (SWC)

El SWC Registry (Smart Contract Weakness Classification, 2020) proporciona una taxonomía estandarizada de vulnerabilidades. Vidal et al. (2024) proponen OpenSCV como una extensión jerárquica del SWC, organizando las debilidades en categorías:

**Tabla 2.3.** Categorías SWC críticas para ciberdefensa

| SWC ID | Nombre | Impacto en Ciberdefensa | Severidad |
|--------|--------|-------------------------|-----------|
| SWC-107 | Reentrancy | Pérdida total de fondos | CRÍTICA |
| SWC-101 | Integer Overflow/Underflow | Manipulación de balances | ALTA |
| SWC-104 | Unchecked Return Value | Falla silenciosa de transferencias | ALTA |
| SWC-105 | Unprotected Ether Withdrawal | Robo de fondos | CRÍTICA |
| SWC-106 | Unprotected SELFDESTRUCT | Destrucción de contrato | CRÍTICA |
| SWC-115 | Authorization vía tx.origin | Suplantación de identidad | ALTA |
| SWC-116 | Block Timestamp Dependence | Manipulación por mineros | MEDIA |
| SWC-120 | Weak Randomness | Predicción de resultados | ALTA |

### 2.3.2 Common Weakness Enumeration (CWE)

El CWE (MITRE, 2024) permite mapear vulnerabilidades de smart contracts a debilidades de software tradicional, facilitando la comunicación con equipos de ciberseguridad generales:

**Tabla 2.4.** Mapeo SWC a CWE

| SWC | CWE | Categoría CWE |
|-----|-----|---------------|
| SWC-107 | CWE-841 | Improper Enforcement of Behavioral Workflow |
| SWC-101 | CWE-190 | Integer Overflow or Wraparound |
| SWC-104 | CWE-252 | Unchecked Return Value |
| SWC-105 | CWE-284 | Improper Access Control |
| SWC-115 | CWE-287 | Improper Authentication |
| SWC-120 | CWE-330 | Use of Insufficiently Random Values |

### 2.3.3 OWASP Smart Contract Top 10

OWASP (2023) mantiene una clasificación de las 10 vulnerabilidades más críticas, actualizada según incidentes reales:

1. **Reentrancy:** $60M (The DAO, 2016)
2. **Integer Overflow/Underflow:** colapso de la cotización del token BEC (2018)
3. **Front-Running:** Pérdidas constantes en DEXs
4. **Oracle Manipulation:** $130M (Cream Finance, 2021)
5. **Denial of Service:** Bloqueo de fondos
6. **Access Control Issues:** $150M congelados (Parity Wallet, 2017)
7. **Unprotected Functions:** Múltiples incidentes
8. **Exploits de Puentes Cross-Chain:** ~$320M (incidente del puente Wormhole, febrero de 2022)
9. **Signature Malleability:** Robo de fondos
10. **Short Address Attack:** Manipulación de transferencias

## 2.4 Técnicas de Análisis de Seguridad

### 2.4.1 Análisis Estático

El análisis estático examina el código sin ejecutarlo (Aho et al., 2006). En el contexto de los smart contracts, Ivanov et al. (2023) distinguen tres familias de técnicas. El análisis de flujo de datos sigue el recorrido de las variables (*taint analysis*), lo que permite detectar la propagación de datos no confiables e identificar código muerto. El *pattern matching* busca patrones vulnerables conocidos mediante reglas definidas sobre el árbol de sintaxis abstracta (AST) y heurísticas de detección. La interpretación abstracta, por su parte, aproxima el comportamiento del programa para verificar propiedades sin ejecutarlo y constituye la base teórica de herramientas como Slither (Feist et al., 2019). Slither, Solhint, Securify2 y Aderyn son representativas de este enfoque.

### 2.4.2 Análisis Dinámico (Fuzzing)

El fuzzing genera entradas aleatorias o semi-dirigidas para descubrir comportamientos anómalos (Sutton et al., 2007). Según el estudio de He et al. (2019):

**Tabla 2.5.** Tipos de fuzzing en smart contracts

| Tipo | Descripción | Herramienta | Efectividad |
|------|-------------|-------------|-------------|
| Black-box | Sin conocimiento del código | Echidna básico | Media |
| Grey-box | Guiado por cobertura | Medusa | Alta |
| White-box | Con instrumentación | Foundry Fuzz | Alta |
| Property-based | Verifica invariantes | Echidna avanzado | Muy Alta |

### 2.4.3 Ejecución Simbólica

La ejecución simbólica trata las entradas como símbolos y explora caminos de ejecución (King, 1976). Según Mossberg et al. (2019), es particularmente efectiva para explorar caminos que dependen de valores específicos de entrada, como ilustra la Figura 2.2. Mythril (Mueller, 2018), Manticore (Mossberg et al., 2019) y Oyente (Luu et al., 2016) son sus exponentes en este dominio.

**Figura 2.2.** Ejecución concreta vs ejecución simbólica

![Figura 2.2 - Ejecución concreta vs ejecución simbólica](figures/Figura%203%20Ejecución%20concreta%20vs%20ejecución%20simbólica.svg)

### 2.4.4 Verificación Formal

La verificación formal emplea métodos matemáticos para probar propiedades de los programas (Hoare, 1969). Tolmach et al. (2021) identifican tres técnicas aplicadas a smart contracts. El *model checking* explora el espacio de estados en forma exhaustiva y verifica propiedades temporales; en el ecosistema Solidity lo implementa SMTChecker, con sus motores BMC y CHC. El *theorem proving* demuestra matemáticamente las propiedades a partir de especificaciones escritas en lenguajes formales, como ocurre con Certora Prover. El *bounded model checking*, finalmente, limita la verificación a una profundidad *k* y busca así un equilibrio entre completitud y escalabilidad; Halmos es su exponente en este dominio. La Tabla 2.6 compara las tres técnicas.

**Tabla 2.6.** Comparación de técnicas de verificación

| Técnica | Soundness | Completeness | Escalabilidad |
|---------|-----------|--------------|---------------|
| Model Checking | Alta | Alta | Baja |
| Theorem Proving | Completa | Completa | Media |
| Bounded MC | Limitada (k) | Limitada (k) | Alta |

## 2.5 Patrones de Diseño de Software

### 2.5.1 Patrón Adapter (Gamma et al., 1994)

El patrón Adapter convierte la interfaz de una clase en otra esperada por los clientes. MIESC utiliza este patrón para integrar herramientas heterogéneas:

**Figura 2.3.** Patrón Adapter en MIESC

![Figura 2.3 - Patrón Adapter en MIESC](figures/Figura%203.1.%20Patron%20Adapter%20en%20MIESC.svg)

### 2.5.2 Principios SOLID

MIESC implementa los principios SOLID (Martin, 2000):

| Principio | Aplicación en MIESC |
|-----------|---------------------|
| **S**ingle Responsibility | Cada adapter maneja una herramienta |
| **O**pen/Closed | Extensible mediante nuevos adapters |
| **L**iskov Substitution | Adapters son intercambiables |
| **I**nterface Segregation | ToolProtocol define interfaz mínima |
| **D**ependency Inversion | Dependencia de abstracciones |

### 2.5.3 Defense in Depth

Defense in Depth es una estrategia de seguridad que emplea múltiples capas de controles (Ross et al., 2016). Según la definición del glosario de seguridad nacional de los Estados Unidos, que el NIST adopta en sus publicaciones (Committee on National Security Systems, 2015):

> "Defense in depth is an information security strategy that integrates people, technology, and operations capabilities to establish variable barriers across multiple layers and missions of the organization."

Durieux et al. (2020) muestran empíricamente que ninguna herramienta individual detecta todas las clases de vulnerabilidades y que combinar herramientas complementarias aumenta la cobertura de detección, evidencia que sustenta el enfoque defense-in-depth.

**Figura 2.4.** Arquitectura Defense-in-Depth de MIESC

![Figura 2.4 - Arquitectura Defense-in-Depth de MIESC](figures/Figura%204%20Arquitectura%20Defense-in-Depth%20de%20MIESC.svg)

El principio es simple: cada capa aporta una protección complementaria y, si una de ellas no detecta una vulnerabilidad, las siguientes ofrecen oportunidades adicionales de detección. El Capítulo 5 muestra, sin embargo, que esa complementariedad no es automática entre herramientas de la misma naturaleza (§5.3.3).

## 2.6 Inteligencia Artificial en Ciberseguridad

### 2.6.1 Large Language Models (LLMs) en Seguridad

Los LLMs han emergido como herramientas prometedoras para el análisis de seguridad de código (Zhang et al., 2025). Según el estudio sistemático de Hou et al. (2024):

> "Los LLMs demuestran capacidades emergentes para detectar vulnerabilidades que escapan a herramientas tradicionales basadas en patrones, particularmente aquellas que requieren comprensión semántica del código." (traducción propia)

En la seguridad de smart contracts, sus aplicaciones abarcan la detección de vulnerabilidades mediante análisis semántico del código, la generación automática de propiedades e invariantes, la explicación de los hallazgos en lenguaje natural y la sugerencia de remediaciones con código corregido. Sun et al. (2024) reportan que GPTScan, que combina GPT-4 con análisis de programas, alcanza una precisión superior al 90% en contratos de tokens y un recall superior al 70% en vulnerabilidades de lógica, como complemento —no reemplazo— de las herramientas tradicionales.

### 2.6.2 Retrieval Augmented Generation (RAG)

RAG combina LLMs con bases de conocimiento externas (Lewis et al., 2020). En MIESC, SmartLLM implementa RAG con una base de conocimiento de vulnerabilidades SWC:

**Figura 2.5.** Arquitectura RAG en SmartLLM

![Figura 2.5 - Arquitectura RAG en SmartLLM](figures/Figura%205.%20Arquitectura%20RAG%20en%20SmartLLM.svg)

### 2.6.3 Model Context Protocol (MCP)

MCP es un estándar abierto para conectar LLMs con herramientas externas (Anthropic, 2024). Define tres primitivas: las herramientas (*tools*), funciones que el LLM puede invocar; los recursos (*resources*), datos estructurados accesibles; y los *prompts*, plantillas de instrucciones predefinidas. El Capítulo 7 desarrolla su aplicación en MIESC.

### 2.6.4 Soberanía de Datos en IA

La soberanía de datos es crítica en contextos de ciberdefensa (Floridi, 2020). Ejecutar los LLM localmente mediante Ollama atiende esa exigencia en cuatro dimensiones: preserva la confidencialidad, porque el código no se transmite a terceros; facilita el cumplimiento de marcos normativos como GDPR, LGPD y las regulaciones nacionales; asegura la independencia operativa respecto de servicios externos; y mantiene el procesamiento bajo control del auditor, lo que lo vuelve auditable. El Capítulo 6 examina el costo en capacidad de detección que esa elección implica.

## 2.7 Normalización y Taxonomías

### 2.7.1 Necesidad de Normalización

Las herramientas de seguridad utilizan nomenclaturas heterogéneas:

| Herramienta | Nombre del Hallazgo | ID | Severidad |
|-------------|---------------------|-----|-----------|
| Slither | reentrancy-eth | - | High |
| Mythril | State change after external call | SWC-107 | Medium |
| Echidna | property_balance_invariant | - | FAILED |

Esta heterogeneidad dificulta la correlación, la deduplicación y la priorización de los hallazgos.

### 2.7.2 Esquema de Normalización MIESC

MIESC normaliza hallazgos a un esquema unificado basado en taxonomías estándar:

```json
{
  "id": "MIESC-YYYY-NNN",
  "type": "categoria-normalizada",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "confidence": "HIGH|MEDIUM|LOW",
  "location": {
    "file": "path/to/contract.sol",
    "line": 42,
    "function": "withdraw()",
    "contract": "VulnerableBank"
  },
  "classification": {
    "swc_id": "SWC-107",
    "cwe_id": "CWE-841",
    "owasp_id": "SC01"
  },
  "detected_by": ["slither", "mythril"],
  "message": "Descripcion normalizada",
  "recommendation": "Sugerencia de remediacion"
}
```

### 2.7.3 Algoritmo de Deduplicación

MIESC agrupa los hallazgos que comparten tipo normalizado, archivo y una ventana de tres líneas de código, conserva la severidad y la confianza máximas del grupo y registra todas las herramientas que lo detectaron. La sección 4.6.2 presenta el algoritmo y sus límites.

## 2.8 Referencias del Capítulo

Aho, A. V., Lam, M. S., Sethi, R., & Ullman, J. D. (2006). *Compilers: Principles, Techniques, and Tools* (2nd ed.). Addison-Wesley.

Anthropic. (2024). Model Context Protocol Specification. https://modelcontextprotocol.io/

Atzei, N., Bartoletti, M., & Cimoli, T. (2017). A survey of attacks on Ethereum smart contracts (SoK). In *International Conference on Principles of Security and Trust* (pp. 164-186). Springer.

Chainalysis. (2024). The 2024 Crypto Crime Report. Chainalysis Inc.

Committee on National Security Systems. (2015). *Committee on National Security Systems (CNSS) glossary* (CNSSI No. 4009). CNSS. https://www.cnss.gov/CNSS/issuances/Instructions.cfm

Durieux, T., Ferreira, J. F., Abreu, R., & Cruz, P. (2020). Empirical review of automated analysis tools on 47,587 Ethereum smart contracts. *Proceedings of the ACM/IEEE 42nd International Conference on Software Engineering (ICSE)*, 530-541. https://doi.org/10.1145/3377811.3380364

Feist, J., Grieco, G., & Groce, A. (2019). Slither: A static analysis framework for smart contracts. In *2019 IEEE/ACM 2nd International Workshop on Emerging Trends in Software Engineering for Blockchain* (pp. 8-15). IEEE.

Gamma, E., Helm, R., Johnson, R., & Vlissides, J. (1994). *Design Patterns: Elements of Reusable Object-Oriented Software*. Addison-Wesley.

He, J., Balunović, M., Ambroladze, N., Tsankov, P., & Vechev, M. (2019). Learning to fuzz from symbolic execution with application to smart contracts. En *Proceedings of the 2019 ACM SIGSAC Conference on Computer and Communications Security (CCS '19)* (pp. 531-548). ACM. https://doi.org/10.1145/3319535.3363230

Hildenbrandt, E., Saxena, M., Rodrigues, N., Zhu, X., Daian, P., Guth, D., ... & Rosu, G. (2018). KEVM: A complete formal semantics of the Ethereum virtual machine. In *2018 IEEE 31st Computer Security Foundations Symposium* (pp. 204-217). IEEE.

Hoare, C. A. R. (1969). An axiomatic basis for computer programming. *Communications of the ACM, 12*(10), 576-580.

Hou, X., Zhao, Y., Liu, Y., Yang, Z., Wang, K., Li, L., ... & Grundy, J. (2024). Large language models for software engineering: A systematic literature review. *ACM Transactions on Software Engineering and Methodology*. https://doi.org/10.1145/3695988

Ivanov, N., Li, C., Yan, Q., Sun, Z., Cao, Z., & Luo, X. (2023). Security defense for smart contracts: A comprehensive survey. *arXiv preprint arXiv:2302.07347*. https://arxiv.org/abs/2302.07347

Joint Chiefs of Staff. (2018). *Cyberspace Operations (JP 3-12)*. U.S. Department of Defense.

King, J. C. (1976). Symbolic execution and program testing. *Communications of the ACM, 19*(7), 385-394.

Lewis, P., Perez, E., Piktus, A., Petroni, F., Karpukhin, V., Goyal, N., ... & Kiela, D. (2020). Retrieval-augmented generation for knowledge-intensive NLP tasks. In *Advances in Neural Information Processing Systems, 33*, 9459-9474.

Libicki, M. C. (2009). *Cyberdeterrence and Cyberwar*. RAND Corporation.

Luu, L., Chu, D. H., Olickel, H., Saxena, P., & Hobor, A. (2016). Making smart contracts smarter. In *Proceedings of the 2016 ACM SIGSAC Conference on Computer and Communications Security* (pp. 254-269). ACM.

Martin, R. C. (2000). Design principles and design patterns. *Object Mentor, 1*(34), 1-20.

MITRE. (2024). Common Weakness Enumeration (CWE). https://cwe.mitre.org/

Mossberg, M., Manzano, F., Hennenfent, E., Groce, A., Grieco, G., Feist, J., ... & Sloan, J. (2019). Manticore: A user-friendly symbolic execution framework for binaries and smart contracts. In *2019 34th IEEE/ACM International Conference on Automated Software Engineering* (pp. 1186-1189). IEEE.

Mueller, B. (2018). Mythril: Security analysis tool for EVM bytecode. In *DEFCON 26*.

Nakamoto, S. (2008). Bitcoin: A peer-to-peer electronic cash system. https://bitcoin.org/bitcoin.pdf

National Institute of Standards and Technology. (2024). *NIST Cybersecurity Framework 2.0*. NIST.

OWASP. (2023). *Smart Contract Security Verification Standard*. OWASP Foundation.

Ross, R., McEvilley, M., & Oren, J. C. (2016). *Systems security engineering: Considerations for a multidisciplinary approach in the engineering of trustworthy secure systems* (NIST Special Publication 800-160, Vol. 1). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-160v1

Sayeed, S., Marco-Gisbert, H., & Caira, T. (2020). Smart contract: Attacks and protections. *IEEE Access, 8*, 24416-24427.

Smart Contract Weakness Classification. (2020). SWC Registry. https://swcregistry.io/

Sun, Y., Wu, D., Xue, Y., Liu, H., Wang, H., Xu, Z., Xie, X., & Liu, Y. (2024). GPTScan: Detecting logic vulnerabilities in smart contracts by combining GPT with program analysis. En *Proceedings of the IEEE/ACM 46th International Conference on Software Engineering (ICSE '24)* (pp. 1-13). ACM. https://doi.org/10.1145/3597503.3639117

Sutton, M., Greene, A., & Amini, P. (2007). *Fuzzing: Brute Force Vulnerability Discovery*. Addison-Wesley.

Szabo, N. (1996). Smart contracts: Building blocks for digital markets. *Extropy, 16*(16), 1-10.

Tolmach, P., Li, Y., Lin, S. W., Liu, Y., & Li, Z. (2021). A survey of smart contract formal specification and verification. *ACM Computing Surveys, 54*(7), 1-38.

Vidal, F. R., Ivaki, N., & Laranjeiro, N. (2024). OpenSCV: An open hierarchical taxonomy for smart contract vulnerabilities. *Empirical Software Engineering, 29*(4), Article 101. https://doi.org/10.1007/s10664-024-10446-8

Wood, G. (2014). Ethereum: A secure decentralised generalised transaction ledger. *Ethereum Yellow Paper, 151*, 1-32.

Zhang, J., Bu, H., Wen, H., Liu, Y., Fei, H., Xi, R., Li, L., Yang, Y., Zhu, H., & Meng, D. (2025). When LLMs meet cybersecurity: A systematic literature review. *Cybersecurity, 8*(1), Article 55. https://doi.org/10.1186/s42400-025-00361-w
