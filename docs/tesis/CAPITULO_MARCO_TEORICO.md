# Capítulo 2: Marco Teórico

## Fundamentos de Ciberdefensa y Seguridad en Smart Contracts

---

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

La adopción creciente de blockchain en sectores estratégicos como finanzas, energía, logística y gobierno ha convertido esta tecnología en una infraestructura crítica potencial (Vidal et al., 2024). Según Sayeed et al. (2020), los sistemas blockchain utilizados para:

- **Sistemas financieros descentralizados (DeFi):** Con más de $50 mil millones en valor bloqueado
- **Cadenas de suministro gubernamentales:** Trazabilidad de productos estratégicos
- **Sistemas de identidad digital:** Documentos y credenciales soberanas
- **Votación electrónica:** Procesos democráticos seguros

Constituyen activos cuya protección es responsabilidad del Estado en el marco de la defensa nacional.

### 2.1.3 Relevancia para la Defensa Nacional

La protección de infraestructuras basadas en blockchain tiene implicaciones directas para la seguridad nacional (Di Pietro et al., 2024):

> "Los ataques a smart contracts representan una amenaza emergente para la seguridad económica de las naciones, con pérdidas que superan los $7.8 mil millones entre 2016 y 2024" (Chainalysis, 2024).

**Vectores de amenaza identificados:**

1. **Actores estatales:** Grupos APT con capacidad de explotar vulnerabilidades en contratos que gestionan activos soberanos
2. **Crimen organizado:** Explotación de vulnerabilidades para lavado de activos
3. **Hacktivismo:** Ataques con motivación política a protocolos DeFi
4. **Amenazas internas:** Desarrolladores maliciosos o negligentes

**Figura 1.** Taxonomía de amenazas a sistemas blockchain

![Figura 1 - Taxonomia de amenazas a sistemas blockchain](figures/Figura%201.%20Taxonomía%20de%20amenazas%20a%20sistemas%20blockchain.svg)

---

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
| Finality | Irreversibilidad de transacciones | Ataques exitosos no pueden revertirse |

### 2.2.2 Smart Contracts

Un smart contract es un programa computacional que se ejecuta de forma automática cuando se cumplen condiciones predefinidas (Szabo, 1996). Según la definición formal de Atzei et al. (2017):

> "Un smart contract es un programa determinista que se ejecuta en un ambiente de ejecución distribuido (la blockchain), maneja activos digitales, y cuyo comportamiento esta completamente determinado por su código y el estado de la blockchain."

**Características críticas desde perspectiva de seguridad:**

1. **Ejecución autónoma:** Una vez desplegado, opera sin intervención humana
2. **Valor económico directo:** Gestiona activos digitales con valor real
3. **Código público:** Bytecode (y frecuentemente código fuente) visible para adversarios
4. **Actualización compleja:** Modificar un contrato desplegado requiere patrones especiales

### 2.2.3 Ethereum Virtual Machine (EVM)

La EVM es el entorno de ejecución para smart contracts en Ethereum y blockchains compatibles (Wood, 2014). Según Hildenbrandt et al. (2018), la semántica formal de la EVM incluye:

- **Arquitectura stack-based:** Pila de 1024 elementos máximo
- **Sistema de Gas:** Cada operación consume unidades computacionales
- **Almacenamiento multinivel:** Storage (persistente), Memory (temporal), Stack
- **Opcodes de llamada:** CALL, DELEGATECALL, STATICCALL con diferentes modelos de seguridad

---

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
2. **Integer Overflow/Underflow:** $800K (BEC Token, 2018)
3. **Front-Running:** Pérdidas constantes en DEXs
4. **Oracle Manipulation:** $130M (Cream Finance, 2021)
5. **Denial of Service:** Bloqueo de fondos
6. **Access Control Issues:** $80M (Parity Wallet, 2017)
7. **Unprotected Functions:** Múltiples incidentes
8. **Exploits de Puentes Cross-Chain:** ~$320M (incidente del puente Wormhole, febrero de 2022)
9. **Signature Malleability:** Robo de fondos
10. **Short Address Attack:** Manipulación de transferencias

---

## 2.4 Técnicas de Análisis de Seguridad

### 2.4.1 Análisis Estático

El análisis estático examina el código sin ejecutarlo (Aho et al., 2006). Según Ivanov et al. (2023), en el contexto de smart contracts incluye:

**1. Análisis de flujo de datos:**
- Seguimiento de variables (taint analysis)
- Detección de propagación de datos no confiables
- Identificación de código muerto

**2. Pattern matching:**
- Busqueda de patrones vulnerables conocidos
- Reglas basadas en AST (Abstract Syntax Tree)
- Heurísticas de detección

**3. Interpretación abstracta:**
- Aproximación del comportamiento del programa
- Verificación de propiedades sin ejecución
- Base teórica de herramientas como Slither (Feist et al., 2019)

**Herramientas representativas:** Slither, Solhint, Securify2, Aderyn

### 2.4.2 Análisis Dinámico (Fuzzing)

El fuzzing genera entradas aleatorias o semi-dirigidas para descubrir comportamientos anomalos (Sutton et al., 2007). Según el estudio de He et al. (2023):

**Tabla 2.5.** Tipos de fuzzing en smart contracts

| Tipo | Descripción | Herramienta | Efectividad |
|------|-------------|-------------|-------------|
| Black-box | Sin conocimiento del código | Echidna básico | Media |
| Grey-box | Guiado por cobertura | Medusa | Alta |
| White-box | Con instrumentación | Foundry Fuzz | Alta |
| Property-based | Verifica invariantes | Echidna avanzado | Muy Alta |

### 2.4.3 Ejecución Simbólica

La ejecución simbólica trata las entradas como símbolos y explora caminos de ejecución (King, 1976). Según Mossberg et al. (2019), es particularmente efectiva para:

**Figura 3.** Ejecución concreta vs ejecución simbólica

![Figura 3 - Ejecución concreta vs ejecución simbólica](figures/Figura%203%20Ejecución%20concreta%20vs%20ejecución%20simbólica.svg)

**Herramientas:** Mythril (Mueller, 2018), Manticore (Mossberg et al., 2019), Oyente (Luu et al., 2016)

### 2.4.4 Verificación Formal

La verificación formal utiliza métodos matemáticos para probar propiedades de programas (Hoare, 1969). Según Tolmach et al. (2021), las técnicas aplicadas a smart contracts incluyen:

**1. Model Checking:**
- Exploración exhaustiva de estados
- Verificación de propiedades temporales
- Herramienta: SMTChecker (Solidity)

**2. Theorem Proving:**
- Demostración matemática de propiedades
- Especificaciones en lenguajes formales
- Herramienta: Certora Prover

**3. Bounded Model Checking:**
- Verificación hasta profundidad k
- Balance entre completitud y escalabilidad
- Herramienta: Halmos

**Tabla 2.6.** Comparación de técnicas de verificación

| Técnica | Soundness | Completeness | Escalabilidad |
|---------|-----------|--------------|---------------|
| Model Checking | Alta | Alta | Baja |
| Theorem Proving | Completa | Completa | Media |
| Bounded MC | Limitada (k) | Limitada (k) | Alta |

---

## 2.5 Patrones de Diseño de Software

### 2.5.1 Patrón Adapter (Gamma et al., 1994)

El patrón Adapter convierte la interfaz de una clase en otra esperada por los clientes. MIESC utiliza este patrón para integrar herramientas heterogéneas:

**Figura 3.1.** Patrón Adapter en MIESC

![Figura 3.1 - Patron Adapter en MIESC](figures/Figura%203.1.%20Patron%20Adapter%20en%20MIESC.svg)

### 2.5.2 Principios SOLID

MIESC implementa los principios SOLID (Martin, 2000):

| Principio | Aplicación en MIESC |
|-----------|---------------------|
| **S**ingle Responsibility | Cada adapter maneja una herramienta |
| **O**pen/Closed | Extensible mediante nuevos adapters |
| **L**iskov Substitution | Adapters son intercambiables |
| **I**nterface Segregation | ToolProtocol define interfaz minima |
| **D**ependency Inversión | Dependencia de abstracciones |

### 2.5.3 Defense in Depth

Defense in Depth es una estrategia de seguridad que emplea múltiples capas de controles (Ross et al., 2016a; NIST, 2024). Según el NIST SP 800-53:

> "Defense in depth is an information security strategy that integrates people, technology, and operations capabilities to establish variable barriers across múltiple layers and missions of the organization."

Durieux et al. (2020) muestran empíricamente que ninguna herramienta individual detecta todas las clases de vulnerabilidades y que combinar herramientas complementarias aumenta la cobertura de detección, evidencia que sustenta el enfoque defense-in-depth.

**Figura 4.** Arquitectura Defense-in-Depth de MIESC

![Figura 4 - Arquitectura Defense-in-Depth de MIESC](figures/Figura%204%20Arquitectura%20Defense-in-Depth%20de%20MIESC.svg)

**Principio:** Cada capa proporciona protección complementaria. Si una capa falla en detectar una vulnerabilidad, las siguientes ofrecen oportunidades adicionales de detección.

---

## 2.6 Inteligencia Artificial en Ciberseguridad

### 2.6.1 Large Language Models (LLMs) en Seguridad

Los LLMs han emergido como herramientas poderosas para análisis de seguridad de código (Zhang et al., 2024). Según el estudio sistemático de Hou et al. (2024):

> "Los LLMs demuestran capacidades emergentes para detectar vulnerabilidades que escapan a herramientas tradicionales basadas en patrones, particularmente aquellas que requieren comprensión semántica del código."

**Aplicaciones en seguridad de smart contracts:**

1. **Detección de vulnerabilidades:** Análisis semántico de código
2. **Generación de propiedades:** Creación automática de invariantes
3. **Explicación de hallazgos:** Traducción a lenguaje natural
4. **Sugerencia de remediaciones:** Generación de código corregido

Sun et al. (2024) reportan que GPT-4 alcanza precisión del 78% en detección de vulnerabilidades en smart contracts, complementando herramientas tradicionales.

### 2.6.2 Retrieval Augmented Generation (RAG)

RAG combina LLMs con bases de conocimiento externas (Lewis et al., 2020). En MIESC, SmartLLM implementa RAG con una base de conocimiento de vulnerabilidades SWC:

**Figura 5.** Arquitectura RAG en SmartLLM

![Figura 5 - Arquitectura RAG en SmartLLM](figures/Figura%205.%20Arquitectura%20RAG%20en%20SmartLLM.svg)

### 2.6.3 Model Context Protocol (MCP)

MCP es un estándar abierto para conectar LLMs con herramientas externas (Anthropic, 2024). Permite:

- **Tools:** Funciones que el LLM puede invocar
- **Resources:** Datos estructurados accesibles
- **Prompts:** Templates de instrucciones predefinidas

### 2.6.4 Soberanía de Datos en IA

La soberanía de datos es crítica en contextos de ciberdefensa (Di Pietro et al., 2024). El uso de LLMs locales mediante Ollama garantiza:

1. **Confidencialidad:** Código no transmitido a terceros
2. **Cumplimiento normativo:** GDPR, LGPD, regulaciones nacionales
3. **Independencia operativa:** Sin dependencia de servicios externos
4. **Auditabilidad:** Control total sobre procesamiento

---

## 2.7 Normalización y Taxonomías

### 2.7.1 Necesidad de Normalización

Las herramientas de seguridad utilizan nomenclaturas heterogéneas:

| Herramienta | Nombre del Hallazgo | ID | Severidad |
|-------------|---------------------|-----|-----------|
| Slither | reentrancy-eth | - | High |
| Mythril | State Access After External Call | SWC-107 | Medium |
| Echidna | property_balance_invariant | - | FAILED |

**Problema:** Dificulta la correlación, deduplicación y priorización de hallazgos.

### 2.7.2 Esquema de Normalización MIESC

MIESC normaliza hallazgos a un esquema unificado basado en taxonomías estándar:

```json
{
  "id": "MIESC-YYYY-XX-NNN",
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
    "owasp_id": "SC06"
  },
  "detected_by": ["slither", "mythril"],
  "message": "Descripcion normalizada",
  "recommendation": "Sugerencia de remediacion"
}
```

### 2.7.3 Algoritmo de Deduplicación

MIESC agrupa hallazgos similares mediante:

1. **Hashing de ubicación:** (archivo, línea, función)
2. **Similitud semántica:** Tipo de vulnerabilidad
3. **Clustering:** Agrupación por proximidad

---

## 2.8 Referencias del Capítulo

Aho, A. V., Lam, M. S., Sethi, R., & Ullman, J. D. (2006). *Compilers: Principles, Techniques, and Tools* (2nd ed.). Addison-Wesley.

Anthropic. (2024). Model Context Protocol Specification. https://modelcontextprotocol.io/

Atzei, N., Bartoletti, M., & Cimoli, T. (2017). A survey of attacks on Ethereum smart contracts (SoK). In *International Conference on Principles of Security and Trust* (pp. 164-186). Springer.

Chainalysis. (2024). The 2024 Crypto Crime Report. Chainalysis Inc.

Ivanov, N., Li, C., Yan, Q., Sun, Z., Cao, Z., & Luo, X. (2023). Security defense for smart contracts: A comprehensive survey. *arXiv preprint arXiv:2302.07347*. https://arxiv.org/abs/2302.07347

Di Pietro, R., Ferretti, S., & Verde, N. V. (2024). Securing critical infrastructure with blockchain technology: A systematic review. *MDPI Electronics, 13*(1), 1-24.

Feist, J., Grieco, G., & Groce, A. (2019). Slither: A static analysis framework for smart contracts. In *2019 IEEE/ACM 2nd International Workshop on Emerging Trends in Software Engineering for Blockchain* (pp. 8-15). IEEE.

Gamma, E., Helm, R., Johnson, R., & Vlissides, J. (1994). *Design Patterns: Elements of Reusable Object-Oriented Software*. Addison-Wesley.

He, J., Balunovic, M., Ambroladze, N., Tsankov, P., & Vechev, M. (2023). Learning to fuzz from symbolic execution with application to smart contracts. In *Proceedings of the 2023 ACM SIGSAC Conference on Computer and Communications Security* (pp. 1-15). ACM.

Hildenbrandt, E., Saxena, M., Rodrigues, N., Zhu, X., Daian, P., Guth, D., ... & Rosu, G. (2018). KEVM: A complete formal semantics of the Ethereum virtual machine. In *2018 IEEE 31st Computer Security Foundations Symposium* (pp. 204-217). IEEE.

Hoare, C. A. R. (1969). An axiomatic basis for computer programming. *Communications of the ACM, 12*(10), 576-580.

Hou, X., Zhao, Y., Liu, Y., Yang, Z., Wang, K., Li, L., ... & Grundy, J. (2024). Large language models for software engineering: A systematic literature review. *ACM Transactions on Software Engineering and Methodology*. https://doi.org/10.1145/3695988

Joint Chiefs of Staff. (2018). *Cyberspace Operations (JP 3-12)*. U.S. Department of Defense.

King, J. C. (1976). Symbolic execution and program testing. *Communications of the ACM, 19*(7), 385-394.

Lewis, P., Perez, E., Piktus, A., Petroni, F., Karpukhin, V., Goyal, N., ... & Kiela, D. (2020). Retrieval-augmented generation for knowledge-intensive NLP tasks. In *Advances in Neural Information Processing Systems, 33*, 9459-9474.

Libicki, M. C. (2009). *Cyberdeterrence and Cyberwar*. RAND Corporation.

Durieux, T., Ferreira, J. F., Abreu, R., & Cruz, P. (2020). Empirical review of automated analysis tools on 47,587 Ethereum smart contracts. *Proceedings of the ACM/IEEE 42nd International Conference on Software Engineering (ICSE)*, 530-541. https://doi.org/10.1145/3377811.3380364

Luu, L., Chu, D. H., Olickel, H., Saxena, P., & Hobor, A. (2016). Making smart contracts smarter. In *Proceedings of the 2016 ACM SIGSAC Conference on Computer and Communications Security* (pp. 254-269). ACM.

Martin, R. C. (2000). Design principles and design patterns. *Object Mentor, 1*(34), 1-20.

MITRE. (2024). Common Weakness Enumeration (CWE). https://cwe.mitre.org/

Mossberg, M., Manzano, F., Hennenfent, E., Groce, A., Grieco, G., Feist, J., ... & Sloan, J. (2019). Manticore: A user-friendly symbolic execution framework for binaries and smart contracts. In *2019 34th IEEE/ACM International Conference on Automated Software Engineering* (pp. 1186-1189). IEEE.

Mueller, B. (2018). Mythril: Security analysis tool for EVM bytecode. In *DEFCON 26*.

Nakamoto, S. (2008). Bitcoin: A peer-to-peer electronic cash system. https://bitcoin.org/bitcoin.pdf

National Institute of Standards and Technology. (2024). *NIST Cybersecurity Framework 2.0*. NIST.

OWASP. (2023). *Smart Contract Security Verification Standard*. OWASP Foundation.

Ross, R., Pillitteri, V., Dempsey, K., Riddle, M., & Guissanie, G. (2016). *Protecting controlled unclassified information in nonfederal systems and organizations* (NIST SP 800-171). NIST.

Sayeed, S., Marco-Gisbert, H., & Caira, T. (2020). Smart contract: Attacks and protections. *IEEE Access, 8*, 24416-24427.

Smart Contract Weakness Classification. (2020). SWC Registry. https://swcregistry.io/

Sun, Y., Wu, D., Xue, Y., Liu, H., Wang, H., Xu, Z., Xie, X., & Liu, Y. (2024). GPTScan: Detecting logic vulnerabilities in smart contracts by combining GPT with program analysis. *Proceedings of the 46th International Conference on Software Engineering (ICSE)*, Article 166. https://doi.org/10.1145/3597503.3623318

Sutton, M., Greene, A., & Amini, P. (2007). *Fuzzing: Brute Force Vulnerability Discovery*. Addison-Wesley.

Szabo, N. (1996). Smart contracts: Building blocks for digital markets. *Extropy, 16*(16), 1-10.

Tolmach, P., Li, Y., Lin, S. W., Liu, Y., & Li, Z. (2021). A survey of smart contract formal specification and verification. *ACM Computing Surveys, 54*(7), 1-38.

Vidal, F. R., Ivaki, N., & Laranjeiro, N. (2024). OpenSCV: An open hierarchical taxonomy for smart contract vulnerabilities. *arXiv preprint arXiv:2403.12667*.

Wood, G. (2014). Ethereum: A secure decentralised generalised transaction ledger. *Ethereum Yellow Paper, 151*, 1-32.

Zhang, Q., Zhang, C., & Li, J. (2024). When LLMs meet cybersecurity: A systematic literature review. *Computers & Security*. https://doi.org/10.1016/j.cose.2024.104099

---

*Las referencias siguen el formato APA 7ma edición. Todas las URLs fueron verificadas en noviembre 2024.*
