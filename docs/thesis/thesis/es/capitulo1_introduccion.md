# CAPÍTULO 1 – INTRODUCCIÓN

## 1.1 Contexto General

Los contratos inteligentes (smart contracts) sobre la Máquina Virtual de Ethereum (EVM) representan una revolución en la automatización de acuerdos y procesos de negocio en entornos descentralizados. Desde su introducción en 2015, Ethereum ha consolidado un ecosistema de más de USD $400 mil millones en valor total bloqueado (TVL), convirtiéndose en infraestructura crítica para aplicaciones financieras (DeFi), tokens no fungibles (NFTs), organizaciones autónomas descentralizadas (DAOs) y sistemas de identidad digital.

Sin embargo, la inmutabilidad característica de los contratos inteligentes—que garantiza la ejecución determinística y transparente del código—también implica que las vulnerabilidades de seguridad no pueden ser corregidas una vez desplegadas en la blockchain. Esta particularidad convierte a la auditoría de seguridad previa al despliegue en un proceso crítico para la protección de activos digitales y la preservación de la confianza en sistemas descentralizados.

### 1.1.1 Relevancia en la Ciberdefensa

La ciberdefensa aplicada a entornos blockchain trasciende el paradigma tradicional de protección perimetral. Los contratos inteligentes operan en un modelo de adversario donde:

- **El código es público y auditable**: Los atacantes pueden analizar exhaustivamente el código antes de diseñar exploits.
- **Los incentivos económicos son directos**: Las vulnerabilidades pueden explotarse para extraer fondos de manera inmediata e irreversible.
- **No existe autoridad central de remediación**: No hay mecanismos de rollback ni parches en caliente como en sistemas centralizados.

Desde la perspectiva de ciberdefensa nacional e internacional, la proliferación de infraestructura crítica basada en blockchain (sistemas de pago, registros públicos, supply chains tokenizadas) requiere marcos de evaluación de seguridad robustos, automatizados y reproducibles.

## 1.2 Problemática Actual

### 1.2.1 Complejidad Creciente del Ecosistema EVM

El ecosistema EVM ha evolucionado significativamente desde su lanzamiento:

- **Estándares en constante expansión**: ERC-20, ERC-721, ERC-1155, ERC-4626 (tokenized vaults), ERC-4337 (account abstraction), cada uno con vectores de ataque específicos.
- **Patrones de diseño complejos**: Proxies upgradeables (UUPS, Transparent, Beacon), patrón Diamond (EIP-2535), meta-transacciones, que introducen superficies de ataque no triviales.
- **Interoperabilidad cross-chain**: Bridges, wrapped tokens y oráculos que expanden el modelo de amenazas más allá de una única blockchain.
- **MEV (Maximal Extractable Value)**: Vectores de ataque económico que explotan la ordenación de transacciones (front-running, sandwich attacks).

### 1.2.2 Vulnerabilidades Críticas

El análisis histórico de incidentes revela patrones recurrentes:

| Vulnerabilidad | Ejemplo Histórico | Pérdidas (USD) |
|----------------|-------------------|----------------|
| Reentrancy | The DAO (2016) | $60M |
| Access Control | Parity Multisig (2017) | $280M |
| Oracle Manipulation | Mango Markets (2022) | $114M |
| Bridge Exploits | Ronin Bridge (2022) | $625M |
| ERC-4626 Inflation | Varios protocolos (2023) | $10M+ |

Según el informe **"DeFi Security Report 2023"** de CertiK, las vulnerabilidades de smart contracts fueron responsables del **46.8%** de las pérdidas totales en el ecosistema blockchain, superando los USD $2.3 mil millones.

### 1.2.3 Limitaciones de las Metodologías Actuales

Las auditorías tradicionales de smart contracts enfrentan desafíos estructurales:

1. **Costo prohibitivo**: Auditorías manuales de protocolos complejos pueden costar entre USD $50,000 y $500,000.
2. **Tiempo de entrega**: 4-8 semanas para protocolos medianos, incompatible con ciclos de desarrollo ágiles.
3. **Cobertura limitada**: Herramientas estáticas generan altos volúmenes de falsos positivos (>50% en algunos detectores).
4. **Falta de integración**: Las herramientas operan de manera aislada, sin consolidación de resultados.
5. **Ausencia de inteligencia contextual**: No hay priorización automática basada en riesgo real de explotación.

## 1.3 Hipótesis de Investigación

**Hipótesis Principal:**

> Es posible desarrollar un marco automatizado de evaluación de seguridad para contratos inteligentes sobre la EVM que, mediante la integración de técnicas de análisis estático, dinámico, formal y asistencia de inteligencia artificial, logre mejorar significativamente la detección de vulnerabilidades críticas en comparación con herramientas individuales, reduciendo simultáneamente el esfuerzo manual requerido y el tiempo de análisis.

**Hipótesis Secundarias:**

1. **H1**: Un pipeline híbrido que combine Slither (análisis estático), Echidna/Medusa (fuzzing), Foundry (testing diferencial) y Certora (verificación formal) incrementará la tasa de detección de vulnerabilidades en al menos un 30% respecto al uso de Slither individual.

2. **H2**: La integración de modelos de lenguaje (LLMs) para el triage y clasificación de findings reducirá el volumen de falsos positivos en al menos un 40%, priorizando efectivamente los hallazgos críticos.

3. **H3**: El tiempo total de análisis automatizado (pipeline completo) será inferior a 2 horas para contratos de complejidad media (<1000 SLOC), representando una reducción de al menos 95% respecto a auditorías manuales.

## 1.4 Objetivos

### 1.4.1 Objetivo General

Desarrollar, implementar y validar experimentalmente un marco de trabajo integral (framework) para la evaluación automatizada de seguridad en contratos inteligentes sobre la Máquina Virtual de Ethereum, integrando técnicas de análisis estático, dinámico y formal con capacidades de inteligencia artificial, orientado a maximizar la detección de vulnerabilidades críticas y optimizar el proceso de auditoría en términos de precisión, cobertura y eficiencia temporal.

### 1.4.2 Objetivos Específicos

**OE1**: Diseñar e implementar un pipeline híbrido de análisis que integre:
- Análisis estático con Slither (SlithIR, detectores custom)
- Fuzzing property-based con Echidna
- Fuzzing coverage-guided con Medusa
- Testing diferencial con Foundry (forge, anvil)
- Runtime verification con Scribble
- Verificación formal con Certora Prover (CVL)

**OE2**: Desarrollar un módulo de inteligencia artificial que:
- Clasifique automáticamente findings por severidad real (no solo impacto teórico)
- Estime exploitabilidad y probabilidad de falso positivo
- Priorice hallazgos para revisión manual
- Genere resúmenes ejecutivos y recomendaciones de remediación

**OE3**: Construir un dataset anotado de contratos vulnerables que cubra:
- Vulnerabilidades clásicas (SWC-107 reentrancy, SWC-105 access control)
- Vulnerabilidades modernas (ERC-4626 inflation, oracle manipulation)
- Patrones complejos (proxies, diamonds, account abstraction)

**OE4**: Evaluar experimentalmente el framework mediante:
- Métricas de precisión (precision), exhaustividad (recall) y F1-score
- Comparación contra herramientas individuales
- Análisis de casos reales de protocolos DeFi
- Medición de reducción de esfuerzo manual

**OE5**: Integrar el framework en pipelines CI/CD mediante:
- GitHub Actions workflows
- Generación automática de reportes
- Dashboards de métricas visuales
- Alertas automatizadas de vulnerabilidades críticas

**OE6**: Documentar y publicar el framework como herramienta open-source para:
- Auditoría de seguridad en la industria
- Investigación académica en verificación formal
- Educación en seguridad de smart contracts

## 1.5 Alcance

### 1.5.1 Alcance Técnico

**Incluye:**
- Contratos escritos en Solidity (versiones 0.8.x y 0.7.x)
- Máquina Virtual de Ethereum (EVM) y cadenas compatibles (Polygon, Optimism, Arbitrum, Base)
- Estándares ERC-20, ERC-721, ERC-1155, ERC-4626, ERC-4337
- Vulnerabilidades clasificadas en SWC Registry y DASP Top 10
- Integración con toolchains modernas (Foundry, Hardhat)

**Excluye:**
- Smart contracts en otros lenguajes (Vyper, Huff, Yul puro)
- Blockchains no-EVM (Solana, Cardano, Polkadot)
- Vulnerabilidades de infraestructura (nodos, RPC endpoints)
- Análisis de front-ends y aplicaciones web3

### 1.5.2 Alcance Experimental

Los experimentos se realizarán sobre:
- Dataset propio de 30+ contratos vulnerables diseñados ad-hoc
- 20 contratos reales de protocolos DeFi (selección de auditorías públicas)
- Casos de estudio de incidentes históricos reproducidos en entornos controlados

### 1.5.3 Alcance Metodológico

La investigación se enmarca en:
- **Paradigma**: Experimental cuantitativo con validación empírica
- **Referenciales normativos**: ISO/IEC 27001, ISO/IEC 42001, NIST SSDF
- **Métricas**: Precisión, recall, F1-score, tiempo de análisis, cobertura de código

## 1.6 Justificación

### 1.6.1 Contribución Científica

- **Originalidad**: Primer framework que integra análisis estático, fuzzing, formal verification y AI en un pipeline unificado para EVM.
- **Reproducibilidad**: Pipeline automatizado completamente documentado y publicado como open-source.
- **Metodología**: Evaluación empírica rigurosa con métricas estandarizadas.

### 1.6.2 Contribución Práctica

- **Reducción de costos**: Automatización que reduce el costo de auditoría preliminar en >90%.
- **Mejora de seguridad**: Detección temprana de vulnerabilidades en fase de desarrollo.
- **Democratización**: Herramienta accesible para proyectos sin recursos para auditorías privadas.

### 1.6.3 Relevancia para Ciberdefensa

- **Protección de infraestructura crítica**: Aplicable a sistemas blockchain gubernamentales y financieros.
- **Capacitación**: Material educativo para especialistas en ciberdefensa.
- **Gobernanza**: Contribución a estándares de seguridad en tecnologías emergentes.

## 1.7 Estructura del Documento

La presente tesis se organiza en los siguientes capítulos:

- **Capítulo 2**: Marco de Ciberdefensa - Contextualización normativa y regulatoria
- **Capítulo 3**: Marco Teórico Técnico - Fundamentos de EVM y vulnerabilidades
- **Capítulo 4**: Estado del Arte - Análisis de herramientas existentes
- **Capítulo 5**: Metodología Propuesta - Diseño del framework Xaudit
- **Capítulo 6**: Implementación y Experimentos - Validación experimental
- **Capítulo 7**: Resultados y Análisis - Evaluación de hipótesis
- **Capítulo 8**: Conclusiones y Trabajo Futuro

---

**Referencias del Capítulo**

1. Wood, G. (2014). "Ethereum: A Secure Decentralised Generalised Transaction Ledger"
2. CertiK. (2023). "DeFi Security Report 2023"
3. Consensys. (2023). "Smart Contract Weakness Classification (SWC Registry)"
4. NIST. (2022). "Secure Software Development Framework (SSDF) v1.1"
5. ISO/IEC 42001:2023 - Information technology — Artificial intelligence — Management system
