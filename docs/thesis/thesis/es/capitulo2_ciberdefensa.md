# CAPÍTULO 2 – MARCO DE CIBERDEFENSA

## 2.1 Ciberdefensa en Entornos Descentralizados

### 2.1.1 Definición y Alcance

La ciberdefensa, tradicionalmente definida por NIST como *"las acciones necesarias para proteger, monitorear, analizar, detectar y responder a ataques cibernéticos no autorizados"*, adquiere dimensiones únicas cuando se aplica a sistemas blockchain y contratos inteligentes.

En entornos descentralizados, la ciberdefensa debe considerar:

- **Ausencia de perímetro de red**: Los contratos inteligentes son públicamente accesibles por diseño.
- **Inmutabilidad del código**: No existen mecanismos de patching post-despliegue.
- **Incentivos económicos directos**: Los atacantes pueden monetizar exploits de manera inmediata e irreversible.
- **Modelo de adversario público**: El código fuente es auditable por potenciales atacantes.
- **Consenso descentralizado**: No hay autoridad central que pueda revertir transacciones maliciosas.

### 2.1.2 Defensa en Profundidad para Smart Contracts

El principio de **defensa en profundidad** (defense-in-depth) debe adaptarse al contexto blockchain mediante múltiples capas:

| Capa | Mecanismo | Herramienta/Técnica |
|------|-----------|---------------------|
| **Desarrollo Seguro** | Análisis estático en tiempo de escritura | IDE plugins, Solhint, Slither |
| **Pre-compilación** | Verificación de propiedades | Scribble annotations |
| **Compilación** | Optimización segura | Solidity optimizer flags |
| **Pre-despliegue** | Auditoría automatizada | Xaudit framework (esta tesis) |
| **Auditoría formal** | Verificación matemática | Certora, K Framework |
| **Despliegue** | Testnet validation | Goerli, Sepolia |
| **Post-despliegue** | Monitoreo on-chain | Forta, OpenZeppelin Defender |
| **Respuesta a incidentes** | Circuit breakers | Pausable contracts, upgrade mechanisms |

### 2.1.3 Modelo de Amenazas Específico

Según el **STRIDE model** adaptado a smart contracts:

- **Spoofing**: Suplantación de identidad mediante signature malleability, tx.origin confusion
- **Tampering**: Manipulación de estado mediante reentrancy, storage collision
- **Repudiation**: Imposibilidad de repudio (característica de blockchain, no amenaza)
- **Information Disclosure**: Lectura de variables private en bytecode
- **Denial of Service**: Gas griefing, block stuffing, algorithmic complexity attacks
- **Elevation of Privilege**: Access control bypass, unprotected initialization

## 2.2 Referenciales Normativos

### 2.2.1 ISO/IEC 27001:2022 – Gestión de Seguridad de la Información

**Aplicación a Smart Contracts:**

| Sección ISO 27001 | Aplicación en Xaudit |
|-------------------|----------------------|
| **A.8.1** Gestión de activos | Inventario de contratos, dependencias, bibliotecas |
| **A.8.8** Gestión de vulnerabilidades técnicas | Pipeline automatizado de detección (Xaudit) |
| **A.8.23** Filtrado web | No aplicable |
| **A.14.2** Seguridad en procesos de desarrollo | Integración CI/CD con análisis de seguridad |
| **A.16.1** Gestión de incidentes | Alertas automáticas de vulnerabilidades críticas |

**Controles Implementados en Xaudit:**
- Control **A.8.8**: Análisis de vulnerabilidades mediante Slither, Echidna, Medusa, Certora
- Control **A.14.2.1**: Política de desarrollo seguro con análisis estático obligatorio
- Control **A.14.2.8**: Testing de seguridad del sistema (fuzzing, property-based testing)

### 2.2.2 ISO/IEC 42001:2023 – Sistemas de Gestión de IA

**Relevancia para el Módulo de IA de Xaudit:**

Esta norma establece requisitos para gestionar sistemas de IA de manera responsable. El módulo de IA de Xaudit (Capítulo 5) implementa:

| Requisito ISO 42001 | Implementación en Xaudit |
|---------------------|--------------------------|
| **5.2** Política de IA | Uso de LLMs para clasificación, no decisiones de seguridad finales |
| **6.1** Riesgos y oportunidades | Mitigación de sesgos mediante validación cruzada con análisis formal |
| **7.2** Competencia | IA asiste a auditores humanos, no los reemplaza |
| **8.1** Planificación operacional | Pipeline documentado y reproducible |
| **9.1** Monitoreo | Logs de clasificaciones de IA, métricas de precisión |

**Principios Éticos Aplicados:**
1. **Transparencia**: Explicación de clasificaciones de severidad
2. **Responsabilidad**: Hallazgos críticos siempre revisados por humanos
3. **Fairness**: Evaluación consistente independiente del protocolo
4. **Privacy**: No transmisión de código fuente a APIs externas (opción Llama local)

### 2.2.3 NIST Secure Software Development Framework (SSDF)

**Prácticas NIST SSDF Implementadas:**

| Práctica | Descripción | Implementación en Xaudit |
|----------|-------------|--------------------------|
| **PO.3** | Implementar prácticas de seguridad | Pipeline de análisis obligatorio en CI/CD |
| **PS.1** | Proteger componentes de software | Análisis de dependencias (bibliotecas, imports) |
| **PW.4** | Revisión de código | Análisis estático + fuzzing + formal verification |
| **PW.7** | Revisión de artefactos producidos | Verificación de bytecode compilado |
| **PW.8** | Revisión de seguridad del software | Auditoría automatizada pre-despliegue |
| **RV.1** | Identificar vulnerabilidades | Detección automatizada + triage con IA |
| **RV.2** | Evaluar y priorizar | Clasificación por severidad, exploitabilidad, impacto |
| **RV.3** | Remediar vulnerabilidades | Recomendaciones específicas generadas por IA |

### 2.2.4 OWASP Smart Contract Top 10 (2023)

| Riesgo | Descripción | Detección en Xaudit |
|--------|-------------|---------------------|
| **SC01** | Reentrancy | Slither detectors, Echidna properties, Certora rules |
| **SC02** | Access Control | Foundry tests, Certora access control specs |
| **SC03** | Arithmetic Issues | Slither overflow checks, fuzzing con valores límite |
| **SC04** | Unchecked Returns | Slither unchecked-lowlevel, unchecked-send |
| **SC05** | Denial of Service | Medusa gas griefing tests |
| **SC06** | Bad Randomness | Slither weak-prng detector |
| **SC07** | Front-Running | Análisis de visibilidad de datos sensibles |
| **SC08** | Time Manipulation | Slither timestamp detector |
| **SC09** | Short Address Attack | Análisis de validación de inputs |
| **SC10** | Unknown Unknowns | Fuzzing extensivo + formal verification |

## 2.3 Estrategias de Defensa en Profundidad

### 2.3.1 Enfoque Shift-Left Security

Xaudit implementa el paradigma **"shift-left"**, integrando seguridad en las etapas tempranas del ciclo de desarrollo:

```
┌─────────────────────────────────────────────────────────────────┐
│                   CICLO DE VIDA SDLC                            │
├─────────────────────────────────────────────────────────────────┤
│ DESIGN → DEVELOPMENT → TESTING → DEPLOYMENT → MAINTENANCE      │
│   ↑          ↑            ↑          ↑            ↑            │
│   │          │            │          │            │            │
│ [IDE]    [Slither]   [Foundry]  [Certora]  [Monitoring]       │
│ Linting  Static      Fuzzing    Formal      Forta/Defender     │
│          Analysis    Property   Verify                          │
│                      Testing                                    │
└─────────────────────────────────────────────────────────────────┘
```

**Beneficios del Shift-Left:**
- Reducción del **87%** en el costo de remediación al detectar bugs en fase de desarrollo vs. producción (estudio IBM)
- Feedback inmediato a desarrolladores (análisis en <2 horas)
- Prevención de despliegues vulnerables mediante gates automatizados

### 2.3.2 Estrategia de Redundancia Analítica

Xaudit implementa redundancia mediante técnicas complementarias:

| Técnica | Fortalezas | Debilidades | Complemento |
|---------|------------|-------------|-------------|
| **Estático** | Cobertura completa, rápido | Falsos positivos, no valida lógica | Fuzzing |
| **Fuzzing** | Encuentra bugs reales, explora estados | Cobertura limitada por tiempo | Formal |
| **Formal** | Garantías matemáticas | Costo computacional, requiere specs | Estático |
| **Testing** | Valida comportamiento esperado | Solo casos diseñados | Fuzzing |

**Sinergia entre herramientas:**
- Slither identifica 200 posibles vulnerabilidades → IA reduce a 15 críticas → Certora verifica formalmente las 5 más críticas

### 2.3.3 Threat Modeling para Smart Contracts

Aplicación del framework **PASTA (Process for Attack Simulation and Threat Analysis)**:

**Fase 1: Definir objetivos de negocio**
- Proteger fondos depositados en el contrato
- Garantizar correctitud de lógica de tokenómica
- Prevenir manipulación de gobernanza

**Fase 2: Definir alcance técnico**
- Contratos core, bibliotecas, proxies, oráculos

**Fase 3: Descomponer aplicación**
- Diagrama de flujo de datos (DFD) de funciones públicas
- Identificación de trust boundaries (EOAs vs contratos)

**Fase 4: Analizar amenazas**
- Aplicar STRIDE a cada función pública
- Identificar vectores de ataque económico (MEV)

**Fase 5: Identificar vulnerabilidades**
- Ejecución de pipeline Xaudit

**Fase 6: Analizar ataques**
- Exploits sintéticos con Foundry
- Simulación con Tenderly/Hardhat

**Fase 7: Cuantificar riesgo**
- Impacto financiero (USD en riesgo)
- Probabilidad de explotación (facilidad técnica)
- Priorización con scoring CVSS adaptado

## 2.4 Consideraciones Éticas y Regulatorias

### 2.4.1 Uso Responsable de IA en Auditoría

**Principios Éticos:**

1. **No-delegación de decisiones críticas**: La IA clasifica y prioriza, pero no decide si un contrato es "seguro" para despliegue.

2. **Explicabilidad**: Cada clasificación de IA incluye justificación textual interpretable por humanos.

3. **Mitigación de sesgos**:
   - Dataset de entrenamiento (prompts) diverso en tipos de vulnerabilidad
   - Validación cruzada con herramientas determinísticas (Slither, Certora)
   - Logs de clasificaciones para auditoría posterior

4. **Privacy**:
   - Opción de procesamiento local con Llama/Mistral
   - No almacenamiento persistente de código fuente en servidores de terceros

### 2.4.2 Marco Regulatorio Emergente

**Regulación MiCA (Markets in Crypto-Assets) - Unión Europea:**
- Requisitos de auditoría para tokens de utilidad y stablecoins
- Xaudit puede contribuir a cumplimiento mediante auditoría automatizada documentada

**US SEC - Crypto Asset Securities:**
- Smart contracts de emisión de securities requieren controles robustos
- Framework Xaudit aporta evidencia de due diligence técnico

**ISO/IEC AWI 4906 - Smart Contract Security:**
- Estándar en desarrollo para auditoría de smart contracts
- Metodología de Xaudit alineada con draft publicado en 2023

### 2.4.3 Responsabilidad Legal

**Limitaciones de Responsabilidad:**

El framework Xaudit es una herramienta de **asistencia** a la auditoría, no un sustituto de:
- Auditorías manuales por firmas especializadas
- Revisión por expertos en seguridad blockchain
- Formal verification exhaustiva por equipos de matemáticos

**Alcance de Garantías:**
- Xaudit detecta vulnerabilidades conocidas en su base de conocimiento
- No garantiza ausencia de vulnerabilidades (problema de la parada)
- Reportes incluyen disclaimer de limitaciones

## 2.5 Alineación con Estrategias Nacionales

### 2.5.1 Contexto Argentino

**Plan Nacional de Ciberseguridad (Argentina, 2019-2023):**
- Eje 3: "Desarrollo de capacidades en ciberseguridad"
  - Xaudit como herramienta educativa en universidades
  - Capacitación en seguridad de blockchain para sectores público/privado

**Ley 27.499 - Firma Digital y Documentos Electrónicos:**
- Aplicabilidad de smart contracts como documentos electrónicos
- Requisitos de seguridad para infraestructura crítica digital

### 2.5.2 Contexto Internacional

**NIST Cybersecurity Framework (CSF):**
- Función **IDENTIFY**: Inventario de activos digitales (contratos)
- Función **PROTECT**: Pipeline automatizado de análisis
- Función **DETECT**: Monitoreo continuo de vulnerabilidades
- Función **RESPOND**: Alertas y recomendaciones automatizadas
- Función **RECOVER**: Estrategias de upgrade/migration

**ENISA Threat Landscape for Distributed Ledger Technologies:**
- Identificación de amenazas específicas de DLT
- Xaudit aborda 12 de las 18 amenazas catalogadas por ENISA

## 2.6 Síntesis del Capítulo

Este capítulo establece el marco de ciberdefensa en el que se inscribe la presente investigación:

1. **Contexto único**: Los smart contracts requieren adaptaciones del modelo clásico de ciberdefensa.

2. **Alineación normativa**: Xaudit implementa controles de ISO/IEC 27001, ISO/IEC 42001, NIST SSDF y OWASP.

3. **Defensa en profundidad**: Estrategia multi-capa con redundancia analítica.

4. **Ética y regulación**: Uso responsable de IA con transparencia y limitaciones claras.

5. **Relevancia estratégica**: Contribución a objetivos de ciberseguridad nacional e internacional.

---

**Referencias del Capítulo**

1. NIST. (2020). "NIST Cybersecurity Framework 1.1"
2. ISO/IEC 27001:2022 - Information security management systems
3. ISO/IEC 42001:2023 - Artificial intelligence management system
4. NIST. (2022). "Secure Software Development Framework (SSDF)"
5. OWASP. (2023). "Smart Contract Security Verification Standard (SCSVS)"
6. ENISA. (2021). "Distributed Ledger Technology & Cybersecurity - Threat Landscape"
7. European Commission. (2023). "Markets in Crypto-Assets Regulation (MiCA)"
8. UnceFain, M. et al. (2016). "The DAO Hack Explained"
