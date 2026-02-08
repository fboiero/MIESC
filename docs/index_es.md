---
layout: default
title: MIESC - Framework de Seguridad para Smart Contracts
lang: es
---

# MIESC - Evaluación Inteligente Multicapa para Smart Contracts

<p align="center">
  <img src="https://img.shields.io/badge/MIESC-v5.0.3-blue?style=for-the-badge" alt="MIESC v5.0.3">
  <img src="https://img.shields.io/pypi/v/miesc?style=for-the-badge&label=PyPI" alt="PyPI">
  <img src="https://img.shields.io/badge/Licencia-AGPL--3.0-green?style=for-the-badge" alt="Licencia">
  <img src="https://img.shields.io/badge/Python-3.12+-yellow?style=for-the-badge" alt="Python">
  <img src="https://img.shields.io/badge/IA-Potenciado-purple?style=for-the-badge" alt="IA Potenciado">
</p>

<p align="center">
  <strong>Framework de Seguridad Defense-in-Depth para Smart Contracts de Ethereum</strong><br>
  <em>Tesis de Maestría en Ciberdefensa | Universidad de la Defensa Nacional (UNDEF)</em>
</p>

<p align="center">
  <a href="https://youtu.be/pLa_McNBRRw">Video Demo</a> •
  <a href="thesis_es">Tesis</a> •
  <a href="INSTALLATION">Documentacion</a> •
  <a href="https://github.com/fboiero/MIESC">GitHub</a>
</p>

<p align="center">
  <a href="./">English</a> | <strong>Español</strong>
</p>

---

## Video Demostrativo

<p align="center">
  <strong>Mira MIESC en Acción</strong><br><br>
  <a href="https://youtu.be/pLa_McNBRRw">
    <img src="https://img.shields.io/badge/YouTube-Demo-red?style=for-the-badge&logo=youtube" alt="YouTube Demo">
  </a><br><br>
  <a href="https://youtu.be/pLa_McNBRRw">Ver en YouTube</a> (~10 minutos)
</p>

**Demuestra:**

- Análisis Defense-in-Depth a través de 9 capas de seguridad
- 31 herramientas integradas (Slither, Mythril, Echidna, Certora, etc.)
- Integración del Model Context Protocol (MCP) con Claude Desktop
- 100% Precisión, 70% Recall, F1-Score 82.35% (benchmark SmartBugs-curated)
- IA Soberana con Ollama (el código nunca sale de tu máquina)

---

## Alcance y Limitaciones

**Propósito:**

- Orquestación automatizada de 31 herramientas de análisis de seguridad
- Correlación asistida por IA para reducir reportes duplicados
- Detección de vulnerabilidades basada en ML con 95.7% de precisión
- Mapeo de cumplimiento a estándares ISO/NIST/OWASP
- Formato de reportes estandarizado (JSON/HTML/PDF)

**Limitaciones:**

- No puede detectar todas las clases de vulnerabilidades (especialmente logica de negocio compleja)
- Metricas de efectividad pendientes de validacion empirica a gran escala
- Requiere revision manual de todos los hallazgos por profesionales calificados
- No adecuado como unica evaluacion de seguridad para contratos en produccion

> **Importante**: Auditorias de seguridad profesionales obligatorias para contratos que manejen valor real.

---

## Descripción General

**MIESC** es un framework de seguridad de smart contracts de grado de producción que implementa una **arquitectura Defense-in-Depth de 9 capas**, integrando **31 herramientas de seguridad especializadas** con **correlación potenciada por IA** y **detección basada en ML** para ofrecer detección integral de vulnerabilidades con precisión líder en la industria.

### Logros Principales (v5.0.3)

- **31 Herramientas Integradas** en 9 capas de defensa
- **95.7% de Precisión de Detección ML** con Redes Neuronales de Grafos DA-GNN
- **100% Precisión**, **70% Recall**, **F1-Score 82.35%** (benchmark SmartBugs-curated)
- **91.4% Índice de Cumplimiento** en 12 estándares internacionales
- **IA Soberana** con Ollama - el código nunca sale de tu máquina
- **$0 Costo Operativo** - ejecución completamente local
- **Disponible en PyPI**: `pip install miesc`

---

## Novedades en v4.0.0

**Lanzamiento Mayor** (Enero 2025) - Cuatro mejoras basadas en investigación de vanguardia:

### 1. PropertyGPT (Capa 4 - Verificación Formal)

- Generación automatizada de propiedades CVL para verificación formal
- 80% recall en propiedades Certora de ground-truth
- Aumenta la adopción de verificación formal del 5% al 40% (+700%)
- Basado en paper NDSS 2025 (arXiv:2405.02580)

### 2. DA-GNN (Capa 6 - Detección ML)

- Detección de vulnerabilidades basada en Redes Neuronales de Grafos
- 95.7% de precisión con 4.3% de tasa de falsos positivos
- Representa contratos como grafos de flujo de control + flujo de datos
- Basado en Computer Networks (ScienceDirect, Feb 2024)

### 3. SmartLLM RAG Mejorado (Capa 5 - Análisis IA)

- Generación Aumentada por Recuperación con base de conocimiento ERC-20/721/1155
- Rol de Verificador para comprobación de hechos (Generador → Verificador → Consenso)
- Precisión mejorada del 75% al 88% (+17%), tasa FP reducida en 52%
- Basado en arXiv:2502.13167 (Feb 2025)

### 4. DogeFuzz (Capa 2 - Testing Dinámico)

- Fuzzing guiado por cobertura estilo AFL con programación de potencia
- Fuzzing híbrido + ejecución simbólica
- 85% cobertura de código, 3x más rápido que Echidna
- Basado en arXiv:2409.01788 (Sep 2024)

---

## Características

### Arquitectura de Defensa de 9 Capas

| Capa | Categoría | Herramientas | Enfoque de Detección |
|------|-----------|--------------|----------------------|
| **1** | Análisis Estático | Slither, Aderyn, Solhint | Detección de patrones (90+ detectores) |
| **2** | Testing Dinámico | Echidna, Medusa, Foundry, DogeFuzz | Fuzzing basado en propiedades |
| **3** | Ejecución Simbólica | Mythril, Manticore, Halmos | Exploración profunda de estados |
| **4** | Verificación Formal | Certora, SMTChecker | Pruebas matemáticas |
| **5** | Testing de Propiedades | PropertyGPT, Wake, Vertigo | Generación de invariantes |
| **6** | Análisis IA/LLM | SmartLLM, GPTScan, LLM-SmartAudit | Análisis semántico |
| **7** | Reconocimiento de Patrones | DA-GNN, SmartGuard, Clone Detector | Detección basada en ML |
| **8** | Seguridad DeFi | DeFi Analyzer, MEV Detector, Gas Analyzer | Específico de protocolos |
| **9** | Detección Avanzada | Advanced Detector, Threat Model | Correlación entre capas |

### Inteligencia Potenciada por IA

- **Correlación LLM Local**: Reduce falsos positivos usando deepseek-coder vía Ollama
- **Análisis de Causa Raíz**: Explicaciones de vulnerabilidades amigables para desarrolladores
- **Priorización de Riesgos**: Puntuación multidimensional (CVSS + explotabilidad + impacto)
- **Remediación Automatizada**: Recomendaciones de corrección accionables con parches de código

### Cumplimiento y Gobernanza

Mapeo incorporado a 12 frameworks de seguridad principales:

| Estándar | Cobertura | Dominio |
|----------|-----------|---------|
| ISO/IEC 27001:2022 | 5/5 controles | Seguridad de información |
| ISO/IEC 42001:2023 | 5/5 cláusulas | Gobernanza de IA |
| NIST SP 800-218 | 5/5 prácticas | Desarrollo seguro |
| OWASP SC Top 10 | 10/10 | Vulnerabilidades de smart contracts |
| OWASP SCSVS | Nivel 3 | Verificación de seguridad |
| Registro SWC | 33/37 tipos | Clasificación de debilidades |
| DASP Top 10 | 10/10 | Patrones DeFi |
| EU MiCA/DORA | Parcial | Cumplimiento regulatorio |

### Integración de Protocolo MCP

Soporte nativo de Model Context Protocol para integración con asistentes de IA:

- **run_audit** - Ejecutar análisis multi-herramienta
- **correlate_findings** - Aplicar filtrado IA
- **map_compliance** - Generar mapeos de cumplimiento
- **generate_report** - Producir reportes formateados

---

## Inicio Rápido

### Instalación

```bash
# Desde PyPI (recomendado)
pip install miesc

# Con todas las funciones
pip install miesc[full]

# Desde código fuente (desarrollo)
git clone https://github.com/fboiero/MIESC.git
cd MIESC && pip install -e .[dev]
```

### Uso Básico

```bash
# Escaneo rápido de vulnerabilidades
miesc scan contract.sol

# Modo CI/CD (exit 1 si hay issues críticos/altos)
miesc scan contract.sol --ci

# Auditoría completa de 9 capas
miesc audit full contract.sol

# Verificar disponibilidad de herramientas
miesc doctor
```

### Interfaz Web

```bash
# Lanzar UI web interactiva
pip install miesc[web]
make webapp
# Abrir navegador en http://localhost:8501
```

[Guía de Instalación Completa](INSTALLATION) | [Guía de Inicio Rápido](https://github.com/fboiero/MIESC/blob/main/QUICKSTART.md)
---

## Arquitectura

```
Smart Contract
      │
CoordinatorAgent (MCP)
      │
   ┌──┴──┬──────┬─────────┐
   │     │      │         │
Capa1  Capa2  Capa3   Capa4   → Herramientas ejecutan en paralelo
Static Dynamic Symbolic Formal
   │     │      │         │
   └──┬──┴──────┴─────────┘
      │
   Capa5 (Testing de Propiedades)
      │
   Capa6 (Análisis IA/LLM)
      │
   Capa7 (Reconocimiento de Patrones ML)
      │
   Capa8 (Seguridad DeFi)
      │
   Capa9 (Detección Avanzada + Correlación)
      │
   Reporte (JSON/HTML/PDF/SARIF)
```

### Descripción de Componentes

| Capa | Agente | Propósito | Salida |
|------|--------|-----------|--------|
| **L1-4** | Agentes de Análisis | Escaneo multi-herramienta | Hallazgos de vulnerabilidades crudos |
| **L5** | Agente de Propiedades | Generación de invariantes | Propiedades CVL/tests de propiedad |
| **L6** | Agente IA | Análisis semántico | Hallazgos correlacionados + causa raíz |
| **L7** | Agente ML | Detección basada en grafos | Patrones de vulnerabilidad |
| **L8** | Agente DeFi | Análisis específico de protocolos | Riesgos DeFi/MEV |
| **L9** | Agente Avanzado | Correlación entre capas | Reporte final de auditoría |

[Detalles de Arquitectura](thesis_es)
---

## Métricas de Rendimiento

### Resultados v5.0.3 (Benchmark SmartBugs-curated)

| Métrica | Valor | Notas |
|---------|-------|-------|
| **Precisión** | 100% | 0 falsos positivos |
| **Recall** | 70% | 35/50 vulnerabilidades detectadas |
| **F1-Score** | 82.35% | Benchmark de 50 contratos |
| **Herramientas** | 31 | Operativas en 9 capas |
| **Categorías con 100% Recall** | 3 | arithmetic, bad_randomness, front_running |

### Suite de Tests

- **117 tests pasando**
- **80.8% cobertura de código**
- **0 vulnerabilidades críticas**
- **31/31 herramientas operativas**

---

## Fundamento Académico

### Tesis de Maestría

**Título**: *Framework Integrado de Evaluación de Seguridad para Smart Contracts: Un Enfoque Defense-in-Depth para Ciberdefensa*

**Institución**: Universidad de la Defensa Nacional (UNDEF) - IUA Córdoba

**Autor**: Fernando Boiero

**Director**: M.Sc. Eduardo Casanovas

**Defensa Esperada**: Q4 2025

### Contribuciones de Investigación

1. **Arquitectura Defense-in-Depth de 9 Capas** para seguridad de smart contracts
2. **Integración de 31 Herramientas** bajo protocolo unificado ToolAdapter
3. **Sistema de Normalización Triple** (SWC/CWE/OWASP) con 97.1% de precisión
4. **Backend de IA Soberano** con Ollama para soberanía de datos
5. **Servidor MCP** para integración con asistentes de IA
6. **Rescate de Herramientas Legacy** (Manticore Python 3.11, Oyente Docker)

### Citación

```bibtex
@software{boiero2025miesc,
  author = {Boiero, Fernando},
  title = {MIESC: Evaluación Inteligente Multicapa para Smart Contracts},
  year = {2025},
  url = {https://github.com/fboiero/MIESC},
  version = {5.0.3},
  note = {Implementación para Tesis de Maestría en Ciberdefensa}
}
```

[Documentación de Tesis](tesis/)
---

## Documentación

### Comenzar

- [Guía de Instalación](INSTALLATION)
- [Ejemplos y Demos](https://github.com/fboiero/MIESC/tree/main/examples)
- [Ejecutar Web App](https://github.com/fboiero/MIESC#web-interface)
- [Configuración Docker](INSTALLATION#docker-installation)

### Conceptos Principales

- [Descripción de Arquitectura](thesis_es)
- [Correlación IA](thesis_es)
- [Policy Agent](thesis_es)
- [Protocolo MCP](thesis_es)

### Recursos para Desarrolladores

- [Guía de Desarrollador](CONTRIBUTING)
- [Guía de Contribución](CONTRIBUTING)
- [Referencia API](https://github.com/fboiero/MIESC)
- [Extender MIESC](CONTRIBUTING)

### Políticas y Gobernanza

- [Cumplimiento DPG](policies/DPG-COMPLIANCE_ES)
- [Gobernanza](policies/GOVERNANCE_ES)
- [Política de Privacidad](policies/PRIVACY_ES)

### Temas Avanzados

- [Seguridad Shift-Left](SECURITY_ES)
- [Mapeo de Cumplimiento](thesis_es)
- [Características v4.0](evidence/PHASE_3_4_5_COMPLETION_SUMMARY)

[Índice Completo de Documentación](index_es)
---

## Contribuir

Damos la bienvenida a contribuciones de las comunidades de investigación en seguridad y blockchain.

### Cómo Contribuir

1. **Hacer fork del repositorio**
2. **Crear una rama de feature**: `git checkout -b feature/nuevo-detector`
3. **Realizar cambios** siguiendo nuestra [guía de estilo](CONTRIBUTING)
4. **Ejecutar verificaciones de calidad**: `make all-checks`
5. **Enviar pull request**

### Áreas Prioritarias

- Specs CVL Certora para patrones comunes (ERC-20/721)
- Templates de propiedades Echidna para DeFi
- Tests de integración para las 31 herramientas
- Análisis de vulnerabilidades cross-chain
- Traducciones de documentación

[Guía de Contribución](CONTRIBUTING)
---

## Soporte y Comunidad

### Obtener Ayuda

- **Documentación**: [https://fboiero.github.io/MIESC](https://fboiero.github.io/MIESC)
- **Issues de GitHub**: [Reportes de bugs y solicitudes de features](https://github.com/fboiero/MIESC/issues)
- **Email**: <fboiero@frvm.utn.edu.ar>

---

## Ejemplos de Uso

**Escaneo Rápido (Integración CI/CD):**

```bash
miesc scan contracts/MyToken.sol --ci
# Código de salida 0 si no hay issues críticos, 1 de lo contrario
```

**Auditoría Completa de 9 Capas:**

```bash
miesc audit full contracts/MyToken.sol -o audit_report.json
```

**Auditoría Batch (Múltiples Contratos):**

```bash
miesc audit batch contracts/ -r -o batch_report.json
```

**Ejecución Selectiva de Capas:**

```bash
miesc audit full contracts/Treasury.sol --layers 1,3,6
# Ejecuta solo Capa 1 (Estático), Capa 3 (Simbólico), Capa 6 (IA)
```

**Exportar a Diferentes Formatos:**

```bash
miesc audit quick contract.sol -f sarif -o report.sarif
miesc audit quick contract.sol -f markdown -o report.md
```

**Modo Servidor MCP:**

```bash
miesc server mcp
# Habilita: audit_contract(), explain_vulnerability(), suggest_fix()
```

---

## Licencia

**Licencia AGPL-3.0** - Ver [LICENSE](LICENSE) para detalles.

Asegura que el framework permanezca open-source. Permite uso comercial con atribución. Trabajos derivados deben ser open-source.

**Descargo de responsabilidad**: Herramienta de investigación proporcionada "tal cual" sin garantías. Revisión manual por profesionales de seguridad calificados requerida. No es un reemplazo para auditorías profesionales.

---

## Agradecimientos

### Herramientas de Seguridad

- **Trail of Bits** (Slither, Manticore, Echidna)
- **Crytic** (Medusa)
- **ConsenSys** (Mythril)
- **Ackee Blockchain** (Wake)
- **Certora**
- **a16z** (Halmos)
- **Cyfrin** (Aderyn)
- **Ethereum Foundation** (SMTChecker)
- **Paradigm** (Foundry)
- **Anthropic** (MCP)

### Datasets

- SmartBugs (INESC-ID)
- SolidiFI (TU Delft)
- Etherscan

---

<p align="center">
  <strong>Construido para la Comunidad de Seguridad de Smart Contracts</strong>
</p>

<p align="center">
  <a href="INSTALLATION.md">Comenzar</a> |
  <a href="https://github.com/fboiero/MIESC">Ver en GitHub</a>
</p>

---

<p align="center">
  <strong>MIESC v5.0.3</strong> | Tesis de Maestría en Ciberdefensa | Licencia AGPL-3.0
</p>

<p align="center">
  2025 Fernando Boiero - Universidad de la Defensa Nacional (UNDEF)
</p>
