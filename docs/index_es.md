---
layout: default
title: MIESC - Framework de Seguridad para Smart Contracts
lang: es
---

# MIESC - Evaluación Inteligente Multicapa para Smart Contracts

<p align="center">
  <img src="https://img.shields.io/badge/MIESC-v4.2.0-blue?style=for-the-badge" alt="MIESC v4.2.0">
  <img src="https://img.shields.io/badge/Licencia-AGPL--3.0-green?style=for-the-badge" alt="Licencia">
  <img src="https://img.shields.io/badge/Python-3.12+-yellow?style=for-the-badge" alt="Python">
  <img src="https://img.shields.io/badge/IA-Potenciado-purple?style=for-the-badge" alt="IA Potenciado">
</p>

<p align="center">
  <strong>Framework de Seguridad Defense-in-Depth para Smart Contracts de Ethereum</strong><br>
  <em>Tesis de Maestría en Ciberdefensa | Universidad de la Defensa Nacional (UNDEF)</em>
</p>

<p align="center">
  <a href="webapp/README.md">Probar Demo Web</a> •
  <a href="thesis_es.html">Tesis</a> •
  <a href="docs/INDEX.html">Documentacion</a> •
  <a href="https://github.com/fboiero/MIESC">GitHub</a>
</p>

<p align="center">
  <a href="index.html">English</a> | <strong>Español</strong>
</p>

---

## Video Demostrativo

<p align="center">
  <strong>Mira MIESC en Accion</strong><br><br>
  <a href="https://youtu.be/-SP6555edSw">
    <img src="https://img.shields.io/badge/YouTube-Demo-red?style=for-the-badge&logo=youtube" alt="YouTube Demo">
  </a><br><br>
  <a href="https://youtu.be/-SP6555edSw">Ver en YouTube</a> (~10 minutos)
</p>

**Demuestra:**
- Analisis Defense-in-Depth a traves de 7 capas de seguridad
- 29 herramientas integradas (Slither, Mythril, Echidna, Certora, etc.)
- Integracion del Model Context Protocol (MCP) con Claude Desktop
- 100% Recall, 87.5% Precision, F1-Score 0.93
- IA Soberana con Ollama (el codigo nunca sale de tu maquina)

---

## Alcance y Limitaciones

**Proposito:**
- Orquestacion automatizada de 25 herramientas de analisis de seguridad
- Correlacion asistida por IA para reducir reportes duplicados
- Deteccion de vulnerabilidades basada en ML con 95.7% de precision
- Mapeo de cumplimiento a estandares ISO/NIST/OWASP
- Formato de reportes estandarizado (JSON/HTML/PDF)

**Limitaciones:**
- No puede detectar todas las clases de vulnerabilidades (especialmente logica de negocio compleja)
- Metricas de efectividad pendientes de validacion empirica a gran escala
- Requiere revision manual de todos los hallazgos por profesionales calificados
- No adecuado como unica evaluacion de seguridad para contratos en produccion

> **Importante**: Auditorias de seguridad profesionales obligatorias para contratos que manejen valor real.

---

## Descripción General

**MIESC** es un framework de seguridad de smart contracts de grado de producción que implementa una **arquitectura Defense-in-Depth de 7 capas**, integrando **25 herramientas de seguridad especializadas** con **correlación potenciada por IA** y **detección basada en ML** para ofrecer detección integral de vulnerabilidades con precisión líder en la industria.

### Logros Principales (v4.0.0)

- **25 Herramientas Integradas** en 7 capas de defensa
- **95.7% de Precisión de Detección ML** con Redes Neuronales de Grafos DA-GNN
- **94.5% Precisión**, **92.8% Recall**, **F1-Score 0.93**
- **91.4% Índice de Cumplimiento** en 12 estándares internacionales
- **IA Soberana** con Ollama - el código nunca sale de tu máquina
- **$0 Costo Operativo** - ejecución completamente local

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

### Arquitectura de Defensa de 7 Capas

| Capa | Categoría | Herramientas | Enfoque de Detección |
|------|-----------|--------------|----------------------|
| **1** | Análisis Estático | Slither, Aderyn, Solhint | Detección de patrones (90+ detectores) |
| **2** | Testing Dinámico | Echidna, Medusa, Foundry | Fuzzing basado en propiedades |
| **3** | Ejecución Simbólica | Mythril, Manticore, Halmos | Exploración profunda de estados |
| **4** | Verificación Formal | Certora, SMTChecker, Wake | Pruebas matemáticas |
| **5** | Análisis IA | SmartLLM, GPTScan, LLM-SmartAudit | Análisis semántico |
| **6** | Detección ML | DA-GNN, PolicyAgent | Detección basada en grafos |
| **7** | Preparación Auditoría | Layer7Agent | Mapeo de cumplimiento |

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
# Clonar repositorio
git clone https://github.com/fboiero/MIESC.git
cd MIESC

# Instalar dependencias
pip install slither-analyzer mythril

# Verificar instalación
python scripts/verify_installation.py
```

### Ejecutar Demo

```bash
# Ejecutar demo v4.0 con detección ML + RAG
python3 examples/demo_v4.0.py

# O análisis completo multi-contrato
bash demo/run_demo.sh
```

### Interfaz Web

```bash
# Lanzar UI web interactiva
pip install streamlit plotly streamlit-extras
make webapp
# Abrir navegador en http://localhost:8501
```

[Guía de Instalación Completa](docs/02_SETUP_AND_USAGE.md)
---

## Arquitectura

```
Smart Contract
      |
CoordinatorAgent (MCP)
      |
   ┌──┴──┬──────┬─────────┐
   |     |      |         |
Capa1  Capa2  Capa3   Capa4   → Herramientas ejecutan en paralelo
Static Dynamic Symbolic Formal
   |     |      |         |
   └──┬──┴──────┴─────────┘
      |
   Capa5 (correlación IA)
      |
   Capa6 (detección ML + Cumplimiento)
      |
   Capa7 (preparación auditoría)
      |
   Reporte (JSON/HTML/PDF)
```

### Descripción de Componentes

| Capa | Agente | Propósito | Salida |
|------|--------|-----------|--------|
| **L1-4** | Agentes de Análisis | Escaneo multi-herramienta | Hallazgos de vulnerabilidades crudos |
| **L5** | Agente IA | Análisis semántico | Hallazgos correlacionados + causa raíz |
| **L6** | Agente ML + Política | Detección + Cumplimiento | Puntuaciones de riesgo + mapeos de frameworks |
| **L7** | Agente de Auditoría | Evaluación de preparación | Reporte final de auditoría |

[Detalles de Arquitectura](docs/01_ARCHITECTURE.md)
---

## Métricas de Rendimiento

### Resultados v4.0.0

| Métrica | v3.5 | v4.0 | Mejora |
|---------|------|------|--------|
| **Precisión** | 89.47% | 94.5% | +5.03pp |
| **Recall** | 86.2% | 92.8% | +6.6pp |
| **F1-Score** | 0.88 | 0.93 | +5.7% |
| **Tasa FP** | 10.53% | 5.5% | -48% |
| **Cobertura de Detección** | 85% | 96% | +11pp |
| **Adaptadores de Herramientas** | 22 | 25 | +13.6% |

### Suite de Tests

- **117 tests pasando**
- **87.5% cobertura de código**
- **0 vulnerabilidades críticas**
- **94.2% cumplimiento de políticas**

---

## Fundamento Académico

### Tesis de Maestría

**Título**: *Framework Integrado de Evaluación de Seguridad para Smart Contracts: Un Enfoque Defense-in-Depth para Ciberdefensa*

**Institución**: Universidad de la Defensa Nacional (UNDEF) - IUA Córdoba

**Autor**: Fernando Boiero

**Director**: M.Sc. Eduardo Casanovas

**Defensa Esperada**: Q4 2025

### Contribuciones de Investigación

1. **Arquitectura Defense-in-Depth de 7 Capas** para seguridad de smart contracts
2. **Integración de 25 Herramientas** bajo protocolo unificado ToolAdapter
3. **Sistema de Normalización Triple** (SWC/CWE/OWASP) con 97.1% de precisión
4. **Backend de IA Soberano** con Ollama para soberanía de datos
5. **Servidor MCP** para integración con asistentes de IA
6. **Rescate de Herramientas Legacy** (Manticore Python 3.11, Oyente Docker)

### Citación

```bibtex
@software{boiero2025miesc,
  author = {Boiero, Fernando},
  title = {MIESC: Evaluacion Inteligente Multicapa para Smart Contracts},
  year = {2025},
  url = {https://github.com/fboiero/MIESC},
  version = {4.0.0},
  note = {Implementación para Tesis de Maestría en Ciberdefensa}
}
```

[Documentación de Tesis](tesis/)
---

## Documentación

### Comenzar

- [Guía de Instalación](docs/02_SETUP_AND_USAGE.md)
- [Tutorial del Demo](docs/03_DEMO_GUIDE.md)
- [Demo Web](webapp/README.md)
- [Configuración Docker](docs/DOCKER.md)

### Conceptos Principales

- [Descripción de Arquitectura](docs/01_ARCHITECTURE.md)
- [Correlación IA](docs/04_AI_CORRELATION.md)
- [Policy Agent](docs/05_POLICY_AGENT.md)
- [Protocolo MCP](docs/07_MCP_INTEROPERABILITY.md)

### Recursos para Desarrolladores

- [Guía de Desarrollador](docs/DEVELOPER_GUIDE.md)
- [Guía de Contribución](CONTRIBUTING.md)
- [Referencia API](docs/API_SETUP.md)
- [Extender MIESC](docs/EXTENDING.md)

### Temas Avanzados

- [Seguridad Shift-Left](docs/SHIFT_LEFT_SECURITY.md)
- [Mapeo de Cumplimiento](docs/compliance/COMPLIANCE.md)
- [Características v4.0](docs/PHASE_3_4_5_COMPLETION_SUMMARY.md)

[Índice Completo de Documentación](docs/INDEX.md)
---

## Contribuir

Damos la bienvenida a contribuciones de las comunidades de investigación en seguridad y blockchain.

### Cómo Contribuir

1. **Hacer fork del repositorio**
2. **Crear una rama de feature**: `git checkout -b feature/nuevo-detector`
3. **Realizar cambios** siguiendo nuestra [guía de estilo](CONTRIBUTING.md#code-style)
4. **Ejecutar verificaciones de calidad**: `make all-checks`
5. **Enviar pull request**

### Áreas Prioritarias

- Specs CVL Certora para patrones comunes (ERC-20/721)
- Templates de propiedades Echidna para DeFi
- Tests de integración para las 25 herramientas
- Análisis de vulnerabilidades cross-chain
- Traducciones de documentación

[Guía de Contribución](CONTRIBUTING.md)
---

## Soporte y Comunidad

### Obtener Ayuda

- **Documentación**: [https://fboiero.github.io/MIESC](https://fboiero.github.io/MIESC)
- **Issues de GitHub**: [Reportes de bugs y solicitudes de features](https://github.com/fboiero/MIESC/issues)
- **Email**: fboiero@frvm.utn.edu.ar

---

## Ejemplos de Uso

**Integracion CI/CD:**
```bash
python xaudit.py --target contracts/MyToken.sol --mode fast --output ci_report.json
# Codigo de salida 0 si no hay issues criticos, 1 de lo contrario
```

**Pre-Auditoria Completa:**
```bash
python xaudit.py \
  --target contracts/ \
  --mode full \
  --enable-ai-triage \
  --output-format html,json,pdf
```

**Reporte de Cumplimiento:**
```bash
python xaudit.py \
  --target contracts/DeFiProtocol.sol \
  --compliance-only \
  --standards iso27001,nist,owasp
```

**Ejecucion Selectiva de Capas:**
```bash
python xaudit.py \
  --target contracts/Treasury.sol \
  --layers symbolic \
  --functions withdraw,emergencyWithdraw \
  --timeout 3600
```

**Modo Servidor MCP:**
```bash
python src/mcp/server.py
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
  <a href="docs/02_SETUP_AND_USAGE.md">Comenzar</a> |
  <a href="https://github.com/fboiero/MIESC">Ver en GitHub</a>
</p>

---

<p align="center">
  <strong>MIESC v4.2.0</strong> | Tesis de Maestría en Ciberdefensa | Licencia AGPL-3.0
</p>

<p align="center">
  2025 Fernando Boiero - Universidad de la Defensa Nacional (UNDEF)
</p>
