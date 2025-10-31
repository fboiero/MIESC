# 🛡️ MIESC - Documentación Completa

Marco Integrado de Evaluación de Seguridad en Smart Contracts con Arquitectura Multiagente MCP

---

## 📚 Índice de Documentación

### 🚀 Getting Started
1. [**README Principal**](../README.md) - Visión general y quick start
2. [**Deployment Guide**](deployment_guide.md) - Instalación y deployment
3. [**MCP Clients Setup**](MCP_clients_setup.md) - Configuración de clientes MCP

### 🏗️ Arquitectura
4. [**MIESC Framework**](MIESC_framework.md) - Especificación completa del framework
5. [**MCP Evolution**](MCP_evolution.md) - Evolución hacia arquitectura multiagente
6. [**Framework Evolution**](framework_evolution.md) - **NUEVO** Evolución histórica y justificación MCP
7. [**Tool Integration Standard**](tool_integration_standard.md) - **NUEVO** Estándar para integrar herramientas
8. [**Agents Usage**](agents_usage.md) - Guía de uso de cada agente

### 📋 Standards & Compliance
9. [**ISO/IEC 27001 Controls**](../standards/iso27001_controls.md) - Mapeo de controles
10. [**NIST SSDF Mapping**](../standards/nist_ssdf_mapping.md) - Prácticas NIST
11. [**OWASP SC Top 10**](../standards/owasp_sc_top10_mapping.md) - Cobertura OWASP

### 💻 Desarrollo
12. [**Examples README**](../examples/README.md) - Contratos de prueba
13. [**Testing Guide**](../test_mcp_e2e.py) - Tests end-to-end

---

## 🎯 Quick Navigation

### Para Empezar

**¿Primera vez usando MIESC?**
→ Leer: [README Principal](../README.md) → [Deployment Guide](deployment_guide.md)

**¿Quieres probar rápido?**
```bash
git clone https://github.com/fboiero/MIESC
cd xaudit
python demo_mcp_poc.py examples/voting.sol
```

**¿Necesitas integrarlo con un cliente?**
→ Leer: [MCP Clients Setup](MCP_clients_setup.md)

---

### Para Desarrolladores

**¿Quieres usar un agente específico?**
→ Leer: [Agents Usage Guide](agents_usage.md)

**¿Necesitas entender la arquitectura?**
→ Leer: [MIESC Framework](MIESC_framework.md) → [MCP Evolution](MCP_evolution.md)

**¿Quieres crear contratos de prueba?**
→ Leer: [Examples README](../examples/README.md)

---

### Para Compliance

**¿Necesitas certificación ISO 27001?**
→ Leer: [ISO/IEC 27001 Controls](../standards/iso27001_controls.md)

**¿Siguiendo NIST SSDF?**
→ Leer: [NIST SSDF Mapping](../standards/nist_ssdf_mapping.md)

**¿Validando contra OWASP?**
→ Leer: [OWASP SC Top 10 Mapping](../standards/owasp_sc_top10_mapping.md)

---

## 📖 Resumen de Cada Documento

### 1. README Principal
**Ubicación**: `../README.md`
**Contenido**:
- Justificación del framework
- Arquitectura Defense-in-Depth (6 capas)
- Evolución MCP multiagente
- Alineación con estándares
- Quick start guide
- Métricas y KPIs

**Cuándo leer**: Primera vez usando MIESC

---

### 2. Deployment Guide
**Ubicación**: `deployment_guide.md`
**Contenido**:
- Instalación local paso a paso
- Deployment en servidor Linux
- Docker y Kubernetes
- CI/CD integration
- Configuración de producción
- Monitoring y logging

**Cuándo leer**: Para instalar MIESC en cualquier entorno

---

### 3. MCP Clients Setup
**Ubicación**: `MCP_clients_setup.md`
**Contenido**:
- 6 clientes MCP open source
- Configuración detallada por cliente
- Comparativa de clientes
- Testing y validación
- Troubleshooting

**Cuándo leer**: Para conectar MIESC con clientes AI

**Clientes documentados**:
- 5ire (Desktop AI - Recomendado)
- AIQL TUUI (Multi-provider)
- Amazon Q IDE (VSCode)
- Amp (CLI + Multi-IDE)
- Apify MCP Tester (Testing)
- AgentAI (Rust library)

---

### 4. MIESC Framework
**Ubicación**: `MIESC_framework.md`
**Contenido**:
- Especificación formal del framework
- 6 capas de análisis detalladas
- Formato JSON unificado
- Integración de herramientas
- Métricas y validación
- Roadmap técnico

**Cuándo leer**: Para entender arquitectura técnica completa

---

### 5. MCP Evolution
**Ubicación**: `MCP_evolution.md`
**Contenido**:
- Historia evolutiva (3 etapas)
- Arquitectura multiagente
- 7 agentes especializados
- Protocolo MCP detallado
- Comparativa pipeline vs MCP
- Roadmap de implementación

**Cuándo leer**: Para entender transición a multiagente

---

### 6. Framework Evolution **NUEVO**
**Ubicación**: `framework_evolution.md`
**Contenido**:
- Evolución histórica (Fase 0 → v1.0 → v1.5 → v2.0 MCP)
- Justificación científica de cada fase
- Limitaciones identificadas y soluciones
- Comparativa de arquitecturas (secuencial vs multiagente)
- Métricas comparativas de rendimiento
- Aportaciones científicas

**Cuándo leer**: Para defensa de tesis, justificar decisiones arquitectónicas

**Contenido clave**:
- Benchmarks empíricos (v1.0: 132 min → v2.0: 20 min)
- Speedup 5x con arquitectura MCP paralela
- Comparación con estado del arte (LLM-SmartAudit, GPTScan)
- Validación con 800+ contratos

---

### 7. Tool Integration Standard **NUEVO**
**Ubicación**: `tool_integration_standard.md`
**Contenido**:
- Estándar para integrar nuevas herramientas
- Template paso a paso (BaseAgent + Tests)
- Ejemplos completos: GPTScan, LLM-SmartAudit, SmartLLM
- Schema unificado de findings
- Mapeo SWC → OWASP → CWE
- Validación y testing

**Cuándo leer**: Para integrar herramientas AI open source

**Herramientas documentadas**:
- GPTScan (ICSE 2024): Logic vulnerabilities con GPT + Falcon
- LLM-SmartAudit (ArXiv 2410.09381): Multi-agent conversational
- SmartLLM (ArXiv 2502.13167): LLaMA + RAG local

**Valor agregado**: Código completo funcional para 3 integraciones

---

### 8. Agents Usage Guide
**Ubicación**: `agents_usage.md`
**Contenido**:
- Documentación de 8 agentes
- Ejemplos de código funcionales
- Context types publicados
- Parámetros y configuración
- Best practices
- Troubleshooting

**Cuándo leer**: Para usar agentes programáticamente

**Agentes documentados**:
- BaseAgent
- StaticAgent (Layer 1)
- DynamicAgent (Layer 2)
- SymbolicAgent (Layer 4)
- FormalAgent (Layer 5)
- AIAgent (Layer 6)
- PolicyAgent (Compliance)
- CoordinatorAgent (Orchestrator)

---

### 9. ISO/IEC 27001 Controls
**Ubicación**: `../standards/iso27001_controls.md`
**Contenido**:
- Mapeo de 5 controles ISO 27001:2022
- Evidencias de implementación
- Compliance score: 100%
- Audit checklist

**Controles mapeados**:
- A.8.8: Management of technical vulnerabilities
- A.8.15: Logging
- A.8.16: Monitoring activities
- A.8.30: Testing
- A.14.2.5: Secure system engineering

**Cuándo leer**: Para certificación ISO 27001

---

### 8. NIST SSDF Mapping
**Ubicación**: `../standards/nist_ssdf_mapping.md`
**Contenido**:
- Mapeo de 5 prácticas NIST SSDF
- Implementación en MIESC
- Compliance score: 100%
- Alineación con ISO 42001

**Prácticas mapeadas**:
- PO.3.1: Ensure acquisition of genuine software
- PS.2: Review software design
- PW.8: Review/analyze developed code
- RV.1.1: Identify publicly disclosed vulnerabilities
- RV.3: Analyze vulnerabilities root causes

**Cuándo leer**: Para cumplimiento NIST

---

### 9. OWASP SC Top 10 Mapping
**Ubicación**: `../standards/owasp_sc_top10_mapping.md`
**Contenido**:
- Cobertura de 10 categorías OWASP
- Mapeo SWC → OWASP
- Herramientas por categoría
- Ejemplos de detección
- Coverage score: 95%

**Categorías cubiertas**:
- SC01: Reentrancy (100%)
- SC02: Access Control (100%)
- SC03: Arithmetic (100%)
- SC04: Unchecked Calls (100%)
- SC05: DoS (100%)
- SC06: Bad Randomness (100%)
- SC07: Front-Running (60%)
- SC08: Time Manipulation (100%)
- SC09: Short Address (40%)
- SC10: Unknown Unknowns (80%)

**Cuándo leer**: Para validación contra OWASP

---

### 10. Examples README
**Ubicación**: `../examples/README.md`
**Contenido**:
- 3 contratos de ejemplo documentados
- Vulnerabilidades intencionadas
- Comparativa vulnerable vs secure
- Comandos de testing
- Resultados esperados

**Contratos incluidos**:
- `voting.sol`: Básico para testing
- `vulnerable_bank.sol`: 4 vulnerabilidades conocidas
- `secure_bank.sol`: Best practices implementadas

**Cuándo leer**: Para crear tests o ejemplos

---

### 11. Testing Guide (test_mcp_e2e.py)
**Ubicación**: `../test_mcp_e2e.py`
**Contenido**:
- 8 test suites completas
- Testing de Context Bus
- Testing de agentes
- Testing cross-layer
- Validación de compliance

**Tests incluidos**:
1. Context Bus initialization
2. Agent initialization (7 agentes)
3. Pub/Sub messaging
4. StaticAgent execution
5. PolicyAgent compliance
6. CoordinatorAgent orchestration
7. Audit trail export
8. Cross-layer integration

**Cuándo usar**: Para validar instalación

---

## 🔍 Búsqueda Rápida por Tema

### Instalación
- [Deployment Guide](deployment_guide.md) - Sección "Instalación Local"
- [Deployment Guide](deployment_guide.md) - Sección "Docker Deployment"

### Uso de Agentes
- [Agents Usage Guide](agents_usage.md) - Por agente específico
- [MCP Evolution](MCP_evolution.md) - Arquitectura general

### Clientes MCP
- [MCP Clients Setup](MCP_clients_setup.md) - Todos los clientes
- [MCP Clients Setup](MCP_clients_setup.md) - Comparativa

### Compliance
- [ISO 27001 Controls](../standards/iso27001_controls.md)
- [NIST SSDF Mapping](../standards/nist_ssdf_mapping.md)
- [OWASP SC Top 10](../standards/owasp_sc_top10_mapping.md)

### Testing
- [test_mcp_e2e.py](../test_mcp_e2e.py) - Tests automatizados
- [Examples README](../examples/README.md) - Contratos de prueba

### Deployment
- [Deployment Guide](deployment_guide.md) - Producción
- [Deployment Guide](deployment_guide.md) - CI/CD

---

## 📊 Mapa de Flujos de Trabajo

### Workflow 1: Primera Instalación

```
1. Leer README Principal
   ↓
2. Seguir Deployment Guide (Instalación Local)
   ↓
3. Ejecutar test_mcp_e2e.py
   ↓
4. Probar demo_mcp_poc.py
   ↓
5. Configurar cliente MCP (MCP Clients Setup)
```

### Workflow 2: Uso Programático

```
1. Leer Agents Usage Guide
   ↓
2. Importar agente necesario
   ↓
3. Ver ejemplos en Examples README
   ↓
4. Ejecutar en contrato propio
```

### Workflow 3: Deployment Producción

```
1. Leer Deployment Guide (Servidor/Docker)
   ↓
2. Configurar CI/CD
   ↓
3. Setup monitoring
   ↓
4. Validar con tests E2E
   ↓
5. Deploy
```

### Workflow 4: Certificación/Compliance

```
1. Leer standard específico (ISO/NIST/OWASP)
   ↓
2. Ejecutar PolicyAgent
   ↓
3. Generar compliance report
   ↓
4. Exportar audit trail
   ↓
5. Review con auditor
```

---

## 🎓 Para Tesis/Investigación

### Documentos Clave para Defensa

1. **Justificación**: Framework Evolution (evolución histórica y científica)
2. **Arquitectura**: MIESC Framework + MCP Evolution
3. **Extensibilidad**: Tool Integration Standard (integrar herramientas AI)
4. **Implementación**: Agents Usage Guide
5. **Validación**: test_mcp_e2e.py + Examples README
6. **Compliance**: ISO 27001 + NIST SSDF + OWASP
7. **Deploy**: Deployment Guide

### Orden de Lectura Recomendado para Defensa

1. README Principal (contexto general)
2. **Framework Evolution** (justificación científica - **CLAVE PARA TESIS**)
3. MIESC Framework (arquitectura técnica)
4. MCP Evolution (innovación arquitectónica)
5. **Tool Integration Standard** (extensibilidad y futuro)
6. Standards (3 documentos) - compliance
7. Deployment Guide (implementación práctica)

### Documentos Nuevos para Tesis

**Framework Evolution** (`framework_evolution.md`):
- **Por qué**: Justifica científicamente la evolución v0 → v1 → v2
- **Qué aporta**: Benchmarks empíricos, comparación con estado del arte
- **Defensa**: Responde "¿Por qué MCP y no otra arquitectura?"

**Tool Integration Standard** (`tool_integration_standard.md`):
- **Por qué**: Demuestra extensibilidad del framework
- **Qué aporta**: 3 integraciones completas (GPTScan, LLM-SmartAudit, SmartLLM)
- **Defensa**: Responde "¿Cómo se integran herramientas AI del estado del arte?"

---

## 🔗 Enlaces Externos

### Estándares
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)
- [ISO/IEC 42001:2023](https://www.iso.org/standard/81230.html)
- [NIST SSDF](https://csrc.nist.gov/Projects/ssdf)
- [OWASP SC Top 10](https://owasp.org/www-project-smart-contract-top-10/)

### Herramientas
- [Slither](https://github.com/crytic/slither)
- [Mythril](https://github.com/ConsenSys/mythril)
- [Echidna](https://github.com/crytic/echidna)
- [Certora](https://www.certora.com/)
- [Foundry](https://getfoundry.sh/)

### MCP
- [MCP Official Docs](https://modelcontextprotocol.io/)
- [MCP GitHub](https://github.com/modelcontextprotocol)
- [MCP Clients](https://modelcontextprotocol.io/clients)

---

## 📞 Soporte

**Autor**: Fernando Boiero
**Email**: fboiero@frvm.utn.edu.ar
**Institución**: Universidad Tecnológica Nacional - FRVM
**GitHub**: [@fboiero](https://github.com/fboiero)

---

## 📝 Contribuir

Ver [CONTRIBUTING.md](../CONTRIBUTING.md) para guías de contribución.

---

## 📄 Licencia

GPL-3.0 License - Ver [LICENSE](../LICENSE)

---

**Última Actualización**: Octubre 2025
**Versión**: 2.1 (Con documentación para tesis)
**Status**: Production-Ready ✅
**Documentos**: 13 (11 originales + 2 nuevos para tesis)
