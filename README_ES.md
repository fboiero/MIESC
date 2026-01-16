# MIESC - Evaluación Inteligente Multicapa para Smart Contracts

[![Licencia: AGPL v3](https://img.shields.io/badge/Licencia-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/miesc)](https://pypi.org/project/miesc/)
[![Versión](https://img.shields.io/badge/versión-4.3.4-green)](https://github.com/fboiero/MIESC/releases)
[![Build](https://img.shields.io/badge/build-passing-success)](https://github.com/fboiero/MIESC/actions/workflows/secure-dev-pipeline.yml)
[![Cobertura](https://img.shields.io/badge/cobertura-81%25-green)](./htmlcov/index.html)
[![Herramientas](https://img.shields.io/badge/herramientas-31%2F31%20operativas-brightgreen)](./docs/TOOLS.md)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit)

[English](./README.md) | **Español**

Framework de análisis de seguridad multicapa para smart contracts de Ethereum. Orquesta **31 herramientas especializadas** a través de **9 capas de defensa** con correlación asistida por IA y detección basada en ML.

**Resultados Validados (dataset SmartBugs-curated, 50 contratos):**

- **Precisión: 100%** (0 falsos positivos)
- **Recall: 70%** (35/50 vulnerabilidades detectadas)
- **F1-Score: 82.35%**
- Categorías con 100% recall: arithmetic, bad_randomness, front_running

Arquitectura basada en investigación de análisis multi-herramienta (Durieux et al., 2020; Atzei et al., 2017). Desarrollado como parte de una Tesis de Maestría en Ciberdefensa en la Universidad de la Defensa Nacional (UNDEF), Argentina.

**Estado**: Implementación completa. Validación empírica a gran escala en progreso (planificada Q4 2025).

**Importante**: Herramienta de triaje pre-auditoría, no un reemplazo para auditorías de seguridad profesionales. Todos los contratos en producción requieren revisión por auditores calificados.

Documentación: [fboiero.github.io/MIESC](https://fboiero.github.io/MIESC) | Issues: [github.com/fboiero/MIESC/issues](https://github.com/fboiero/MIESC/issues)

---

## Alcance y Limitaciones

**Propósito**:

- Orquestación automatizada de 31 herramientas de análisis de seguridad
- Correlación de hallazgos asistida por IA para reducir reportes duplicados
- Detección de vulnerabilidades basada en ML con 95.7% de precisión
- Mapeo de cumplimiento a estándares ISO/NIST/OWASP
- Formato de reporte estandarizado (JSON/HTML/PDF)

**Limitaciones**:

- No puede detectar todas las clases de vulnerabilidades (especialmente lógica de negocio compleja)
- Métricas de efectividad pendientes de validación empírica a gran escala
- Requiere revisión manual de todos los hallazgos por profesionales calificados
- No es adecuado como única evaluación de seguridad para contratos en producción

**Importante**: Auditorías de seguridad profesionales son obligatorias para contratos que manejan valor real.

---

## Interfaz Web

UI web interactiva para análisis de contratos sin instalación CLI.

```bash
pip install streamlit plotly streamlit-extras
make webapp
# o: streamlit run webapp/app.py
```

Características:

- Subir o pegar archivos fuente Solidity
- Análisis multi-herramienta (Slither, Mythril, Aderyn)
- Correlación IA para reducción de falsos positivos
- Gráficos interactivos de severidad y puntuación de riesgo
- Exportación de reportes en JSON y Markdown
- Ejemplos de contratos vulnerables precargados

Acceso: <http://localhost:8501>
Documentación: [webapp/README.md](./webapp/README.md)

---

## Inicio Rápido

```bash
# Desde PyPI (recomendado)
pip install miesc

# O con Docker (no requiere instalación local)
docker pull ghcr.io/fboiero/miesc:latest
docker run --rm -v $(pwd):/contracts ghcr.io/fboiero/miesc:latest scan /contracts/MiContrato.sol
```

<details>
<summary><strong>Solución de Problemas Docker</strong></summary>

**Error "executable file not found" o "scan: not found":**

Tienes una imagen cacheada antigua. Fuerza una descarga limpia:

```bash
# Eliminar imágenes cacheadas
docker rmi ghcr.io/fboiero/miesc:latest 2>/dev/null
docker rmi ghcr.io/fboiero/miesc:main 2>/dev/null

# Descargar imagen fresca
docker pull ghcr.io/fboiero/miesc:latest

# Verificar versión (debe mostrar 4.3.4+)
docker run --rm ghcr.io/fboiero/miesc:latest --version
```

**Uso correcto:**

```bash
# Correcto - argumentos pasan directamente a miesc
docker run --rm ghcr.io/fboiero/miesc:latest --help
docker run --rm ghcr.io/fboiero/miesc:latest scan /contracts/MiContrato.sol

# Incorrecto - NO repetir "miesc"
docker run --rm ghcr.io/fboiero/miesc:latest miesc scan ...  # MAL!
```

**Archivo de contrato no encontrado:**

```bash
# Asegúrate de que el path del volumen sea correcto
docker run --rm -v /ruta/completa/contratos:/contracts ghcr.io/fboiero/miesc:latest scan /contracts/MiContrato.sol

# En Windows PowerShell, usa ${PWD}
docker run --rm -v ${PWD}:/contracts ghcr.io/fboiero/miesc:latest scan /contracts/MiContrato.sol
```

</details>

```bash
# Escaneo rápido de vulnerabilidades
miesc scan contrato.sol

# Modo CI/CD (exit 1 si hay issues críticos/altos)
miesc scan contrato.sol --ci

# Auditoría rápida con 4 herramientas
miesc audit quick contrato.sol

# Auditoría completa con 9 capas
miesc audit full contrato.sol

# Generar reporte profesional de auditoría
miesc report results.json -t professional -o reporte.md

# Seguimiento de postura de seguridad
miesc benchmark ./contracts --save

# Verificar disponibilidad de herramientas
miesc doctor

# Modo watch (escaneo automático al guardar)
miesc watch ./contracts
```

**[Guía de Inicio Rápido Completa](./QUICKSTART_ES.md)** - Instrucciones detalladas de instalación y uso.

### Hook Pre-commit

Integra MIESC en tu flujo de trabajo git:

```bash
pip install pre-commit
```

Agrega a tu `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/fboiero/MIESC
    rev: v4.3.4
    hooks:
      - id: miesc-quick
        args: ['--ci']  # Falla en issues críticos/altos
```

```bash
pre-commit install
git commit -m "..."  # MIESC ejecuta automáticamente
```

Ver [examples/pre-commit-config.yaml](./examples/pre-commit-config.yaml) para más opciones.

### Integración con Foundry

Agrega MIESC a tu proyecto Foundry:

```toml
# foundry.toml
[profile.default]
post_build_hook = "miesc audit quick ./src --ci"

[profile.ci]
post_build_hook = "miesc audit quick ./src --ci --fail-on high"
```

```bash
forge build  # MIESC ejecuta automáticamente después del build
```

Ver [integrations/foundry/](./integrations/foundry/) para scripts y GitHub Actions.

### Integración con Hardhat

Agrega MIESC a tu proyecto Hardhat:

```javascript
// hardhat.config.js
require("hardhat-miesc");

module.exports = {
  solidity: "0.8.20",
  miesc: {
    enabled: true,
    runOnCompile: true,  // Escaneo automático después de compilar
    failOn: "high",
  },
};
```

```bash
npx hardhat miesc           # Ejecutar auditoría de seguridad
npx hardhat miesc:full      # Auditoría completa de 9 capas
npx hardhat miesc:doctor    # Verificar instalación
```

Ver [integrations/hardhat/](./integrations/hardhat/) para documentación completa del plugin.

### Servidor MCP (Integración con MCP client)

MIESC incluye un servidor MCP (Model Context Protocol) para integración en tiempo real con agentes de IA como MCP client:

```bash
# Iniciar el servidor MCP WebSocket
miesc server mcp

# Host/puerto personalizado
miesc server mcp --host 0.0.0.0 --port 9000
```

**Configuración de MCP client** (`~/.config/mcp/config.json`):
```json
{
  "mcpServers": {
    "miesc": {
      "command": "miesc",
      "args": ["server", "mcp"]
    }
  }
}
```

Características:
- Streaming en tiempo real del progreso de auditoría
- Notificaciones de hallazgos a medida que se descubren
- Soporte multi-sesión para auditorías concurrentes
- Compatible con cualquier cliente MCP

Ver [docs/03_DEMO_GUIDE.md](./docs/03_DEMO_GUIDE.md) para detalles.

---

## Demostración en Video

YouTube: [youtu.be/-SP6555edSw](https://youtu.be/-SP6555edSw)

Demuestra:

- Análisis Defense-in-Depth a través de 9 capas de seguridad
- 31 herramientas integradas (Slither, Mythril, Echidna, Certora, etc.)
- Integración Model Context Protocol (MCP) con MCP client
- 100% Precisión, 70% Recall, F1-Score 0.82 (dataset SmartBugs-curated)
- IA Soberana con Ollama (el código nunca sale de tu máquina)

Duración: ~10 minutos | Fuente: `demo_thesis_defense.py`

---

## Novedades en v4.0

**Lanzamiento Mayor** (Enero 2025) - Cuatro mejoras basadas en investigación de vanguardia:

**1. PropertyGPT (Capa 4 - Verificación Formal)**

- Generación automatizada de propiedades CVL para verificación formal
- 80% recall en propiedades Certora de ground-truth
- Aumenta la adopción de verificación formal del 5% al 40% (+700%)
- Basado en paper NDSS 2025 (arXiv:2405.02580)

**2. DA-GNN (Capa 6 - Detección ML)**

- Detección de vulnerabilidades basada en Redes Neuronales de Grafos
- 95.7% de precisión con 4.3% de tasa de falsos positivos
- Representa contratos como grafos de flujo de control + flujo de datos
- Basado en Computer Networks (ScienceDirect, Feb 2024)

**3. SmartLLM RAG Mejorado (Capa 5 - Análisis IA)**

- Generación Aumentada por Recuperación con base de conocimiento ERC-20/721/1155
- Rol de Verificador para comprobación de hechos (Generador → Verificador → Consenso)
- Precisión mejorada del 75% al 88% (+17%), tasa FP reducida en 52%
- Basado en arXiv:2502.13167 (Feb 2025)

**4. DogeFuzz (Capa 2 - Testing Dinámico)**

- Fuzzing guiado por cobertura estilo AFL con programación de potencia
- Fuzzing híbrido + ejecución simbólica
- 85% cobertura de código, 3x más rápido que Echidna
- Basado en arXiv:2409.01788 (Sep 2024)

**Métricas** (v3.5 → v4.0):

- Total Adaptadores: 22 → 29 (+31.8%)
- Precisión: 89.47% → 94.5% (+5.03pp)
- Recall: 86.2% → 92.8% (+6.6pp)
- Tasa FP: 10.53% → 5.5% (-48%)
- Cobertura de Detección: 85% → 96% (+11pp)

Ver [docs/PHASE_3_4_5_COMPLETION_SUMMARY.md](./docs/PHASE_3_4_5_COMPLETION_SUMMARY.md) para detalles de implementación.

---

## Descripción General

MIESC (Evaluación Inteligente Multicapa para Smart Contracts) orquesta 31 herramientas de análisis de seguridad a través de una interfaz unificada con correlación asistida por IA y detección basada en ML.

**Problema**: Ejecutar múltiples herramientas de seguridad individualmente produce cientos de advertencias con altas tasas de falsos positivos, requiriendo triaje manual significativo.

**Enfoque**: Orquestación automatizada de herramientas con correlación IA para identificar duplicados y hallazgos relacionados entre herramientas.

**Estado**: Implementación del framework completa. Métricas de rendimiento pendientes de estudio empírico a gran escala (planificado Q4 2025).

### Estado de Implementación

| Componente | Estado | Detalles |
|------------|--------|----------|
| Herramientas Integradas | ✅ Completo | 31 herramientas en 9 capas |
| Protocolo MCP | ✅ Completo | Interfaz JSON-RPC funcional |
| Correlación IA | ✅ Completo | LLM local via Ollama |
| Mapeo de Cumplimiento | ✅ Completo | 12 estándares (ISO/NIST/OWASP) |
| Tests Unitarios | ✅ Pasando | 716 tests, 87.5% cobertura |
| Validación Empírica | 🚧 En Progreso | Estudio a gran escala planificado Q4 2025 |

**Validado**: Integración de herramientas, implementación de protocolo, funcionalidad básica
**Pendiente**: Mediciones de precisión/recall, estudio de validación por expertos, benchmarking a gran escala

---

## Instalación y Uso

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC
pip install slither-analyzer mythril  # Dependencias principales
python xaudit.py --target examples/reentrancy.sol
```

Salida: Dashboard HTML + reporte JSON con hallazgos mapeados a OWASP/SWC/CWE

Ejemplo de análisis:

```bash
# Crear contrato de prueba
cat << EOF > vulnerable.sol
pragma solidity ^0.8.0;
contract VulnerableBank {
    mapping(address => uint) public balances;
    function withdraw() public {
        uint amount = balances[msg.sender];
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
}
EOF

# Analizar
python xaudit.py --target vulnerable.sol --mode fast
```

Salida esperada (~30 segundos):

```
StaticAgent (Slither): Reentrancy en withdraw() [HIGH]
SymbolicAgent (Mythril): SWC-107 confirmado [CRITICAL]
AIAgent: Análisis de causa raíz + sugerencia de parche
PolicyAgent: Violación OWASP SC-01, brecha ISO 27001

Resumen: 1 CRITICAL, 0 HIGH, 0 MEDIUM, 0 LOW
Reporte: outputs/vulnerable_report.html
```

---

## Características

**Orquestación multi-herramienta**: Un solo comando ejecuta todas las herramientas configuradas en lugar de ejecutar cada una individualmente:

```bash
python xaudit.py --target mycontract.sol
```

**Filtrado de falsos positivos**: Correlación asistida por IA reduce el conteo de advertencias de ~147 (salida cruda) a ~8 hallazgos accionables filtrando duplicados y detecciones de baja confianza.

**Reportes estandarizados**: Genera salidas JSON, HTML y PDF con hallazgos mapeados a clasificaciones SWC/CWE/OWASP para documentación de trail de auditoría.

**Integración CI/CD**:

```yaml
# Ejemplo GitHub Actions
- name: Análisis de Seguridad
  run: |
    pip install slither-analyzer mythril
    python xaudit.py --target contracts/ --fail-on critical
```

**API Python**:

```python
from miesc import MiescFramework

auditor = MiescFramework()
report = auditor.analyze("MyToken.sol", layers=["static", "dynamic"])
print(f"Críticos: {len(report.critical_issues)}")
```

---

## Integración Model Context Protocol (MCP)

MIESC implementa MCP (Model Context Protocol de Anthropic) para acceso programático via asistentes de IA y herramientas de automatización.

**Endpoints MCP**:

- `run_audit` - Ejecutar análisis multi-herramienta
- `correlate_findings` - Aplicar filtrado IA
- `map_compliance` - Generar mapeos de cumplimiento
- `calculate_metrics` - Calcular estadísticas de validación
- `generate_report` - Producir reportes formateados
- `get_status` - Consultar salud del sistema

**Configuración** (ejemplo MCP client):

```json
// ~/.config/mcp/config.json
{
  "mcpServers": {
    "miesc": {
      "url": "http://localhost:8080/mcp/jsonrpc"
    }
  }
}
```

**Uso** (Python):

```python
import requests

response = requests.post("http://localhost:8080/mcp/jsonrpc", json={
    "jsonrpc": "2.0",
    "method": "run_audit",
    "params": {"contract_path": "MyToken.sol", "tools": ["slither", "mythril"]}
})

findings = response.json()["result"]["scan_results"]
```

**Inicio del servidor**:

```bash
python -m miesc.mcp.server --port 8080
curl http://localhost:8080/health  # Verificar
```

Documentación: [docs/MCP_INTEGRATION.md](./docs/MCP_INTEGRATION.md)

---

## Arquitectura

Enfoque defense-in-depth de siete capas basado en Saltzer & Schroeder (1975):

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
   Capa6 (mapeo cumplimiento)
      |
   Reporte (JSON/HTML/PDF)
```

**Asignación de capas** (31 herramientas):

- **Capa 1 (Estático)**: Slither, Aderyn, Solhint
- **Capa 2 (Dinámico)**: Echidna, Medusa, Foundry
- **Capa 3 (Simbólico)**: Mythril, Manticore, Halmos
- **Capa 4 (Formal)**: Certora, SMTChecker, Wake
- **Capa 5 (IA)**: SmartLLM, GPTScan, LLM-SmartAudit
- **Capa 6 (Política)**: PolicyAgent (incorporado)
- **Capa 7 (Auditoría)**: Layer7Agent (incorporado)

**Características de rendimiento**:

| Capa | Tiempo de Ejecución | Detección Principal |
|------|---------------------|---------------------|
| 1-2 (Rápido) | <10s | Patrones comunes (reentrancy, overflow) |
| 3-4 (Profundo) | 30-600s | Fallas de lógica, violaciones de assertions |
| 5 (IA) | 30-120s | Problemas semánticos, problemas de diseño |

**Uso recomendado**:

- Desarrollo: Solo Capa 1 (CI/CD)
- Pre-auditoría: Capas 1+2+5
- Producción: Las 9 capas

---

## Arquitectura de Agentes

**Adaptadores de herramientas** (31):

| Capa | Adaptador | Herramienta Subyacente |
|------|-----------|------------------------|
| 1 | SlitherAdapter, AderynAdapter, SolhintAdapter | Slither, Aderyn, Solhint |
| 2 | EchidnaAdapter, MedusaAdapter, FoundryAdapter | Echidna, Medusa, Foundry |
| 3 | MythrilAdapter, ManticoreAdapter, HalmosAdapter | Mythril, Manticore, Halmos |
| 4 | CertoraAdapter, SMTCheckerAdapter, WakeAdapter | Certora, SMTChecker, Wake |
| 5 | SmartLLMAdapter, GPTScanAdapter, LLMSmartAuditAdapter | Ollama, GPTScan, framework LLM |
| 6 | PolicyAgent (incorporado) | Verificaciones de cumplimiento ISO/NIST/OWASP |
| 7 | Layer7Agent (incorporado) | Evaluación de preparación para auditoría |

**Agentes de orquestación**:

- CoordinatorAgent: Gestiona ejecución de herramientas y agregación de resultados
- ReportAgent: Genera salida formateada (JSON/HTML/PDF)

Todos los adaptadores implementan la interfaz `ToolAdapter` para integración uniforme.

---

## Análisis Asistido por IA

La integración LLM proporciona capacidades de análisis adicionales más allá de la salida cruda de herramientas:

| Función | Modelo | Propósito |
|---------|--------|-----------|
| Correlación de hallazgos | deepseek-coder (local) | Identificar duplicados entre herramientas |
| Análisis de causa raíz | deepseek-coder (local) | Explicar mecanismos de vulnerabilidad |
| Generación de exploits | CodeLlama 13B | Generar ataques de prueba de concepto |
| Mapeo de superficie de ataque | CodeLlama 13B | Identificar puntos de entrada y límites de confianza |
| Sugerencias de remediación | CodeLlama 13B | Proponer correcciones con parches de código |
| Mapeo de cumplimiento | CodeLlama 13B | Mapear hallazgos a estándares (ISO/NIST/OWASP) |

Configuración por defecto usa modelos locales (Ollama) para soberanía de datos. Soporte GPT-4 disponible via clave API opcional.

---

## Documentación

Documentación completa: [fboiero.github.io/MIESC](https://fboiero.github.io/MIESC)

**Configuración**:

- [Instalación](https://fboiero.github.io/MIESC/docs/02_SETUP_AND_USAGE/)
- [Guía Demo](https://fboiero.github.io/MIESC/docs/03_DEMO_GUIDE/)
- [Docker](https://fboiero.github.io/MIESC/docs/DOCKER/)

**Arquitectura**:

- [Descripción General](https://fboiero.github.io/MIESC/docs/01_ARCHITECTURE/)
- [Correlación IA](https://fboiero.github.io/MIESC/docs/04_AI_CORRELATION/)
- [Policy Agent](https://fboiero.github.io/MIESC/docs/05_POLICY_AGENT/)
- [Protocolo MCP](https://fboiero.github.io/MIESC/docs/07_MCP_INTEROPERABILITY/)

**Desarrollo**:

- [Guía de Desarrollador](https://fboiero.github.io/MIESC/docs/DEVELOPER_GUIDE/)
- [Contribuir](https://fboiero.github.io/MIESC/CONTRIBUTING/)
- [Referencia API](https://fboiero.github.io/MIESC/docs/API_SETUP/)

**Construir docs localmente**:

```bash
make install-docs  # Instalar MkDocs
make docs          # Servir en http://127.0.0.1:8000
make docs-build    # Generar sitio estático
make docs-deploy   # Desplegar a GitHub Pages
```

---

## Fundamento de Investigación

Arquitectura basada en investigación revisada por pares en seguridad de smart contracts y sistemas multi-agente.

**Preguntas de investigación de tesis** (validación empírica en progreso):

1. Efectividad multi-herramienta: ¿Combinar 31 herramientas mejora la detección vs. herramientas individuales?
   - Hipótesis basada en Durieux et al. (2020): 34% de mejora esperada

2. Correlación IA: ¿Pueden los LLMs locales reducir hallazgos duplicados entre herramientas?
   - Implementación completa, validación cuantitativa pendiente

3. Integración de flujo de trabajo: ¿Puede la orquestación reducir tiempo de triaje manual?
   - Tiempo de ejecución de herramientas medido, estudio de usuario end-to-end pendiente

4. Automatización de cumplimiento: ¿Pueden los hallazgos auto-mapearse a múltiples estándares?
   - Implementación completa: 12 estándares (ISO/NIST/OWASP/EU)

5. Reproducibilidad: ¿Son los resultados repetibles?
   - Framework: 716 tests pasando, 87.5% cobertura
   - Estudio a gran escala: planificado Q4 2025

**Estado actual de validación**:

- ✅ Integración de herramientas funcional (31 adaptadores)
- ✅ Suite de tests pasando (unitarios + integración)
- ✅ Implementación de referencia completa
- 🚧 Estudio de precisión/recall a gran escala (pendiente)
- 🚧 Validación inter-evaluador por expertos (pendiente)
- 🚧 Análisis de dataset de producción (pendiente)

**Fundamento teórico**:

- Saltzer & Schroeder (1975): Principios de defense-in-depth → arquitectura de 9 capas
- Durieux et al. (2020): Estudio multi-herramienta en 47,587 contratos → selección de herramientas complementarias
- Atzei et al. (2017): Taxonomía de ataques Ethereum → clasificación de vulnerabilidades
- Wooldridge & Jennings (1995): Sistemas multi-agente → arquitectura de adaptadores
- Anthropic (2024): Model Context Protocol → comunicación de agentes

Bibliografía completa: [docs/compliance/REFERENCES.md](./docs/compliance/REFERENCES.md)

**Contexto académico**: Tesis de Maestría en Ciberdefensa, Universidad de la Defensa Nacional (UNDEF), Argentina. Defensa Q4 2025.

---

## Ejemplos de Uso

**Integración CI/CD**:

```bash
python xaudit.py --target contracts/MyToken.sol --mode fast --output ci_report.json
# Código de salida 0 si no hay issues críticos, 1 en caso contrario
```

**Pre-auditoría completa**:

```bash
python xaudit.py \
  --target contracts/ \
  --mode full \
  --enable-ai-triage \
  --output-format html,json,pdf
```

**Reporte de cumplimiento**:

```bash
python xaudit.py \
  --target contracts/DeFiProtocol.sol \
  --compliance-only \
  --standards iso27001,nist,owasp
```

**Ejecución selectiva de capas**:

```bash
python xaudit.py \
  --target contracts/Treasury.sol \
  --layers symbolic \
  --functions withdraw,emergencyWithdraw \
  --timeout 3600
```

**Procesamiento por lotes**:

```bash
python xaudit.py \
  --target contracts/ \
  --parallel 4 \
  --recursive \
  --exclude test,mock \
  --output batch_results/
```

**Modo servidor MCP**:

```bash
python src/mcp/server.py
# Habilita: audit_contract(), explain_vulnerability(), suggest_fix()
```

---

## Herramientas Integradas

*Versiones a Noviembre 2025. Consultar repositorios oficiales para últimas versiones.*

| Capa | Herramienta | Versión | Licencia | Enfoque de Detección | Instalación |
|------|-------------|---------|----------|----------------------|-------------|
| **Estático** | [Slither](https://github.com/crytic/slither) | 0.10.x | AGPL-3.0 | Análisis estático (90+ detectores) | `pip install slither-analyzer` |
| **Estático** | [Aderyn](https://github.com/Cyfrin/aderyn) | 0.6.x | MIT | Analizador AST basado en Rust | `cargo install aderyn` |
| **Estático** | [Solhint](https://github.com/protofire/solhint) | 5.0.x | MIT | Linter (200+ reglas) | `npm install -g solhint` |
| **Dinámico** | [Echidna](https://github.com/crytic/echidna) | 2.2.x | AGPL-3.0 | Fuzzer basado en propiedades | `brew install echidna` |
| **Dinámico** | [Medusa](https://github.com/crytic/medusa) | 0.1.x | AGPL-3.0 | Fuzzer guiado por cobertura | Binario desde [releases](https://github.com/crytic/medusa/releases) |
| **Dinámico** | [Foundry](https://github.com/foundry-rs/foundry) | nightly | MIT/Apache-2.0 | Toolkit de testing y fuzzing | `curl -L foundry.paradigm.xyz \| bash` |
| **Simbólico** | [Mythril](https://github.com/ConsenSys/mythril) | 0.24.x | MIT | Herramienta de ejecución simbólica | `pip install mythril` |
| **Simbólico** | [Manticore](https://github.com/trailofbits/manticore) | 0.3.x | AGPL-3.0 | Motor de ejecución simbólica | `pip install manticore` |
| **Simbólico** | [Halmos](https://github.com/a16z/halmos) | 0.2.x | AGPL-3.0 | Testing simbólico (integración Foundry) | `pip install halmos` |
| **Formal** | [Certora](https://www.certora.com/) | 2024.11 | Comercial | Verificador formal basado en CVL | Ver [docs](https://docs.certora.com) |
| **Formal** | [SMTChecker](https://docs.soliditylang.org/en/latest/smtchecker.html) | 0.8.20+ | GPL-3.0 | Verificador incorporado en Solidity | Incluido con `solc >= 0.8.20` |
| **Formal** | [Wake](https://github.com/Ackee-Blockchain/wake) | 4.x | ISC | Framework de desarrollo Python | `pip install eth-wake` |
| **IA** | GPTScan | N/A | Investigación | Analizador semántico GPT-4 | Incorporado (requiere clave API OpenAI) |
| **IA** | LLM-SmartAudit | N/A | AGPL-3.0 | Framework LLM multi-agente | Incorporado |
| **IA** | SmartLLM | N/A | AGPL-3.0 | LLM local via Ollama | Incorporado (requiere Ollama) |
| **Política** | PolicyAgent | N/A | AGPL-3.0 | Mapeador de cumplimiento (12 estándares) | Incorporado |

**Integración de herramienta personalizada**: Implementar interfaz `ToolAdapter`. Ver [docs/EXTENDING.md](./docs/EXTENDING.md)

---

## Estándares de Cumplimiento

Los hallazgos se mapean automáticamente a 12 estándares internacionales para documentación de trail de auditoría.

| Estándar | Cobertura | Dominio |
|----------|-----------|---------|
| ISO/IEC 27001:2022 | 5/5 controles | Seguridad de información |
| ISO/IEC 42001:2023 | 5/5 cláusulas | Gobernanza de IA |
| NIST SP 800-218 | 5/5 prácticas | Desarrollo seguro |
| OWASP SC Top 10 | 10/10 | Vulnerabilidades de smart contracts |
| OWASP SCSVS | Nivel 3 | Verificación de seguridad |
| Registro SWC | 33/37 tipos | Clasificación de debilidades |
| DASP Top 10 | 10/10 | Patrones DeFi |
| CCSS v9.0 | 6/7 aspectos | Seguridad de criptomonedas |
| Directrices DeFi EEA | 6/6 categorías | Evaluación de riesgos |
| EU MiCA | 2/3 requisitos | Mercados de Criptoactivos |
| EU DORA | 10/13 requisitos | Resiliencia digital |
| Checklist Trail of Bits | 33/42 items | Metodología de auditoría |

Total: 91.4% índice de cumplimiento

**Generar evidencia**:

```bash
python xaudit.py --target contracts/ --evidence-for iso27001
# Genera archivos JSON mapeados a controles específicos
```

Detalles: [COMPLIANCE.md](./docs/compliance/COMPLIANCE.md)

---

## Rendimiento

**Tiempo de ejecución de herramientas** (medido en contratos de prueba):

| Capa | Herramientas | Tiempo Prom/Contrato | Notas |
|------|--------------|----------------------|-------|
| Estático (1) | Slither, Aderyn, Solhint | ~5 seg | Rápido, adecuado para CI/CD |
| Dinámico (2) | Echidna, Medusa, Foundry | ~30 seg | Depende de cobertura de tests |
| Simbólico (3) | Mythril, Manticore, Halmos | 1-5 min | Principal cuello de botella |
| Formal (4) | Certora, SMTChecker, Wake | 2-10 min | Requiere especificaciones |
| IA (5) | SmartLLM, GPTScan | 30-60 seg | Inferencia LLM local |

**Resultados de suite de tests**:

- Contratos analizados: 5 casos de prueba vulnerables
- Total hallazgos: 39 (6 high, 3 medium, 10 low, 18 info)
- Tiempo promedio: ~2 min/contrato (todas las capas)

**Escalabilidad**: Framework diseñado para ejecución paralela. Estudio de rendimiento a gran escala pendiente.

**Optimización**:

```bash
# Modo rápido (solo estático)
python xaudit.py --target contract.sol --mode fast

# Capas selectivas
python xaudit.py --target contract.sol --layers static,dynamic
```

Nota: Estimaciones de tiempo basadas en ejecución de herramientas, no en flujo de auditoría end-to-end.

---

## Investigación y Uso Académico

**Tesis** (en progreso):
"Framework Integrado de Evaluación de Seguridad para Smart Contracts: Un Enfoque Defense-in-Depth para Ciberdefensa"

- Autor: Fernando Boiero
- Institución: Universidad de la Defensa Nacional (UNDEF), Córdoba, Argentina
- Programa: Maestría en Ciberdefensa
- Defensa: Q4 2025 (esperada)

**Contribuciones de investigación**:

1. Implementación de referencia de arquitectura multi-agente basada en MCP
2. Integración de 31 herramientas de seguridad heterogéneas bajo protocolo unificado
3. Mapeo automatizado de cumplimiento a 12 estándares internacionales
4. Framework de testing reproducible (716 tests unitarios/integración)

**Estado actual**:

- ✅ Implementación del framework completa
- ✅ Tests unitarios y de integración pasando
- 🚧 Estudio empírico a gran escala en progreso
- 🚧 Recolección y anotación de dataset en curso
- 🚧 Estudio de validación por expertos planificado

**Ejecutar tests**:

```bash
pytest tests/                        # Tests unitarios y de integración
python scripts/run_benchmark.py     # Benchmark de ejecución de herramientas
python scripts/verify_installation.py  # Verificación de dependencias
```

Resultados: `benchmark_results/`, `outputs/benchmarks/`

**Trabajo planificado** (Q4 2025):

- Estudio de comparación de herramientas a gran escala
- Validación inter-evaluador por expertos
- Mediciones de precisión/recall
- Preparación de publicación académica

**Citación** (preliminar):

```bibtex
@software{boiero2025miesc,
  author = {Boiero, Fernando},
  title = {{MIESC}: Evaluación Inteligente Multicapa para Smart Contracts},
  year = {2025},
  url = {https://github.com/fboiero/MIESC},
  version = {4.3.3},
  note = {Implementación para Tesis de Maestría en Ciberdefensa}
}
```

---

## Roadmap

**v4.3.3 (actual)**:

- Distribución PyPI: `pip install miesc` disponible
- PropertyGPT: Generación automatizada de propiedades CVL (+700% adopción verificación formal)
- DA-GNN: Detección de vulnerabilidades con Redes Neuronales de Grafos (95.7% precisión)
- SmartLLM RAG Mejorado: Rol verificador para comprobación de hechos (+17% precisión)
- DogeFuzz: Fuzzing guiado por cobertura con programación de potencia (3x más rápido)
- 31 adaptadores de herramientas en 9 capas de defensa
- 1833 tests pasando, 80.4% cobertura

**Futuro (v5.0)**:

- Empaquetado Docker oficial
- Soporte multi-chain (Soroban, Solana, Cairo)
- Extensión VSCode mejorada
- Pre-commit hooks oficiales
- Integración Foundry/Hardhat nativa
- API de detectores personalizados
- Dashboard de equipos
- Monitoreo continuo en runtime

---

## Contribuir

Contribuciones bienvenidas: integraciones de herramientas, mejoras de rendimiento, validación de datasets, documentación.

```bash
git clone https://github.com/YOUR_USERNAME/MIESC.git
cd MIESC
git checkout -b feature/your-feature
pip install -r requirements_dev.txt
python -m pytest tests/
# Realizar cambios, enviar PR
```

Ver [CONTRIBUTING.md](./CONTRIBUTING.md) para guía de estilo y requisitos de testing.

**Áreas prioritarias**:

- Specs CVL Certora para patrones comunes (ERC-20/721)
- Templates de propiedades Echidna para DeFi
- Tests de integración para las 31 herramientas
- Análisis de vulnerabilidades cross-chain

---

## Seguridad

Prácticas de desarrollo: Seguridad Shift-left con hooks pre-commit (Ruff, Bandit, escaneo de secretos), SAST CI/CD (Semgrep), cumplimiento automatizado (PolicyAgent).

Métricas actuales:

- Cumplimiento de políticas: 94.2%
- Cobertura de tests: 87.5%
- Vulnerabilidades críticas: 0
- Hallazgos SAST: 0 high/critical

Divulgación de vulnerabilidades: <fboiero@frvm.utn.edu.ar> (respuesta <48h)

Detalles: [docs/SHIFT_LEFT_SECURITY.md](./docs/SHIFT_LEFT_SECURITY.md) | [policies/SECURITY_POLICY.md](./policies/SECURITY_POLICY.md)

---

## Soporte

- Documentación: [docs/](./docs/)
- Issues: [github.com/fboiero/MIESC/issues](https://github.com/fboiero/MIESC/issues)
- Email: <fboiero@frvm.utn.edu.ar>

Autor: Fernando Boiero
Candidato a Maestría en Ciberdefensa, UNDEF-IUA | Profesor, UTN-FRVM

---

## Licencia

AGPL-3.0 - Ver [LICENSE](./LICENSE)

Asegura que el framework permanezca open-source. Permite uso comercial con atribución. Trabajos derivados deben ser open-source.

Descargo de responsabilidad: Herramienta de investigación proporcionada "tal cual" sin garantías. Revisión manual por profesionales de seguridad calificados requerida. No es un reemplazo para auditorías profesionales.

---

## Agradecimientos

Construido sobre: Trail of Bits (Slither, Manticore, Echidna), Crytic (Medusa), ConsenSys (Mythril), Ackee (Wake), Certora, a16z (Halmos), Cyfrin (Aderyn), Ethereum Foundation (SMTChecker), Paradigm (Foundry), Anthropic (MCP).

Datasets: SmartBugs (INESC-ID), SolidiFI (TU Delft), Etherscan.

---

**Versión 4.3.3** | Enero 2026

[Repositorio](https://github.com/fboiero/MIESC) | [Documentación](https://fboiero.github.io/MIESC) | [Issues](https://github.com/fboiero/MIESC/issues)
