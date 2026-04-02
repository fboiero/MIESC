<p align="center">
  <h1 align="center">MIESC</h1>
  <p align="center">
    <strong>50 herramientas de seguridad. 9 capas de defensa. Un comando.</strong>
  </p>
  <p align="center">
    Seguridad de nivel empresarial para contratos inteligentes, libre y abierta para todos.
  </p>
</p>

<p align="center">
  <a href="https://pypi.org/project/miesc/"><img src="https://img.shields.io/pypi/v/miesc?color=blue&label=PyPI" alt="PyPI"></a>
  <a href="https://github.com/fboiero/MIESC/actions/workflows/ci.yml"><img src="https://github.com/fboiero/MIESC/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/fboiero/MIESC"><img src="https://codecov.io/gh/fboiero/MIESC/graph/badge.svg" alt="Coverage"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/fboiero/MIESC"><img src="https://api.securityscorecards.dev/projects/github.com/fboiero/MIESC/badge" alt="OpenSSF"></a>
  <a href="https://www.gnu.org/licenses/agpl-3.0"><img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg" alt="License"></a>
  <a href="https://github.com/fboiero/MIESC/discussions"><img src="https://img.shields.io/github/discussions/fboiero/MIESC" alt="Discussions"></a>
  <a href="./docs/policies/DPG-COMPLIANCE.md"><img src="https://img.shields.io/badge/DPG-Candidate-4c9f38?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PGNpcmNsZSBjeD0iMTIiIGN5PSIxMiIgcj0iMTAiIGZpbGw9Im5vbmUiIHN0cm9rZT0id2hpdGUiIHN0cm9rZS13aWR0aD0iMiIvPjxwYXRoIGQ9Ik04IDEybDMgMyA1LTYiIGZpbGw9Im5vbmUiIHN0cm9rZT0id2hpdGUiIHN0cm9rZS13aWR0aD0iMiIvPjwvc3ZnPg==" alt="DPG Candidate"></a>
</p>

<p align="center">
  <a href="#inicio-rápido">Inicio Rápido</a> &bull;
  <a href="#por-qué-miesc">Por Qué MIESC</a> &bull;
  <a href="#github-action">GitHub Action</a> &bull;
  <a href="#docker">Docker</a> &bull;
  <a href="./README.md">English</a> &bull;
  <a href="https://fboiero.github.io/MIESC">Docs</a>
</p>

---

## Inicio Rápido

```bash
pip install miesc
miesc scan MyContract.sol
```

Eso es todo. MIESC ejecuta Slither + Aderyn + Solhint y te entrega un reporte unificado en segundos.

¿Querés el análisis completo de 9 capas con correlación por IA?

```bash
miesc audit full MyContract.sol -o results.json
miesc report results.json -t premium -f pdf --llm-interpret
```

<details>
<summary><strong>Ver ejemplo de salida</strong></summary>

```
=== Layer 1: Static Analysis ===
OK slither: 5 findings in 1.7s
OK aderyn: 5 findings in 3.0s
OK solhint: 0 findings in 0.7s

=== Layer 2: Dynamic Testing ===
OK echidna: 0 findings in 2.0s
OK foundry: 0 findings in 9.0s

=== Layer 3: Symbolic Execution ===
OK mythril: 2 findings in 298.0s

=== Layer 5: AI Analysis ===
OK smartllm: 4 findings in 198.9s
OK gptscan: 4 findings in 49.7s

 Full Audit Summary
+----------+-------+
| Severity | Count |
+----------+-------+
| CRITICAL |     1 |
| HIGH     |    11 |
| MEDIUM   |     1 |
| LOW      |     9 |
| TOTAL    |    22 |
+----------+-------+

Tools executed: 12/29
Report saved to results.json
```

</details>

---

## Por Qué MIESC

**El problema**: Las auditorías profesionales de smart contracts cuestan entre $50K y $200K y llevan semanas. Mientras tanto, se pierden más de $1,500M al año por exploits. La mayoría de los proyectos salen a producción sin ninguna auditoría. Ejecutar Slither solo detecta ~70% de las vulnerabilidades con un 15-20% de falsos positivos. Cada herramienta tiene puntos ciegos. Los auditores ejecutan manualmente 5-10 herramientas, normalizan las salidas y correlacionan los hallazgos. Esto lleva horas.

**MIESC hace accesible ese flujo de trabajo para todos.** Un comando orquesta 50 herramientas a través de 9 técnicas de análisis complementarias, deduplica hallazgos, filtra falsos positivos con ML y genera reportes profesionales. Gratuito, open-source, se ejecuta localmente — tu código nunca sale de tu máquina.

### Resultados Validados

Evaluado con el dataset SmartBugs-curated (143 contratos) y 5,127 contratos del mundo real:

| Métrica | Slither solo | Mythril solo | MIESC (9 capas) |
|---------|:------------:|:------------:|:---------------:|
| Precisión | ~70% | ~65% | **89.5%** |
| Recall | ~70% | ~60% | **86.2%** |
| F1-Score | ~70% | ~62% | **87.8%** |
| Tasa de Falsos Positivos | 15-20% | 10-15% | **<5%** |

> Cohen's Kappa = 0.847 (alta concordancia con auditores expertos). Validado en 5,127 contratos. [Metodología completa](./docs/ARCHITECTURE.md)

### Las 9 Capas de Defensa

```
Capa 1  Análisis Estático        Slither, Aderyn, Solhint, Wake, Semgrep
Capa 2  Testing Dinámico         Echidna, Foundry, Medusa, DogeFuzz
Capa 3  Ejecución Simbólica      Mythril, Manticore, Halmos
Capa 4  Verificación Formal      Certora, SMTChecker, PropertyGPT
Capa 5  Testing de Propiedades   Wake, Vertigo, Scribble
Capa 6  Análisis IA/LLM          SmartLLM, GPTScan, LLMSmartAudit
Capa 7  Detección de Patrones ML DA-GNN, SmartGuard, Clone Detector
Capa 8  Seguridad DeFi           MEV Detector, Flash Loan Analyzer
Capa 9  Ensemble IA Avanzado     Consenso Multi-LLM, Síntesis de Exploits
```

### vs. SmartBugs 2.0 (competidor más cercano)

| | MIESC | SmartBugs 2.0 |
|---|---|---|
| Herramientas | **50** | 19 |
| Correlación IA/LLM | Sí (RAG + Ollama) | No |
| Filtro ML de falsos positivos | Sí | No |
| Multi-chain | 7 chains | Solo EVM |
| Reportes PDF profesionales | Sí | No |
| Sistema de plugins | Sí (PyPI) | No |
| GitHub Action | Sí | No |
| Salida SARIF | Sí | No |

---

## GitHub Action

Agregá seguridad de contratos inteligentes a cualquier pipeline CI/CD en 30 segundos:

```yaml
# .github/workflows/security.yml
name: Security
on: [push, pull_request]

permissions:
  security-events: write
  pull-requests: write

jobs:
  miesc:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: fboiero/MIESC@v5
        with:
          path: contracts/
          mode: scan
          fail-on: high
          upload-sarif: true
          comment-on-pr: true
```

Los resultados aparecen en la pestaña **Security** de GitHub y como comentario en el PR. Consultá el [workflow de ejemplo](./.github/workflows/example-miesc-action.yml) para configuraciones avanzadas.

### Modos Disponibles

| Modo | Herramientas | Tiempo | Caso de Uso |
|------|--------------|--------|-------------|
| `scan` | Slither, Aderyn, Solhint | ~30s | Cada push |
| `audit-quick` | 4 herramientas core | ~2min | Checks de PR |
| `audit-full` | Las 9 capas | ~10min | Pre-release |
| `audit-profile` | Configurable | Variable | DeFi, tokens, etc. |

---

## Instalación

```bash
# CLI mínima
pip install miesc

# Con reportes PDF
pip install miesc[pdf]

# Todo incluido (PDF, LLM, RAG, web UI)
pip install miesc[full]

# Desarrollo
git clone https://github.com/fboiero/MIESC.git
cd MIESC && pip install -e .[dev]
```

Requisitos: Python 3.12+. Slither se instala automáticamente. Las demás herramientas son opcionales — MIESC usa las que estén disponibles.

---

## Docker

```bash
# Imagen estándar (~3GB, multi-arch incluyendo Apple Silicon)
docker pull ghcr.io/fboiero/miesc:latest
docker run --rm -v $(pwd):/contracts ghcr.io/fboiero/miesc:latest scan /contracts/MyContract.sol

# Imagen completa (~8GB, las 50 herramientas, amd64)
docker pull ghcr.io/fboiero/miesc:full
docker run --rm -v $(pwd):/contracts ghcr.io/fboiero/miesc:full audit full /contracts/MyContract.sol

# Verificar qué herramientas están disponibles
docker run --rm ghcr.io/fboiero/miesc:latest doctor
```

<details>
<summary><strong>Docker + Ollama para reportes PDF con IA</strong></summary>

```bash
# 1. Iniciar Ollama y descargar el modelo
ollama serve &
ollama pull mistral:latest

# 2. Auditoría completa
docker run --rm -v $(pwd):/contracts \
  ghcr.io/fboiero/miesc:full \
  audit full /contracts/MyContract.sol -o /contracts/results.json

# 3. Generar reporte premium en PDF con interpretación IA
docker run --rm \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  -v $(pwd):/contracts \
  ghcr.io/fboiero/miesc:full \
  report /contracts/results.json -t premium -f pdf \
    --llm-interpret \
    --client "Your Client" \
    --auditor "Your Name" \
    -o /contracts/audit_report.pdf
```

El reporte premium incluye puntuación CVSS, matriz de riesgo, escenarios de ataque, recomendación de despliegue (GO/NO-GO) y hoja de ruta de remediación generada por IA. Comparable al estilo de reportes de Trail of Bits / OpenZeppelin.

</details>

<details>
<summary><strong>Notas para ARM / Apple Silicon</strong></summary>

La imagen **estándar** corre nativamente en ARM. La imagen **completa** es solo amd64 en el registro (corre bajo emulación QEMU). Para compilar nativamente:

```bash
./scripts/build-images.sh full  # ~30-60 min, pero velocidad nativa
```

</details>

---

## Referencia CLI

```bash
miesc scan contract.sol              # Escaneo rápido (Slither + Aderyn + Solhint)
miesc scan contract.sol --ci         # Modo CI: exit 1 en critical/high
miesc audit quick contract.sol       # Auditoría de 4 herramientas
miesc audit full contract.sol        # Auditoría completa de 9 capas
miesc audit layer 3 contract.sol     # Capa específica (ej., ejecución simbólica)
miesc audit profile defi contract.sol  # Perfil nombrado (defi, token, security, etc.)
miesc report results.json -t premium -f pdf --llm-interpret  # Reporte PDF con IA
miesc export results.json -f sarif   # Exportar como SARIF
miesc doctor                         # Verificar disponibilidad de herramientas
miesc watch ./contracts              # Auto-escaneo ante cambios en archivos
miesc benchmark ./contracts --save   # Seguimiento de la postura de seguridad en el tiempo
```

### Perfiles de Análisis

| Perfil | Capas | Ideal Para |
|--------|-------|------------|
| `fast` | 1 | Feedback rápido durante el desarrollo |
| `balanced` | 1, 3 | Checks pre-commit |
| `ci` | 1 | Pipelines CI/CD |
| `security` | 1, 3, 4, 5 | Contratos de alto valor |
| `defi` | 1, 2, 3, 5, 8 | Protocolos DeFi |
| `token` | 1, 3, 5 | Tokens ERC20/721/1155 |
| `thorough` | 1-9 | Pre-release / auditoría exhaustiva |

---

## Extender MIESC

### Detectores Personalizados

```python
from miesc.detectors import BaseDetector, Finding, Severity

class DangerousDelegatecall(BaseDetector):
    name = "dangerous-delegatecall"
    description = "Detects unprotected delegatecall patterns"

    def analyze(self, source_code, file_path=None):
        findings = []
        # Your detection logic here
        return findings
```

Registrar vía `pyproject.toml`:

```toml
[project.entry-points."miesc.detectors"]
dangerous-delegatecall = "my_package:DangerousDelegatecall"
```

### Sistema de Plugins

```bash
miesc plugins install miesc-defi-detectors   # Instalar desde PyPI
miesc plugins create my-detector             # Crear un nuevo plugin
miesc plugins list                           # Listar plugins instalados
miesc detectors list                         # Listar todos los detectores disponibles
```

### Integraciones

```yaml
# Pre-commit hook (.pre-commit-config.yaml)
repos:
  - repo: https://github.com/fboiero/MIESC
    rev: v5.1.1
    hooks:
      - id: miesc-quick
        args: ['--ci']
```

```toml
# Foundry (foundry.toml)
[profile.default]
post_build_hook = "miesc audit quick ./src --ci"
```

```javascript
// Hardhat (hardhat.config.js)
require("hardhat-miesc");
module.exports = {
  miesc: { enabled: true, runOnCompile: true, failOn: "high" }
};
```

### Servidor MCP

MIESC se integra con agentes de IA a través del [Model Context Protocol](https://modelcontextprotocol.io):

```bash
miesc server mcp  # Iniciar servidor MCP WebSocket
```

```json
// Claude Desktop / Configuración de cliente MCP
{
  "mcpServers": {
    "miesc": {
      "command": "miesc",
      "args": ["server", "mcp"]
    }
  }
}
```

### API Python

```python
from miesc.api import run_tool, run_full_audit

results = run_tool("slither", "contract.sol")
report = run_full_audit("contract.sol")
```

### Interfaz Web

```bash
pip install miesc[web]
make webapp  # Abre en http://localhost:8501
```

Dashboard interactivo en Streamlit con carga de archivos, análisis, visualización de resultados y exportación de reportes.

---

## Soporte Multi-Chain

| Chain | Estado | Lenguajes |
|-------|--------|-----------|
| **EVM** (Ethereum, Polygon, BSC, Arbitrum, etc.) | Producción | Solidity, Vyper |
| Solana | Alpha | Rust/Anchor |
| NEAR | Alpha | Rust |
| Move (Sui, Aptos) | Alpha | Move |
| Stellar/Soroban | Alpha | Rust |
| Algorand | Alpha | TEAL, PyTeal |
| Cardano | Alpha | Plutus, Aiken |

```bash
miesc scan program.rs --chain solana
miesc scan module.move --chain sui
```

> El soporte para cadenas no-EVM es experimental. El análisis EVM (50 herramientas, 9 capas) está listo para producción.

---

## Mapeo de Cumplimiento

MIESC mapea cada hallazgo a estándares de seguridad internacionales:

**ISO/IEC 27001:2022** | **NIST CSF** | **OWASP Smart Contract Top 10** | **CWE** | **SWC Registry** | **MITRE ATT&CK** | **PCI-DSS** | **SOC 2**

---

## Arquitectura

```
Contract.sol
    |
    v
 CLI / API / MCP / GitHub Action
    |
    v
 Orquestador --> 9 Capas --> 50 Adaptadores de Herramientas
    |
    v
 Agregador de Hallazgos --> Pipeline ML --> Contexto RAG --> Filtro FP
    |
    v
 Generador de Reportes --> JSON / SARIF / PDF / HTML / Markdown
```

MIESC utiliza una arquitectura de doble paquete:
- `miesc/` - API Pública (estable, instalable vía pip)
- `src/` - Implementación interna (50 adaptadores, pipeline ML, RAG, generación de reportes)

Consultá [ARCHITECTURE.md](./docs/ARCHITECTURE.md) para el diseño técnico completo con diagramas Mermaid.

---

## Validación Académica

MIESC fue desarrollado como tesis de Maestría en Ciberdefensa en [UNDEF-IUA](https://www.iua.edu.ar/) (Argentina). El framework fue rigurosamente validado:

- **5,127 contratos del mundo real** analizados
- **Cohen's Kappa 0.847** (alta concordancia con auditores expertos)
- **34% de mejora** respecto al análisis con una sola herramienta
- **Benchmark SmartBugs-curated**: 100% precisión, 70% recall, F1 82.35%

Si usás MIESC en investigación, por favor citá:

```bibtex
@mastersthesis{boiero2025miesc,
  title={Integrated Security Assessment Framework for Smart Contracts:
         A Defense-in-Depth Approach to Cyberdefense},
  author={Boiero, Fernando},
  year={2025},
  school={Universidad de la Defensa Nacional (UNDEF) - IUA C{\'o}rdoba},
  type={Master's Thesis in Cyberdefense}
}
```

---

## Bien Público Digital

MIESC es candidato a la certificación de la [Digital Public Goods Alliance](https://digitalpublicgoods.net/) (Application ID: GID0092948), alineado con los Objetivos de Desarrollo Sostenible de la ONU:

- **ODS 9** (Industria e Infraestructura): Fortalecimiento de la seguridad en infraestructura blockchain
- **ODS 16** (Paz e Instituciones Sólidas): Protección de activos digitales, reducción del fraude
- **ODS 17** (Alianzas): Colaboración de código abierto para estándares globales de seguridad

El proyecto cumple plenamente con los 9 indicadores de la DPGA: licencia abierta (AGPL-3.0), propiedad clara, independencia de plataforma, documentación exhaustiva, portabilidad de datos (SARIF/CSV/JSON), respeto a la privacidad (local-first), basado en estándares (12 estándares internacionales) y políticas de uso responsable.

| Política | Descripción |
|----------|-------------|
| [Cumplimiento DPG](./docs/policies/DPG-COMPLIANCE.md) | Declaración de cumplimiento de los 9 indicadores |
| [Relevancia ODS](./docs/policies/SDG_RELEVANCE.md) | Mapeo de Objetivos de Desarrollo Sostenible |
| [Política de Privacidad](./PRIVACY.md) | Declaración de manejo de datos y privacidad |
| [Uso Responsable](./RESPONSIBLE_USE.md) | Directrices de uso ético |
| [No Hacer Daño](./docs/policies/DO_NO_HARM.md) | Evaluación de riesgos y mitigaciones |

---

## Documentación

| Recurso | Descripción |
|---------|-------------|
| [Guía de Instalación](./docs/INSTALLATION.md) | Instrucciones completas de configuración |
| [Inicio Rápido](./docs/guides/QUICKSTART.md) | Funcionando en 5 minutos |
| [Arquitectura](./docs/ARCHITECTURE.md) | Diseño técnico y detalle de capas |
| [Referencia de Herramientas](./docs/TOOLS.md) | Las 50 herramientas y sus capacidades |
| [Guía de Reportes](./docs/guides/REPORTS.md) | Plantillas y personalización de reportes |
| [Detectores Personalizados](./docs/CUSTOM_DETECTORS.md) | Construí tus propios detectores |
| [Multi-Chain](./docs/MULTICHAIN.md) | Análisis de cadenas no-EVM |
| [Referencia de API](https://fboiero.github.io/MIESC/api/) | Auto-generada desde docstrings |
| [Contribuir](./CONTRIBUTING.md) | Guías de desarrollo |
| [Hoja de Ruta](./ROADMAP.md) | Próximos pasos |

---

## Contribuir

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC && pip install -e .[dev]
pytest tests/  # 4,700+ tests
```

Consultá [CONTRIBUTING.md](./CONTRIBUTING.md) para las guías. [CONTRIBUTING_ES.md](./CONTRIBUTING_ES.md) disponible en español.

---

## Licencia

[AGPL-3.0](./LICENSE) - Libre para cualquier uso. La seguridad no debería ser un privilegio reservado para proyectos con grandes presupuestos. Si construís un servicio sobre MIESC, contribuí tus cambios de vuelta.

## Autor

**Fernando Boiero** - Tesis de Maestría en Ciberdefensa, UNDEF-IUA Argentina

Construido sobre los hombros de: [Slither](https://github.com/crytic/slither), [Mythril](https://github.com/ConsenSys/mythril), [Echidna](https://github.com/crytic/echidna), [Foundry](https://github.com/foundry-rs/foundry), [Aderyn](https://github.com/Cyfrin/aderyn), [Halmos](https://github.com/a16z/halmos), y la comunidad de seguridad de Ethereum.
