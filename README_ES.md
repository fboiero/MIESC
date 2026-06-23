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
  <a href="https://pepy.tech/project/miesc"><img src="https://static.pepy.tech/badge/miesc/month" alt="Downloads"></a>
  <a href="https://pypi.org/project/miesc/"><img src="https://img.shields.io/pypi/pyversions/miesc" alt="Python"></a>
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

Eso es todo. MIESC ejecuta Slither + Aderyn + Solhint, deduplica los hallazgos y te entrega un reporte unificado con puntuaciones de confianza en segundos.

### Pipeline completo: detectar → corregir → verificar → cumplir

```bash
miesc scan contract.sol -o results.json           # Detección + inteligencia
miesc fix results.json -c contract.sol -o fixed.sol  # Parcheo automático de vulnerabilidades
miesc remediate results.json -c contract.sol --compile --rescan  # Parche + paquete de evidencia
miesc verify fixed.sol --tool smtchecker           # Probar que la corrección funciona
miesc compliance results.json --standard mica      # Mapear a MiCA/DORA/ISO 27001
miesc report results.json -t premium -f pdf        # Reporte de auditoría profesional
```

### Pipeline de investigación actual: Motor de Inteligencia

```bash
miesc scan contract.sol --verbose                  # Confianza + corrección por hallazgo
miesc scan contracts/ --recursive                  # Escaneo de directorios
miesc scan . --diff origin/main                    # Nivel PR: solo archivos modificados
miesc scan contract.sol --verify-fp                # Filtro de FP recall-safe: descarta solo benignos type-deterministic, flaggea el resto
```

El motor de inteligencia automáticamente:
- **Deduplica** hallazgos entre herramientas (Slither + Aderyn reportan el mismo bug → 1 hallazgo)
- **Puntúa la confianza** mediante acuerdo bayesiano multi-herramienta (2 herramientas = 85%, 3 = 95%)
- **Genera código de corrección** — parches de Solidity listos para copiar y pegar para 10 categorías de vulnerabilidades
- **Reduce falsos positivos** — descarta solo benignos type-deterministic (Solidity 0.8+, llamada chequeada/SafeERC20, lint informativo); guardas contextuales (onlyOwner, nonReentrant) se flaggean para revisión, nunca se descartan (recall 1.0)
- **Calibra la severidad** entre herramientas (Aderyn LOW → Medium cuando corresponde)

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

**El problema**: Las auditorías profesionales de smart contracts cuestan entre $50K y $200K y llevan semanas. Mientras tanto, se pierden más de $1.5B al año por exploits. La mayoría de los proyectos salen a producción sin ninguna auditoría. Ejecutar Slither solo detecta ~70% de las vulnerabilidades con un 15-20% de falsos positivos. Cada herramienta tiene puntos ciegos. Los auditores ejecutan manualmente 5-10 herramientas, normalizan las salidas y correlacionan los hallazgos. Esto lleva horas.

**MIESC hace accesible ese flujo de trabajo para todos.** Un comando orquesta múltiples herramientas de seguridad a través de 9 técnicas de análisis complementarias, deduplica hallazgos y genera reportes profesionales. Gratuito, open-source, se ejecuta localmente — tu código nunca sale de tu máquina.

### Resultados del Benchmark

**SmartBugs-curated** (143 contratos, 207 vulnerabilidades ground-truth):

| Métrica | Slither solo | Mythril solo | Perfil reproducible MIESC Paper 1 | Alcance de la evidencia |
|---------|:------------:|:------------:|:---------------------------------:|:------------------------|
| Recall | 43.2% | 27.4% | **95.8%** | Corpus completo SmartBugs-curated |
| Precisión | 8.3% | 6.1% | **22.2%** | Corpus completo SmartBugs-curated |
| F1-Score | 13.9% | 10.0% | **36.0%** | Corpus completo SmartBugs-curated |

El resultado sobre el corpus completo de SmartBugs es el perfil reproducible del
Paper 1. Un seguimiento local con Ollama sobre los casos no detectados restantes
se reporta en el Paper 1 como 140/143 (97.9%) y debe tratarse como una afirmación
de seguimiento secundaria hasta que se publique su propio artefacto de mejora
legible por máquina. La corrida de 9 capas se reporta por separado como una prueba
de integración end-to-end (smoke run), no como una afirmación a nivel de corpus.

**Exploits reales** (11 exploits DeFi confirmados, $1.59B en pérdidas combinadas):

| Vulnerabilidad | Exploits | Detectados | Recall | Ejemplos |
|----------------|:--------:|:----------:|:------:|----------|
| Reentrancy | 3 | 3 | **100%** | Euler $197M, Rari $80M, Platypus $8.5M |
| Access Control | 3 | 3 | **100%** | Parity $280M, Ronin $624M |
| Flash Loan | 2 | 2 | **100%** | bZx $8.1M, Compound $80M |
| General | 11 | 9 | **81.8%** | Cohen's Kappa: 0.77 |

> **81.8% recall en exploits reales** — MIESC habría marcado 9 de 11 exploits multimillonarios antes del deploy. [Reproducibilidad del Paper 1](./paper/PAPER1_REPRODUCIBILITY.md) | [Evaluación de exploits](./benchmarks/evaluate_exploits.py)

**Por qué importa más el recall que la precisión en triaje pre-auditoría**: Alto recall significa menos vulnerabilidades perdidas. Los falsos positivos se filtran en la etapa de triaje — las vulnerabilidades perdidas se convierten en exploits en producción.

### Papers de Investigación y Afirmaciones Reproducibles

MIESC tiene dos líneas de investigación vinculadas. El Paper 1 evalúa la detección y la evaluación de seguridad multi-capa. El Paper 2 extiende esa evidencia hacia artefactos de remediación automática y pasos de verificación independiente. El Paper 2 no reemplaza ni invalida al Paper 1; parte del mismo pipeline de detección y mide qué sucede después de que un hallazgo se convierte en un candidato a parche.

| Paper | Foco | Evidencia reproducible principal | Artefactos |
|-------|------|----------------------------------|------------|
| [Paper 1](./paper/miesc-paper.pdf) | Evaluación de seguridad multi-capa de contratos inteligentes | SmartBugs: 95.8% recall en 143 contratos, con un seguimiento local con Ollama reportado en 97.9%; exploits DeFi: 81.8% recall en 11 incidentes; ensemble EVMBench: 111/120 hallazgos de severidad alta, 92.5% recall | [Reproducibilidad](./paper/PAPER1_REPRODUCIBILITY.md), [matriz de afirmaciones](./benchmarks/results/paper1_claims_matrix.json) |
| [Paper 2](./paper/paper2-remediation.pdf) | Artefactos de remediación verificables | 141/143 correcciones aplicadas; 90/141 contratos parcheados standalone compilan; 93/141 eliminan el hallazgo original por re-escaneo; 91/141 pasan no-regresión acotada | [Reproducibilidad](./paper/PAPER2_REPRODUCIBILITY.md), [matriz de afirmaciones](./benchmarks/results/paper2_claims_matrix.json), [auditoría del experimento](./benchmarks/results/paper2_experiment_audit.json) |

Para citación y revisión de investigación, las afirmaciones canónicas actuales son los dos PDFs de los papers, sus notas de reproducibilidad y los archivos `benchmarks/results/paper*_claims_matrix.json`. El plan de alineación de plataforma mapea estos resultados de los papers a los requisitos de los flujos de trabajo de CLI, API, MCP, RAG y remediación: [Aprendizajes de los papers y alineación de plataforma](./docs/roadmap/PAPER_LEARNINGS_PLATFORM_ALIGNMENT.md). La selección y ponderación de fuentes RAG se rige por la [política de fuentes RAG](./docs/guides/RAG_SOURCE_POLICY.md). Las notas de versiones anteriores, borradores de tesis y documentos de hoja de ruta se conservan para la historia del proyecto y pueden contener corridas de benchmark previas o métricas específicas de versión.

La limpieza de deuda técnica actual y el trabajo de plataforma pendiente se siguen en el [plan de remediación de deuda técnica](./docs/roadmap/TECHNICAL_DEBT_REMEDIATION_PLAN.md).

### Las 9 Capas de Defensa

```
Capa 1  Análisis Estático        Slither, Aderyn, Solhint, Semgrep
Capa 2  Testing Dinámico         Echidna, Foundry, Medusa
Capa 3  Ejecución Simbólica      Mythril, Halmos, Manticore
Capa 4  Verificación Formal      SMTChecker, Scribble, Certora*
Capa 5  Análisis IA/LLM          SmartLLM, GPTScan, LLMSmartAudit (Ollama)
Capa 6  Detección de Patrones    Gas Analyzer, Clone Detector, Threat Model
Capa 7  Seguridad DeFi           MEV Detector, Flash Loan Analyzer, Oracle Checker
Capa 8  Validación de Exploits   PoC Synthesizer (Foundry), Vulnerability Verifier
Capa 9  Consenso y Reportes      Consenso Bayesiano, Enriquecimiento RAG, Reportes PDF
```

*Certora requiere API key. Todas las demás herramientas son completamente open-source.

### Qué integra MIESC

| Categoría | Cantidad | Ejemplos |
|-----------|:--------:|---------|
| **Herramientas de seguridad externas** | 13 | Slither, Mythril, Echidna, Foundry, Halmos, Aderyn, Semgrep |
| **Módulos de análisis LLM** | 6 | SmartLLM, GPTScan, PropertyGPT (vía Ollama local) |
| **Analizadores internos** | 16 | MEV detector, gas analyzer, threat model, clone detector |
| **Total de módulos de análisis** | **35** | A través de 9 técnicas complementarias |

### vs. SmartBugs 2.0 (competidor más cercano)

| | MIESC | SmartBugs 2.0 |
|---|---|---|
| Herramientas externas | 13 | 19 |
| Análisis IA/LLM | Sí (Ollama local) | No |
| Analizadores internos | 16 | No |
| Filtro de falsos positivos | Sí (RAG + ML) | No |
| Reportes PDF profesionales | Sí | No |
| Sistema de plugins | Sí (PyPI) | No |
| GitHub Action | Sí | No |
| Salida SARIF | Sí | Sí |

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

# Todo incluido para análisis local (PDF, LLM, RAG, APIs)
pip install miesc[full]

# Desarrollo
git clone https://github.com/fboiero/MIESC.git
cd MIESC && pip install -e .[dev]
```

Requisitos: Python 3.12+. Slither se instala automáticamente. Las demás herramientas son opcionales — MIESC usa las que estén disponibles.

Para una estación de trabajo completa de investigador con Mythril, Manticore, Certora CLI, Wake, Semgrep y herramientas de verificación formal aisladas:

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC
./scripts/bootstrap_researcher_tools.sh
make researcher-smoke
```

Consultá la [Guía de Empaquetado para Investigadores](./docs/guides/RESEARCHER_PACKAGING.md) para el modelo de distribución recomendado de PyPI + Docker + bootstrap local.

---

## Soporte Multi-Chain

```bash
miesc analyze Token.sol           # EVM (Solidity/Vyper) — producción
# Las no-EVM (Cairo/Solana/Move/NEAR/Stellar/Algorand/Cardano) están en el ROADMAP:
# existe código de adapter experimental pero todavía no está validado para producción.
```

**77 tipos de vulnerabilidades** en 4 ecosistemas, basados en exploits reales de 2024-2026 (zkLend $9.6M, Braavos, Wormhole $326M, Ronin $624M).

Detección de vulnerabilidades en bridges:
```bash
miesc scan Bridge.sol             # Detecta 7 patrones de exploits en bridges
```

---

## Todos los Comandos

| Comando | Descripción |
|---------|-------------|
| `miesc scan` | Escaneo rápido (3 herramientas + motor de inteligencia) |
| `miesc scan --diff HEAD~1` | **NUEVO** Nivel PR: solo archivos .sol modificados |
| `miesc scan contracts/` | **NUEVO** Escaneo de directorios (+ `--recursive`) |
| `miesc scan --verify-fp` | **NUEVO** Filtro de FP recall-safe: descarta solo benignos type-deterministic, flaggea guards/LLM como needs_review (`--verify-model` = pase LLM advisory) |
| `miesc audit quick\|full` | Auditoría multi-capa (3 herramientas rápidas o stack configurado de 9 capas) |
| `miesc fix results.json` | Auto-genera archivos .sol parcheados |
| `miesc remediate results.json` | **NUEVO** Genera archivos parcheados más evidencia de compilación/re-escaneo |
| `miesc verify contract.sol` | Ejecuta probadores Certora/Halmos/SMTChecker |
| `miesc compliance results.json` | **NUEVO** Mapea a ISO/NIST/MiCA/DORA |
| `miesc report results.json` | Reporte profesional en PDF/HTML/Markdown |
| `miesc specs results.json` | Genera specs Certora CVL / Scribble |
| `miesc export results.json` | Exportación SARIF (GitHub), CSV, HTML |
| `miesc analyze contract.cairo` | Análisis multi-chain |
| `miesc doctor` | Verificar disponibilidad de herramientas |
| `miesc watch contracts/` | Observación de archivos en vivo + auto-escaneo |

---

## Docker

El estado de la versión, los enlaces a los artefactos publicados, el digest de GHCR
y los comandos de smoke-test del último estado de versión detallado publicado (5.4.2)
están registrados en
[Estado de la Versión MIESC 5.4.2](./docs/policies/RELEASE_STATUS_5.4.2.md). La
versión actual publicada es la 5.4.3 (PyPI y GHCR).

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
<summary><strong>Docker + Ollama en el host (recomendado para aceleración por GPU)</strong></summary>

Las capas LLM de MIESC (Capa 5) usan Ollama para el análisis local con IA. La configuración recomendada ejecuta Ollama en tu máquina host (con acceso a GPU) y conecta el contenedor Docker por red:

```bash
# 1. Instalar e iniciar Ollama en tu HOST (no dentro de Docker)
# Descargá desde https://ollama.com
ollama serve &
ollama pull qwen2.5-coder:14b   # Mejor modelo para análisis de código
ollama pull deepseek-coder:6.7b  # Alternativa más liviana

# 2. Escanear con Ollama del host (macOS)
docker run --rm \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  -v $(pwd)/contracts:/contracts \
  ghcr.io/fboiero/miesc:latest \
  scan /contracts/MyContract.sol -o /contracts/results.json

# 3. Escanear con Ollama del host (Linux)
docker run --rm --network=host \
  -e OLLAMA_HOST=http://localhost:11434 \
  -v $(pwd)/contracts:/contracts \
  ghcr.io/fboiero/miesc:latest \
  scan /contracts/MyContract.sol

# 4. Generar reporte premium en PDF con IA
docker run --rm \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  -v $(pwd):/work \
  ghcr.io/fboiero/miesc:full \
  report /work/results.json -t premium -f pdf \
    --llm-interpret -o /work/audit_report.pdf
```

**¿Por qué Ollama en el host?** Los contenedores Docker no tienen acceso a GPU por defecto. Ejecutar Ollama en el host le permite usar tu GPU (Apple Silicon, NVIDIA CUDA) para una inferencia LLM 10-50x más rápida.

</details>

<details>
<summary><strong>Docker Compose (stack completo con Ollama incluido)</strong></summary>

Para entornos sin un Ollama en el host, usá docker-compose para ejecutar todo junto:

```bash
# Iniciar MIESC + Ollama + inicialización del modelo
docker compose -f docker/docker-compose.yml --profile llm up -d

# Ejecutar análisis
docker compose -f docker/docker-compose.yml exec miesc miesc scan /app/contracts/MyContract.sol

# Detener
docker compose -f docker/docker-compose.yml down
```

El stack de compose descarga automáticamente `deepseek-coder:6.7b` y configura la red entre servicios.

</details>

<details>
<summary><strong>Notas para ARM / Apple Silicon</strong></summary>

La imagen **estándar** corre nativamente en ARM. La imagen **completa** del registro está pensada como amd64 para máxima paridad de herramientas. Las builds nativas ARM de la imagen completa omiten Echidna, Medusa, Mythril, Manticore, Halmos y Semgrep por defecto, porque sus releases upstream son solo amd64, requieren largas compilaciones de Z3 desde el código fuente, o publican wheels ARM que no son confiables en Docker. Compilá nativamente con:

```bash
./scripts/build-images.sh full
```

Para paridad completa de estación de trabajo ARM, preferí el bootstrap local:

```bash
./scripts/bootstrap_researcher_tools.sh
```

Para forzar builds nativas ARM de Mythril, Manticore, Halmos o Semgrep dentro de Docker:

```bash
MIESC_BUILD_MYTHRIL=true ./scripts/build-images.sh full
MIESC_BUILD_MANTICORE=true ./scripts/build-images.sh full
MIESC_BUILD_HALMOS=true ./scripts/build-images.sh full
MIESC_BUILD_SEMGREP=true ./scripts/build-images.sh full
```

</details>

---

## Referencia CLI

```bash
miesc scan contract.sol              # Escaneo rápido (Slither + Aderyn + Solhint)
miesc scan contract.sol --ci         # Modo CI: exit 1 en critical/high
miesc audit quick contract.sol       # Auditoría de 3 herramientas
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
    rev: v5.4.3
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

### Servidor MCP (Claude Desktop / Cursor / Claude Code)

MIESC expone su análisis de seguridad de 9 capas como herramientas MCP a través del [Model Context Protocol](https://modelcontextprotocol.io):

```bash
pip install 'miesc[mcp]'   # Instalar con soporte MCP
miesc-mcp                   # Iniciar servidor MCP stdio
```

Agregalo a tu `config.json` de Claude Desktop:

```json
{
  "mcpServers": {
    "miesc": {
      "command": "miesc-mcp",
      "env": {"OLLAMA_HOST": "http://localhost:11434"}
    }
  }
}
```

**Herramientas MCP disponibles:** `miesc_quick_scan`, `miesc_deep_scan`, `miesc_deep_audit`, `miesc_run_tool`, `miesc_run_layer`, `miesc_analyze_defi`, `miesc_apply_fix`, `miesc_validate_remediation`, `miesc_remediation_evidence_bundle`, `miesc_list_tools`, `miesc_doctor`

### Remediación vía API REST

La API expone el mismo esquema de evidencia de remediación que la CLI:

| Endpoint | Propósito |
|----------|-----------|
| `POST /api/v1/remediate/` | Aplica candidatos de corrección y devuelve un paquete de evidencia |
| `POST /api/v1/validate-remediation/` | Aplica correcciones con validación de compilación/re-escaneo habilitada por defecto |

Ejemplos: [Guía de API de remediación y MCP](./docs/guides/REMEDIATION_API_MCP.md).

### API Python

```python
from miesc.api import run_tool, run_full_audit

results = run_tool("slither", "contract.sol")
report = run_full_audit("contract.sol")
```

### APIs Locales Y Reportes

```bash
pip install "miesc[django]"
python -m miesc.api.rest --host 127.0.0.1 --port 8000
python -m src.utils.web_dashboard --results analysis/results --output analysis/dashboard
```

El core abierto expone automatización local REST/MCP y generación de reportes
estáticos. La UI hospedada de producto, dashboards de equipo, el flujo de
licenciamiento y los clientes IDE viven ahora en la capa de plataforma.

---

## Soporte Multi-Chain

| Chain | Estado | Lenguajes |
|-------|--------|-----------|
| **EVM** (Ethereum, Polygon, BSC, Arbitrum, etc.) | **Producción** | Solidity, Vyper |
| Solana | Roadmap | Rust/Anchor |
| NEAR | Roadmap | Rust |
| Move (Sui, Aptos) | Roadmap | Move |
| Stellar/Soroban | Roadmap | Rust |
| Algorand | Roadmap | TEAL, PyTeal |
| Cardano | Roadmap | Plutus, Aiken |
| Starknet/Cairo | Roadmap | Cairo |

> **El análisis EVM (50 herramientas, 9 capas) está listo para producción.** Las cadenas
> no-EVM están en el ROADMAP: existe código de adapter temprano pero es experimental y todavía
> no está validado para producción.

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
 Orquestador --> 9 Capas --> Stack de Adaptadores Configurado
    |
    v
 Agregador de Hallazgos --> Pipeline ML --> Contexto RAG --> Filtro FP
    |
    v
 Generador de Reportes --> JSON / SARIF / PDF / HTML / Markdown
```

MIESC utiliza una arquitectura de doble paquete:
- `miesc/` - API Pública (estable, instalable vía pip)
- `src/` - Implementación interna (35 módulos de análisis, pipeline ML, RAG, generación de reportes)

Consultá [ARCHITECTURE.md](./docs/ARCHITECTURE.md) para el diseño técnico completo con diagramas Mermaid.

---

## Validación Académica

MIESC fue desarrollado como tesis de Maestría en Ciberdefensa en [UNDEF-IUA](https://www.iua.edu.ar/) (Argentina). Las afirmaciones de investigación actuales están consolidadas en el [Paper 1](./paper/miesc-paper.pdf), el [Paper 2](./paper/paper2-remediation.pdf) y sus artefactos de reproducibilidad:

- **143 contratos**, 207 vulnerabilidades ground-truth, 10 categorías
- **95.8% recall** en el último perfil reproducible local de SmartBugs sobre el corpus completo; baseline de Slither solo: 43.2%
- El Paper 1 reporta un seguimiento local con Ollama sobre los casos no detectados restantes de SmartBugs en 140/143 (97.9%); el artefacto reproducible del corpus sigue siendo el perfil JSON de 95.8%.
- El Paper 1 ahora trata a EVMBench como el benchmark principal de lógica de negocio: el enfoque estático-solo alcanza 22/120 (18.3%), mientras que el ensemble reproducible de cuatro proveedores alcanza 111/120 (92.5%)
- El Paper 2 evalúa artefactos de remediación: 141/143 correcciones aplicadas, 90/141 contratos parcheados compilan standalone, 93/141 eliminan el hallazgo original por re-escaneo y 91/141 pasan no-regresión acotada
- El perfil reproducible de SmartBugs corre en 737.0s en total (~5.15 seg/contrato)
- Resultados canónicos: [Reproducibilidad del Paper 1](./paper/PAPER1_REPRODUCIBILITY.md), [Reproducibilidad del Paper 2](./paper/PAPER2_REPRODUCIBILITY.md), [matriz de afirmaciones del Paper 1](./benchmarks/results/paper1_claims_matrix.json), [matriz de afirmaciones del Paper 2](./benchmarks/results/paper2_claims_matrix.json)

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
| [Referencia de Herramientas](./docs/TOOLS.md) | Los 35 módulos de análisis y sus capacidades |
| [Guía de Reportes](./docs/guides/REPORTS.md) | Plantillas y personalización de reportes |
| [Detectores Personalizados](./docs/CUSTOM_DETECTORS.md) | Construí tus propios detectores |
| [Multi-Chain](./docs/MULTICHAIN.md) | Análisis de cadenas no-EVM |
| [Referencia de API](https://fboiero.github.io/MIESC/api/) | Auto-generada desde docstrings |
| [Contribuir](./.github/CONTRIBUTING.md) | Guías de desarrollo |
| [Hoja de Ruta](./docs/ROADMAP.md) | Próximos pasos |

---

## Troubleshooting

<details>
<summary><strong>Problemas Comunes</strong></summary>

**`miesc: command not found`**
Después de `pip install miesc`, el punto de entrada puede no estar en tu PATH. Usá:
```bash
python3 -m miesc.cli.main --help
```
O agregá `~/.local/bin` (o el `bin` de tu venv) a tu PATH.

**`Tool 'mythril' not installed`**
Las herramientas opcionales deben instalarse por separado. Podés:
```bash
pip install miesc[full]              # Todas las herramientas basadas en Python
brew install mythril                 # Instalación del sistema
docker run ghcr.io/fboiero/miesc:full  # O usá la imagen Docker completa
```

**`Ollama API error: HTTP 404` o el análisis LLM devuelve vacío**
El modelo requerido no fue descargado. Ejecutá:
```bash
ollama pull qwen2.5-coder:14b   # ~9 GB, recomendado
ollama pull qwen2.5-coder:32b   # ~20 GB, más preciso (necesita 24+GB de RAM)
```
Verificá que Ollama esté corriendo: `curl http://localhost:11434/api/tags`

**El contenedor Docker no puede alcanzar Ollama en el host (macOS)**
```bash
docker run -e OLLAMA_HOST=http://host.docker.internal:11434 ...
```
En Linux, usá `--network=host` y `OLLAMA_HOST=http://localhost:11434`.

**Slither falla con `solc not found` o desajuste de versión**
Instalá solc-select:
```bash
pip install solc-select
solc-select install 0.4.26 0.5.17 0.8.20
```

**La generación de reportes PDF falla (errores de `weasyprint`)**
WeasyPrint necesita librerías del sistema:
```bash
brew install pango cairo gdk-pixbuf libffi   # macOS
sudo apt install libpango-1.0-0 libpangoft2-1.0-0  # Linux
```

**`miesc audit full` corre lento (>10 min por contrato)**
Modelos LLM pesados (32B) en contratos pequeños. Usá `qwen2.5-coder:14b` en `~/.miesc/config.yaml` o ejecutá un escaneo rápido: `miesc audit quick`.

</details>

---

## Contribuir

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC && pip install -e .[dev]
pytest tests/ --no-cov              # Corrida local rápida
pytest tests/ --cov=src --cov-report=term-missing  # Corrida con cobertura
```

Consultá [CONTRIBUTING.md](./.github/CONTRIBUTING.md) para las guías. [CONTRIBUTING_ES.md](./.github/CONTRIBUTING_ES.md) disponible en español.

---

## Licencia

[AGPL-3.0](./LICENSE) - Libre para cualquier uso. La seguridad no debería ser un privilegio reservado para proyectos con grandes presupuestos. Si construís un servicio sobre MIESC, contribuí tus cambios de vuelta.

## Autor

**Fernando Boiero** - Tesis de Maestría en Ciberdefensa, UNDEF-IUA Argentina

Construido sobre los hombros de: [Slither](https://github.com/crytic/slither), [Mythril](https://github.com/ConsenSys/mythril), [Echidna](https://github.com/crytic/echidna), [Foundry](https://github.com/foundry-rs/foundry), [Aderyn](https://github.com/Cyfrin/aderyn), [Halmos](https://github.com/a16z/halmos), y la comunidad de seguridad de Ethereum.
</content>
</invoke>
