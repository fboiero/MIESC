<p align="center">
  <h1 align="center">MIESC</h1>
  <p align="center">
    <strong>50 security tools. 9 defense layers. One command.</strong>
  </p>
  <p align="center">
    Enterprise-grade smart contract security, free and open to everyone.
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
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#why-miesc">Why MIESC</a> &bull;
  <a href="#github-action">GitHub Action</a> &bull;
  <a href="#docker">Docker</a> &bull;
  <a href="./README_ES.md">Espanol</a> &bull;
  <a href="https://fboiero.github.io/MIESC">Docs</a>
</p>

---

## Quick Start

```bash
pip install miesc
miesc scan MyContract.sol
```

That's it. MIESC runs Slither + Aderyn + Solhint and gives you a unified report in seconds.

Want the full 9-layer analysis with AI correlation?

```bash
miesc audit full MyContract.sol -o results.json
miesc report results.json -t premium -f pdf --llm-interpret
```

<details>
<summary><strong>See example output</strong></summary>

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

## Why MIESC

**The problem**: Professional smart contract audits cost $50K-$200K and take weeks. Meanwhile, $1.5B+ is lost to exploits every year. Most projects ship without any audit at all. Running Slither alone catches ~70% of vulnerabilities with 15-20% false positives. Every tool has blind spots. Auditors manually run 5-10 tools, normalize outputs, and cross-reference findings. This takes hours.

**MIESC makes that workflow accessible to everyone.** One command orchestrates multiple security tools across 9 complementary analysis techniques, deduplicates findings, and generates professional reports. Free, open-source, runs locally — your code never leaves your machine.

### Benchmark Results

**SmartBugs-curated** (143 contracts, 207 ground-truth vulnerabilities):

| Metric | Slither alone | Mythril alone | MIESC |
|--------|:------------:|:-------------:|:-----:|
| Recall | 43.2% | 27.4% | **80.0%** |
| Precision | 8.3% | 6.1% | 22.7% |
| F1-Score | 13.9% | 10.0% | **35.4%** |

**Real-world exploits** (11 confirmed DeFi exploits, $3.3B total losses):

| Vulnerability | Exploits | Detected | Recall | Examples |
|---------------|:--------:|:--------:|:------:|----------|
| Reentrancy | 3 | 3 | **100%** | Euler $197M, Rari $80M, Platypus $8.5M |
| Access Control | 3 | 3 | **100%** | Parity $280M, Ronin $624M |
| Flash Loan | 2 | 2 | **100%** | bZx $8.1M, Compound $80M |
| Overall | 11 | 9 | **81.8%** | Cohen's Kappa: 0.773 |

> **81.8% recall on real-world exploits** — MIESC would have flagged 9 of 11 multi-million dollar exploits before deployment. [Full methodology](./benchmarks/results/SMARTBUGS_SCIENTIFIC_REPORT.md) | [Exploit evaluation](./benchmarks/evaluate_exploits.py)

**Why recall matters more than precision for pre-audit triage**: High recall means fewer missed vulnerabilities. False positives are filtered in the triage step — missed vulnerabilities become exploits in production.

### The 9 Defense Layers

```
Layer 1  Static Analysis        Slither, Aderyn, Solhint, Semgrep
Layer 2  Dynamic Testing        Echidna, Foundry, Medusa
Layer 3  Symbolic Execution     Mythril, Halmos, Manticore
Layer 4  Formal Verification    SMTChecker, Scribble, Certora*
Layer 5  AI/LLM Analysis        SmartLLM, GPTScan, LLMSmartAudit (Ollama)
Layer 6  Pattern Detection      Gas Analyzer, Clone Detector, Threat Model
Layer 7  DeFi Security          MEV Detector, Flash Loan Analyzer, Oracle Checker
Layer 8  Exploit Validation     PoC Synthesizer (Foundry), Vulnerability Verifier
Layer 9  Consensus & Reporting  Bayesian Consensus, RAG Enrichment, PDF Reports
```

*Certora requires API key. All other tools are fully open-source.

### What MIESC integrates

| Category | Count | Examples |
|----------|:-----:|---------|
| **External security tools** | 13 | Slither, Mythril, Echidna, Foundry, Halmos, Aderyn, Semgrep |
| **LLM analysis modules** | 6 | SmartLLM, GPTScan, PropertyGPT (via local Ollama) |
| **Internal analyzers** | 16 | MEV detector, gas analyzer, threat model, clone detector |
| **Total analysis modules** | **35** | Across 9 complementary techniques |

### vs. SmartBugs 2.0 (closest competitor)

| | MIESC | SmartBugs 2.0 |
|---|---|---|
| External tools | 13 | 19 |
| AI/LLM analysis | Yes (Ollama local) | No |
| Internal analyzers | 16 | No |
| False-positive filter | Yes (RAG + ML) | No |
| Professional PDF reports | Yes | No |
| Plugin system | Yes (PyPI) | No |
| GitHub Action | Yes | No |
| SARIF output | Yes | Yes |

---

## GitHub Action

Add smart contract security to any CI/CD pipeline in 30 seconds:

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

Results appear in GitHub's **Security** tab and as a PR comment. See [example workflow](./.github/workflows/example-miesc-action.yml) for advanced configurations.

### Available Modes

| Mode | Tools | Time | Use Case |
|------|-------|------|----------|
| `scan` | Slither, Aderyn, Solhint | ~30s | Every push |
| `audit-quick` | 4 core tools | ~2min | PR checks |
| `audit-full` | All 9 layers | ~10min | Pre-release |
| `audit-profile` | Configurable | Varies | DeFi, tokens, etc. |

---

## Installation

```bash
# Minimal CLI
pip install miesc

# With PDF reports
pip install miesc[pdf]

# Everything (PDF, LLM, RAG, web UI)
pip install miesc[full]

# Development
git clone https://github.com/fboiero/MIESC.git
cd MIESC && pip install -e .[dev]
```

Requirements: Python 3.12+. Slither installs automatically. Other tools are optional — MIESC uses whatever is available.

---

## Docker

```bash
# Standard image (~3GB, multi-arch including Apple Silicon)
docker pull ghcr.io/fboiero/miesc:latest
docker run --rm -v $(pwd):/contracts ghcr.io/fboiero/miesc:latest scan /contracts/MyContract.sol

# Full image (~8GB, all 50 tools, amd64)
docker pull ghcr.io/fboiero/miesc:full
docker run --rm -v $(pwd):/contracts ghcr.io/fboiero/miesc:full audit full /contracts/MyContract.sol

# Check what tools are available
docker run --rm ghcr.io/fboiero/miesc:latest doctor
```

<details>
<summary><strong>Docker + Ollama for AI-powered PDF reports</strong></summary>

```bash
# 1. Start Ollama and pull the model
ollama serve &
ollama pull mistral:latest

# 2. Full audit
docker run --rm -v $(pwd):/contracts \
  ghcr.io/fboiero/miesc:full \
  audit full /contracts/MyContract.sol -o /contracts/results.json

# 3. Generate premium PDF with AI interpretation
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

The premium report includes CVSS scoring, risk matrix, attack scenarios, deployment recommendation (GO/NO-GO), and AI-generated remediation roadmap. Comparable to Trail of Bits / OpenZeppelin report style.

</details>

<details>
<summary><strong>ARM / Apple Silicon notes</strong></summary>

The **standard** image runs natively on ARM. The **full** image is amd64-only in the registry (runs under QEMU emulation). Build natively with:

```bash
./scripts/build-images.sh full  # ~30-60 min, but native speed
```

</details>

---

## CLI Reference

```bash
miesc scan contract.sol              # Quick scan (Slither + Aderyn + Solhint)
miesc scan contract.sol --ci         # CI mode: exit 1 on critical/high
miesc audit quick contract.sol       # 4-tool audit
miesc audit full contract.sol        # Full 9-layer audit
miesc audit layer 3 contract.sol     # Specific layer (e.g., symbolic execution)
miesc audit profile defi contract.sol  # Named profile (defi, token, security, etc.)
miesc report results.json -t premium -f pdf --llm-interpret  # AI-powered PDF report
miesc export results.json -f sarif   # Export as SARIF
miesc doctor                         # Check tool availability
miesc watch ./contracts              # Auto-scan on file changes
miesc benchmark ./contracts --save   # Track security posture over time
```

### Analysis Profiles

| Profile | Layers | Best For |
|---------|--------|----------|
| `fast` | 1 | Quick feedback during development |
| `balanced` | 1, 3 | Pre-commit checks |
| `ci` | 1 | CI/CD pipelines |
| `security` | 1, 3, 4, 5 | High-value contracts |
| `defi` | 1, 2, 3, 5, 8 | DeFi protocols |
| `token` | 1, 3, 5 | ERC20/721/1155 tokens |
| `thorough` | 1-9 | Pre-release / comprehensive audit |

---

## Extend MIESC

### Custom Detectors

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

Register via `pyproject.toml`:

```toml
[project.entry-points."miesc.detectors"]
dangerous-delegatecall = "my_package:DangerousDelegatecall"
```

### Plugin System

```bash
miesc plugins install miesc-defi-detectors   # Install from PyPI
miesc plugins create my-detector             # Scaffold a new plugin
miesc plugins list                           # List installed plugins
miesc detectors list                         # List all available detectors
```

### Integrations

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

### MCP Server

MIESC integrates with AI agents via the [Model Context Protocol](https://modelcontextprotocol.io):

```bash
miesc server mcp  # Start MCP WebSocket server
```

```json
// Claude Desktop / MCP client config
{
  "mcpServers": {
    "miesc": {
      "command": "miesc",
      "args": ["server", "mcp"]
    }
  }
}
```

### Python API

```python
from miesc.api import run_tool, run_full_audit

results = run_tool("slither", "contract.sol")
report = run_full_audit("contract.sol")
```

### Web UI

```bash
pip install miesc[web]
make webapp  # Opens at http://localhost:8501
```

Interactive Streamlit dashboard with upload, analysis, results visualization, and report export.

---

## Multi-Chain Support

| Chain | Status | Languages |
|-------|--------|-----------|
| **EVM** (Ethereum, Polygon, BSC, Arbitrum, etc.) | Production | Solidity, Vyper |
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

> Non-EVM support is experimental. EVM analysis (50 tools, 9 layers) is production-ready.

---

## Compliance Mapping

MIESC maps every finding to international security standards:

**ISO/IEC 27001:2022** | **NIST CSF** | **OWASP Smart Contract Top 10** | **CWE** | **SWC Registry** | **MITRE ATT&CK** | **PCI-DSS** | **SOC 2**

---

## Architecture

```
Contract.sol
    |
    v
 CLI / API / MCP / GitHub Action
    |
    v
 Orchestrator --> 9 Layers --> 50 Tool Adapters
    |
    v
 Finding Aggregator --> ML Pipeline --> RAG Context --> FP Filter
    |
    v
 Report Generator --> JSON / SARIF / PDF / HTML / Markdown
```

MIESC uses a dual-package architecture:
- `miesc/` - Public API (stable, pip-installable)
- `src/` - Internal implementation (35 analysis modules, ML pipeline, RAG, report generation)

See [ARCHITECTURE.md](./docs/ARCHITECTURE.md) for the full technical design with Mermaid diagrams.

---

## Academic Validation

MIESC was developed as a Master's thesis in Cyberdefense at [UNDEF-IUA](https://www.iua.edu.ar/) (Argentina). Evaluated on the SmartBugs-curated benchmark (Durieux et al., ICSE 2020):

- **143 contracts**, 207 ground-truth vulnerabilities, 10 categories
- **80% recall** (184/230 vulnerabilities detected) — best-in-class for multi-tool orchestration
- **90.6% recall on reentrancy**, 100% on unchecked calls and time manipulation
- **85% faster than running tools manually** (~1 sec/contract)
- Full results: [SMARTBUGS_SCIENTIFIC_REPORT.md](./benchmarks/results/SMARTBUGS_SCIENTIFIC_REPORT.md)

If you use MIESC in research, please cite:

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

## Digital Public Good

MIESC is a candidate for [Digital Public Goods Alliance](https://digitalpublicgoods.net/) certification (Application ID: GID0092948), aligned with the UN Sustainable Development Goals:

- **SDG 9** (Industry & Infrastructure): Strengthening blockchain infrastructure security
- **SDG 16** (Peace & Strong Institutions): Protecting digital assets, reducing fraud
- **SDG 17** (Partnerships): Open-source collaboration for global security standards

The project is fully compliant with all 9 DPGA indicators: open license (AGPL-3.0), clear ownership, platform independence, comprehensive documentation, data portability (SARIF/CSV/JSON), privacy-preserving (local-first), standards-based (12 international standards), and responsible use policies.

| Policy | Description |
|--------|-------------|
| [DPG Compliance](./docs/policies/DPG-COMPLIANCE.md) | Full 9-indicator compliance statement |
| [SDG Relevance](./docs/policies/SDG_RELEVANCE.md) | Sustainable Development Goals mapping |
| [Privacy Policy](./PRIVACY.md) | Data handling and privacy statement |
| [Responsible Use](./RESPONSIBLE_USE.md) | Ethical use guidelines |
| [Do No Harm](./docs/policies/DO_NO_HARM.md) | Risk assessment and mitigations |

---

## Documentation

| Resource | Description |
|----------|-------------|
| [Installation Guide](./docs/INSTALLATION.md) | Complete setup instructions |
| [Quick Start](./docs/guides/QUICKSTART.md) | Get running in 5 minutes |
| [Architecture](./docs/ARCHITECTURE.md) | Technical design and layer details |
| [Tool Reference](./docs/TOOLS.md) | All 50 tools and their capabilities |
| [Report Guide](./docs/guides/REPORTS.md) | Report templates and customization |
| [Custom Detectors](./docs/CUSTOM_DETECTORS.md) | Build your own detectors |
| [Multi-Chain](./docs/MULTICHAIN.md) | Non-EVM chain analysis |
| [API Reference](https://fboiero.github.io/MIESC/api/) | Auto-generated from docstrings |
| [Contributing](./CONTRIBUTING.md) | Development guidelines |
| [Roadmap](./ROADMAP.md) | What's coming next |

---

## Contributing

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC && pip install -e .[dev]
pytest tests/  # 4,700+ tests
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines. [CONTRIBUTING_ES.md](./CONTRIBUTING_ES.md) disponible en espanol.

---

## License

[AGPL-3.0](./LICENSE) - Free for any use. Security should not be a privilege reserved for well-funded projects. If you build a service on top of MIESC, contribute your changes back.

## Author

**Fernando Boiero** - Master's Thesis in Cyberdefense, UNDEF-IUA Argentina

Built on the shoulders of: [Slither](https://github.com/crytic/slither), [Mythril](https://github.com/ConsenSys/mythril), [Echidna](https://github.com/crytic/echidna), [Foundry](https://github.com/foundry-rs/foundry), [Aderyn](https://github.com/Cyfrin/aderyn), [Halmos](https://github.com/a16z/halmos), and the Ethereum security community.
