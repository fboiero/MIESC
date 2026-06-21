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

That's it. MIESC runs Slither + Aderyn + Solhint, deduplicates findings, and gives you a unified report with confidence scores in seconds.

### Full pipeline: detect → fix → verify → comply

```bash
miesc scan contract.sol -o results.json           # Detect + intelligence
miesc fix results.json -c contract.sol -o fixed.sol  # Auto-patch vulnerabilities
miesc remediate results.json -c contract.sol --compile --rescan  # Patch + evidence bundle
miesc verify fixed.sol --tool smtchecker           # Prove fix works
miesc compliance results.json --standard mica      # Map to MiCA/DORA/ISO 27001
miesc report results.json -t premium -f pdf        # Professional audit report
```

### Current research pipeline: Intelligence Engine

```bash
miesc scan contract.sol --verbose                  # Per-finding confidence + fix
miesc scan contracts/ --recursive                  # Directory scanning
miesc scan . --diff origin/main                    # PR-level: only changed files
```

The intelligence engine automatically:
- **Deduplicates** cross-tool findings (Slither + Aderyn report same bug → 1 finding)
- **Scores confidence** via Bayesian multi-tool agreement (2 tools = 85%, 3 = 95%)
- **Generates fix code** — copy-pasteable Solidity patches for 10 vulnerability categories
- **Suppresses false positives** — context-aware (onlyOwner, Solidity 0.8+, OpenZeppelin guards)
- **Calibrates severity** across tools (Aderyn LOW → Medium when warranted)

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

| Metric | Slither alone | Mythril alone | MIESC Paper 1 reproducible profile | Evidence scope |
|--------|:------------:|:-------------:|:---------------------------------:|:--------------|
| Recall | 43.2% | 27.4% | **99.3%** | Full SmartBugs-curated corpus (layer-1 + intelligence) |
| Precision | 8.3% | 6.1% | **26.4%** | Full SmartBugs-curated corpus (layer-1 + intelligence) |
| F1-Score | 13.9% | 10.0% | **36.0%** | Full SmartBugs-curated corpus |

The full-corpus SmartBugs result is the reproducible Paper 1 profile. A local
Ollama follow-up on the remaining misses is reported in Paper 1 as 140/143
(97.9%) and should be treated as a secondary follow-up claim until its own
machine-readable lift artifact is published. The 9-layer run is reported
separately as an end-to-end integration smoke run, not as a corpus-wide claim.

**Real-world exploits** (11 confirmed DeFi exploits, $3.3B total losses):

| Vulnerability | Exploits | Detected | Recall | Examples |
|---------------|:--------:|:--------:|:------:|----------|
| Reentrancy | 3 | 3 | **100%** | Euler $197M, Rari $80M, Platypus $8.5M |
| Access Control | 3 | 3 | **100%** | Parity $280M, Ronin $624M |
| Flash Loan | 2 | 2 | **100%** | bZx $8.1M, Compound $80M |
| Overall | 11 | 9 | **81.8%** | Cohen's Kappa: 0.77 |

> **81.8% recall on real-world exploits** — MIESC would have flagged 9 of 11 multi-million dollar exploits before deployment. [Paper 1 reproducibility](./paper/PAPER1_REPRODUCIBILITY.md) | [Exploit evaluation](./benchmarks/evaluate_exploits.py)

**Why recall matters more than precision for pre-audit triage**: High recall means fewer missed vulnerabilities. False positives are filtered in the triage step — missed vulnerabilities become exploits in production.

### Research Papers and Reproducible Claims

MIESC has two linked research tracks. Paper 1 evaluates detection and multi-layer security assessment. Paper 2 extends that evidence into automatic remediation artifacts and independent verification steps. Paper 2 does not replace or invalidate Paper 1; it starts from the same detection pipeline and measures what happens after a finding is converted into a patch candidate.

| Paper | Focus | Main reproducible evidence | Artifacts |
|-------|-------|----------------------------|-----------|
| [Paper 1](./paper/miesc-paper.pdf) | Multi-layer smart contract security evaluation | SmartBugs: 99.3% recall (142/143, layer-1 + intelligence, no LLM); DeFi exploits: 81.8% recall on 11 incidents; EVMBench ensemble: 111/120 high-severity findings, 92.5% recall | [Reproducibility](./paper/PAPER1_REPRODUCIBILITY.md), [claims matrix](./benchmarks/results/paper1_claims_matrix.json) |
| [Paper 2](./paper/paper2-remediation.pdf) | Verifiable remediation artifacts | 141/143 fixes applied; 90/141 standalone patched contracts compile; 93/141 eliminate the original finding by re-scan; 91/141 pass bounded no-regression | [Reproducibility](./paper/PAPER2_REPRODUCIBILITY.md), [claims matrix](./benchmarks/results/paper2_claims_matrix.json), [experiment audit](./benchmarks/results/paper2_experiment_audit.json) |

For research citation and review, the canonical current claims are the two paper PDFs, their reproducibility notes, and the `benchmarks/results/paper*_claims_matrix.json` files. The platform alignment plan maps these paper results into CLI, API, MCP, RAG, and remediation workflow requirements: [Paper learnings and platform alignment](./docs/roadmap/PAPER_LEARNINGS_PLATFORM_ALIGNMENT.md). RAG source selection and weighting are governed by the [RAG source policy](./docs/guides/RAG_SOURCE_POLICY.md). Older release notes, thesis drafts, and roadmap documents are kept for project history and may contain previous benchmark runs or version-specific metrics.

Current technical-debt cleanup and remaining platform work are tracked in the [technical debt remediation plan](./docs/roadmap/TECHNICAL_DEBT_REMEDIATION_PLAN.md).

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

# Everything for local analysis (PDF, LLM, RAG, APIs)
pip install miesc[full]

# Development
git clone https://github.com/fboiero/MIESC.git
cd MIESC && pip install -e .[dev]
```

Requirements: Python 3.12+. Slither installs automatically. Other tools are optional — MIESC uses whatever is available.

For a full researcher workstation with isolated Mythril, Manticore, Certora CLI, Wake, Semgrep, and formal-verification tooling:

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC
./scripts/bootstrap_researcher_tools.sh
make researcher-smoke
```

See [Researcher Packaging Guide](./docs/guides/RESEARCHER_PACKAGING.md) for the recommended PyPI + Docker + local bootstrap distribution model.

---

## Multi-Chain Support

```bash
miesc analyze Token.sol           # Auto-detects EVM (Solidity/Vyper)
miesc analyze Vault.cairo         # Starknet/Cairo (13 vuln types, zkLend-informed)
miesc analyze Program.rs          # Solana/Anchor (22 vuln types)
miesc analyze Module.move         # Move/Sui/Aptos (19 vuln types)
```

**77 vulnerability types** across 4 ecosystems, informed by real 2024-2026 exploits (zkLend $9.6M, Braavos, Wormhole $326M, Ronin $624M).

Bridge vulnerability detection:
```bash
miesc scan Bridge.sol             # Detects 7 bridge exploit patterns
```

---

## All Commands

| Command | Description |
|---------|-------------|
| `miesc scan` | Quick scan (3 tools + intelligence engine) |
| `miesc scan --diff HEAD~1` | **NEW** PR-level: only changed .sol files |
| `miesc scan contracts/` | **NEW** Directory scan (+ `--recursive`) |
| `miesc audit quick\|full` | Multi-layer audit (3 quick tools or configured 9-layer stack) |
| `miesc fix results.json` | Auto-generate patched .sol files |
| `miesc remediate results.json` | **NEW** Generate patched files plus compile/re-scan evidence |
| `miesc verify contract.sol` | Run Certora/Halmos/SMTChecker provers |
| `miesc compliance results.json` | **NEW** Map to ISO/NIST/MiCA/DORA |
| `miesc report results.json` | Professional PDF/HTML/Markdown report |
| `miesc specs results.json` | Generate Certora CVL / Scribble specs |
| `miesc export results.json` | SARIF (GitHub), CSV, HTML export |
| `miesc analyze contract.cairo` | Multi-chain analysis |
| `miesc doctor` | Check tool availability |
| `miesc watch contracts/` | Live file watching + auto-scan |

---

## Docker

Release status, published artifact links, GHCR digest, and smoke-test commands
for the current 5.4.2 release are recorded in
[MIESC 5.4.2 Release Status](./docs/policies/RELEASE_STATUS_5.4.2.md).

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
<summary><strong>Docker + Host Ollama (recommended for GPU acceleration)</strong></summary>

MIESC's LLM layers (Layer 5) use Ollama for local AI analysis. The recommended setup runs Ollama on your host machine (with GPU access) and connects the Docker container via network:

```bash
# 1. Install and start Ollama on your HOST (not inside Docker)
# Download from https://ollama.com
ollama serve &
ollama pull qwen2.5-coder:14b   # Best model for code analysis
ollama pull deepseek-coder:6.7b  # Lighter alternative

# 2. Scan with host Ollama (macOS)
docker run --rm \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  -v $(pwd)/contracts:/contracts \
  ghcr.io/fboiero/miesc:latest \
  scan /contracts/MyContract.sol -o /contracts/results.json

# 3. Scan with host Ollama (Linux)
docker run --rm --network=host \
  -e OLLAMA_HOST=http://localhost:11434 \
  -v $(pwd)/contracts:/contracts \
  ghcr.io/fboiero/miesc:latest \
  scan /contracts/MyContract.sol

# 4. Generate AI-powered premium PDF report
docker run --rm \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  -v $(pwd):/work \
  ghcr.io/fboiero/miesc:full \
  report /work/results.json -t premium -f pdf \
    --llm-interpret -o /work/audit_report.pdf
```

**Why host Ollama?** Docker containers don't have GPU access by default. Running Ollama on the host lets it use your GPU (Apple Silicon, NVIDIA CUDA) for 10-50x faster LLM inference.

</details>

<details>
<summary><strong>Docker Compose (full stack with bundled Ollama)</strong></summary>

For environments without a host Ollama, use docker-compose to run everything together:

```bash
# Start MIESC + Ollama + model initialization
docker compose -f docker/docker-compose.yml --profile llm up -d

# Run analysis
docker compose -f docker/docker-compose.yml exec miesc miesc scan /app/contracts/MyContract.sol

# Stop
docker compose -f docker/docker-compose.yml down
```

The compose stack automatically pulls `deepseek-coder:6.7b` and configures inter-service networking.

</details>

<details>
<summary><strong>ARM / Apple Silicon notes</strong></summary>

The **standard** image runs natively on ARM. The registry **full** image is intended as amd64 for maximum tool parity. Native ARM full builds skip Echidna, Medusa, Mythril, Manticore, Halmos, and Semgrep by default because upstream releases are amd64-only, require long Z3 source builds, or ship ARM wheels that are not reliable in Docker. Build natively with:

```bash
./scripts/build-images.sh full
```

For full ARM workstation parity, prefer the local bootstrap:

```bash
./scripts/bootstrap_researcher_tools.sh
```

To force native ARM Mythril, Manticore, Halmos, or Semgrep builds inside Docker:

```bash
MIESC_BUILD_MYTHRIL=true ./scripts/build-images.sh full
MIESC_BUILD_MANTICORE=true ./scripts/build-images.sh full
MIESC_BUILD_HALMOS=true ./scripts/build-images.sh full
MIESC_BUILD_SEMGREP=true ./scripts/build-images.sh full
```

</details>

---

## CLI Reference

```bash
miesc scan contract.sol              # Quick scan (Slither + Aderyn + Solhint)
miesc scan contract.sol --ci         # CI mode: exit 1 on critical/high
miesc audit quick contract.sol       # 3-tool audit
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
    rev: v5.4.2
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

### MCP Server (Claude Desktop / Cursor / Claude Code)

MIESC exposes its 9-layer security analysis as MCP tools via [Model Context Protocol](https://modelcontextprotocol.io):

```bash
pip install 'miesc[mcp]'   # Install with MCP support
miesc-mcp                   # Start stdio MCP server
```

Add to your Claude Desktop `config.json`:

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

**Available MCP tools:** `miesc_quick_scan`, `miesc_deep_scan`, `miesc_deep_audit`, `miesc_run_tool`, `miesc_run_layer`, `miesc_analyze_defi`, `miesc_apply_fix`, `miesc_validate_remediation`, `miesc_remediation_evidence_bundle`, `miesc_list_tools`, `miesc_doctor`

### REST API Remediation

The API exposes the same remediation evidence schema as the CLI:

| Endpoint | Purpose |
|----------|---------|
| `POST /api/v1/remediate/` | Apply fix candidates and return an evidence bundle |
| `POST /api/v1/validate-remediation/` | Apply fixes with compile/re-scan validation enabled by default |

Examples: [Remediation API and MCP guide](./docs/guides/REMEDIATION_API_MCP.md).

### Python API

```python
from miesc.api import run_tool, run_full_audit

results = run_tool("slither", "contract.sol")
report = run_full_audit("contract.sol")
```

### Local APIs And Reports

```bash
pip install "miesc[django]"
python -m miesc.api.rest --host 127.0.0.1 --port 8000
python -m src.utils.web_dashboard --results analysis/results --output analysis/dashboard
```

The open core exposes local REST/MCP automation and static report generation.
The hosted product UI, team dashboards, licensing workflow, and IDE product
clients now live in the platform layer.

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
 Orchestrator --> 9 Layers --> Configured Adapter Stack
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

MIESC was developed as a Master's thesis in Cyberdefense at [UNDEF-IUA](https://www.iua.edu.ar/) (Argentina). The current research claims are consolidated in [Paper 1](./paper/miesc-paper.pdf), [Paper 2](./paper/paper2-remediation.pdf), and their reproducibility artifacts:

- **143 contracts**, 207 ground-truth vulnerabilities, 10 categories
- **99.3% recall** (142/143) on the full-corpus reproducible SmartBugs profile (layer-1 + intelligence engine, no LLM); Slither alone baseline: 43.2%
- Deterministic detectors (uninitialized storage pointer, front-running, modifier reentrancy) close 5 of the 6 prior misses; only a short-address case remains. Aggregate has tool-stability variance 0.972--0.993 (run unloaded).
- Paper 1 now treats EVMBench as the primary business-logic benchmark: static-only reaches 22/120 (18.3%), while the reproducible four-provider ensemble reaches 111/120 (92.5%)
- Paper 2 evaluates remediation artifacts: 141/143 fixes applied, 90/141 patched contracts compile standalone, 93/141 eliminate the original finding by re-scan, and 91/141 pass bounded no-regression
- Reproducible SmartBugs profile runs in 737.0s total (~5.15 sec/contract)
- Canonical results: [Paper 1 reproducibility](./paper/PAPER1_REPRODUCIBILITY.md), [Paper 2 reproducibility](./paper/PAPER2_REPRODUCIBILITY.md), [Paper 1 claims matrix](./benchmarks/results/paper1_claims_matrix.json), [Paper 2 claims matrix](./benchmarks/results/paper2_claims_matrix.json)

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
| [Tool Reference](./docs/TOOLS.md) | All 35 analysis modules and their capabilities |
| [Report Guide](./docs/guides/REPORTS.md) | Report templates and customization |
| [Custom Detectors](./docs/CUSTOM_DETECTORS.md) | Build your own detectors |
| [Multi-Chain](./docs/MULTICHAIN.md) | Non-EVM chain analysis |
| [API Reference](https://fboiero.github.io/MIESC/api/) | Auto-generated from docstrings |
| [Contributing](./.github/CONTRIBUTING.md) | Development guidelines |
| [Roadmap](./docs/ROADMAP.md) | What's coming next |

---

## Troubleshooting

<details>
<summary><strong>Common Issues</strong></summary>

**`miesc: command not found`**
After `pip install miesc`, the entry point may not be on your PATH. Use:
```bash
python3 -m miesc.cli.main --help
```
Or add `~/.local/bin` (or your venv's `bin`) to your PATH.

**`Tool 'mythril' not installed`**
Optional tools must be installed separately. Either:
```bash
pip install miesc[full]              # All Python-based tools
brew install mythril                 # System install
docker run ghcr.io/fboiero/miesc:full  # Or use the full Docker image
```

**`Ollama API error: HTTP 404` or LLM analysis returns empty**
The required model isn't pulled. Run:
```bash
ollama pull qwen2.5-coder:14b   # ~9 GB, recommended
ollama pull qwen2.5-coder:32b   # ~20 GB, more accurate (needs 24+GB RAM)
```
Verify Ollama is running: `curl http://localhost:11434/api/tags`

**Docker container can't reach Ollama on host (macOS)**
```bash
docker run -e OLLAMA_HOST=http://host.docker.internal:11434 ...
```
On Linux, use `--network=host` and `OLLAMA_HOST=http://localhost:11434`.

**Slither errors with `solc not found` or version mismatch**
Install solc-select:
```bash
pip install solc-select
solc-select install 0.4.26 0.5.17 0.8.20
```

**PDF report generation fails (`weasyprint` errors)**
WeasyPrint needs system libraries:
```bash
brew install pango cairo gdk-pixbuf libffi   # macOS
sudo apt install libpango-1.0-0 libpangoft2-1.0-0  # Linux
```

**`miesc audit full` runs slowly (>10 min per contract)**
Heavy LLM models (32B) on small contracts. Use `qwen2.5-coder:14b` in `~/.miesc/config.yaml` or run quick scan: `miesc audit quick`.

</details>

---

## Contributing

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC && pip install -e .[dev]
pytest tests/ --no-cov              # Fast local run
pytest tests/ --cov=src --cov-report=term-missing  # Coverage run
```

See [CONTRIBUTING.md](./.github/CONTRIBUTING.md) for guidelines. [CONTRIBUTING_ES.md](./.github/CONTRIBUTING_ES.md) disponible en espanol.

---

## License

[AGPL-3.0](./LICENSE) - Free for any use. Security should not be a privilege reserved for well-funded projects. If you build a service on top of MIESC, contribute your changes back.

## Author

**Fernando Boiero** - Master's Thesis in Cyberdefense, UNDEF-IUA Argentina

Built on the shoulders of: [Slither](https://github.com/crytic/slither), [Mythril](https://github.com/ConsenSys/mythril), [Echidna](https://github.com/crytic/echidna), [Foundry](https://github.com/foundry-rs/foundry), [Aderyn](https://github.com/Cyfrin/aderyn), [Halmos](https://github.com/a16z/halmos), and the Ethereum security community.
