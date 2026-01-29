# MIESC - Multi-layer Intelligent Evaluation for Smart Contracts

Multi-layer security analysis framework for smart contracts with **multi-chain support**.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/miesc)](https://pypi.org/project/miesc/)
[![Version](https://img.shields.io/badge/version-4.5.0-green)](https://github.com/fboiero/MIESC/releases)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/fboiero/MIESC/badge)](https://securityscorecards.dev/viewer/?uri=github.com/fboiero/MIESC)
[![Security Audit](https://github.com/fboiero/MIESC/actions/workflows/miesc-security.yml/badge.svg)](https://github.com/fboiero/MIESC/actions/workflows/miesc-security.yml)
[![codecov](https://codecov.io/gh/fboiero/MIESC/graph/badge.svg)](https://codecov.io/gh/fboiero/MIESC)
[![Tools](https://img.shields.io/badge/tools-31%2F31%20operational-brightgreen)](./docs/TOOLS.md)
[![Chains](https://img.shields.io/badge/chains-7%20supported-blue)](./docs/MULTICHAIN.md)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit)

[English](./README.md) | [Espa&ntilde;ol](./README_ES.md)

MIESC orchestrates **31 security tools** across **9 defense layers** with AI-assisted correlation and ML-based detection. Pre-audit triage tool for smart contract security.

## Supported Blockchains

| Chain | Status | Languages | Tools |
|-------|--------|-----------|-------|
| **EVM** (Ethereum, Polygon, BSC, etc.) | ✅ Production | Solidity, Vyper | 31 tools, 9 layers |
| **Solana** | 🧪 Alpha | Rust/Anchor | Pattern detection |
| **NEAR** | 🧪 Alpha | Rust | Pattern detection |
| **Move** (Sui, Aptos) | 🧪 Alpha | Move | Pattern detection |
| **Stellar/Soroban** | 🧪 Alpha | Rust | Pattern detection |
| **Algorand** | 🧪 Alpha | TEAL, PyTeal | Pattern detection |
| **Cardano** | 🧪 Alpha | Plutus, Aiken | Pattern detection |

> **Note:** Non-EVM chain support is **experimental/alpha**. These analyzers use pattern-based detection and are under active development. Production audits should use EVM analysis (31 tools, 9 defense layers) for comprehensive coverage.

**Validated Results (SmartBugs-curated dataset, 50 contracts):**

- **Precision: 100%** (0 false positives)
- **Recall: 70%** (35/50 vulnerabilities detected)
- **F1-Score: 82.35%**
- Categories with 100% recall: arithmetic, bad_randomness, front_running

**[Documentation](https://fboiero.github.io/MIESC)** | **[Demo Video](https://youtu.be/pLa_McNBRRw)**

## Installation

```bash
# From PyPI (recommended) - minimal CLI
pip install miesc

# With PDF report generation
pip install miesc[pdf]

# With web UI and API servers
pip install miesc[web]

# With all optional features (includes PDF)
pip install miesc[full]

# From source (development)
git clone https://github.com/fboiero/MIESC.git
cd MIESC && pip install -e .[dev]
```

**Docker:**

```bash
# STANDARD image (~2-3GB) - Core tools: Slither, Aderyn, Solhint, Foundry
docker pull ghcr.io/fboiero/miesc:latest
docker run --rm -v $(pwd):/contracts ghcr.io/fboiero/miesc:latest scan /contracts/MyContract.sol

# FULL image (~8GB) - ALL tools: Mythril, Manticore, Echidna, Halmos, PyTorch
docker pull ghcr.io/fboiero/miesc:full
docker run --rm -v $(pwd):/contracts ghcr.io/fboiero/miesc:full scan /contracts/MyContract.sol

# Check available tools
docker run --rm ghcr.io/fboiero/miesc:latest doctor  # Standard: ~15 tools
docker run --rm ghcr.io/fboiero/miesc:full doctor    # Full: ~30 tools

# Or build locally
docker build -t miesc:latest -f docker/Dockerfile .              # Standard
docker build -t miesc:full -f docker/Dockerfile.full .           # Full
```

<details>
<summary><strong>Docker Troubleshooting</strong></summary>

**"executable file not found" or "scan: not found" error:**

You have an old cached image. Force a fresh download:

```bash
# Remove old cached images
docker rmi ghcr.io/fboiero/miesc:latest 2>/dev/null
docker rmi ghcr.io/fboiero/miesc:main 2>/dev/null

# Pull fresh image
docker pull ghcr.io/fboiero/miesc:latest

# Verify version (should show 4.3.7+)
docker run --rm ghcr.io/fboiero/miesc:latest --version
```

**Verify correct usage:**

```bash
# Correct - arguments passed directly to miesc
docker run --rm ghcr.io/fboiero/miesc:latest --help
docker run --rm ghcr.io/fboiero/miesc:latest scan /contracts/MyContract.sol

# Wrong - don't repeat "miesc"
docker run --rm ghcr.io/fboiero/miesc:latest miesc scan ...  # WRONG!
```

**Permission denied errors:**

```bash
# On Linux, you may need to run as root or add user to docker group
sudo usermod -aG docker $USER
# Then log out and back in
```

**Contract file not found:**

```bash
# Make sure the volume mount path is correct
# The path INSIDE the container must match where you mounted
docker run --rm -v /full/path/to/contracts:/contracts ghcr.io/fboiero/miesc:latest scan /contracts/MyContract.sol

# On Windows PowerShell, use ${PWD}
docker run --rm -v ${PWD}:/contracts ghcr.io/fboiero/miesc:latest scan /contracts/MyContract.sol
```

</details>

**Docker with LLM Support (Professional PDF Reports):**

Generate AI-powered professional audit reports with MIESC + Ollama:

> **⚠️ Memory Requirement:** LLM models require significant RAM. Configure Docker Desktop with **≥8GB memory**:
> - Docker Desktop → Settings → Resources → Memory → 8GB (or more)
> - The `mistral:latest` model requires ~4.5GB RAM to run

<details>
<summary><strong>Step 1: Install Ollama (one-time setup)</strong></summary>

```bash
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.com/install.sh | sh

# Windows: Download from https://ollama.com/download

# Start Ollama and download the model (~4GB)
ollama serve &
ollama pull mistral:latest

# Optional: Download deepseek-coder for code analysis (~3.8GB)
ollama pull deepseek-coder:6.7b
```

**Available Models:**

| Model | Size | RAM Required | Use Case |
|-------|------|--------------|----------|
| `mistral:latest` | 4.0GB | ~4.5GB | General interpretation |
| `deepseek-coder:6.7b` | 3.8GB | ~4.2GB | Code analysis |

</details>

```bash
# Full Audit + Professional PDF Report (recommended workflow)

# 1. Run full 9-layer security audit (use :full image for all tools)
docker run --rm \
  -v $(pwd):/contracts \
  ghcr.io/fboiero/miesc:full \
  audit batch /contracts -o /contracts/results.json -p thorough -r

# 2. Generate professional PDF report with cover page metadata
docker run --rm \
  -v $(pwd):/contracts \
  ghcr.io/fboiero/miesc:full \
  report /contracts/results.json -t premium -f pdf \
    --client "Acme Corp" \
    --auditor "Security Team" \
    --contract-name "TokenV2.sol" \
    --repository "github.com/acme/token" \
    --network "Ethereum Mainnet" \
    -o /contracts/audit_report.pdf

# 3. With AI interpretation (requires Ollama running)
# macOS/Windows:
docker run --rm \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  -v $(pwd):/contracts \
  ghcr.io/fboiero/miesc:full \
  report /contracts/results.json -t premium -f pdf \
    --client "Acme Corp" \
    --auditor "Security Team" \
    --contract-name "TokenV2.sol" \
    --llm-interpret \
    -o /contracts/audit_report.pdf

# Linux (use host network):
docker run --rm --network host \
  -e OLLAMA_HOST=http://localhost:11434 \
  -v $(pwd):/contracts \
  ghcr.io/fboiero/miesc:full \
  report /contracts/results.json -t premium --llm-interpret -f pdf -o /contracts/audit_report.pdf
```

**Report CLI Options:**

| Option | Description | Example |
|--------|-------------|---------|
| `--client` | Client name for cover page | `--client "Acme Corp"` |
| `--auditor` | Auditor name | `--auditor "Security Team"` |
| `--contract-name` | Override contract name | `--contract-name "TokenV2"` |
| `--repository` | Repository URL | `--repository "github.com/acme/token"` |
| `--network` | Target network | `--network "Polygon"` |
| `--classification` | Report classification | `--classification "PUBLIC"` |
| `--llm-interpret` | Enable AI insights | Requires Ollama |
| `-i, --interactive` | Interactive wizard mode | Prompts for missing fields |

<details>
<summary><strong>Example Output: Step 1 - Full Audit</strong></summary>

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
╭──────────┬───────╮
│ Severity │ Count │
├──────────┼───────┤
│ CRITICAL │     1 │
│ HIGH     │    11 │
│ MEDIUM   │     1 │
│ LOW      │     9 │
│ TOTAL    │    22 │
╰──────────┴───────╯

Tools executed: 12/29
OK Report saved to /contracts/results.json
```

</details>

<details>
<summary><strong>Example Output: Step 2 - Professional Report with LLM</strong></summary>

```
INFO Loaded results from /contracts/results.json
INFO LLM interpretation enabled - generating AI-powered insights...
INFO LLM Interpreter: mistral:latest available via HTTP API
INFO Generating executive summary interpretation...
INFO Generating risk narrative...
INFO Interpreting 5 critical/high findings...
INFO Generating remediation priority recommendations...
OK LLM interpretation complete!
INFO Generating profesional report data (CVSS scores, risk matrix, etc.)...
INFO Generating profesional LLM insights (attack scenarios, deployment recommendation)...
OK Profesional LLM insights generated!
OK Report saved to /contracts/audit_report.html

Report Summary: 1 critical, 11 high, 1 medium, 9 low
```

</details>

<details>
<summary><strong>What the Professional Report Includes</strong></summary>

- **Cover Page** with confidentiality classification
- **Executive Summary** with AI-generated business risk analysis
- **Deployment Recommendation** (GO / NO-GO / CONDITIONAL)
- **Risk Matrix** with CVSS-like scoring
- **Detailed Findings** with attack scenarios
- **Remediation Roadmap** with prioritization
- **AI Disclosure** for transparency

</details>

<details>
<summary><strong>Alternative: docker-compose with Ollama</strong></summary>

```bash
# Start MIESC + Ollama containers
docker-compose -f docker/docker-compose.yml --profile llm up -d

# Run full audit and generate report
docker-compose -f docker/docker-compose.yml exec miesc miesc audit full /data/contract.sol -o results.json
docker-compose -f docker/docker-compose.yml exec miesc miesc report results.json -t premium --llm-interpret -o report.html
```

</details>

**As module:**

```bash
python -m miesc --help
python -m miesc scan contract.sol
```

## Quick Start

```bash
# Quick vulnerability scan (simplest command)
miesc scan contract.sol

# CI/CD mode (exits 1 if critical/high issues)
miesc scan contract.sol --ci

# Quick 4-tool audit with more options
miesc audit quick contract.sol

# Full 9-layer audit
miesc audit full contract.sol

# Check tool availability
miesc doctor
```

**[Complete Quick Start Guide](./docs/guides/QUICKSTART.md)** - Detailed installation and usage instructions.

## Features

- **9 defense layers**: Static, Dynamic, Symbolic, Formal, AI, ML, Threat Modeling, Cross-Chain, AI Ensemble
- **31 operational tools**: Slither, Aderyn, Mythril, Echidna, Foundry, Certora, Halmos, SmartLLM, and more
- **Multi-chain support**: EVM (production), Solana, NEAR, Move, Stellar, Algorand, Cardano (alpha)
- **AI correlation**: Local LLM (Ollama) reduces false positives
- **Compliance mapping**: ISO 27001, NIST, OWASP, SWC
- **Multiple interfaces**: CLI, REST API, WebSocket, MCP, Web UI
- **Professional reports**: PDF/HTML audit reports comparable to OpenZeppelin/Certora style

## Usage

### CLI

```bash
miesc scan contract.sol              # Quick vulnerability scan
miesc scan contract.sol --ci         # CI mode (exit 1 on issues)
miesc audit quick contract.sol       # Fast 4-tool scan
miesc audit full contract.sol        # Complete 9-layer audit
miesc audit layer 3 contract.sol     # Run specific layer
miesc report results.json -t professional  # Generate audit report
miesc report results.json -t premium --llm-interpret  # Premium report with AI
miesc benchmark ./contracts --save   # Track security posture
miesc server rest --port 5001        # Start REST API
miesc doctor                         # Check tool availability
miesc watch ./contracts              # Watch mode (auto-scan on save)
miesc detectors list                 # List custom detectors
miesc detectors run contract.sol     # Run custom detectors
miesc plugins list                   # List installed plugins
miesc plugins install <package>      # Install plugin from PyPI
miesc plugins create <name>          # Create new plugin project
```

### Report Generation

Generate professional audit reports from analysis results:

```bash
# Available templates
miesc report results.json -t simple        # Basic findings list
miesc report results.json -t professional  # Standard audit report
miesc report results.json -t executive     # C-level summary
miesc report results.json -t premium       # Trail of Bits style (CVSS, risk matrix)

# With AI-powered interpretation (requires Ollama)
miesc report results.json -t premium --llm-interpret -o report.md

# Different output formats
miesc report results.json -t premium -f html -o report.html
miesc report results.json -t premium -f pdf -o report.pdf
```

**Premium Report Features:**
- CVSS-like scoring for each finding
- Risk matrix (Impact vs Likelihood)
- Deployment recommendation (GO/NO-GO/CONDITIONAL)
- Attack scenarios for critical vulnerabilities
- Code remediation suggestions with diffs
- Remediation roadmap with prioritization

**LLM Requirements (for `--llm-interpret`):**

| Model | Size | Purpose |
|-------|------|---------|
| `mistral:latest` | ~4GB | Report interpretation, risk analysis |
| `deepseek-coder:6.7b` | ~4GB | Code analysis (optional) |

```bash
# Install Ollama: https://ollama.com/download
# Then pull the required model:
ollama pull mistral:latest

# Verify it's working:
ollama list  # Should show mistral:latest

# For Docker: set OLLAMA_HOST to connect to host
# macOS/Windows: OLLAMA_HOST=http://host.docker.internal:11434
# Linux: use --network host
```

### Custom Detectors

Create your own vulnerability detectors:

```python
from miesc.detectors import BaseDetector, Finding, Severity

class MyDetector(BaseDetector):
    name = "my-detector"
    description = "Detects my custom pattern"

    def analyze(self, source_code, file_path=None):
        findings = []
        # Your detection logic
        return findings
```

Register in `pyproject.toml`:

```toml
[project.entry-points."miesc.detectors"]
my-detector = "my_package:MyDetector"
```

See [docs/CUSTOM_DETECTORS.md](./docs/CUSTOM_DETECTORS.md) for full API documentation.

### Plugin System

Install, manage, and create detector plugins from PyPI:

```bash
# List installed plugins
miesc plugins list

# Install a plugin from PyPI
miesc plugins install miesc-defi-detectors

# Create a new plugin project
miesc plugins create my-detector -d "My custom detector"

# Enable/disable plugins
miesc plugins disable miesc-some-plugin
miesc plugins enable miesc-some-plugin

# Show plugin details
miesc plugins info miesc-defi-detectors
```

**Create your own plugin package:**

```bash
# Generate plugin scaffold
miesc plugins create flash-loan-detector -o ./my-plugins

# Structure created:
# miesc-flash_loan_detector/
#   pyproject.toml          # With entry points configured
#   flash_loan_detector/
#     detectors.py          # Your detector class
#   tests/
#     test_flash_loan_detector.py

# Install in development mode
cd miesc-flash_loan_detector
pip install -e .

# Verify it's registered
miesc plugins list
miesc detectors list
```

Plugins are discovered automatically via `miesc.detectors` entry points.

### Pre-commit Hook

Integrate MIESC into your git workflow:

```bash
pip install pre-commit
```

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/fboiero/MIESC
    rev: v4.3.7
    hooks:
      - id: miesc-quick
        args: ['--ci']  # Fail on critical/high issues
```

```bash
pre-commit install
git commit -m "..."  # MIESC runs automatically
```

See [examples/pre-commit-config.yaml](./examples/pre-commit-config.yaml) for more options.

### Foundry Integration

Add MIESC to your Foundry project:

```toml
# foundry.toml
[profile.default]
post_build_hook = "miesc audit quick ./src --ci"

[profile.ci]
post_build_hook = "miesc audit quick ./src --ci --fail-on high"
```

```bash
forge build  # MIESC runs automatically after build
```

See [integrations/foundry/](./integrations/foundry/) for hook scripts and GitHub Actions.

### Hardhat Integration

Add MIESC to your Hardhat project:

```javascript
// hardhat.config.js
require("hardhat-miesc");

module.exports = {
  solidity: "0.8.20",
  miesc: {
    enabled: true,
    runOnCompile: true,  // Auto-scan after compile
    failOn: "high",
  },
};
```

```bash
npx hardhat miesc           # Run security audit
npx hardhat miesc:full      # Full 9-layer audit
npx hardhat miesc:doctor    # Check installation
```

See [integrations/hardhat/](./integrations/hardhat/) for full plugin documentation.

### Web Interface

```bash
make webapp  # or: streamlit run webapp/app.py
# Open http://localhost:8501
```

### Python API

```python
from miesc.api import run_tool, run_full_audit

results = run_tool("slither", "contract.sol")
report = run_full_audit("contract.sol")
```

### Multi-Chain Analysis (Alpha)

Analyze smart contracts on non-EVM chains:

```bash
# Solana/Anchor programs
miesc scan program.rs --chain solana

# NEAR Protocol
miesc scan contract.rs --chain near

# Move (Sui/Aptos)
miesc scan module.move --chain sui

# Stellar/Soroban
miesc scan contract.rs --chain stellar

# Algorand (TEAL/PyTeal)
miesc scan approval.teal --chain algorand

# Cardano (Plutus/Aiken)
miesc scan validator.hs --chain cardano
```

> **Important:** Non-EVM chain support is **alpha/experimental**. These analyzers use pattern-based detection without the full 9-layer analysis available for EVM. See [Multi-Chain Documentation](./docs/MULTICHAIN.md) for details.

### MCP Server (MCP client Integration)

MIESC includes an MCP (Model Context Protocol) server for real-time integration with AI agents like MCP client:

```bash
# Start the MCP WebSocket server
miesc server mcp

# Custom host/port
miesc server mcp --host 0.0.0.0 --port 9000
```

**MCP client Configuration** (`~/.config/mcp/config.json`):
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

Features:
- Real-time audit progress streaming
- Finding notifications as they're discovered
- Multi-session support for concurrent audits
- Compatible with any MCP-compliant client

## Architecture

```
Layer 1: Static Analysis      (Slither, Aderyn, Solhint)
Layer 2: Dynamic Testing      (Echidna, Medusa, Foundry, DogeFuzz)
Layer 3: Symbolic Execution   (Mythril, Manticore, Halmos)
Layer 4: Formal Verification  (Certora, SMTChecker)
Layer 5: Property Testing     (PropertyGPT, Wake, Vertigo)
Layer 6: AI/LLM Analysis      (SmartLLM, GPTScan, LLMSmartAudit, SmartBugs-ML)
Layer 7: Pattern Recognition  (DA-GNN, SmartGuard, Clone Detector)
Layer 8: DeFi Security        (DeFi Analyzer, MEV Detector, Gas Analyzer)
Layer 9: Advanced Detection   (Advanced Detector, SmartBugs, Threat Model)
```

**31/31 tools operational** - See `miesc doctor` for availability status.

## Requirements

- Python 3.12+
- [Slither](https://github.com/crytic/slither): `pip install slither-analyzer`
- [Mythril](https://github.com/ConsenSys/mythril): `pip install mythril` (optional)
- [Ollama](https://ollama.ai): For AI correlation (optional)

See [docs/INSTALLATION.md](./docs/INSTALLATION.md) for complete setup.

## Documentation

- [Installation Guide](https://fboiero.github.io/MIESC/docs/02_SETUP_AND_USAGE/)
- [Architecture](https://fboiero.github.io/MIESC/docs/01_ARCHITECTURE/)
- [API Reference](https://fboiero.github.io/MIESC/docs/API_SETUP/)
- [Tool Reference](./docs/TOOLS.md)
- [Report Generation Guide](./docs/guides/REPORTS.md)
- [Testing Guide](./docs/guides/TESTING.md)
- [Contributing](./CONTRIBUTING.md)

## Contributing

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC && pip install -e .[dev]
pytest tests/
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## Support

Need help? Here's how to get support:

| Resource | Description |
|----------|-------------|
| [GitHub Issues](https://github.com/fboiero/MIESC/issues) | Bug reports and feature requests |
| [Documentation](https://fboiero.github.io/MIESC) | Full documentation and guides |
| [Quick Start](./docs/guides/QUICKSTART.md) | Get started in 5 minutes |
| [Security Issues](./docs/policies/SECURITY.md) | Report security vulnerabilities |

**Common Issues:**

<details>
<summary><strong>Tool not found / not installed</strong></summary>

```bash
# Check which tools are available
miesc doctor

# Most tools are optional - MIESC works with whatever is installed
# Install specific tools as needed:
pip install slither-analyzer  # Static analysis
pip install mythril           # Symbolic execution
```

</details>

<details>
<summary><strong>Docker memory errors with LLM</strong></summary>

LLM models require significant RAM. Configure Docker Desktop:
- Settings → Resources → Memory → 8GB (minimum)
- The `mistral:latest` model needs ~4.5GB RAM

</details>

<details>
<summary><strong>Ollama connection refused</strong></summary>

```bash
# Make sure Ollama is running
ollama serve

# For Docker, set the correct host:
# macOS/Windows: OLLAMA_HOST=http://host.docker.internal:11434
# Linux: use --network host
```

</details>

## License

AGPL-3.0 - See [LICENSE](./LICENSE)

## Author

Fernando Boiero - Master's thesis in Cyberdefense, UNDEF-IUA Argentina

## Acknowledgments

Built on: [Slither](https://github.com/crytic/slither), [Mythril](https://github.com/ConsenSys/mythril), [Echidna](https://github.com/crytic/echidna), [Foundry](https://github.com/foundry-rs/foundry), [Certora](https://www.certora.com/), and the Ethereum security community.
