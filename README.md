# MIESC - Multi-layer Intelligent Evaluation for Smart Contracts

Multi-layer security analysis framework for Ethereum smart contracts.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/miesc)](https://pypi.org/project/miesc/)
[![Version](https://img.shields.io/badge/version-4.3.4-green)](https://github.com/fboiero/MIESC/releases)
[![Security Audit](https://github.com/fboiero/MIESC/actions/workflows/miesc-security.yml/badge.svg)](https://github.com/fboiero/MIESC/actions/workflows/miesc-security.yml)
[![Coverage](https://img.shields.io/badge/coverage-80.8%25-green)](./htmlcov/index.html)
[![Tools](https://img.shields.io/badge/tools-31%2F31%20operational-brightgreen)](./docs/TOOLS.md)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit)

[English](./README.md) | [Espa&ntilde;ol](./README_ES.md)

MIESC orchestrates **31 security tools** across **9 defense layers** with AI-assisted correlation and ML-based detection. Pre-audit triage tool for smart contract security.

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

# With web UI and API servers
pip install miesc[web]

# With all optional features
pip install miesc[full]

# From source (development)
git clone https://github.com/fboiero/MIESC.git
cd MIESC && pip install -e .[dev]
```

**Docker:**

```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/fboiero/miesc:latest
docker run --rm -v $(pwd):/contracts ghcr.io/fboiero/miesc:latest scan /contracts/MyContract.sol

# Or build locally
docker build -t miesc:latest .
docker run --rm -v $(pwd):/contracts miesc:latest scan /contracts/MyContract.sol
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

# Verify version (should show 4.3.4+)
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

**[Complete Quick Start Guide](./QUICKSTART.md)** - Detailed installation and usage instructions.

## Features

- **9 defense layers**: Static, Dynamic, Symbolic, Formal, AI, ML, Threat Modeling, Cross-Chain, AI Ensemble
- **31 operational tools**: Slither, Aderyn, Mythril, Echidna, Foundry, Certora, Halmos, SmartLLM, and more
- **AI correlation**: Local LLM (Ollama) reduces false positives
- **Compliance mapping**: ISO 27001, NIST, OWASP, SWC
- **Multiple interfaces**: CLI, REST API, WebSocket, MCP, Web UI

## Usage

### CLI

```bash
miesc scan contract.sol              # Quick vulnerability scan
miesc scan contract.sol --ci         # CI mode (exit 1 on issues)
miesc audit quick contract.sol       # Fast 4-tool scan
miesc audit full contract.sol        # Complete 9-layer audit
miesc audit layer 3 contract.sol     # Run specific layer
miesc report results.json -t professional  # Generate audit report
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
    rev: v4.3.4
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
- [Contributing](./CONTRIBUTING.md)

## Contributing

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC && pip install -e .[dev]
pytest tests/
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## License

AGPL-3.0 - See [LICENSE](./LICENSE)

## Author

Fernando Boiero - Master's thesis in Cyberdefense, UNDEF-IUA Argentina

## Acknowledgments

Built on: [Slither](https://github.com/crytic/slither), [Mythril](https://github.com/ConsenSys/mythril), [Echidna](https://github.com/crytic/echidna), [Foundry](https://github.com/foundry-rs/foundry), [Certora](https://www.certora.com/), and the Ethereum security community.
