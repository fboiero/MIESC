# MIESC

Multi-layer security analysis framework for Ethereum smart contracts.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-4.2.2-green)](https://github.com/fboiero/MIESC/releases)

MIESC orchestrates 32 security tools across 9 defense layers with AI-assisted correlation and ML-based detection. Pre-audit triage tool for smart contract security.

**[Documentation](https://fboiero.github.io/MIESC)** | **[Demo Video](https://youtu.be/pLa_McNBRRw)**

## Installation

```bash
pip install -e .
```

**Docker:**
```bash
docker pull ghcr.io/fboiero/miesc:latest
docker run --rm -v $(pwd):/contracts miesc:latest audit quick /contracts/MyContract.sol
```

## Quick Start

```bash
# Quick scan (~30s)
miesc audit quick contract.sol

# Full 9-layer audit
miesc audit full contract.sol

# Check tool availability
miesc doctor
```

## Features

- **9 defense layers**: Static, Dynamic, Symbolic, Formal, AI, ML, Threat Modeling, Cross-Chain, AI Ensemble
- **32 integrated tools**: Slither, Mythril, Echidna, Certora, Halmos, and more
- **AI correlation**: Local LLM (Ollama) reduces false positives
- **Compliance mapping**: ISO 27001, NIST, OWASP, SWC
- **Multiple interfaces**: CLI, REST API, WebSocket, MCP, Web UI

## Usage

### CLI

```bash
miesc audit quick contract.sol       # Fast 4-tool scan
miesc audit full contract.sol        # Complete 9-layer audit
miesc audit layer 3 contract.sol     # Run specific layer
miesc server rest --port 5001        # Start REST API
```

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

## Architecture

```
Layer 1: Static Analysis      (Slither, Aderyn, Solhint)
Layer 2: Dynamic Testing      (Echidna, Medusa, Foundry)
Layer 3: Symbolic Execution   (Mythril, Manticore, Halmos)
Layer 4: Formal Verification  (Certora, SMTChecker, Wake)
Layer 5: AI Analysis          (SmartLLM, GPTScan)
Layer 6: ML Detection         (DA-GNN, Graph Neural Networks)
Layer 7: Threat Modeling      (Risk scoring, attack surface)
Layer 8: Cross-Chain & ZK     (Bridge security, ZK circuits)
Layer 9: AI Ensemble          (Multi-LLM consensus detection)
```

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
