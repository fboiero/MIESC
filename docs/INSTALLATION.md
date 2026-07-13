# MIESC v6.0.0 - Complete Installation Guide

**[Versión en Español](INSTALLATION_ES.md)**

This guide covers the complete installation of MIESC from scratch, including all dependencies and tools.

## Table of Contents

- [Quick Install](#quick-install)
- [System Requirements](#system-requirements)
- [Step-by-Step Installation](#step-by-step-installation)
- [Tool Installation by Layer](#tool-installation-by-layer)
- [Docker Installation](#docker-installation)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

---

## Quick Install

For users who want to get started quickly with basic functionality:

```bash
# Clone repository
git clone https://github.com/fboiero/MIESC.git
cd MIESC

# Install MIESC and core dependencies
pip install -e .

# Install Slither (required for basic analysis)
pip install slither-analyzer

# Verify installation
python scripts/verify_installation.py
```

---

## System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| OS | macOS 12+, Ubuntu 20.04+, Windows 10+ (WSL2) |
| Python | 3.12 or higher |
| Memory | 8 GB RAM |
| Disk | 5 GB free space |

### Recommended Requirements

| Component | Requirement |
|-----------|-------------|
| OS | macOS 14+, Ubuntu 22.04+ |
| Python | 3.12+ |
| Memory | 16 GB RAM |
| Disk | 20 GB free space (for all tools) |
| Node.js | 18+ (for Solhint) |
| Rust | 1.70+ (for Aderyn, Foundry) |
| Go | 1.21+ (for Medusa) |

---

## Step-by-Step Installation

### Step 1: Clone Repository

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC
```

### Step 2: Create Virtual Environment (Recommended)

```bash
python3.12 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or: .venv\Scripts\activate  # Windows
```

### Step 3: Install MIESC

```bash
# Basic installation
pip install -e .

# Full installation (all optional dependencies)
pip install -e .[full]

# Development installation
pip install -e .[dev]
```

### Step 4: Install Solidity Compiler

```bash
pip install solc-select
solc-select install 0.8.20
solc-select use 0.8.20

# Verify
solc --version
```

### Step 5: Install Core Analysis Tools

```bash
# Static Analysis (Layer 1)
pip install slither-analyzer

# Verify
slither --version
```

---

## Tool Installation by Layer

MIESC integrates 50 tools across 35 analysis modules, organized in 9 defense layers. Install tools based on your needs.

### Layer 1: Static Analysis (3 tools)

| Tool | Installation | Required |
|------|--------------|----------|
| Slither | `pip install slither-analyzer` | Yes |
| Aderyn | `cargo install aderyn` | Recommended |
| Solhint | `npm install -g solhint` | Recommended |

```bash
# Install all Layer 1 tools
pip install slither-analyzer
cargo install aderyn
npm install -g solhint
```

### Layer 2: Dynamic Testing (4 tools)

| Tool | Installation | Notes |
|------|--------------|-------|
| Echidna | Binary from releases | Property-based fuzzer |
| Medusa | Binary from releases | Coverage-guided fuzzer |
| Foundry | `curl -L foundry.paradigm.xyz \| bash && foundryup` | Complete toolkit |
| DogeFuzz | Built-in | No external install |

```bash
# Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Echidna (macOS)
brew install echidna

# Echidna (Linux) - download from GitHub releases
wget https://github.com/crytic/echidna/releases/latest/download/echidna-linux-x86_64.tar.gz
tar -xzf echidna-linux-x86_64.tar.gz
sudo mv echidna /usr/local/bin/

# Medusa - download from GitHub releases
# https://github.com/crytic/medusa/releases
```

### Layer 3: Symbolic Execution (3 tools)

| Tool | Installation | Notes |
|------|--------------|-------|
| Mythril | `pip install mythril` | May conflict with slither |
| Manticore | `pip install manticore[native]` | Python 3.10 only |
| Halmos | `pip install halmos` | Foundry integration |

```bash
# Mythril (install in separate venv if conflicts)
pip install mythril

# Halmos
pip install halmos

# Manticore (requires Python 3.10)
# Best installed in Docker or separate environment
```

### Layer 4: Formal Verification (3 tools)

| Tool | Installation | Notes |
|------|--------------|-------|
| Certora | [certora.com](https://docs.certora.com) | Commercial, free tier |
| SMTChecker | Included with solc | Built-in |
| Wake | `pip install eth-wake` | Python framework |

```bash
pip install eth-wake
```

### Layer 5: AI Analysis (6 tools)

| Tool | Installation | Notes |
|------|--------------|-------|
| SmartLLM | Built-in + Ollama | Local LLM analysis |
| GPTScan | Built-in | Requires OpenAI API key |
| LLMSmartAudit | Built-in | Multi-agent LLM |
| GPTLens | Built-in | LLM auditor/critic |
| LlamaAudit | Built-in + Ollama | Llama-based analysis |
| iAudit | Built-in | Fine-tuned LLM auditor |

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull required models
ollama pull deepseek-coder:6.7b
ollama pull codellama
```

### Layer 6: ML Detection (5 tools)

| Tool | Installation | Notes |
|------|--------------|-------|
| DA-GNN | Built-in | Graph neural network |
| SmartBugs-ML | Built-in | ML classifier |
| SmartBugs-Detector | Built-in | SWC-category detection |
| SmartGuard | Built-in | Pattern matching |
| Peculiar | Built-in | Crucial data-flow ML |

All built-in, no external installation required.

### Layer 7: Specialized Analysis (7 tools)

| Tool | Installation | Notes |
|------|--------------|-------|
| Threat Model | Built-in | Threat modeling |
| Gas Analyzer | Built-in | Gas optimization |
| MEV Detector | Built-in | MEV exposure |
| Clone Detector | Built-in | Contract clone detection |
| DeFi | Built-in | Flash loan, oracle |
| Advanced Detector | Built-in | Rug pull, honeypot |
| Upgradability Checker | Built-in | Proxy/upgradability risks |

All built-in, no external installation required.

> Layers 8–9 (Cross-Chain & ZK Security, Advanced AI Ensemble) are experimental modules on the multi-chain roadmap; the EVM core is Layers 1–7.

### Layer 8: Cross-Chain & ZK Security (5 tools)

| Tool | Installation | Notes |
|------|--------------|-------|
| Cross-Chain | Built-in | Cross-chain risks |
| ZK Circuit | `cargo install circomspect` | ZK circuit analysis |
| Bridge Monitor | Built-in | Bridge security |
| L2 Validator | Built-in | L2-specific checks |
| Circom Analyzer | `npm install -g circom snarkjs` | Circom/Noir analysis |

```bash
# For ZK circuit analysis
cargo install circomspect
npm install -g circom snarkjs
```

### Layer 9: Advanced AI Ensemble (5 tools)

| Tool | Installation | Notes |
|------|--------------|-------|
| LLMBugScanner | Built-in + Ollama | deepseek-coder model |
| Audit Consensus | Built-in | Multi-LLM consensus |
| Exploit Synthesizer | Built-in | PoC exploit synthesis |
| Vuln Verifier | Built-in | Finding verification |
| Remediation Validator | Built-in | Fix validation |

---

## Docker Installation

For a complete, isolated environment with all tools pre-installed:

### ARM64 (Apple Silicon)

```bash
docker build -t miesc:6.0.0 .
docker run --rm -v $(pwd):/contracts miesc:6.0.0 audit quick /contracts/MyContract.sol
```

### x86_64 (Intel/AMD)

```bash
docker build --platform linux/amd64 -f Dockerfile.x86 -t miesc:6.0.0-x86 .
docker run --platform linux/amd64 --rm -v $(pwd):/contracts miesc:6.0.0-x86 audit quick /contracts/MyContract.sol
```

### Pre-built Image

```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/fboiero/miesc:latest    # Standard (multi-arch, ~2-3GB)
docker pull ghcr.io/fboiero/miesc:full      # Full - amd64 only (~8GB)

# Run audit
docker run --rm -v $(pwd):/contracts ghcr.io/fboiero/miesc:latest audit quick /contracts/MyContract.sol

# Or build locally (use the build script for ARM compatibility)
./scripts/build-images.sh standard
./scripts/build-images.sh full              # On ARM: prompts for native build
docker run --rm -v $(pwd):/contracts miesc:latest audit quick /contracts/MyContract.sol
```

---

## Verification

After installation, verify everything is working:

```bash
# Run verification script
python scripts/verify_installation.py

# Or use the CLI
miesc doctor
```

Expected output:

```
MIESC 6.0.0 - Installation Verification
============================================================

1. Python Environment
----------------------------------------
  [OK] Python 3.12.x

2. Core Python Dependencies
----------------------------------------
  [OK] slither-analyzer (0.10.x)
  [OK] django (5.x)
  [OK] djangorestframework (3.14.x)
  ...

5. MIESC Adapter Registration
----------------------------------------
  [OK] All 50/50 adapters registered
  [OK] run `miesc doctor` to see available tools

Installation Summary
============================================================
MIESC is ready to use!
```

---

## Troubleshooting

### Mythril installation fails

Mythril may conflict with slither-analyzer due to z3-solver version requirements.

**Solution**: Install Mythril in a separate virtual environment or use Docker:

```bash
# Option 1: Separate venv
python3 -m venv mythril-env
source mythril-env/bin/activate
pip install mythril

# Option 2: Docker
docker run -it mythril/myth analyze /path/to/contract.sol
```

### Manticore on ARM (Apple Silicon)

Manticore requires x86_64 architecture and Python 3.10.

**Solution**: Use Docker with emulation:

```bash
docker build --platform linux/amd64 -f Dockerfile.x86 -t miesc:x86 .
```

### solc version issues

```bash
solc-select install 0.8.20
solc-select use 0.8.20
```

### Ollama not responding

```bash
# Start Ollama service
ollama serve &

# Check status
ollama list

# Pull required models
ollama pull deepseek-coder:6.7b
```

### Missing Rust/Cargo

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### Missing Node.js/npm

```bash
# macOS
brew install node

# Ubuntu
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

### Permission denied errors

```bash
# Fix pip permissions
pip install --user -e .

# Or use virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## Next Steps

After installation:

1. **Quick Start**: `miesc audit quick contract.sol`
2. **Full Audit**: `miesc audit full contract.sol`
3. **Local REST API**: `python -m miesc.api.rest --host 127.0.0.1 --port 8000`
4. **Static Reports**: `python -m src.utils.web_dashboard --results analysis/results --output analysis/dashboard`
5. **Documentation**: [fboiero.github.io/MIESC](https://fboiero.github.io/MIESC)

---

## Support

- **Issues**: [github.com/fboiero/MIESC/issues](https://github.com/fboiero/MIESC/issues)
- **Email**: fboiero@frvm.utn.edu.ar
- **Documentation**: [fboiero.github.io/MIESC](https://fboiero.github.io/MIESC)

---

**Version**: 6.0.0 | **Last Updated**: June 2026
