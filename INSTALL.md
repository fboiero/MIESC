# Installation Guide

MIESC requires Python 3.12+ and external security analysis tools.

## Quick Start

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC
pip install -r requirements.txt
```

## Tool Installation

Install security analysis tools based on your needs:

### Core Tools (recommended)

```bash
# Static analysis
pip install slither-analyzer

# Symbolic execution
pip install mythril

# Verify installation
python scripts/verify_installation.py
```

### Complete Installation

```bash
# Use automated installer for all 17 tools
python install_tools.py

# Select tools interactively or install all
```

## Tool-by-Tool

**Layer 1 - Static Analysis**:
```bash
pip install slither-analyzer        # Slither
cargo install aderyn                 # Aderyn (requires Rust)
npm install -g solhint               # Solhint
```

**Layer 2 - Dynamic Testing**:
```bash
brew install echidna                 # Echidna (macOS)
go install github.com/crytic/medusa@latest  # Medusa
curl -L https://foundry.paradigm.xyz | bash && foundryup  # Foundry
```

**Layer 3 - Symbolic Execution**:
```bash
pip install mythril                  # Mythril
pip install manticore[native]        # Manticore
pip install halmos                   # Halmos
```

**Layer 4 - Formal Verification**:
```bash
pip install certora-cli              # Certora (requires API key)
# SMTChecker: included in solc >= 0.8.0
pip install eth-wake                 # Wake
```

**Layer 5 - AI Analysis**:
```bash
# SmartLLM - local LLM via Ollama
brew install ollama                  # macOS
ollama pull deepseek-coder

# GPTScan (optional, requires OpenAI API key)
pip install gptscan
export OPENAI_API_KEY=your_key_here
```

## System Requirements

- Python: 3.12+
- Node.js: 14+ (for Solhint)
- Rust: 1.70+ (for Aderyn)
- Go: 1.19+ (for Medusa)
- Memory: 4GB minimum, 8GB recommended
- Disk: 2GB for tools + datasets

## Platform-Specific

**macOS**:
```bash
brew install python node rust go
```

**Ubuntu/Debian**:
```bash
apt-get update
apt-get install python3 python3-pip nodejs npm rustc cargo golang-go
```

**Docker** (alternative):
```bash
docker build -t miesc .
docker run -v $(pwd)/contracts:/contracts miesc analyze /contracts/MyToken.sol
```

See [docs/DOCKER_DEPLOYMENT.md](./docs/DOCKER_DEPLOYMENT.md)

## Verification

```bash
# Check which tools are available
python scripts/verify_installation.py

# Run test suite
pytest tests/

# Quick benchmark
python scripts/run_benchmark.py
```

## Troubleshooting

**Slither fails to install**:
```bash
pip install slither-analyzer --no-cache-dir
```

**Mythril z3-solver errors**:
```bash
pip install z3-solver==4.12.2.0
```

**Ollama not found**:
```bash
# macOS
brew install ollama
# Linux
curl -fsSL https://ollama.com/install.sh | sh
```

**Permission errors**:
```bash
# Use virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows
```

## Minimal Installation

If you only need static analysis:

```bash
pip install slither-analyzer
python xaudit.py --target contract.sol --layers static
```

Framework gracefully degrades when tools are unavailable (DPGA compliance).

## Next Steps

- Read [README.md](./README.md) for usage examples
- See [docs/03_DEMO_GUIDE.md](./docs/03_DEMO_GUIDE.md) for demo walkthrough
- Check [CONTRIBUTING.md](./CONTRIBUTING.md) for development setup

## Support

- Issues: https://github.com/fboiero/MIESC/issues
- Email: fboiero@frvm.utn.edu.ar
