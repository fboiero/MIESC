# Installation Guide

## Quick Install

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC
pip install -e .
```

## Requirements

- Python 3.12+
- pip or pipx

## Tool Dependencies

### Required (minimum functionality)

```bash
pip install slither-analyzer
```

### Recommended

```bash
# Static analysis
pip install slither-analyzer
cargo install aderyn
npm install -g solhint

# Solidity compiler
pip install solc-select
solc-select install 0.8.20
solc-select use 0.8.20
```

### Full Suite

```bash
# Symbolic execution
pip install mythril

# Fuzzers (binary install)
# Echidna: https://github.com/crytic/echidna/releases
# Medusa: https://github.com/crytic/medusa/releases

# Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Formal verification
pip install halmos eth-wake

# AI features (local LLM)
# Install Ollama: https://ollama.ai
ollama pull deepseek-coder
ollama pull codellama
```

## Docker Installation

Recommended for complete environment with all tools.

### ARM64 (Apple Silicon, native)

```bash
docker build -t miesc:v4.2.2 .
docker run --rm -v $(pwd):/contracts miesc:v4.2.2 audit quick /contracts/MyContract.sol
```

### x86_64 (Intel/AMD, or emulated on ARM)

```bash
docker build --platform linux/amd64 -f Dockerfile.x86 -t miesc:v4.2.2-x86 .
docker run --platform linux/amd64 --rm miesc:v4.2.2-x86
```

Note: x86_64 build includes Manticore (requires Python 3.10 and pysha3).

## Verify Installation

```bash
miesc doctor
```

Expected output:
```
MIESC v4.2.2 - Tool Availability Check

[OK] slither (0.10.x)
[OK] solc (0.8.20)
[OK] aderyn (0.6.x)
[--] mythril (not installed)
[--] echidna (not installed)
...
```

## Development Install

```bash
pip install -e .[dev]
pytest tests/
```

## Troubleshooting

### Mythril installation fails

Mythril requires z3-solver. On some systems:

```bash
pip install z3-solver
pip install mythril
```

### Manticore on ARM (Apple Silicon)

Manticore requires x86_64. Use Docker with emulation:

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

# Pull required models
ollama pull deepseek-coder
```
