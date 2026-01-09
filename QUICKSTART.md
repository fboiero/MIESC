# MIESC - Quick Start Guide

Quick guide for installing and using MIESC from the command line.

## Requirements

- Python 3.12+
- Git

## 1. Installation

```bash
# Clone the repository
git clone https://github.com/fboiero/MIESC.git
cd MIESC

# Install (choose one option)
pip install -e .              # Minimal installation (CLI only)
pip install -e .[cli]         # With enhanced output (Rich)
pip install -e .[full]        # All features
```

## 2. Verify Installation

```bash
# Check version
miesc --version

# Check available tools (shows 31 tools across 9 layers)
miesc doctor
```

## 3. Audit Commands

### Quick Scan (4 tools, ~30 seconds)

```bash
# Quick scan of a contract
miesc scan MyContract.sol

# Scan with JSON report
miesc scan MyContract.sol -o report.json

# CI/CD mode (exit code 1 if critical/high issues found)
miesc scan MyContract.sol --ci
```

### Quick Audit (4 tools)

```bash
miesc audit quick MyContract.sol
miesc audit quick MyContract.sol -o report.json
```

### Full Audit - 9 Layers, 31 Tools

```bash
# Complete security audit with all 9 defense layers
miesc audit full MyContract.sol -o full_audit.json

# Run specific layers only
miesc audit full MyContract.sol --layers 1,2,3
```

### Batch Audit (Multiple Contracts)

```bash
# Audit all contracts in a folder
miesc audit batch ./contracts/ -o batch_report.json

# Recursive scan of subfolders
miesc audit batch ./contracts/ -r -o report.json

# With parallel workers for speed
miesc audit batch ./contracts/ -j 4 -o report.json
```

## 4. The 9 Defense Layers

MIESC analyzes contracts through **9 specialized defense layers**:

| Layer | Name | Tools | Description |
|-------|------|-------|-------------|
| 1 | Static Analysis | Slither, Aderyn, Solhint | Code patterns, vulnerabilities |
| 2 | Dynamic Testing | Echidna, Medusa, Foundry, DogeFuzz | Fuzzing, property testing |
| 3 | Symbolic Execution | Mythril, Manticore, Halmos | Path exploration, SMT solving |
| 4 | Formal Verification | Certora, SMTChecker | Mathematical proofs |
| 5 | Property Testing | PropertyGPT, Wake, Vertigo | Invariant generation |
| 6 | AI/LLM Analysis | SmartLLM, GPTScan, LLMSmartAudit | AI-powered detection |
| 7 | Pattern Recognition | DA-GNN, SmartGuard, Clone Detector | ML-based patterns |
| 8 | DeFi Security | DeFi Analyzer, MEV Detector, Gas Analyzer | Protocol-specific |
| 9 | Advanced Detection | Advanced Detector, Threat Model | Cross-layer correlation |

### Run Specific Layers

```bash
# Static analysis only (Layer 1)
miesc audit full contract.sol --layers 1

# Static + Symbolic (Layers 1 and 3)
miesc audit full contract.sol --layers 1,3

# All layers (default)
miesc audit full contract.sol --layers 1,2,3,4,5,6,7,8,9
```

## 5. Output Formats

```bash
# JSON (default)
miesc scan contract.sol -o report.json

# SARIF (for GitHub/IDE integration)
miesc audit quick contract.sol -f sarif -o report.sarif

# Markdown
miesc audit quick contract.sol -f markdown -o report.md
```

## 6. CI/CD Integration

```bash
# Exit with code 1 if critical or high severity issues found
miesc scan contract.sol --ci

# For batch audits
miesc audit batch ./contracts/ --fail-on critical,high
```

## 7. Complete Example

```bash
# 1. Navigate to project
cd my_project

# 2. Quick scan of main contract
miesc scan contracts/Token.sol

# 3. Full audit with all 9 layers
miesc audit full contracts/Token.sol -o audit_report.json

# 4. Batch audit entire project
miesc audit batch contracts/ -r -o full_project_audit.json
```

## 8. Useful Options

```bash
# General help
miesc --help

# Command-specific help
miesc scan --help
miesc audit --help
miesc audit full --help
miesc audit batch --help

# Run as Python module
python -m miesc scan MyContract.sol
python -m miesc audit full MyContract.sol
```

## 9. Troubleshooting

```bash
# Check installed tools and their status
miesc doctor

# Run with debug output
MIESC_DEBUG=1 miesc scan contract.sol

# Check Python version (must be 3.12+)
python --version

# List all available tools
miesc tools list
```

## Documentation

- Full documentation: https://fboiero.github.io/MIESC
- GitHub: https://github.com/fboiero/MIESC
- Demo video: https://youtu.be/pLa_McNBRRw
