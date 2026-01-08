# MIESC v4.3.0 Release Notes

**Release Date:** January 8, 2026
**Tag:** [v4.3.0](https://github.com/fboiero/MIESC/releases/tag/v4.3.0)

---

## Overview

MIESC v4.3.0 completes the tool integration with all **31 security analysis tools** fully operational across **9 defense layers**. This release focuses on installation reliability, comprehensive documentation, and adapter fixes.

---

## Highlights

- **31/31 Tools Operational**: All security analysis tools now properly registered and available
- **Complete Installation Guide**: Step-by-step documentation for all dependencies
- **Installation Verification Script**: Automated validation of MIESC setup
- **Adapter Fixes**: Corrected metadata for DeFi, Advanced, and SmartBugs detectors
- **Test Coverage**: 1833 tests passing with 80.4% code coverage

---

## New Features

### Installation Verification Script

New script to validate MIESC installation:

```bash
python scripts/verify_installation.py
```

Checks:
- Python version (3.12+)
- Core Python dependencies
- External tools (Slither, Aderyn, Mythril, etc.)
- Ollama and LLM models
- All 31 adapter registrations

### Comprehensive Installation Guide

Updated `docs/INSTALLATION.md` with:
- System requirements (minimum and recommended)
- Step-by-step installation instructions
- Tool installation by layer (9 layers)
- Docker installation options
- Troubleshooting guide

---

## Tool Organization (31 Tools in 9 Layers)

| Layer | Category | Tools |
|-------|----------|-------|
| 1 | Static Analysis | Slither, Aderyn, Solhint |
| 2 | Dynamic Testing | Echidna, Medusa, Foundry, DogeFuzz |
| 3 | Symbolic Execution | Mythril, Manticore, Halmos |
| 4 | Formal Verification | Certora, SMTChecker, Wake |
| 5 | Property Testing | PropertyGPT, Vertigo |
| 6 | AI/LLM Analysis | SmartLLM, GPTScan, LLMSmartAudit, LLMBugScanner |
| 7 | Pattern Recognition | DA-GNN, SmartGuard, SmartBugs-ML, ContractCloneDetector |
| 8 | DeFi Security | DeFi Analyzer, MEV Detector, Gas Analyzer, CrossChain |
| 9 | Advanced Detection | Advanced Detector, SmartBugs Detector, Threat Model, ZK Circuit |

---

## Bug Fixes

### Adapter Registration

- **Fixed**: `DeFiAdapter` now uses proper `ToolMetadata` with `ToolCategory.MEV_DETECTION`
- **Fixed**: `AdvancedDetectorAdapter` now uses `ToolCategory.STATIC_ANALYSIS`
- **Fixed**: `SmartBugsDetectorAdapter` now uses `ToolCategory.STATIC_ANALYSIS`
- **Fixed**: All adapters now use `ToolCapability` dataclass instances instead of enum references

### Removed Deprecated Tools

- **Removed**: Oyente adapter (deprecated, requires Python 2.7)
- **Updated**: Test suite to reflect 31 tools (was 32)

---

## Breaking Changes

None. This release is fully backward compatible with v4.2.x.

---

## Installation

### Quick Install

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC
pip install -e .
pip install slither-analyzer
python scripts/verify_installation.py
```

### Full Install (All Tools)

```bash
# Core
pip install -e .[full]
pip install slither-analyzer

# Static Analysis
cargo install aderyn
npm install -g solhint

# Dynamic Testing
curl -L https://foundry.paradigm.xyz | bash && foundryup
brew install echidna  # macOS

# Symbolic
pip install mythril halmos

# AI Features
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull deepseek-coder:6.7b
ollama pull codellama
```

### Docker

```bash
docker build -t miesc:v4.3.0 .
docker run --rm -v $(pwd):/contracts miesc:v4.3.0 audit quick /contracts/MyContract.sol
```

---

## Usage

```bash
# Quick scan (static analysis only)
miesc audit quick contract.sol

# Full 9-layer audit
miesc audit full contract.sol

# Check tool availability
miesc doctor

# Verify installation
python scripts/verify_installation.py
```

---

## Test Results

```
========== 1833 passed, 53 skipped in 404.11s ==========
Total coverage: 80.40%
```

### Validation Results (SmartBugs-curated dataset)

- **Precision**: 100% (0 false positives)
- **Recall**: 70% (35/50 vulnerabilities detected)
- **F1-Score**: 82.35%

---

## Files Changed

| File | Changes |
|------|---------|
| `src/adapters/__init__.py` | Reorganized 31 adapters in 9 layers |
| `src/adapters/defi_adapter.py` | Fixed ToolMetadata |
| `src/adapters/advanced_detector_adapter.py` | Fixed ToolMetadata |
| `src/adapters/smartbugs_detector_adapter.py` | Fixed ToolMetadata |
| `docs/INSTALLATION.md` | Complete rewrite with layer-by-layer guide |
| `scripts/verify_installation.py` | New installation verification script |
| `pyproject.toml` | Version bump to 4.3.0 |
| `README.md` | Updated version badge |
| `README_ES.md` | Updated version badge |

---

## Upgrade from v4.2.x

```bash
cd MIESC
git pull origin main
pip install -e .
python scripts/verify_installation.py
```

No database migrations or configuration changes required.

---

## Known Issues

1. **Manticore**: Requires Python 3.10 and has protobuf compatibility issues on some systems. Use Docker for Manticore analysis.

2. **Mythril**: May conflict with slither-analyzer due to z3-solver version requirements. Install in separate virtual environment if needed.

3. **Aderyn**: Version 0.1.9 may exit with code 101 even on successful analysis (version parsing bug).

---

## Contributors

- Fernando Boiero ([@fboiero](https://github.com/fboiero))

---

## Links

- **Documentation**: [fboiero.github.io/MIESC](https://fboiero.github.io/MIESC)
- **Repository**: [github.com/fboiero/MIESC](https://github.com/fboiero/MIESC)
- **Issues**: [github.com/fboiero/MIESC/issues](https://github.com/fboiero/MIESC/issues)
- **Demo Video**: [youtu.be/pLa_McNBRRw](https://youtu.be/pLa_McNBRRw)

---

## What's Next (v4.4.0)

- PyPI distribution (`pip install miesc`)
- GitHub Actions CI/CD integration
- VSCode extension
- Multi-chain support (Solana, Soroban)

---

**Full Changelog**: [v4.2.3...v4.3.0](https://github.com/fboiero/MIESC/compare/v4.2.3...v4.3.0)
