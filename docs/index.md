---
layout: default
title: MIESC - Smart Contract Security Framework
---

# MIESC - Multi-layer Intelligent Evaluation for Smart Contracts

<p align="center">
  <img src="https://img.shields.io/badge/MIESC-v4.3.2-blue?style=for-the-badge" alt="MIESC v4.3.2">
  <img src="https://img.shields.io/pypi/v/miesc?style=for-the-badge&label=PyPI" alt="PyPI">
  <img src="https://img.shields.io/badge/License-AGPL--3.0-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Python-3.12+-yellow?style=for-the-badge" alt="Python">
  <img src="https://img.shields.io/badge/AI-Powered-purple?style=for-the-badge" alt="AI Powered">
</p>

<p align="center">
  <strong>Defense-in-Depth Security Framework for Ethereum Smart Contracts</strong><br>
  <em>Master's Thesis in Cyberdefense | Universidad de la Defensa Nacional (UNDEF)</em>
</p>

<p align="center">
  <a href="https://youtu.be/pLa_McNBRRw">Video Demo</a> •
  <a href="thesis">Thesis</a> •
  <a href="INSTALLATION">Documentation</a> •
  <a href="https://github.com/fboiero/MIESC">GitHub</a>
</p>

<p align="center">
  <strong>English</strong> | <a href="index_es">Español</a>
</p>

---

## Video Demonstration

<p align="center">
  <strong>Watch MIESC in Action</strong><br><br>
  <a href="https://youtu.be/pLa_McNBRRw">
    <img src="https://img.shields.io/badge/YouTube-Demo-red?style=for-the-badge&logo=youtube" alt="YouTube Demo">
  </a><br><br>
  <a href="https://youtu.be/pLa_McNBRRw">Watch on YouTube</a> (~10 minutes)
</p>

**Demonstrates:**

- Defense-in-Depth analysis across 9 security layers
- 31 integrated tools (Slither, Mythril, Echidna, Certora, etc.)
- Model Context Protocol (MCP) integration with MCP client
- 100% Precision, 70% Recall, F1-Score 82.35% (SmartBugs-curated benchmark)
- Sovereign AI with Ollama (code never leaves your machine)

---

## Scope and Limitations

**Purpose:**

- Automated orchestration of 31 security analysis tools
- AI-assisted finding correlation to reduce duplicate reports
- ML-based vulnerability detection with 95.7% accuracy
- Compliance mapping to ISO/NIST/OWASP standards
- Standardized reporting format (JSON/HTML/PDF)

**Limitations:**

- Cannot detect all vulnerability classes (especially complex business logic)
- Effectiveness metrics pending large-scale empirical validation
- Requires manual review of all findings by qualified professionals
- Not suitable as sole security assessment for production contracts

> **Important**: Professional security audits mandatory for contracts handling real value.

---

## Overview

**MIESC** is a production-grade smart contract security framework that implements a **9-layer Defense-in-Depth architecture**, integrating **31 specialized security tools** with **AI-powered correlation** and **ML-based detection** to deliver comprehensive vulnerability detection with industry-leading accuracy.

### Key Achievements (v4.3.2)

- **31 Integrated Tools** across 9 defense layers
- **95.7% ML Detection Accuracy** with DA-GNN Graph Neural Networks
- **100% Precision**, **70% Recall**, **F1-Score 82.35%** (SmartBugs-curated benchmark)
- **91.4% Compliance Index** across 12 international standards
- **Sovereign AI** with Ollama - code never leaves your machine
- **$0 Operational Cost** - fully local execution
- **Now on PyPI**: `pip install miesc`

---

## What's New in v4.0.0

**Major Release** (January 2025) - Four cutting-edge research-based enhancements:

### 1. PropertyGPT (Layer 4 - Formal Verification)

- Automated CVL property generation for formal verification
- 80% recall on ground-truth Certora properties
- Increases formal verification adoption from 5% to 40% (+700%)
- Based on NDSS 2025 paper (arXiv:2405.02580)

### 2. DA-GNN (Layer 6 - ML Detection)

- Graph Neural Network-based vulnerability detection
- 95.7% accuracy with 4.3% false positive rate
- Represents contracts as control-flow + data-flow graphs
- Based on Computer Networks (ScienceDirect, Feb 2024)

### 3. Enhanced RAG SmartLLM (Layer 5 - AI Analysis)

- Retrieval-Augmented Generation with ERC-20/721/1155 knowledge base
- Verificator role for fact-checking (Generator → Verificator → Consensus)
- Precision improved from 75% to 88% (+17%), FP rate reduced by 52%
- Based on arXiv:2502.13167 (Feb 2025)

### 4. DogeFuzz (Layer 2 - Dynamic Testing)

- AFL-style coverage-guided fuzzing with power scheduling
- Hybrid fuzzing + symbolic execution
- 85% code coverage, 3x faster than Echidna
- Based on arXiv:2409.01788 (Sep 2024)

---

## Features

### 9-Layer Defense Architecture

| Layer | Category | Tools | Detection Focus |
|-------|----------|-------|-----------------|
| **1** | Static Analysis | Slither, Aderyn, Solhint | Pattern detection (90+ detectors) |
| **2** | Dynamic Testing | Echidna, Medusa, Foundry, DogeFuzz | Property-based fuzzing |
| **3** | Symbolic Execution | Mythril, Manticore, Halmos | Deep state exploration |
| **4** | Formal Verification | Certora, SMTChecker | Mathematical proofs |
| **5** | Property Testing | PropertyGPT, Wake, Vertigo | Invariant generation |
| **6** | AI/LLM Analysis | SmartLLM, GPTScan, LLM-SmartAudit | Semantic analysis |
| **7** | Pattern Recognition | DA-GNN, SmartGuard, Clone Detector | ML-based detection |
| **8** | DeFi Security | DeFi Analyzer, MEV Detector, Gas Analyzer | Protocol-specific |
| **9** | Advanced Detection | Advanced Detector, Threat Model | Cross-layer correlation |

### AI-Powered Intelligence

- **Local LLM Correlation**: Reduces false positives using deepseek-coder via Ollama
- **Root Cause Analysis**: Developer-friendly vulnerability explanations
- **Risk Prioritization**: Multi-dimensional scoring (CVSS + exploitability + impact)
- **Automated Remediation**: Actionable fix recommendations with code patches

### Compliance & Governance

Built-in mapping to 12 major security frameworks:

| Standard | Coverage | Domain |
|----------|----------|--------|
| ISO/IEC 27001:2022 | 5/5 controls | Information security |
| ISO/IEC 42001:2023 | 5/5 clauses | AI governance |
| NIST SP 800-218 | 5/5 practices | Secure development |
| OWASP SC Top 10 | 10/10 | Smart contract vulnerabilities |
| OWASP SCSVS | Level 3 | Security verification |
| SWC Registry | 33/37 types | Weakness classification |
| DASP Top 10 | 10/10 | DeFi patterns |
| EU MiCA/DORA | Partial | Regulatory compliance |

### MCP Protocol Integration

Native Model Context Protocol support for AI assistant integration:

- **run_audit** - Execute multi-tool analysis
- **correlate_findings** - Apply AI filtering
- **map_compliance** - Generate compliance mappings
- **generate_report** - Produce formatted reports

---

## Quick Start

### Installation

```bash
# From PyPI (recommended)
pip install miesc

# With all features
pip install miesc[full]

# From source (development)
git clone https://github.com/fboiero/MIESC.git
cd MIESC && pip install -e .[dev]
```

### Basic Usage

```bash
# Quick vulnerability scan
miesc scan contract.sol

# CI/CD mode (exit 1 if critical/high issues)
miesc scan contract.sol --ci

# Full 9-layer audit
miesc audit full contract.sol

# Check tool availability
miesc doctor
```

### Web Interface

```bash
# Launch interactive web UI
pip install miesc[web]
make webapp
# Open browser to http://localhost:8501
```

[Full Installation Guide](INSTALLATION) | [Quick Start Guide](https://github.com/fboiero/MIESC/blob/main/QUICKSTART.md)

---

## Architecture

```
Smart Contract
      │
CoordinatorAgent (MCP)
      │
   ┌──┴──┬──────┬─────────┐
   │     │      │         │
Layer1 Layer2 Layer3  Layer4   → Tools execute in parallel
Static Dynamic Symbolic Formal
   │     │      │         │
   └──┬──┴──────┴─────────┘
      │
   Layer5 (Property Testing)
      │
   Layer6 (AI/LLM Analysis)
      │
   Layer7 (ML Pattern Recognition)
      │
   Layer8 (DeFi Security)
      │
   Layer9 (Advanced Detection + Correlation)
      │
   Report (JSON/HTML/PDF/SARIF)
```

### Component Overview

| Layer | Agent | Purpose | Output |
|-------|-------|---------|--------|
| **L1-4** | Analysis Agents | Multi-tool scanning | Raw vulnerability findings |
| **L5** | Property Agent | Invariant generation | CVL properties/property tests |
| **L6** | AI Agent | Semantic analysis | Correlated findings + root cause |
| **L7** | ML Agent | Graph-based detection | Vulnerability patterns |
| **L8** | DeFi Agent | Protocol-specific analysis | DeFi/MEV risks |
| **L9** | Advanced Agent | Cross-layer correlation | Final audit report |

[Architecture Details](thesis)

---

## Performance Metrics

### v4.3.2 Results (SmartBugs-curated Benchmark)

| Metric | Value | Notes |
|--------|-------|-------|
| **Precision** | 100% | 0 false positives |
| **Recall** | 70% | 35/50 vulnerabilities detected |
| **F1-Score** | 82.35% | 50 contract benchmark |
| **Tools** | 31 | Operational across 9 layers |
| **Categories with 100% Recall** | 3 | arithmetic, bad_randomness, front_running |

### Test Suite

- **117 tests passing**
- **80.8% code coverage**
- **0 critical vulnerabilities**
- **31/31 tools operational**

---

## Academic Foundation

### Master's Thesis

**Title**: *Integrated Security Assessment Framework for Smart Contracts: A Defense-in-Depth Approach to Cyberdefense*

**Institution**: Universidad de la Defensa Nacional (UNDEF) - IUA Córdoba

**Author**: Fernando Boiero

**Advisor**: M.Sc. Eduardo Casanovas

**Expected Defense**: Q4 2025

### Research Contributions

1. **9-Layer Defense-in-Depth Architecture** for smart contract security
2. **31 Tool Integration** under unified ToolAdapter protocol
3. **Triple Normalization System** (SWC/CWE/OWASP) with 97.1% accuracy
4. **Sovereign AI Backend** with Ollama for data sovereignty
5. **MCP Server** for AI assistant integration
6. **Legacy Tool Rescue** (Manticore Python 3.11 compatibility)

### Citation

```bibtex
@software{boiero2025miesc,
  author = {Boiero, Fernando},
  title = {MIESC: Multi-layer Intelligent Evaluation for Smart Contracts},
  year = {2025},
  url = {https://github.com/fboiero/MIESC},
  version = {4.3.2},
  note = {Implementation for Master's thesis in Cyberdefense}
}
```

[Thesis Documentation](thesis)

---

## Documentation

### Getting Started

- [Installation Guide](INSTALLATION)
- [Tools Reference](TOOLS)
- [Validation Guide](VALIDATION_GUIDE)

### Releases

- [Release Notes v4.3.0](RELEASE_NOTES_v4.3.0)
- [Release Notes v4.2.3](RELEASE_NOTES_v4.2.3)
- [Release Notes v4.0.0](RELEASE_NOTES_v4.0.0)

### Developer Resources

- [Contributing Guidelines](CONTRIBUTING)
- [Security Policy](SECURITY)
- [Changelog](CHANGELOG)

### Thesis

- [Thesis Overview](thesis)
- [Tesis (Español)](thesis_es)

---

## Contributing

We welcome contributions from the security research and blockchain communities!

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-detector`
3. **Make changes** following our [style guide](CONTRIBUTING)
4. **Run quality checks**: `make all-checks`
5. **Submit pull request**

### Priority Areas

- Certora CVL specs for common patterns (ERC-20/721)
- Echidna property templates for DeFi
- Integration tests for all 31 tools
- Cross-chain vulnerability analysis
- Documentation translations

[Contributing Guide](CONTRIBUTING)

---

## Support & Community

### Get Help

- **Documentation**: [https://fboiero.github.io/MIESC](https://fboiero.github.io/MIESC)
- **GitHub Issues**: [Bug reports and feature requests](https://github.com/fboiero/MIESC/issues)
- **Email**: <fboiero@frvm.utn.edu.ar>

---

## Usage Examples

**Quick Scan (CI/CD Integration):**

```bash
miesc scan contracts/MyToken.sol --ci
# Exit code 0 if no critical issues, 1 otherwise
```

**Full 9-Layer Audit:**

```bash
miesc audit full contracts/MyToken.sol -o audit_report.json
```

**Batch Audit (Multiple Contracts):**

```bash
miesc audit batch contracts/ -r -o batch_report.json
```

**Selective Layer Execution:**

```bash
miesc audit full contracts/Treasury.sol --layers 1,3,6
# Runs only Layer 1 (Static), Layer 3 (Symbolic), Layer 6 (AI)
```

**Export to Different Formats:**

```bash
miesc audit quick contract.sol -f sarif -o report.sarif
miesc audit quick contract.sol -f markdown -o report.md
```

**MCP Server Mode:**

```bash
miesc server mcp
# Enables: audit_contract(), explain_vulnerability(), suggest_fix()
```

---

## License

**AGPL-3.0 License** - See [LICENSE](LICENSE) for details.

Ensures framework remains open-source. Allows commercial use with attribution. Derivative works must be open-source.

**Disclaimer**: Research tool provided "as is" without warranties. Manual review by qualified security professionals required. Not a replacement for professional audits.

---

## Acknowledgments

### Security Tools

- **Trail of Bits** (Slither, Manticore, Echidna)
- **Crytic** (Medusa)
- **ConsenSys** (Mythril)
- **Ackee Blockchain** (Wake)
- **Certora**
- **a16z** (Halmos)
- **Cyfrin** (Aderyn)
- **Ethereum Foundation** (SMTChecker)
- **Paradigm** (Foundry)
- **Anthropic** (MCP)

### Datasets

- SmartBugs (INESC-ID)
- SolidiFI (TU Delft)
- Etherscan

---

<p align="center">
  <strong>Built for the Smart Contract Security Community</strong>
</p>

<p align="center">
  <a href="INSTALLATION.md">Get Started</a> |
  <a href="https://github.com/fboiero/MIESC">View on GitHub</a>
</p>

---

<p align="center">
  <strong>MIESC v4.3.2</strong> | Master's Thesis in Cyberdefense | AGPL-3.0 License
</p>

<p align="center">
  2025 Fernando Boiero - Universidad de la Defensa Nacional (UNDEF)
</p>
