---
layout: default
title: MIESC - Smart Contract Security Framework
---

# MIESC - Multi-layer Intelligent Evaluation for Smart Contracts

<div align="center">

![MIESC Banner](https://img.shields.io/badge/MIESC-v4.0.0-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-AGPL--3.0-green?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.9+-yellow?style=for-the-badge)
![AI Powered](https://img.shields.io/badge/AI-Powered-purple?style=for-the-badge)

**Defense-in-Depth Security Framework for Ethereum Smart Contracts**

*Master's Thesis in Cyberdefense | Universidad de la Defensa Nacional (UNDEF)*

[Try Web Demo](webapp/README.md){ .md-button .md-button--primary }
[Thesis](thesis.md){ .md-button .md-button--primary }
[Documentation](docs/INDEX.md){ .md-button }
[GitHub](https://github.com/fboiero/MIESC){ .md-button }

**English** | [Espanol](index_es.md)

</div>

---

## Overview

**MIESC** is a production-grade smart contract security framework that implements a **7-layer Defense-in-Depth architecture**, integrating **25 specialized security tools** with **AI-powered correlation** and **ML-based detection** to deliver comprehensive vulnerability detection with industry-leading accuracy.

### Key Achievements (v4.0.0)

- **25 Integrated Tools** across 7 defense layers
- **95.7% ML Detection Accuracy** with DA-GNN Graph Neural Networks
- **94.5% Precision**, **92.8% Recall**, **F1-Score 0.93**
- **91.4% Compliance Index** across 12 international standards
- **Sovereign AI** with Ollama - code never leaves your machine
- **$0 Operational Cost** - fully local execution

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

### 7-Layer Defense Architecture

| Layer | Category | Tools | Detection Focus |
|-------|----------|-------|-----------------|
| **1** | Static Analysis | Slither, Aderyn, Solhint | Pattern detection (90+ detectors) |
| **2** | Dynamic Testing | Echidna, Medusa, Foundry | Property-based fuzzing |
| **3** | Symbolic Execution | Mythril, Manticore, Halmos | Deep state exploration |
| **4** | Formal Verification | Certora, SMTChecker, Wake | Mathematical proofs |
| **5** | AI Analysis | SmartLLM, GPTScan, LLM-SmartAudit | Semantic analysis |
| **6** | ML Detection | DA-GNN, PolicyAgent | Graph-based detection |
| **7** | Audit Readiness | Layer7Agent | Compliance mapping |

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
# Clone repository
git clone https://github.com/fboiero/MIESC.git
cd MIESC

# Install dependencies
pip install slither-analyzer mythril

# Verify installation
python scripts/verify_installation.py
```

### Run Demo

```bash
# Run v4.0 demo with ML detection + RAG
python3 examples/demo_v4.0.py

# Or full multi-contract analysis
bash demo/run_demo.sh
```

### Web Interface

```bash
# Launch interactive web UI
pip install streamlit plotly streamlit-extras
make webapp
# Open browser to http://localhost:8501
```

[Full Installation Guide](docs/02_SETUP_AND_USAGE.md){ .md-button }

---

## Architecture

```
Smart Contract
      |
CoordinatorAgent (MCP)
      |
   ┌──┴──┬──────┬─────────┐
   |     |      |         |
Layer1 Layer2 Layer3  Layer4   → Tools execute in parallel
Static Dynamic Symbolic Formal
   |     |      |         |
   └──┬──┴──────┴─────────┘
      |
   Layer5 (AI correlation)
      |
   Layer6 (ML detection + Compliance)
      |
   Layer7 (Audit readiness)
      |
   Report (JSON/HTML/PDF)
```

### Component Overview

| Layer | Agent | Purpose | Output |
|-------|-------|---------|--------|
| **L1-4** | Analysis Agents | Multi-tool scanning | Raw vulnerability findings |
| **L5** | AI Agent | Semantic analysis | Correlated findings + root cause |
| **L6** | ML + Policy Agent | Detection + Compliance | Risk scores + framework mappings |
| **L7** | Audit Agent | Readiness assessment | Final audit report |

[Architecture Details](docs/01_ARCHITECTURE.md){ .md-button }

---

## Performance Metrics

### v4.0.0 Results

| Metric | v3.5 | v4.0 | Improvement |
|--------|------|------|-------------|
| **Precision** | 89.47% | 94.5% | +5.03pp |
| **Recall** | 86.2% | 92.8% | +6.6pp |
| **F1-Score** | 0.88 | 0.93 | +5.7% |
| **FP Rate** | 10.53% | 5.5% | -48% |
| **Detection Coverage** | 85% | 96% | +11pp |
| **Tool Adapters** | 22 | 25 | +13.6% |

### Test Suite

- **117 tests passing**
- **87.5% code coverage**
- **0 critical vulnerabilities**
- **94.2% policy compliance**

---

## Academic Foundation

### Master's Thesis

**Title**: *Integrated Security Assessment Framework for Smart Contracts: A Defense-in-Depth Approach to Cyberdefense*

**Institution**: Universidad de la Defensa Nacional (UNDEF) - IUA Córdoba

**Author**: Fernando Boiero

**Advisor**: M.Sc. Eduardo Casanovas

**Expected Defense**: Q4 2025

### Research Contributions

1. **7-Layer Defense-in-Depth Architecture** for smart contract security
2. **25 Tool Integration** under unified ToolAdapter protocol
3. **Triple Normalization System** (SWC/CWE/OWASP) with 97.1% accuracy
4. **Sovereign AI Backend** with Ollama for data sovereignty
5. **MCP Server** for AI assistant integration
6. **Legacy Tool Rescue** (Manticore Python 3.11, Oyente Docker)

### Citation

```bibtex
@software{boiero2025miesc,
  author = {Boiero, Fernando},
  title = {{MIESC}: Multi-layer Intelligent Evaluation for Smart Contracts},
  year = {2025},
  url = {https://github.com/fboiero/MIESC},
  version = {4.0.0},
  note = {Implementation for Master's thesis in Cyberdefense}
}
```

[Thesis Documentation](thesis.md){ .md-button }

---

## Documentation

### Getting Started

- [Installation Guide](docs/02_SETUP_AND_USAGE.md)
- [Demo Walkthrough](docs/03_DEMO_GUIDE.md)
- [Web Demo](webapp/README.md)
- [Docker Setup](docs/DOCKER.md)

### Core Concepts

- [Architecture Overview](docs/01_ARCHITECTURE.md)
- [AI Correlation](docs/04_AI_CORRELATION.md)
- [Policy Agent](docs/05_POLICY_AGENT.md)
- [MCP Protocol](docs/07_MCP_INTEROPERABILITY.md)

### Developer Resources

- [Developer Guide](docs/DEVELOPER_GUIDE.md)
- [Contributing Guidelines](CONTRIBUTING.md)
- [API Reference](docs/API_SETUP.md)
- [Extending MIESC](docs/EXTENDING.md)

### Advanced Topics

- [Shift-Left Security](docs/SHIFT_LEFT_SECURITY.md)
- [Compliance Mapping](docs/compliance/COMPLIANCE.md)
- [v4.0 Features](docs/PHASE_3_4_5_COMPLETION_SUMMARY.md)

[Complete Documentation Index](docs/INDEX.md){ .md-button .md-button--primary }

---

## Contributing

We welcome contributions from the security research and blockchain communities!

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-detector`
3. **Make changes** following our [style guide](CONTRIBUTING.md#code-style)
4. **Run quality checks**: `make all-checks`
5. **Submit pull request**

### Priority Areas

- Certora CVL specs for common patterns (ERC-20/721)
- Echidna property templates for DeFi
- Integration tests for all 25 tools
- Cross-chain vulnerability analysis
- Documentation translations

[Contributing Guide](CONTRIBUTING.md){ .md-button }

---

## Support & Community

### Get Help

- **Documentation**: [https://fboiero.github.io/MIESC](https://fboiero.github.io/MIESC)
- **GitHub Issues**: [Bug reports and feature requests](https://github.com/fboiero/MIESC/issues)
- **Email**: fboiero@frvm.utn.edu.ar

### Video Demo

YouTube: [youtu.be/-SP6555edSw](https://youtu.be/-SP6555edSw) (~10 minutes)

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

<div align="center">

**Built for the Smart Contract Security Community**

[Get Started](docs/02_SETUP_AND_USAGE.md){ .md-button .md-button--primary }
[View on GitHub](https://github.com/fboiero/MIESC){ .md-button }

---

**MIESC v4.0.0** | Master's Thesis in Cyberdefense | AGPL-3.0 License

2025 Fernando Boiero - Universidad de la Defensa Nacional (UNDEF)

</div>
