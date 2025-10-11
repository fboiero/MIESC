# 🔍 Xaudit: Hybrid Smart Contract Auditing Framework

**Xaudit** is a hybrid smart contract auditing framework integrating static, fuzzing, and formal methods with AI-assisted analysis (2025 edition).

This framework addresses the growing complexity of decentralized application security by combining traditional security tools (Slither, Echidna, Medusa, Certora) with AI-powered triage and analysis capabilities.

---

## 🎓 Academic Research

This repository supports the Master's thesis:

**"Development of a Framework for Security Evaluation of Smart Contracts on the Ethereum Virtual Machine Using Artificial Intelligence"**

- **Author**: Fernando Boiero
- **Institution**: Universidad Tecnológica Nacional - FRVM
- **Contact**: fboiero@frvm.utn.edu.ar
- **Year**: 2025

📚 **Thesis Documentation**: See [`/thesis`](/thesis) directory for methodology, experiments, and results.

---

## ✨ Key Features

- **Multi-Layer Analysis**
  - Static analysis (Slither)
  - Property-based fuzzing (Echidna)
  - Coverage-guided fuzzing (Medusa)
  - Formal verification (Certora, Scribble)
  - Differential testing (Foundry)

- **AI-Powered Triage**
  - Automated vulnerability classification
  - False positive reduction
  - PoC exploit generation
  - Natural language explanations

- **CI/CD Integration**
  - Automated GitHub Actions workflows
  - Continuous security monitoring
  - Report generation

- **Comprehensive Dataset**
  - 100+ vulnerable contracts (SWC categorized)
  - Real-world case studies
  - Ground truth annotations

---

## 🏗️ Architecture

```
xaudit/
├── src/
│   ├── contracts/          # Test contracts & vulnerable examples
│   ├── tests/              # Foundry test suites
│   └── utils/              # Analysis scripts
├── analysis/
│   ├── slither/            # Static analysis configs
│   ├── echidna/            # Fuzzing configurations
│   ├── medusa/             # Fuzzer configs
│   ├── scribble/           # Runtime verification specs
│   └── certora/            # Formal verification specs (CVL)
├── thesis/
│   ├── methods.md          # Research methodology
│   ├── experiments.md      # Experimental design
│   └── results.md          # Results & analysis
└── .github/workflows/      # CI/CD pipelines
```

---

## 🚀 Quick Start

### Prerequisites

- **Foundry** (`forge`, `anvil`, `cast`)
- **Slither** (`pip install slither-analyzer`)
- **Echidna** (Haskell-based fuzzer)
- **Medusa** (Go-based fuzzer)
- **Certora** (optional, requires license)
- **Python 3.9+** with dependencies

### Installation

```bash
# Clone repository
git clone https://github.com/fboiero/xaudit.git
cd xaudit

# Setup environment
./setup.sh

# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Install Python tools
pip install -r requirements.txt
```

### Run Analysis

```bash
# Full pipeline on a contract
./run_audit.sh src/contracts/examples/voting.sol 0.8.0 my_audit

# Individual tools
slither src/contracts/examples/voting.sol
echidna src/contracts/examples/voting.sol --config analysis/echidna/config.yaml
forge test --fuzz-runs 10000
```

---

## 📊 Experimental Pipeline

### 1. Static Analysis
```bash
slither src/contracts/vulnerable/reentrancy/*.sol --json analysis/slither/results.json
```

### 2. Fuzzing
```bash
# Echidna (property-based)
echidna src/contracts/vulnerable/reentrancy/BasicReentrancy.sol \
  --config analysis/echidna/config.yaml

# Medusa (coverage-guided)
medusa fuzz --config analysis/medusa/medusa.json
```

### 3. Formal Verification
```bash
# Certora
certoraRun src/contracts/examples/ERC20.sol \
  --verify ERC20:analysis/certora/ERC20.spec
```

### 4. AI Triage
```bash
python src/utils/ai_assistant.py \
  --findings analysis/slither/results.json \
  --output analysis/consolidated_report.md
```

---

## 🔬 Research Contributions

1. **Novel Framework**: First open-source integration of static + fuzzing + formal + AI
2. **Benchmark Dataset**: 100+ vulnerable contracts with ground truth
3. **Reproducible Methodology**: Standardized metrics (precision/recall/F1)
4. **Empirical Evaluation**: Quantitative analysis of tool effectiveness

---

## 📈 Preliminary Results

*Results will be updated as experiments complete (see `/thesis/results.md`)*

| Tool/Framework | Precision | Recall | F1-Score | Time (avg) |
|----------------|-----------|--------|----------|------------|
| Slither | TBD | TBD | TBD | TBD |
| Echidna | TBD | TBD | TBD | TBD |
| **Xaudit (hybrid)** | **TBD** | **TBD** | **TBD** | **TBD** |

---

## 🤝 Contributing

Contributions welcome! Areas:
- Additional vulnerable contract examples
- Improved fuzzing properties
- Formal verification specs
- AI prompt optimization
- Documentation enhancements

---

## 📄 License

GPL-3.0 License - See [LICENSE](LICENSE)

---

## ⚠️ Disclaimer

Xaudit is a research tool. It does not guarantee complete vulnerability detection. Always:
- Manually review findings
- Conduct comprehensive testing
- Engage professional auditors for production contracts

---

## 📚 References

- Thesis documentation: [`/thesis`](/thesis)
- Methodology: [`/thesis/methods.md`](/thesis/methods.md)
- Experiments: [`/thesis/experiments.md`](/thesis/experiments.md)
- Results: [`/thesis/results.md`](/thesis/results.md)

---

## 📞 Contact

- **Author**: Fernando Boiero
- **Email**: fboiero@frvm.utn.edu.ar
- **Institution**: Universidad Tecnológica Nacional - FRVM
- **GitHub**: [@fboiero](https://github.com/fboiero)

---

## 🌟 Citation

If you use Xaudit in your research, please cite:

```bibtex
@mastersthesis{boiero2025xaudit,
  author = {Boiero, Fernando},
  title = {Development of a Framework for Security Evaluation of Smart Contracts on the Ethereum Virtual Machine Using Artificial Intelligence},
  school = {Universidad Tecnológica Nacional - FRVM},
  year = {2025},
  type = {Master's Thesis},
  url = {https://github.com/fboiero/xaudit}
}
```

---

**Last Updated**: October 2025
**Status**: 🚧 Active Research
