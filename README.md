# 🔍 Xaudit v2.0: Hybrid Smart Contract Auditing Framework

**Xaudit v2.0** is a comprehensive hybrid smart contract auditing framework integrating **10 specialized tools** across static analysis, symbolic execution, fuzzing, and formal verification, enhanced with AI-powered triage and interactive dashboards.

This framework addresses the growing complexity of decentralized application security by combining traditional security tools (Solhint, Slither, Surya, Mythril, Manticore, Echidna, Medusa, Foundry, Certora) with GPT-4o-mini powered analysis and professional reporting capabilities.

**🆕 v2.0 Features:**
- ✅ 10-tool integrated pipeline with 12 phases
- ✅ AI-powered triage with 89.47% precision (Cohen's Kappa 0.847)
- ✅ Interactive web dashboard with Chart.js visualizations
- ✅ ISO/IEC 42001:2023 compliant AI management
- ✅ Public dataset integration (SmartBugs, SolidiFI, etc.)
- ✅ Comprehensive JSON/Markdown/HTML reporting

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

### 🛠️ **10-Tool Integrated Pipeline**

**Phase 1-3: Linting & Static Analysis**
- **Solhint**: Linting y mejores prácticas (200+ reglas)
- **Slither**: Análisis estático profundo (90+ detectores)
- **Surya**: Visualización de grafos de control de flujo

**Phase 4-6: Symbolic Execution**
- **Mythril**: Ejecución simbólica con detección de 9 SWC
- **Manticore**: Generación automática de exploits ejecutables

**Phase 7-10: Fuzzing**
- **Echidna**: Property-based fuzzing (Haskell)
- **Medusa**: Coverage-guided fuzzing con mutación inteligente
- **Foundry Fuzz**: Fuzz testing integrado con Forge
- **Foundry Invariants**: Testing de invariantes con stateful fuzzing

**Phase 11: Formal Verification**
- **Certora Prover**: Verificación formal con CVL (Certora Verification Language)

**Phase 12: AI Triage**
- **GPT-4o-mini**: Clasificación automática, filtrado de FPs, priorización

### 🤖 **AI-Powered Analysis**
- ✅ **89.47% Precision** en reducción de falsos positivos (Experimento 7)
- ✅ **Cohen's Kappa 0.847** de acuerdo experto-AI (Experimento 8)
- ✅ **Explicabilidad Completa**: Cada hallazgo incluye justificación textual
- ✅ **ISO/IEC 42001:2023 Compliant**: Gestión responsable de sistemas AI

### 📊 **Interactive Dashboards**
- **Web Dashboard**: Visualizaciones interactivas con Chart.js
- **Executive Reports**: JSON, Markdown, HTML con métricas cuantitativas
- **Real-Time Metrics**: Monitoreo de precisión, recall, F1-score
- **Tool Comparison**: Análisis comparativo entre herramientas

### 📦 **Public Dataset Integration**
- **SmartBugs Curated**: 142 contratos anotados con vulnerabilidades
- **SolidiFI Benchmark**: 9,369 bugs inyectados (7 tipos)
- **Smart Contract Dataset**: 12,000+ contratos de producción
- **VeriSmart Benchmarks**: 129 contratos para verificación formal
- **Not So Smart Contracts**: Ejemplos reales de vulnerabilidades (Crytic)

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

**Required:**
- **Python 3.9+**
- **Foundry** (`forge`, `anvil`, `cast`)
- **Slither** (`pip install slither-analyzer`)
- **Solhint** (`npm install -g solhint`)
- **Surya** (`npm install -g surya`)

**Optional (for full pipeline):**
- **Mythril** (`pip install mythril`)
- **Manticore** (`pip install manticore`)
- **Echidna** (via Homebrew: `brew install echidna`)
- **Medusa** (Go-based: https://github.com/crytic/medusa)
- **Certora** (requires license: https://www.certora.com/)

### Installation

```bash
# Clone repository
git clone https://github.com/fboiero/xaudit.git
cd xaudit

# Install Python dependencies
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Install Node.js tools
npm install -g solhint surya

# Download public datasets (optional)
bash scripts/download_datasets.sh
```

### Run Analysis

```bash
# Full 12-phase pipeline on a contract
python xaudit.py --target src/contracts/examples/voting.sol

# Quick analysis (skip time-intensive tools)
python xaudit.py --target src/contracts/examples/voting.sol --quick

# Run specific tools only
python xaudit.py --target src/contracts/examples/voting.sol --tools slither,mythril,echidna

# Generate interactive dashboard
python src/utils/web_dashboard.py --results analysis/results --output analysis/dashboard
```

### Run Benchmarks

```bash
# Download public datasets
bash scripts/download_datasets.sh

# Run benchmark on SmartBugs Curated
python scripts/run_benchmark.py --dataset smartbugs-curated --parallel 4

# Compare tool performance
python scripts/compare_tools.py --all

# View results in browser
open analysis/dashboard/index.html
```

---

## 📊 Xaudit v2.0 Pipeline (12 Phases)

```
┌─────────────────────────────────────────────────────────────────┐
│                    Xaudit v2.0 Pipeline                         │
└─────────────────────────────────────────────────────────────────┘

Phase 1: Configuración y Validación
  └─> Verificar código Solidity, configurar herramientas

Phase 2: Linting (Solhint)
  └─> 200+ reglas de mejores prácticas

Phase 3: Análisis Estático (Slither)
  └─> 90+ detectores de vulnerabilidades

Phase 4: Visualización (Surya)
  └─> Grafos de control de flujo, diagramas de herencia

Phase 5: Análisis Simbólico (Mythril)
  └─> Ejecución simbólica, detección de 9 SWC

Phase 6: Generación de Exploits (Manticore)
  └─> PoCs ejecutables automáticos

Phase 7: Fuzzing Echidna
  └─> Property-based fuzzing con propiedades invariantes

Phase 8: Fuzzing Medusa
  └─> Coverage-guided con mutación inteligente

Phase 9: Foundry Fuzz Testing
  └─> Fuzz testing integrado con Forge

Phase 10: Foundry Invariant Testing
  └─> Stateful fuzzing de invariantes

Phase 11: Verificación Formal (Certora)
  └─> Pruebas matemáticas de corrección con CVL

Phase 12: AI Triage (GPT-4o-mini)
  └─> Clasificación, filtrado FPs, priorización, recomendaciones

Output: JSON + Markdown + HTML Dashboard
```

### Individual Tool Usage

```bash
# Phase 2: Linting
solhint 'src/**/*.sol'

# Phase 3: Static Analysis
slither src/contracts/examples/voting.sol --json output.json

# Phase 4: Visualization
surya graph src/contracts/examples/voting.sol | dot -Tpng > graph.png

# Phase 5: Symbolic Execution
myth analyze src/contracts/examples/voting.sol --execution-timeout 300

# Phase 6: Exploit Generation
manticore src/contracts/examples/voting.sol --contract Voting

# Phase 7: Echidna Fuzzing
echidna src/contracts/examples/voting.sol --config echidna.yaml

# Phase 8: Medusa Fuzzing
medusa fuzz --target src/contracts/examples/voting.sol

# Phase 9-10: Foundry Testing
forge test --fuzz-runs 10000
forge test --invariant-runs 1000

# Phase 11: Formal Verification
certoraRun src/contracts/examples/voting.sol --verify Voting:voting.spec

# Phase 12: AI Triage
python src/ai_triage.py --findings consolidated.json --output report.md
```

---

## 🔬 Research Contributions

1. **Comprehensive Framework**: Primera integración open-source de 10 herramientas + AI en pipeline unificado
2. **AI Triage Validation**: Validación empírica con Cohen's Kappa 0.847 (acuerdo experto-AI)
3. **Public Dataset Integration**: 5 datasets públicos integrados (20K+ contratos)
4. **ISO/IEC 42001:2023 Compliance**: Primer framework de auditoría blockchain certificable bajo norma AI
5. **Interactive Dashboards**: Visualizaciones profesionales para análisis comparativo de herramientas
6. **Reproducible Methodology**: Métricas estandarizadas (precision/recall/F1/Kappa) con scripts de benchmark
7. **Empirical Evaluation**: 8 experimentos cuantitativos documentados con resultados publicables

---

## 📈 Experimental Results

### Experimento 7: AI Triage - Reducción de Falsos Positivos

| Métrica | Resultado | Baseline (Sin AI) |
|---------|-----------|-------------------|
| **Precisión** | **89.47%** | 67.3% |
| **Recall** | **86.2%** | 94.1% |
| **F1-Score** | **87.81** | 78.5 |
| **Falsos Positivos Filtrados** | **73.6%** | N/A |
| **Tiempo de Análisis** | 1.3s/hallazgo | N/A |

### Experimento 8: Validación Experto-AI

| Métrica | Resultado | Interpretación |
|---------|-----------|----------------|
| **Cohen's Kappa** | **0.847** | Acuerdo casi perfecto (>0.80) |
| **Precisión de Clasificación** | **91.2%** | 200 hallazgos evaluados |
| **Acuerdo en Críticos** | **95.8%** | Consenso alto en vulnerabilidades críticas |
| **Explicabilidad** | **100%** | Todas las decisiones justificadas |

### Comparación de Herramientas (SmartBugs Curated - 142 contratos)

| Herramienta | Vulnerabilidades Detectadas | Falsos Positivos | Tiempo Promedio |
|-------------|----------------------------|------------------|-----------------|
| Slither | 847 | 23.4% | 2.3s |
| Mythril | 234 | 31.2% | 45.6s |
| Manticore | 89 | 12.1% | 287s |
| Echidna | 156 | 8.7% | 120s |
| Foundry | 201 | 15.3% | 34s |
| Certora | 78 | 3.2% | 456s |
| **Xaudit (10 tools + AI)** | **1,247** | **11.8%** | **~500s** |

**Nota**: Resultados completos en [`thesis/es/capitulo7_resultados.md`](thesis/es/capitulo7_resultados.md)

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

## 📚 Documentation

### Thesis Documentation (Spanish)
- **Capítulo 3**: [`Objetivos y Alcance`](thesis/es/capitulo3_objetivos.md)
- **Capítulo 4**: [`Estado del Arte`](thesis/es/capitulo4_estado_arte.md) - Análisis de 10 herramientas
- **Capítulo 5**: [`Metodología`](thesis/es/capitulo5_metodologia.md) - Pipeline de 12 fases
- **Capítulo 6**: [`Implementación`](thesis/es/capitulo6_implementacion.md) - Detalles técnicos
- **Capítulo 7**: [`Resultados`](thesis/es/capitulo7_resultados.md) - 8 experimentos con métricas
- **Capítulo 8**: [`Conclusiones`](thesis/es/capitulo8_conclusiones.md) - Aportes y trabajo futuro

### Technical Documentation
- **AI Policy**: [`docs/ai_policy.md`](docs/ai_policy.md) - Uso responsable de IA
- **ISO 42001 Compliance**: [`docs/ISO_42001_compliance.md`](docs/ISO_42001_compliance.md) - Cumplimiento normativo
- **Dataset Guide**: [`datasets/README.md`](datasets/README.md) - Uso de datasets públicos

### Code Documentation
- **Enhanced Reporter**: [`src/utils/enhanced_reporter.py`](src/utils/enhanced_reporter.py) - Sistema de reportes
- **Web Dashboard**: [`src/utils/web_dashboard.py`](src/utils/web_dashboard.py) - Dashboard interactivo
- **Benchmark Runner**: [`scripts/run_benchmark.py`](scripts/run_benchmark.py) - Ejecución de benchmarks
- **Tool Comparison**: [`scripts/compare_tools.py`](scripts/compare_tools.py) - Comparación de herramientas

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
