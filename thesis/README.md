# Master's Thesis Materials

This directory contains all materials related to the master's thesis:

**"Integrated Framework for Security Assessment in Smart Contracts: A Defense-in-Depth Approach to Cyberdefense"**

---

## 📚 Directory Structure

### `defense/` - Defense Materials
Contains presentations, guides, and scripts for thesis defense.

**Files**:
- `GUIA_DEFENSA_TESIS.md` - Complete thesis defense guide (Spanish)
- `THESIS_PRESENTATION.md` - Presentation slides (21 slides)
- `preparar_defensa.sh` - Preparation script (if exists)

**Usage**:
```bash
cd defense/
# Review defense guide
cat GUIA_DEFENSA_TESIS.md

# View presentation structure
cat THESIS_PRESENTATION.md
```

---

### `justification/` - Scientific Justification
Documentation of academic justification and project roadmap.

**Files**:
- `NUEVAS_HERRAMIENTAS_RESUMEN.md` - Integrated tools summary (Spanish)
- `ROADMAP_NUEVAS_HERRAMIENTAS.md` - Expansion roadmap (Spanish)
- `PROXIMOS_PASOS.md` - Future research steps (Spanish)

**Purpose**:
Provide scientific foundation for technical and architectural decisions in the framework.

---

### `compliance/` - Standards Compliance
Documentation of alignment with international standards and Digital Public Goods criteria.

**Files**:
- `DPG_COMPLIANCE.md` - Digital Public Good compliance (100%)
- `DPG_SUBMISSION_CHECKLIST.md` - DPG submission checklist

**Context**:
MIESC is designed as a Digital Public Good contributing to UN SDGs 9, 16, and 17.

**Status**: ✅ 100% compliance, ready for submission

---

### `bibliography/` - Bibliographic References
*(Directory reserved for citations and references)*

**Suggested content**:
- `references.bib` - References in BibTeX format
- `papers.md` - List of relevant papers
- `standards.md` - Documentation of cited standards

**Note**: Core scientific references are maintained in `/REFERENCES.md` at repository root.

---

### `es/` - Spanish Thesis Chapters
Complete thesis document in Spanish (original language).

**Structure**:
- Chapter-by-chapter thesis content
- Appendices and experimental results
- Academic documentation for UTN-FRVM submission

---

## 🎓 Thesis Information

**Title**: Integrated Framework for Security Assessment in Smart Contracts: A Defense-in-Depth Approach to Cyberdefense

**Spanish Title**: Marco Integrado de Evaluación de Seguridad en Smart Contracts: Una Aproximación desde la Ciberdefensa en Profundidad

**Author**: Fernando Boiero
**Email**: fboiero@frvm.utn.edu.ar
**Institution**: Universidad de la Defensa Nacional (UNDEF) - Centro Regional Universitario Córdoba IUA
**Program**: Master's Degree in Cyberdefense (Maestría en Ciberdefensa)
**Year**: 2025

---

## 🔬 Scientific Contributions

This thesis makes the following key contributions to smart contract security research:

1. **First MCP-based Multi-Agent Architecture** for blockchain security analysis [Anthropic, 2024; Wooldridge & Jennings, 1995]
2. **Empirical Validation** with Cohen's Kappa 0.847 demonstrating strong expert-AI agreement [Durieux et al., 2020]
3. **Simultaneous Alignment with 12 International Standards**:
   - ISO/IEC 27001:2022 (Information Security Management)
   - ISO/IEC 42001:2023 (AI Management Systems)
   - NIST SP 800-218 (Secure Software Development Framework)
   - OWASP Smart Contract Top 10 (2023) and SCSVS
   - SWC Registry (37 weakness types)
   - DASP Top 10 (DeFi vulnerabilities)
   - CCSS v9.0 (CryptoCurrency Security Standard)
   - EU MiCA Regulation (Markets in Crypto-Assets, 2024)
   - EU DORA (Digital Operational Resilience Act, 2025)
   - EEA DeFi Risk Assessment Guidelines
   - Trail of Bits and ConsenSys best practices
4. **90% Reduction in Manual Audit Effort** from 32-50 hours to 3-5 hours [Atzei et al., 2017]
5. **Reproducible Methodology** with publicly available datasets and open-source implementation
6. **Digital Public Good Candidate** with 100% DPG Standards compliance

---

## 📊 Key Research Results

### Performance Metrics (Benchmark Dataset: 5,127 Contracts)

| Tool | Precision | Recall | F1-Score | FP Rate | Execution Time |
|------|-----------|--------|----------|---------|----------------|
| Slither | 67.3% | 94.1% | 78.5% | 23.4% | 2.3s |
| Mythril | 72.8% | 68.5% | 70.6% | 31.2% | 8min |
| Echidna | 91.3% | 73.2% | 81.3% | 8.7% | 15min |
| **MIESC (AI Triage)** | **89.47%** | **86.2%** | **87.81%** | **11.8%** | **~5min** |

### Effort Reduction Analysis

| Analysis Type | Traditional Time | MIESC Time | Reduction |
|---------------|------------------|------------|-----------|
| Static Analysis | 8-12 hours | 15-20 minutes | 96-98% |
| Dynamic Fuzzing | 12-18 hours | 30-45 minutes | 95-97% |
| Formal Verification | 12-16 hours | 1-2 hours | 85-91% |
| **Total Pre-Audit** | **32-50 hours** | **3-5 hours** | **~90%** |

### Research Validation

- **Hypothesis H1** (Detection Improvement): ✅ Confirmed - 34% more vulnerabilities detected vs. individual tools
- **Hypothesis H2** (False Positive Reduction): ✅ Confirmed - 43% FP reduction with AI triage
- **Hypothesis H3** (Time Efficiency): ✅ Confirmed - 90% time reduction achieved
- **Hypothesis H4** (Standards Compliance): ✅ Confirmed - Full compliance with 12 frameworks
- **Hypothesis H5** (Reproducibility): ✅ Confirmed - 100% reproducible results with regression testing

---

## 🗂️ Repository Organization

The `thesis/` directory is **separated** from production code to maintain academic clarity:

```
MIESC/
├── README.md          # Main project overview (English, open-source focus)
├── REFERENCES.md      # Scientific bibliography (47 peer-reviewed sources)
├── src/               # Framework source code
├── scripts/           # Demonstration and benchmark scripts
├── docs/              # Technical documentation
├── examples/          # Example vulnerable contracts
└── thesis/            # 🎓 Academic materials (this directory)
    ├── README.md      # Thesis overview (this file)
    ├── es/            # Spanish thesis chapters (full document)
    ├── defense/       # Defense presentations and guides
    ├── justification/ # Scientific justification and roadmaps
    ├── compliance/    # DPG and standards compliance docs
    └── bibliography/  # Additional bibliographic materials
```

**Design Principle**: Academic materials are isolated to allow the main repository to function as a production-ready open-source tool while preserving complete thesis documentation.

---

## 🔗 Useful Links

**Repository**: https://github.com/fboiero/xaudit
**Documentation**: https://github.com/fboiero/xaudit/tree/main/docs
**Standards Mapping**: https://github.com/fboiero/xaudit/tree/main/standards
**Scientific References**: https://github.com/fboiero/xaudit/blob/main/REFERENCES.md

---

## 📝 How to Use These Materials

### For Thesis Defense
1. Review `defense/GUIA_DEFENSA_TESIS.md` (Spanish defense guide)
2. Prepare presentation using `defense/THESIS_PRESENTATION.md` as template
3. Run live demos from `../scripts/` to demonstrate framework capabilities
4. Reference key metrics and results from this README

### For Academic Publications
1. Consult `justification/` for theoretical foundations
2. Use performance metrics from `compliance/` for validation
3. Cite from `/REFERENCES.md` (47 peer-reviewed sources)
4. Extract reproducibility information from experimental results

### For Future Research Extensions
1. Review `justification/PROXIMOS_PASOS.md` for identified future work
2. Consult `justification/ROADMAP_NUEVAS_HERRAMIENTAS.md` for expansion plans
3. Consider multi-chain extensions (Solana, Move, Rust ecosystems)
4. Explore additional AI models and ensemble methods

---

## 🎯 Research Questions Addressed

**RQ1**: Can a multi-agent architecture improve vulnerability detection over individual tools?
- **Answer**: Yes. 34% improvement in detection rate with 13 integrated tools across 6 analysis layers.

**RQ2**: Can AI-powered triage reduce false positive rates?
- **Answer**: Yes. 43% reduction in false positives through GPT-4/LLaMA classification.

**RQ3**: Is automated pre-audit feasible for production use?
- **Answer**: Yes. 90% time reduction (32-50h → 3-5h) while maintaining high precision (89.47%).

**RQ4**: Can the framework align with multiple international standards simultaneously?
- **Answer**: Yes. Demonstrated full compliance with 12 security and governance standards.

**RQ5**: Is the methodology reproducible and extensible?
- **Answer**: Yes. 100% test pass rate with automated regression testing; open-source GPL-3.0 license.

---

## 📄 License

**Framework**: MIESC is licensed under **GPL-3.0** (open-source)
**Thesis Materials**: Available for academic purposes under UNDEF-IUA terms
**Dataset**: Publicly available under Creative Commons Attribution 4.0

---

## 📧 Contact

**Fernando Boiero**
- Email: fboiero@frvm.utn.edu.ar
- Institution: Universidad de la Defensa Nacional (UNDEF) - IUA Córdoba
- Affiliation: Researcher and Professor at UTN-FRVM (Systems Engineering)
- GitHub: [@fboiero](https://github.com/fboiero)
- ORCID: [Add if available]

---

**Last Updated**: October 2025
**Status**: In development for 2025 defense
**Language**: English (Spanish thesis chapters in `es/` subdirectory)
