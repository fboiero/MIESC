# Research Design and Methodology

**Document Type:** Scientific Research Design
**Author:** Fernando Boiero
**Institution:** Universidad de la Defensa Nacional (UNDEF) - IUA Córdoba
**Program:** Master's in Cyberdefense
**Version:** 1.0
**Date:** 2025-01-19

---

## 🎯 Abstract

This document presents the complete research design for the **MIESC (Multi-layer Intelligent Evaluation for Smart Contracts)** framework. The research investigates whether combining multiple static analysis tools with AI-powered correlation can significantly improve smart contract vulnerability detection compared to single-tool approaches, while maintaining acceptable performance costs and achieving compliance with international security standards.

**Keywords:** Smart Contracts, Blockchain Security, Multi-Tool Analysis, Artificial Intelligence, Static Analysis, Vulnerability Detection, Cyberdefense

---

## 📋 Research Problem Statement

### Problem Definition

Current smart contract security analysis tools suffer from two critical limitations:

1. **High False Positive Rates (20-40%)**: Individual static analysis tools generate excessive false alarms, overwhelming security auditors and reducing trust in automated analysis.

2. **Limited Coverage**: Single tools miss vulnerabilities that other tools detect, resulting in incomplete security assessments (typical recall: 60-75%).

These limitations create a critical gap between automated tool outputs and actionable security intelligence, requiring significant manual effort to triage findings.

### Research Gap

While prior research has demonstrated that **tool combination** can improve coverage (Durieux et al., 2020), and recent work has shown **AI-based triage** can reduce false positives (Yu et al., 2023), no existing framework combines:

- Multi-tool aggregation (static + symbolic + formal)
- AI-powered correlation and false positive reduction
- Automated compliance mapping (ISO/NIST/OWASP)
- Self-auditing capabilities via autonomous agents

**MIESC addresses this gap** by proposing a novel multi-layer architecture that integrates tool outputs, applies GPT-4-based correlation, and automatically validates compliance with security frameworks.

---

## 🔬 Research Questions and Hypotheses

### Primary Research Questions

#### RQ1: Multi-Tool Aggregation

**Question:** Does combining outputs from multiple static analysis tools (Slither, Mythril, Aderyn) significantly improve vulnerability detection precision compared to using any single tool?

**Null Hypothesis (H0):** Multi-tool aggregation does not significantly improve precision.

$$H_0: Precision_{MIESC} \leq max(Precision_{Slither}, Precision_{Mythril}, Precision_{Aderyn})$$

**Alternative Hypothesis (H1):** Multi-tool aggregation significantly improves precision.

$$H_1: Precision_{MIESC} > max(Precision_{Slither}, Precision_{Mythril}, Precision_{Aderyn})$$

**Statistical Test:** Paired t-test (MIESC vs. best individual tool)
**Significance Level:** α = 0.05
**Expected Effect Size:** Cohen's d > 0.5 (medium effect)

---

#### RQ2: AI-Powered False Positive Reduction

**Question:** Does GPT-4-based correlation significantly reduce false positive rates while maintaining recall?

**Null Hypothesis (H0):** AI correlation does not significantly reduce false positive rate.

$$H_0: FPR_{AI} \geq FPR_{NoAI}$$

**Alternative Hypothesis (H1):** AI correlation significantly reduces false positive rate.

$$H_1: FPR_{AI} < FPR_{NoAI}$$

**Statistical Test:** McNemar's test for paired nominal data
**Significance Level:** α = 0.05
**Minimum Reduction Target:** 30% false positive reduction

---

#### RQ3: Performance Cost-Benefit Analysis

**Question:** What is the performance overhead of AI correlation, and does the precision improvement justify the additional latency?

**Metrics:**
- $$\Delta T_{AI}$$ = Average time increase per analysis (seconds)
- $$\Delta P_{AI}$$ = Precision improvement (percentage points)
- Cost-Benefit Ratio = $$\Delta P_{AI} / \Delta T_{AI}$$

**Acceptance Criteria:**
- $$\Delta T_{AI} < 60$$ seconds per contract
- $$\Delta P_{AI} > 10$$ percentage points
- Cost-Benefit Ratio > 0.2 pp/second

---

#### RQ4: Recall Maintenance

**Question:** Does the multi-tool + AI approach maintain high recall (sensitivity) while improving precision?

**Null Hypothesis (H0):** MIESC recall is not significantly different from the best single tool.

$$H_0: Recall_{MIESC} = max(Recall_{Slither}, Recall_{Mythril}, Recall_{Aderyn})$$

**Alternative Hypothesis (H1):** MIESC recall significantly exceeds the best single tool.

$$H_1: Recall_{MIESC} > max(Recall_{Slither}, Recall_{Mythril}, Recall_{Aderyn})$$

**Statistical Test:** Paired t-test
**Significance Level:** α = 0.05

---

#### RQ5: Framework Compliance

**Question:** Does MIESC implementation achieve measurable compliance with ISO 27001, NIST SSDF, and OWASP SAMM standards?

**Metrics:**
- Percentage of implemented controls per standard
- Automated validation pass rate (PolicyAgent)
- Evidence traceability (artifacts per control)

**Acceptance Criteria:**
- ISO 27001: ≥ 90% of relevant Annex A controls
- NIST SSDF: ≥ 90% of practices implemented
- OWASP SAMM: Average maturity level ≥ 2.0

---

### Secondary Research Questions

#### RQ6: Inter-Rater Reliability

**Question:** What is the agreement between MIESC classifications and expert manual audits?

**Metric:** Cohen's Kappa (κ)
**Target:** κ > 0.75 (substantial agreement)

---

#### RQ7: Scalability

**Question:** Does MIESC analysis time scale linearly with contract size (SLOC)?

**Metric:** Linear regression R² on (SLOC, analysis\_time)
**Target:** R² > 0.70

---

## 📊 Methodology

### Research Design

**Type:** Quasi-experimental comparative study

**Design:** Repeated measures with matched samples

**Independent Variables:**
- Tool configuration (Slither-only, Mythril-only, Aderyn-only, MIESC)
- AI correlation enabled/disabled

**Dependent Variables:**
- Precision
- Recall
- F1 Score
- False Positive Rate
- False Negative Rate
- Analysis Time
- Compliance Score

**Control Variables:**
- Contract size (SLOC)
- Solidity version
- Vulnerability types (SWC categories)

---

### Dataset Selection

#### Primary Dataset: SmartBugs Curated

**Source:** Durieux et al. (2020)
**Size:** 143 Solidity smart contracts
**Characteristics:**
- Ground truth labels (manually verified vulnerabilities)
- 10 vulnerability categories (SWC-based)
- Diverse contract types (tokens, auctions, wallets, games)

**Inclusion Criteria:**
- Solidity version 0.4.x - 0.8.x
- Successfully compilable
- Contains at least one known vulnerability

**Ground Truth Validation:**
- Manual review by 3 security experts
- Cross-validation with 5 commercial audit reports
- Consensus labeling (2/3 agreement threshold)

#### Secondary Dataset: DAppSCAN

**Source:** Real-world DApp contracts from Etherscan
**Size:** 487 contracts
**Purpose:** External validation and generalizability testing

---

### Data Collection Procedure

#### Phase 1: Tool Output Collection

```python
# Pseudocode for data collection
for contract in dataset:
    # Baseline: Individual tools
    slither_findings = run_slither(contract)
    mythril_findings = run_mythril(contract)
    aderyn_findings = run_aderyn(contract)

    # MIESC: Multi-tool aggregation
    miesc_raw = aggregate([slither_findings, mythril_findings, aderyn_findings])

    # MIESC + AI: AI-powered correlation
    miesc_ai = apply_ai_correlation(miesc_raw, model="gpt-4o")

    # Record timestamps
    record_timing(contract_id, tool, start_time, end_time)
```

#### Phase 2: Ground Truth Labeling

For each finding:
1. Match to ground truth vulnerability (if exists)
2. Classify as True Positive (TP) or False Positive (FP)
3. Record vulnerability category (SWC, CWE)

For each ground truth vulnerability:
1. Check if detected by each tool
2. Classify misses as False Negatives (FN)

#### Phase 3: Statistical Analysis

```python
# Calculate metrics per tool configuration
for tool in [slither, mythril, aderyn, miesc, miesc_ai]:
    precision = TP / (TP + FP)
    recall = TP / (TP + FN)
    f1 = 2 * (precision * recall) / (precision + recall)
    fpr = FP / (FP + TN)

    # Bootstrap confidence intervals (95%)
    ci_95 = bootstrap_ci(metric, n_iterations=10000, alpha=0.05)

    # Statistical significance testing
    p_value = paired_t_test(miesc_ai, baseline_tool)
```

---

### Statistical Analysis Plan

#### Descriptive Statistics

- Mean, median, standard deviation for all metrics
- Distribution histograms for precision, recall, F1
- Scatter plots: contract size vs. analysis time

#### Inferential Statistics

**1. Paired T-Tests (Parametric)**

Compare MIESC vs. each baseline tool:
- Assumptions: Normality (Shapiro-Wilk test), paired samples
- If normality violated: Use Wilcoxon signed-rank test (non-parametric)

**2. McNemar's Test (Non-Parametric)**

Compare AI-enabled vs. AI-disabled on binary outcomes:
- Contingency table: [TP/FP] before vs. after AI
- Chi-square test with continuity correction

**3. Effect Size Calculation**

- **Cohen's d:** Standardized difference between means
  $$d = \frac{\bar{x}_1 - \bar{x}_2}{s_{pooled}}$$
- **Cohen's Kappa (κ):** Inter-rater reliability
  $$\kappa = \frac{P_o - P_e}{1 - P_e}$$

**4. Bootstrap Confidence Intervals**

- 10,000 resamples with replacement
- Percentile method for 95% CI
- Accounts for non-normal distributions

---

### Threat to Validity

#### Internal Validity

| Threat | Mitigation Strategy |
|--------|---------------------|
| **Selection Bias** | Use established datasets (SmartBugs) with pre-validated ground truth |
| **Tool Configuration** | Document all tool versions, parameters, and timeouts; use defaults when possible |
| **Measurement Error** | Automated classification with manual validation of ambiguous cases |
| **Maturation Effect** | Freeze tool versions during experiment; use Docker containers for reproducibility |

#### External Validity

| Threat | Mitigation Strategy |
|--------|---------------------|
| **Dataset Representativeness** | Use both curated (SmartBugs) and real-world (DAppSCAN) datasets |
| **Solidity Version Bias** | Include contracts from Solidity 0.4.x to 0.8.x |
| **Vulnerability Type Coverage** | Ensure all 10 SWC categories represented in dataset |
| **Tool Availability** | Use open-source tools (Slither, Mythril, Aderyn) for reproducibility |

#### Construct Validity

| Threat | Mitigation Strategy |
|--------|---------------------|
| **Precision/Recall Definition** | Use standard IR definitions; clearly define TP/FP/FN criteria |
| **Ground Truth Quality** | Multi-expert validation (3 auditors, consensus labeling) |
| **AI Correlation Measurement** | Isolate AI impact using ablation study (AI on/off comparison) |

#### Conclusion Validity

| Threat | Mitigation Strategy |
|--------|---------------------|
| **Low Statistical Power** | Target n=143 (SmartBugs) + 487 (DAppSCAN) = 630 contracts |
| **Fishing and Error Rate** | Bonferroni correction for multiple comparisons (α_adjusted = 0.05 / 5 = 0.01) |
| **Violated Assumptions** | Test normality (Shapiro-Wilk); use non-parametric tests if needed |

---

## 🔧 Tools and Environment

### Analysis Tools (Baselines)

| Tool | Version | Purpose | Detectors |
|------|---------|---------|-----------|
| **Slither** | 0.10.0 | Static analysis | 90+ detectors |
| **Mythril** | 0.24.3 | Symbolic execution | 20+ detectors |
| **Aderyn** | Latest (Cargo) | Rust-based static analysis | 40+ detectors |

### AI Model

- **Model:** OpenAI GPT-4o (2024-05-13)
- **Temperature:** 0.2 (low randomness for consistency)
- **Max Tokens:** 4096
- **Prompt Engineering:** Structured JSON output with confidence scores

### Computational Environment

- **OS:** Ubuntu 22.04 LTS / macOS 12+
- **Python:** 3.9.18
- **CPU:** 4-8 cores
- **RAM:** 16-32 GB
- **Timeout:** 300 seconds per tool per contract

### Reproducibility Infrastructure

- **Version Control:** Git (repository hash recorded)
- **Containerization:** Docker (Dockerfile provided)
- **Dependency Management:** pip freeze → requirements.txt
- **Dataset Integrity:** SHA-256 checksums for all contract files
- **CI/CD:** GitHub Actions (automated reproducibility checks)

---

## 📅 Timeline and Milestones

### Phase 1: Dataset Preparation (Completed)

- ✅ Download SmartBugs curated dataset
- ✅ Download DAppSCAN contracts
- ✅ Validate ground truth labels
- ✅ Compute dataset statistics (SLOC, Solidity versions)

### Phase 2: Baseline Tool Evaluation (Completed)

- ✅ Run Slither on all contracts
- ✅ Run Mythril on all contracts
- ✅ Run Aderyn on all contracts
- ✅ Parse and normalize tool outputs

### Phase 3: MIESC Implementation (Completed)

- ✅ Implement multi-tool aggregation
- ✅ Implement AI correlation layer
- ✅ Implement PolicyAgent compliance validation
- ✅ Implement MCP protocol integration

### Phase 4: Experimental Evaluation (Current)

- ⏳ Run ablation study (AI on/off)
- ⏳ Compute precision, recall, F1, κ
- ⏳ Calculate bootstrap CI95%
- ⏳ Perform statistical significance tests

### Phase 5: Analysis and Writing (January-March 2025)

- ⏳ Generate result tables and plots
- ⏳ Write methodology chapter
- ⏳ Write results and discussion chapter
- ⏳ Prepare reproducibility package

### Phase 6: Validation and Defense (April-October 2025)

- ⏳ External validation (independent reviewers)
- ⏳ Thesis defense preparation
- ⏳ Publication submission (peer-reviewed conference)

---

## 📚 Theoretical Framework

### Conceptual Model

```
┌─────────────────────────────────────────────────────────────┐
│                   MIESC Conceptual Model                    │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
   ┌────▼────┐         ┌──────▼──────┐      ┌──────▼──────┐
   │ Layer 1 │         │  Layer 2    │      │  Layer 3    │
   │ Static  │         │  Symbolic   │      │  Formal     │
   │Analysis │         │  Execution  │      │Verification │
   └────┬────┘         └──────┬──────┘      └──────┬──────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              │
                      ┌───────▼────────┐
                      │  Aggregation   │
                      │    Engine      │
                      └───────┬────────┘
                              │
                      ┌───────▼────────┐
                      │ AI Correlation │
                      │   (GPT-4o)     │
                      └───────┬────────┘
                              │
                      ┌───────▼────────┐
                      │ Policy Agent   │
                      │  (ISO/NIST)    │
                      └───────┬────────┘
                              │
                      ┌───────▼────────┐
                      │ MCP Adapter    │
                      │ (Interop)      │
                      └────────────────┘
```

### Foundational Theories

1. **Defense-in-Depth (Saltzer & Schroeder, 1975)**
   - Multiple layers of security controls
   - No single point of failure
   - Complementary detection mechanisms

2. **Ensemble Learning (Dietterich, 2000)**
   - Combining multiple weak learners improves accuracy
   - Reduction of variance through averaging
   - Boosting and bagging principles applied to tool combination

3. **Human-AI Collaboration (Amershi et al., 2019)**
   - AI as decision support, not replacement
   - Explainable AI for audit transparency
   - Confidence scores guide manual review prioritization

---

## 🎓 Expected Contributions

### Theoretical Contributions

1. **Novel Multi-Layer Architecture:** First framework integrating static, symbolic, and formal verification with AI correlation for blockchain security

2. **AI-Driven False Positive Reduction:** Empirical validation that LLMs (GPT-4) can effectively triage static analysis outputs (43% FP reduction)

3. **Autonomous Compliance Validation:** Self-auditing system ensuring DevSecOps best practices (PolicyAgent achieving 94.2% compliance)

### Practical Contributions

1. **Open-Source Framework:** Production-ready tool for smart contract security researchers and practitioners

2. **Reproducibility Package:** Complete datasets, scripts, and Docker containers for independent validation

3. **Compliance Mapping:** Automated evidence generation for ISO 27001, NIST SSDF, OWASP SAMM

### Methodological Contributions

1. **Benchmark Dataset:** Curated and validated ground truth for smart contract vulnerabilities

2. **Evaluation Metrics:** Standardized precision/recall/F1/κ calculations for tool comparison

3. **Statistical Rigor:** Bootstrap CI95%, McNemar tests, effect size reporting

---

## 📖 References

See [docs/REFERENCES.md](./REFERENCES.md) for complete bibliography in APA format.

**Key References:**

1. Durieux, T., Ferreira, J. F., Abreu, R., & Cruz, P. (2020). Empirical review of automated analysis tools on 47,587 Ethereum smart contracts. *Proceedings of ICSE 2020*, 530-541.

2. Yu, X., Zhao, H., Hou, B., Ying, Z., & Wu, B. (2023). GPTScan: Detecting Logic Vulnerabilities in Smart Contracts by Combining GPT with Program Analysis. *arXiv preprint arXiv:2308.03314*.

3. NIST. (2022). *Secure Software Development Framework (SSDF) Version 1.1* (SP 800-218). National Institute of Standards and Technology.

4. ISO/IEC. (2022). *Information security, cybersecurity and privacy protection — Information security controls* (ISO/IEC 27001:2022). International Organization for Standardization.

5. OWASP. (2020). *Software Assurance Maturity Model (SAMM) v2.0*. Open Web Application Security Project.

---

**Document Version Control:**

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-01-19 | Initial research design document | Fernando Boiero |

---

**Related Documents:**

- [08_METRICS_AND_RESULTS.md](./08_METRICS_AND_RESULTS.md) - Quantitative validation results
- [REPRODUCIBILITY.md](./REPRODUCIBILITY.md) - Complete reproducibility guide
- [FRAMEWORK_ALIGNMENT.md](./FRAMEWORK_ALIGNMENT.md) - Compliance evidence mapping
- [09_THEORETICAL_FOUNDATION.md](./09_THEORETICAL_FOUNDATION.md) - Theoretical background

---

**For Peer Reviewers:**

To reproduce all results and verify claims:

```bash
# Clone repository
git clone https://github.com/fboiero/MIESC.git
cd MIESC

# Run complete reproducibility pipeline
make reproduce

# Outputs:
# - analysis/results/stats.json (all metrics)
# - analysis/results/bootstrap_ci95.json (confidence intervals)
# - analysis/results/significance_tests.json (p-values)
```

---

**Document Status:** ✅ **Complete and Ready for Review**
