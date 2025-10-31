# MASTER'S THESIS IN CYBER DEFENSE

## DEVELOPMENT OF A FRAMEWORK FOR SECURITY EVALUATION OF SMART CONTRACTS ON THE ETHEREUM VIRTUAL MACHINE USING ARTIFICIAL INTELLIGENCE

**Universidad de la Defensa Nacional (UNDEF - National Defense University)**
**Centro Regional Universitario Córdoba - IUA**
**Master's in Cyber Defense**
**Author:** Fernando Boiero
**Year:** 2025

---

## TABLE OF CONTENTS

### MAIN CHAPTERS

1. **[INTRODUCTION](./chapter1_introduction.md)**
   - 1.1 General Context
   - 1.2 Current Problems
   - 1.3 Research Hypothesis
   - 1.4 Objectives
   - 1.5 Scope
   - 1.6 Justification
   - 1.7 Document Structure

2. **[CYBER DEFENSE FRAMEWORK](./chapter2_cyberdefense.md)**
   - 2.1 Cyber Defense in Decentralized Environments
   - 2.2 Normative References (ISO/IEC 27001, 42001, NIST, OWASP)
   - 2.3 Defense-in-Depth Strategies
   - 2.4 Ethical and Regulatory Considerations
   - 2.5 Alignment with National Strategies

3. **[TECHNICAL THEORETICAL FRAMEWORK](./chapter3_theoretical.md)**
   - 3.1 EVM Architecture
   - 3.2 Evolution of ERC Standards
   - 3.3 Security Patterns and Vulnerabilities
   - 3.4 Audit Frameworks
   - 3.5 SWC and CWE Classification

4. **[STATE OF THE ART IN TOOLS](./chapter4_state_of_art.md)**
   - 4.1 Static Analysis (Slither)
   - 4.2 Fuzzing (Echidna, Medusa)
   - 4.3 Advanced Testing (Foundry)
   - 4.4 Runtime Verification (Scribble)
   - 4.5 Formal Verification (Certora)
   - 4.6 Comparison and Limitations

5. **[PROPOSED METHODOLOGY - XAUDIT](./chapter5_methodology.md)**
   - 5.1 Framework Overview
   - 5.2 Hybrid Analysis Pipeline
   - 5.3 System Architecture
   - 5.4 Artificial Intelligence Module
   - 5.5 CI/CD Integration
   - 5.6 Report Format

6. **[IMPLEMENTATION AND EXPERIMENTS](./chapter6_implementation.md)**
   - 6.1 Experimental Environment
   - 6.2 Contract Dataset
   - 6.3 Tool Configuration
   - 6.4 Pipeline Execution
   - 6.5 Evaluation Metrics
   - 6.6 Experimental Design

7. **[RESULTS AND ANALYSIS](./chapter7_results.md)**
   - 7.1 Experiment 1 Results: Slither
   - 7.2 Experiment 2 Results: Comparative Fuzzing
   - 7.3 Experiment 3 Results: Hybrid Pipeline
   - 7.4 Experiment 4 Results: AI Impact
   - 7.5 Experiment 5 Results: Certora
   - 7.6 Experiment 6 Results: Real Cases
   - 7.7 Critical Case Analysis
   - 7.8 Hypothesis Validation

8. **[CONCLUSIONS AND FUTURE WORK](./chapter8_conclusions.md)**
   - 8.1 Main Hypothesis Evaluation
   - 8.2 Objective Achievement
   - 8.3 Research Contributions
   - 8.4 Model Limitations
   - 8.5 Future Work
   - 8.6 Impact on Cyber Defense

### APPENDICES

- **[APPENDIX A - Analyzed Contracts](./appendix_a_contracts.md)**
  - Complete source code of vulnerable contracts
  - Classification by vulnerability type (SWC)
  - Synthetic exploits

- **[APPENDIX B - CI/CD Configuration](./appendix_b_cicd.md)**
  - GitHub Actions workflows
  - Automation scripts
  - Runner configuration

- **[APPENDIX C - Properties and Scripts](./appendix_c_properties.md)**
  - Scribble annotations
  - Echidna properties
  - Certora specifications (CVL)

- **[APPENDIX D - Experimental Results](./appendix_d_data.md)**
  - Complete results tables
  - Raw data (JSON/CSV)
  - Charts and visualizations

- **[APPENDIX E - AI Module Source Code](./appendix_e_ai_code.md)**
  - Complete AI assistant implementation
  - Prompts used
  - Classification strategies

---

## EXECUTIVE SUMMARY

This thesis develops **Xaudit**, an automated framework for security evaluation of smart contracts on the Ethereum Virtual Machine (EVM). The research integrates static analysis techniques (Slither), property-based fuzzing (Echidna) and coverage-guided (Medusa), differential testing (Foundry), formal verification (Certora), and artificial intelligence for vulnerability triage and classification.

### Problem Statement
Manual smart contract audits are expensive (USD $50,000-$500,000), slow (4-8 weeks), and prone to human error. Individual tools generate high volumes of false positives (>50%) without contextual prioritization.

### Hypothesis
A hybrid pipeline combining multiple analysis techniques with AI assistance significantly improves critical vulnerability detection (+30%), reduces false positives (-40%), and decreases analysis time (-95%) compared to traditional methods.

### Methodology
- **Paradigm:** Quantitative experimental
- **Dataset:** 30+ ad-hoc designed vulnerable contracts + 20 real cases
- **Metrics:** Precision, Recall, F1-Score, analysis time, coverage
- **References:** ISO/IEC 27001:2022, ISO/IEC 42001:2023, NIST SSDF, OWASP SCSVS

### Main Results
1. **Improved detection:** Hybrid pipeline detects 34% more vulnerabilities than Slither alone
2. **FP reduction:** AI reduces false positives by 43% through contextual classification
3. **Time efficiency:** Complete analysis in <2 hours vs. 4-8 weeks manual
4. **Coverage:** 94.7% code coverage through coverage-guided fuzzing
5. **Open-source:** Framework published for academic and industrial use

### Contributions
1. **Scientific:** First complete integration of static, dynamic, formal analysis and AI for EVM
2. **Practical:** Reduction of preliminary audit costs by >90%
3. **Educational:** Teaching material for smart contract security education
4. **Strategic:** Tool for protecting critical blockchain infrastructure

---

## KEYWORDS

Smart Contracts, Ethereum, EVM, Cyber Defense, Security, Audit, Static Analysis, Fuzzing, Formal Verification, Artificial Intelligence, Slither, Echidna, Medusa, Foundry, Certora, DevSecOps, ISO 27001, ISO 42001, NIST SSDF, DeFi

---

## ALIGNMENT WITH MASTER'S IN CYBER DEFENSE

This research aligns with the thematic axes of the Master's in Cyber Defense at UNDEF - IUA Córdoba:

1. **System Security:** Vulnerability analysis in decentralized systems
2. **Applied Cryptography:** Cryptographic foundations of blockchain and smart contracts
3. **Risk Management:** Risk evaluation and prioritization framework
4. **Norms and Regulations:** Alignment with ISO 27001, ISO 42001, NIST
5. **Applied Research:** Development of open-source tool with experimental validation

---

## COMPLETION STATUS

| Chapter | Status | Progress |
|---------|--------|----------|
| Chapter 1 - Introduction | ✅ Complete (Spanish) | 100% |
| Chapter 2 - Cyber Defense Framework | ✅ Complete (Spanish) | 100% |
| Chapter 3 - Theoretical Framework | ✅ Complete (Spanish) | 100% |
| Chapter 4 - State of the Art | ✅ Complete (Spanish) | 100% |
| Chapter 5 - Methodology | ✅ Complete (Spanish) | 100% |
| Chapter 6 - Implementation | ✅ Complete (Spanish) | 100% |
| Chapter 7 - Results | ✅ Complete (Spanish) | 100% |
| Chapter 8 - Conclusions | ✅ Complete (Spanish) | 100% |
| **English Translation** | 📝 Pending | 0% |

**Note:** All chapters are complete in Spanish. English translations are planned for future work.

---

**Universidad de la Defensa Nacional (UNDEF)**
**Centro Regional Universitario Córdoba - IUA**
**Master's in Cyber Defense**
**2025**
