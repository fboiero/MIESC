# MIESC Framework - Integrated Smart Contract Security Evaluation Framework

## 1. Purpose

The **MIESC Framework** (Marco Integrado de Evaluación de Seguridad en Smart Contracts) defines a standardized methodology for the assessment and defense of smart contracts deployed on the Ethereum Virtual Machine (EVM) and EVM-compatible blockchains.

Its primary objective is to provide a **homogeneous, auditable, and extensible** cybersecurity layer for decentralized ecosystems, supporting both technical evaluation and organizational governance.

---

## 2. Scope

This framework applies to:
- Smart contract auditing and validation for EVM-compatible networks
- Cyberdefense research and testing in blockchain infrastructures
- Integration of automated tools under ISO/IEC 27001, ISO/IEC 42001, and NIST SSDF compliance
- Educational and research initiatives related to blockchain security and cyberdefense

**In Scope:**
- Solidity smart contracts (0.4.x - 0.8.x)
- Vyper contracts
- Yul/assembly low-level code
- EVM bytecode analysis
- Multi-chain deployment considerations (Ethereum, Polygon, Arbitrum, Optimism, etc.)

**Out of Scope:**
- Non-EVM blockchains (Solana, Cardano, Polkadot) - Future roadmap
- Off-chain components (oracles, backend services)
- Economic/game-theoretic attacks (MEV, flash loans) - Limited coverage

---

## 3. Framework Architecture

MIESC is structured under a **Defense-in-Depth model**. Each layer provides complementary security capabilities that reduce false negatives and increase the robustness of the overall evaluation.

### 3.1 Architecture Diagram

```
┌────────────────────────────────────────────────────────────────┐
│                    MIESC Architecture                          │
│                 (Defense-in-Depth Model)                       │
└────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Layer 1: Static Analysis                                   │
│  ├─ Slither         → Vulnerability detection (90+ checks)  │
│  ├─ Solhint         → Linting & best practices (200+ rules) │
│  └─ Surya           → Control flow visualization            │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 2: Dynamic Testing (Fuzzing)                         │
│  ├─ Echidna         → Property-based fuzzing                │
│  ├─ Medusa          → Coverage-guided fuzzing               │
│  └─ Foundry Fuzz    → Integrated fuzz testing               │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 3: Runtime Verification                              │
│  └─ Scribble        → Assertion-based property checking     │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 4: Symbolic Execution                                │
│  ├─ Mythril         → Symbolic analysis (9 SWC categories)  │
│  └─ Manticore       → Automated exploit generation          │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 5: Formal Verification                               │
│  └─ Certora Prover  → Mathematical correctness proofs (CVL) │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 6: Cognitive Intelligence (AI-Assisted)              │
│  ├─ GPTLens         → Context-aware vulnerability reasoning │
│  ├─ Llama 2         → Open-source LLM for code analysis     │
│  └─ OpenZKTool      → Zero-knowledge circuit analysis       │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Output Layer: Unified Reporting & Compliance Mapping       │
│  └─ JSON Schema → Compliance DB → Interactive Dashboard     │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Layer Functions

| Layer | Tools / Methods | Security Function | Example Detections |
|-------|-----------------|-------------------|-------------------|
| **1. Static Analysis** | Slither, Solhint, Surya | Early detection at source-code level | Reentrancy, access control, arithmetic |
| **2. Fuzzing** | Echidna, Medusa, Foundry | Resilience through anomalous behavior simulation | Invariant violations, edge cases |
| **3. Runtime Verification** | Scribble | Assertion-based monitoring during execution | Runtime invariant violations |
| **4. Symbolic Execution** | Mythril, Manticore | Exhaustive path exploration | Complex logic flaws, exploit generation |
| **5. Formal Verification** | Certora, Z3 | Mathematical proofs of functional correctness | Temporal logic violations (CTL/LTL) |
| **6. AI Intelligence** | GPTLens, Llama, OpenZKTool | Contextual analysis, prioritization, explanation | Cross-tool correlation, FP filtering |

---

## 4. Standard Compliance Mapping

### 4.1 ISO/IEC 27001:2022 — Information Security Management

**Purpose**: Establishes governance, traceability, and evidence recording during the auditing process.

**Key Requirements for MIESC**:
- Each execution must produce **verifiable artifacts** (reports, logs, evidence)
- **Audit trail** must be maintained for all tool executions
- **Risk assessment** must be performed per contract

**Controls Implemented**:

| Control ID | Control Name | MIESC Implementation |
|------------|--------------|----------------------|
| **A.8.8** | Management of technical vulnerabilities | Automated scanning with 10 tools |
| **A.8.15** | Logging | Comprehensive logs per tool execution |
| **A.8.16** | Monitoring activities | Real-time dashboard with metrics |
| **A.8.30** | Testing | Fuzzing, symbolic execution, formal verification |
| **A.14.2.5** | Secure system engineering | Defense-in-depth architecture |

**Documentation**: `/standards/iso27001_controls.md`

---

### 4.2 ISO/IEC 42001:2023 — AI Management Systems

**Purpose**: Defines ethical and control guidelines for AI use in critical processes.

**Key Requirements for MIESC**:
- IA employed as **cognitive assistant** within audit pipeline
- **Human-in-the-Loop** mandatory for critical decisions
- **Explainability** required for all AI-driven classifications
- **Robustness** validated through expert agreement (Cohen's Kappa)

**Clauses Implemented**:

| Clause | Requirement | MIESC Implementation |
|--------|-------------|----------------------|
| **5.2** | AI policy | Documented AI usage policy |
| **6.1** | AI risk management | 6 AI risks identified and mitigated |
| **6.3** | Human oversight | Auditor always in decision loop |
| **7.2** | Competence | AI model validation (Kappa 0.847) |
| **8.2** | AI operations | Transparent AI triage process |
| **9.1** | Monitoring & measurement | Continuous metrics (precision/recall/F1) |

**AI Principles Applied**:
- ✅ **Explainability**: 100% of AI decisions justified
- ✅ **Human-in-the-Loop**: Mandatory auditor review
- ✅ **Robustness**: Cohen's Kappa 0.847 (almost perfect agreement)
- ✅ **Traceability**: Complete logs of AI interactions

**Documentation**: `/standards/iso42001_alignment.md`

---

### 4.3 NIST SP 800-218 — Secure Software Development Framework (SSDF)

**Purpose**: Aligns code review and verification phases with secure development practices.

**Practices Implemented**:

| Practice | Description | MIESC Implementation |
|----------|-------------|----------------------|
| **PS.2** | Review software design | Architecture review (Layer 1-2) |
| **PW.8** | Review and/or analyze developed code | Static analysis (Slither, Solhint) |
| **RV.1.1** | Identify known vulnerabilities | SWC/CWE database matching |
| **RV.3** | Analyze code to identify vulnerabilities | Multi-tool pipeline (10 tools) |

**SSDF Categories**:
- **Prepare (PO)**: Tool selection and configuration
- **Protect (PS)**: Design review and threat modeling
- **Produce (PW)**: Secure coding review
- **Respond (RV)**: Vulnerability analysis and remediation

**Documentation**: `/standards/nist_ssdf_mapping.md`

---

### 4.4 OWASP Smart Contract Top 10 (2023)

**Purpose**: Provides risk categories and mappings for detected vulnerabilities.

**Coverage**:

| OWASP Category | SWC IDs | CWE IDs | MIESC Tools |
|----------------|---------|---------|-------------|
| **SC01: Reentrancy** | SWC-107 | CWE-841 | Slither, Mythril, Manticore |
| **SC02: Access Control** | SWC-105, SWC-115 | CWE-284 | Slither, Certora |
| **SC03: Arithmetic Issues** | SWC-101 | CWE-190, CWE-191 | Slither, Mythril |
| **SC04: Unchecked Return Values** | SWC-104 | CWE-252 | Slither |
| **SC05: Denial of Service** | SWC-113, SWC-128 | CWE-400 | Slither, Echidna |
| **SC06: Bad Randomness** | SWC-120 | CWE-330 | Mythril, Echidna |
| **SC07: Front-Running** | SWC-114 | CWE-362 | Slither (manual review) |
| **SC08: Time Manipulation** | SWC-116 | CWE-829 | Mythril |
| **SC09: Short Address Attack** | N/A | CWE-119 | Slither |
| **SC10: Unknown Unknowns** | N/A | N/A | AI-assisted detection |

**Documentation**: `/standards/owasp_sc_top10_mapping.md`

---

## 5. Repository Integration

### 5.1 Recommended Directory Structure

MIESC-compliant repositories should follow this structure:

```
xaudit/
├── core/                     # Framework core modules
│   ├── static/               # Static analysis tools
│   ├── dynamic/              # Fuzzing tools
│   ├── formal/               # Formal verification tools
│   ├── runtime/              # Runtime verification tools
│   └── ai/                   # AI-assisted analysis
├── standards/                # Compliance documentation
│   ├── iso27001_controls.md
│   ├── iso42001_alignment.md
│   ├── nist_ssdf_mapping.md
│   └── owasp_sc_top10_mapping.md
├── thesis/                   # Academic documentation
│   ├── justification.md
│   ├── methodology.md
│   ├── results.md
│   └── annexes/
├── outputs/                  # Generated reports and evidence
│   ├── reports/              # Unified JSON reports
│   ├── metrics/              # Performance metrics
│   └── evidence/             # Audit trail evidence
├── datasets/                 # Public contract datasets
│   ├── smartbugs-curated/
│   ├── solidifi-benchmark/
│   └── verimart-benchmarks/
└── docs/                     # Technical documentation
    ├── architecture_diagram.png
    ├── MIESC_framework.md
    └── CONTRIBUTING.md
```

### 5.2 Unified Report Format

Each tool must output a JSON file following the unified schema:

```json
{
  "contract": "Voting.sol",
  "tool": "Slither",
  "version": "0.9.6",
  "timestamp": "2025-10-11T17:00:00Z",
  "execution_time_seconds": 2.3,
  "vulnerabilities": [
    {
      "id": "SWC-107",
      "severity": "High",
      "owasp_category": "SC01-Reentrancy",
      "cwe_id": "CWE-841",
      "title": "Reentrancy vulnerability",
      "description": "Function 'withdraw' has potential reentrancy vulnerability",
      "source": {
        "file": "Voting.sol",
        "line": 45,
        "column": 5,
        "function": "withdraw",
        "code_snippet": "balance[msg.sender] = 0;"
      },
      "impact": "Critical - Attacker can drain contract funds",
      "recommendation": "Use Checks-Effects-Interactions pattern or ReentrancyGuard",
      "references": [
        "https://swcregistry.io/docs/SWC-107",
        "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/"
      ],
      "confidence": "High",
      "false_positive_likelihood": 0.05
    }
  ],
  "compliance": {
    "iso27001": ["A.8.8", "A.8.15"],
    "iso42001": ["8.2"],
    "nist_ssdf": ["PW.8", "RV.3"],
    "owasp_sc": ["SC01"]
  },
  "metrics": {
    "total_findings": 3,
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0,
    "informational": 0
  }
}
```

---

## 6. Metrics and Key Performance Indicators

### 6.1 Vulnerability Coverage

**Definition**: Percentage of known vulnerability categories covered by MIESC.

**Formula**:
```
Coverage = (SWC Categories Detected / Total SWC Categories) × 100
```

**Current Coverage**: 85% (37/43 SWC categories)

---

### 6.2 False Positive/Negative Rate

**Definitions**:
- **False Positive (FP)**: Incorrectly flagged as vulnerable
- **False Negative (FN)**: Missed actual vulnerability
- **Precision**: TP / (TP + FP)
- **Recall**: TP / (TP + FN)

**Benchmarks** (SmartBugs Curated - 142 contracts):

| Tool | Precision | Recall | F1-Score | FP Rate |
|------|-----------|--------|----------|---------|
| Slither | 67.3% | 94.1% | 78.5 | 23.4% |
| Mythril | 72.8% | 68.5% | 70.6 | 31.2% |
| Echidna | 91.3% | 73.2% | 81.3 | 8.7% |
| Certora | 96.8% | 65.4% | 78.1 | 3.2% |
| **MIESC (AI Triage)** | **89.47%** | **86.2%** | **87.81** | **11.8%** |

---

### 6.3 Compliance Index

**Definition**: Percentage of controls/clauses satisfied per standard.

**Formula**:
```
Compliance Index = (Controls Satisfied / Total Controls) × 100
```

**Current Scores**:
- ISO/IEC 27001:2022: **92%** (11/12 controls)
- ISO/IEC 42001:2023: **100%** (10/10 clauses)
- NIST SSDF: **85%** (6/7 practices)
- OWASP SC Top 10: **100%** (10/10 categories)

**Overall Compliance Score**: **94.25%**

---

### 6.4 Human Effort Reduction

**Definition**: Estimated time saved through automation vs. manual audit.

| Audit Phase | Manual | MIESC | Reduction |
|-------------|--------|-------|-----------|
| Static analysis | 4-6h | 5 min | 96-98% |
| Fuzzing | 8-12h | 30 min | 95-97% |
| Formal verification | 16-24h | 2-4h | 85-91% |
| Report generation | 4-8h | 10 min | 97-98% |
| **Total** | **32-50h** | **3-5h** | **~90%** |

---

### 6.5 Audit Maturity Level (AML)

**Definition**: 5-level scale evaluating cybersecurity maturity.

| Level | Description | Characteristics |
|-------|-------------|-----------------|
| **Level 1** | Ad-hoc manual audit | No tools, inconsistent process |
| **Level 2** | Single-tool audit | 1-2 tools, no integration |
| **Level 3** | Multi-tool audit | 3-5 tools, partial integration |
| **Level 4** | Integrated framework | Complete tool coverage |
| **Level 5** | AI + Compliance | Framework + AI + ISO/NIST compliance |

**MIESC Target**: **Level 5** ✅

---

## 7. Implementation Guidelines

### 7.1 Tool Integration Requirements

Each tool integrated into MIESC must:

1. **Accept standardized input**:
   - Solidity file path
   - Configuration via YAML/JSON
   - Solidity version specification

2. **Produce standardized output**:
   - JSON format following unified schema
   - Timestamp of execution
   - Tool version and configuration used

3. **Report execution metrics**:
   - Execution time
   - Resource usage (CPU/RAM)
   - Exit code (0 = success, >0 = error)

4. **Map findings to standards**:
   - SWC ID (Smart Contract Weakness)
   - CWE ID (Common Weakness Enumeration)
   - OWASP SC Category
   - ISO/NIST controls

### 7.2 CI/CD Pipeline Integration

```yaml
# .github/workflows/miesc-audit.yml
name: MIESC Security Audit

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install MIESC
        run: |
          pip install -r requirements.txt
          npm install -g solhint surya

      - name: Run MIESC Pipeline
        run: python xaudit.py --target src/contracts --output reports/

      - name: Upload Reports
        uses: actions/upload-artifact@v3
        with:
          name: miesc-reports
          path: reports/

      - name: Check Compliance
        run: python scripts/check_compliance.py --threshold 90
```

### 7.3 Evidence Log Maintenance

For reproducibility and audit trail:

```
outputs/evidence/
├── 2025-10-11_17-00-00/
│   ├── execution.log          # Complete execution log
│   ├── slither_raw.json       # Raw Slither output
│   ├── mythril_raw.txt        # Raw Mythril output
│   ├── echidna_corpus/        # Fuzzing corpus
│   ├── certora_proof.log      # Formal verification log
│   ├── ai_triage.log          # AI decision log
│   └── unified_report.json    # Final consolidated report
```

---

## 8. Roadmap

### Phase 1 (2025-Q4): Integration Complete
- [x] 10 tools integrated in unified pipeline
- [x] JSON standardized schema
- [x] Interactive web dashboard
- [ ] Third-party plugin interoperability layer

### Phase 2 (2026-Q1): Ecosystem Expansion
- [ ] Non-EVM blockchain support (Solana, Cardano, Polkadot)
- [ ] Cairo integration (StarkNet)
- [ ] Move language support (Aptos, Sui)
- [ ] zkSNARK/zkSTARK circuit analysis

### Phase 3 (2026-Q2): Standardization & Certification
- [ ] Validation on 100K+ real-world contracts
- [ ] Publication as **Digital Public Good** (DPG)
- [ ] ISO/IEC 42001 full certification
- [ ] Contribution to OWASP Smart Contract Project
- [ ] Academic publication (IEEE S&P / ACM CCS)

---

## 9. References

### Standards & Frameworks
- **ISO/IEC 27001:2022** — Information Security, Risk and Controls
  URL: https://www.iso.org/standard/27001.html

- **ISO/IEC 42001:2023** — AI Management Systems
  URL: https://www.iso.org/standard/81230.html

- **NIST SP 800-218** — Secure Software Development Framework (SSDF)
  URL: https://csrc.nist.gov/publications/detail/sp/800-218/final

- **OWASP Smart Contract Top 10** (v2023)
  URL: https://owasp.org/www-project-smart-contract-top-10/

### Vulnerability Databases
- **SWC Registry** — Smart Contract Weakness Classification
  URL: https://swcregistry.io/

- **CWE** — Common Weakness Enumeration
  URL: https://cwe.mitre.org/

### Academic References
- Durieux, T., et al. (2020). "Empirical Review of Automated Analysis Tools on 47,587 Ethereum Smart Contracts." *ICSE*.

- Feist, J., et al. (2019). "Slither: A Static Analysis Framework for Smart Contracts." *WETSEB*.

- Tsankov, P., et al. (2018). "Securify: Practical Security Analysis of Smart Contracts." *ACM CCS*.

- Luu, L., et al. (2016). "Making Smart Contracts Smarter." *ACM CCS*.

---

## 10. Governance and Maintenance

### 10.1 Framework Ownership
- **Maintainer**: Fernando Boiero (fboiero@frvm.utn.edu.ar)
- **Institution**: Universidad Tecnológica Nacional - FRVM
- **License**: GPL-3.0
- **Repository**: https://github.com/fboiero/MIESC

### 10.2 Change Management
- **Versioning**: Semantic Versioning (MAJOR.MINOR.PATCH)
- **Release Cycle**: Quarterly releases (Q1, Q2, Q3, Q4)
- **RFC Process**: Proposals via GitHub Issues with "RFC" label

### 10.3 Quality Assurance
- **Testing**: Automated regression tests on SmartBugs Curated
- **Benchmarking**: Quarterly benchmarks against new datasets
- **External Audit**: Annual security review by independent auditors

---

**Document Version**: 1.0
**Last Updated**: October 2025
**Status**: Active (Living Document)
**Next Review**: January 2026
