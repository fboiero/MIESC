# NIST SSDF Mapping for MIESC

## Overview

**Standard**: NIST SP 800-218 - Secure Software Development Framework (SSDF)
**Purpose**: Map MIESC practices to NIST secure development lifecycle
**MIESC Version**: 2.0
**Last Updated**: October 2025

---

## SSDF Practice Groups

### PO - Prepare the Organization

#### PO.3.1 - Ensure Acquisition of Genuine Software

**MIESC Implementation**:
- Verification of tool authenticity via checksums
- Use of official package repositories (PyPI, npm, Homebrew)
- Dependency integrity checking via `requirements.txt`

**Evidence**: `requirements.txt`, tool installation scripts

**Compliance**: ✅ Implemented

---

### PS - Protect the Software

#### PS.2 - Review the Software Design

**MIESC Implementation**:
- **Layer 1 (Static Analysis)**: Slither architecture review
- **Layer 3 (Runtime)**: Scribble specification review
- **Layer 5 (Formal)**: Certora formal specification (CVL)

**Evidence**: `/core/static/`, `/core/formal/`

**Compliance**: ✅ Implemented

---

### PW - Produce Well-Secured Software

#### PW.8 - Review and/or Analyze Developed Code

**MIESC Implementation**:
- **Automated Code Review**: Slither (90+ detectors), Solhint (200+ rules)
- **Symbolic Analysis**: Mythril, Manticore
- **AI-Assisted Review**: GPTLens context-aware analysis

**Evidence**: `/outputs/reports/`, unified JSON schema

**Compliance**: ✅ Implemented

---

### RV - Respond to Vulnerabilities

#### RV.1.1 - Identify Publicly Disclosed Vulnerabilities in Software Components

**MIESC Implementation**:
- **SWC Registry Integration**: Mapping to 37 known smart contract weaknesses
- **CWE Database**: Cross-reference to Common Weakness Enumeration
- **OWASP SC Top 10**: Coverage of all 10 categories

**Evidence**: `/standards/owasp_sc_top10_mapping.md`

**Compliance**: ✅ Implemented

---

#### RV.3 - Analyze Identified Vulnerabilities to Determine their Root Causes

**MIESC Implementation**:
- **Multi-Tool Correlation**: Cross-tool validation of findings
- **AI Root Cause Analysis**: GPTLens generates explanations
- **Symbolic Execution**: Mythril/Manticore trace vulnerability paths

**Evidence**: AI triage reports with root cause analysis

**Compliance**: ✅ Implemented

---

## Practice Mapping Summary

| Practice ID | Practice Name | MIESC Layer | Compliance |
|-------------|---------------|-------------|------------|
| **PO.3.1** | Acquire genuine software | All | ✅ Implemented |
| **PS.2** | Review software design | Layer 1, 3, 5 | ✅ Implemented |
| **PW.8** | Analyze code | Layer 1, 4, 6 | ✅ Implemented |
| **RV.1.1** | Identify known vulnerabilities | All layers | ✅ Implemented |
| **RV.3** | Analyze root causes | Layer 4, 6 | ✅ Implemented |

**Overall NIST SSDF Compliance**: **100%** (5/5 relevant practices)

---

## Detailed Practice Implementation

### PW.8 - Code Review & Analysis

**NIST Requirement**: *"Analyze the code to find vulnerabilities and verify compliance with security requirements"*

**MIESC Multi-Layer Approach**:

| SSDF Sub-Practice | MIESC Implementation | Tools Used |
|-------------------|----------------------|------------|
| **Static analysis** | Automated source code scanning | Slither, Solhint, Surya |
| **Dynamic analysis** | Runtime behavior testing | Echidna, Medusa, Foundry |
| **Symbolic execution** | Path exploration | Mythril, Manticore |
| **Formal verification** | Mathematical proofs | Certora Prover |
| **Manual review** | AI-assisted human analysis | GPTLens + Human expert |

**Outputs**:
- Unified JSON reports with SWC/CWE/OWASP mappings
- Severity classification (Critical/High/Medium/Low/Info)
- Remediation recommendations
- Compliance checklist

---

### RV.1.1 - Known Vulnerability Identification

**Vulnerability Databases Integrated**:

| Database | Coverage | MIESC Integration |
|----------|----------|-------------------|
| **SWC Registry** | 37 smart contract weaknesses | Direct mapping in JSON output |
| **CWE** | 900+ software weaknesses | Cross-reference via SWC→CWE |
| **OWASP SC Top 10** | 10 critical categories | 100% coverage |
| **CVE** | Specific tool vulnerabilities | Tool version tracking |

**Evidence**: `/outputs/reports/*.json` → `"id": "SWC-107", "cwe_id": "CWE-841"`

---

## Integration with ISO Standards

### Alignment with ISO/IEC 27001:2022

| NIST SSDF Practice | ISO 27001 Control | Relationship |
|--------------------|-------------------|--------------|
| PO.3.1 | A.5.9 (Asset inventory) | Direct mapping |
| PS.2 | A.14.2.5 (Secure engineering) | Direct mapping |
| PW.8 | A.8.8 (Vulnerability management) | Direct mapping |
| RV.1.1 | A.8.8 (Vulnerability management) | Direct mapping |
| RV.3 | A.8.16 (Monitoring) | Indirect mapping |

---

## Integration with ISO/IEC 42001:2023

**AI-Specific Practices**:
- **PW.8 + AI**: GPTLens for code review assistance
- **RV.3 + AI**: Root cause analysis via LLM reasoning
- **ISO 42001 Clause 8.2**: AI operations governance

**Human-in-the-Loop Requirement**: All AI-assisted findings require human validation before final classification.

---

## Recommendations

1. **Enhance RV.2**: Implement automated remediation suggestions
2. **Add PO.1**: Define secure development lifecycle for smart contracts
3. **Expand PS.1**: Create threat models for common DeFi patterns

---

## References

- NIST SP 800-218: Secure Software Development Framework
  https://csrc.nist.gov/publications/detail/sp/800-218/final
- SWC Registry: https://swcregistry.io/
- CWE: https://cwe.mitre.org/
- OWASP SC Top 10: https://owasp.org/www-project-smart-contract-top-10/

---

**Document Version**: 1.0
**Maintained By**: Fernando Boiero (fboiero@frvm.utn.edu.ar)
**Review Cycle**: Quarterly
