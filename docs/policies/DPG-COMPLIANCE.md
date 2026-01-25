# Digital Public Good Compliance Statement

**MIESC - Multi-layer Intelligent Evaluation for Smart Contracts**

[![DPG Standard](https://img.shields.io/badge/DPG%20Standard-v1.1.6-blue)](https://digitalpublicgoods.net/standard/)
[![DPGA Application](https://img.shields.io/badge/DPGA-Under%20Review-yellow)](https://app.digitalpublicgoods.net/a/13478)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

This document demonstrates MIESC's compliance with the [Digital Public Goods Standard](https://github.com/DPGAlliance/DPG-Standard) (v1.1.6) established by the [Digital Public Goods Alliance (DPGA)](https://digitalpublicgoods.net/).

---

## Application Status

| Field | Value |
|-------|-------|
| **Application ID** | GID0092948 |
| **Submission Date** | December 5, 2025 |
| **Status** | Under Review |
| **Expected Review** | 4-8 weeks |
| **Contact** | Bolaji Ayodeji (DPG Evangelist) |

---

## Executive Summary

MIESC is an open-source security analysis framework for smart contracts that advances **SDG 9 (Industry, Innovation and Infrastructure)** and **SDG 16 (Peace, Justice and Strong Institutions)** by providing accessible, transparent cybersecurity tools for blockchain ecosystems.

| Indicator | Status | Evidence |
|-----------|--------|----------|
| 1. SDG Relevance | Compliant | [SDG Alignment](#indicator-1-sdg-relevance) |
| 2. Open Licensing | Compliant | [AGPL-3.0 License](./LICENSE) |
| 3. Clear Ownership | Compliant | [Ownership Statement](#indicator-3-clear-ownership) |
| 4. Platform Independence | Compliant | [Technical Architecture](#indicator-4-platform-independence) |
| 5. Documentation | Compliant | [Documentation](#indicator-5-documentation) |
| 6. Data Extraction | Compliant | [Export Formats](#indicator-6-data-extraction) |
| 7. Privacy & Laws | Compliant | [Privacy Policy](./PRIVACY.md) |
| 8. Standards & Best Practices | Compliant | [Standards Compliance](#indicator-8-standards--best-practices) |
| 9. Do No Harm | Compliant | [Harm Prevention](#indicator-9-do-no-harm) |

---

## Indicator 1: SDG Relevance

### Primary SDG Alignment

**SDG 9: Industry, Innovation and Infrastructure**
- **Target 9.b**: Support domestic technology development, research and innovation in developing countries
- **Contribution**: MIESC democratizes access to enterprise-grade smart contract security tools, enabling developers worldwide to build secure blockchain applications without expensive commercial licenses

**SDG 16: Peace, Justice and Strong Institutions**
- **Target 16.5**: Substantially reduce corruption and bribery in all their forms
- **Target 16.6**: Develop effective, accountable and transparent institutions
- **Contribution**: Automated security verification of smart contracts increases transparency and reduces opportunities for financial fraud in blockchain systems

### Secondary SDG Alignment

**SDG 8: Decent Work and Economic Growth**
- **Target 8.10**: Strengthen the capacity of domestic financial institutions to encourage and expand access to banking, insurance and financial services
- **Contribution**: Secure DeFi protocols enable broader financial inclusion through trustworthy decentralized finance

**SDG 17: Partnerships for the Goals**
- **Target 17.6**: Enhance North-South, South-South and triangular regional and international cooperation on science, technology and innovation
- **Contribution**: Open-source framework enables global collaboration on blockchain security research

### Impact Metrics

| Metric | Value | Evidence |
|--------|-------|----------|
| Tools Integrated | 25 | Multi-tool orchestration reducing barriers to security analysis |
| Compliance Standards | 12 | Automated mapping to ISO/NIST/OWASP standards |
| Detection Accuracy | 94.5% | Empirical validation on SmartBugs dataset |
| False Positive Reduction | 89% | AI-assisted correlation filtering |
| Cost Savings | ~$50,000/audit | Compared to commercial alternatives |

### Use Cases for Development

1. **Government Blockchain Projects**: Security verification for public sector blockchain implementations
2. **DeFi in Emerging Markets**: Enabling secure decentralized finance in underbanked regions
3. **Academic Research**: Reproducible security analysis for blockchain research
4. **NGO Transparency**: Smart contract auditing for charitable donation tracking

---

## Indicator 2: Open Licensing

### License Type

**GNU Affero General Public License v3.0 (AGPL-3.0)**

This license is [OSI-approved](https://opensource.org/licenses/AGPL-3.0) and ensures:
- Freedom to use, study, modify, and distribute
- Network use triggers copyleft (modifications must be shared)
- Derivative works remain open-source
- Commercial use permitted with attribution

### License File

Full license text: [LICENSE](./LICENSE)

### Third-Party Components

All dependencies use compatible open-source licenses:

| Component | License | Compatibility |
|-----------|---------|---------------|
| Slither | AGPL-3.0 | Compatible |
| Mythril | MIT | Compatible |
| Echidna | AGPL-3.0 | Compatible |
| Foundry | MIT/Apache-2.0 | Compatible |
| Halmos | AGPL-3.0 | Compatible |
| Ollama | MIT | Compatible |

---

## Indicator 3: Clear Ownership

### Project Ownership

| Attribute | Value |
|-----------|-------|
| **Project Name** | MIESC - Multi-layer Intelligent Evaluation for Smart Contracts |
| **Copyright Holder** | Fernando Boiero |
| **Institution** | Universidad de la Defensa Nacional (UNDEF), Argentina |
| **Repository** | https://github.com/fboiero/MIESC |
| **Contact** | fboiero@frvm.utn.edu.ar |

### Intellectual Property

- **Source Code**: Copyright 2024-2025 Fernando Boiero, licensed under AGPL-3.0
- **Documentation**: Copyright 2024-2025 Fernando Boiero, licensed under CC-BY-4.0
- **Trademarks**: "MIESC" name and logo owned by Fernando Boiero
- **Patents**: No patents filed; commitment to patent-free development

### Academic Context

MIESC was developed as part of a Master's thesis in Cyberdefense at Universidad de la Defensa Nacional (UNDEF), Argentina. The university supports open-source release of research outputs.

---

## Indicator 4: Platform Independence

### Core Architecture

MIESC is designed for platform independence:

```
┌─────────────────────────────────────────────────┐
│                    MIESC Core                    │
│  (Python 3.9+ - Cross-platform)                 │
├─────────────────────────────────────────────────┤
│  Tool Adapters (Pluggable Architecture)         │
│  - Each tool is optional                        │
│  - Graceful degradation when tools unavailable  │
├─────────────────────────────────────────────────┤
│  Open Standards                                  │
│  - JSON-RPC (MCP Protocol)                      │
│  - SARIF (Static Analysis Results)              │
│  - OpenAPI (REST API)                           │
└─────────────────────────────────────────────────┘
```

### Dependency Analysis

| Dependency | Type | Open Alternative |
|------------|------|------------------|
| Python | Runtime | Open-source (PSF License) |
| Solidity Compiler | Build | Open-source (GPL-3.0) |
| Ollama | AI Inference | Open-source (MIT) |
| PostgreSQL | Database (optional) | Open-source (PostgreSQL License) |
| Docker | Containerization | Open-source (Apache-2.0) |

### No Vendor Lock-in

- **AI Models**: Uses local LLMs (Ollama) by default; no cloud API required
- **Database**: SQLite by default; PostgreSQL optional
- **Cloud Services**: Fully functional offline; no cloud dependencies
- **Proprietary Tools**: Optional integrations (e.g., Certora) not required for core functionality

---

## Indicator 5: Documentation

### Documentation Structure

| Resource | Location | Description |
|----------|----------|-------------|
| User Guide | [docs/](./docs/) | Installation, configuration, usage |
| API Reference | [docs/openapi.yaml](./docs/openapi.yaml) | OpenAPI 3.0 specification |
| Architecture | [docs/01_ARCHITECTURE.md](./docs/01_ARCHITECTURE.md) | System design and components |
| Demo Guide | [docs/03_DEMO_GUIDE.md](./docs/03_DEMO_GUIDE.md) | Step-by-step tutorials |
| Developer Guide | [docs/DEVELOPER_GUIDE.md](./docs/DEVELOPER_GUIDE.md) | Contributing and extending |
| Hosted Docs | [fboiero.github.io/MIESC](https://fboiero.github.io/MIESC) | MkDocs-generated site |

### Quick Start

```bash
# Clone repository
git clone https://github.com/fboiero/MIESC.git
cd MIESC

# Install dependencies
pip install -r requirements.txt

# Run demo
python3 examples/demo_v4.0.py
```

### Multilingual Support

- English: [README.md](./README.md)
- Spanish: [README_ES.md](./README_ES.md)

---

## Indicator 6: Data Extraction

### Export Formats

MIESC supports multiple open, non-proprietary export formats:

| Format | Standard | Use Case |
|--------|----------|----------|
| JSON | RFC 8259 | Machine-readable reports |
| SARIF | OASIS | IDE integration, CI/CD |
| Markdown | CommonMark | Human-readable reports |
| HTML | W3C | Interactive dashboards |
| PDF | ISO 32000 | Formal documentation |
| CSV | RFC 4180 | Spreadsheet analysis |

### Data Portability

```python
from miesc import MiescFramework

auditor = MiescFramework()
report = auditor.analyze("contract.sol")

# Export to multiple formats
report.export("results.json", format="json")
report.export("results.sarif", format="sarif")
report.export("results.md", format="markdown")
report.export("results.csv", format="csv")
```

### No Data Lock-in

- All analysis results exportable in open formats
- No proprietary binary formats
- Full data ownership retained by user
- API access to all internal data structures

---

## Indicator 7: Privacy & Applicable Laws

### Privacy Statement

See full policy: [PRIVACY.md](./PRIVACY.md)

**Key Principles**:
1. **Local Processing**: All analysis runs locally; code never leaves user's machine
2. **No Telemetry**: No usage data collection without explicit consent
3. **Sovereign AI**: Default LLM (Ollama) runs locally; no external API calls
4. **Data Minimization**: Only processes files explicitly provided by user

### Legal Compliance

| Regulation | Compliance | Notes |
|------------|------------|-------|
| GDPR (EU) | Compliant | No personal data processing |
| CCPA (California) | Compliant | No personal data collection |
| Argentina Data Protection Law | Compliant | Local processing only |

### Responsible Disclosure

Security vulnerabilities: fboiero@frvm.utn.edu.ar (response within 48 hours)

---

## Indicator 8: Standards & Best Practices

### Open Standards Adherence

| Standard | Implementation |
|----------|----------------|
| [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) | JSON-RPC interface for AI integration |
| [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) | Static analysis result format |
| [OpenAPI 3.0](https://swagger.io/specification/) | REST API specification |
| [SWC Registry](https://swcregistry.io/) | Vulnerability classification |
| [CWE](https://cwe.mitre.org/) | Common Weakness Enumeration |

### Security Standards Mapping

MIESC maps findings to 12 international standards:
- ISO/IEC 27001:2022
- ISO/IEC 42001:2023 (AI Governance)
- NIST SP 800-218
- OWASP Smart Contract Security
- EU DORA (Digital Operational Resilience)

### Development Best Practices

| Practice | Implementation |
|----------|----------------|
| Version Control | Git with signed commits |
| Code Review | Pull request required |
| Testing | 117 tests, 87.5% coverage |
| CI/CD | GitHub Actions pipeline |
| Security Scanning | Bandit, Semgrep, Snyk |
| Documentation | MkDocs with versioning |

---

## Indicator 9: Do No Harm

### Risk Assessment

| Risk Category | Assessment | Mitigation |
|---------------|------------|------------|
| **Privacy** | Low | Local processing, no data collection |
| **Security** | Low | Tool outputs warnings, doesn't modify code |
| **Misinformation** | Low | Clear disclaimer about limitations |
| **Discrimination** | N/A | Does not process personal data |
| **Economic Harm** | Low | Free tool reduces audit costs |

### Safeguards

1. **Clear Disclaimers**: Documentation states MIESC is a pre-audit triage tool, not a replacement for professional audits
2. **No Automated Fixes**: Does not modify user code; only reports findings
3. **Responsible AI**: Local LLM usage prevents data leakage
4. **Educational Focus**: Includes explanations and remediation guidance

### Content Moderation

Not applicable - MIESC does not host user-generated content or social features.

### Child Safety

Not applicable - MIESC is a developer tool that does not interact with minors.

### Harmful Content

MIESC's AI components are restricted to security analysis and cannot generate:
- Malicious code or exploits (beyond proof-of-concept for educational purposes)
- Harmful content
- Biased outputs

---

## Governance

### Project Governance

See: [GOVERNANCE.md](./GOVERNANCE.md)

- **Maintainer**: Fernando Boiero
- **Decision Process**: RFC-style proposals for major changes
- **Community**: GitHub Discussions for feature requests
- **Code of Conduct**: [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)

### Sustainability Plan

1. **Academic Support**: Continued development as part of ongoing research
2. **Community Contributions**: Open to external contributors
3. **Grant Funding**: Seeking DPGA pathfinder funding
4. **Institutional Adoption**: Partnerships with universities and research institutions

---

## Contact Information

| Role | Contact |
|------|---------|
| **Project Lead** | Fernando Boiero |
| **Email** | fboiero@frvm.utn.edu.ar |
| **Institution** | Universidad de la Defensa Nacional (UNDEF) |
| **GitHub** | https://github.com/fboiero/MIESC |
| **Documentation** | https://fboiero.github.io/MIESC |

---

## Certification Request

This document serves as MIESC's application for recognition as a Digital Public Good under the DPGA Standard v1.1.6.

**Submitted by**: Fernando Boiero
**Date**: December 2024
**Version**: 1.0

---

## References

- [Digital Public Goods Alliance](https://digitalpublicgoods.net/)
- [DPG Standard v1.1.6](https://github.com/DPGAlliance/DPG-Standard)
- [DPGA Submission Guide](https://digitalpublicgoods.net/submission-guide)
- [UN Secretary-General's Roadmap for Digital Cooperation](https://www.un.org/en/content/digital-cooperation-roadmap/)
