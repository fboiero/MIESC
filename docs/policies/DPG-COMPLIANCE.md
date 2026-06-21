# Digital Public Good Compliance Statement

**[Versión en Español](DPG-COMPLIANCE_ES.md)**

**MIESC - Multi-layer Intelligent Evaluation for Smart Contracts**

[![DPG Standard](https://img.shields.io/badge/DPG%20Standard-v1.1.6-blue)](https://digitalpublicgoods.net/standard/)
[![DPGA Application](https://img.shields.io/badge/DPGA-Under%20Review-yellow)](https://app.digitalpublicgoods.net/a/13478)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

This document demonstrates MIESC's compliance with the [Digital Public Goods Standard](https://github.com/DPGAlliance/DPG-Standard) (v1.1.6) established by the [Digital Public Goods Alliance (DPGA)](https://digitalpublicgoods.net/).

---

## Application Status

| Field | Value |
|-------|-------|
| **DPGA Application** | [#13478](https://app.digitalpublicgoods.net/a/13478) |
| **GID (Global ID)** | GID0092948 |
| **Submission Date** | December 5, 2025 |
| **Status** | Under Review (submitted 2025-12-05) |
| **Contact** | Bolaji Ayodeji (DPG Evangelist) |

> The two identifiers refer to the same submission: **13478** is the DPGA
> application number (used in the app.digitalpublicgoods.net URL), and
> **GID0092948** is its Global ID (GID). They are not a mismatch.

---

## Executive Summary

MIESC is an open-source security analysis framework for smart contracts that advances **SDG 9 (Industry, Innovation and Infrastructure)** and **SDG 16 (Peace, Justice and Strong Institutions)** by providing accessible, transparent cybersecurity tools for blockchain ecosystems.

| Indicator | Status | Evidence |
|-----------|--------|----------|
| 1. SDG Relevance | Compliant | [SDG Alignment](#indicator-1-sdg-relevance) |
| 2. Open Licensing | Compliant | [AGPL-3.0 License](https://github.com/fboiero/MIESC/blob/main/LICENSE) |
| 3. Clear Ownership | Compliant | [Ownership Statement](#indicator-3-clear-ownership) |
| 4. Platform Independence | Compliant | [Technical Architecture](#indicator-4-platform-independence) |
| 5. Documentation | Compliant | [Documentation](#indicator-5-documentation) |
| 6. Data Extraction | Compliant | [Export Formats](#indicator-6-data-extraction) |
| 7. Privacy & Laws | Compliant | [Privacy Policy](./PRIVACY.md) |
| 8. Standards & Best Practices | Compliant | Standards Compliance |
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
| Tools Integrated | 50 | Across 9 defense layers (35 counted as analysis modules in Paper 1); multi-tool orchestration reducing barriers |
| Compliance Standards | 12 | Automated mapping to ISO/NIST/OWASP standards |
| Detection Recall | 95.8% (137/143) | SmartBugs-curated; see paper1_smartbugs_eval_layers_1_6_7.json (Paper 1 reproducible profile) |
| Post-filter findings | ~2–3 per contract | Context-aware FP suppression (Paper 1, False Positive Management) |
| Cost | Free (vs. $20K–60K) | Open-source vs. commercial audit engagements |

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

Full license text: [LICENSE](https://github.com/fboiero/MIESC/blob/main/LICENSE)

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
| **Institution** | Originated at Universidad de la Defensa Nacional (UNDEF); continues as research at Universidad Tecnológica Nacional, Facultad Regional Villa María (UTN-FRVM), Argentina |
| **Repository** | https://github.com/fboiero/MIESC |
| **Contact** | fboiero@frvm.utn.edu.ar |

### Intellectual Property

- **Source Code**: Copyright 2024-2026 Fernando Boiero, licensed under AGPL-3.0
- **Documentation**: Copyright 2024-2026 Fernando Boiero, licensed under CC-BY-4.0
- **Trademarks**: "MIESC" name and logo owned by Fernando Boiero
- **Patents**: No patents filed; commitment to patent-free development

### Academic Context

MIESC originated as a Master's thesis in Cyberdefense at Universidad de la Defensa Nacional (UNDEF), Argentina, and continues as a research project at Universidad Tecnológica Nacional, Facultad Regional Villa María (UTN-FRVM). Both institutions support open-source release of research outputs.

---

## Indicator 4: Platform Independence

### Core Architecture

MIESC is designed for platform independence:

```
┌─────────────────────────────────────────────────┐
│                    MIESC Core                    │
│  (Python 3.12+ - Cross-platform)                │
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
| User Guide | [docs/index.md](../index.md) | Installation, configuration, usage |
| API Reference | [docs/openapi.yaml](../openapi.yaml) | OpenAPI 3.0 specification |
| Architecture | [docs/ARCHITECTURE.md](../ARCHITECTURE.md) | System design and components |
| Quickstart | [docs/guides/QUICKSTART.md](../guides/QUICKSTART.md) | Step-by-step tutorials |
| Developer Guide | [docs/CONTRIBUTING.md](../CONTRIBUTING.md) | Contributing and extending |
| Hosted Docs | [fboiero.github.io/MIESC](https://fboiero.github.io/MIESC) | MkDocs-generated site |

### Quick Start

```bash
# Clone repository
git clone https://github.com/fboiero/MIESC.git
cd MIESC

# Install dependencies
pip install -r requirements.txt

# Run a local smoke scan
miesc scan tests/fixtures/reentrancy.sol --fp-strictness off
```

### Multilingual Support

- English: [README.md](https://github.com/fboiero/MIESC/blob/main/README.md)
- Spanish: [README_ES.md](https://github.com/fboiero/MIESC/blob/main/README_ES.md)

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
| Testing | 5967 tests passed, 8 skipped in the latest full local regression |
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

### Dual-Use Considerations

MIESC is a vulnerability-analysis tool, and vulnerability information is inherently
dual-use: a finding that helps a developer fix a bug could, in principle, inform an
attacker. We address this directly rather than ignoring it:

- **Defensive orientation**: MIESC is designed for *pre-deployment* triage of the
  user's own contracts. Its outputs—findings with remediation guidance, generated
  fixes, tests, and formal specifications—are oriented toward *closing*
  vulnerabilities, not weaponizing them.
- **No mass or offensive scanning**: MIESC analyzes source code the user explicitly
  supplies. It does not crawl, enumerate, or scan third parties' deployed contracts
  at scale, and ships no exploitation or fund-extraction tooling.
- **Bounded proof-of-concept**: exploit-test generation is scoped to confirming a
  vulnerability on the user's own contract and verifying that a patch blocks it—not
  to producing deployable attacks.
- **Public knowledge base**: the vulnerability patterns MIESC detects are already
  public (SWC Registry, CWE, peer-reviewed literature, post-mortem reports). MIESC
  democratizes *access to defense*; it does not create novel offensive capability.
- **Asymmetry correction**: professional audits cost \$20K–60K and are out of reach
  for most teams, while attackers are already well-resourced. Lowering the cost of
  defensive analysis toward zero shifts the security asymmetry *toward defenders*,
  which is the project's core do-good rationale.
- **Responsible disclosure**: MIESC provides a security contact with a 48-hour
  response commitment for issues in MIESC itself, and its documentation encourages
  responsible disclosure for vulnerabilities discovered in third-party code.

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
- **Code of Conduct**: [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md)

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
**DPGA submission**: December 5, 2025 (application #13478 / GID0092948)
**Last updated**: June 2026

---

## References

- [Digital Public Goods Alliance](https://digitalpublicgoods.net/)
- [DPG Standard v1.1.6](https://github.com/DPGAlliance/DPG-Standard)
- [DPGA Submission Guide](https://digitalpublicgoods.net/submission-guide)
- [UN Secretary-General's Roadmap for Digital Cooperation](https://www.un.org/en/content/digital-cooperation-roadmap/)
