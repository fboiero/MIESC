# Sustainable Development Goals (SDG) Relevance

**MIESC - Multi-layer Intelligent Evaluation for Smart Contracts**

This document maps MIESC's contributions to the United Nations Sustainable Development Goals (SDGs) as required by the [Digital Public Goods Standard](https://digitalpublicgoods.net/standard/).

---

## Primary SDG Alignment

### SDG 9: Industry, Innovation and Infrastructure

**Target 9.1:** Develop quality, reliable, sustainable and resilient infrastructure to support economic development and human well-being.

**MIESC's contribution:**
- Blockchain infrastructure is increasingly critical for financial services, supply chains, and governance systems worldwide
- MIESC strengthens this infrastructure by detecting vulnerabilities before deployment
- The framework's 9-layer defense-in-depth approach provides comprehensive security coverage that single tools cannot achieve
- Open-source availability ensures all blockchain developers have access to enterprise-grade security analysis, not just well-funded projects

**Evidence:**
- 89.47% precision and 86.2% recall on 5,127 real-world contracts
- 34% improvement over single-tool analysis approaches
- Mapped findings to 12 international security standards (ISO 27001, NIST CSF, etc.)

### SDG 16: Peace, Justice and Strong Institutions

**Target 16.5:** Substantially reduce corruption and bribery in all their forms.

**Target 16.6:** Develop effective, accountable and transparent institutions at all levels.

**MIESC's contribution:**
- Smart contracts enable transparent, tamper-proof governance and financial systems
- Vulnerabilities in these contracts undermine trust and enable exploitation
- MIESC's compliance mapping (ISO 27001, NIST, OWASP) helps organizations meet regulatory requirements
- The tool's transparency (open source, reproducible results) enables accountable security practices
- Professional audit reports provide evidence for regulatory compliance

**Evidence:**
- Compliance mapping to 12 international standards
- Automated SARIF output integrates with institutional security workflows
- Reports include CVSS scoring aligned with industry standards

### SDG 17: Partnerships for the Goals

**Target 17.6:** Enhance North-South, South-South and triangular regional and international cooperation on and access to science, technology and innovation.

**Target 17.8:** Fully operationalize the technology bank and science, technology and innovation capacity-building mechanism for least developed countries.

**MIESC's contribution:**
- Open-source framework freely available to developers worldwide
- Bilingual documentation (English/Spanish) improves accessibility for Latin American developers
- Local-first architecture (Ollama LLM) enables use without cloud dependencies or expensive API subscriptions
- Plugin system enables community-driven security research contributions
- Academic foundation supports knowledge transfer and capacity building

**Evidence:**
- Published as open-source under AGPL-3.0
- Bilingual documentation (EN/ES) across all governance and user-facing documents
- Docker images enable deployment without complex tool installation
- Master's thesis research conducted in Argentina (South-South cooperation)

---

## Secondary SDG Alignment

### SDG 8: Decent Work and Economic Growth

**Target 8.10:** Strengthen the capacity of domestic financial institutions to encourage and expand access to banking, insurance and financial services for all.

**Contribution:** DeFi (Decentralized Finance) protocols expand financial access. MIESC's DeFi-specific security profile ensures these protocols are safe for users, particularly in regions with limited traditional banking.

### SDG 10: Reduced Inequalities

**Target 10.c:** Reduce to less than 3 per cent the transaction costs of migrant remittances.

**Contribution:** Blockchain-based remittance systems rely on secure smart contracts. MIESC helps ensure these systems are safe for the vulnerable populations that depend on them.

---

## Impact Metrics

| Metric | Value |
|--------|-------|
| Security tools integrated | 50 |
| Blockchain chains supported | 7 (EVM production + 6 alpha) |
| Vulnerability patterns in knowledge base | 59 |
| International standards mapped | 12 |
| Languages supported (docs) | 2 (English, Spanish) |
| License | AGPL-3.0 (copyleft, ensures open access) |
| Platform independence | Python 3.12+, Docker, any OS |
| Cloud dependency | None required (local-first) |

---

## References

- [UN Sustainable Development Goals](https://sdgs.un.org/goals)
- [Digital Public Goods Standard](https://digitalpublicgoods.net/standard/)
- [Blockchain for SDGs (UN)](https://www.un.org/en/digital-financing-taskforce)
