# Responsible Use Policy

**MIESC - Multi-layer Intelligent Evaluation for Smart Contracts**
**Last updated:** 2026-03-31

## Purpose

MIESC is designed to **improve the security of smart contracts** by identifying vulnerabilities before deployment. This document establishes guidelines for the ethical and responsible use of MIESC and its capabilities.

## Intended Use

MIESC is intended for:

- **Pre-deployment security audits** of smart contracts
- **Continuous security monitoring** in development pipelines
- **Academic research** in smart contract security
- **Educational purposes** in cybersecurity training
- **Collaborative defense** through responsible vulnerability disclosure
- **Compliance verification** against security standards

## Acceptable Use

### Authorized activities

- Analyzing your own smart contracts
- Analyzing contracts with explicit authorization from the contract owner
- Security research on contracts deployed to public testnets
- Academic study using established benchmark datasets (SmartBugs, SolidiFI, etc.)
- Contributing to the security of open-source smart contract projects
- Bug bounty participation through authorized programs (Immunefi, Code4rena, etc.)

### Prohibited activities

- Using MIESC to find and exploit vulnerabilities in production contracts without authorization
- Using findings to front-run, sandwich attack, or otherwise exploit DeFi protocols
- Using the PoC generator to create exploits for malicious purposes
- Distributing vulnerability information about live contracts without responsible disclosure
- Using MIESC to facilitate theft, fraud, or unauthorized access to funds
- Circumventing security measures of deployed contracts

## Dual-Use Considerations

MIESC is a **dual-use security tool**. Like any vulnerability scanner, it can be used defensively (finding and fixing vulnerabilities) or offensively (finding and exploiting them). We acknowledge this inherent duality and address it through:

### Technical safeguards

1. **PoC generator limitations:** The proof-of-concept generator creates test scenarios for verification, not weaponized exploits. Generated PoCs are designed to run in local Foundry test environments, not against live networks.

2. **Local-first architecture:** MIESC runs locally, reducing the risk of vulnerability data leaking to unauthorized parties.

3. **Report confidentiality:** Generated reports include confidentiality classifications and are stored locally under the user's control.

### Community safeguards

1. **Responsible disclosure:** Users who discover vulnerabilities in deployed contracts should follow [responsible disclosure practices](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html).

2. **Bug bounty programs:** We encourage using MIESC findings through established bug bounty programs rather than independent exploitation.

3. **Code of Conduct:** All community interactions are governed by our [Code of Conduct](./CODE_OF_CONDUCT.md).

## AI/LLM Considerations

MIESC integrates AI/LLM capabilities for enhanced analysis. Responsible AI practices include:

- **Transparency:** AI-generated findings are clearly labeled in reports (AI Disclosure section)
- **Reproducibility:** Seeds and model versioning enable reproducible results
- **Hallucination detection:** Built-in cross-validation reduces false AI-generated findings
- **Local execution:** Default Ollama integration ensures code stays on the user's machine
- **Prompt sanitization:** Input sanitization prevents prompt injection attacks

## Reporting Misuse

If you become aware of MIESC being used for malicious purposes:

- **Email:** fboiero@frvm.utn.edu.ar
- **Security issues:** See [SECURITY.md](./docs/SECURITY.md)

## License Implications

MIESC is licensed under **AGPL-3.0**. This license requires:

- Any modifications to MIESC must be released under the same license
- Services built on MIESC must make their source code available
- This ensures transparency and prevents proprietary exploitation of the tool

## Acknowledgment

By using MIESC, you acknowledge that:

1. You will use the tool for legitimate security improvement purposes
2. You have authorization to analyze the contracts you scan
3. You will follow responsible disclosure practices for any vulnerabilities found
4. You will comply with applicable laws and regulations in your jurisdiction
