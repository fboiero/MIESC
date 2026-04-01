# Do No Harm Assessment

**MIESC - Multi-layer Intelligent Evaluation for Smart Contracts**
**Last updated:** 2026-03-31

This assessment addresses DPGA Standard Indicator 9 and evaluates the potential risks associated with MIESC, along with the mitigation strategies in place.

---

## 9a. Data Privacy and Security Risks

### Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Exposure of proprietary contract code | Low | High | Local-first architecture, no data exfiltration |
| Vulnerability data leaking to attackers | Low | High | Local storage, report confidentiality controls |
| LLM sending code to external services | Medium | Medium | Default to Ollama (local), explicit opt-in for remote |
| Docker container data exposure | Low | Low | No network calls from containers, volume-based I/O |

### Mitigation Details

1. **Local-first architecture:** MIESC processes all data locally. No telemetry, no analytics, no external API calls during analysis.

2. **LLM data handling:** When using local Ollama, all LLM processing stays on the user's machine. Remote LLM providers (OpenAI, Anthropic) are optional and require explicit configuration.

3. **Report security:** Generated reports include confidentiality classification headers. Reports are stored locally and never transmitted by MIESC.

4. **Prompt sanitization:** The `prompt_sanitizer` module prevents prompt injection attacks that could extract sensitive information through LLM interactions.

---

## 9b. Dual-Use Risk (Primary Concern)

### Nature of the Risk

MIESC is a **dual-use security tool**. Its core capability — finding vulnerabilities in smart contracts — can be used both defensively and offensively:

- **Defensive use:** Finding and fixing vulnerabilities before deployment
- **Offensive use:** Finding vulnerabilities to exploit in deployed contracts

This is the same dual-use challenge faced by all vulnerability scanners (Nessus, Burp Suite, Metasploit, etc.) and is inherent to the security field.

### Risk Assessment

| Component | Dual-Use Risk | Severity | Mitigation |
|-----------|--------------|----------|------------|
| Vulnerability scanner (core) | Medium | Medium | Standard security tool risk; same as Slither, Mythril |
| PoC generator | Higher | Medium | Generates test-environment PoCs, not production exploits |
| AI/LLM analysis | Low | Low | Identifies patterns, does not generate exploits |
| Report generator | Low | Low | Documents findings for remediation |
| SARIF/CI integration | Low | Low | Integrates with defensive workflows |

### Mitigation Strategies

1. **PoC generator scope:** The proof-of-concept generator creates Foundry test scripts designed to run in local test environments. Generated PoCs:
   - Target local Foundry/Anvil test networks, not production chains
   - Verify vulnerability existence, not maximize exploitation impact
   - Include remediation suggestions alongside exploit demonstration

2. **Responsible use policy:** MIESC includes a [Responsible Use Policy](../../RESPONSIBLE_USE.md) that explicitly prohibits malicious use.

3. **AGPL-3.0 license:** The copyleft license ensures that any service built on MIESC must release its source code, preventing proprietary weaponization.

4. **Community governance:** The project's [Code of Conduct](../../CODE_OF_CONDUCT.md) and [Governance](../../GOVERNANCE.md) establish clear expectations for ethical behavior.

5. **Industry precedent:** MIESC follows the same responsible disclosure model as established open-source security tools:
   - [OWASP ZAP](https://www.zaproxy.org/) (web vulnerability scanner)
   - [Metasploit](https://www.metasploit.com/) (penetration testing)
   - [Slither](https://github.com/crytic/slither) (smart contract analysis)
   - [Mythril](https://github.com/ConsenSys/mythril) (symbolic execution)

### Net Impact Assessment

The **net impact is strongly positive**:

- Smart contract exploits caused **$1.8B+ in losses in 2023** (source: DeFi Llama)
- MIESC democratizes access to security analysis that was previously only available through expensive audit firms
- The defensive value (preventing exploits) far outweighs the marginal offensive risk (which exists with or without MIESC, through other freely available tools)

---

## 9c. Inappropriate and Illegal Content

### Assessment

MIESC does **not** generate, store, or distribute any content that could be classified as inappropriate or illegal. The tool:

- Processes only smart contract source code
- Generates only technical security reports
- Does not host user-generated content
- Does not include a social or messaging component
- Does not process, store, or generate personal data

### Risk: None

---

## 9d. Protection from Harassment

### Assessment

MIESC's community interactions are governed by:

1. **Code of Conduct** ([English](../../CODE_OF_CONDUCT.md) | [Spanish](../../CODE_OF_CONDUCT_ES.md)): Based on the Contributor Covenant, establishing standards for respectful participation.

2. **Enforcement:** The project maintainer (Fernando Boiero) is responsible for enforcement, with clear escalation procedures documented in the Code of Conduct.

3. **Reporting:** Community members can report harassment via:
   - Email: fboiero@frvm.utn.edu.ar
   - GitHub Issues (for public matters)
   - Direct communication (for sensitive matters)

4. **Response timeline:** Harassment reports are addressed within 48 hours.

---

## Summary

| DPGA Indicator 9 | Risk Level | Status |
|-------------------|-----------|--------|
| 9a. Data Privacy & Security | Low | Mitigated (local-first architecture) |
| 9b. Dual-Use / Harmful Use | Medium | Mitigated (responsible use policy, PoC limitations, AGPL license) |
| 9c. Inappropriate Content | None | Not applicable |
| 9d. Harassment Protection | Low | Mitigated (Code of Conduct, enforcement process) |

**Overall Assessment:** MIESC's risks are well-understood, industry-standard for security tooling, and adequately mitigated through technical safeguards, community governance, and responsible use policies.
