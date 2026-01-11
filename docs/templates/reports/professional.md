# Smart Contract Security Audit Report

**Client:** {{ client_name }}
**Contract:** {{ contract_name }}
**Auditor:** {{ auditor_name }}
**Date:** {{ audit_date }}
**Version:** {{ version }}

---

## Executive Summary

This security audit was conducted by {{ auditor_name }} on behalf of {{ client_name }} to evaluate the security posture of {{ contract_name }}.

### Audit Scope

| Item | Details |
|------|---------|
| Repository | {{ repository }} |
| Commit | {{ commit_hash }} |
| Files Analyzed | {{ files_count }} |
| Lines of Code | {{ lines_of_code }} |
| Audit Duration | {{ audit_duration }} |

### Key Findings

| Severity | Count | Status |
|----------|-------|--------|
| Critical | {{ critical_count }} | {{ critical_status }} |
| High | {{ high_count }} | {{ high_status }} |
| Medium | {{ medium_count }} | {{ medium_status }} |
| Low | {{ low_count }} | {{ low_status }} |
| Informational | {{ info_count }} | {{ info_status }} |

### Overall Risk Assessment

**Risk Level:** {{ overall_risk }}

{{ risk_summary }}

---

## Findings

{% for finding in findings %}
### {{ finding.id }}. {{ finding.title }}

| Property | Value |
|----------|-------|
| Severity | {{ finding.severity }} |
| Category | {{ finding.category }} |
| Location | {{ finding.location }} |
| Status | {{ finding.status }} |
| Tool | {{ finding.tool }} |

#### Description

{{ finding.description }}

#### Impact

{{ finding.impact }}

#### Proof of Concept

```solidity
{{ finding.poc }}
```

#### Recommendation

{{ finding.recommendation }}

#### References

{% for ref in finding.references %}
- {{ ref }}
{% endfor %}

---

{% endfor %}

## Methodology

This audit employed MIESC's 9-layer defense-in-depth methodology:

| Layer | Category | Tools Used |
|-------|----------|------------|
| 1 | Static Analysis | {{ layer1_tools }} |
| 2 | Dynamic Testing | {{ layer2_tools }} |
| 3 | Symbolic Execution | {{ layer3_tools }} |
| 4 | Formal Verification | {{ layer4_tools }} |
| 5 | Property Testing | {{ layer5_tools }} |
| 6 | AI/LLM Analysis | {{ layer6_tools }} |
| 7 | Pattern Recognition | {{ layer7_tools }} |
| 8 | DeFi Security | {{ layer8_tools }} |
| 9 | Advanced Detection | {{ layer9_tools }} |

### Audit Process

1. **Code Review**: Manual inspection of smart contract source code
2. **Automated Analysis**: Multi-tool scanning across 9 security layers
3. **AI Correlation**: Cross-tool finding correlation and false positive reduction
4. **Verification**: Manual verification of all findings
5. **Remediation Review**: Review of fixes (if applicable)

---

## Compliance Mapping

### SWC Registry

| SWC ID | Title | Status |
|--------|-------|--------|
{% for swc in swc_mappings %}
| {{ swc.id }} | {{ swc.title }} | {{ swc.status }} |
{% endfor %}

### OWASP Smart Contract Top 10

| ID | Category | Findings |
|----|----------|----------|
{% for owasp in owasp_mappings %}
| {{ owasp.id }} | {{ owasp.category }} | {{ owasp.count }} |
{% endfor %}

---

## Appendix A: Tool Outputs

{% for tool in tool_outputs %}
### {{ tool.name }}

```
{{ tool.output }}
```

{% endfor %}

---

## Appendix B: Files Analyzed

| File | Lines | Findings |
|------|-------|----------|
{% for file in files_analyzed %}
| {{ file.path }} | {{ file.lines }} | {{ file.findings }} |
{% endfor %}

---

## Disclaimer

This audit report is provided "as is" with no guarantees of completeness or accuracy. The auditors have made every effort to identify security vulnerabilities, but cannot guarantee that all issues have been found. Smart contract security is an evolving field, and new vulnerabilities may be discovered after this audit. The client is responsible for addressing the findings and conducting additional security measures as appropriate.

---

**Powered by [MIESC](https://github.com/fboiero/MIESC)** - Multi-layer Intelligent Evaluation for Smart Contracts

*Report generated: {{ generation_date }}*
