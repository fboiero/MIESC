# Compliance Security Report

**Project:** {{ project_name }}
**Contract:** {{ contract_name }}
**Audit Date:** {{ audit_date }}
**Auditor:** {{ auditor_name }}

---

## Compliance Summary

| Standard | Coverage | Status |
|----------|----------|--------|
| SWC Registry | {{ swc_coverage }}% | {{ swc_status }} |
| OWASP Smart Contract Top 10 | {{ owasp_coverage }}% | {{ owasp_status }} |
| CWE (Common Weakness Enumeration) | {{ cwe_coverage }}% | {{ cwe_status }} |
| ERC Security Standards | {{ erc_coverage }}% | {{ erc_status }} |

---

## SWC Registry Mapping

Smart Contract Weakness Classification coverage analysis.

| SWC ID | Title | Status | Finding |
|--------|-------|--------|---------|
{%- for swc in swc_mappings %}
| [{{ swc.id }}](https://swcregistry.io/docs/{{ swc.id }}) | {{ swc.title }} | {{ swc.status }} | {{ swc.finding_id | default('-') }} |
{%- endfor %}

### SWC Categories Analyzed

- **Reentrancy (SWC-107)**: {{ swc_107_status }}
- **Integer Overflow/Underflow (SWC-101)**: {{ swc_101_status }}
- **Unprotected Ether Withdrawal (SWC-105)**: {{ swc_105_status }}
- **Unprotected SELFDESTRUCT (SWC-106)**: {{ swc_106_status }}
- **Floating Pragma (SWC-103)**: {{ swc_103_status }}
- **Unchecked Call Return Value (SWC-104)**: {{ swc_104_status }}
- **Denial of Service (SWC-113, SWC-128)**: {{ swc_dos_status }}
- **Front-Running (SWC-114)**: {{ swc_114_status }}
- **Timestamp Dependence (SWC-116)**: {{ swc_116_status }}
- **Authorization Through tx.origin (SWC-115)**: {{ swc_115_status }}

---

## OWASP Smart Contract Top 10

| Rank | Category | Findings | Severity |
|------|----------|----------|----------|
| SC01 | Reentrancy Attacks | {{ owasp_sc01_count }} | {{ owasp_sc01_severity }} |
| SC02 | Integer Overflow and Underflow | {{ owasp_sc02_count }} | {{ owasp_sc02_severity }} |
| SC03 | Front-Running | {{ owasp_sc03_count }} | {{ owasp_sc03_severity }} |
| SC04 | Denial of Service | {{ owasp_sc04_count }} | {{ owasp_sc04_severity }} |
| SC05 | Logic Errors | {{ owasp_sc05_count }} | {{ owasp_sc05_severity }} |
| SC06 | Insecure Randomness | {{ owasp_sc06_count }} | {{ owasp_sc06_severity }} |
| SC07 | Access Control Issues | {{ owasp_sc07_count }} | {{ owasp_sc07_severity }} |
| SC08 | Unchecked External Calls | {{ owasp_sc08_count }} | {{ owasp_sc08_severity }} |
| SC09 | Oracle Manipulation | {{ owasp_sc09_count }} | {{ owasp_sc09_severity }} |
| SC10 | Flash Loan Attacks | {{ owasp_sc10_count }} | {{ owasp_sc10_severity }} |

---

## CWE Mapping

Common Weakness Enumeration mapping for identified vulnerabilities.

| CWE ID | Name | Finding Count | Severity |
|--------|------|---------------|----------|
{%- for cwe in cwe_mappings %}
| [CWE-{{ cwe.id }}](https://cwe.mitre.org/data/definitions/{{ cwe.id }}.html) | {{ cwe.name }} | {{ cwe.count }} | {{ cwe.severity }} |
{%- endfor %}

---

## ERC Token Standard Compliance

{% if erc20_analysis %}
### ERC-20 Analysis

| Check | Status | Notes |
|-------|--------|-------|
| totalSupply() implemented | {{ erc20.total_supply }} | |
| balanceOf() implemented | {{ erc20.balance_of }} | |
| transfer() implemented | {{ erc20.transfer }} | |
| approve() implemented | {{ erc20.approve }} | |
| allowance() implemented | {{ erc20.allowance }} | |
| transferFrom() implemented | {{ erc20.transfer_from }} | |
| Transfer event defined | {{ erc20.transfer_event }} | |
| Approval event defined | {{ erc20.approval_event }} | |
| Approve race condition protected | {{ erc20.approve_race }} | {{ erc20.approve_race_notes }} |
{% endif %}

{% if erc721_analysis %}
### ERC-721 Analysis

| Check | Status | Notes |
|-------|--------|-------|
| ownerOf() implemented | {{ erc721.owner_of }} | |
| safeTransferFrom() implemented | {{ erc721.safe_transfer_from }} | |
| onERC721Received() callback | {{ erc721.on_received }} | |
| Approval handling | {{ erc721.approval }} | |
{% endif %}

---

## DeFi Security Checks

| Category | Check | Status |
|----------|-------|--------|
| Flash Loan | Attack vector analysis | {{ flash_loan_status }} |
| Oracle | Price manipulation protection | {{ oracle_status }} |
| MEV | Sandwich attack protection | {{ mev_status }} |
| Rug Pull | Owner privilege analysis | {{ rug_pull_status }} |
| Slippage | Protection mechanism | {{ slippage_status }} |
| Liquidation | Fair liquidation process | {{ liquidation_status }} |

---

## Audit Layers Coverage

MIESC 9-layer defense-in-depth analysis coverage.

| Layer | Category | Tools Used | Findings |
|-------|----------|------------|----------|
| 1 | Static Analysis | {{ layer1_tools }} | {{ layer1_count }} |
| 2 | Pattern Detection | {{ layer2_tools }} | {{ layer2_count }} |
| 3 | Symbolic Execution | {{ layer3_tools }} | {{ layer3_count }} |
| 4 | Fuzzing | {{ layer4_tools }} | {{ layer4_count }} |
| 5 | Formal Verification | {{ layer5_tools }} | {{ layer5_count }} |
| 6 | ML Detection | {{ layer6_tools }} | {{ layer6_count }} |
| 7 | LLM Analysis | {{ layer7_tools }} | {{ layer7_count }} |
| 8 | DeFi Security | {{ layer8_tools }} | {{ layer8_count }} |
| 9 | Dependency Audit | {{ layer9_tools }} | {{ layer9_count }} |

---

## Remediation Priority Matrix

| Priority | Finding | SWC | Effort | Risk |
|----------|---------|-----|--------|------|
{%- for finding in prioritized_findings %}
| {{ finding.priority }} | {{ finding.title }} | {{ finding.swc_id }} | {{ finding.effort }} | {{ finding.risk }} |
{%- endfor %}

---

## Attestation

This compliance report was generated using MIESC v{{ miesc_version }} on {{ generation_date }}.

The analysis covered {{ total_checks }} security checks across {{ layers_used }} security layers using {{ tools_count }} specialized tools.

**Report ID:** {{ report_id }}
**Contract Hash:** {{ contract_hash }}

---

*Generated by [MIESC](https://github.com/fboiero/MIESC) - Multi-layer Intelligent Evaluation for Smart Contracts*
