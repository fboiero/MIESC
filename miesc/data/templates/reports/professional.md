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

{% if llm_enabled %}
---

## Model-Assisted Executive Summary

*The following executive summary was produced with model-assisted interpretation ({{ llm_model }}) to provide additional business-focused context for the audit findings.*

{{ llm_executive_summary }}

### AI Risk Narrative

{{ llm_risk_narrative }}

{% endif %}
---

## Tools Execution Summary

**Total Tools Executed:** {{ total_tools_executed }} | **Success:** {{ tools_success_count }} | **Failed:** {{ tools_failed_count }}

| Tool | Status | Duration | Findings | Layer |
|------|--------|----------|----------|-------|
{%- for tool in tools_execution_summary %}
| {{ tool.name }} | {{ tool.status_icon }} {{ tool.status }} | {{ tool.duration }} | {{ tool.findings_count }} | {{ tool.layer }} |
{%- endfor %}

---

## Layer Coverage Analysis

MIESC employs a 9-layer defense-in-depth approach. The following table shows the coverage achieved in this audit:

| Layer | Tools Executed | Success | Failed | Findings | Status |
|-------|----------------|---------|--------|----------|--------|
{%- for layer in layer_summary %}
| {{ layer.name }} | {{ layer.tools }} | {{ layer.success_count }} | {{ layer.failed_count }} | {{ layer.findings_count }} | {{ layer.coverage_status }} |
{%- endfor %}

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
| Detected by | {{ finding.confirming_tools | join(', ') if finding.confirming_tools else finding.tool }}{% if finding.tool_count and finding.tool_count > 1 %} ({{ finding.tool_count }} tools agree){% endif %} |
| Confidence | {{ finding.confidence_pct | default('n/a') }}{% if finding.cross_validated_static or finding.cross_validated_llm %} — cross-validated{% endif %} |

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

{% if llm_enabled and llm_critical_interpretations %}
## Model-Assisted Critical Findings

*The following interpretations were produced with model assistance to provide additional context on critical and high severity findings.*

{% for interp in llm_critical_interpretations %}
### {{ interp.title }}

**Severity:** {{ interp.severity }} | **Location:** {{ interp.location }}

**Model-Assisted Analysis:**

{{ interp.llm_interpretation }}

---

{% endfor %}
{% endif %}

{% if llm_enabled and llm_remediation_priority %}
## AI-Recommended Remediation Priority

*The following prioritization was produced with model assistance based on exploitability, business impact, and fix complexity.*

| Priority | Finding | Severity | Justification |
|----------|---------|----------|---------------|
{%- for item in llm_remediation_priority %}
| {{ item.priority }} | {{ item.title }} | {{ item.severity }} | {{ item.reason }} |
{%- endfor %}

{% endif %}

---

## Coverage and Limitations

What this report does **not** cover is as important as what it does. Figures come from the
run itself, not from the tool catalogue.

| Coverage | Tools |
|----------|-------|
| Ran and produced results | {{ coverage_tools_clean | length }} of {{ coverage_tools_run | length }}{% if coverage_tools_clean %}: {{ coverage_tools_clean | join(', ') }}{% endif %} |
| Skipped (not installed / unsupported input / excluded) | {% if coverage_tools_skipped %}{{ coverage_tools_skipped | join(', ') }}{% else %}none{% endif %} |
| Ran in built-in fallback mode (no external model or binary) | {% if coverage_tools_fallback %}{{ coverage_tools_fallback | join(', ') }}{% else %}none{% endif %} |
| Failed or timed out | {% if coverage_tools_failed %}{{ coverage_tools_failed | join(', ') }}{% else %}none{% endif %} |
{% if coverage_llm_free is not none %}| LLM-backed adapters | {% if coverage_llm_free %}disabled for this run (`--no-llm`){% else %}enabled where a model was reachable{% endif %} |
{% endif %}
Findings from a tool in fallback mode are heuristic and carry lower confidence; a skipped
tool means its vulnerability classes were **not** checked by that engine in this run.

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
{%- for swc in swc_mappings %}
| {{ swc.id }} | {{ swc.title }} | {{ swc.status }} |
{%- endfor %}

### OWASP Smart Contract Top 10

| ID | Category | Findings |
|----|----------|----------|
{%- for owasp in owasp_mappings %}
| {{ owasp.id }} | {{ owasp.category }} | {{ owasp.count }} |
{%- endfor %}

---

## Appendix A: Tool Outputs

{% for tool in tool_outputs %}
### {{ tool.name }}

```
{{ tool.output }}
```

{% endfor %}

---

## Appendix B: Provenance

{% if has_provenance %}
Environment of the run that produced the findings above (from the result file's
`provenance` block), so the audit can be reproduced or cited.

| Item | Value |
|------|-------|
{% for label, value in provenance_rows %}| {{ label }} | `{{ value }}` |
{% endfor %}
{% if provenance_tool_versions %}
| Tool | Version reported by the binary |
|------|-------------------------------|
{% for tool, version in provenance_tool_versions %}| {{ tool }} | {{ version }} |
{% endfor %}{% endif %}
{% else %}
The result file carries no `provenance` block (produced before MIESC 6.2.0). Re-run the
analysis to record tool versions, solc per contract and the exact command.
{% endif %}

## Appendix C: Files Analyzed

| File | Lines | Findings |
|------|-------|----------|
{%- for file in files_analyzed %}
| {{ file.path }} | {{ file.lines }} | {{ file.findings }} |
{%- endfor %}

---

## Disclaimer

This audit report is provided "as is" with no guarantees of completeness or accuracy. The auditors have made every effort to identify security vulnerabilities, but cannot guarantee that all issues have been found. Smart contract security is an evolving field, and new vulnerabilities may be discovered after this audit. The client is responsible for addressing the findings and conducting additional security measures as appropriate.

{% if llm_enabled %}
**Model-Assisted Interpretation Disclosure:** Sections marked as model-assisted were produced with an LLM to provide additional context and analysis. These interpretations are supplementary and must be reviewed by qualified security professionals before operational use.
{% endif %}

---

**Powered by [MIESC](https://github.com/fboiero/MIESC)** - Multi-layer Intelligent Evaluation for Smart Contracts

*Report generated: {{ generation_date }}*
