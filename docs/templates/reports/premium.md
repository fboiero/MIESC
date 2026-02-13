<!-- COVER PAGE -->
<div class="cover-page">

<div style="margin-bottom: 60px;">
<h1 style="font-size: 42pt; margin-bottom: 10px; color: white; border: none;">🛡️ MIESC</h1>
<p style="font-size: 14pt; color: #94a3b8;">Multi-layer Intelligent Evaluation for Smart Contracts</p>
</div>

<h2 style="font-size: 28pt; font-weight: 300; color: white; margin: 40px 0;">Smart Contract Security Audit</h2>

<div style="background: rgba(255,255,255,0.1); border-radius: 12px; padding: 30px; margin: 30px 0;">
<h3 style="font-size: 22pt; color: #60a5fa; border: none; margin: 0;">{{ contract_name }}</h3>
<p style="color: #94a3b8; margin-top: 10px;">{{ client_name | default('Client') }}</p>
</div>

<div style="margin-top: 60px; text-align: left; display: inline-block;">
<table style="background: transparent; border: none;">
<tr><td style="color: #94a3b8; border: none; padding: 8px 20px 8px 0;">Prepared by:</td><td style="color: white; border: none; padding: 8px 0;"><strong>{{ auditor_name | default('MIESC Security') }}</strong></td></tr>
<tr><td style="color: #94a3b8; border: none; padding: 8px 20px 8px 0;">Audit Date:</td><td style="color: white; border: none; padding: 8px 0;"><strong>{{ audit_date }}</strong></td></tr>
<tr><td style="color: #94a3b8; border: none; padding: 8px 20px 8px 0;">Report Date:</td><td style="color: white; border: none; padding: 8px 0;"><strong>{{ generation_date }}</strong></td></tr>
<tr><td style="color: #94a3b8; border: none; padding: 8px 20px 8px 0;">Version:</td><td style="color: white; border: none; padding: 8px 0;"><strong>{{ report_version | default('1.0') }}</strong></td></tr>
</table>
</div>

<div style="margin-top: 50px;">
<span style="background: #dc3545; color: white; padding: 8px 20px; border-radius: 4px; font-weight: 600; font-size: 10pt;">{{ classification | default('CONFIDENTIAL') }}</span>
</div>

<p style="color: #64748b; font-size: 9pt; margin-top: 60px; max-width: 400px;">
This document contains confidential security findings and is intended solely for the addressee. Unauthorized distribution is prohibited.
</p>

</div>

<!-- section-break -->

# Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Scope & Methodology](#2-scope-methodology)
3. [Risk Assessment](#3-risk-assessment)
4. [Findings Overview](#4-findings-overview)
5. [Detailed Findings](#5-detailed-findings)
6. [Remediation Roadmap](#6-remediation-roadmap)
7. [Appendices](#7-appendices)

<!-- section-break -->

# 1. Executive Summary 
## 1.1 Key Takeaways

{{ llm_executive_summary | default('No AI summary available.') }}

## 1.2 Deployment Recommendation

<div class="recommendation-box" style="border: 2px solid {{ deployment_recommendation_color | default('#ff9800') }}; padding: 20px; margin: 15px 0; border-radius: 8px; background: {{ deployment_recommendation_bg | default('#fff8e1') }};">
<p style="margin: 0 0 10px 0; font-size: 11pt;">
<strong style="color: {{ deployment_recommendation_color | default('#ff9800') }};">Recommendation:</strong>
<span style="font-weight: bold; font-size: 14pt; margin-left: 8px;">{{ deployment_recommendation | default('CONDITIONAL') }}</span>
</p>
<p style="margin: 0; color: #4a5568; line-height: 1.5;">{{ deployment_justification | default('Review and address findings before deployment.') }}</p>
</div>

## 1.3 Risk Summary

| Metric | Value |
|--------|-------|
| **Overall Risk Score** | {{ overall_risk_score | default('N/A') }}/100 |
| **Exploitability** | {{ exploitability_rating | default('Medium') }} |
| **Business Impact** | {{ business_impact | default('Medium') }} |
| **Confidence Level** | {{ confidence_level | default('High') }} |

### Findings by Severity

| Severity | Count | % of Total |
|----------|------:|----------:|
| **Critical** | {{ critical_count | default(0) }} | {{ critical_percent | default(0) }}% |
| **High** | {{ high_count | default(0) }} | {{ high_percent | default(0) }}% |
| **Medium** | {{ medium_count | default(0) }} | {{ medium_percent | default(0) }}% |
| **Low** | {{ low_count | default(0) }} | {{ low_percent | default(0) }}% |
| **Informational** | {{ info_count | default(0) }} | {{ info_percent | default(0) }}% |
| **Total** | **{{ total_findings | default(0) }}** | 100% |

## 1.4 Impact Assessment

{%- if value_at_risk %}
| Scenario | Estimated Impact |
|----------|-----------------|
| Worst Case (All Critical Exploited) | {{ value_at_risk.worst_case | default('Unable to estimate') }} |
| Likely Case | {{ value_at_risk.likely_case | default('Unable to estimate') }} |
| Best Case (Minor Exploits Only) | {{ value_at_risk.best_case | default('Unable to estimate') }} |
{%- else %}
Based on the identified vulnerabilities:

| Impact Category | Assessment |
|----------------|------------|
| **Confidentiality** | {{ 'High' if critical_count > 0 else ('Medium' if high_count > 0 else 'Low') }} - {% if critical_count > 0 or high_count > 0 %}Sensitive data or state could be exposed{% else %}No significant confidentiality risks identified{% endif %} |
| **Integrity** | {{ 'High' if critical_count > 0 else ('Medium' if high_count > 0 else 'Low') }} - {% if critical_count > 0 or high_count > 0 %}Contract state could be manipulated{% else %}Contract logic appears sound{% endif %} |
| **Availability** | {{ 'Medium' if critical_count > 0 or high_count > 0 else 'Low' }} - {% if critical_count > 0 %}Denial of service possible{% else %}No significant availability risks{% endif %} |
{%- endif %}

<!-- section-break -->

# 2. Scope & Methodology 
## 2.1 Engagement Details

| Property | Value |
|----------|-------|
| **Client** | {{ client_name | default('N/A') }} |
| **Contract** | {{ contract_name }} |
| **Repository** | {{ repository | default('N/A') }} |
| **Commit Hash** | `{{ commit_hash | default('N/A') }}` |
| **Network** | {{ target_network | default('Ethereum Mainnet') }} |
| **Engagement Type** | {{ engagement_type | default('Full Security Audit') }} |

## 2.2 Scope

### In Scope

| File | Lines | Description |
|------|------:|-------------|
{%- for file in files_in_scope %}
| `{{ file.path }}` | {{ file.lines }} | {{ file.description | default('Contract source') }} |
{%- endfor %}

**Total:** {{ files_count }} files, {{ lines_of_code }} lines of code

### Out of Scope

{%- if out_of_scope %}
{%- for item in out_of_scope %}
- {{ item }}
{%- endfor %}
{%- else %}
- External dependencies and imported libraries
- Off-chain components
- Economic/tokenomics analysis
- Frontend/backend applications
{%- endif %}

## 2.3 Methodology

This audit employed MIESC's comprehensive 9-layer defense-in-depth methodology:

```
Layer 1: Static Analysis        [{{ layer1_coverage | default('--') }}]
Layer 2: Dynamic Testing        [{{ layer2_coverage | default('--') }}]
Layer 3: Symbolic Execution     [{{ layer3_coverage | default('--') }}]
Layer 4: Formal Verification    [{{ layer4_coverage | default('--') }}]
Layer 5: Property Testing       [{{ layer5_coverage | default('--') }}]
Layer 6: AI/LLM Analysis        [{{ layer6_coverage | default('--') }}]
Layer 7: Pattern Recognition    [{{ layer7_coverage | default('--') }}]
Layer 8: DeFi Security          [{{ layer8_coverage | default('--') }}]
Layer 9: Advanced Detection     [{{ layer9_coverage | default('--') }}]
```

### Tools Utilized

| Layer | Tool | Version | Status |
|-------|------|---------|--------|
{%- for tool in tools_execution_summary %}
| {{ tool.layer }} | {{ tool.name }} | {{ tool.version | default('latest') }} | {{ tool.status_icon }} {{ tool.status }} |
{%- endfor %}

### Audit Process

1. **Initial Assessment** - Review documentation, understand architecture
2. **Automated Analysis** - Execute multi-layer tool suite
3. **Manual Review** - Deep dive into flagged code sections
4. **AI Correlation** - Cross-reference findings, reduce false positives
5. **Verification** - Reproduce and validate vulnerabilities
6. **Report Generation** - Document findings with remediation guidance

## 2.4 Limitations

- Time-boxed engagement ({{ audit_duration | default('N/A') }})
- Analysis based on code snapshot at commit `{{ commit_hash | default('N/A') }}`
- No guarantee of finding all vulnerabilities
- Economic attack vectors not fully modeled
- Dependency vulnerabilities may exist beyond analysis scope

<!-- section-break -->

# 3. Risk Assessment 
## 3.1 Risk Matrix

The following matrix maps findings by **Impact** (vertical) and **Likelihood** (horizontal):

<table style="width: 100%; max-width: 500px; margin: 20px auto; border-collapse: collapse; text-align: center;">
<tr>
<td style="border: none; width: 80px;"></td>
<td style="border: none;" colspan="3"><strong>LIKELIHOOD</strong></td>
</tr>
<tr>
<td style="border: none;"></td>
<td style="border: none; color: #6b7280; padding: 8px;">Low</td>
<td style="border: none; color: #6b7280; padding: 8px;">Medium</td>
<td style="border: none; color: #6b7280; padding: 8px;">High</td>
</tr>
<tr>
<td style="border: none; color: #6b7280; vertical-align: middle;"><strong>High</strong></td>
<td style="background: #fbbf24; color: white; padding: 15px; border-radius: 4px;"><small>Medium</small><br><strong style="font-size: 18pt;">{{ risk_matrix.high_low | default(0) }}</strong></td>
<td style="background: #f97316; color: white; padding: 15px; border-radius: 4px;"><small>High</small><br><strong style="font-size: 18pt;">{{ risk_matrix.high_med | default(0) }}</strong></td>
<td style="background: #dc2626; color: white; padding: 15px; border-radius: 4px;"><small>Critical</small><br><strong style="font-size: 18pt;">{{ risk_matrix.high_high | default(0) }}</strong></td>
</tr>
<tr>
<td style="border: none; color: #6b7280; vertical-align: middle;"><strong>Med</strong></td>
<td style="background: #22c55e; color: white; padding: 15px; border-radius: 4px;"><small>Low</small><br><strong style="font-size: 18pt;">{{ risk_matrix.med_low | default(0) }}</strong></td>
<td style="background: #fbbf24; color: white; padding: 15px; border-radius: 4px;"><small>Medium</small><br><strong style="font-size: 18pt;">{{ risk_matrix.med_med | default(0) }}</strong></td>
<td style="background: #f97316; color: white; padding: 15px; border-radius: 4px;"><small>High</small><br><strong style="font-size: 18pt;">{{ risk_matrix.med_high | default(0) }}</strong></td>
</tr>
<tr>
<td style="border: none; color: #6b7280; vertical-align: middle;"><strong>Low</strong></td>
<td style="background: #94a3b8; color: white; padding: 15px; border-radius: 4px;"><small>Info</small><br><strong style="font-size: 18pt;">{{ risk_matrix.low_low | default(0) }}</strong></td>
<td style="background: #22c55e; color: white; padding: 15px; border-radius: 4px;"><small>Low</small><br><strong style="font-size: 18pt;">{{ risk_matrix.low_med | default(0) }}</strong></td>
<td style="background: #fbbf24; color: white; padding: 15px; border-radius: 4px;"><small>Medium</small><br><strong style="font-size: 18pt;">{{ risk_matrix.low_high | default(0) }}</strong></td>
</tr>
<tr>
<td style="border: none;"></td>
<td style="border: none;" colspan="3"><em style="color: #6b7280; font-size: 9pt;">IMPACT →</em></td>
</tr>
</table>

## 3.2 CVSS-like Scoring

| Finding ID | Title | Base Score | Vector |
|------------|-------|-----------|--------|
{%- for score in cvss_scores %}
| {{ score.finding_id }} | {{ score.title }} | **{{ score.base_score }}** | {{ score.vector }} |
{%- endfor %}

**Scoring Methodology:**
- **Attack Vector (AV):** Network, Adjacent, Local, Physical
- **Attack Complexity (AC):** Low, High
- **Privileges Required (PR):** None, Low, High
- **User Interaction (UI):** None, Required
- **Impact:** Confidentiality, Integrity, Availability

## 3.3 Risk Narrative

{%- if llm_risk_narrative %}
{{ llm_risk_narrative }}
{%- else %}
The analyzed contract presents security concerns that should be addressed before production deployment. The combination of findings indicates potential for exploitation if left unmitigated.
{%- endif %}

<!-- section-break -->

# 4. Findings Overview 
## 4.1 Summary Table

| ID | Title | Severity | Status | CVSS |
|----|-------|----------|--------|-----:|
{%- for finding in findings %}
| {{ finding.id }} | {{ finding.title }} | {{ finding.severity_badge }} | {{ finding.status }} | {{ finding.cvss_score | default('--') }} |
{%- endfor %}

## 4.2 Category Distribution

| Category | Count | Severity Breakdown |
|----------|------:|-------------------|
{%- for cat in category_summary %}
| {{ cat.name }} | {{ cat.count }} | {{ cat.breakdown }} |
{%- endfor %}

## 4.3 Layer Coverage Analysis

| Layer | Tools Run | Passed | Failed | Findings | Coverage |
|-------|----------:|-------:|-------:|----------:|----------|
{%- for layer in layer_summary %}
| {{ layer.name }} | {{ layer.tools }} | {{ layer.success_count }} | {{ layer.failed_count }} | {{ layer.findings_count }} | {{ layer.coverage_bar }} |
{%- endfor %}

<!-- section-break -->

# 5. Detailed Findings 
{%- for finding in findings %}

## {{ finding.id }}. {{ finding.title }}

| Property | Value |
|----------|-------|
| **Severity** | <span style="background: {{ finding.severity_color | default('#e0e0e0') }}; color: white; padding: 2px 8px; border-radius: 4px;">{{ finding.severity_badge }}</span> |
| **Category** | {{ finding.category }} |
| **CVSS Score** | {{ finding.cvss_score | default('N/A') }} |
| **Location** | `{{ finding.location }}` |
| **Status** | {{ finding.status }} |
| **Detected By** | {{ finding.tool }} |

### Description

{{ finding.description }}

### Vulnerable Code

```solidity
{{ finding.vulnerable_code | default(finding.poc) }}
```

### Impact Analysis

{{ finding.impact }}

{%- if finding.attack_scenario %}

### Attack Scenario

{{ finding.attack_scenario }}

**Step-by-step:**
{%- for step in finding.attack_steps %}
{{ loop.index }}. {{ step }}
{%- endfor %}
{%- endif %}

### Recommendation

{{ finding.recommendation }}
{%- if finding.remediation_code %}

### Suggested Fix

```diff
{{ finding.remediation_code }}
```

**Remediation Effort:** {{ finding.remediation_effort | default('Medium') }}
**Estimated Fix Time:** {{ finding.fix_time | default('1-2 hours') }}
{%- endif %}
{%- if llm_enabled and finding.llm_interpretation %}

### AI Analysis

*Generated by {{ llm_model }}*

{{ finding.llm_interpretation }}
{%- endif %}

### References
{%- for ref in finding.references %}
- {{ ref }}
{%- endfor %}
{%- if not finding.references %}
- No references available
{%- endif %}

<!-- section-break -->
{%- endfor %}

<!-- section-break -->

# 6. Remediation Roadmap 
## 6.1 Prioritized Actions

{%- if llm_enabled and llm_remediation_priority %}
| Priority | Finding | Severity | Effort | Rationale |
|:--------:|---------|----------|--------|-----------|
{%- for item in llm_remediation_priority %}
| {{ item.priority }} | {{ item.title }} | {{ item.severity }} | {{ item.effort }} | {{ item.reason }} |
{%- endfor %}
{%- else %}
| Priority | Finding | Severity | Recommended Action |
|:--------:|---------|----------|-------------------|
{%- for finding in findings %}
{%- if finding.severity in ['critical', 'high'] %}
| {{ loop.index }} | {{ finding.title }} | {{ finding.severity_badge }} | Immediate fix required |
{%- endif %}
{%- endfor %}
{%- endif %}

## 6.2 Remediation Timeline

| Phase | Week | Priority | Findings | Action |
|:-----:|:----:|----------|:--------:|--------|
| <span style="background:#dc2626;color:white;padding:4px 10px;border-radius:50%;">1</span> | **Week 1** | Critical & High | {{ critical_count }} + {{ high_count }} | Immediate remediation required |
| <span style="background:#f97316;color:white;padding:4px 10px;border-radius:50%;">2</span> | **Week 2** | Medium | {{ medium_count }} | Address medium severity issues |
| <span style="background:#22c55e;color:white;padding:4px 10px;border-radius:50%;">3</span> | **Week 3** | Low & Info | {{ low_count }} + {{ info_count }} | Fix low priority items |
| <span style="background:#3b82f6;color:white;padding:4px 10px;border-radius:50%;">4</span> | **Week 4** | Verification | - | Re-audit and validation |

## 6.3 Quick Wins
{%- if quick_wins %}

The following fixes provide high security impact with minimal effort:
{%- for win in quick_wins %}
- **{{ win.title }}** - {{ win.description }}
{%- endfor %}
{%- else %}

Review findings marked as "Low" effort for quick security improvements.
{%- endif %}

## 6.4 Effort vs Impact Matrix

<table style="width: 100%; max-width: 550px; margin: 20px auto; border-collapse: collapse; text-align: center;">
<tr>
<td style="border: none; width: 80px;"></td>
<td style="border: none;" colspan="3"><strong>IMPACT</strong></td>
</tr>
<tr>
<td style="border: none;"></td>
<td style="border: none; color: #6b7280; padding: 8px;">Low</td>
<td style="border: none; color: #6b7280; padding: 8px;">Medium</td>
<td style="border: none; color: #6b7280; padding: 8px;">High</td>
</tr>
<tr>
<td style="border: none; color: #6b7280; vertical-align: middle;"><strong>E<br/>F<br/>F<br/>O<br/>R<br/>T</strong></td>
<td style="background: #ef4444; color: white; padding: 15px; border-radius: 4px;"><strong>Avoid</strong><br/><span style="font-size: 18pt;">{{ effort_impact_matrix.high_low.count if effort_impact_matrix else 0 }}</span></td>
<td style="background: #f97316; color: white; padding: 15px; border-radius: 4px;"><strong>Consider</strong><br/><span style="font-size: 18pt;">{{ effort_impact_matrix.high_medium.count if effort_impact_matrix else 0 }}</span></td>
<td style="background: #eab308; color: white; padding: 15px; border-radius: 4px;"><strong>Schedule</strong><br/><span style="font-size: 18pt;">{{ effort_impact_matrix.high_high.count if effort_impact_matrix else 0 }}</span></td>
</tr>
<tr>
<td style="border: none; color: #6b7280; vertical-align: middle;"><strong>High<br/>↑<br/>Med<br/>↑<br/>Low</strong></td>
<td style="background: #94a3b8; color: white; padding: 15px; border-radius: 4px;"><strong>Defer</strong><br/><span style="font-size: 18pt;">{{ effort_impact_matrix.medium_low.count if effort_impact_matrix else 0 }}</span></td>
<td style="background: #3b82f6; color: white; padding: 15px; border-radius: 4px;"><strong>Plan</strong><br/><span style="font-size: 18pt;">{{ effort_impact_matrix.medium_medium.count if effort_impact_matrix else 0 }}</span></td>
<td style="background: #8b5cf6; color: white; padding: 15px; border-radius: 4px;"><strong>Priority</strong><br/><span style="font-size: 18pt;">{{ effort_impact_matrix.medium_high.count if effort_impact_matrix else 0 }}</span></td>
</tr>
<tr>
<td style="border: none;"></td>
<td style="background: #64748b; color: white; padding: 15px; border-radius: 4px;"><strong>If Time</strong><br/><span style="font-size: 18pt;">{{ effort_impact_matrix.low_low.count if effort_impact_matrix else 0 }}</span></td>
<td style="background: #22c55e; color: white; padding: 15px; border-radius: 4px;"><strong>Quick Win</strong><br/><span style="font-size: 18pt;">{{ effort_impact_matrix.low_medium.count if effort_impact_matrix else 0 }}</span></td>
<td style="background: #16a34a; color: white; padding: 15px; border-radius: 4px;"><strong>DO FIRST!</strong><br/><span style="font-size: 18pt;">{{ effort_impact_matrix.low_high.count if effort_impact_matrix else 0 }}</span></td>
</tr>
</table>

{% if effort_impact_matrix %}
**Prioritization Summary:**
{% if effort_impact_matrix.low_high.count > 0 %}- 🚀 **DO FIRST ({{ effort_impact_matrix.low_high.count }})**: Low effort, high impact - immediate wins{% endif %}
{% if effort_impact_matrix.low_medium.count > 0 %}- ✅ **Quick Wins ({{ effort_impact_matrix.low_medium.count }})**: Low effort, medium impact - easy improvements{% endif %}
{% if effort_impact_matrix.medium_high.count > 0 %}- ⚡ **Priority ({{ effort_impact_matrix.medium_high.count }})**: Medium effort, high impact - plan these next{% endif %}
{% if effort_impact_matrix.high_high.count > 0 %}- 📅 **Schedule ({{ effort_impact_matrix.high_high.count }})**: High effort, high impact - important but complex{% endif %}
{% endif %}

<!-- section-break -->

# 7. Appendices 
## Appendix A: Tool Execution Details

{%- for tool in tool_outputs %}

### A.{{ loop.index }}. {{ tool.name }}

**Execution Time:** {{ tool.duration | default('N/A') }}
**Exit Code:** {{ tool.exit_code | default('0') }}
**Findings:** {{ tool.findings_count | default(0) }}

<details>
<summary>Raw Output (click to expand)</summary>

```
{{ tool.output }}
```

</details>
{%- endfor %}

## Appendix B: Files Analyzed

| # | File Path | Lines | Functions | Findings |
|--:|-----------|------:|----------:|----------:|
{%- for file in files_analyzed %}
| {{ loop.index }} | `{{ file.path }}` | {{ file.lines }} | {{ file.functions | default('--') }} | {{ file.findings }} |
{%- endfor %}

## Appendix C: SWC Registry Compliance

| SWC ID | Title | Status | Finding(s) |
|--------|-------|--------|------------|
{%- for swc in swc_mappings %}
| [{{ swc.id }}](https://swcregistry.io/docs/{{ swc.id }}) | {{ swc.title }} | {{ swc.status_icon }} {{ swc.status }} | {{ swc.finding_ids | default('--') }} |
{%- endfor %}

## Appendix D: OWASP Smart Contract Top 10

| Rank | Category | Status | Findings |
|------|----------|--------|----------|
{%- for owasp in owasp_mappings %}
| {{ owasp.id }} | {{ owasp.category }} | {{ owasp.status_icon }} | {{ owasp.count }} |
{%- endfor %}

## Appendix E: Glossary

| Term | Definition |
|------|------------|
| **Reentrancy** | A vulnerability where an external call allows execution to re-enter the calling contract before the first execution completes |
| **Integer Overflow** | When an arithmetic operation results in a value larger than can be stored in the variable |
| **Front-running** | Exploiting knowledge of pending transactions to gain an advantage |
| **Flash Loan Attack** | Using uncollateralized loans within a single transaction to manipulate protocols |
| **Oracle Manipulation** | Attacking price feeds or external data sources to influence contract behavior |
| **Access Control** | Mechanisms that restrict who can execute sensitive functions |

## Appendix F: Audit Trail

| Event | Timestamp | Hash |
|-------|-----------|------|
| Contract Snapshot | {{ audit_date }} | `{{ commit_hash | default('N/A') }}` |
| Analysis Started | {{ analysis_start | default(audit_date) }} | -- |
| Analysis Completed | {{ analysis_end | default(generation_date) }} | -- |
| Report Generated | {{ generation_date }} | -- |
| Report Hash | {{ generation_date }} | `{{ report_hash | default('N/A') }}` |

<!-- section-break -->

# Disclaimer

This audit report is provided on an "AS IS" basis without warranties of any kind, whether express or implied. The findings and recommendations represent the auditor's professional opinion based on the scope and methodology described.

**Limitations:**
- This audit does not guarantee the absence of vulnerabilities
- Smart contract security is an evolving field
- New vulnerabilities may be discovered post-audit
- Economic and governance attacks may not be fully modeled
- The client is responsible for implementing and testing fixes

{%- if llm_enabled %}

**AI Disclosure:** Sections labeled as "AI-Generated" or "AI Analysis" were produced using large language models ({{ llm_model }}). These AI-generated insights are supplementary and should be reviewed by qualified security professionals. AI outputs may contain inaccuracies and are provided for informational purposes only.
{%- endif %}

<!-- section-break -->

<div class="footer" style="text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ccc;">

**Powered by [MIESC](https://github.com/fboiero/MIESC)**

Multi-layer Intelligent Evaluation for Smart Contracts

*Report generated: {{ generation_date }}*

*Report Version: {{ report_version | default('1.0') }}*

</div>
