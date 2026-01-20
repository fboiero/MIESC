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

---

# Table of Contents

1. [Executive Summary](#executive-summary)
2. [Scope & Methodology](#scope--methodology)
3. [Risk Assessment](#risk-assessment)
4. [Findings Overview](#findings-overview)
5. [Detailed Findings](#detailed-findings)
6. [Remediation Roadmap](#remediation-roadmap)
7. [Appendices](#appendices)

---

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

## 1.4 Estimated Value at Risk

{% if value_at_risk %}
| Scenario | Estimated Impact |
|----------|-----------------|
| Worst Case (All Critical Exploited) | {{ value_at_risk.worst_case | default('Unable to estimate') }} |
| Likely Case | {{ value_at_risk.likely_case | default('Unable to estimate') }} |
| Best Case (Minor Exploits Only) | {{ value_at_risk.best_case | default('Unable to estimate') }} |
{% else %}
*Value at risk estimation requires additional context about contract TVL and usage patterns.*
{% endif %}

---

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

{% if out_of_scope %}
{% for item in out_of_scope %}
- {{ item }}
{% endfor %}
{% else %}
- External dependencies and imported libraries
- Off-chain components
- Economic/tokenomics analysis
- Frontend/backend applications
{% endif %}

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

---

# 3. Risk Assessment

## 3.1 Risk Matrix

The following matrix maps findings by **Impact** (vertical) and **Likelihood** (horizontal):

<svg viewBox="0 0 450 320" xmlns="http://www.w3.org/2000/svg" style="max-width: 450px; margin: 20px auto; display: block;">
  <!-- Title -->
  <text x="280" y="25" font-family="Arial, sans-serif" font-size="14" font-weight="bold" fill="#374151" text-anchor="middle">LIKELIHOOD</text>

  <!-- Column headers -->
  <text x="180" y="55" font-family="Arial, sans-serif" font-size="11" fill="#6b7280" text-anchor="middle">Low</text>
  <text x="280" y="55" font-family="Arial, sans-serif" font-size="11" fill="#6b7280" text-anchor="middle">Medium</text>
  <text x="380" y="55" font-family="Arial, sans-serif" font-size="11" fill="#6b7280" text-anchor="middle">High</text>

  <!-- Row label IMPACT -->
  <text x="35" y="175" font-family="Arial, sans-serif" font-size="14" font-weight="bold" fill="#374151" text-anchor="middle" transform="rotate(-90, 35, 175)">IMPACT</text>

  <!-- Row labels -->
  <text x="80" y="105" font-family="Arial, sans-serif" font-size="11" fill="#6b7280" text-anchor="middle">High</text>
  <text x="80" y="175" font-family="Arial, sans-serif" font-size="11" fill="#6b7280" text-anchor="middle">Med</text>
  <text x="80" y="245" font-family="Arial, sans-serif" font-size="11" fill="#6b7280" text-anchor="middle">Low</text>

  <!-- Grid cells - Row 1 (High Impact) -->
  <rect x="130" y="70" width="100" height="70" fill="#fbbf24" stroke="#e5e7eb" stroke-width="1" rx="4"/>
  <rect x="230" y="70" width="100" height="70" fill="#f97316" stroke="#e5e7eb" stroke-width="1" rx="4"/>
  <rect x="330" y="70" width="100" height="70" fill="#dc2626" stroke="#e5e7eb" stroke-width="1" rx="4"/>

  <!-- Grid cells - Row 2 (Med Impact) -->
  <rect x="130" y="140" width="100" height="70" fill="#22c55e" stroke="#e5e7eb" stroke-width="1" rx="4"/>
  <rect x="230" y="140" width="100" height="70" fill="#fbbf24" stroke="#e5e7eb" stroke-width="1" rx="4"/>
  <rect x="330" y="140" width="100" height="70" fill="#f97316" stroke="#e5e7eb" stroke-width="1" rx="4"/>

  <!-- Grid cells - Row 3 (Low Impact) -->
  <rect x="130" y="210" width="100" height="70" fill="#94a3b8" stroke="#e5e7eb" stroke-width="1" rx="4"/>
  <rect x="230" y="210" width="100" height="70" fill="#22c55e" stroke="#e5e7eb" stroke-width="1" rx="4"/>
  <rect x="330" y="210" width="100" height="70" fill="#fbbf24" stroke="#e5e7eb" stroke-width="1" rx="4"/>

  <!-- Cell labels and counts -->
  <text x="180" y="100" font-family="Arial, sans-serif" font-size="10" fill="#fff" text-anchor="middle">Medium</text>
  <text x="180" y="118" font-family="Arial, sans-serif" font-size="18" font-weight="bold" fill="#fff" text-anchor="middle">{{ risk_matrix.high_low | default(0) }}</text>

  <text x="280" y="100" font-family="Arial, sans-serif" font-size="10" fill="#fff" text-anchor="middle">High</text>
  <text x="280" y="118" font-family="Arial, sans-serif" font-size="18" font-weight="bold" fill="#fff" text-anchor="middle">{{ risk_matrix.high_med | default(0) }}</text>

  <text x="380" y="100" font-family="Arial, sans-serif" font-size="10" fill="#fff" text-anchor="middle">Critical</text>
  <text x="380" y="118" font-family="Arial, sans-serif" font-size="18" font-weight="bold" fill="#fff" text-anchor="middle">{{ risk_matrix.high_high | default(0) }}</text>

  <text x="180" y="170" font-family="Arial, sans-serif" font-size="10" fill="#fff" text-anchor="middle">Low</text>
  <text x="180" y="188" font-family="Arial, sans-serif" font-size="18" font-weight="bold" fill="#fff" text-anchor="middle">{{ risk_matrix.med_low | default(0) }}</text>

  <text x="280" y="170" font-family="Arial, sans-serif" font-size="10" fill="#fff" text-anchor="middle">Medium</text>
  <text x="280" y="188" font-family="Arial, sans-serif" font-size="18" font-weight="bold" fill="#fff" text-anchor="middle">{{ risk_matrix.med_med | default(0) }}</text>

  <text x="380" y="170" font-family="Arial, sans-serif" font-size="10" fill="#fff" text-anchor="middle">High</text>
  <text x="380" y="188" font-family="Arial, sans-serif" font-size="18" font-weight="bold" fill="#fff" text-anchor="middle">{{ risk_matrix.med_high | default(0) }}</text>

  <text x="180" y="240" font-family="Arial, sans-serif" font-size="10" fill="#fff" text-anchor="middle">Info</text>
  <text x="180" y="258" font-family="Arial, sans-serif" font-size="18" font-weight="bold" fill="#fff" text-anchor="middle">{{ risk_matrix.low_low | default(0) }}</text>

  <text x="280" y="240" font-family="Arial, sans-serif" font-size="10" fill="#fff" text-anchor="middle">Low</text>
  <text x="280" y="258" font-family="Arial, sans-serif" font-size="18" font-weight="bold" fill="#fff" text-anchor="middle">{{ risk_matrix.low_med | default(0) }}</text>

  <text x="380" y="240" font-family="Arial, sans-serif" font-size="10" fill="#fff" text-anchor="middle">Medium</text>
  <text x="380" y="258" font-family="Arial, sans-serif" font-size="18" font-weight="bold" fill="#fff" text-anchor="middle">{{ risk_matrix.low_high | default(0) }}</text>
</svg>

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

{% if llm_risk_narrative %}
{{ llm_risk_narrative }}
{% else %}
The analyzed contract presents security concerns that should be addressed before production deployment. The combination of findings indicates potential for exploitation if left unmitigated.
{% endif %}

---

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

---

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

{% if finding.attack_scenario %}
### Attack Scenario

{{ finding.attack_scenario }}

**Step-by-step:**
{% for step in finding.attack_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}
{% endif %}

### Recommendation

{{ finding.recommendation }}

{% if finding.remediation_code %}
### Suggested Fix

```diff
{{ finding.remediation_code }}
```

**Remediation Effort:** {{ finding.remediation_effort | default('Medium') }}
**Estimated Fix Time:** {{ finding.fix_time | default('1-2 hours') }}
{% endif %}

{% if llm_enabled and finding.llm_interpretation %}
### AI Analysis

*Generated by {{ llm_model }}*

{{ finding.llm_interpretation }}
{% endif %}

### References

{% for ref in finding.references %}
- {{ ref }}
{% endfor %}

---

{% endfor %}

---

# 6. Remediation Roadmap

## 6.1 Prioritized Actions

{% if llm_enabled and llm_remediation_priority %}
| Priority | Finding | Severity | Effort | Rationale |
|:--------:|---------|----------|--------|-----------|
{%- for item in llm_remediation_priority %}
| {{ item.priority }} | {{ item.title }} | {{ item.severity }} | {{ item.effort }} | {{ item.reason }} |
{%- endfor %}
{% else %}
| Priority | Finding | Severity | Recommended Action |
|:--------:|---------|----------|-------------------|
{%- for finding in findings %}
{%- if finding.severity in ['Critical', 'High'] %}
| {{ loop.index }} | {{ finding.title }} | {{ finding.severity }} | Immediate fix required |
{%- endif %}
{%- endfor %}
{% endif %}

## 6.2 Remediation Timeline

<svg viewBox="0 0 600 200" xmlns="http://www.w3.org/2000/svg" style="max-width: 600px; margin: 20px auto; display: block;">
  <!-- Timeline base line -->
  <line x1="50" y1="100" x2="550" y2="100" stroke="#e5e7eb" stroke-width="4" stroke-linecap="round"/>

  <!-- Week 1 - Critical & High -->
  <circle cx="100" cy="100" r="20" fill="#dc2626"/>
  <text x="100" y="106" font-family="Arial, sans-serif" font-size="11" fill="#fff" text-anchor="middle" font-weight="bold">W1</text>
  <text x="100" y="75" font-family="Arial, sans-serif" font-size="10" fill="#374151" text-anchor="middle" font-weight="bold">Critical & High</text>
  <text x="100" y="140" font-family="Arial, sans-serif" font-size="9" fill="#6b7280" text-anchor="middle">{{ critical_count }} Critical</text>
  <text x="100" y="155" font-family="Arial, sans-serif" font-size="9" fill="#6b7280" text-anchor="middle">{{ high_count }} High</text>

  <!-- Week 2 - Medium -->
  <circle cx="225" cy="100" r="20" fill="#f97316"/>
  <text x="225" y="106" font-family="Arial, sans-serif" font-size="11" fill="#fff" text-anchor="middle" font-weight="bold">W2</text>
  <text x="225" y="75" font-family="Arial, sans-serif" font-size="10" fill="#374151" text-anchor="middle" font-weight="bold">Medium</text>
  <text x="225" y="140" font-family="Arial, sans-serif" font-size="9" fill="#6b7280" text-anchor="middle">{{ medium_count }} Medium</text>
  <text x="225" y="155" font-family="Arial, sans-serif" font-size="9" fill="#6b7280" text-anchor="middle">findings</text>

  <!-- Week 3 - Low & Info -->
  <circle cx="350" cy="100" r="20" fill="#22c55e"/>
  <text x="350" y="106" font-family="Arial, sans-serif" font-size="11" fill="#fff" text-anchor="middle" font-weight="bold">W3</text>
  <text x="350" y="75" font-family="Arial, sans-serif" font-size="10" fill="#374151" text-anchor="middle" font-weight="bold">Low & Info</text>
  <text x="350" y="140" font-family="Arial, sans-serif" font-size="9" fill="#6b7280" text-anchor="middle">{{ low_count }} Low</text>
  <text x="350" y="155" font-family="Arial, sans-serif" font-size="9" fill="#6b7280" text-anchor="middle">{{ info_count }} Info</text>

  <!-- Week 4 - Verification -->
  <circle cx="475" cy="100" r="20" fill="#3b82f6"/>
  <text x="475" y="106" font-family="Arial, sans-serif" font-size="11" fill="#fff" text-anchor="middle" font-weight="bold">W4</text>
  <text x="475" y="75" font-family="Arial, sans-serif" font-size="10" fill="#374151" text-anchor="middle" font-weight="bold">Verification</text>
  <text x="475" y="140" font-family="Arial, sans-serif" font-size="9" fill="#6b7280" text-anchor="middle">Re-audit &</text>
  <text x="475" y="155" font-family="Arial, sans-serif" font-size="9" fill="#6b7280" text-anchor="middle">Validation</text>

  <!-- Arrows between phases -->
  <path d="M125 100 L195 100" stroke="#9ca3af" stroke-width="2" marker-end="url(#arrowhead)"/>
  <path d="M250 100 L320 100" stroke="#9ca3af" stroke-width="2" marker-end="url(#arrowhead)"/>
  <path d="M375 100 L445 100" stroke="#9ca3af" stroke-width="2" marker-end="url(#arrowhead)"/>

  <!-- Arrow marker definition -->
  <defs>
    <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
      <polygon points="0 0, 10 3.5, 0 7" fill="#9ca3af"/>
    </marker>
  </defs>
</svg>

## 6.3 Quick Wins

{% if quick_wins %}
The following fixes provide high security impact with minimal effort:

{% for win in quick_wins %}
- **{{ win.title }}** - {{ win.description }}
{% endfor %}
{% else %}
Review findings marked as "Low" effort for quick security improvements.
{% endif %}

## 6.4 Effort vs Impact Matrix

<svg viewBox="0 0 450 320" xmlns="http://www.w3.org/2000/svg" style="max-width: 450px; margin: 20px auto; display: block;">
  <!-- Title -->
  <text x="280" y="25" font-family="Arial, sans-serif" font-size="14" font-weight="bold" fill="#374151" text-anchor="middle">IMPACT</text>

  <!-- Column headers -->
  <text x="180" y="55" font-family="Arial, sans-serif" font-size="11" fill="#6b7280" text-anchor="middle">Low</text>
  <text x="280" y="55" font-family="Arial, sans-serif" font-size="11" fill="#6b7280" text-anchor="middle">Medium</text>
  <text x="380" y="55" font-family="Arial, sans-serif" font-size="11" fill="#6b7280" text-anchor="middle">High</text>

  <!-- Row label EFFORT -->
  <text x="35" y="175" font-family="Arial, sans-serif" font-size="14" font-weight="bold" fill="#374151" text-anchor="middle" transform="rotate(-90, 35, 175)">EFFORT</text>

  <!-- Row labels -->
  <text x="80" y="105" font-family="Arial, sans-serif" font-size="11" fill="#6b7280" text-anchor="middle">High</text>
  <text x="80" y="175" font-family="Arial, sans-serif" font-size="11" fill="#6b7280" text-anchor="middle">Med</text>
  <text x="80" y="245" font-family="Arial, sans-serif" font-size="11" fill="#6b7280" text-anchor="middle">Low</text>

  <!-- Grid cells - Row 1 (High Effort) -->
  <rect x="130" y="70" width="100" height="70" fill="#ef4444" stroke="#e5e7eb" stroke-width="1" rx="4"/>
  <rect x="230" y="70" width="100" height="70" fill="#f97316" stroke="#e5e7eb" stroke-width="1" rx="4"/>
  <rect x="330" y="70" width="100" height="70" fill="#eab308" stroke="#e5e7eb" stroke-width="1" rx="4"/>

  <!-- Grid cells - Row 2 (Med Effort) -->
  <rect x="130" y="140" width="100" height="70" fill="#94a3b8" stroke="#e5e7eb" stroke-width="1" rx="4"/>
  <rect x="230" y="140" width="100" height="70" fill="#3b82f6" stroke="#e5e7eb" stroke-width="1" rx="4"/>
  <rect x="330" y="140" width="100" height="70" fill="#8b5cf6" stroke="#e5e7eb" stroke-width="1" rx="4"/>

  <!-- Grid cells - Row 3 (Low Effort) -->
  <rect x="130" y="210" width="100" height="70" fill="#64748b" stroke="#e5e7eb" stroke-width="1" rx="4"/>
  <rect x="230" y="210" width="100" height="70" fill="#22c55e" stroke="#e5e7eb" stroke-width="1" rx="4"/>
  <rect x="330" y="210" width="100" height="70" fill="#16a34a" stroke="#e5e7eb" stroke-width="1" rx="4"/>

  <!-- Cell labels -->
  <text x="180" y="110" font-family="Arial, sans-serif" font-size="12" font-weight="bold" fill="#fff" text-anchor="middle">Avoid</text>
  <text x="280" y="110" font-family="Arial, sans-serif" font-size="12" font-weight="bold" fill="#fff" text-anchor="middle">Consider</text>
  <text x="380" y="110" font-family="Arial, sans-serif" font-size="12" font-weight="bold" fill="#fff" text-anchor="middle">Schedule</text>

  <text x="180" y="180" font-family="Arial, sans-serif" font-size="12" font-weight="bold" fill="#fff" text-anchor="middle">Defer</text>
  <text x="280" y="180" font-family="Arial, sans-serif" font-size="12" font-weight="bold" fill="#fff" text-anchor="middle">Plan</text>
  <text x="380" y="180" font-family="Arial, sans-serif" font-size="12" font-weight="bold" fill="#fff" text-anchor="middle">Priority</text>

  <text x="180" y="250" font-family="Arial, sans-serif" font-size="12" font-weight="bold" fill="#fff" text-anchor="middle">If Time</text>
  <text x="280" y="250" font-family="Arial, sans-serif" font-size="12" font-weight="bold" fill="#fff" text-anchor="middle">Quick Win</text>
  <text x="380" y="250" font-family="Arial, sans-serif" font-size="12" font-weight="bold" fill="#fff" text-anchor="middle">DO FIRST!</text>
</svg>

---

# 7. Appendices

## Appendix A: Tool Execution Details

{% for tool in tool_outputs %}
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

{% endfor %}

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

---

# Disclaimer

This audit report is provided on an "AS IS" basis without warranties of any kind, whether express or implied. The findings and recommendations represent the auditor's professional opinion based on the scope and methodology described.

**Limitations:**
- This audit does not guarantee the absence of vulnerabilities
- Smart contract security is an evolving field
- New vulnerabilities may be discovered post-audit
- Economic and governance attacks may not be fully modeled
- The client is responsible for implementing and testing fixes

{% if llm_enabled %}
**AI Disclosure:** Sections labeled as "AI-Generated" or "AI Analysis" were produced using large language models ({{ llm_model }}). These AI-generated insights are supplementary and should be reviewed by qualified security professionals. AI outputs may contain inaccuracies and are provided for informational purposes only.
{% endif %}

---

<div class="footer" style="text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ccc;">

**Powered by [MIESC](https://github.com/fboiero/MIESC)**

Multi-layer Intelligent Evaluation for Smart Contracts

*Report generated: {{ generation_date }}*

*Report Version: {{ report_version | default('1.0') }}*

</div>
