<!-- COVER PAGE -->
<div class="cover-page">

<div style="margin-bottom: 40px;">
<h1 style="font-size: 38pt; margin-bottom: 10px; color: white; border: none;"><svg width="42" height="42" viewBox="0 0 24 24" style="vertical-align: -6px; margin-right: 12px;" xmlns="http://www.w3.org/2000/svg"><path d="M12 2L4 5v6c0 5 3.4 8.9 8 11 4.6-2.1 8-6 8-11V5l-8-3z" fill="#ffffff"/><path d="M9.1 11.9l2 2 3.7-4" fill="none" stroke="#1e293b" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>MIESC</h1>
<p style="font-size: 13pt; color: #cbd5e1;">Multi-layer Intelligent Evaluation for Smart Contracts</p>
</div>

<h2 style="font-size: 26pt; font-weight: 300; color: white; margin: 30px 0;">Smart Contract Security Audit</h2>

<div style="background: rgba(255,255,255,0.1); border-radius: 12px; padding: 25px; margin: 25px 0;">
<h3 style="font-size: 20pt; color: #60a5fa; border: none; margin: 0;">{{ contract_name }}</h3>
<p style="color: #cbd5e1; margin-top: 8px; font-size: 12pt;">{{ client_name | default('Client') }}</p>
</div>

<div style="margin-top: 40px; text-align: left; display: inline-block;">
<table style="background: transparent; border: none; font-size: 11pt;">
<tr><td style="color: #cbd5e1; border: none; padding: 6px 20px 6px 0;">Prepared by:</td><td style="color: white; border: none; padding: 6px 0;"><strong>{{ auditor_name | default('MIESC Security') }}</strong></td></tr>
<tr><td style="color: #cbd5e1; border: none; padding: 6px 20px 6px 0;">Audit Date:</td><td style="color: white; border: none; padding: 6px 0;"><strong>{{ audit_date }}</strong></td></tr>
<tr><td style="color: #cbd5e1; border: none; padding: 6px 20px 6px 0;">Report Date:</td><td style="color: white; border: none; padding: 6px 0;"><strong>{{ generation_date }}</strong></td></tr>
<tr><td style="color: #cbd5e1; border: none; padding: 6px 20px 6px 0;">Version:</td><td style="color: white; border: none; padding: 6px 0;"><strong>{{ report_version | default('1.0') }}</strong></td></tr>
<tr><td style="color: #cbd5e1; border: none; padding: 6px 20px 6px 0;">Network:</td><td style="color: white; border: none; padding: 6px 0;"><strong>{{ network | default('Ethereum Mainnet') }}</strong></td></tr>
</table>
</div>

<div style="margin-top: 35px;">
<span style="background: #dc3545; color: white; padding: 8px 24px; border-radius: 4px; font-weight: 600; font-size: 11pt; letter-spacing: 1px;">{{ classification | default('CONFIDENTIAL') }}</span>
</div>

<p style="color: #94a3b8; font-size: 8pt; margin-top: 40px; max-width: 400px;">
This document contains confidential security findings and is intended solely for the named addressee. Unauthorized distribution, reproduction, or disclosure is prohibited.
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

{{ key_takeaways | default(llm_executive_summary | default('No AI summary available.')) }}

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

<div class="chart chart-severity">
{%- if total_findings and (total_findings | int) > 0 %}
{%- set s = 380 / (total_findings | int) %}
<svg viewBox="0 0 520 172" width="520" height="172" role="img" aria-label="Findings by severity" xmlns="http://www.w3.org/2000/svg" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif">
<text x="88" y="28" text-anchor="end" font-size="10" font-weight="600" fill="#1e293b">Critical</text>
<rect x="96" y="16" width="380" height="16" rx="3" fill="#eef2f7"/>
<rect x="96" y="16" width="{{ (critical_count * s) | round(2) }}" height="16" rx="3" fill="#dc2626"/>
<text x="{{ (102 + critical_count * s) | round(2) }}" y="28" font-size="10" font-weight="700" fill="#334155">{{ critical_count }}</text>
<text x="88" y="59" text-anchor="end" font-size="10" font-weight="600" fill="#1e293b">High</text>
<rect x="96" y="47" width="380" height="16" rx="3" fill="#eef2f7"/>
<rect x="96" y="47" width="{{ (high_count * s) | round(2) }}" height="16" rx="3" fill="#f97316"/>
<text x="{{ (102 + high_count * s) | round(2) }}" y="59" font-size="10" font-weight="700" fill="#334155">{{ high_count }}</text>
<text x="88" y="90" text-anchor="end" font-size="10" font-weight="600" fill="#1e293b">Medium</text>
<rect x="96" y="78" width="380" height="16" rx="3" fill="#eef2f7"/>
<rect x="96" y="78" width="{{ (medium_count * s) | round(2) }}" height="16" rx="3" fill="#eab308"/>
<text x="{{ (102 + medium_count * s) | round(2) }}" y="90" font-size="10" font-weight="700" fill="#334155">{{ medium_count }}</text>
<text x="88" y="121" text-anchor="end" font-size="10" font-weight="600" fill="#1e293b">Low</text>
<rect x="96" y="109" width="380" height="16" rx="3" fill="#eef2f7"/>
<rect x="96" y="109" width="{{ (low_count * s) | round(2) }}" height="16" rx="3" fill="#3b82f6"/>
<text x="{{ (102 + low_count * s) | round(2) }}" y="121" font-size="10" font-weight="700" fill="#334155">{{ low_count }}</text>
<text x="88" y="152" text-anchor="end" font-size="10" font-weight="600" fill="#1e293b">Info</text>
<rect x="96" y="140" width="380" height="16" rx="3" fill="#eef2f7"/>
<rect x="96" y="140" width="{{ (info_count * s) | round(2) }}" height="16" rx="3" fill="#64748b"/>
<text x="{{ (102 + info_count * s) | round(2) }}" y="152" font-size="10" font-weight="700" fill="#334155">{{ info_count }}</text>
</svg>
<span class="chart-caption">Figure 1 — Findings by severity ({{ total_findings | int }} total). Bar length is proportional to each severity's share of all findings.</span>
{%- else %}
<p style="text-align:center;color:#64748b;font-style:italic;">No findings to chart.</p>
{%- endif %}
</div>

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
| **Availability** | {{ availability_rating | default('Low') }} - {{ availability_note | default('No significant availability risks identified') }} |
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
{%- if scope_source_unavailable %}

> Line counts shown as `—` could not be measured: source not available at report time for one or more in-scope files.
{%- endif %}

### Out of Scope

{%- if out_of_scope %}

The following were not exercised in this run and are therefore outside the analysed scope:
{%- for item in out_of_scope %}
- {{ item }}
{%- endfor %}
{%- else %}

Out-of-scope boundaries were not explicitly assessed in this engagement.
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

1. **Initial Assessment** - Parse the target sources and build the analysis scope
2. **Automated Analysis** - Execute the multi-layer tool suite
3. **Multi-Tool Analysis** - Automated static, dynamic, and symbolic analysis across the defense-in-depth layers
4. **AI Correlation** - Cross-reference findings, reduce false positives
5. **Corroboration & Filtering** - Cross-tool corroboration, false-positive filtering, and execution-based confirmation where enabled
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

<div class="chart chart-matrix">
<svg viewBox="0 0 470 268" width="470" height="268" role="img" aria-label="Risk matrix by impact and likelihood" xmlns="http://www.w3.org/2000/svg" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif">
<text x="274" y="18" text-anchor="middle" font-size="10" font-weight="700" letter-spacing="1" fill="#475569">LIKELIHOOD</text>
<text x="170" y="38" text-anchor="middle" font-size="9" fill="#6b7280">Low</text>
<text x="274" y="38" text-anchor="middle" font-size="9" fill="#6b7280">Medium</text>
<text x="378" y="38" text-anchor="middle" font-size="9" fill="#6b7280">High</text>
<text x="22" y="144" text-anchor="middle" font-size="10" font-weight="700" letter-spacing="1" fill="#475569" transform="rotate(-90 22 144)">IMPACT</text>
<text x="112" y="80" text-anchor="end" font-size="9" font-weight="600" fill="#475569">High</text>
<text x="112" y="148" text-anchor="end" font-size="9" font-weight="600" fill="#475569">Med</text>
<text x="112" y="216" text-anchor="end" font-size="9" font-weight="600" fill="#475569">Low</text>
<rect x="120" y="44" width="100" height="64" rx="4" fill="#fbbf24"/>
<text x="170" y="66" text-anchor="middle" font-size="8" fill="#ffffff">Medium</text>
<text x="170" y="92" text-anchor="middle" font-size="19" font-weight="700" fill="#ffffff">{{ risk_matrix.high_low | default(0) }}</text>
<rect x="224" y="44" width="100" height="64" rx="4" fill="#f97316"/>
<text x="274" y="66" text-anchor="middle" font-size="8" fill="#ffffff">High</text>
<text x="274" y="92" text-anchor="middle" font-size="19" font-weight="700" fill="#ffffff">{{ risk_matrix.high_med | default(0) }}</text>
<rect x="328" y="44" width="100" height="64" rx="4" fill="#dc2626"/>
<text x="378" y="66" text-anchor="middle" font-size="8" fill="#ffffff">Critical</text>
<text x="378" y="92" text-anchor="middle" font-size="19" font-weight="700" fill="#ffffff">{{ risk_matrix.high_high | default(0) }}</text>
<rect x="120" y="112" width="100" height="64" rx="4" fill="#22c55e"/>
<text x="170" y="134" text-anchor="middle" font-size="8" fill="#ffffff">Low</text>
<text x="170" y="160" text-anchor="middle" font-size="19" font-weight="700" fill="#ffffff">{{ risk_matrix.med_low | default(0) }}</text>
<rect x="224" y="112" width="100" height="64" rx="4" fill="#fbbf24"/>
<text x="274" y="134" text-anchor="middle" font-size="8" fill="#ffffff">Medium</text>
<text x="274" y="160" text-anchor="middle" font-size="19" font-weight="700" fill="#ffffff">{{ risk_matrix.med_med | default(0) }}</text>
<rect x="328" y="112" width="100" height="64" rx="4" fill="#f97316"/>
<text x="378" y="134" text-anchor="middle" font-size="8" fill="#ffffff">High</text>
<text x="378" y="160" text-anchor="middle" font-size="19" font-weight="700" fill="#ffffff">{{ risk_matrix.med_high | default(0) }}</text>
<rect x="120" y="180" width="100" height="64" rx="4" fill="#94a3b8"/>
<text x="170" y="202" text-anchor="middle" font-size="8" fill="#ffffff">Info</text>
<text x="170" y="228" text-anchor="middle" font-size="19" font-weight="700" fill="#ffffff">{{ risk_matrix.low_low | default(0) }}</text>
<rect x="224" y="180" width="100" height="64" rx="4" fill="#22c55e"/>
<text x="274" y="202" text-anchor="middle" font-size="8" fill="#ffffff">Low</text>
<text x="274" y="228" text-anchor="middle" font-size="19" font-weight="700" fill="#ffffff">{{ risk_matrix.low_med | default(0) }}</text>
<rect x="328" y="180" width="100" height="64" rx="4" fill="#fbbf24"/>
<text x="378" y="202" text-anchor="middle" font-size="8" fill="#ffffff">Medium</text>
<text x="378" y="228" text-anchor="middle" font-size="19" font-weight="700" fill="#ffffff">{{ risk_matrix.low_high | default(0) }}</text>
</svg>
<span class="chart-caption">Figure 2 — Risk matrix. Each cell counts findings at that impact / likelihood pairing; colour encodes the resulting risk band.</span>
</div>

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
The analysed contract presents security concerns that should be resolved before production deployment. Taken together, the findings indicate a credible potential for exploitation if left unmitigated.
{%- endif %}

<!-- section-break -->

# 4. Findings Overview
## 4.1 Summary Table

| ID | Title | Severity | Confidence | Tools | Verification | Status | CVSS |
|----|-------|----------|:----------:|------:|--------------|--------|-----:|
{%- for finding in findings %}
| {{ finding.id }} | {{ finding.title }} | {{ finding.severity_badge }} | {{ finding.confidence_pct | default('') }} | {{ finding.tool_count | default(1) }} | {{ finding.verification }} | {{ finding.status }} | {{ finding.cvss_score | default('--') }} |
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

## 4.4 Property & Invariant Analysis

This section reports the formal and invariant evidence layer separately from the
static findings above. An execution-verified finding is a counterexample that was
reproduced by running the call under Foundry: a dynamic counterexample, not a
formal proof. No invariant is asserted as mathematically established here.

{%- if not formal_verification_tools and not execution_verified_findings %}

**Not performed in this engagement.** Neither formal verification (Layer 4) nor
execution-based invariant checking produced evidence for this contract. To enable
the execution-verified invariant layer, run the deep-audit agent with
`enable_gap_execution` (access-control gaps) and/or `enable_gap_reasoning`
(pause and freshness gaps).
{%- else %}

### 4.4.1 Formal Verification (Layer 4)

{%- if formal_verification_tools %}

Tool execution status and finding counts only — no invariant is reported as
established by these tools.

| Tool | Status | Findings |
|------|--------|---------:|
{%- for tool in formal_verification_tools %}
| {{ tool.name }} | {{ tool.status_icon }} {{ tool.status }} | {{ tool.findings_count | default(0) }} |
{%- endfor %}
{%- else %}

No formal-verification tool (certora, smtchecker, scribble, pyrometer,
propertygpt) ran in this engagement.
{%- endif %}

### 4.4.2 Execution-Verified Findings

{%- if execution_verified_findings %}

The following findings were reproduced by execution under Foundry — a dynamic
counterexample, not a formal proof.

{%- for finding in execution_verified_findings %}

**{{ finding.id }}. {{ finding.title }}** &nbsp; {{ finding.severity_badge }} &nbsp; `{{ finding.location }}`

- **Verification:** {{ finding.verification }}
{%- for line in finding.evidence %}
- Evidence: {{ line }}
{%- endfor %}
{%- endfor %}
{%- else %}

No execution-verified counterexamples were produced in this engagement.
{%- endif %}
{%- endif %}

## 4.5 Trust Model & Privileged Roles
{%- if not governance_plans and not trust_inventory_ran and not trust_findings %}

**Trust model not assessed in this engagement.** No privileged-role inventory was
extracted and no trust-relevant findings (access control, centralization, or
proxy/upgrade) were reported.
{%- else %}

This section inventories the privileged actors and roles the contract source declares
and cross-references the trust-relevant findings above. It is an **advisory static
model of authority**, not a governance audit: a role is a trust assumption, not a
vulnerability, and nothing here changes any finding count or the risk score.

> **Custody.** This audit did not verify key custody or off-chain governance; roles are
> as declared in source. An account named `owner` is not assumed to be a multisig or a
> timelock.
>
> **Completeness.** The role inventory is identified by static extraction; it may miss
> inherited, proxied, or assembly-level authority and may be incomplete. The extracted
> role graph is produced for single-file agentic audits only — directory audits carry
> the findings-based cross-reference in §4.5.2 but no extracted role graph.

### 4.5.1 Privileged roles identified
{%- if governance_plans %}

Identified by static extraction (advisory). Each actor and role is anchored to the
source lines where it was observed.
{%- for plan in governance_plans %}

{{ plan.objective }}
{%- if plan.actors %}

**Actors**

| Actor | Declared kind | Source | Guards functions | Source anchors |
|-------|---------------|--------|------------------|----------------|
{%- for actor in plan.actors %}
| `{{ actor.id }}` | {{ actor.kind }} | {{ actor.source }} | {{ actor.guards | default('—', true) }} | {{ actor.anchors | default('—', true) }} |
{%- endfor %}
{%- endif %}
{%- if plan.roles %}

**Roles**

| Role | Admin role | Guards functions | Grant functions | Revoke functions |
|------|------------|------------------|-----------------|------------------|
{%- for role in plan.roles %}
| `{{ role.name }}` | {{ role.admin_role | default('—', true) }} | {{ role.guards | default('—', true) }} | {{ role.grant_functions | default('—', true) }} | {{ role.revoke_functions | default('—', true) }} |
{%- endfor %}
{%- endif %}
{%- if plan.truncated %}

_Note: this inventory reached the per-list extraction cap and may be truncated._
{%- endif %}
{%- endfor %}
{%- elif trust_inventory_ran %}

Static extraction ran; no privileged actors or roles were identified in the analyzed
source. This does not establish that none exist (see the completeness note above).
{%- else %}

Role inventory not extracted in this engagement. Enable it with `enable_advisory_plans`
(single-file agentic audits).
{%- endif %}

### 4.5.2 Trust-relevant findings
{%- if trust_findings %}

Findings above whose canonical category concerns privileged authority (access control,
centralization, or proxy/upgrade), cross-referenced by id and severity. The detail and
scoring stay in §5; this is a cross-reference, not a new finding.

| Finding | Title | Category | Severity |
|---------|-------|----------|----------|
{%- for f in trust_findings %}
| {{ f.id }} | {{ f.title }} | {{ f.category }} | {{ f.severity_badge }} |
{%- endfor %}
{%- else %}

No trust-relevant findings (access control, centralization, or proxy/upgrade) were
reported in this engagement.
{%- endif %}
{%- endif %}

## 4.6 Dynamic Testing & Fuzzing
{%- if fuzzing_tools %}

Fuzzing campaigns ran in this engagement. The metrics below describe each campaign's
scope and outcome and correspond to **Layer 2 (Dynamic Testing)** of the methodology
(§2.3). A campaign statistic is not a finding: any issue a fuzzer produced is already
counted in §1 and detailed in §5, and is cross-referenced here by id, never re-counted.
{%- for ft in fuzzing_tools %}
{%- if ft.is_foundry %}
{%- if ft.stats_unparsed %}

- **{{ ft.display }} test suite:** ran with a configured {{ ft.fuzz_runs | default('--', true) }} fuzz runs per test; campaign statistics could not be parsed from the tool output.{% if ft.finding_ids %} Findings reproduced by execution: {{ ft.finding_ids }}.{% endif %}
{%- else %}

- **{{ ft.display }} test suite:** {{ ft.tests_run }} tests ({{ ft.tests_passed | default(0, true) }} passed / {{ ft.tests_failed | default(0, true) }} failed), configured {{ ft.fuzz_runs | default('--', true) }} fuzz runs per test.{% if ft.finding_ids %} Findings reproduced by execution: {{ ft.finding_ids }}.{% endif %}
{%- endif %}
{%- else %}

- **{{ ft.display }}:** configured test limit {{ ft.test_limit | default('--', true) }} (a cap, not the number of sequences run); {{ ft.property_violations | default(0, true) }} property violations reported by the tool.{% if ft.finding_ids %} See {{ ft.finding_ids }}.{% endif %}
{%- endif %}
{%- endfor %}
{%- elif dynamic_layer_ran %}

Dynamic-testing tooling ran in this engagement (**Layer 2**, §2.3) but recorded no
fuzzing-campaign statistics. Any results reproduced by execution are reported in §4.4
(Property & Invariant Analysis).
{%- else %}

No dynamic or fuzzing testing was performed in this engagement. This is **Layer 2
(Dynamic Testing)** of the methodology (§2.3); property-based fuzzing with Foundry,
Echidna, or Medusa would supply this layer.
{%- endif %}

<!-- section-break -->

# 5. Detailed Findings
{%- for finding in findings %}

## {{ finding.id }}. {{ finding.title }}

| Property | Value |
|----------|-------|
| **Severity** | <span style="background: {{ finding.severity_color | default('#e0e0e0') }}; color: white; padding: 2px 8px; border-radius: 4px;">{{ finding.severity_badge }}</span> |
| **Category** | {{ finding.canonical_category or finding.category }} |
| **CVSS Score** | {{ finding.cvss_score | default('N/A') }} |
| **Confidence** | {{ finding.confidence_pct | default('N/A') }} |
| **Location** | `{{ finding.location }}` |
| **Status** | {{ finding.status }} |
| **Detected By** | {{ finding.confirming_tools | join(', ') if finding.confirming_tools else finding.tool }} |
| **Verification** | {{ finding.verification }} |

### Description

{{ finding.description }}

### Vulnerable Code

```solidity
{{ finding.vulnerable_code }}
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

### Model-Assisted Analysis

*Generated by {{ llm_model }}*

{{ finding.llm_interpretation }}
{%- endif %}

### References
{%- for ref in finding.references %}
- {{ ref }}
{%- endfor %}
{%- if not finding.references %}
- [OWASP Smart Contract Top 10](https://owasp.org/www-project-smart-contract-top-10/)
{%- endif %}

{%- endfor %}

<!-- section-break -->

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
{%- for finding in critical_high_findings %}
| {{ loop.index }} | {{ finding.title }} | {{ finding.severity_badge }} | Immediate fix required |
{%- endfor %}
{%- if not critical_high_findings %}
| -- | No critical or high severity findings | -- | -- |
{%- endif %}
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

<div class="chart chart-effort">
{%- if effort_impact_matrix %}
<svg viewBox="0 0 470 268" width="470" height="268" role="img" aria-label="Effort versus impact matrix" xmlns="http://www.w3.org/2000/svg" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif">
<text x="274" y="18" text-anchor="middle" font-size="10" font-weight="700" letter-spacing="1" fill="#475569">IMPACT</text>
<text x="170" y="38" text-anchor="middle" font-size="9" fill="#6b7280">Low</text>
<text x="274" y="38" text-anchor="middle" font-size="9" fill="#6b7280">Medium</text>
<text x="378" y="38" text-anchor="middle" font-size="9" fill="#6b7280">High</text>
<text x="22" y="144" text-anchor="middle" font-size="10" font-weight="700" letter-spacing="1" fill="#475569" transform="rotate(-90 22 144)">EFFORT</text>
<text x="112" y="80" text-anchor="end" font-size="9" font-weight="600" fill="#475569">High</text>
<text x="112" y="148" text-anchor="end" font-size="9" font-weight="600" fill="#475569">Med</text>
<text x="112" y="216" text-anchor="end" font-size="9" font-weight="600" fill="#475569">Low</text>
<rect x="120" y="44" width="100" height="64" rx="4" fill="#ef4444"/>
<text x="170" y="66" text-anchor="middle" font-size="8" fill="#ffffff">Avoid</text>
<text x="170" y="92" text-anchor="middle" font-size="19" font-weight="700" fill="#ffffff">{{ effort_impact_matrix.high_low.count }}</text>
<rect x="224" y="44" width="100" height="64" rx="4" fill="#f97316"/>
<text x="274" y="66" text-anchor="middle" font-size="8" fill="#ffffff">Consider</text>
<text x="274" y="92" text-anchor="middle" font-size="19" font-weight="700" fill="#ffffff">{{ effort_impact_matrix.high_medium.count }}</text>
<rect x="328" y="44" width="100" height="64" rx="4" fill="#eab308"/>
<text x="378" y="66" text-anchor="middle" font-size="8" fill="#ffffff">Schedule</text>
<text x="378" y="92" text-anchor="middle" font-size="19" font-weight="700" fill="#ffffff">{{ effort_impact_matrix.high_high.count }}</text>
<rect x="120" y="112" width="100" height="64" rx="4" fill="#94a3b8"/>
<text x="170" y="134" text-anchor="middle" font-size="8" fill="#ffffff">Defer</text>
<text x="170" y="160" text-anchor="middle" font-size="19" font-weight="700" fill="#ffffff">{{ effort_impact_matrix.medium_low.count }}</text>
<rect x="224" y="112" width="100" height="64" rx="4" fill="#3b82f6"/>
<text x="274" y="134" text-anchor="middle" font-size="8" fill="#ffffff">Plan</text>
<text x="274" y="160" text-anchor="middle" font-size="19" font-weight="700" fill="#ffffff">{{ effort_impact_matrix.medium_medium.count }}</text>
<rect x="328" y="112" width="100" height="64" rx="4" fill="#8b5cf6"/>
<text x="378" y="134" text-anchor="middle" font-size="8" fill="#ffffff">Priority</text>
<text x="378" y="160" text-anchor="middle" font-size="19" font-weight="700" fill="#ffffff">{{ effort_impact_matrix.medium_high.count }}</text>
<rect x="120" y="180" width="100" height="64" rx="4" fill="#64748b"/>
<text x="170" y="202" text-anchor="middle" font-size="8" fill="#ffffff">If Time</text>
<text x="170" y="228" text-anchor="middle" font-size="19" font-weight="700" fill="#ffffff">{{ effort_impact_matrix.low_low.count }}</text>
<rect x="224" y="180" width="100" height="64" rx="4" fill="#22c55e"/>
<text x="274" y="202" text-anchor="middle" font-size="8" fill="#ffffff">Quick Win</text>
<text x="274" y="228" text-anchor="middle" font-size="19" font-weight="700" fill="#ffffff">{{ effort_impact_matrix.low_medium.count }}</text>
<rect x="328" y="180" width="100" height="64" rx="4" fill="#16a34a"/>
<text x="378" y="202" text-anchor="middle" font-size="8" fill="#ffffff">Do First</text>
<text x="378" y="228" text-anchor="middle" font-size="19" font-weight="700" fill="#ffffff">{{ effort_impact_matrix.low_high.count }}</text>
</svg>
<span class="chart-caption">Figure 3 — Effort vs impact. Each cell counts findings by remediation effort and security impact; the green band is the highest-value work.</span>
{%- else %}
<p style="text-align:center;color:#64748b;font-style:italic;">Effort / impact prioritisation was not computed for this engagement.</p>
{%- endif %}
</div>

{% if effort_impact_matrix %}
**Prioritization Summary:**
{% if effort_impact_matrix.low_high.count > 0 %}- 🚀 **DO FIRST ({{ effort_impact_matrix.low_high.count }})**: Low effort, high impact - immediate wins{% endif %}
{% if effort_impact_matrix.low_medium.count > 0 %}- ✅ **Quick Wins ({{ effort_impact_matrix.low_medium.count }})**: Low effort, medium impact - easy improvements{% endif %}
{% if effort_impact_matrix.medium_high.count > 0 %}- ⚡ **Priority ({{ effort_impact_matrix.medium_high.count }})**: Medium effort, high impact - plan these next{% endif %}
{% if effort_impact_matrix.high_high.count > 0 %}- 📅 **Schedule ({{ effort_impact_matrix.high_high.count }})**: High effort, high impact - important but complex{% endif %}
{% endif %}

## 6.5 Bug Bounty Submission Readiness

This section is an automated triage starting point, not a submission package. The findings in this report are **not confirmed vulnerabilities** and are **not submission-ready as they stand**: each one must be independently verified and backed by a working Proof of Concept before it is taken to any program. Most programs on Immunefi assess severity with the **Immunefi Vulnerability Severity Classification System V2.3** and, for **all** severities, require a mandatory Proof of Concept, an in-scope impact, a previously-unknown issue (not already covered by a prior audit or report), completion of KYC, and payment of a non-refundable submission fee. Read the table below as a list of work still outstanding, never as evidence that a finding can be submitted.

| Finding | Severity | PoC available | Readiness |
|---------|----------|:-------------:|-----------|
{%- for finding in findings %}
| {{ finding.id }}. {{ finding.title }} | {{ finding.severity_badge }} | {{ 'Yes' if finding.poc_available else 'No' }} | Requires manual triage + PoC |
{%- endfor %}
{%- if not findings %}
| — | — | — | No findings to assess |
{%- endif %}

A "Yes" under **PoC available** means MIESC emitted a local Foundry PoC *template* for that finding — a reproduction starting point, not a validated exploit. Readiness stays "Requires manual triage + PoC" for every finding regardless of severity or PoC status: nothing here is ready to submit without human verification and a demonstrated in-scope impact.

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

## Appendix B: Proof of Concept Exploits

{%- set poc_findings = [] %}
{%- for finding in findings %}
{%- if finding.poc and finding.poc != "" %}
{%- set _ = poc_findings.append(finding) %}
{%- endif %}
{%- endfor %}

{%- if poc_findings %}
The following PoC exploit templates were generated for critical/high findings. These are designed for local Foundry test environments and are NOT production exploits.

{%- for finding in findings %}
{%- if finding.poc and finding.poc != "" %}

### B.{{ loop.index }}. {{ finding.id }} - {{ finding.title }}

**Severity:** {{ finding.severity_badge }} | **Category:** {{ finding.category }}

```solidity
{{ finding.poc }}
```

{%- endif %}
{%- endfor %}
{%- else %}
No PoC exploit templates were generated for this audit.
{%- endif %}

## Appendix C: Files Analyzed

| # | File Path | Lines | Functions | Findings |
|--:|-----------|------:|----------:|----------:|
{%- for file in files_analyzed %}
| {{ loop.index }} | `{{ file.path }}` | {{ file.lines }} | {{ file.functions | default('--') }} | {{ file.findings }} |
{%- endfor %}

## Appendix D: SWC Registry Compliance

| SWC ID | Title | Status | Finding(s) |
|--------|-------|--------|------------|
{%- for swc in swc_mappings %}
| [{{ swc.id }}](https://swcregistry.io/docs/{{ swc.id }}) | {{ swc.title }} | {{ swc.status_icon }} {{ swc.status }} | {{ swc.finding_ids | default('--') }} |
{%- endfor %}

## Appendix E: OWASP Smart Contract Top 10

| Rank | Category | Status | Findings |
|------|----------|--------|----------|
{%- for owasp in owasp_mappings %}
| {{ owasp.id }} | {{ owasp.category }} | {{ owasp.status_icon }} | {{ owasp.count }} |
{%- endfor %}

## Appendix F: Glossary

| Term | Definition |
|------|------------|
| **Reentrancy** | A vulnerability where an external call allows execution to re-enter the calling contract before the first execution completes |
| **Integer Overflow** | When an arithmetic operation results in a value larger than can be stored in the variable |
| **Front-running** | Exploiting knowledge of pending transactions to gain an advantage |
| **Flash Loan Attack** | Using uncollateralized loans within a single transaction to manipulate protocols |
| **Oracle Manipulation** | Attacking price feeds or external data sources to influence contract behavior |
| **Access Control** | Mechanisms that restrict who can execute sensitive functions |

## Appendix G: Audit Trail

| Event | Timestamp | Hash |
|-------|-----------|------|
| Contract Snapshot | {{ audit_date }} | `{{ commit_hash | default('N/A') }}` |
| Analysis Started | {{ analysis_start | default(audit_date) }} | -- |
| Analysis Completed | {{ analysis_end | default(generation_date) }} | -- |
| Report Generated | {{ generation_date }} | -- |

### Report Integrity

| Attribute | Value |
|-----------|-------|
| Input results file (SHA-256) | `{{ input_sha256 | default('—', true) }}` |
| Report template version | {{ report_version | default('1.0') }} |
| Generator (MIESC) version | {{ generator_version | default(miesc_version) }} |
| Generated (UTC) | {{ generated_at_utc | default(generation_date) }} |

{% if input_sha256 %}This report was generated from results.json with SHA-256 `{{ input_sha256 }}`; recompute it (`shasum -a 256 <results.json>`) to verify the report corresponds to this scan.{% else %}The input results file was not available for hashing at report time, so no integrity hash is attested.{% endif %} This hash attests only the correspondence between this report and that results file; it does not attest that the scan was run correctly, that the analysis tools were unmodified, or that the analysed source was not substituted.

<!-- section-break -->

# Disclaimer

This audit report is provided on an "AS IS" basis without warranties of any kind, whether express or implied. The findings and recommendations are the output of automated analysis based on the scope and methodology described, and do not constitute a human professional opinion unless an auditor is explicitly named on the cover and attests to them.

**This report is the output of automated security tooling (plus optional local-LLM interpretation), not a manual professional audit.** It has not been reviewed or signed off by a human security auditor unless an auditor is explicitly named on the cover and attests to the findings.

**Limitations:**
- This audit does not guarantee the absence of vulnerabilities
- Smart contract security is an evolving field
- New vulnerabilities may be discovered post-audit
- Economic and governance attacks may not be fully modeled
- The client is responsible for implementing and testing fixes

{%- if llm_enabled %}

**Model-Assisted Interpretation Disclosure:** Sections labeled as model-assisted were produced using large language models ({{ llm_model }}). These interpretations are supplementary and must be reviewed by qualified security professionals before operational use.
{%- endif %}

<!-- section-break -->

<div class="footer" style="text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ccc;">

**Powered by [MIESC](https://github.com/fboiero/MIESC)**

Multi-layer Intelligent Evaluation for Smart Contracts

*Report generated: {{ generation_date }}*

*Report Version: {{ report_version | default('1.0') }}*

</div>
