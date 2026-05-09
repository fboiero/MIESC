## MIESC Security Audit

### Summary

| Severity | Count |
|----------|-------|
| Critical | {{ critical_count }} |
| High | {{ high_count }} |
| Medium | {{ medium_count }} |
| Low | {{ low_count }} |

{% if critical_count > 0 or high_count > 0 %}
### Action Required

{% for finding in critical_high_findings %}
- **[{{ finding.severity | upper }}]** {{ finding.title }}
  - Location: `{{ finding.location }}`
  - {{ finding.description | truncate(100) }}
{% endfor %}

{% else %}
### No Critical or High Issues Found

{% endif %}

{% if medium_count > 0 or low_count > 0 %}
<details>
<summary>View {{ medium_count + low_count }} Medium/Low Findings</summary>

{% for finding in medium_low_findings %}
- **[{{ finding.severity | upper }}]** {{ finding.title }} - `{{ finding.location }}`
{% endfor %}

</details>
{% endif %}

### Files Analyzed

{% for file in files %}
- `{{ file }}`
{% endfor %}

---
*Powered by [MIESC](https://github.com/fboiero/MIESC) - {{ tools_count }} tools across 9 security layers*
