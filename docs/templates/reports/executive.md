# Security Audit Executive Summary

**Client:** {{ client_name }}
**Date:** {{ audit_date }}

---

## Overview

{{ client_name }}'s smart contracts were audited using MIESC's 9-layer security framework with {{ tools_count }} integrated tools.

## Risk Assessment

| Metric | Value |
|--------|-------|
| Overall Risk | **{{ overall_risk }}** |
| Critical Issues | {{ critical_count }} |
| High Issues | {{ high_count }} |
| Total Findings | {{ total_findings }} |
| Files Analyzed | {{ files_count }} |

## Key Findings

{% if critical_count > 0 or high_count > 0 %}
### Immediate Action Required

{% for finding in critical_high_findings %}
- **[{{ finding.severity | upper }}]** {{ finding.title }} - {{ finding.location }}
{% endfor %}

{% endif %}

### Finding Distribution

```
Critical  {{ critical_bar }} {{ critical_count }}
High      {{ high_bar }} {{ high_count }}
Medium    {{ medium_bar }} {{ medium_count }}
Low       {{ low_bar }} {{ low_count }}
```

## Recommendations

1. {{ recommendation_1 }}
2. {{ recommendation_2 }}
3. {{ recommendation_3 }}

## Next Steps

- [ ] Address critical and high severity findings
- [ ] Review medium severity findings
- [ ] Schedule re-audit after fixes
- [ ] Implement continuous monitoring

---

*Full technical report available upon request.*

**Powered by [MIESC](https://github.com/fboiero/MIESC)**
