# MIESC Report Templates

Professional report templates for MIESC security audit output.

## Available Templates

| Template | Description | Use Case |
|----------|-------------|----------|
| `professional.md` | Full audit report with all details | Client deliverables |
| `executive.md` | High-level summary for executives | Management briefings |
| `technical.md` | Deep technical analysis | Developer handoff |
| `compliance.md` | Regulatory compliance mapping | SWC, OWASP, CWE |
| `checklist.md` | Audit checklist with sign-off | Manual audits |
| `github-pr.md` | Compact PR comment format | GitHub Actions |
| `simple.md` | Basic findings list | Quick reviews |
| `sarif.json` | SARIF 2.1.0 format | GitHub Code Scanning |

## Usage

```bash
# Generate professional report
miesc report results.json --template professional --output report.md

# Generate executive summary
miesc report results.json --template executive --output summary.md

# Generate with client info
miesc report results.json \
  --template professional \
  --client "Acme Protocol" \
  --auditor "Security Team" \
  --output audit_report.md

# Generate PDF (requires pandoc)
miesc report results.json --template professional --format pdf --output report.pdf
```

## Template Variables

### Common Variables

| Variable | Description |
|----------|-------------|
| `{{ contract_name }}` | Name of the audited contract |
| `{{ audit_date }}` | Date of the audit |
| `{{ client_name }}` | Client organization name |
| `{{ auditor_name }}` | Auditor name or team |
| `{{ critical_count }}` | Number of critical findings |
| `{{ high_count }}` | Number of high findings |
| `{{ medium_count }}` | Number of medium findings |
| `{{ low_count }}` | Number of low findings |
| `{{ total_findings }}` | Total number of findings |

### Finding Variables

| Variable | Description |
|----------|-------------|
| `{{ finding.id }}` | Finding identifier |
| `{{ finding.title }}` | Finding title |
| `{{ finding.severity }}` | Severity level |
| `{{ finding.category }}` | Vulnerability category |
| `{{ finding.location }}` | File and line location |
| `{{ finding.description }}` | Detailed description |
| `{{ finding.recommendation }}` | Fix recommendation |
| `{{ finding.tool }}` | Detecting tool |

## Custom Templates

Create custom templates in `~/.miesc/templates/` or specify a path:

```bash
miesc report results.json --template /path/to/custom.md
```

### Template Syntax

Templates use Jinja2 syntax:

```markdown
# Report for {{ client_name }}

## Findings

{% for finding in findings %}
### {{ finding.title }}

{{ finding.description }}

{% endfor %}
```

## Output Formats

| Format | Extension | Requirements |
|--------|-----------|--------------|
| Markdown | `.md` | None |
| HTML | `.html` | None |
| PDF | `.pdf` | pandoc, wkhtmltopdf |
| SARIF | `.sarif` | None (built-in) |
| JSON | `.json` | None (built-in) |

## JSON Schema

The `schema.json` file provides a JSON Schema (draft 2020-12) for validating MIESC report output:

```bash
# Validate a report using jsonschema
pip install jsonschema
python -c "
import json
from jsonschema import validate
with open('results.json') as f:
    report = json.load(f)
with open('docs/templates/reports/schema.json') as f:
    schema = json.load(f)
validate(report, schema)
print('Report is valid!')
"
```

## Template Descriptions

### professional.md
Full audit report suitable for client deliverables. Includes:
- Executive summary with risk assessment
- Complete findings with code snippets
- Methodology section (9-layer framework)
- Compliance mapping (SWC, OWASP)
- Tool outputs as appendix

### compliance.md
Regulatory and standards compliance mapping. Includes:
- SWC Registry coverage analysis
- OWASP Smart Contract Top 10 mapping
- CWE (Common Weakness Enumeration) mapping
- ERC token standard compliance checks
- DeFi-specific security verification
- MIESC layer coverage summary

### checklist.md
Interactive audit checklist with sign-off sections. Includes:
- Pre-audit preparation checklist
- Category-specific security checks
- Finding integration per category
- Summary with severity counts
- Sign-off section for auditors

### sarif.json
SARIF 2.1.0 format for integration with:
- GitHub Code Scanning
- Azure DevOps
- Visual Studio Code SARIF Viewer
- Other SARIF-compatible tools

## Examples

### Professional Audit Report

```bash
miesc audit full ./contracts -o results.json
miesc report results.json \
  --template professional \
  --client "DeFi Protocol" \
  --auditor "MIESC Security" \
  --output DeFi_Protocol_Audit_2025.md
```

### GitHub PR Comment

```bash
miesc audit quick ./src -o results.json
miesc report results.json --template github-pr
```

### CI/CD Pipeline

```yaml
- name: Generate Report
  run: |
    miesc audit quick ./contracts -o results.json
    miesc report results.json --template executive --output SECURITY.md
```

### Compliance Report

```bash
# Generate compliance mapping report
miesc audit full ./contracts -o results.json
miesc report results.json \
  --template compliance \
  --client "DeFi Protocol" \
  --output compliance_report.md
```

### Audit Checklist

```bash
# Generate pre-filled audit checklist
miesc audit full ./contracts -o results.json
miesc report results.json \
  --template checklist \
  --auditor "Security Researcher" \
  --client "Client Name" \
  --output audit_checklist.md
```

### SARIF for GitHub Code Scanning

```yaml
# .github/workflows/security.yml
name: Security Audit
on: [push, pull_request]

jobs:
  miesc:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install miesc
      - run: miesc audit quick ./contracts --format sarif -o results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## See Also

- [Custom Detectors](../CUSTOM_DETECTORS.md)
- [CLI Reference](../CLI.md)
- [API Reference](../API_SETUP.md)
