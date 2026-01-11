# MIESC Report Templates

Professional report templates for MIESC security audit output.

## Available Templates

| Template | Description | Use Case |
|----------|-------------|----------|
| `professional.md` | Full audit report with all details | Client deliverables |
| `executive.md` | High-level summary for executives | Management briefings |
| `technical.md` | Deep technical analysis | Developer handoff |
| `github-pr.md` | Compact PR comment format | GitHub Actions |
| `simple.md` | Basic findings list | Quick reviews |

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

## See Also

- [Custom Detectors](../CUSTOM_DETECTORS.md)
- [CLI Reference](../CLI.md)
- [API Reference](../API_SETUP.md)
