# MIESC Report Generation Guide

This guide covers how to generate professional security audit reports in various formats.

## Quick Start

```bash
# Generate PDF report (recommended for clients)
miesc report results.json -t premium -f pdf -o audit_report.pdf

# Generate Markdown report
miesc report results.json -t professional -f markdown -o audit_report.md

# Generate HTML report
miesc report results.json -t premium -f html -o audit_report.html
```

## Prerequisites

### For PDF Generation

PDF generation requires WeasyPrint and its system dependencies:

**macOS:**
```bash
brew install pango cairo
pip install weasyprint markdown
```

**Ubuntu/Debian:**
```bash
sudo apt-get install libpango-1.0-0 libcairo2 libcairo2-dev
pip install weasyprint markdown
```

**Or install via pip extras:**
```bash
pip install miesc[pdf]
```

### For LLM-Enhanced Reports

For AI-generated insights (executive summary, attack scenarios):
```bash
# Requires Ollama running locally
ollama pull mistral
pip install miesc[llm]
```

## Report Templates

| Template | Description | Best For |
|----------|-------------|----------|
| `premium` | Full professional audit with CVSS, attack scenarios | Client delivery |
| `professional` | Standard professional report | Internal audits |
| `executive` | High-level summary for executives | Management |
| `technical` | Detailed technical findings | Development teams |
| `simple` | Basic findings list | Quick reviews |
| `github-pr` | PR comment format | CI/CD integration |

## Usage Examples

### Basic Report

```bash
# Run audit and generate report
miesc audit smart contract.sol -o results.json
miesc report results.json -t professional -f pdf -o report.pdf
```

### Premium Report with LLM Insights

```bash
miesc report results.json \
  -t premium \
  -f pdf \
  -o audit_report.pdf \
  --llm-interpret \
  --client "Acme Protocol" \
  --auditor "Security Team" \
  --network "Ethereum Mainnet" \
  --classification "CONFIDENTIAL"
```

### All Available Options

```bash
miesc report --help
```

| Option | Description |
|--------|-------------|
| `-t, --template` | Report template (premium, professional, etc.) |
| `-f, --format` | Output format (pdf, markdown, html) |
| `-o, --output` | Output file path |
| `--client` | Client name for the report |
| `--auditor` | Auditor/team name |
| `--title` | Custom report title |
| `--contract-name` | Override contract name |
| `--repository` | Repository URL |
| `--commit` | Commit hash |
| `--network` | Target network (Ethereum Mainnet, etc.) |
| `--classification` | Report classification (CONFIDENTIAL, etc.) |
| `--llm-interpret` | Enable LLM-generated insights |
| `-i, --interactive` | Interactive wizard mode |

## Output Formats

### PDF (Recommended for Delivery)

Professional PDF with:
- Cover page with classification
- Table of contents
- Executive summary
- CVSS risk matrix
- Detailed findings with code snippets
- Remediation roadmap
- Appendices

```bash
miesc report results.json -t premium -f pdf -o report.pdf
```

### HTML (Interactive)

Web-based report with:
- Collapsible finding details
- Syntax-highlighted code
- Interactive charts
- Responsive design

```bash
miesc report results.json -t premium -f html -o report.html
```

### Markdown (Documentation)

Markdown report for:
- GitHub/GitLab wikis
- Documentation sites
- Version control

```bash
miesc report results.json -t professional -f markdown -o report.md
```

### SARIF (CI/CD Integration)

Standard SARIF 2.1.0 format for:
- GitHub Code Scanning
- Azure DevOps
- Other SARIF-compatible tools

```bash
miesc export results.json -f sarif -o report.sarif
```

## Premium Report Features

The `premium` template includes:

1. **Executive Summary** - LLM-generated overview
2. **Deployment Recommendation** - GO/NO-GO/CONDITIONAL
3. **CVSS Risk Matrix** - Severity scoring
4. **Attack Scenarios** - LLM-generated exploit paths
5. **Remediation Roadmap** - Prioritized fix plan
6. **Code Remediations** - Suggested fixes

## LLM Integration

When `--llm-interpret` is enabled:

```bash
miesc report results.json -t premium -f pdf --llm-interpret -o report.pdf
```

The LLM generates:
- **Executive Summary**: Business-focused overview
- **Risk Narrative**: Context-aware risk assessment
- **Attack Scenarios**: Potential exploit chains
- **Deployment Recommendation**: GO/NO-GO with justification

**Requirements:**
- Ollama running locally (`ollama serve`)
- Model available (`ollama pull mistral` or `codellama`)

## Troubleshooting

### PDF Generation Fails

**Error:** `ModuleNotFoundError: No module named 'weasyprint'`
```bash
pip install weasyprint markdown
```

**Error:** `OSError: cannot load library 'pango'`
```bash
# macOS
brew install pango cairo

# Ubuntu
sudo apt-get install libpango-1.0-0 libcairo2
```

### Jinja2 Template Errors

**Error:** `No module named 'jinja2'`
```bash
pip install jinja2
```

### LLM Insights Not Working

**Error:** `Connection refused to localhost:11434`
```bash
# Start Ollama
ollama serve

# In another terminal, pull a model
ollama pull mistral
```

## Best Practices

1. **For Client Reports**: Use `premium` template with `--llm-interpret`
2. **For CI/CD**: Use SARIF export (`miesc export -f sarif`)
3. **For GitHub PRs**: Use `github-pr` template to stdout
4. **Always Include**: `--client`, `--auditor`, `--classification`

## Example Workflow

```bash
# 1. Run comprehensive audit
miesc audit full contract.sol -o full_audit.json

# 2. Generate client-ready PDF
miesc report full_audit.json \
  -t premium \
  -f pdf \
  -o ClientName_Audit_Report.pdf \
  --llm-interpret \
  --client "ClientName" \
  --auditor "Your Company" \
  --network "Ethereum Mainnet" \
  --classification "CONFIDENTIAL"

# 3. Generate SARIF for CI
miesc export full_audit.json -f sarif -o findings.sarif
```
