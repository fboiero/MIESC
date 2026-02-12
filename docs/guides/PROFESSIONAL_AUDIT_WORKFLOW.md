# Professional Smart Contract Audit Workflow

**MIESC v5.1.0** | Professional Auditor Guide

This guide provides a structured workflow for conducting professional smart contract security audits using MIESC.

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Audit Phases](#audit-phases)
4. [Command Reference](#command-reference)
5. [Interpreting Findings](#interpreting-findings)
6. [Managing False Positives](#managing-false-positives)
7. [Report Generation](#report-generation)
8. [CI/CD Integration](#cicd-integration)
9. [Best Practices](#best-practices)
10. [Example Workflows](#example-workflows)

---

## Overview

MIESC integrates **50 security tools** across **9 defense layers** to provide comprehensive smart contract analysis:

| Layer | Focus | Key Tools |
|-------|-------|-----------|
| 1 | Static Analysis | Slither, Aderyn, Solhint, Semgrep, Wake |
| 2 | Dynamic Testing | Echidna, Medusa, Foundry, Hardhat |
| 3 | Symbolic Execution | Mythril, Manticore, Halmos |
| 4 | Formal Verification | Certora, Scribble, Solc-verify |
| 5 | Economic Analysis | DeFi-specific detectors |
| 6 | Dependency Audit | npm-audit, pip-audit, cargo-audit |
| 7 | LLM-Powered Analysis | GPTScan, SmartLLM, GPTLens |
| 8 | Specialized Audits | Bridge monitor, L2 validator |
| 9 | Meta-Analysis | Cross-tool correlation, consensus |

---

## Prerequisites

### Docker (Recommended)

```bash
# Standard image (~15 tools, fast)
docker pull ghcr.io/fboiero/miesc:5.1.0

# Full image (~30 tools, comprehensive)
docker pull ghcr.io/fboiero/miesc:5.1.0-full

# Verify installation
docker run --rm ghcr.io/fboiero/miesc:5.1.0 --version
```

### Local Installation

```bash
pip install miesc==5.1.0
miesc doctor  # Check tool availability
```

### LLM Setup (Optional, for AI-powered reports)

```bash
# Start Ollama with required models
ollama pull mistral
ollama pull deepseek-coder

# Set environment variable
export OLLAMA_HOST=http://localhost:11434
```

---

## Audit Phases

### Phase 1: Triage (5 minutes)

**Goal:** Quick assessment to identify obvious issues and estimate audit scope.

```bash
# Quick 4-tool scan
miesc scan contract.sol

# Or with Docker
docker run --rm -v $(pwd):/contracts ghcr.io/fboiero/miesc:5.1.0 \
  scan /contracts/Contract.sol
```

**Output:** Summary of critical/high/medium/low findings.

**Decision Points:**
- **0 critical/high:** Proceed to full audit
- **Many critical:** Flag for immediate client notification
- **Complex codebase:** Consider layer-by-layer approach

---

### Phase 2: Quick Audit (15-30 minutes)

**Goal:** Fast comprehensive scan using primary tools.

```bash
miesc audit quick ./contracts -o results-quick.json
```

**Tools Used:** Slither, Aderyn, Solhint, Semgrep

**When to Use:**
- Initial client engagement
- PR reviews
- CI/CD pipelines
- Time-constrained assessments

---

### Phase 3: Full Audit (1-4 hours)

**Goal:** Complete 9-layer analysis with all available tools.

```bash
# Full audit with all layers
miesc audit full ./contracts -o results-full.json

# Skip unavailable tools (recommended for Docker)
miesc audit full ./contracts --skip-unavailable -o results-full.json

# With specific timeout per tool
miesc audit full ./contracts --timeout 600 -o results-full.json
```

**When to Use:**
- Pre-deployment audits
- High-value contracts (DeFi, bridges, governance)
- Compliance requirements
- Client deliverables

---

### Phase 4: Layer-Specific Analysis (Variable)

**Goal:** Deep dive into specific security aspects.

```bash
# Single layer analysis
miesc audit layer ./contracts --layer 1  # Static only
miesc audit layer ./contracts --layer 3  # Symbolic execution
miesc audit layer ./contracts --layer 7  # LLM analysis

# Multiple specific layers
miesc audit layer ./contracts --layer 1 --layer 3 --layer 7
```

**Layer Selection Guide:**

| Concern | Recommended Layers |
|---------|-------------------|
| Code quality | Layer 1 (Static) |
| Logic bugs | Layer 2 (Dynamic) + Layer 3 (Symbolic) |
| Formal correctness | Layer 4 (Formal Verification) |
| DeFi vulnerabilities | Layer 5 (Economic) + Layer 7 (LLM) |
| Supply chain | Layer 6 (Dependencies) |
| Cross-chain/L2 | Layer 8 (Specialized) |

---

### Phase 5: Report Generation (15-60 minutes)

**Goal:** Create professional deliverable for client.

```bash
# Professional PDF report with LLM interpretation
miesc report results-full.json \
  -t premium \
  --llm-interpret \
  -f pdf \
  -o audit-report.pdf

# Executive summary (for management)
miesc report results-full.json \
  -t executive \
  -f pdf \
  -o executive-summary.pdf

# Technical report (for developers)
miesc report results-full.json \
  -t technical \
  -f markdown \
  -o technical-findings.md

# SARIF for GitHub Code Scanning
miesc export results-full.json -f sarif -o results.sarif.json
```

---

## Command Reference

### Core Commands

| Command | Purpose | Typical Duration |
|---------|---------|------------------|
| `miesc scan <file>` | Quick triage scan | 1-5 min |
| `miesc audit quick <dir>` | Fast 4-tool audit | 15-30 min |
| `miesc audit full <dir>` | Complete 9-layer audit | 1-4 hours |
| `miesc audit layer <dir> --layer N` | Specific layer analysis | Variable |
| `miesc audit smart <dir>` | AI-guided adaptive audit | 30-60 min |
| `miesc report <json>` | Generate report | 5-60 min |
| `miesc export <json>` | Convert to SARIF/CSV/HTML | Instant |

### Utility Commands

| Command | Purpose |
|---------|---------|
| `miesc doctor` | Check tool availability |
| `miesc detect <dir>` | Auto-detect framework (Foundry/Hardhat/Truffle) |
| `miesc tools list` | List all available tools |
| `miesc benchmark <dir>` | Track security posture over time |
| `miesc watch <dir>` | Real-time file monitoring |

### Common Options

| Option | Description |
|--------|-------------|
| `-o, --output <file>` | Output file path |
| `--skip-unavailable` | Skip tools that aren't installed |
| `--timeout <seconds>` | Per-tool timeout (default: 300) |
| `-q, --quiet` | Minimal output |
| `--ci` | CI mode (exit 1 on critical/high findings) |
| `-t, --template` | Report template (premium, professional, executive, technical) |
| `--llm-interpret` | Add AI-powered analysis to reports |
| `-f, --format` | Output format (json, pdf, html, markdown, sarif) |

---

## Interpreting Findings

### Severity Levels

| Level | Action Required | Typical Issues |
|-------|-----------------|----------------|
| **CRITICAL** | Immediate fix, block deployment | Reentrancy, access control bypass, fund drain |
| **HIGH** | Fix before deployment | Integer overflow, front-running, oracle manipulation |
| **MEDIUM** | Should fix, review carefully | Gas optimization, centralization risks |
| **LOW** | Consider fixing | Code style, minor gas inefficiencies |
| **INFO** | Informational | Best practices, suggestions |

### Finding Structure

```json
{
  "tool": "slither",
  "severity": "HIGH",
  "confidence": "HIGH",
  "title": "Reentrancy vulnerability",
  "description": "External call followed by state change",
  "location": {
    "file": "Contract.sol",
    "line": 45,
    "function": "withdraw()"
  },
  "swc_id": "SWC-107",
  "cwe_id": "CWE-841",
  "recommendation": "Use checks-effects-interactions pattern"
}
```

### Cross-Tool Validation

MIESC's correlation engine validates findings across tools:

| Validation Level | Meaning |
|-----------------|---------|
| **Confirmed** | Multiple tools report same issue |
| **High Confidence** | Tool-specific high confidence |
| **Medium Confidence** | Single tool, medium confidence |
| **Needs Review** | Potential false positive |

---

## Managing False Positives

### Built-in Correlation Engine

MIESC automatically reduces false positives through:

1. **Cross-tool validation:** Findings reported by multiple tools get higher confidence
2. **Pattern matching:** Known false positive patterns are filtered
3. **Context analysis:** Guards, require statements, and CEI patterns are recognized

### Manual Filtering

```bash
# Filter by minimum confidence
miesc audit full ./contracts --min-confidence high

# Filter by severity
miesc audit full ./contracts --min-severity medium
```

### Suppression Comments

In your Solidity code:

```solidity
// slither-disable-next-line reentrancy-eth
// miesc-ignore: false-positive-reason
function withdraw() external {
    // ...
}
```

### False Positive Report

After audit, document false positives for client:

```markdown
## False Positives

| Finding | Tool | Reason |
|---------|------|--------|
| Reentrancy in withdraw() | Slither | Protected by ReentrancyGuard |
| Integer overflow | Mythril | Solidity 0.8+ has built-in checks |
```

---

## Report Generation

### Available Templates

| Template | Audience | Contents |
|----------|----------|----------|
| `premium` | Clients | CVSS scores, risk matrix, attack scenarios, remediation |
| `professional` | Clients | Standard audit format with findings and recommendations |
| `executive` | Management | High-level summary, risk assessment, business impact |
| `technical` | Developers | Detailed findings, code snippets, fix examples |
| `compliance` | Compliance | ISO 27001, NIST, OWASP, SWC mapping |
| `github-pr` | CI/CD | PR comment format |

### LLM-Enhanced Reports

With `--llm-interpret`, reports include:

- **Executive Summary:** AI-generated overview of security posture
- **Attack Scenarios:** Realistic exploitation paths
- **Remediation Guidance:** Detailed fix recommendations
- **Risk Assessment:** Business impact analysis

```bash
# Premium report with all AI features
miesc report results.json \
  -t premium \
  --llm-interpret \
  --model mistral \
  -f pdf \
  -o premium-audit-report.pdf
```

### Output Formats

| Format | Use Case | Command |
|--------|----------|---------|
| PDF | Client delivery | `-f pdf` |
| HTML | Web viewing | `-f html` |
| Markdown | Documentation | `-f markdown` |
| SARIF | GitHub Code Scanning | `miesc export -f sarif` |
| CSV | Spreadsheet analysis | `miesc export -f csv` |
| JSON | Programmatic use | Default output |

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Audit

on:
  pull_request:
    paths:
      - 'contracts/**'

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run MIESC Audit
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/contracts \
            ghcr.io/fboiero/miesc:5.1.0 \
            audit quick /contracts \
            --ci \
            -o /contracts/results.json

      - name: Upload SARIF
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/contracts \
            ghcr.io/fboiero/miesc:5.1.0 \
            export /contracts/results.json \
            -f sarif \
            -o /contracts/results.sarif.json

      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif.json
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: miesc-scan
        name: MIESC Security Scan
        entry: miesc scan
        language: system
        files: \.sol$
        args: ['--ci']
```

### GitLab CI

```yaml
security-audit:
  image: ghcr.io/fboiero/miesc:5.1.0
  stage: test
  script:
    - miesc audit quick ./contracts --ci -o results.json
  artifacts:
    paths:
      - results.json
    reports:
      sast: results.json
```

---

## Best Practices

### Before the Audit

1. **Understand the project scope**
   - Contract count and complexity
   - Dependencies and external calls
   - DeFi integrations (if any)

2. **Set up environment**
   - Use Docker for consistent results
   - Ensure Ollama is running for LLM features
   - Check tool availability with `miesc doctor`

3. **Review existing documentation**
   - Project README and specifications
   - Previous audit reports (if any)
   - Known issues or limitations

### During the Audit

1. **Start with triage**
   ```bash
   miesc scan contract.sol
   ```

2. **Run quick audit first**
   ```bash
   miesc audit quick ./contracts -o results-quick.json
   ```

3. **Review critical findings immediately**
   - Don't wait for full audit to flag critical issues
   - Communicate with client if blocking issues found

4. **Run full audit**
   ```bash
   miesc audit full ./contracts --skip-unavailable -o results-full.json
   ```

5. **Layer-specific deep dives**
   - Use `audit layer` for specific concerns
   - Focus on layers relevant to contract type

6. **Document false positives**
   - Note why each false positive was dismissed
   - Include in final report

### After the Audit

1. **Generate multiple reports**
   - Premium/Professional for client
   - Executive for management
   - Technical for developers

2. **Verify remediation**
   - Re-run audit after fixes
   - Use `miesc benchmark` to track improvement

3. **Archive results**
   - Keep JSON results for future reference
   - Store reports with project documentation

---

## Example Workflows

### Workflow 1: Quick PR Review (15 minutes)

```bash
# 1. Quick scan
miesc scan ./contracts/NewFeature.sol

# 2. If issues found, get details
miesc audit quick ./contracts -o pr-review.json

# 3. Generate PR comment
miesc report pr-review.json -t github-pr -f markdown
```

### Workflow 2: Pre-deployment Audit (4 hours)

```bash
# 1. Triage
miesc scan ./contracts

# 2. Full audit
miesc audit full ./contracts --skip-unavailable -o full-audit.json

# 3. Generate reports
miesc report full-audit.json -t premium --llm-interpret -f pdf -o client-report.pdf
miesc report full-audit.json -t executive -f pdf -o executive-summary.pdf
miesc report full-audit.json -t technical -f markdown -o dev-findings.md

# 4. Export for CI
miesc export full-audit.json -f sarif -o results.sarif.json
```

### Workflow 3: DeFi Protocol Audit (1 day)

```bash
# 1. Quick triage
miesc scan ./contracts

# 2. Static analysis (Layer 1)
miesc audit layer ./contracts --layer 1 -o layer1.json

# 3. Symbolic execution (Layer 3)
miesc audit layer ./contracts --layer 3 -o layer3.json

# 4. Economic analysis (Layer 5)
miesc audit layer ./contracts --layer 5 -o layer5.json

# 5. LLM analysis for DeFi patterns (Layer 7)
miesc audit layer ./contracts --layer 7 -o layer7.json

# 6. Full audit for completeness
miesc audit full ./contracts --skip-unavailable -o full-audit.json

# 7. Premium report with AI
miesc report full-audit.json -t premium --llm-interpret -f pdf -o defi-audit.pdf
```

### Workflow 4: Continuous Monitoring

```bash
# 1. Set up baseline
miesc benchmark ./contracts --save

# 2. Watch for changes
miesc watch ./contracts --profile balanced

# 3. Compare after changes
miesc benchmark ./contracts --compare last
```

---

## Docker Quick Reference

### Standard Image (Most Common)

```bash
# Basic audit
docker run --rm -v $(pwd):/contracts \
  ghcr.io/fboiero/miesc:5.1.0 \
  audit quick /contracts -o /contracts/results.json

# With LLM (macOS)
docker run --rm -v $(pwd):/contracts \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  ghcr.io/fboiero/miesc:5.1.0 \
  audit full /contracts --skip-unavailable -o /contracts/results.json
```

### Full Image (Comprehensive)

```bash
# Full audit with all tools
docker run --rm -v $(pwd):/contracts \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  ghcr.io/fboiero/miesc:5.1.0-full \
  audit full /contracts --skip-unavailable -o /contracts/results.json

# Generate premium report
docker run --rm -v $(pwd):/contracts \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  ghcr.io/fboiero/miesc:5.1.0-full \
  report /contracts/results.json \
  -t premium --llm-interpret -f pdf -o /contracts/report.pdf
```

---

## Support & Resources

- **Documentation:** https://github.com/fboiero/MIESC/tree/main/docs
- **Issues:** https://github.com/fboiero/MIESC/issues
- **Docker Images:** ghcr.io/fboiero/miesc
- **PyPI:** pip install miesc

---

*Document version: 5.1.0 | Last updated: February 2026*
