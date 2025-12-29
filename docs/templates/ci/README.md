# CI/CD Integration Templates for MIESC

This folder contains ready-to-use CI/CD pipeline templates for integrating
MIESC into your smart contract development workflow.

## Quick Start

Copy the appropriate template to your project:

```bash
# GitHub Actions (recommended)
mkdir -p .github/workflows
cp docs/templates/ci/github-actions.yml .github/workflows/miesc-audit.yml

# GitLab CI
cp docs/templates/ci/.gitlab-ci.yml .gitlab-ci.yml

# CircleCI
cp -r docs/templates/ci/.circleci .

# Azure DevOps
cp docs/templates/ci/azure-pipelines.yml azure-pipelines.yml

# Jenkins
cp docs/templates/ci/Jenkinsfile Jenkinsfile
```

## Available Templates

| Template | Platform | Features |
|----------|----------|----------|
| `github-actions.yml` | GitHub Actions | SARIF, PR comments, matrix |
| `.gitlab-ci.yml` | GitLab CI/CD | Parallel layers, security reports, caching |
| `.circleci/config.yml` | CircleCI | Workflows, parallel jobs, nightly builds |
| `azure-pipelines.yml` | Azure DevOps | Multi-stage, approval gates, templates |
| `Jenkinsfile` | Jenkins | Declarative pipeline, Docker, email |

## Pipeline Stages

All templates follow a similar structure:

```text
Setup -> Analysis -> Report -> Security Gate
```

### 1. Setup

- Install MIESC and dependencies
- Configure solc version
- Prepare output directories

### 2. Analysis

- **Quick Audit** (PRs): Layers 1-2 for fast feedback
- **Full Audit** (main): All 7 layers with parallel execution
- **Custom**: User-defined layer selection

### 3. Report

- Aggregate findings from all layers
- Generate SARIF for security dashboards
- Create summary reports

### 4. Security Gate

- Fail on critical vulnerabilities
- Configurable thresholds for high/medium

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SOLC_VERSION` | Solidity compiler version | `0.8.20` |
| `MIESC_OUTPUT` | Output directory | `miesc-results` |
| `MAX_CRITICAL` | Max critical before fail | `0` |
| `MAX_HIGH` | Max high before warning | `5` |

### Layer Timeouts

| Layer | Default Timeout | Description |
|-------|-----------------|-------------|
| 1 | 10 min | Static analysis |
| 2 | 15 min | Semantic analysis |
| 3 | 30 min | Symbolic execution |
| 4 | 45 min | Fuzzing |
| 5 | 60 min | Formal verification |

## Output Formats

MIESC supports multiple output formats for CI integration:

```bash
# SARIF (recommended for GitHub/Azure/GitLab Security)
miesc analyze contract.sol --output-format sarif --output result.sarif

# JSON (for custom processing)
miesc analyze contract.sol --output-format json --output result.json

# Markdown (for PR comments)
miesc analyze contract.sol --output-format markdown --output result.md
```

## SARIF Integration

### GitHub Security Tab

The templates automatically upload SARIF files to GitHub's Security tab:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: miesc-results/
```

### GitLab Security Dashboard

GitLab automatically processes SARIF files in artifacts:

```yaml
artifacts:
  reports:
    sast: miesc-results/*.sarif
```

### Azure DevOps

Use the SARIF SAST Scans Tab extension or Code Analysis tools.

## Examples

### Minimal GitHub Actions

```yaml
name: Security Audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install miesc
      - run: miesc analyze contracts/ --output-format sarif --output results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Scheduled Nightly Audit

```yaml
on:
  schedule:
    - cron: '0 2 * * *'  # 2 AM daily
jobs:
  full-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install miesc
      - run: miesc analyze contracts/ --layers 1,2,3,4,5,6,7 --parallel
```

### Custom Layer Selection

```yaml
- run: |
    # Only run static and symbolic execution
    miesc analyze contracts/ --layers 1,3 --output-format json
```

## Troubleshooting

### solc Version Issues

```yaml
# Install specific solc version
- run: |
    pip install solc-select
    solc-select install 0.8.20
    solc-select use 0.8.20
```

### Timeout Issues

```yaml
# Increase timeout for fuzzing layer
- run: miesc analyze contract.sol --layers 4
  timeout-minutes: 60
```

### No Solidity Files Found

Ensure your contracts are in the expected location:

- `contracts/` (Hardhat/Truffle)
- `src/` (Foundry)

### Permission Issues

```yaml
permissions:
  contents: read
  security-events: write  # For SARIF upload
  pull-requests: write    # For PR comments
```

## Integration with Other Tools

### Foundry Projects

MIESC auto-detects Foundry projects:

```yaml
- run: |
    miesc detect .  # Shows framework info
    miesc analyze src/ --framework foundry
```

### Hardhat Projects

```yaml
- run: |
    npm install  # Install dependencies first
    miesc analyze contracts/ --framework hardhat
```

## Support

- Documentation: <https://github.com/fboiero/MIESC>
- Issues: <https://github.com/fboiero/MIESC/issues>
