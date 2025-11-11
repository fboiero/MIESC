# MIESC Setup and Usage

**Version:** 3.3.0
**Document:** Installation, Configuration, and Usage Guide
**Last Updated:** 2025-01-18

---

## 📋 Prerequisites

### System Requirements

**Operating Systems:**
- ✅ Linux (Ubuntu 20.04+, Debian 11+)
- ✅ macOS (11.0+)
- ⚠️ Windows (WSL2 required)

**Software Dependencies:**
- Python 3.9, 3.10, or 3.11 (3.12 not yet tested)
- pip 21.0+
- Git 2.30+
- solc (Solidity compiler) 0.8.0+

**Hardware:**
- CPU: 4 cores recommended (minimum 2)
- RAM: 4 GB minimum (8 GB recommended)
- Disk: 2 GB free space

---

## 🚀 Quick Installation

### Option 1: Standard Installation (Recommended)

```bash
# 1. Clone repository
git clone https://github.com/fboiero/MIESC.git
cd MIESC

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install core dependencies
pip install -r requirements.txt

# 4. Install security tools
pip install slither-analyzer mythril

# 5. Verify installation
python src/miesc_cli.py --version
# Expected: MIESC v3.3.0

# 6. Run quick test
bash demo/run_demo.sh
```

**Installation time:** ~5-10 minutes

---

### Option 2: Development Installation

For contributors who need all development tools:

```bash
# 1-3. Same as Option 1

# 4. Install all dependencies (including dev tools)
pip install -r requirements-dev.txt

# 5. Install pre-commit hooks
pre-commit install

# 6. Run full test suite
pytest --cov=src --cov-report=html

# 7. Check compliance
python src/miesc_policy_agent.py
```

---

### Option 3: Docker Installation (Future)

```bash
# Pull pre-built image
docker pull fboiero/miesc:3.3.0

# Run demo
docker run --rm -v $(pwd)/demo:/demo fboiero/miesc:3.3.0 \
    python /app/src/miesc_cli.py run-audit /demo/sample_contracts/Reentrancy.sol

# Or build locally
docker build -t miesc:local .
docker run --rm miesc:local bash demo/run_demo.sh
```

**Note:** Docker image not yet published - planned for v3.4.0

---

## 📦 Dependency Details

### Core Dependencies (`requirements.txt`)

```txt
# Smart Contract Analysis
slither-analyzer==0.10.0
mythril==0.24.0
solc-select==1.0.4

# AI Correlation
openai==1.3.0
anthropic==0.8.0  # Future support

# Web Framework (MCP REST API)
flask==3.0.0
flask-cors==4.0.0

# Data Processing
pydantic==2.5.0
pyyaml==6.0.1

# Reporting
jinja2==3.1.2
markdown==3.5.0

# Testing
pytest==7.4.0
pytest-cov==4.1.0
```

### Development Dependencies (`requirements-dev.txt`)

```txt
# Include all from requirements.txt plus:

# Code Quality
ruff==0.1.0
black==23.10.0
mypy==1.6.0
flake8==6.1.0

# Security Scanning
bandit==1.7.5
semgrep==1.45.0
pip-audit==2.6.0

# Pre-commit
pre-commit==3.5.0

# Documentation
mkdocs==1.5.0
mkdocs-material==9.4.0

# Jupyter (for demo notebook)
jupyter==1.0.0
matplotlib==3.8.0
seaborn==0.13.0
pandas==2.1.0
```

---

## 🔧 Configuration

### Environment Variables

Create `.env` file in project root:

```bash
# AI Correlation (Optional - demo works without this)
OPENAI_API_KEY=sk-...your-key-here...

# MCP REST API
MCP_HOST=0.0.0.0
MCP_PORT=5001

# Tool Configuration
SLITHER_TIMEOUT=60
MYTHRIL_TIMEOUT=120
ADERYN_ENABLED=true

# Reporting
REPORT_OUTPUT_DIR=analysis/reports/
REPORT_FORMATS=json,markdown,html

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/miesc.log
```

**Load environment:**

```bash
# Automatically loaded by python-dotenv
# Or manually:
export $(cat .env | xargs)
```

---

### Tool-Specific Configuration

#### Slither Configuration

Create `slither.config.json`:

```json
{
  "detectors_to_run": "all",
  "detectors_to_exclude": "naming-convention,solc-version",
  "exclude_dependencies": true,
  "exclude_informational": false,
  "exclude_low": false,
  "exclude_medium": false,
  "exclude_high": false,
  "json": "-",
  "legacy_ast": false,
  "show_ignored_findings": false
}
```

**Usage:**

```bash
python src/miesc_cli.py run-audit Contract.sol --slither-config slither.config.json
```

---

#### Mythril Configuration

Create `mythril.yaml`:

```yaml
analysis:
  max_depth: 22
  create_timeout: 10
  solver_timeout: 10000
  strategy: "dfs"
  transaction_count: 3
  modules:
    - ether_thief
    - exceptions
    - external_calls
    - integer
    - suicide
    - delegatecall
    - dependence_on_predictable_vars
```

---

## 🎯 Basic Usage

### Command-Line Interface

#### Analyze a Single Contract

```bash
# Basic analysis (no AI)
python src/miesc_cli.py run-audit demo/sample_contracts/Reentrancy.sol

# With AI correlation
python src/miesc_cli.py run-audit demo/sample_contracts/Reentrancy.sol --enable-ai

# Specify tools
python src/miesc_cli.py run-audit Contract.sol --tools slither,mythril

# Custom output location
python src/miesc_cli.py run-audit Contract.sol --output /path/to/report.json
```

---

#### Analyze Multiple Contracts

```bash
# Analyze all contracts in a directory
python src/miesc_cli.py run-audit-batch contracts/

# With glob pattern
python src/miesc_cli.py run-audit-batch "contracts/**/*.sol"

# Parallel execution
python src/miesc_cli.py run-audit-batch contracts/ --parallel --workers 4
```

---

#### PolicyAgent Compliance Check

```bash
# Check MIESC codebase compliance
python src/miesc_policy_agent.py

# Custom repository path
python src/miesc_policy_agent.py --repo-path /path/to/repo

# Output formats
python src/miesc_policy_agent.py \
    --output-json reports/compliance.json \
    --output-md reports/compliance.md
```

---

#### MCP REST API Server

```bash
# Start server (foreground)
python src/miesc_mcp_rest.py

# Custom host/port
python src/miesc_mcp_rest.py --host 0.0.0.0 --port 5001

# Background with logging
nohup python src/miesc_mcp_rest.py > logs/mcp.log 2>&1 &

# Check status
curl http://localhost:5001/mcp/status
```

---

### Makefile Shortcuts

The project includes a Makefile for common tasks:

```bash
# Show all available commands
make help

# Install dependencies
make install

# Run demo
make demo

# Run tests
make test

# Check code quality
make lint

# Run PolicyAgent
make policy-check

# Start MCP server
make mcp-rest

# Generate coverage report
make coverage

# Clean build artifacts
make clean
```

---

## 📊 Understanding Output

### JSON Report Structure

```json
{
  "metadata": {
    "contract": "demo/sample_contracts/Reentrancy.sol",
    "timestamp": "2025-01-18T12:34:56Z",
    "miesc_version": "3.3.0",
    "analysis_duration": 45.3
  },
  "summary": {
    "total_findings": 6,
    "critical": 1,
    "high": 2,
    "medium": 2,
    "low": 1,
    "informational": 0
  },
  "findings": [
    {
      "id": "MIESC-001",
      "vulnerability_type": "reentrancy-eth",
      "severity": "Critical",
      "confidence": 0.95,
      "tools_detected": ["slither", "mythril"],
      "location": {
        "file": "Reentrancy.sol",
        "line": 41,
        "function": "withdraw"
      },
      "code_snippet": "function withdraw() public {...}",
      "description": "Reentrancy vulnerability in withdraw function",
      "impact": "Attacker can drain contract funds",
      "remediation": "Apply Checks-Effects-Interactions pattern",
      "references": {
        "cwe": "CWE-841",
        "swc": "SWC-107",
        "owasp": "SC01: Reentrancy",
        "real_world": "DAO Hack (2016) - $60M loss"
      },
      "cvss": {
        "score": 9.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
      },
      "ai_analysis": {
        "is_true_positive": true,
        "confidence": 0.95,
        "reasoning": "External call before state update enables reentrancy",
        "priority": 1
      }
    }
  ],
  "compliance_mapping": {
    "iso_27001": ["A.14.2.1", "A.14.2.5"],
    "nist_ssdf": ["PO.3.2", "PS.1.1"],
    "owasp_samm": ["Design-Threat Assessment-2"]
  },
  "metrics": {
    "lines_of_code": 100,
    "functions_analyzed": 8,
    "contracts_analyzed": 3,
    "processing_time_per_tool": {
      "slither": 3.2,
      "mythril": 38.1,
      "aderyn": 2.4
    }
  }
}
```

---

### Markdown Report Example

```markdown
# MIESC Security Analysis Report

**Contract:** Reentrancy.sol
**Date:** 2025-01-18 12:34:56 UTC
**MIESC Version:** 3.3.0

---

## 🎯 Executive Summary

**Overall Risk:** 🔴 Critical

- Total Findings: 6
- Critical: 1
- High: 2
- Medium: 2
- Low: 1

---

## 🔍 Critical Findings

### MIESC-001: Reentrancy Vulnerability

**Severity:** Critical (CVSS 9.1)
**Confidence:** 95%
**Location:** `Reentrancy.sol:41` (function `withdraw`)

**Description:**
Reentrancy vulnerability allows attacker to recursively call withdraw before balance is updated.

**Impact:**
Complete drainage of contract funds.

**Remediation:**
Apply Checks-Effects-Interactions pattern:
```solidity
function withdraw() public {
    uint256 amount = balances[msg.sender];
    require(amount > 0, "Insufficient balance");

    // 1. Checks (done above)
    // 2. Effects (update state BEFORE external call)
    balances[msg.sender] = 0;

    // 3. Interactions (external call last)
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}
```

**References:**
- CWE-841: Improper Enforcement of Behavioral Workflow
- SWC-107: Reentrancy
- OWASP SC01: Reentrancy
- Real-world: DAO Hack (2016) - $60M stolen

**Detected by:** Slither, Mythril, AI Correlation

---
```

---

## 🔬 Advanced Usage

### Custom Tool Integration

Add your own security tool:

```python
# src/miesc_custom_tools.py
from typing import List, Dict

class CustomTool:
    def __init__(self):
        self.name = "my-custom-tool"
        self.version = "1.0.0"

    def analyze(self, contract_path: str) -> List[Dict]:
        # Your analysis logic
        findings = []
        # ... analyze contract ...
        return findings

# Register in miesc_core.py
from miesc_custom_tools import CustomTool

class MIESCCore:
    def __init__(self):
        self.tools = {
            "slither": SlitherWrapper(),
            "mythril": MythrilWrapper(),
            "custom": CustomTool()  # Add here
        }
```

---

### Programmatic API

Use MIESC as a Python library:

```python
from src.miesc_core import MIESCCore
from src.miesc_ai_layer import AICorrelationLayer

# Initialize
miesc = MIESCCore()
ai_layer = AICorrelationLayer(api_key="sk-...")

# Run analysis
contract_path = "path/to/Contract.sol"
raw_findings = miesc.run_tools(contract_path, tools=["slither", "mythril"])

# AI correlation
correlated = ai_layer.correlate_findings(raw_findings)

# Filter by severity
critical = [f for f in correlated if f.severity == "Critical"]

# Generate report
report = miesc.generate_report(correlated, format="json")
print(report)
```

---

### CI/CD Integration

#### GitHub Actions

`.github/workflows/miesc-audit.yml`:

```yaml
name: MIESC Security Audit

on:
  pull_request:
    paths:
      - 'contracts/**/*.sol'
  push:
    branches: [main, develop]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Install MIESC
        run: |
          pip install -r requirements.txt
          pip install slither-analyzer mythril

      - name: Run MIESC Audit
        run: |
          python src/miesc_cli.py run-audit-batch contracts/ \
            --output reports/audit.json \
            --fail-on critical,high

      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: miesc-audit-report
          path: reports/audit.json

      - name: Comment PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const report = require('./reports/audit.json');
            const comment = `## MIESC Security Audit\n\n${report.summary}`;
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

---

#### GitLab CI

`.gitlab-ci.yml`:

```yaml
miesc-audit:
  stage: test
  image: python:3.10
  before_script:
    - pip install -r requirements.txt
    - pip install slither-analyzer mythril
  script:
    - python src/miesc_cli.py run-audit-batch contracts/
    - python src/miesc_policy_agent.py
  artifacts:
    paths:
      - reports/
    reports:
      junit: reports/junit.xml
  only:
    - merge_requests
    - main
```

---

### Pre-commit Hook

Local Git hook for immediate feedback:

`.git/hooks/pre-commit`:

```bash
#!/bin/bash

# Find all staged .sol files
SOL_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.sol$')

if [ -z "$SOL_FILES" ]; then
    echo "No Solidity files to check"
    exit 0
fi

echo "Running MIESC analysis on staged contracts..."

for file in $SOL_FILES; do
    python src/miesc_cli.py run-audit "$file" --quick --fail-on critical
    if [ $? -ne 0 ]; then
        echo "❌ Critical vulnerability found in $file"
        echo "Fix the issue or use 'git commit --no-verify' to bypass (not recommended)"
        exit 1
    fi
done

echo "✅ All staged contracts passed MIESC analysis"
exit 0
```

```bash
chmod +x .git/hooks/pre-commit
```

---

## 🐛 Troubleshooting

### Common Issues

#### 1. ImportError: No module named 'slither'

**Solution:**

```bash
pip install slither-analyzer
# Or if using conda:
conda install -c conda-forge slither-analyzer
```

---

#### 2. Mythril takes too long / hangs

**Solution:**

```bash
# Reduce timeout
python src/miesc_cli.py run-audit Contract.sol --mythril-timeout 60

# Or disable Mythril
python src/miesc_cli.py run-audit Contract.sol --tools slither,aderyn
```

---

#### 3. AI correlation fails with 401 Unauthorized

**Solution:**

```bash
# Check API key
echo $OPENAI_API_KEY

# Set if missing
export OPENAI_API_KEY="sk-..."

# Or use .env file
echo "OPENAI_API_KEY=sk-..." >> .env
```

---

#### 4. MCP server: Address already in use

**Solution:**

```bash
# Find process using port 5001
lsof -i :5001

# Kill it
kill -9 <PID>

# Or use different port
python src/miesc_mcp_rest.py --port 5002
```

---

#### 5. PolicyAgent reports low compliance

**Solution:**

```bash
# Install missing dev tools
pip install -r requirements-dev.txt

# Run each check individually
ruff check src/
black --check src/
mypy src/
bandit -r src/
pytest --cov=src

# Fix issues and re-run
python src/miesc_policy_agent.py
```

---

## 📚 Example Workflows

### Workflow 1: Pre-Deployment Audit

```bash
# 1. Analyze your contract
python src/miesc_cli.py run-audit contracts/MyDeFiProtocol.sol \
    --enable-ai \
    --output reports/pre-deploy-audit.json

# 2. Review critical findings
cat reports/pre-deploy-audit.json | jq '.findings[] | select(.severity == "Critical")'

# 3. Fix vulnerabilities

# 4. Re-analyze
python src/miesc_cli.py run-audit contracts/MyDeFiProtocol.sol \
    --enable-ai \
    --output reports/post-fix-audit.json

# 5. Compare
diff <(jq '.summary' reports/pre-deploy-audit.json) \
     <(jq '.summary' reports/post-fix-audit.json)
```

---

### Workflow 2: Continuous Monitoring

```bash
# 1. Start MCP server
python src/miesc_mcp_rest.py &

# 2. Monitor for new contracts (cron job)
*/10 * * * * /path/to/monitor_contracts.sh

# monitor_contracts.sh:
#!/bin/bash
NEW_CONTRACTS=$(find contracts/ -name "*.sol" -mmin -10)
for contract in $NEW_CONTRACTS; do
    curl -X POST http://localhost:5001/mcp/run_audit \
        -H "Content-Type: application/json" \
        -d "{\"contract\": \"$contract\"}"
done
```

---

### Workflow 3: Batch Analysis

```bash
# Analyze all contracts in SmartBugs dataset
python src/miesc_cli.py run-audit-batch \
    ~/datasets/smartbugs-wild/ \
    --recursive \
    --output analysis/smartbugs-results.json \
    --parallel \
    --workers 8

# Generate summary statistics
python scripts/analyze_results.py analysis/smartbugs-results.json
```

---

## 🔄 Updating MIESC

```bash
# Pull latest changes
git pull origin main

# Update dependencies
pip install -r requirements.txt --upgrade

# Re-run tests
pytest

# Check new version
python src/miesc_cli.py --version
```

---

## 🗑️ Uninstalling

```bash
# Deactivate virtual environment
deactivate

# Remove MIESC directory
cd ..
rm -rf MIESC/

# Remove pip cache (optional)
pip cache purge
```

---

**Next:** Read `docs/03_DEMO_GUIDE.md` for interactive demonstration.

---

**Version:** 3.3.0
**Maintainer:** Fernando Boiero - UNDEF
**Support:** fboiero@frvm.utn.edu.ar
