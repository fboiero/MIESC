# MIESC Interactive Demo

**Version:** 3.3.0
**Purpose:** Hands-on demonstration of MIESC's multi-layer security analysis capabilities

---

## 🎯 What This Demo Shows

This demo illustrates how MIESC:

1. **Analyzes Smart Contracts** using multiple security tools (Slither, Mythril, Aderyn)
2. **Correlates Vulnerabilities** using AI to reduce false positives
3. **Validates Internal Security** with PolicyAgent compliance checks
4. **Exposes MCP Endpoints** for inter-agent communication
5. **Generates Compliance Reports** aligned with ISO/NIST/OWASP standards

**Time Required:** 5-10 minutes
**Prerequisites:** Python 3.9+, pip, basic Solidity knowledge

---

## 📁 Demo Contents

```
demo/
├── README.md                    # This file
├── run_demo.sh                  # Automated demo script
├── sample_contracts/            # Vulnerable smart contracts
│   ├── Reentrancy.sol          # Classic reentrancy vulnerability
│   ├── IntegerOverflow.sol     # Arithmetic overflow/underflow
│   └── DelegateCall.sol        # Unsafe delegatecall
├── demo_notebook.ipynb         # Jupyter notebook walkthrough
├── expected_outputs/           # Expected results
│   ├── demo_report.json        # Vulnerability analysis results
│   ├── demo_metrics.json       # Scientific validation metrics
│   ├── policy_audit.json       # PolicyAgent compliance report
│   └── mcp_response.json       # MCP API response
└── screenshots/                # Visual aids
    ├── demo_results.png        # Analysis results visualization
    ├── mcp_response.png        # MCP endpoint response
    └── coverage_badge.png      # Test coverage badge
```

---

## 🚀 Quick Start (Automated)

### Option 1: Run Complete Demo

```bash
# Execute the automated demo script
bash demo/run_demo.sh
```

**What it does:**
1. Analyzes `Reentrancy.sol` with MIESC core
2. Runs PolicyAgent security compliance checks
3. Launches MCP REST adapter
4. Tests MCP endpoint with sample request
5. Generates all output files in `expected_outputs/`

**Expected output:**
```
[1/4] Running smart contract analysis...
✓ Found 3 vulnerabilities (1 Critical, 1 High, 1 Medium)

[2/4] Running PolicyAgent security compliance checks...
✓ Compliance Score: 94.2% (15/16 checks passed)

[3/4] Launching MCP adapter (background)...
✓ MCP REST API listening on http://localhost:5001

[4/4] Testing MCP endpoint...
✓ MCP response saved to demo/expected_outputs/mcp_response.json

[✓] Demo completed. Check demo/expected_outputs for results.
```

---

## 🔬 Step-by-Step Manual Demo

### Step 1: Analyze a Vulnerable Contract

#### Example: Reentrancy Vulnerability

```bash
# Run MIESC core analysis on Reentrancy.sol
python src/miesc_cli.py run-audit \
    demo/sample_contracts/Reentrancy.sol \
    --enable-ai \
    --output demo/expected_outputs/reentrancy_report.json
```

**Expected findings:**

| Tool | Vulnerability | Severity | Line | Confidence |
|------|---------------|----------|------|------------|
| Slither | reentrancy-eth | High | 41 | High |
| Mythril | SWC-107 | High | 41 | Medium |
| AI Correlation | Reentrancy | Critical | 41 | 0.95 |

**AI Correlation Output:**
```json
{
  "vulnerability_type": "Reentrancy",
  "severity": "Critical",
  "confidence": 0.95,
  "is_false_positive": false,
  "root_cause": "State modification after external call in withdraw function",
  "remediation": "Apply Checks-Effects-Interactions pattern or use ReentrancyGuard",
  "remediation_priority": 1
}
```

#### Example: Integer Overflow

```bash
python src/miesc_cli.py run-audit \
    demo/sample_contracts/IntegerOverflow.sol \
    --tools slither,mythril \
    --output demo/expected_outputs/overflow_report.json
```

**Expected findings:**

| Tool | Vulnerability | Severity | Location |
|------|---------------|----------|----------|
| Slither | integer-overflow | High | buyTokens() |
| Mythril | SWC-101 | High | Multiple locations |
| Solhint | compiler-version | Warning | pragma ^0.7.0 |

#### Example: Unsafe Delegatecall

```bash
python src/miesc_cli.py run-audit \
    demo/sample_contracts/DelegateCall.sol \
    --enable-ai \
    --output demo/expected_outputs/delegatecall_report.json
```

**Expected findings:**

| Tool | Vulnerability | Severity | Function |
|------|---------------|----------|----------|
| Slither | controlled-delegatecall | High | forward() |
| Slither | suicidal | High | MaliciousLibrary.drain() |
| Mythril | SWC-112 | High | execute() |

---

### Step 2: Run PolicyAgent Compliance Check

```bash
# Execute PolicyAgent validation
python src/miesc_policy_agent.py \
    --repo-path . \
    --output-json demo/expected_outputs/policy_audit.json \
    --output-md demo/expected_outputs/policy_audit.md
```

**Expected PolicyAgent Report:**

```
🔒 MIESC Internal Compliance Validation
============================================================
Compliance Score: 94.2%
Passed: 15 | Failed: 0 | Warnings: 1

Framework Compliance:
  ISO/IEC 27001:2022    10/10 controls  ✅
  NIST SSDF             11/12 practices ✅
  OWASP SAMM v2.0       Level 2.3       ✅

Recommendations:
  📊 Review 1 medium-severity SAST finding
  ✅ All critical checks passed
```

**Policy Checks Performed:**

| Category | Check | Status |
|----------|-------|--------|
| Code Quality | Ruff Linting | ✅ Pass |
| Code Quality | Black Formatting | ✅ Pass |
| Code Quality | MyPy Type Checking | ⚠️ Warning |
| Security | Bandit SAST | ✅ Pass |
| Security | Secret Scanning | ✅ Pass |
| Dependencies | pip-audit | ✅ Pass |
| Testing | Coverage ≥85% | ✅ Pass (87.5%) |
| Documentation | Required Docs | ✅ Pass |

---

### Step 3: Test MCP Interoperability

#### Start MCP REST Server

```bash
# Launch MCP adapter (Flask-based REST API)
python src/miesc_mcp_rest.py --host 0.0.0.0 --port 5001
```

**Output:**
```
Starting MIESC MCP REST Adapter v3.3.0
Listening on http://0.0.0.0:5001
Available endpoints:
  GET  / - API information
  GET  /mcp/capabilities - List capabilities
  GET  /mcp/status - Agent status
  GET  /mcp/get_metrics - Scientific metrics
  POST /mcp/run_audit - Execute audit
  POST /mcp/policy_audit - Internal compliance check
```

#### Test MCP Endpoints

**Get Capabilities:**
```bash
curl http://localhost:5001/mcp/capabilities | jq
```

**Response:**
```json
{
  "agent_id": "miesc-agent-v3.3.0",
  "protocol": "mcp/1.0",
  "version": "3.3.0",
  "capabilities": {
    "run_audit": {
      "description": "Execute comprehensive smart contract security audit",
      "method": "POST",
      "endpoint": "/mcp/run_audit"
    },
    "get_metrics": {
      "description": "Retrieve scientific validation metrics",
      "method": "GET",
      "endpoint": "/mcp/get_metrics"
    }
  },
  "metadata": {
    "precision": 0.8947,
    "recall": 0.862,
    "f1_score": 0.8781,
    "cohens_kappa": 0.847
  }
}
```

**Run Audit via MCP:**
```bash
curl -X POST http://localhost:5001/mcp/run_audit \
  -H "Content-Type: application/json" \
  -d '{
    "contract": "demo/sample_contracts/Reentrancy.sol"
  }' | jq
```

**Get Scientific Metrics:**
```bash
curl http://localhost:5001/mcp/get_metrics | jq
```

**Response:**
```json
{
  "status": "success",
  "metrics": {
    "precision": 0.8947,
    "recall": 0.862,
    "f1_score": 0.8781,
    "cohens_kappa": 0.847,
    "false_positive_reduction": 0.43,
    "dataset_size": 5127,
    "validation": {
      "method": "Expert annotation (3 auditors, 5+ years exp)",
      "statistical_significance": "p < 0.001"
    }
  }
}
```

**Run Policy Audit via MCP:**
```bash
curl -X POST http://localhost:5001/mcp/policy_audit \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "."}' | jq
```

---

## 📊 Understanding the Results

### Vulnerability Report Structure

```json
{
  "contract": "Reentrancy.sol",
  "scan_timestamp": "2025-01-18T12:00:00Z",
  "tools_executed": ["slither", "mythril", "aderyn"],
  "findings": [
    {
      "tool": "slither",
      "vulnerability_type": "reentrancy-eth",
      "severity": "High",
      "confidence": "High",
      "location": {
        "file": "Reentrancy.sol",
        "function": "withdraw",
        "line": 41
      },
      "description": "Reentrancy in VulnerableBank.withdraw()",
      "cwe_id": "CWE-841",
      "swc_id": "SWC-107",
      "owasp_category": "SC01"
    }
  ],
  "ai_correlated_findings": [
    {
      "vulnerability_type": "Reentrancy",
      "severity": "Critical",
      "confidence": 0.95,
      "is_false_positive": false,
      "root_cause": "State modification after external call",
      "remediation": "Apply Checks-Effects-Interactions pattern",
      "remediation_priority": 1,
      "original_findings_count": 2
    }
  ],
  "compliance_mapping": {
    "ISO_27001": ["A.8.8"],
    "NIST_CSF": ["PR.DS-1"],
    "OWASP_SC_Top_10": ["SC01"],
    "CWE": ["CWE-841"],
    "SWC": ["SWC-107"]
  },
  "metrics": {
    "total_findings": 2,
    "critical": 1,
    "high": 1,
    "medium": 0,
    "false_positive_reduction": 0.0
  }
}
```

### Key Metrics Explained

| Metric | Value | Meaning |
|--------|-------|---------|
| **Precision** | 89.47% | 9 out of 10 reported issues are real vulnerabilities |
| **Recall** | 86.2% | Catches 86% of all vulnerabilities |
| **F1 Score** | 87.81% | Harmonic mean of precision and recall |
| **Cohen's Kappa** | 0.847 | Strong agreement with expert auditors |
| **False Positive Reduction** | 43% | AI triage filters out nearly half of false alarms |

---

## 🧪 Interactive Jupyter Notebook

For a step-by-step interactive experience:

```bash
# Install Jupyter
pip install jupyter

# Launch notebook
jupyter notebook demo/demo_notebook.ipynb
```

The notebook includes:
- Contract analysis walkthrough
- Visualization of findings
- AI correlation explanation
- PolicyAgent deep dive
- MCP API interaction examples

---

## 🎓 Educational Value

### What Each Contract Demonstrates

#### Reentrancy.sol
- **Vulnerability:** CWE-841 (Improper Enforcement of Behavioral Workflow)
- **Attack Vector:** Recursive external calls before state update
- **Real-World Example:** DAO Hack (2016) - $60M stolen
- **Detection Difficulty:** Easy (tools agree)
- **MIESC Confidence:** 0.95

#### IntegerOverflow.sol
- **Vulnerability:** CWE-190/191 (Integer Overflow/Underflow)
- **Attack Vector:** Unchecked arithmetic in Solidity <0.8.0
- **Real-World Example:** BeautyChain (BEC) - Market crash
- **Detection Difficulty:** Medium (requires symbolic execution)
- **MIESC Confidence:** 0.89

#### DelegateCall.sol
- **Vulnerability:** CWE-829 (Functionality from Untrusted Source)
- **Attack Vector:** Storage collision via delegatecall
- **Real-World Example:** Parity Wallet Hack - $280M frozen
- **Detection Difficulty:** Hard (requires context understanding)
- **MIESC Confidence:** 0.92

---

## 🔍 Comparing Tools

### Detection Matrix

| Vulnerability | Slither | Mythril | Aderyn | AI Corr. | Combined |
|---------------|---------|---------|--------|----------|----------|
| Reentrancy | ✅ High | ✅ High | ✅ Medium | ✅ 0.95 | ✅ Critical |
| Int. Overflow | ✅ High | ✅ High | ❌ Miss | ✅ 0.89 | ✅ High |
| Delegatecall | ✅ High | ✅ High | ✅ Medium | ✅ 0.92 | ✅ Critical |

**Key Insight:** Multi-tool approach + AI correlation achieves higher precision than any single tool.

---

## 📈 Expected Demo Metrics

After running the complete demo:

| Metric | Expected Value | Actual (Your Run) |
|--------|----------------|-------------------|
| Contracts Analyzed | 3 | ___ |
| Total Vulnerabilities | 7 | ___ |
| Critical Severity | 2 | ___ |
| High Severity | 4 | ___ |
| Medium Severity | 1 | ___ |
| False Positives (pre-AI) | 3 | ___ |
| False Positives (post-AI) | 1 | ___ |
| Policy Compliance Score | 94.2% | ___ |
| Execution Time | ~90 seconds | ___ |

---

## 🛠️ Troubleshooting

### Common Issues

**Issue:** `ModuleNotFoundError: No module named 'slither'`
```bash
# Solution: Install security tools
pip install slither-analyzer mythril
```

**Issue:** `MCP server not responding`
```bash
# Solution: Check if port 5001 is available
lsof -i :5001
# Kill process if needed
kill -9 <PID>
```

**Issue:** `PolicyAgent reports low compliance score`
```bash
# Solution: Install development dependencies
pip install ruff black mypy bandit semgrep pytest-cov
```

**Issue:** `AI correlation not working`
```bash
# Solution: Set OpenAI API key
export OPENAI_API_KEY="your-api-key-here"
```

---

## 📚 Further Reading

- **MIESC Documentation:** `../docs/00_OVERVIEW.md`
- **Architecture Guide:** `../docs/01_ARCHITECTURE.md`
- **AI Correlation Logic:** `../docs/04_AI_CORRELATION.md`
- **PolicyAgent Details:** `../docs/05_POLICY_AGENT.md`
- **Thesis Context:** `../thesis/README.md`

---

## 🤝 Contributing Demo Improvements

Have ideas for better demo contracts or scenarios?

1. Fork the repository
2. Add your contract to `demo/sample_contracts/`
3. Update this README with expected outputs
4. Submit a pull request

**Ideal demo contracts:**
- Real-world vulnerability patterns
- Educational value (well-commented)
- Diverse difficulty levels
- Realistic attack scenarios

---

## 📞 Support

**Issues with demo?**
- GitHub Issues: https://github.com/fboiero/MIESC/issues
- Email: fboiero@frvm.utn.edu.ar
- Tag: `demo` or `documentation`

---

**Demo Version:** 3.3.0
**Last Updated:** 2025-01-18
**Maintainer:** Fernando Boiero - UNDEF
**Estimated Time:** 5-10 minutes

**Happy Hunting! 🔍🛡️**
