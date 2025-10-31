# MIESC Demo Guide

**Version:** 3.3.0
**Estimated Time:** 5-10 minutes
**Difficulty:** Beginner

---

## 🎯 Demo Objectives

By completing this demo, you will:

1. ✅ Analyze 3 vulnerable smart contracts (Reentrancy, Overflow, Delegatecall)
2. ✅ Understand multi-tool vulnerability detection
3. ✅ See AI correlation in action (false positive reduction)
4. ✅ Validate internal security with PolicyAgent
5. ✅ Interact with MCP REST API endpoints
6. ✅ Generate compliance reports (ISO/NIST/OWASP)

---

## 📋 Prerequisites

### Required
- Python 3.9+
- pip package manager
- 2GB free disk space
- Internet connection (for AI correlation - optional)

### Optional (Enhanced Experience)
- Slither (`pip install slither-analyzer`)
- Mythril (`pip install mythril`)
- jq (`brew install jq` or `apt-get install jq`)
- Jupyter (`pip install jupyter`)

---

## 🚀 Quick Start (Automated Demo)

### Option 1: One-Command Demo

```bash
# Run complete automated demo
bash demo/run_demo.sh
```

**What happens:**
1. Analyzes `Reentrancy.sol` for vulnerabilities
2. Runs PolicyAgent compliance checks
3. Launches MCP REST server
4. Tests MCP endpoints
5. Generates reports in `demo/expected_outputs/`

**Expected duration:** ~90 seconds

**Expected output:**
```
╔════════════════════════════════════════════════════════════════╗
║         MIESC - Interactive Security Analysis Demo            ║
╚════════════════════════════════════════════════════════════════╝

[1/4] Running smart contract security analysis...
  ✓ Analysis complete - report saved
  ✓ Found 2 potential vulnerabilities

[2/4] Running PolicyAgent security compliance checks...
  ✓ PolicyAgent validation complete
  ✓ Compliance Score: 94.2%

[3/4] Launching MCP adapter (background)...
  ✓ MCP server started (PID: 12345)
  ✓ MCP REST API listening on http://localhost:5001

[4/4] Testing MCP endpoints...
  → Testing /mcp/capabilities
    ✓ Capabilities retrieved
  → Testing /mcp/get_metrics
    ✓ Metrics retrieved
  → Testing /mcp/run_audit
    ✓ Audit endpoint tested

╔════════════════════════════════════════════════════════════════╗
║                   Demo Completed Successfully                  ║
╚════════════════════════════════════════════════════════════════╝
```

---

## 🔬 Step-by-Step Manual Demo

### Step 1: Analyze Reentrancy Vulnerability

#### 1.1 Examine the Vulnerable Code

```bash
# View the vulnerable contract
cat demo/sample_contracts/Reentrancy.sol
```

**Key vulnerability (line 41-47):**
```solidity
function withdraw() public {
    uint256 amount = balances[msg.sender];
    require(amount > 0, "Insufficient balance");

    // ❌ VULNERABILITY: External call before state update
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");

    // ❌ State update happens AFTER external call
    balances[msg.sender] = 0;
}
```

**Why it's vulnerable:**
- External call before state update
- Allows recursive calls before balance is zeroed
- Classic reentrancy attack vector

#### 1.2 Run MIESC Analysis

```bash
# Analyze with MIESC
python src/miesc_cli.py run-audit \
    demo/sample_contracts/Reentrancy.sol \
    --enable-ai \
    --output demo/expected_outputs/reentrancy_analysis.json
```

**Expected tools executed:**
- Slither (static analysis)
- Mythril (symbolic execution)
- Aderyn (Rust-based analysis)

#### 1.3 Review Results

```bash
# Pretty-print JSON results
cat demo/expected_outputs/reentrancy_analysis.json | jq
```

**Expected findings:**

```json
{
  "findings": [
    {
      "tool": "slither",
      "vulnerability_type": "reentrancy-eth",
      "severity": "High",
      "confidence": "High",
      "location": {"line": 41, "function": "withdraw"}
    },
    {
      "tool": "mythril",
      "vulnerability_type": "SWC-107",
      "severity": "High",
      "confidence": "Medium"
    }
  ],
  "ai_correlated_findings": [
    {
      "vulnerability_type": "Reentrancy",
      "confidence": 0.95,
      "is_false_positive": false,
      "root_cause": "State modification after external call",
      "remediation": "Apply Checks-Effects-Interactions pattern",
      "priority": 1
    }
  ]
}
```

**Key observations:**
- ✅ Both tools detected the issue (cross-validation)
- ✅ AI correlation confidence: 0.95 (very high)
- ✅ Not a false positive
- ✅ Clear remediation advice

---

### Step 2: Analyze Integer Overflow

#### 2.1 Run Analysis

```bash
python src/miesc_cli.py run-audit \
    demo/sample_contracts/IntegerOverflow.sol \
    --tools slither,mythril \
    --output demo/expected_outputs/overflow_analysis.json
```

#### 2.2 Key Findings

**Vulnerability locations:**
1. Line 31: `uint256 cost = amount * tokenPrice;` (multiplication overflow)
2. Line 49: `balances[msg.sender] -= amount;` (subtraction underflow)
3. Line 64: Loop accumulation overflow

**Tool comparison:**
- Slither: Detects all 3 overflow points
- Mythril: Detects 2 overflow points (misses loop)
- AI: Confirms all as true positives, suggests Solidity 0.8+ upgrade

---

### Step 3: Test PolicyAgent Compliance

#### 3.1 Run PolicyAgent

```bash
python src/miesc_policy_agent.py \
    --repo-path . \
    --output-json demo/expected_outputs/policy_audit.json \
    --output-md demo/expected_outputs/policy_audit.md
```

#### 3.2 Review Compliance Report

```bash
# View Markdown report
cat demo/expected_outputs/policy_audit.md
```

**Expected sections:**
- **Summary:** Compliance score (94.2%)
- **Code Quality:** Ruff, Black, MyPy results
- **Security:** Bandit, Semgrep findings
- **Dependencies:** pip-audit vulnerabilities
- **Testing:** Coverage percentage
- **Framework Alignment:** ISO/NIST/OWASP mapping

**Example output:**
```markdown
# MIESC Internal Compliance Report

**Compliance Score:** 94.2%

## Summary
- **Total Checks:** 16
- **✅ Passed:** 15
- **⚠️ Warnings:** 1
- **❌ Failed:** 0

## Framework Compliance

### ISO/IEC 27001:2022
- Controls Tested: 10
- Controls Passed: 10 (100%)

### NIST SSDF (SP 800-218)
- Practices Tested: 12
- Practices Passed: 11 (92%)
```

---

### Step 4: MCP API Interaction

#### 4.1 Start MCP Server

```bash
# Terminal 1: Start MCP REST API
python src/miesc_mcp_rest.py --host 0.0.0.0 --port 5001
```

**Expected output:**
```
Starting MIESC MCP REST Adapter v3.3.0
Listening on http://0.0.0.0:5001
```

#### 4.2 Test Endpoints (New Terminal)

**Get Agent Capabilities:**
```bash
curl http://localhost:5001/mcp/capabilities | jq
```

**Expected response:**
```json
{
  "agent_id": "miesc-agent-v3.3.0",
  "protocol": "mcp/1.0",
  "capabilities": {
    "run_audit": {...},
    "get_metrics": {...},
    "policy_audit": {...}
  }
}
```

**Get Scientific Metrics:**
```bash
curl http://localhost:5001/mcp/get_metrics | jq
```

**Expected response:**
```json
{
  "metrics": {
    "precision": 0.8947,
    "recall": 0.862,
    "f1_score": 0.8781,
    "cohens_kappa": 0.847
  }
}
```

**Run Audit via API:**
```bash
curl -X POST http://localhost:5001/mcp/run_audit \
  -H "Content-Type: application/json" \
  -d '{"contract": "demo/sample_contracts/Reentrancy.sol"}' | jq
```

---

## 📊 Expected Results Summary

### Vulnerability Detection Matrix

| Contract | Vulnerability | Slither | Mythril | AI Corr. | Severity |
|----------|---------------|---------|---------|----------|----------|
| Reentrancy.sol | Reentrancy | ✅ High | ✅ High | ✅ 0.95 | Critical |
| IntegerOverflow.sol | Overflow | ✅ High | ✅ High | ✅ 0.89 | High |
| IntegerOverflow.sol | Underflow | ✅ High | ✅ High | ✅ 0.89 | High |
| DelegateCall.sol | Unsafe delegatecall | ✅ High | ✅ High | ✅ 0.92 | Critical |
| DelegateCall.sol | Suicidal | ✅ High | ❌ Miss | ⚠️ 0.72 | High |

**Totals:**
- Contracts analyzed: 3
- Vulnerabilities found: 5
- True positives: 4
- False positives: 0
- False negatives: 1 (Mythril missed suicidal)
- Average AI confidence: 0.89

### Performance Metrics

| Phase | Expected Time | Actual (Your Run) |
|-------|---------------|-------------------|
| Contract analysis (3 files) | 45 sec | ___ |
| PolicyAgent validation | 30 sec | ___ |
| MCP server startup | 3 sec | ___ |
| MCP endpoint tests | 5 sec | ___ |
| **Total demo time** | **~90 sec** | ___ |

---

## 🧪 Advanced Demo: Jupyter Notebook

For interactive exploration:

```bash
# Install Jupyter
pip install jupyter matplotlib pandas

# Launch notebook
jupyter notebook demo/demo_notebook.ipynb
```

**Notebook sections:**
1. Contract loading and visualization
2. Tool-by-tool analysis comparison
3. AI correlation deep dive
4. Compliance framework mapping
5. Interactive metrics dashboard

---

## 🎯 Learning Objectives Checklist

After completing the demo, you should be able to:

- [ ] Identify common smart contract vulnerabilities (reentrancy, overflow, delegatecall)
- [ ] Run MIESC analysis from command line
- [ ] Interpret multi-tool detection results
- [ ] Understand AI correlation confidence scores
- [ ] Read PolicyAgent compliance reports
- [ ] Interact with MCP REST API endpoints
- [ ] Map vulnerabilities to compliance frameworks (ISO/NIST/OWASP)
- [ ] Distinguish true positives from false positives

---

## 🐛 Troubleshooting

### Issue: "Tool not found" errors

**Solution:**
```bash
# Install missing tools
pip install slither-analyzer mythril
```

### Issue: MCP server won't start (port in use)

**Solution:**
```bash
# Kill process on port 5001
lsof -ti:5001 | xargs kill -9

# Or use different port
python src/miesc_mcp_rest.py --port 5002
```

### Issue: PolicyAgent shows low compliance

**Solution:**
```bash
# Install dev dependencies
pip install ruff black mypy bandit semgrep pytest-cov

# Re-run PolicyAgent
python src/miesc_policy_agent.py
```

### Issue: AI correlation not working

**Solution:**
```bash
# Set API key (optional - demo works without AI)
export OPENAI_API_KEY="your-key-here"

# Or disable AI correlation
python src/miesc_cli.py run-audit CONTRACT.sol --no-ai
```

---

## 📚 Next Steps

After completing the demo:

1. **Read Documentation:**
   - `docs/04_AI_CORRELATION.md` - How AI reduces false positives
   - `docs/05_POLICY_AGENT.md` - Internal security validation
   - `docs/08_METRICS_AND_RESULTS.md` - Scientific validation

2. **Analyze Your Own Contracts:**
   ```bash
   python src/miesc_cli.py run-audit YourContract.sol --enable-ai
   ```

3. **Integrate into CI/CD:**
   - See `.github/workflows/secure-dev-pipeline.yml`
   - Add MIESC to your pipeline

4. **Explore Advanced Features:**
   - Custom tool configurations
   - Batch contract analysis
   - Compliance report generation

5. **Contribute:**
   - Report bugs or suggest improvements
   - Add new vulnerable contract examples
   - Extend tool integrations

---

## 🎓 Academic Use

**For researchers:**
- Reproduce thesis experiments: `docs/08_METRICS_AND_RESULTS.md`
- Access datasets: `analysis/experiments/`
- Cite this work: See `CITATION.cff`

**For educators:**
- Use demo contracts in security courses
- Assign MIESC analysis as homework
- Compare tool outputs for critical thinking

---

**Demo Version:** 3.3.0
**Last Updated:** 2025-01-18
**Maintainer:** Fernando Boiero - UNDEF

**Questions?** Open an issue or email fboiero@frvm.utn.edu.ar

---

**Next:** Explore `docs/04_AI_CORRELATION.md` to understand how AI reduces false positives.
