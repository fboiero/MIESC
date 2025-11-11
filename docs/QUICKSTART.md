# ⚡ MIESC Quick Start - 5 Minutes to Your First Smart Contract Audit

<div align="center">

**From zero to detecting vulnerabilities in under 5 minutes**

[🎥 Watch Video Demo](#) | [💻 Try Web Demo](./webapp/README.md) | [📖 Full Documentation](./docs/)

</div>

---

## 🎯 What You'll Build

By the end of this guide, you'll:
- ✅ Install MIESC on your machine
- ✅ Analyze a vulnerable smart contract
- ✅ View an interactive security report
- ✅ Understand how to integrate MIESC into your workflow

**Time required**: 5 minutes
**Prerequisites**: Python 3.9+, basic terminal knowledge

---

## 📦 Step 1: Installation (30 seconds)

### Option A: Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/fboiero/MIESC.git
cd MIESC

# Install core dependencies
pip install slither-analyzer mythril

# Verify installation
python src/miesc_cli.py --version
```

### Option B: Full Install (All 15 Tools)

```bash
# Install all security tools (takes ~5 minutes)
pip install -r requirements.txt

# Install additional tools
brew install echidna  # macOS
# or see docs/02_SETUP_AND_USAGE.md for Linux/Windows
```

**Troubleshooting**: See [Installation Guide](./docs/02_SETUP_AND_USAGE.md) for detailed instructions.

---

## 🔍 Step 2: Analyze Your First Contract (1 minute)

### Example: Detect a Reentrancy Vulnerability

```bash
# Analyze a vulnerable contract included in the repository
python src/miesc_cli.py run-audit \
    examples/reentrancy_simple.sol \
    --mode fast \
    --output outputs/my_first_audit.json
```

**What's happening**:
- 🔍 **Static analysis** with Slither (finds known patterns)
- 🎯 **Symbolic execution** with Mythril (confirms exploits)
- 🤖 **AI triage** filters false positives
- 📊 **Report generation** in HTML, JSON, and PDF formats

**Expected output**:
```
🚀 MIESC v3.3.0 - Smart Contract Security Analysis
====================================================

[1/3] 🔍 Running static analysis (Slither)...
  ✓ Found 3 potential issues

[2/3] 🎯 Running symbolic execution (Mythril)...
  ✓ Confirmed 1 critical vulnerability

[3/3] 📊 Generating reports...
  ✓ Report saved to: outputs/my_first_audit.html

📋 Summary:
  🔴 1 CRITICAL: Reentrancy vulnerability in withdraw()
  🟡 2 LOW: Missing event emissions

⏱️  Total time: 8 seconds
✅ Analysis complete!
```

---

## 📊 Step 3: View the Results (30 seconds)

### Interactive HTML Report

```bash
# Open the report in your browser
open outputs/my_first_audit.html  # macOS
# or
xdg-open outputs/my_first_audit.html  # Linux
# or just double-click the file
```

**The report includes**:
- 📍 **Exact code location** of each vulnerability
- 🛠️ **Fix suggestions** (AI-powered)
- 🔢 **Risk scores** (CVSS)
- 📋 **Compliance mapping** (OWASP, SWC, CWE)
- 📈 **Visualizations** (severity breakdown, tool comparison)

### JSON Output (for CI/CD integration)

```bash
# View JSON output
cat outputs/my_first_audit.json | jq .

# Example structure:
{
  "summary": {
    "total_issues": 3,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 2
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "type": "Reentrancy",
      "location": "withdraw() @ line 41",
      "swc_id": "SWC-107",
      "cwe_id": "CWE-841",
      "fix_suggestion": "Use checks-effects-interactions pattern..."
    }
  ]
}
```

---

## 🚀 Step 4: What's Next?

### Try Different Analysis Modes

```bash
# Fast mode (< 1 minute) - Static analysis only
python src/miesc_cli.py run-audit mycontract.sol --mode fast

# Balanced mode (< 5 minutes) - Static + Symbolic
python src/miesc_cli.py run-audit mycontract.sol --mode balanced

# Full mode (5-15 minutes) - All 6 layers + AI triage
python src/miesc_cli.py run-audit mycontract.sol --mode full --enable-ai-triage
```

### Analyze Your Own Contracts

```bash
# Single contract
python src/miesc_cli.py run-audit path/to/MyToken.sol

# Entire project
python src/miesc_cli.py run-audit contracts/ --recursive

# Specific functions only
python src/miesc_cli.py run-audit MyContract.sol --functions withdraw,transfer
```

### Generate Compliance Reports

```bash
# ISO 27001 compliance evidence
python src/miesc_cli.py run-audit mycontract.sol \
    --compliance-only \
    --standards iso27001,nist,owasp

# Output: outputs/compliance_matrix.html
```

### Try the Web Interface (No Installation!)

```bash
# Launch Streamlit web app
pip install streamlit plotly streamlit-extras
streamlit run webapp/app.py

# Opens at http://localhost:8501
```

**Web demo features**:
- 📝 Paste Solidity code directly
- 📤 Upload `.sol` files
- 🎯 Pre-loaded vulnerable examples
- 📊 Interactive dashboard
- 💾 Export reports

---

## 🎓 Learning Path

### Beginner (Week 1)
- [x] Complete this quick start
- [ ] Read [Architecture Overview](./docs/01_ARCHITECTURE.md)
- [ ] Try [Interactive Demo](./demo/run_demo.sh)
- [ ] Analyze 5 vulnerable contracts from `examples/`

### Intermediate (Week 2)
- [ ] Integrate into [CI/CD pipeline](./.github/workflows/)
- [ ] Customize [PolicyAgent](./docs/05_POLICY_AGENT.md) rules
- [ ] Build custom [Agent](./docs/AGENT_DEVELOPMENT_GUIDE.md)
- [ ] Contribute to [open issues](https://github.com/fboiero/MIESC/issues)

### Advanced (Week 3-4)
- [ ] Deploy [MCP server](./docs/07_MCP_INTEROPERABILITY.md)
- [ ] Create [formal specifications](./data/analysis/certora/specs/)
- [ ] Run [full thesis experiments](./thesis/experiments/)
- [ ] Publish your own research

---

## 💡 Pro Tips

### Tip 1: Start with Fast Mode
Always run `--mode fast` first (takes 8-15 seconds). Only escalate to `--mode full` if you need deep analysis.

### Tip 2: Use AI Triage
Add `--enable-ai-triage` to reduce false positives by 43%. Requires OpenAI API key:
```bash
export OPENAI_API_KEY="your-key-here"
python src/miesc_cli.py run-audit mycontract.sol --enable-ai-triage
```

### Tip 3: Focus on Critical Findings
Filter by severity to reduce noise:
```bash
# Only show critical and high severity issues
python src/miesc_cli.py run-audit mycontract.sol --min-severity high
```

### Tip 4: Compare with Other Tools
Benchmark against individual tools:
```bash
# Run only Slither for comparison
slither mycontract.sol

# Run only Mythril
myth analyze mycontract.sol

# Compare with MIESC output
python src/miesc_cli.py run-audit mycontract.sol
```

---

## 🆘 Troubleshooting

### Issue: "slither: command not found"

**Solution**:
```bash
pip install slither-analyzer
# Verify
slither --version
```

### Issue: "mythril: command not found"

**Solution**:
```bash
pip install mythril
# Verify
myth version
```

### Issue: "ModuleNotFoundError: No module named 'miesc'"

**Solution**:
```bash
# Make sure you're in the MIESC root directory
cd /path/to/MIESC

# Run with Python module syntax
python -m src.miesc_cli run-audit examples/reentrancy_simple.sol
```

### Issue: Analysis takes too long

**Solution**:
```bash
# Use fast mode (skips symbolic execution)
python src/miesc_cli.py run-audit mycontract.sol --mode fast

# Or skip specific slow tools
python src/miesc_cli.py run-audit mycontract.sol --skip mythril,manticore
```

### Still stuck?

- 📖 Check [Full Setup Guide](./docs/02_SETUP_AND_USAGE.md)
- 🐛 [Report a bug](https://github.com/fboiero/MIESC/issues)
- 💬 [Ask the community](https://github.com/fboiero/MIESC/discussions)
- 📧 Email: fboiero@frvm.utn.edu.ar

---

## 🎯 Real-World Examples

### Example 1: DeFi Vault Audit

```bash
# Download a real DeFi contract
curl https://etherscan.io/address/0xYourVault/code > vault.sol

# Run comprehensive audit
python src/miesc_cli.py run-audit vault.sol \
    --mode full \
    --enable-ai-triage \
    --output-format html,json,pdf

# Review findings
open outputs/vault_audit_report.html
```

### Example 2: Pre-Deployment Check (CI/CD)

```bash
# In your GitHub Actions workflow
- name: MIESC Security Check
  run: |
    pip install slither-analyzer mythril
    python src/miesc_cli.py run-audit contracts/ \
      --mode fast \
      --fail-on critical \
      --output ci_report.json
```

### Example 3: Batch Analysis

```bash
# Analyze entire project
python src/miesc_cli.py run-audit contracts/ \
    --recursive \
    --parallel 4 \
    --output batch_results/

# Generate summary
cat batch_results/summary.json | jq '.summary'
```

---

## 📚 Additional Resources

### Official Documentation
- 📖 [Complete Documentation](./docs/)
- 🏗️ [Architecture Deep Dive](./docs/01_ARCHITECTURE.md)
- 🔌 [API Reference](./docs/API_SETUP.md)
- 🤝 [Contributing Guide](./CONTRIBUTING.md)

### Video Tutorials
- 🎥 [5-Minute Intro](#) (coming soon)
- 🎥 [Full Walkthrough](#) (coming soon)
- 🎥 [CI/CD Integration](#) (coming soon)

### Academic Materials
- 🎓 [Master's Thesis](./thesis/)
- 📊 [Experimental Results](./thesis/results/)
- 📄 [Scientific References](./docs/REFERENCES.md) (47 papers)

### Community
- 💬 [GitHub Discussions](https://github.com/fboiero/MIESC/discussions)
- 🐛 [Issue Tracker](https://github.com/fboiero/MIESC/issues)
- 🌟 [Star on GitHub](https://github.com/fboiero/MIESC)

---

## ✨ What Makes MIESC Different?

### vs. Individual Tools (Slither, Mythril)
- ✅ **Multi-tool orchestration**: Combines strengths of 15 tools
- ✅ **AI triage**: 43% fewer false positives
- ✅ **One command**: No need to run tools separately

### vs. Commercial Audit Firms
- ✅ **90% time savings**: 32-50h → 3-5h
- ✅ **Automated compliance**: Maps to 12 standards
- ✅ **Always available**: No waiting for auditor slots

### vs. Other Frameworks
- ✅ **Academic rigor**: Thesis-backed, peer-reviewed
- ✅ **Reproducible**: 100% open source, documented methodology
- ✅ **Standards-compliant**: ISO 27001, NIST, OWASP

---

<div align="center">

## 🚀 Ready to Secure Your Smart Contracts?

[🎯 Try the Demo](./demo/run_demo.sh) | [📖 Read Full Docs](./docs/) | [⭐ Star on GitHub](https://github.com/fboiero/MIESC)

---

**Made with ❤️ for the smart contract security community**

**MIESC v3.3.0** | [GPL-3.0](./LICENSE) | [Fernando Boiero](https://github.com/fboiero) @ UNDEF

</div>
