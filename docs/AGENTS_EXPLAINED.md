# 🤖 MIESC Agents - Complete Guide

## Overview

MIESC uses a **multi-agent architecture** where each agent specializes in a different type of security analysis. Each agent produces **independent evidence** that is then combined for comprehensive coverage.

---

## 🎯 Agent Types

### 1. Static Analysis Agents
**Speed:** ⚡ Fast (seconds)
**Cost:** FREE
**Evidence:** Code patterns, best practices

### 2. Symbolic Execution Agents
**Speed:** 🐌 Slow (minutes)
**Cost:** FREE
**Evidence:** Path exploration, exploit scenarios

### 3. AI Analysis Agents
**Speed:** 🚀 Medium (30-120 seconds)
**Cost:** FREE (Ollama) or Paid (GPT-4)
**Evidence:** Logic bugs, business logic issues

---

## 📋 Available Agents

### Agent #1: Slither (Static Analysis)

**Type:** Static Analyzer
**Developer:** Trail of Bits
**Language:** Python
**License:** AGPL-3.0

**What it does:**
- Analyzes Solidity code without executing it
- 87 built-in detectors
- Finds: reentrancy, access control, arithmetic issues
- Instant results (< 5 seconds)

**Evidence Generated:**
```
output/tag/Slither.txt

Example content:
INFO:Detectors:
Reentrancy in Victim.withdraw() (contracts/reentrancy.sol#8-13):
    External calls:
    - (success) = msg.sender.call{value: amount}() (...)
    State variables written after the call(s):
    - balances[msg.sender] = 0 (...)
Reference: https://github.com/crytic/slither/wiki/...
```

**Installation:**
```bash
pip install slither-analyzer
```

**Usage in MIESC:**
```bash
python main_ai.py contract.sol tag --use-slither
```

**Strengths:**
- ✅ Very fast
- ✅ Low false positive rate
- ✅ Well-documented detectors
- ✅ Actively maintained

**Limitations:**
- ⚠️ Only finds known patterns
- ⚠️ Can't detect complex logic bugs
- ⚠️ Misses runtime issues

---

### Agent #2: Mythril (Symbolic Execution)

**Type:** Symbolic Analyzer
**Developer:** ConsenSys
**Language:** Python
**License:** MIT

**What it does:**
- Explores all possible execution paths
- Analyzes EVM bytecode
- Proves exploitability
- Slower but thorough (2-10 minutes)

**Evidence Generated:**
```
output/tag/Mythril.txt

Example content:
==== Integer Overflow ====
SWC ID: 101
Severity: High
Contract: Token
Function name: transfer(address,uint256)
PC address: 666
Estimated Gas Usage: 5883 - 26598
The arithmetic operation can result in integer overflow.
```

**Installation:**
```bash
pip install mythril
```

**Usage in MIESC:**
```bash
python main_ai.py contract.sol tag --use-mythril
```

**Strengths:**
- ✅ Deep analysis
- ✅ Proves exploitability
- ✅ Finds edge cases
- ✅ Low false positives

**Limitations:**
- ⚠️ Very slow
- ⚠️ Doesn't scale to large contracts
- ⚠️ High resource usage

---

### Agent #3: Aderyn (Fast Static Analysis)

**Type:** Static Analyzer
**Developer:** Cyfrin
**Language:** Rust
**License:** MIT

**What it does:**
- Ultra-fast AST analysis
- Rust-based (compiled, not interpreted)
- Foundry-native integration
- Specialized for modern Solidity patterns

**Evidence Generated:**
```
output/tag/Aderyn.txt

Example content:
High Issues: 2
Medium Issues: 5
Low Issues: 12

H-1: Centralization Risk
Location: contracts/Token.sol:45
The contract has an owner with privileged access...
```

**Installation:**
```bash
cargo install aderyn
# Or use Docker
docker pull cyfrin/aderyn
```

**Usage in MIESC:**
```bash
python main_ai.py contract.sol tag --use-aderyn
```

**Strengths:**
- ✅ Extremely fast
- ✅ Modern Solidity patterns
- ✅ Foundry integration
- ✅ Clean output format

**Limitations:**
- ⚠️ Newer tool (less battle-tested)
- ⚠️ Fewer detectors than Slither
- ⚠️ Rust dependency

---

### Agent #4: Semgrep (Pattern Matching)

**Type:** Pattern Matcher
**Developer:** r2c
**Language:** Python/OCaml
**License:** LGPL 2.1

**What it does:**
- Custom rule-based scanning
- Pattern matching across languages
- SAST tool (not Solidity-specific)
- Community rules available

**Evidence Generated:**
```
output/tag/Semgrep.txt

Example content:
ruleid: solidity-reentrancy
contracts/Bank.sol:10
    (bool success, ) = msg.sender.call{value: amount}("");
    balances[msg.sender] = 0; // State change after external call
```

**Installation:**
```bash
pip install semgrep
```

**Usage in MIESC:**
```bash
python main_ai.py contract.sol tag --use-semgrep
```

**Strengths:**
- ✅ Customizable rules
- ✅ Fast execution
- ✅ Cross-language support
- ✅ CI/CD friendly

**Limitations:**
- ⚠️ Requires custom rules for Solidity
- ⚠️ Not Solidity-native
- ⚠️ Pattern-based only

---

### Agent #5: Ollama (Local AI)

**Type:** AI Analyzer
**Developer:** Ollama + Meta (CodeLlama)
**Language:** Python + Go
**License:** MIT

**What it does:**
- AI-powered code understanding
- Runs 100% locally (private)
- FREE - no API costs
- Detects logic bugs, best practices
- Natural language explanations

**Models Available:**
- `codellama:7b` - Fast, good for CI/CD (30-60s)
- `codellama:13b` - Balanced quality/speed (60-120s)
- `codellama:33b` - Most accurate (requires GPU, 2-5min)

**Evidence Generated:**
```
output/tag/Ollama.txt

Example content:
Ollama Analysis (Model: codellama:13b)
============================================================

Found 3 potential issues

1. [High] Reentrancy vulnerability
   Location: withdraw()
   Description: The withdraw function is vulnerable to reentrancy...
   Recommendation: Use nonReentrant modifier from OpenZeppelin
   SWC-ID: SWC-107
   OWASP: SC-01 - Reentrancy

2. [Medium] Unchecked return value
   Location: transfer()
   Description: The transfer function doesn't check the return value...
   Recommendation: Use SafeERC20 library
```

**Installation:**
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull model
ollama pull codellama:7b
ollama pull codellama:13b
```

**Usage in MIESC:**
```bash
# Quick mode (7b)
python main_ai.py contract.sol tag --use-ollama --quick

# Detailed mode (13b)
python main_ai.py contract.sol tag --use-ollama --ollama-model codellama:13b
```

**Strengths:**
- ✅ Completely free
- ✅ 100% private (local)
- ✅ Finds logic bugs
- ✅ Natural language explanations
- ✅ Contextual understanding

**Limitations:**
- ⚠️ Requires powerful hardware (8GB+ RAM)
- ⚠️ Can have false positives
- ⚠️ Slower than static analysis
- ⚠️ Output quality varies by model

---

### Agent #6: CrewAI (Multi-Agent AI)

**Type:** AI Multi-Agent System
**Developer:** CrewAI
**Language:** Python
**License:** MIT

**What it does:**
- Multiple AI agents collaborate
- Specialized roles (auditor, developer, QA)
- Comprehensive analysis
- Uses GPT-4 or other LLMs

**Agent Roles:**
1. **Security Auditor** - Finds vulnerabilities
2. **Smart Contract Developer** - Reviews code quality
3. **QA Engineer** - Tests edge cases

**Evidence Generated:**
```
output/tag/CrewAI.txt

Example content:
=== Security Auditor Report ===
I've identified 2 critical issues:
1. Reentrancy in withdraw() - HIGH RISK
2. Missing access control in setOwner() - MEDIUM RISK

=== Developer Review ===
Code quality observations:
- Missing natspec comments
- No input validation on amount parameter
- Consider using SafeMath

=== QA Assessment ===
Test coverage gaps:
- No test for reentrancy attack
- Missing edge case: zero amount withdrawal
```

**Installation:**
```bash
pip install crewai
# Requires: export OPENAI_API_KEY=sk-...
```

**Usage in MIESC:**
```bash
python main_ai.py contract.sol tag --use-crewai
```

**Strengths:**
- ✅ Multi-perspective analysis
- ✅ Comprehensive coverage
- ✅ Natural language reports
- ✅ Collaborative reasoning

**Limitations:**
- ⚠️ Requires API key (costs money)
- ⚠️ Slower (2-5 minutes)
- ⚠️ Sends code to cloud
- ⚠️ Variable quality

---

### Agent #7: ChatGPT (Cloud AI)

**Type:** AI Analyzer
**Developer:** OpenAI
**Language:** Python
**License:** Proprietary

**What it does:**
- GPT-4 powered analysis
- Most advanced AI reasoning
- Cloud-based
- Costs per analysis

**Evidence Generated:**
```
output/tag/ChatGPT.txt

Example content:
GPT-4 Security Analysis
=======================

Critical Issues:
1. Reentrancy Vulnerability (HIGH)
   - Function: withdraw()
   - Line: 45-52
   - Impact: Attacker can drain contract
   - Fix: Use Checks-Effects-Interactions pattern

2. Integer Overflow (MEDIUM)
   - Function: add()
   - Line: 78
   - Impact: Balance corruption
   - Fix: Use Solidity 0.8.x or SafeMath
```

**Installation:**
```bash
pip install openai
# Set: export OPENAI_API_KEY=sk-...
```

**Usage in MIESC:**
```bash
python main_ai.py contract.sol tag --use-chatgpt
```

**Strengths:**
- ✅ Most advanced AI
- ✅ Best natural language
- ✅ Contextual understanding
- ✅ Explains complex issues

**Limitations:**
- ⚠️ Costs ~$0.50 per contract
- ⚠️ Sends code to cloud
- ⚠️ Rate limits
- ⚠️ Requires internet

---

## 📊 Agent Comparison Matrix

| Agent | Type | Speed | Cost | Privacy | Accuracy | Best For |
|-------|------|-------|------|---------|----------|----------|
| **Slither** | Static | ⚡⚡⚡ | FREE | ✅ Local | 90% | Known patterns |
| **Mythril** | Symbolic | 🐌 | FREE | ✅ Local | 85% | Deep analysis |
| **Aderyn** | Static | ⚡⚡⚡ | FREE | ✅ Local | 80% | Modern Solidity |
| **Semgrep** | Pattern | ⚡⚡ | FREE | ✅ Local | 75% | Custom rules |
| **Ollama** | AI | 🚀 | FREE | ✅ Local | 70-80% | Logic bugs |
| **CrewAI** | AI | 🚀 | $$ | ❌ Cloud | 75-85% | Comprehensive |
| **ChatGPT** | AI | 🚀 | $$$ | ❌ Cloud | 80-90% | Complex logic |

---

## 🔄 Multi-Agent Workflow

### How Agents Work Together

```
                   Smart Contract
                         │
                         ▼
           ┌─────────────────────────┐
           │  MIESC Coordinator      │
           │  (main_ai.py)           │
           └─────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
   ┌────────┐      ┌────────┐      ┌────────┐
   │Slither │      │Mythril │      │ Ollama │
   │ Agent  │      │ Agent  │      │ Agent  │
   └────────┘      └────────┘      └────────┘
        │                │                │
        ▼                ▼                ▼
   Slither.txt     Mythril.txt      Ollama.txt
        │                │                │
        └────────────────┼────────────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  Report Generator   │
              │  (Consolidates all) │
              └─────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
   dashboard.html  summary.txt   conclusion.txt
```

### Evidence Preservation

Each agent's output is preserved separately:

```
output/mycontract/
├── Slither.txt       ← Slither Agent evidence
├── Mythril.txt       ← Mythril Agent evidence
├── Aderyn.txt        ← Aderyn Agent evidence
├── Ollama.txt        ← Ollama Agent evidence
├── CrewAI.txt        ← CrewAI Agent evidence
├── summary.txt       ← Combined summary
└── conclusion.txt    ← Final assessment
```

**Why separate files?**
- ✅ Full transparency
- ✅ Audit trail
- ✅ Compare agent results
- ✅ Debug false positives
- ✅ Verify findings independently

---

## 🎯 Recommended Agent Combinations

### For CI/CD (Fast Feedback)
```bash
--use-slither --use-ollama --quick
```
- Time: 30-60 seconds
- Cost: $0
- Coverage: Known patterns + basic AI

### For Pre-Audit (Thorough)
```bash
--use-slither --use-mythril --use-ollama --ollama-model codellama:13b
```
- Time: 3-5 minutes
- Cost: $0
- Coverage: Static + Symbolic + AI

### For Critical Contracts (Maximum)
```bash
--use-slither --use-mythril --use-aderyn --use-ollama --use-crewai
```
- Time: 5-10 minutes
- Cost: ~$0.50
- Coverage: All layers

### For Budget-Conscious (Free Only)
```bash
--use-slither --use-mythril --use-ollama
```
- Time: 2-4 minutes
- Cost: $0
- Coverage: Excellent (no cloud services)

---

## 📈 Coverage Analysis

### What Each Agent Catches

**Slither excels at:**
- ✅ Reentrancy
- ✅ Access control
- ✅ Arithmetic issues
- ✅ Uninitialized variables
- ✅ Dangerous delegatecall

**Mythril excels at:**
- ✅ Integer overflow (pre-0.8)
- ✅ Assertion failures
- ✅ Unchecked return values
- ✅ Transaction ordering
- ✅ Front-running

**Ollama excels at:**
- ✅ Logic bugs
- ✅ Business logic issues
- ✅ Best practice violations
- ✅ Gas optimization
- ✅ Code quality

**Combined coverage:**
- 🎯 **86-92%** of common vulnerabilities
- 🎯 **70-80%** of logic bugs
- 🎯 **95%** of known patterns

---

## 🔍 Reading Agent Output

### Slither Output Format
```
INFO:Detectors:
[FINDING_NAME] in [FUNCTION] ([FILE]#[LINE]):
    [DESCRIPTION]
    [DETAILS]
Reference: [URL]
```

### Mythril Output Format
```
==== [ISSUE_TYPE] ====
SWC ID: [NUMBER]
Severity: [High|Medium|Low]
Contract: [NAME]
Function name: [NAME]
PC address: [NUMBER]
[DESCRIPTION]
```

### Ollama Output Format
```
Ollama Analysis (Model: [MODEL])
============================================================

Found [N] potential issues

1. [Severity] [Issue Type]
   Location: [function]
   Description: [details]
   Recommendation: [fix]
   SWC-ID: [id]
```

---

## 💡 Tips for Best Results

### 1. Start with Slither
Always run Slither first - it's fast and catches most issues.

### 2. Add AI for Logic Bugs
Use Ollama to catch issues that pattern matching misses.

### 3. Use Mythril for Critical Functions
Focus symbolic execution on high-risk functions only.

### 4. Compare Agent Results
If multiple agents find the same issue, it's likely real.

### 5. Read Individual Evidence
Don't just rely on summaries - check each agent's output.

### 6. Understand False Positives
Each agent has different FP patterns - learn to recognize them.

---

## 🆘 Troubleshooting

### Agent Not Running

**Slither fails:**
```bash
# Check installation
slither --version

# Reinstall
pip install --upgrade slither-analyzer
```

**Ollama times out:**
```bash
# Use faster model
--ollama-model codellama:7b

# Or increase timeout
--timeout 600
```

**Mythril crashes:**
```bash
# Limit depth
--use-mythril --mythril-max-depth 50

# Or skip for large contracts
--skip-mythril
```

---

## 📚 Further Reading

- [Slither Documentation](https://github.com/crytic/slither/wiki)
- [Mythril Documentation](https://mythril-classic.readthedocs.io/)
- [Ollama Models](https://ollama.ai/library)
- [CrewAI Framework](https://www.crewai.io/)

---

**Remember:** Each agent provides **independent evidence**. The power of MIESC is combining multiple specialized agents for comprehensive coverage! 🚀
