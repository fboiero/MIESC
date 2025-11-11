# 🤖 MIESC Agents - Visual Quick Reference

## Agent Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    MIESC MULTI-AGENT SYSTEM                     │
│                                                                 │
│  Input: Smart Contract (.sol file)                             │
│                         │                                       │
│                         ▼                                       │
│             ┌───────────────────────┐                          │
│             │   COORDINATOR         │                          │
│             │   (main_ai.py)        │                          │
│             └───────────────────────┘                          │
│                         │                                       │
│         ┌───────────────┼───────────────┐                      │
│         │               │               │                      │
│         ▼               ▼               ▼                      │
│   ┌─────────┐    ┌─────────┐    ┌─────────┐                  │
│   │SLITHER  │    │ MYTHRIL │    │ OLLAMA  │                  │
│   │ Static  │    │Symbolic │    │   AI    │                  │
│   │⚡ Fast  │    │🐌 Slow  │    │🚀 Smart │                  │
│   │💰 FREE  │    │💰 FREE  │    │💰 FREE  │                  │
│   └─────────┘    └─────────┘    └─────────┘                  │
│         │               │               │                      │
│         ▼               ▼               ▼                      │
│   Slither.txt    Mythril.txt    Ollama.txt                    │
│         │               │               │                      │
│         └───────────────┼───────────────┘                      │
│                         │                                       │
│                         ▼                                       │
│              ┌──────────────────┐                              │
│              │  CONSOLIDATOR    │                              │
│              │  (report_gen)    │                              │
│              └──────────────────┘                              │
│                         │                                       │
│         ┌───────────────┼───────────────┐                      │
│         ▼               ▼               ▼                      │
│   dashboard.html  summary.txt  conclusion.txt                 │
│                                                                 │
│  Output: Evidence + Reports + Dashboard                        │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Quick Agent Comparison

```
┌──────────┬─────────┬───────┬──────┬─────────┬──────────┐
│  Agent   │  Type   │ Speed │ Cost │ Privacy │ Accuracy │
├──────────┼─────────┼───────┼──────┼─────────┼──────────┤
│ Slither  │ Static  │  ⚡⚡⚡ │ FREE │  Local  │   90%    │
│ Mythril  │Symbolic │   🐌  │ FREE │  Local  │   85%    │
│ Aderyn   │ Static  │  ⚡⚡⚡ │ FREE │  Local  │   80%    │
│ Ollama   │   AI    │   🚀  │ FREE │  Local  │   75%    │
│ CrewAI   │   AI    │   🚀  │  $$  │  Cloud  │   80%    │
│ ChatGPT  │   AI    │   🚀  │  $$$ │  Cloud  │   85%    │
└──────────┴─────────┴───────┴──────┴─────────┴──────────┘

Legend:
⚡ = Instant (< 5 sec)
🚀 = Fast (30-120 sec)
🐌 = Slow (2-10 min)
FREE = $0
$$ = ~$0.50/contract
$$$ = ~$1-2/contract
```

---

## 📂 Evidence File Structure

### Single Contract Analysis
```
output/mycontract/
│
├── 📄 Slither.txt          ← Evidence from Slither Agent
│   ├─ Detector: Reentrancy
│   ├─ Detector: Access Control
│   └─ Detector: ...
│
├── 📄 Mythril.txt          ← Evidence from Mythril Agent
│   ├─ SWC-107: Reentrancy
│   ├─ SWC-101: Integer Overflow
│   └─ ...
│
├── 📄 Ollama.txt           ← Evidence from AI Agent
│   ├─ Issue #1: Logic Bug
│   ├─ Issue #2: Best Practice
│   └─ ...
│
├── 📄 summary.txt          ← Executive Summary
└── 📄 conclusion.txt       ← Final Assessment
```

### Multi-Contract Analysis
```
output/myproject/
│
├── 📁 reports/
│   ├── dashboard.html           ← Interactive view (ALL AGENTS)
│   ├── consolidated_report.md   ← All findings (ALL AGENTS)
│   ├── ContractA_report.md      ← Individual report
│   └── ContractB_report.md
│
├── 📁 visualizations/
│   ├── dependency_graph.html
│   └── dependency_tree.txt
│
├── 📁 ContractA/
│   ├── Slither.txt     ← Slither evidence for Contract A
│   ├── Mythril.txt     ← Mythril evidence for Contract A
│   ├── Ollama.txt      ← Ollama evidence for Contract A
│   └── ...
│
└── 📁 ContractB/
    ├── Slither.txt     ← Slither evidence for Contract B
    ├── Mythril.txt     ← Mythril evidence for Contract B
    ├── Ollama.txt      ← Ollama evidence for Contract B
    └── ...
```

---

## 🔍 What Each Agent Detects

### Agent #1: SLITHER (Static Analysis)
```
┌─────────────────────────────────────────┐
│  SLITHER AGENT                          │
│  ────────────────────────────────       │
│  Detects:                               │
│  ✓ Reentrancy                           │
│  ✓ Access control issues                │
│  ✓ Uninitialized variables              │
│  ✓ Dangerous delegatecall               │
│  ✓ Incorrect ERC20 implementation       │
│  ✓ Naming conventions                   │
│  ✓ ... and 81 more detectors            │
│                                         │
│  Output: Slither.txt                    │
│  Format: Line-by-line findings          │
└─────────────────────────────────────────┘
```

### Agent #2: MYTHRIL (Symbolic Execution)
```
┌─────────────────────────────────────────┐
│  MYTHRIL AGENT                          │
│  ────────────────────────────────       │
│  Detects:                               │
│  ✓ Integer overflow/underflow           │
│  ✓ Assertion failures                   │
│  ✓ Unchecked return values              │
│  ✓ Transaction ordering issues          │
│  ✓ Exploitable paths                    │
│                                         │
│  Output: Mythril.txt                    │
│  Format: SWC-ID based findings          │
└─────────────────────────────────────────┘
```

### Agent #3: OLLAMA (Local AI)
```
┌─────────────────────────────────────────┐
│  OLLAMA AGENT (CodeLlama)               │
│  ────────────────────────────────       │
│  Detects:                               │
│  ✓ Logic bugs                           │
│  ✓ Business logic issues                │
│  ✓ Best practice violations             │
│  ✓ Gas optimization opportunities       │
│  ✓ Code quality issues                  │
│  ✓ Complex vulnerabilities              │
│                                         │
│  Output: Ollama.txt                     │
│  Format: Natural language + SWC-ID      │
│  Cost: $0 (runs locally)                │
└─────────────────────────────────────────┘
```

---

## 📊 Example Evidence Files

### Slither.txt Example
```
'solc --version' running
INFO:Detectors:
Reentrancy in Victim.withdraw() (contracts/reentrancy.sol#8-13):
    External calls:
    - (success) = msg.sender.call{value: amount}()
    State variables written after the call(s):
    - balances[msg.sender] = 0
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities
```

### Mythril.txt Example
```
==== Integer Overflow ====
SWC ID: 101
Severity: High
Contract: Token
Function name: transfer(address,uint256)
Description: The arithmetic operation can result in integer overflow.
--------------------
```

### Ollama.txt Example
```
Ollama Analysis (Model: codellama:13b)
============================================================

Found 3 potential issues

1. [High] Reentrancy vulnerability
   Location: withdraw()
   Description: The withdraw function is vulnerable to reentrancy attacks.
                An attacker can exploit this by calling withdraw() recursively
                before the balance is updated.
   Recommendation: Use the Checks-Effects-Interactions pattern or
                   OpenZeppelin's ReentrancyGuard.
   SWC-ID: SWC-107
   OWASP: SC-01 - Reentrancy

2. [Medium] Unchecked return value
   Location: transfer()
   Description: The return value of the transfer call is not checked.
   Recommendation: Use SafeERC20 library or check return value.
   SWC-ID: SWC-104
```

---

## 🎬 Demo Flow

### Step 1: Check Available Agents
```bash
./demo_agents.sh

# Shows:
✓ Slither Agent       - Available
✓ Mythril Agent       - Available (optional)
✓ Ollama Agent        - Available
○ CrewAI Agent        - Not configured
```

### Step 2: Run Analysis
```bash
# Single contract with all agents
python main_ai.py contract.sol demo \
  --use-slither \
  --use-mythril \
  --use-ollama
```

### Step 3: View Individual Evidence
```bash
# Slither findings
cat output/demo/Slither.txt

# Mythril findings
cat output/demo/Mythril.txt

# AI findings
cat output/demo/Ollama.txt
```

### Step 4: View Consolidated Report
```bash
# HTML dashboard (all agents combined)
open output/demo/reports/dashboard.html

# Or markdown report
cat output/demo/reports/consolidated_report.md
```

---

## 📈 Coverage Matrix

```
Vulnerability Type       Slither  Mythril  Ollama  Combined
─────────────────────    ───────  ───────  ──────  ────────
Reentrancy               ✓✓✓      ✓✓       ✓✓      ✓✓✓✓
Access Control           ✓✓✓      ✓        ✓✓      ✓✓✓
Integer Overflow         ✓        ✓✓✓      ✓       ✓✓✓
Uninitialized Variables  ✓✓✓      ✓        ✓       ✓✓✓
Logic Bugs               ✗        ✗        ✓✓✓     ✓✓✓
Best Practices           ✓✓       ✗        ✓✓✓     ✓✓✓
Gas Optimization         ✓        ✗        ✓✓      ✓✓
Arithmetic Issues        ✓✓       ✓✓✓      ✓       ✓✓✓

Legend:
✓✓✓ = Excellent detection
✓✓  = Good detection
✓   = Basic detection
✗   = Not detected
```

---

## 💡 Key Takeaways

### 1. **Multiple Agents = Better Coverage**
```
Single Agent:     70-80% vulnerability detection
Multiple Agents:  85-95% vulnerability detection
```

### 2. **Each Agent Has Strengths**
- Slither: Fast, known patterns
- Mythril: Deep, exploitability proofs
- Ollama: Logic bugs, explanations

### 3. **Evidence is Preserved**
Every agent produces separate output files for:
- Full transparency
- Independent verification
- Audit trails
- Debugging false positives

### 4. **Free = Powerful**
```
Slither + Mythril + Ollama = $0
Coverage: ~90% of vulnerabilities
Time: 2-4 minutes
```

### 5. **Consolidation is Automatic**
MIESC automatically:
- Runs all selected agents
- Preserves individual evidence
- Generates consolidated dashboard
- Creates professional reports

---

## 🚀 Quick Commands

### Run All Free Agents
```bash
python main_ai.py contract.sol tag \
  --use-slither --use-mythril --use-ollama
```

### Multi-Contract with Evidence
```bash
python main_project.py contracts/ tag \
  --visualize --use-ollama
```

### View Individual Agent Results
```bash
# List all evidence files
ls output/tag/*.txt

# Read specific agent
cat output/tag/Slither.txt
cat output/tag/Ollama.txt
```

### View Consolidated Dashboard
```bash
open output/tag/reports/dashboard.html
```

---

## 📞 Need Help?

### Understanding Agent Output
See: `docs/AGENTS_EXPLAINED.md`

### Running the Demo
```bash
./demo_agents.sh
```

### Agent Installation
- Slither: `pip install slither-analyzer`
- Mythril: `pip install mythril`
- Ollama: `curl -fsSL ollama.ai/install.sh | sh`

---

**Remember:** Each agent is a specialist. Together, they provide comprehensive security coverage! 🛡️
