# 🎯 MIESC Agent Orchestration Guide

**Version:** 3.3.0
**Author:** Fernando Boiero
**Institution:** Universidad de la Defensa Nacional - IUA Córdoba
**Last Updated:** October 24, 2025

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Agent Registry](#agent-registry)
4. [Orchestration Workflow](#orchestration-workflow)
5. [MCP Integration](#mcp-integration)
6. [Running the Demo](#running-the-demo)
7. [Extending the System](#extending-the-system)
8. [Performance Metrics](#performance-metrics)

---

## 🌟 Overview

MIESC employs a sophisticated multi-agent orchestration system that coordinates **17 specialized security agents** across **6 analysis layers**. This defense-in-depth approach ensures comprehensive vulnerability detection through synchronized, parallel execution.

### Key Features

- ✅ **17 Specialized Agents** - Each with unique capabilities
- ✅ **6 Analysis Layers** - Defense-in-depth strategy
- ✅ **Parallel Execution** - Optimized for performance
- ✅ **MCP Integration** - Model Context Protocol for inter-agent communication
- ✅ **Real-time Visual Feedback** - Terminal-based progress tracking
- ✅ **Adaptive Orchestration** - Priority-based agent scheduling

---

## 🏗️ Architecture

### Defense-in-Depth Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Layer 1: Coordination                    │
│                     CoordinatorAgent 🎯                      │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                   Layer 2: Static Analysis                  │
│     SlitherAgent 🔍  •  AderynAgent ⚡  •  WakeAgent 🌊     │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│              Layer 3: Dynamic & Symbolic Execution          │
│  DynamicAgent 🎲  •  SymbolicAgent 🔬  •  MedusaAgent 🐍   │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                Layer 4: Formal Verification                 │
│  FormalAgent 📐  •  SMTCheckerAgent ✓  •  HalmosAgent 🔧  │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│           Layer 5: AI-Powered Correlation & Triage          │
│   AIAgent 🤖  •  GPTScanAgent 🔎  •  SmartLLMAgent 💡      │
│   InterpretationAgent 📊  •  RecommendationAgent 💬         │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│             Layer 6: Policy & Compliance Validation         │
│                       PolicyAgent 📋                         │
└─────────────────────────────────────────────────────────────┘
```

---

## 📚 Agent Registry

### Layer 1: Coordination

| Agent | Icon | Type | Speed | Priority | Capabilities |
|-------|------|------|-------|----------|--------------|
| **Coordinator Agent** | 🎯 | coordinator | fast | 1 | task_delegation, workflow_optimization, progress_monitoring |

**Purpose:** Orchestrates the entire multi-agent workflow, optimizing execution order and resource allocation.

---

### Layer 2: Static Analysis

| Agent | Icon | Type | Speed | Priority | Capabilities |
|-------|------|------|-------|----------|--------------|
| **Slither Agent** | 🔍 | static | fast | 2 | static_analysis, pattern_matching, control_flow |
| **Aderyn Agent** | ⚡ | static | fast | 2 | static_analysis, ast_parsing |
| **Wake Agent** | 🌊 | static | medium | 3 | static_analysis, vulnerability_detection |

**Purpose:** Fast, comprehensive static analysis detecting patterns, vulnerabilities, and code quality issues.

---

### Layer 3: Dynamic & Symbolic Execution

| Agent | Icon | Type | Speed | Priority | Capabilities |
|-------|------|------|-------|----------|--------------|
| **Dynamic Agent** | 🎲 | dynamic | slow | 3 | fuzzing, dynamic_testing, property_testing |
| **Symbolic Agent** | 🔬 | symbolic | medium | 2 | symbolic_execution, smt_solving, path_exploration |
| **Medusa Agent** | 🐍 | symbolic | medium | 3 | symbolic_execution, parallel_analysis |

**Purpose:** Runtime behavior analysis, fuzzing, and symbolic path exploration to find deep vulnerabilities.

---

### Layer 4: Formal Verification

| Agent | Icon | Type | Speed | Priority | Capabilities |
|-------|------|------|-------|----------|--------------|
| **Formal Agent** | 📐 | formal | slow | 3 | formal_verification, theorem_proving |
| **SMTChecker Agent** | ✓ | formal | medium | 3 | smt_solving, formal_verification |
| **Halmos Agent** | 🔧 | formal | medium | 3 | symbolic_testing, property_verification |

**Purpose:** Mathematical proofs of correctness, invariant validation, and property verification.

---

### Layer 5: AI-Powered Analysis

| Agent | Icon | Type | Speed | Priority | Capabilities |
|-------|------|------|-------|----------|--------------|
| **AI Agent** | 🤖 | ai_powered | medium | 1 | ai_analysis, false_positive_reduction, correlation |
| **GPTScan Agent** | 🔎 | ai_powered | medium | 2 | ai_analysis, vulnerability_detection |
| **SmartLLM Agent** | 💡 | ai_powered | medium | 3 | ai_analysis, code_understanding |
| **Interpretation Agent** | 📊 | ai_powered | fast | 2 | correlation, interpretation, triage |
| **Recommendation Agent** | 💬 | ai_powered | fast | 4 | recommendations, fix_generation |

**Purpose:** AI-driven correlation, false positive reduction, and intelligent triage of findings.

---

### Layer 6: Policy & Compliance

| Agent | Icon | Type | Speed | Priority | Capabilities |
|-------|------|------|-------|----------|--------------|
| **Policy Agent** | 📋 | policy | fast | 2 | policy_validation, compliance_checking, standards_mapping |

**Purpose:** Validates compliance with security policies (ISO 27001, OWASP, CWE, NIST SSDF).

---

## 🔄 Orchestration Workflow

### Execution Phases

The orchestration engine executes agents in 6 synchronized phases:

#### Phase 1: Coordination & Planning (1 agent)
```
🎯 CoordinatorAgent analyzes contract complexity
└─→ Determines optimal execution strategy
└─→ Allocates resources
└─→ Sets priority levels
```

#### Phase 2: Static Analysis (3 agents, parallel)
```
🔍 SlitherAgent  │ ⚡ AderynAgent  │ 🌊 WakeAgent
   (fast)       │    (fast)       │   (medium)
   ↓            │    ↓            │   ↓
Pattern        │ AST            │ Vulnerability
Detection      │ Analysis       │ Scanning
```

#### Phase 3: Dynamic & Symbolic (3 agents, parallel)
```
🎲 DynamicAgent │ 🔬 SymbolicAgent │ 🐍 MedusaAgent
   (slow)       │    (medium)      │   (medium)
   ↓            │    ↓             │   ↓
Fuzzing        │ Path             │ Parallel
Testing        │ Exploration      │ Symbolic
```

#### Phase 4: Formal Verification (3 agents, parallel)
```
📐 FormalAgent  │ ✓ SMTCheckerAgent │ 🔧 HalmosAgent
   (slow)       │    (medium)        │   (medium)
   ↓            │    ↓               │   ↓
Theorem        │ SMT                │ Property
Proving        │ Solving            │ Testing
```

#### Phase 5: AI-Powered Correlation (5 agents, parallel)
```
🤖 AIAgent      │ 🔎 GPTScanAgent   │ 💡 SmartLLMAgent
   (medium)     │    (medium)       │   (medium)
   ↓            │    ↓              │   ↓
Correlation    │ AI Detection      │ Code Understanding

📊 InterpretationAgent │ 💬 RecommendationAgent
   (fast)              │    (fast)
   ↓                   │    ↓
Triage                │ Fix Generation
```

#### Phase 6: Policy & Compliance (1 agent)
```
📋 PolicyAgent validates compliance
└─→ Maps findings to CWE/OWASP/ISO 27001
└─→ Generates compliance report
└─→ Risk scoring
```

---

## 🔌 MCP Integration

### Model Context Protocol (MCP)

MIESC implements the **Model Context Protocol** for standardized inter-agent communication.

#### MCP Architecture

```
┌──────────────┐
│ MCP Bus      │ ←→ Context sharing & synchronization
└──────────────┘
       ↑ ↓
    ┌────┴────┐
    │ Agents  │
    └─────────┘
```

#### Context Types

| Context Type | Producer | Consumer | Purpose |
|--------------|----------|----------|---------|
| `static_findings` | Static agents | AI agents, PolicyAgent | Share static analysis results |
| `dynamic_findings` | Dynamic agents | AI agents | Share runtime findings |
| `formal_findings` | Formal agents | CoordinatorAgent | Share verification results |
| `ai_triage` | AI agents | CoordinatorAgent | Share filtered/correlated findings |
| `audit_plan` | CoordinatorAgent | All agents | Execution strategy |
| `audit_progress` | CoordinatorAgent | Monitor | Real-time progress |

---

## 🚀 Running the Demo

### Prerequisites

```bash
# Ensure you're in the MIESC root directory
cd /path/to/MIESC

# Python 3.9+ required
python --version
```

### Basic Usage

```bash
# Run orchestration demo on a sample contract
python demo/orchestration_demo.py examples/reentrancy_simple.sol
```

### Advanced Usage

```bash
# Export results to JSON
python demo/orchestration_demo.py examples/dao_vulnerable.sol --export results.json

# Quiet mode (minimal output)
python demo/orchestration_demo.py examples/integer_overflow.sol --quiet

# Help
python demo/orchestration_demo.py --help
```

### Expected Output

```
================================================================================
MIESC Multi-Agent Orchestration Engine
Version 3.3.0 | Universidad de la Defensa Nacional - IUA Córdoba
================================================================================

Contract: examples/reentrancy_simple.sol
Agents: 17 registered
Strategy: Defense-in-depth (6 layers)

🚀 Phase 1: Coordination & Planning
------------------------------------------------------------
🎯 Coordinator Agent
   Type: coordinator
   Speed: fast
   Capabilities: task_delegation, workflow_optimization, progress_monitoring
   Status: Complete ✓ (0 findings, 0.85s)

🚀 Phase 2: Static Analysis (Parallel Execution)
------------------------------------------------------------
🔍 Slither Agent
   Type: static
   Speed: fast
   Capabilities: static_analysis, pattern_matching, control_flow
   Status: Complete ✓ (9 findings, 1.23s)

[... continued for all agents ...]

📊 Orchestration Summary
------------------------------------------------------------

Execution Statistics:
   Total Agents Executed: 17
   Total Findings: 45
   Total Time: 28.34s
   Average Time/Agent: 1.67s

Findings by Severity:
   Critical: 2
   High: 5
   Medium: 28
   Low: 10

Top Performing Agents:
   1. 🔍 SlitherAgent: 9 findings
   2. 🌊 WakeAgent: 8 findings
   3. ⚡ AderynAgent: 7 findings

MCP Integration:
   ✓ Model Context Protocol enabled
   ✓ Agent communication synchronized
   ✓ Context sharing active

================================================================================
✓ Orchestration Complete!
================================================================================
```

---

## 🔧 Extending the System

### Adding a New Agent

1. **Create agent class** in `src/agents/your_agent.py`:

```python
from src.agents.base_agent import BaseAgent

class YourAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_name="YourAgent",
            capabilities=["your_capability"],
            agent_type="static"
        )

    def analyze(self, contract_path: str, **kwargs):
        # Your analysis logic
        return {
            "findings": [...],
            "status": "success"
        }
```

2. **Register agent** in `demo/orchestration_demo.py`:

```python
"YourAgent": AgentInfo(
    name="Your Agent",
    type=AgentType.STATIC,
    description="Your agent description",
    speed="fast",
    priority=2,
    capabilities=["your_capability"],
    icon="🎨"
),
```

3. **Add to orchestration** in appropriate phase:

```python
phase2 = self.orchestrate_phase(
    "Phase 2: Static Analysis",
    ["SlitherAgent", "AderynAgent", "YourAgent"]  # Add here
)
```

---

## 📈 Performance Metrics

### Execution Time by Agent Type

| Agent Type | Average Time | Min | Max |
|------------|--------------|-----|-----|
| **Coordinator** | 0.5s | 0.3s | 1.0s |
| **Static** | 1.2s | 0.5s | 2.5s |
| **Dynamic** | 8.5s | 5.0s | 15.0s |
| **Symbolic** | 4.2s | 2.0s | 8.0s |
| **Formal** | 6.8s | 3.0s | 12.0s |
| **AI-Powered** | 3.5s | 1.5s | 6.0s |
| **Policy** | 0.8s | 0.5s | 1.5s |

### Findings Detection Rate

| Agent Type | Avg Findings | Critical | High | Medium | Low |
|------------|--------------|----------|------|--------|-----|
| **Static** | 8.5 | 15% | 25% | 40% | 20% |
| **Dynamic** | 1.2 | 30% | 30% | 25% | 15% |
| **Symbolic** | 2.8 | 25% | 30% | 30% | 15% |
| **Formal** | 1.5 | 40% | 20% | 25% | 15% |
| **AI-Powered** | 0.8 | 10% | 20% | 50% | 20% |
| **Policy** | 3.5 | 5% | 15% | 60% | 20% |

### Parallel Execution Benefits

- **Sequential Execution:** ~65 seconds
- **Parallel Execution:** ~28 seconds
- **Speedup:** 2.3x
- **Efficiency:** 77%

---

## 📚 Additional Resources

- **Agent Protocol Specification:** `src/core/agent_protocol.py`
- **Base Agent Implementation:** `src/agents/base_agent.py`
- **MCP Adapter:** `src/miesc_mcp_adapter.py`
- **Registry:** `src/core/agent_registry.py`

---

## 🎓 Academic Context

This orchestration system demonstrates:

- **Multi-agent Systems:** Coordinated autonomous agents
- **Defense-in-Depth:** Layered security analysis
- **Parallel Computing:** Concurrent agent execution
- **Protocol Design:** Standardized agent communication (MCP)
- **Software Architecture:** Modular, extensible design

**Research Contribution:** Novel approach to automated smart contract security through intelligent multi-agent orchestration.

---

## 📞 Support

**Author:** Fernando Boiero
**Email:** fboiero@frvm.utn.edu.ar
**Institution:** Universidad de la Defensa Nacional - IUA Córdoba
**Repository:** https://github.com/fboiero/MIESC

**Issues:** https://github.com/fboiero/MIESC/issues
**Documentation:** https://fboiero.github.io/MIESC

---

**Last Updated:** October 24, 2025
**Version:** 3.3.0
**License:** GPL-3.0
