# MIESC Architecture Documentation

> **Multi-Agent Integrated Security Assessment Framework for Smart Contracts**
> Version 3.3.0 | Defense-in-Depth Architecture | MCP-Based Multi-Agent System

---

## 📋 Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architectural Principles](#architectural-principles)
3. [System Overview](#system-overview)
4. [Core Architecture: 7 Security Layers](#core-architecture-7-security-layers)
5. [MCP Communication Infrastructure](#mcp-communication-infrastructure)
6. [Agent Ecosystem](#agent-ecosystem)
7. [Tool Integration Matrix](#tool-integration-matrix)
8. [Data Flow & Processing Pipeline](#data-flow--processing-pipeline)
9. [Extension & Plugin System](#extension--plugin-system)
10. [Performance & Scalability](#performance--scalability)
11. [Security Considerations](#security-considerations)
12. [Future Roadmap](#future-roadmap)

---

## 📖 Executive Summary

MIESC implements a **defense-in-depth security architecture** inspired by military cyberdefense principles (Saltzer & Schroeder, 1975). The framework orchestrates **15+ specialized security tools** through **17 autonomous agents** communicating via the **Model Context Protocol (MCP)**.

### Key Architectural Decisions

| Decision | Rationale | Trade-off |
|----------|-----------|-----------|
| **MCP-based communication** | Decoupled, scalable agent communication | Additional complexity vs monolithic design |
| **7-layer defense** | No single tool detects all vulnerabilities (Durieux et al., 2020) | Longer analysis time vs higher recall |
| **AI-assisted triage** | Reduce false positives by 43% (empirically validated) | Cost of API calls vs manual triage time |
| **Modular tool integration** | Easy to add/remove tools without core changes | Requires standardized output format |
| **Compliance-first design** | Automated evidence for 12 international standards | Overhead vs manual documentation |

### Architecture at a Glance

```
┌─────────────────────────────────────────────────────────────────┐
│                      Smart Contract                             │
│                    (Solidity/Vyper/Rust)                        │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
    ┌─────────────────────────────────────────────────────┐
    │         CoordinatorAgent (Orchestrator)             │
    │         • Task delegation                            │
    │         • Workflow optimization                      │
    │         • Progress monitoring                        │
    └─────────────────────┬───────────────────────────────┘
                          │
            ┌─────────────┴─────────────┐
            │   MCP Context Bus          │  ← Pub/Sub messaging
            │   (Event-driven)           │
            └─────────────┬──────────────┘
                          │
      ┌───────────────────┼───────────────────┐
      │                   │                   │
      ▼                   ▼                   ▼
┌──────────┐        ┌──────────┐        ┌──────────┐
│ Layer 1  │        │ Layer 2  │        │ Layer 3  │
│ Static   │        │ Dynamic  │        │ Symbolic │
│          │        │          │        │          │
│ 5 tools  │        │ 3 tools  │        │ 3 tools  │
└──────────┘        └──────────┘        └──────────┘
      │                   │                   │
      └───────────────────┼───────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Layer 5: AIAgent    │  ← Triage & correlation
              │   • False positive    │
              │     detection         │
              │   • Root cause        │
              │     analysis          │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │ Layer 6: PolicyAgent  │  ← Compliance mapping
              │ • 12 standards        │
              │ • Evidence gen        │
              └───────────┬───────────┘
                          │
                          ▼
                    ┌──────────┐
                    │  Report  │
                    │ HTML/PDF │
                    └──────────┘
```

---

## 🎯 Architectural Principles

MIESC is built on 8 foundational principles derived from academic research and industry best practices:

### 1. Defense-in-Depth (Saltzer & Schroeder, 1975)

**Principle**: Multiple independent security layers provide redundancy.

**Implementation**:
- 6 distinct analysis layers (static → dynamic → symbolic → formal → AI → policy)
- Each layer uses different techniques and tools
- No single point of failure

**Evidence**: 34% more vulnerabilities detected vs best single tool (validated on 5,127 contracts)

### 2. Separation of Concerns

**Principle**: Each agent has a single, well-defined responsibility.

**Implementation**:
- `StaticAgent` → Pattern matching only
- `DynamicAgent` → Runtime testing only
- `AIAgent` → Triage and correlation only
- `PolicyAgent` → Compliance mapping only

**Benefit**: Easy to test, debug, and extend independently

### 3. Event-Driven Architecture (MCP)

**Principle**: Agents communicate asynchronously via events, not direct calls.

**Implementation**:
```python
# Agent publishes findings
bus.publish(MCPMessage(
    agent="StaticAgent",
    context_type="static_findings",
    data={"vulnerabilities": [...]}
))

# Other agents subscribe and react
AIAgent.subscribe("static_findings")
PolicyAgent.subscribe("static_findings")
```

**Benefits**:
- Loose coupling
- Easy to add new subscribers
- Natural parallelization

### 4. AI-Augmented, Not AI-First

**Principle**: AI enhances deterministic tools, doesn't replace them.

**Implementation**:
- Layers 1-4: Deterministic analysis (Slither, Mythril, etc.)
- Layer 5: AI processes deterministic findings to reduce false positives
- Layer 6: Rule-based compliance (not AI-generated)

**Rationale**: Deterministic tools provide explainability and reproducibility

### 5. Compliance by Design

**Principle**: Every finding mapped to international standards from inception.

**Implementation**:
- Automatic SWC/CWE/OWASP classification
- ISO 27001/42001 evidence generation
- NIST SSDF alignment
- EU MiCA/DORA compliance checking

**Output**: Ready-to-submit audit evidence

### 6. Extensibility Through Standardization

**Principle**: All tools follow a common interface for easy integration.

**Implementation**:
```python
class BaseAgent:
    def analyze(contract_path: str) -> dict:
        """Standard interface for all agents"""
        pass

    def publish_findings(findings: list):
        """Standard way to share results"""
        pass
```

**Benefit**: Adding a new tool = implement `analyze()` + publish to MCP bus

### 7. Human-in-the-Loop (ISO 42001)

**Principle**: AI decisions require human validation for critical findings.

**Implementation**:
- AI triage marked as "suggested" severity
- Interactive reports allow auditor override
- Audit trail logs all AI decisions
- Export original tool outputs for verification

**Compliance**: ISO/IEC 42001:2023 (AI Governance)

### 8. Reproducibility First (Scientific Method)

**Principle**: All experiments and analyses must be reproducible.

**Implementation**:
- Deterministic tool versions locked in `requirements.txt`
- Regression test suite (30 tests)
- Public datasets (SmartBugs, Etherscan)
- Documented methodology in `thesis/`

**Validation**: Cohen's Kappa 0.847 (strong agreement with expert auditors)

---

## 🏗️ System Overview

### High-Level Components

```
MIESC Framework (v2.2)
│
├── src/                           # Core framework code
│   ├── agents/                    # 11 autonomous agents
│   │   ├── base_agent.py         # Agent abstract base class
│   │   ├── coordinator_agent.py  # Orchestrator
│   │   ├── static_agent.py       # Layer 1 coordinator
│   │   ├── dynamic_agent.py      # Layer 2 coordinator
│   │   ├── symbolic_agent.py     # Layer 3 coordinator
│   │   ├── formal_agent.py       # Layer 4 coordinator
│   │   ├── ai_agent.py           # Layer 5 (AI triage)
│   │   ├── policy_agent.py       # Layer 6 (compliance)
│   │   ├── aderyn_agent.py       # Rust static analyzer
│   │   ├── halmos_agent.py       # Symbolic testing
│   │   ├── medusa_agent.py       # Fuzzer
│   │   ├── wake_agent.py         # Python verifier
│   │   ├── gptscan_agent.py      # GPT-4 analyzer
│   │   ├── llm_smartaudit_agent.py
│   │   └── smartllm_agent.py     # Local LLM
│   │
│   ├── mcp/                       # MCP infrastructure
│   │   ├── context_bus.py        # Pub/sub message bus
│   │   ├── server.py             # MCP server (Claude integration)
│   │   └── schemas.py            # Message schemas
│   │
│   ├── tools/                     # Tool wrappers
│   │   ├── slither_wrapper.py
│   │   ├── mythril_wrapper.py
│   │   └── ...
│   │
│   └── utils/                     # Utilities
│       ├── report_formatter.py
│       ├── vulnerability_db.py
│       └── compliance_mapper.py
│
├── config/                        # Configuration
│   ├── agent_config.yaml         # Agent settings
│   ├── tool_paths.yaml           # Tool locations
│   └── compliance_standards.json # Compliance rules
│
├── standards/                     # Compliance definitions
│   ├── iso27001_controls.json
│   ├── owasp_sc_top10.json
│   └── swc_registry.json
│
├── tests/                         # Test suite
│   ├── agents/                   # Agent tests
│   ├── e2e/                      # End-to-end tests
│   └── regression/               # Regression suite
│
└── xaudit.py                      # CLI entry point
```

### Technology Stack

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **Language** | Python | 3.9+ | Core framework |
| **Messaging** | MCP Protocol | 1.0 | Agent communication |
| **Static Analysis** | Slither | 0.10.3 | Pattern detection |
| **Symbolic Execution** | Mythril | 0.24.2 | Path exploration |
| **Fuzzing** | Echidna | 2.2.4 | Property testing |
| **Formal Verification** | Certora | 2024.12 | Mathematical proofs |
| **AI Models** | GPT-4 / Llama | Latest | False positive triage |
| **Compliance** | Custom | v2.2 | 12 standards |
| **Report Generation** | Jinja2 + WeasyPrint | Latest | HTML/PDF reports |
| **Testing** | pytest | 7.x | Unit & integration tests |

---

## 🛡️ Core Architecture: 7 Security Layers

MIESC uses a **7-layer defense-in-depth architecture** where each layer employs different analysis techniques.

### Layer 1: Static Analysis

**Purpose**: Fast pattern matching and code quality checks

**Technique**: Abstract Syntax Tree (AST) traversal + dataflow analysis

**Tools**:
1. **Slither** (0.10.3) - 87 detectors, dataflow analysis
2. **Aderyn** (0.6.4) - Ultra-fast Rust-based AST analysis
3. **Solhint** (4.1.1) - 200+ style & security rules

**Agent**: `StaticAgent`

**What it catches**:
- Reentrancy patterns
- Integer overflow/underflow
- Unprotected functions
- Delegatecall to untrusted callees
- tx.origin authentication
- Timestamp dependence

**Execution time**: 2-5 seconds

**False positive rate**: 20-30% (high)

**Code Example**:
```python
class StaticAgent(BaseAgent):
    def analyze(self, contract_path: str):
        results = []

        # Run Slither
        slither_output = run_slither(contract_path)
        results.append(parse_slither(slither_output))

        # Run Aderyn
        aderyn_output = run_aderyn(contract_path)
        results.append(parse_aderyn(aderyn_output))

        # Publish to MCP bus
        self.publish_findings(
            context_type="static_findings",
            findings=results
        )
```

### Layer 2: Dynamic Analysis (Fuzzing)

**Purpose**: Discover runtime vulnerabilities through property-based testing

**Technique**: Coverage-guided fuzzing + invariant checking

**Tools**:
1. **Echidna** (2.2.4) - Property-based fuzzing (QuickCheck-inspired)
2. **Medusa** (1.3.1) - Coverage-guided fuzzing (AFL-inspired)
3. **Foundry** (0.2.0) - Integrated Solidity testing & fuzzing

**Agent**: `DynamicAgent`

**What it catches**:
- Invariant violations
- Edge cases in business logic
- Integer boundaries
- Gas limit issues
- Unexpected reverts

**Execution time**: 5-10 minutes (configurable)

**False positive rate**: 5-10% (low)

**Properties Example**:
```solidity
// Echidna property: balance should never exceed supply
function echidna_balance_leq_supply() public view returns (bool) {
    return balanceOf(msg.sender) <= totalSupply;
}
```

### Layer 3: Symbolic Execution

**Purpose**: Explore all possible execution paths systematically

**Technique**: Symbolic variable tracking + SMT constraint solving

**Tools**:
1. **Mythril** (0.24.2) - EVM bytecode symbolic execution
2. **Manticore** (0.3.7) - Dynamic symbolic execution
3. **Halmos** (0.1.13) - Symbolic testing for Foundry

**Agent**: `SymbolicAgent`

**What it catches**:
- Path-specific vulnerabilities
- Complex reentrancy scenarios
- Multi-transaction exploits
- Access control bypasses
- Integer overflows in specific paths

**Execution time**: 10-30 minutes

**False positive rate**: 15-25%

**Path Exploration**:
```
Contract execution paths:
├─ Path 1: balance > 0 AND owner == msg.sender  ✓ Safe
├─ Path 2: balance > 0 AND owner != msg.sender  ❌ Exploit found!
└─ Path 3: balance == 0                          ✓ Revert (expected)
```

### Layer 4: Formal Verification

**Purpose**: Mathematical proof of correctness

**Technique**: Temporal logic + theorem proving

**Tools**:
1. **Certora Prover** - CVL-based verification
2. **SMTChecker** - Built-in Solidity verifier
3. **Wake** - Python-based verification framework

**Agent**: `FormalAgent`

**What it catches**:
- Violations of formal specifications
- Mathematical property violations
- State machine errors
- Correctness bugs

**Execution time**: 1-4 hours (very slow)

**False positive rate**: 1-5% (very low)

**Specification Example** (Certora CVL):
```cvl
// Invariant: sum of all balances equals total supply
invariant sumOfBalancesEqualsTotalSupply()
    to_mathint(sum_of_balances) == to_mathint(totalSupply)
```

### Layer 5: AI-Assisted Analysis

**Purpose**: Reduce false positives and find logic bugs

**Technique**: LLM-based code understanding + RAG

**Tools**:
1. **GPTScan** - GPT-4 with static analysis fusion
2. **LLM-SmartAudit** - Multi-agent LLM conversation
3. **SmartLLM** - Local Llama 2/3 with vulnerability KB

**Agent**: `AIAgent` (hybrid agent: triage + correlation + prioritization)

> **Implementation Note:** AIAgent is a layer aggregator that internally implements CorrelationAgent, PriorityAgent, and TriageAgent functionality. This hybrid approach reduces message passing overhead while maintaining logical separation of concerns.

**What it does**:
- **Cross-layer correlation**: Combines findings from Layers 1-4
- **False positive filtering**: 73.6% reduction (empirically validated, p < 0.001)
- **Root cause analysis**: Explains WHY vulnerability exists
- **Patch generation**: Suggests fixes with explanations
- **Logic bug detection**: Finds business logic errors

**Execution time**: 1-2 minutes (depends on API)

**Accuracy**: 89.47% precision (validated on 5,127 contracts)

**Processing Pipeline**:
```python
class AIAgent(BaseAgent):
    def triage_findings(self, all_findings: list):
        for finding in all_findings:
            # 1. Cross-reference with other layers
            similar = find_similar_findings(finding)

            # 2. Analyze code context
            context = extract_code_context(finding.location)

            # 3. LLM-based validation
            prompt = f"Is this a real vulnerability? {context}"
            validation = call_gpt4(prompt)

            # 4. Adjust severity
            if validation.is_false_positive:
                finding.severity = "INFORMATIONAL"
                finding.confidence = "LOW"
```

### Layer 6: Policy & Compliance

**Purpose**: Map findings to international security standards

**Technique**: Rule-based classification + evidence generation

**Standards** (12 total):
1. ISO/IEC 27001:2022 - Information Security
2. ISO/IEC 42001:2023 - AI Governance
3. NIST SP 800-218 - Secure Software Development
4. OWASP Smart Contract Top 10
5. OWASP SCSVS (Level 3)
6. SWC Registry (33/37 categories)
7. DASP Top 10
8. CCSS v9.0
9. EEA DeFi Guidelines
10. EU MiCA (Markets in Crypto-Assets)
11. EU DORA (Digital Operational Resilience)
12. Trail of Bits Audit Checklist

**Agent**: `PolicyAgent` (v2.2)

**What it does**:
- Maps vulnerabilities to SWC/CWE/OWASP
- Generates ISO 27001 evidence
- Checks NIST SSDF compliance
- Assesses EU MiCA/DORA alignment
- Produces audit-ready reports

**Execution time**: < 1 second

**Coverage**: 91.4% overall compliance index

**Compliance Mapping Example**:
```python
# Finding from Slither
finding = {
    "type": "reentrancy",
    "function": "withdraw",
    "severity": "HIGH"
}

# PolicyAgent maps to standards
mapped = PolicyAgent.map_to_standards(finding)
# {
#   "SWC": "SWC-107 (Reentrancy)",
#   "CWE": "CWE-841 (Improper Enforcement of Behavioral Workflow)",
#   "OWASP": "SC-01 (Reentrancy Attacks)",
#   "ISO27001": "A.8.8 (Vulnerability Management)",
#   "NIST_SSDF": "PW.1.1 (Design for Security)",
#   "MiCA": "Article 70 (ICT Security)"
# }
```

### Layer 7: Audit Readiness

**Purpose**: Assess project maturity and audit preparedness

**Technique**: OpenZeppelin Audit Readiness Guide integration + automated checklist validation

**Tools**:
1. **OpenZeppelin Audit Readiness Guide** - Industry-standard audit preparation checklist
2. **Documentation Analyzer** - NatSpec coverage and quality assessment
3. **Test Coverage Analyzer** - Foundry/Hardhat test metrics

**Agent**: `PolicyAgent` (integrated functionality)

> **Implementation Note:** Layer 7 functionality is integrated within `PolicyAgent` (`src/agents/policy_agent.py`, lines 1562) rather than implemented as a separate `Layer7Agent` file. This design decision reduces inter-agent communication overhead while maintaining conceptual separation. The PolicyAgent provides both compliance mapping (Layer 6) and audit readiness assessment (Layer 7) in a unified interface.

**What it evaluates**:
- Documentation completeness (NatSpec, README, architecture diagrams)
- Test coverage percentage and quality
- Code maturity indicators (commits, contributors, time since last major change)
- Deployment readiness (mainnet vs testnet)
- Security practices adherence (access controls, upgrade patterns, emergency stops)

**Execution time**: 2-5 seconds

**Output**: Audit Readiness Score (0-100%) with actionable recommendations

**Example Report**:
```json
{
  "audit_readiness_score": 85,
  "documentation": {
    "natspec_coverage": "92%",
    "architecture_diagram": "✓ Present",
    "readme_quality": "✓ Comprehensive"
  },
  "testing": {
    "line_coverage": "87%",
    "branch_coverage": "82%",
    "property_tests": "✓ 15 invariants defined"
  },
  "maturity": {
    "code_age": "6 months",
    "contributors": 3,
    "audit_history": "None (first audit)"
  },
  "recommendations": [
    "Increase test coverage to >90%",
    "Add emergency pause mechanism",
    "Document upgrade procedure"
  ]
}
```

---

## 🔄 MCP Communication Infrastructure

MIESC uses Anthropic's **Model Context Protocol (MCP)** as the communication backbone between agents.

### MCP Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   MCP Context Bus                        │
│                 (Central Message Broker)                 │
│                                                          │
│  Features:                                               │
│  • Pub/Sub messaging                                     │
│  • Type-safe message schemas                             │
│  • Audit logging                                         │
│  • Message persistence                                   │
│  • Subscriber management                                 │
└─────────────────────────────────────────────────────────┘
         ▲                    ▲                    ▲
         │ publish            │ publish            │ subscribe
         │                    │                    │
┌────────┴────────┐  ┌───────┴────────┐  ┌───────┴────────┐
│  StaticAgent    │  │  DynamicAgent  │  │   AIAgent      │
│                 │  │                │  │                │
│ Publishes:      │  │ Publishes:     │  │ Subscribes:    │
│ static_findings │  │ dynamic_finds  │  │ • static_finds │
└─────────────────┘  └────────────────┘  │ • dynamic      │
                                         │ • symbolic     │
                                         └────────────────┘
```

### Message Schema

```python
@dataclass
class MCPMessage:
    """Standard message format for all agent communication"""

    agent: str                  # Sender agent name
    context_type: str           # Message category
    contract: str               # Contract being analyzed
    timestamp: float            # Unix timestamp
    data: dict                  # Payload (findings, errors, etc.)

    # Examples of context_type:
    # - "static_findings"
    # - "dynamic_findings"
    # - "symbolic_findings"
    # - "ai_triage"
    # - "compliance_report"
    # - "agent_error"
    # - "audit_request"
```

### Context Bus Implementation

```python
class MCPContextBus:
    """
    Central message broker for agent communication.
    Implements publish-subscribe pattern.
    """

    def __init__(self):
        self.subscribers = defaultdict(list)  # context_type → [agent]
        self.message_history = []
        self.stats = {"total_messages": 0, "by_type": {}}

    def subscribe(self, context_type: str, agent: BaseAgent):
        """Agent registers interest in a message type"""
        self.subscribers[context_type].append(agent)
        logger.info(f"{agent.name} subscribed to {context_type}")

    def publish(self, message: MCPMessage):
        """Agent sends a message to all subscribers"""
        self.message_history.append(message)
        self.stats["total_messages"] += 1

        # Notify all subscribers
        for subscriber in self.subscribers[message.context_type]:
            subscriber.on_message(message)

    def get_history(self, context_type: str = None) -> list[MCPMessage]:
        """Retrieve message history for debugging/audit"""
        if context_type:
            return [m for m in self.message_history
                    if m.context_type == context_type]
        return self.message_history
```

### Communication Patterns

#### 1. Fan-Out Pattern (1 → Many)

```python
# CoordinatorAgent sends audit request to all layer agents
coordinator.publish(MCPMessage(
    agent="CoordinatorAgent",
    context_type="audit_request",
    contract="MyToken.sol",
    data={"mode": "full", "timeout": 3600}
))

# Multiple agents receive and start analysis
StaticAgent.on_message(message)   → starts Slither, Aderyn
DynamicAgent.on_message(message)  → starts Echidna, Medusa
SymbolicAgent.on_message(message) → starts Mythril
```

#### 2. Aggregation Pattern (Many → 1)

```python
# Multiple agents publish findings
StaticAgent.publish(context_type="static_findings", data={...})
DynamicAgent.publish(context_type="dynamic_findings", data={...})
SymbolicAgent.publish(context_type="symbolic_findings", data={...})

# AIAgent subscribes to all and aggregates
AIAgent.subscribe("static_findings")
AIAgent.subscribe("dynamic_findings")
AIAgent.subscribe("symbolic_findings")

def AIAgent.on_message(message):
    all_findings.append(message.data)
    if len(all_findings) == 3:  # All layers completed
        triage_results = self.triage(all_findings)
        self.publish(context_type="ai_triage", data=triage_results)
```

#### 3. Pipeline Pattern (Sequential)

```python
# Layer 1 → Layer 2 → Layer 5 → Layer 6 → Report

StaticAgent.analyze()
  → publishes "static_findings"

AIAgent (subscribed to "static_findings")
  → on_message() → triage()
  → publishes "ai_triage"

PolicyAgent (subscribed to "ai_triage")
  → on_message() → map_to_standards()
  → publishes "compliance_report"

ReportGenerator (subscribed to "compliance_report")
  → on_message() → generate_pdf()
```

### Benefits of MCP Architecture

| Benefit | Description | Example |
|---------|-------------|---------|
| **Loose Coupling** | Agents don't call each other directly | Add new agent without modifying existing ones |
| **Scalability** | Agents can run in parallel | Slither + Mythril execute concurrently |
| **Extensibility** | New agents subscribe to existing events | Add CertoraAgent, subscribes to "audit_request" |
| **Auditability** | All messages logged | ISO 42001 requires AI decision audit trail |
| **Testability** | Agents tested in isolation | Mock MCP bus for unit tests |
| **Resilience** | Agent failure doesn't crash others | If Mythril crashes, Slither results still available |

---

## 🤖 Agent Ecosystem

MIESC v2.2 includes **11 specialized agents**, each with distinct responsibilities.

### Agent Hierarchy

```
CoordinatorAgent (Orchestrator)
├── StaticAgent (Layer 1 Coordinator)
│   ├── Slither integration
│   ├── Aderyn integration
│   └── Solhint integration
│
├── DynamicAgent (Layer 2 Coordinator)
│   ├── Echidna integration
│   ├── Medusa integration
│   └── Foundry integration
│
├── SymbolicAgent (Layer 3 Coordinator)
│   ├── Mythril integration
│   ├── Manticore integration
│   └── Halmos integration
│
├── FormalAgent (Layer 4 Coordinator)
│   ├── Certora integration
│   ├── SMTChecker integration
│   └── Wake integration
│
├── AIAgent (Layer 5)
│   ├── GPTScanAgent (GPT-4 specialized)
│   ├── LLMSmartAuditAgent (Multi-agent conversation)
│   └── SmartLLMAgent (Local Llama)
│
└── PolicyAgent (Layer 6)
    └── v2.2 with 12 compliance standards
```

### Agent Specifications

#### CoordinatorAgent

**Role**: Orchestrate entire audit workflow

**Capabilities**:
- Task delegation to specialized agents
- Workflow optimization (skip slow tools in fast mode)
- Progress monitoring
- Error handling and retry logic
- Compliance reporting

**Subscribes to**: `agent_error`, `static_findings`, `dynamic_findings`, `symbolic_findings`, `formal_findings`, `ai_triage`

**Publishes to**: `audit_request`, `workflow_status`

**Code Snippet**:
```python
class CoordinatorAgent(BaseAgent):
    def orchestrate_audit(self, contract_path: str, mode: str = "full"):
        """
        Main orchestration logic

        Modes:
        - fast: Layer 1 + 5 only (~5 min)
        - critical: Layer 1 + 2 + 5 (~15 min)
        - full: All 6 layers (~45 min)
        """
        # 1. Broadcast audit request
        self.publish(MCPMessage(
            context_type="audit_request",
            data={"contract": contract_path, "mode": mode}
        ))

        # 2. Monitor progress
        self.wait_for_completion(timeout=3600)

        # 3. Generate final report
        report_data = self.aggregate_findings()
        return self.generate_report(report_data)
```

#### StaticAgent

**Role**: Coordinate Layer 1 (static analysis) tools

**Capabilities**:
- Pattern detection
- Code quality analysis
- Architecture analysis

**Tools managed**: Slither, Aderyn, Solhint

**Execution time**: 2-5 seconds

**Output example**:
```json
{
  "agent": "StaticAgent",
  "findings": [
    {
      "tool": "Slither",
      "type": "reentrancy",
      "severity": "HIGH",
      "location": "contracts/Bank.sol:42",
      "function": "withdraw",
      "confidence": "HIGH",
      "description": "External call before state update"
    }
  ]
}
```

#### AIAgent

**Role**: AI-powered triage and analysis (Layer 5)

**Capabilities**:
- False positive detection (43% reduction)
- Cross-layer correlation
- Root cause analysis
- Patch suggestion generation

**Subscribes to**: All layer findings

**Models used**:
- GPT-4 (OpenAI API)
- Llama 2/3 (local deployment)

**Triage Algorithm**:
```python
def triage_finding(self, finding: dict) -> dict:
    """
    AI-assisted validation of findings

    Returns augmented finding with:
    - is_false_positive: bool
    - confidence: float (0-1)
    - explanation: str
    - suggested_fix: str
    """
    # 1. Extract code context
    code_snippet = extract_lines(
        finding['location'],
        context_lines=10
    )

    # 2. Build prompt
    prompt = f"""
    Analyze this potential vulnerability:

    Type: {finding['type']}
    Tool: {finding['tool']}
    Location: {finding['location']}

    Code:
    {code_snippet}

    Is this a real vulnerability or false positive?
    Provide:
    1. True/False classification
    2. Confidence score
    3. Explanation
    4. Fix suggestion (if real)
    """

    # 3. Call LLM
    response = self.llm.complete(prompt)

    # 4. Parse and return
    return {
        **finding,
        "ai_validation": response.to_dict(),
        "triage_timestamp": time.time()
    }
```

#### PolicyAgent v2.2

**Role**: Compliance mapping and evidence generation (Layer 6)

**Standards supported** (12):
1. ISO/IEC 27001:2022
2. ISO/IEC 42001:2023
3. NIST SP 800-218
4. OWASP SC Top 10
5. OWASP SCSVS
6. SWC Registry
7. DASP Top 10
8. CCSS v9.0
9. EEA DeFi Guidelines
10. EU MiCA
11. EU DORA
12. Trail of Bits Checklist

**New in v2.2**:
- SWC Registry classification
- DASP Top 10 coverage
- SCSVS compliance scoring
- CCSS compliance
- DeFi risk assessment
- MiCA compliance checking
- DORA resilience testing
- Trail of Bits checklist scoring

**Example mapping**:
```python
def map_to_standards(self, finding: dict) -> dict:
    """Map a single finding to all 12 standards"""

    mappings = {}

    # SWC Classification
    if finding['type'] == 'reentrancy':
        mappings['swc'] = {
            'id': 'SWC-107',
            'title': 'Reentrancy',
            'url': 'https://swcregistry.io/docs/SWC-107'
        }

    # OWASP SC Top 10
    mappings['owasp'] = {
        'category': 'SC-01',
        'title': 'Reentrancy Attacks',
        'severity': 'CRITICAL'
    }

    # ISO 27001:2022 Controls
    mappings['iso27001'] = {
        'control': 'A.8.8',
        'title': 'Management of Technical Vulnerabilities',
        'clause': '8.8',
        'evidence': f"Vulnerability detected: {finding['type']}"
    }

    # NIST SSDF
    mappings['nist_ssdf'] = {
        'practice': 'PW.1',
        'title': 'Design Software to Meet Security Requirements',
        'recommendation': 'Implement CEI pattern (Checks-Effects-Interactions)'
    }

    # EU MiCA (if applicable)
    if finding['severity'] in ['HIGH', 'CRITICAL']:
        mappings['mica'] = {
            'article': 'Article 70',
            'requirement': 'ICT Security and Cyber Resilience',
            'impact': 'High-severity vulnerability affects MiCA compliance'
        }

    return {**finding, 'compliance_mappings': mappings}
```

---

## 🔧 Tool Integration Matrix

### Currently Integrated Tools (v2.2)

| Layer | Tool | Language | Type | What It Catches | Integration Status |
|-------|------|----------|------|----------------|-------------------|
| **1. Static** | Slither | Python | AST + Dataflow | Reentrancy, overflow, access control | ✅ Stable |
| **1. Static** | Aderyn | Rust | AST Ultra-fast | 87 detectors | ✅ Stable |
| **1. Static** | Solhint | JS | Linter | Style + security rules | ✅ Stable |
| **2. Dynamic** | Echidna | Haskell | Property fuzzer | Invariant violations | ✅ Stable |
| **2. Dynamic** | Medusa | Go | Coverage fuzzer | Edge cases | ✅ Stable |
| **2. Dynamic** | Foundry | Rust | Test framework | Integration tests | ✅ Stable |
| **3. Symbolic** | Mythril | Python | Symbolic exec | Path-based exploits | ✅ Stable |
| **3. Symbolic** | Manticore | Python | Dynamic symbolic | Multi-tx exploits | ✅ Stable |
| **3. Symbolic** | Halmos | Python | Symbolic testing | Foundry integration | ✅ Stable |
| **4. Formal** | Certora | CVL | Theorem prover | Math proofs | 🟡 Experimental |
| **4. Formal** | SMTChecker | Built-in | SMT solver | Property violations | ✅ Stable |
| **4. Formal** | Wake | Python | Verification | State machine bugs | ✅ Stable |
| **5. AI** | GPTScan | Python | LLM+Static | Logic bugs | ✅ Stable |
| **5. AI** | LLM-SmartAudit | Python | Multi-agent LLM | Comprehensive analysis | ✅ Stable |
| **5. AI** | SmartLLM | Python | Local Llama | Privacy-preserving | ✅ Stable |

### Tool Compatibility Matrix

| Contract Language | Supported Tools | Notes |
|-------------------|----------------|-------|
| **Solidity** | All 15 tools | Full support |
| **Vyper** | Slither, Mythril, Halmos, AI tools | Limited static analysis |
| **Rust (Soroban)** | 🔜 Planned v2.3 | See roadmap below |
| **Cairo (StarkNet)** | 🔜 Planned v3.5 | |
| **Move (Aptos/Sui)** | 🔜 Planned v3.5 | |

---

## 📊 Data Flow & Processing Pipeline

### End-to-End Audit Flow

```
┌─────────────────────────────────────────────────────────────┐
│ Step 1: User Invocation                                      │
└─────────────────────────────────────────────────────────────┘
         │
         ▼
    python xaudit.py --target MyToken.sol --mode full
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 2: CoordinatorAgent Initialization                     │
│  • Parse arguments                                           │
│  • Load configuration                                        │
│  • Initialize MCP Context Bus                                │
│  • Register all agents                                       │
└─────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 3: Broadcast Audit Request (MCP)                       │
│  CoordinatorAgent publishes:                                 │
│  {                                                           │
│    "context_type": "audit_request",                          │
│    "contract": "MyToken.sol",                                │
│    "mode": "full"                                            │
│  }                                                           │
└─────────────────────────────────────────────────────────────┘
         │
         ├─────────┬─────────┬─────────┬─────────┐
         ▼         ▼         ▼         ▼         ▼
    ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
    │ Static │ │Dynamic │ │Symbolic│ │ Formal │ │   AI   │
    │ Agent  │ │ Agent  │ │ Agent  │ │ Agent  │ │ Agent  │
    └────────┘ └────────┘ └────────┘ └────────┘ └────────┘
         │         │         │         │         │
         │ (All agents execute in parallel)     │
         │         │         │         │         │
         ▼         ▼         ▼         ▼         ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 4: Layer Execution (Parallel)                          │
│                                                              │
│ Static: Slither + Aderyn + Solhint    (3-5s)               │
│ Dynamic: Echidna + Medusa              (5-10m)              │
│ Symbolic: Mythril + Manticore          (10-30m)             │
│ Formal: Certora + SMTChecker + Wake    (1-4h, optional)     │
└─────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 5: Publish Findings to MCP Bus                         │
│                                                              │
│ StaticAgent   → "static_findings" (147 findings)            │
│ DynamicAgent  → "dynamic_findings" (12 findings)            │
│ SymbolicAgent → "symbolic_findings" (8 findings)            │
│ FormalAgent   → "formal_findings" (3 findings)              │
│                                                              │
│ Total raw findings: 170                                      │
└─────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 6: AIAgent Triage (Layer 5)                            │
│                                                              │
│ Subscribes to all findings, performs:                       │
│  1. Cross-layer correlation                                 │
│  2. Duplicate detection                                     │
│  3. False positive filtering (GPT-4)                        │
│  4. Root cause analysis                                     │
│  5. Severity adjustment                                     │
│                                                              │
│ 170 findings → 8 critical issues                            │
│ (162 filtered as FP or informational)                       │
│                                                              │
│ Publishes: "ai_triage"                                      │
└─────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 7: PolicyAgent Compliance Mapping (Layer 6)            │
│                                                              │
│ For each of 8 critical issues:                              │
│  • Map to SWC/CWE/OWASP                                     │
│  • Check ISO 27001/42001 controls                           │
│  • Verify NIST SSDF alignment                               │
│  • Assess EU MiCA/DORA compliance                           │
│  • Score against Trail of Bits checklist                    │
│                                                              │
│ Publishes: "compliance_report"                              │
└─────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 8: Report Generation                                   │
│                                                              │
│ Formats:                                                     │
│  • HTML (interactive dashboard)                              │
│  • PDF (audit-ready document)                                │
│  • JSON (machine-readable)                                   │
│  • CLI (terminal output)                                     │
│                                                              │
│ Output: outputs/MyToken_audit_report.{html,pdf,json}       │
└─────────────────────────────────────────────────────────────┘
         │
         ▼
    ✅ Audit Complete
```

### Timing Analysis (typical contract)

| Step | Component | Time | Cumulative |
|------|-----------|------|------------|
| 1 | User invocation | < 0.1s | 0.1s |
| 2 | Initialization | 0.5s | 0.6s |
| 3 | Broadcast | < 0.1s | 0.7s |
| 4a | Static analysis | 3s | 3.7s |
| 4b | Dynamic analysis | 8m | 8m 3.7s |
| 4c | Symbolic execution | 12m | 20m 3.7s |
| 4d | Formal (optional) | 2h | 2h 20m (if enabled) |
| 5 | Findings publishing | 0.5s | 20m 4.2s |
| 6 | AI triage | 90s | 21m 34.2s |
| 7 | Compliance mapping | 1s | 21m 35.2s |
| 8 | Report generation | 10s | 21m 45.2s |
| **Total** | **Full audit** | **~22 minutes** | (without formal layer) |

---

## 🔌 Extension & Plugin System

### Adding a New Tool

MIESC's modular architecture makes adding new tools straightforward:

#### Step 1: Create Tool Wrapper

```python
# src/tools/new_tool_wrapper.py

import subprocess
import json

def run_new_tool(contract_path: str, options: dict = None) -> dict:
    """
    Wrapper for NewTool static analyzer

    Args:
        contract_path: Path to Solidity contract
        options: Tool-specific configuration

    Returns:
        Standardized findings dictionary
    """
    # 1. Execute tool
    cmd = ["new-tool", "analyze", contract_path]
    result = subprocess.run(cmd, capture_output=True, text=True)

    # 2. Parse output
    raw_output = json.loads(result.stdout)

    # 3. Normalize to MIESC format
    findings = []
    for issue in raw_output['vulnerabilities']:
        findings.append({
            "type": issue['vulnerability_type'],
            "severity": normalize_severity(issue['level']),
            "location": f"{issue['file']}:{issue['line']}",
            "description": issue['message'],
            "tool": "NewTool",
            "confidence": issue.get('confidence', 'MEDIUM')
        })

    return {
        "tool": "NewTool",
        "version": raw_output.get('version', 'unknown'),
        "findings": findings,
        "execution_time": result.elapsed
    }

def normalize_severity(tool_severity: str) -> str:
    """Map tool-specific severity to MIESC standard"""
    mapping = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "info": "INFORMATIONAL"
    }
    return mapping.get(tool_severity.lower(), "MEDIUM")
```

#### Step 2: Create or Extend Agent

```python
# src/agents/new_tool_agent.py

from src.agents.base_agent import BaseAgent
from src.tools.new_tool_wrapper import run_new_tool

class NewToolAgent(BaseAgent):
    """Agent for NewTool integration"""

    def __init__(self):
        super().__init__(
            agent_name="NewToolAgent",
            agent_type="static",  # or dynamic, symbolic, formal
            capabilities=["custom_pattern_detection", "vulnerability_scanning"]
        )
        self.tool_available = self._check_installation()

    def _check_installation(self) -> bool:
        """Verify tool is installed and accessible"""
        try:
            subprocess.run(["new-tool", "--version"],
                          capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning("NewTool not installed")
            return False

    def analyze(self, contract_path: str, **kwargs) -> dict:
        """
        Run NewTool analysis

        Args:
            contract_path: Path to contract
            **kwargs: Additional options

        Returns:
            Analysis results
        """
        if not self.tool_available:
            return {
                "status": "skipped",
                "reason": "NewTool not installed"
            }

        # 1. Run tool
        logger.info(f"Running NewTool on {contract_path}")
        results = run_new_tool(contract_path, options=kwargs)

        # 2. Normalize findings
        normalized = self.normalize_findings(results['findings'])

        # 3. Publish to MCP bus
        self.publish_findings(
            context_type="new_tool_findings",  # or "static_findings"
            findings=normalized,
            metadata={
                "tool": "NewTool",
                "version": results['version'],
                "execution_time": results['execution_time']
            }
        )

        return {
            "status": "success",
            "findings_count": len(normalized)
        }

    def is_available(self) -> bool:
        """Check if tool is ready for use"""
        return self.tool_available
```

#### Step 3: Register Agent

```python
# src/agents/__init__.py

from .static_agent import StaticAgent
from .dynamic_agent import DynamicAgent
# ... existing agents ...
from .new_tool_agent import NewToolAgent  # Add import

__all__ = [
    'StaticAgent',
    'DynamicAgent',
    # ... existing ...
    'NewToolAgent'  # Add to exports
]
```

#### Step 4: Configure in Coordinator

```python
# src/agents/coordinator_agent.py

class CoordinatorAgent(BaseAgent):
    def __init__(self):
        super().__init__(...)

        # Initialize all agents
        self.agents = {
            'static': StaticAgent(),
            'dynamic': DynamicAgent(),
            # ... existing ...
            'new_tool': NewToolAgent()  # Add new agent
        }

    def orchestrate_audit(self, contract_path: str, mode: str):
        # Existing logic...

        # Optionally include NewTool in workflow
        if mode in ['full', 'custom'] and self.agents['new_tool'].is_available():
            self.agents['new_tool'].analyze(contract_path)
```

#### Step 5: Add Configuration

```yaml
# config/agent_config.yaml

agents:
  new_tool:
    enabled: true
    layer: 1  # static
    timeout: 120  # seconds
    options:
      check_all: true
      verbose: false
```

#### Step 6: Add Tests

```python
# tests/agents/test_new_tool_agent.py

import pytest
from src.agents.new_tool_agent import NewToolAgent

def test_new_tool_agent_initialization():
    """Test agent can be instantiated"""
    agent = NewToolAgent()
    assert agent.agent_name == "NewToolAgent"
    assert agent.agent_type == "static"

def test_new_tool_analysis(sample_contract):
    """Test analysis on sample contract"""
    agent = NewToolAgent()

    if not agent.is_available():
        pytest.skip("NewTool not installed")

    results = agent.analyze(sample_contract)
    assert results['status'] == 'success'
    assert 'findings_count' in results

def test_new_tool_mcp_publishing(mock_mcp_bus, sample_contract):
    """Test findings published to MCP bus"""
    agent = NewToolAgent()
    agent.analyze(sample_contract)

    # Verify message was published
    messages = mock_mcp_bus.get_history("new_tool_findings")
    assert len(messages) > 0
```

---

## ⚡ Performance & Scalability

### Performance Characteristics

| Analysis Mode | Tools Executed | Avg Time | Use Case |
|--------------|----------------|----------|----------|
| **Fast** | Static + AI | 2-5 min | CI/CD pipelines |
| **Critical** | Static + Dynamic + AI | 10-15 min | Pre-commit checks |
| **Full** | All 6 layers | 20-45 min | Pre-deployment audit |
| **Formal** | Full + Formal verification | 2-5 hours | Production contracts with $$$M TVL |

### Scalability Strategies

#### 1. Parallel Execution

```python
# Layers 1-4 execute concurrently
import concurrent.futures

def parallel_layer_execution(contract_path: str):
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(StaticAgent().analyze, contract_path): "static",
            executor.submit(DynamicAgent().analyze, contract_path): "dynamic",
            executor.submit(SymbolicAgent().analyze, contract_path): "symbolic",
            executor.submit(FormalAgent().analyze, contract_path): "formal"
        }

        results = {}
        for future in concurrent.futures.as_completed(futures):
            layer = futures[future]
            results[layer] = future.result()

        return results
```

#### 2. Caching Results

```python
# Cache tool outputs to avoid re-running on unchanged contracts
import hashlib
import pickle

class ResultCache:
    def __init__(self, cache_dir=".miesc_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)

    def get_cache_key(self, contract_path: str, tool: str) -> str:
        """Generate cache key from contract hash + tool version"""
        with open(contract_path, 'rb') as f:
            contract_hash = hashlib.sha256(f.read()).hexdigest()

        tool_version = get_tool_version(tool)
        return f"{tool}_{tool_version}_{contract_hash[:16]}"

    def get(self, contract_path: str, tool: str):
        """Retrieve cached results if available"""
        key = self.get_cache_key(contract_path, tool)
        cache_file = self.cache_dir / f"{key}.pkl"

        if cache_file.exists():
            with open(cache_file, 'rb') as f:
                return pickle.load(f)
        return None

    def set(self, contract_path: str, tool: str, results: dict):
        """Store results in cache"""
        key = self.get_cache_key(contract_path, tool)
        cache_file = self.cache_dir / f"{key}.pkl"

        with open(cache_file, 'wb') as f:
            pickle.dump(results, f)
```

#### 3. Selective Analysis

```python
# Focus on changed functions only
def incremental_analysis(contract_path: str, changed_functions: list):
    """
    Analyze only specific functions instead of entire contract

    Useful for:
    - CI/CD on PRs (analyze changed code only)
    - Iterative development
    """
    config = {
        "target_functions": changed_functions,
        "skip_unchanged": True
    }

    return xaudit.analyze(contract_path, **config)
```

### Resource Usage

| Tool | CPU | Memory | Disk I/O | Network |
|------|-----|--------|----------|---------|
| Slither | Low | 200MB | Low | None |
| Aderyn | Low | 100MB | Low | None |
| Mythril | High | 2GB | Medium | None |
| Echidna | Medium | 500MB | Low | None |
| GPT-4 (API) | Low | 50MB | None | High |
| Llama (local) | High | 8GB | None | None |

---

## 🔒 Security Considerations

### MIESC's Own Security

| Threat | Mitigation | Status |
|--------|-----------|--------|
| **Malicious contracts** | Sandboxed execution (Docker optional) | ✅ Implemented |
| **API key leakage** | `.env` files + `.gitignore` | ✅ Implemented |
| **Code injection** | Input validation on all file paths | ✅ Implemented |
| **DoS via infinite loops** | Timeouts on all tool executions | ✅ Implemented |
| **Privacy (sensitive contracts)** | Local LLM option (no API calls) | ✅ Implemented |
| **Supply chain attacks** | Locked dependency versions | ✅ Implemented |
| **Unauthorized access** | MCP authentication (planned) | 🔜 v2.3 |

### Privacy Modes

```python
# Privacy-preserving mode: No external API calls
config = {
    "use_gpt": False,        # Disable OpenAI
    "use_local_llm": True,   # Use Llama instead
    "cache_disabled": True,  # No disk persistence
    "network_blocked": True  # Block all outbound connections
}

audit_result = miesc.analyze(contract_path, **config)
```

---

## 🚀 Future Roadmap

### v2.3 (Q4 2024) - Soroban/Rust Initial Support

**Goal**: Add basic support for Stellar Soroban smart contracts

**New Tools**:
1. **cargo-audit** - Rust dependency vulnerability scanner
2. **cargo-clippy** - Rust linter with security checks
3. **cargo-geiger** - Unsafe Rust detection
4. **soroban-cli** - Official Soroban testing tools

**New Agent**: `SorobanAgent` (Layer 1 - Static)

**Supported**: Rust-based Soroban contracts on Stellar

**Limitations**: Initial version will have basic static analysis only

### v3.0 (Q2 2025) - Full Multi-Chain

**New Chains**:
- ✅ Ethereum/EVM (existing)
- 🆕 Stellar (Soroban) - Rust contracts
- 🆕 Solana (Anchor) - Rust contracts
- 🆕 StarkNet (Cairo)
- 🆕 Near Protocol (Rust/AssemblyScript)

**New Architecture**: Chain-agnostic abstraction layer

### v3.5 (Q3 2025) - Advanced Rust Ecosystem

**New Tools**:
- Prusti (Formal verification for Rust)
- MIRI (Rust interpreter for undefined behavior detection)
- Kani (Model checking for Rust)
- Rudra (Rust memory safety analyzer)

### v4.0 (Q4 2025) - AI Evolution

**Features**:
- Automated exploit generation
- AI-powered patch suggestions (not just detection)
- Multi-contract protocol analysis
- Gas optimization recommendations

---

**Last Updated**: October 2024
**Version**: 2.2.0
**Maintained by**: Fernando Boiero (fboiero@frvm.utn.edu.ar)
**License**: GPL-3.0
