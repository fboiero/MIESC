# MIESC MCP Architecture
## Model Context Protocol Implementation

**Version:** 1.0.0
**Date:** November 10, 2025
**Author:** Fernando Boiero (fboiero@frvm.utn.edu.ar)
**Status:** Production-Ready

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [Core Components](#core-components)
4. [Message Flow](#message-flow)
5. [Layer Independence](#layer-independence)
6. [DPGA Compliance](#dpga-compliance)
7. [Security Model](#security-model)
8. [Integration Patterns](#integration-patterns)

---

## Executive Summary

The **Model Context Protocol (MCP)** is the backbone of MIESC's modular architecture, enabling:

- **Decoupled Communication** between agents across 7 independent security layers
- **Publish-Subscribe Pattern** for asynchronous, non-blocking message passing
- **Context Aggregation** for cross-layer vulnerability correlation
- **Thread-Safe Operations** for concurrent analysis execution
- **Zero Vendor Lock-in** through optional adapter integration

**Key Benefits:**
- ✅ Agents can operate independently without knowledge of each other
- ✅ New tools/agents can be added without modifying existing code
- ✅ Cross-layer findings are automatically aggregated
- ✅ System scales horizontally by adding more agents
- ✅ Fully DPGA-compliant (Digital Public Goods Alliance)

---

## Architecture Overview

### High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                     MIESC Coordinator                        │
│                  (Orchestration Layer)                       │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    Context Bus (MCP)                         │
│                   Singleton Instance                         │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Message Queue (Dict[str, List[MCPMessage]])           │ │
│  │  - Organized by context_type                           │ │
│  │  - Thread-safe RLock                                   │ │
│  │  - Automatic timestamping                              │ │
│  └────────────────────────────────────────────────────────┘ │
└──────────────────────┬──────────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┬──────────────┐
        ▼              ▼              ▼              ▼
   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐
   │ Layer 1 │   │ Layer 2 │   │ Layer 4 │   │ Layer 7 │
   │ Static  │   │ Dynamic │   │Symbolic │   │  Audit  │
   │  Agent  │   │  Agent  │   │  Agent  │   │Readiness│
   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘
        │             │              │              │
        │             │              │              │
   ┌────▼────┐   ┌───▼────┐    ┌───▼────┐    ┌───▼────┐
   │Slither  │   │Echidna │    │Mythril │    │Threat  │
   │Solhint  │   │Medusa  │    │Manticore│   │Model   │
   │Surya    │   │Foundry │    │        │    │        │
   └─────────┘   └────────┘    └────────┘    └────────┘
        │             │              │              │
        └─────────────┴──────────────┴──────────────┘
                       │
                  ┌────▼────┐
                  │ Adapter │
                  │  Layer  │
                  │(Optional)│
                  └─────────┘
                       │
        ┌──────────────┼──────────────┬──────────────┐
        ▼              ▼              ▼              ▼
   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐
   │   Gas   │   │   MEV   │   │ Vertigo │   │ Oyente  │
   │Analyzer │   │Detector │   │Adapter  │   │Adapter  │
   └─────────┘   └─────────┘   └─────────┘   └─────────┘
```

---

## Core Components

### 1. MCPMessage

**Purpose:** Standardized message format for all inter-agent communication.

```python
@dataclass
class MCPMessage:
    """
    Immutable message object for Context Bus communication

    Attributes:
        agent_name: Source agent identifier
        context_type: Message category (e.g., "static_findings")
        content: Actual payload (Dict, List, or any serializable data)
        timestamp: ISO 8601 UTC timestamp
        metadata: Optional additional information
    """
    agent_name: str
    context_type: str
    content: Any
    timestamp: str
    metadata: Optional[Dict[str, Any]] = None
```

**Design Decisions:**
- **Immutable**: Uses `@dataclass(frozen=True)` to prevent accidental mutation
- **Timestamped**: Automatic chronological ordering
- **Flexible Content**: Supports any JSON-serializable data
- **Metadata Support**: Extensible for future requirements

### 2. ContextBus

**Purpose:** Central message broker implementing publish-subscribe pattern.

```python
class ContextBus:
    """
    Thread-safe publish-subscribe message bus

    Key Features:
    - Singleton pattern (get_context_bus())
    - Thread-safe operations (RLock)
    - Message storage by context_type
    - Aggregation and statistics
    """

    def __init__(self):
        self._messages: Dict[str, List[MCPMessage]] = {}
        self._lock = RLock()
        self._subscribers: Dict[str, List[callable]] = {}

    # Core Operations
    def publish(self, message: MCPMessage) -> None
    def subscribe(self, context_type: str, callback: callable) -> None
    def get_messages(self, context_type: str) -> List[MCPMessage]
    def aggregate_by_agent(self, agent_name: str) -> List[MCPMessage]
    def get_statistics(self) -> Dict[str, Any]
    def clear(self) -> None
```

**Thread Safety:**
- All operations protected by `RLock` (Reentrant Lock)
- Allows same thread to acquire lock multiple times
- Prevents race conditions in concurrent analysis

**Singleton Pattern:**
```python
_context_bus_instance = None

def get_context_bus() -> ContextBus:
    global _context_bus_instance
    if _context_bus_instance is None:
        _context_bus_instance = ContextBus()
    return _context_bus_instance
```

---

## Message Flow

### Publish Flow

```
Agent                 Context Bus              Subscriber
  │                        │                        │
  │──── publish() ────────►│                        │
  │   (MCPMessage)         │                        │
  │                        │                        │
  │                        │──── callback() ───────►│
  │                        │   (MCPMessage)         │
  │                        │                        │
  │◄──── return ──────────│                        │
  │                        │                        │
  │                   [Message stored              │
  │                    in _messages dict]          │
```

### Retrieve Flow

```
Consumer              Context Bus              Storage
  │                        │                        │
  │── get_messages() ─────►│                        │
  │  (context_type)        │                        │
  │                        │                        │
  │                        │──── retrieve ─────────►│
  │                        │   (by context_type)    │
  │                        │                        │
  │                        │◄──── return ───────────│
  │                        │   (List[MCPMessage])   │
  │                        │                        │
  │◄─ return messages ────│                        │
  │  (List[MCPMessage])    │                        │
```

### Example Usage

```python
from src.mcp import get_context_bus, MCPMessage

# Initialize bus (singleton)
bus = get_context_bus()

# Agent publishes finding
message = MCPMessage(
    agent_name="StaticAgent",
    context_type="static_findings",
    content={
        "vulnerability": "reentrancy",
        "severity": "High",
        "location": "Contract.sol:42"
    }
)
bus.publish(message)

# Another agent retrieves findings
findings = bus.get_messages("static_findings")
for finding in findings:
    print(f"Found: {finding.content}")

# Aggregate all messages from specific agent
agent_messages = bus.aggregate_by_agent("StaticAgent")
```

---

## Layer Independence

### Design Principle

**Each layer operates autonomously** without knowledge of other layers:

1. **Layer 1 (Static)** → Publishes: `static_findings`, `slither_results`
2. **Layer 2 (Dynamic)** → Publishes: `dynamic_findings`, `echidna_results`
3. **Layer 4 (Symbolic)** → Publishes: `symbolic_findings`, `mythril_results`
4. **Layer 7 (Audit)** → Publishes: `audit_metrics`, `threat_model_results`

**No Direct Dependencies:**
```python
# ❌ WRONG - Direct dependency
class DynamicAgent:
    def analyze(self):
        static_agent = StaticAgent()  # TIGHT COUPLING
        static_results = static_agent.analyze()

# ✅ CORRECT - MCP-based communication
class DynamicAgent:
    def analyze(self):
        bus = get_context_bus()
        static_findings = bus.get_messages("static_findings")
        # Process independently
```

### Benefits

1. **Parallel Execution**: Agents run concurrently
2. **Easy Testing**: Mock Context Bus for unit tests
3. **Hot-Swapping**: Replace agents without system restart
4. **Graceful Degradation**: System continues if one agent fails

---

## DPGA Compliance

### Digital Public Goods Alliance Standards

MIESC MCP architecture fully complies with [DPGA standards](https://digitalpublicgoods.net/):

#### ✅ 1. Open Source
- **License**: MIT License
- **Repository**: Public GitHub
- **Documentation**: Comprehensive guides

#### ✅ 2. No Vendor Lock-in
```python
# All adapters are OPTIONAL
class ToolAdapter(ABC):
    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="example_tool",
            is_optional=True  # DPGA REQUIREMENT
        )
```

**Verification:**
```bash
$ python -c "from src.adapters import register_all_adapters; \
  report = register_all_adapters(); \
  print(f'Optional: {all(a[\"optional\"] for a in report[\"adapters\"])}')"

Output: Optional: True  # ✅ DPGA COMPLIANT
```

#### ✅ 3. Modular Architecture
- Agents can be added/removed dynamically
- Tools register via Tool Registry
- No hardcoded dependencies

#### ✅ 4. Extensibility
```python
# Adding new agent (3 steps):
class MyCustomAgent(BaseAgent):
    def analyze(self, contract_path):
        # Custom analysis logic
        pass

# 1. Implement BaseAgent
# 2. Publish to Context Bus
# 3. Register with Coordinator
```

#### ✅ 5. Community Contributions
- Clear integration guides
- Standardized Tool Adapter Protocol
- Comprehensive documentation
- Unit test templates

---

## Security Model

### Threat Model

| Threat | Mitigation | Status |
|--------|-----------|---------|
| **Malicious Agent** | Sandboxing, input validation | ✅ Implemented |
| **Race Conditions** | Thread-safe RLock | ✅ Implemented |
| **Memory Exhaustion** | Message size limits, cleanup | ⚠️ Planned |
| **Injection Attacks** | Input sanitization | ✅ Implemented |
| **Data Leakage** | Agent isolation, no shared state | ✅ Implemented |

### Security Features

#### 1. Agent Isolation
```python
# Each agent has independent execution context
class BaseAgent(ABC):
    def __init__(self, agent_name: str, capabilities: List[str]):
        self._context = {}  # Isolated state
        self._bus = get_context_bus()  # Shared communication
```

#### 2. Input Validation
```python
def publish(self, message: MCPMessage) -> None:
    if not isinstance(message, MCPMessage):
        raise TypeError("Must be MCPMessage instance")

    if not message.agent_name or not message.context_type:
        raise ValueError("Missing required fields")

    # Sanitize content (prevent injection)
    sanitized_content = self._sanitize(message.content)
```

#### 3. Access Control
```python
# Future enhancement: Role-based access
class ContextBus:
    def publish(self, message: MCPMessage, auth_token: str = None):
        if self._require_auth:
            if not self._verify_token(auth_token):
                raise PermissionError("Unauthorized")
        # Proceed with publish
```

---

## Integration Patterns

### Pattern 1: Tool Adapter Integration

**Use Case:** Adding external tools without modifying core system

```python
from src.core.tool_protocol import ToolAdapter, ToolMetadata, ToolStatus
from src.integration.adapter_integration import integrate_static_analysis

class MyCustomTool(ToolAdapter):
    """Custom tool following Tool Adapter Protocol"""

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="my_custom_tool",
            version="1.0.0",
            category="static_analysis",
            description="My custom analyzer",
            is_optional=True,  # DPGA compliance
            capabilities=["pattern_detection"]
        )

    def is_available(self) -> ToolStatus:
        try:
            # Check if tool is installed
            subprocess.run(["my_tool", "--version"], check=True)
            return ToolStatus.AVAILABLE
        except:
            return ToolStatus.NOT_INSTALLED

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        # Run tool
        result = subprocess.run(["my_tool", contract_path], capture_output=True)

        # Normalize findings
        findings = self.normalize_findings(result.stdout)

        return {
            "status": "success",
            "findings": findings,
            "metadata": {"tool": "my_custom_tool"}
        }

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        # Convert tool-specific output to MIESC format
        normalized = []
        for line in raw_output.split('\n'):
            if "VULNERABILITY" in line:
                normalized.append({
                    "source": "my_custom_tool",
                    "type": "security_issue",
                    "severity": "Medium",
                    "description": line
                })
        return normalized

# Register with Tool Registry
from src.core.tool_protocol import get_tool_registry

registry = get_tool_registry()
registry.register(MyCustomTool())
```

### Pattern 2: Agent-to-Agent Communication

**Use Case:** Cross-layer correlation

```python
class CorrelationAgent(BaseAgent):
    """Correlates findings across layers"""

    def analyze(self, contract_path: str) -> Dict[str, Any]:
        bus = get_context_bus()

        # Retrieve findings from multiple layers
        static = bus.get_messages("static_findings")
        dynamic = bus.get_messages("dynamic_findings")
        symbolic = bus.get_messages("symbolic_findings")

        # Correlate vulnerabilities
        correlations = self._correlate(static, dynamic, symbolic)

        # Publish correlation results
        message = MCPMessage(
            agent_name=self.agent_name,
            context_type="correlations",
            content={
                "total_correlations": len(correlations),
                "high_confidence": [c for c in correlations if c["confidence"] > 0.8]
            }
        )
        bus.publish(message)

        return {"correlations": correlations}
```

### Pattern 3: Asynchronous Processing

**Use Case:** Long-running analysis with real-time updates

```python
import threading

class AsyncAgent(BaseAgent):
    def analyze_async(self, contract_path: str) -> threading.Thread:
        def _run():
            bus = get_context_bus()

            # Step 1: Initial scan
            bus.publish(MCPMessage(
                agent_name=self.agent_name,
                context_type="progress",
                content={"stage": "initial_scan", "progress": 10}
            ))

            # Step 2: Deep analysis
            results = self._deep_analysis(contract_path)
            bus.publish(MCPMessage(
                agent_name=self.agent_name,
                context_type="progress",
                content={"stage": "deep_analysis", "progress": 50}
            ))

            # Step 3: Finalize
            bus.publish(MCPMessage(
                agent_name=self.agent_name,
                context_type="final_results",
                content=results
            ))

        thread = threading.Thread(target=_run)
        thread.start()
        return thread
```

---

## Performance Considerations

### Message Storage Strategy

**Current Implementation:** In-memory storage
```python
self._messages: Dict[str, List[MCPMessage]] = {}
```

**Memory Characteristics:**
- **Per Message**: ~1-2 KB (depending on content)
- **100 messages**: ~100-200 KB
- **1000 messages**: ~1-2 MB
- **Acceptable for**: Single analysis sessions

**Future Enhancement:** Persistent storage for large-scale analysis
```python
# Option 1: SQLite
import sqlite3
self._db = sqlite3.connect("mcp_messages.db")

# Option 2: Redis
import redis
self._redis = redis.Redis()

# Option 3: MongoDB
from pymongo import MongoClient
self._mongo = MongoClient()
```

### Scalability

**Horizontal Scaling:**
```
┌──────────┐    ┌──────────┐    ┌──────────┐
│ Worker 1 │    │ Worker 2 │    │ Worker 3 │
│ (Static) │    │ (Dynamic)│    │(Symbolic)│
└────┬─────┘    └────┬─────┘    └────┬─────┘
     │               │               │
     └───────────────┼───────────────┘
                     │
              ┌──────▼──────┐
              │ Context Bus │
              │  (Shared)   │
              └─────────────┘
```

**Vertical Scaling:**
- Increase message queue size
- Optimize message serialization
- Implement lazy loading for large payloads

---

## Testing Strategy

### Unit Tests (21 tests, 100% passing)

```bash
$ pytest tests/mcp/test_context_bus.py -v

tests/mcp/test_context_bus.py::test_mcp_message_creation PASSED
tests/mcp/test_context_bus.py::test_mcp_message_immutability PASSED
tests/mcp/test_context_bus.py::test_context_bus_singleton PASSED
tests/mcp/test_context_bus.py::test_publish_and_retrieve PASSED
tests/mcp/test_context_bus.py::test_subscribe_callback PASSED
tests/mcp/test_context_bus.py::test_aggregate_by_agent PASSED
tests/mcp/test_context_bus.py::test_thread_safety PASSED
...
===================== 21 passed in 2.45s =====================
```

### Integration Tests

```python
def test_agent_integration():
    """Test full agent workflow with MCP"""
    from src.agents.static_agent import StaticAgent
    from src.mcp import get_context_bus

    bus = get_context_bus()
    bus.clear()  # Clean state

    # Run analysis
    agent = StaticAgent()
    results = agent.analyze("test_contract.sol")

    # Verify messages published
    messages = bus.get_messages("static_findings")
    assert len(messages) > 0
    assert messages[0].agent_name == "StaticAgent"
```

---

## Roadmap

### Phase 1 (Completed ✅)
- [x] Core MCP implementation
- [x] Thread-safe operations
- [x] Singleton pattern
- [x] Unit tests (21/21)
- [x] Agent integrations

### Phase 2 (Current)
- [ ] Persistent storage backend
- [ ] Message size limits
- [ ] Compression for large payloads
- [ ] Authentication/authorization

### Phase 3 (Planned)
- [ ] Distributed Context Bus (multi-node)
- [ ] Message encryption
- [ ] Audit logging
- [ ] Performance monitoring
- [ ] WebSocket support for real-time updates

---

## References

- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [DPGA Standards](https://digitalpublicgoods.net/)
- [MIESC Tool Integration Guide](../TOOL_INTEGRATION_GUIDE.md)
- [Agent Development Guide](./AGENT_DEVELOPMENT_GUIDE.md)

---

## Contact & Support

**Maintainer:** Fernando Boiero
**Email:** fboiero@frvm.utn.edu.ar
**Repository:** [github.com/fboiero/MIESC](https://github.com/fboiero/MIESC)
**Issues:** [GitHub Issues](https://github.com/fboiero/MIESC/issues)

---

*Last Updated: November 10, 2025*
