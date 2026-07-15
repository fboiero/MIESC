# MIESC Architecture Patterns

This document describes the design patterns and architectural decisions used in MIESC (Multi-layer Intelligent Evaluation for Smart Contracts).

## Overview

MIESC follows a **layered architecture** with **50 tools across 35 analysis modules** organized across **9 defense layers**, implementing several well-known design patterns to achieve:

- **Extensibility**: New tools can be added without modifying core code
- **Loose Coupling**: No vendor lock-in (DPGA compliance)
- **Testability**: Each component can be tested in isolation
- **Maintainability**: Clear separation of concerns

---

## Core Design Patterns

### 1. Adapter Pattern

**Location**: `miesc/adapters/`

The Adapter pattern is the cornerstone of MIESC's tool integration strategy. Each security tool (Slither, Mythril, Echidna, etc.) has its own adapter that translates between the tool's native interface and MIESC's unified interface.

```
┌─────────────────────────────────────────────────────────────┐
│                      MIESC Core                              │
│                                                              │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐    │
│  │ToolAdapter   │   │ToolAdapter   │   │ToolAdapter   │    │
│  │(Protocol)    │   │(Protocol)    │   │(Protocol)    │    │
│  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘    │
│         │                  │                  │             │
└─────────┼──────────────────┼──────────────────┼─────────────┘
          │                  │                  │
    ┌─────▼─────┐      ┌─────▼─────┐      ┌─────▼─────┐
    │ Slither   │      │ Mythril   │      │ Echidna   │
    │ Adapter   │      │ Adapter   │      │ Adapter   │
    └─────┬─────┘      └─────┬─────┘      └─────┬─────┘
          │                  │                  │
    ┌─────▼─────┐      ┌─────▼─────┐      ┌─────▼─────┐
    │  Slither  │      │  Mythril  │      │  Echidna  │
    │  (Tool)   │      │  (Tool)   │      │  (Tool)   │
    └───────────┘      └───────────┘      └───────────┘
```

**Benefits**:
- Tools can be swapped without changing MIESC core
- New tools can be added by implementing `ToolAdapter`
- Each tool's quirks are encapsulated in its adapter

**Implementation**: `miesc/core/tool_protocol.py`

```python
class ToolAdapter(ABC):
    @abstractmethod
    def get_metadata(self) -> ToolMetadata: ...

    @abstractmethod
    def is_available(self) -> ToolStatus: ...

    @abstractmethod
    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]: ...

    @abstractmethod
    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]: ...
```

---

### 2. Registry Pattern

**Location**: `miesc/core/tool_protocol.py`

The Registry pattern provides a central catalog of all available tools, enabling dynamic tool discovery and selection.

```
┌─────────────────────────────────────────┐
│            ToolRegistry                  │
│  ┌─────────────────────────────────────┐│
│  │  _tools: Dict[str, ToolAdapter]     ││
│  ├─────────────────────────────────────┤│
│  │  + register(adapter)                ││
│  │  + get_tool(name) -> ToolAdapter    ││
│  │  + get_available_tools() -> List    ││
│  │  + get_tools_by_category() -> List  ││
│  └─────────────────────────────────────┘│
└─────────────────────────────────────────┘
```

**Benefits**:
- Centralized tool management
- Runtime tool discovery
- Category-based tool selection

**Usage**:
```python
from miesc.core.tool_protocol import get_tool_registry

registry = get_tool_registry()
static_tools = registry.get_tools_by_category(ToolCategory.STATIC_ANALYSIS)
```

---

### 3. Protocol Pattern (Abstract Base Class)

**Location**: `miesc/core/tool_protocol.py`

Python's Protocol/ABC pattern defines the contract that all adapters must follow, ensuring type safety and consistent interfaces.

```python
@dataclass
class ToolMetadata:
    name: str
    version: str
    category: ToolCategory
    is_optional: bool = True  # DPGA compliance: no vendor lock-in
    ...

class ToolAdapter(ABC):
    """All adapters MUST implement these methods"""
    @abstractmethod
    def get_metadata(self) -> ToolMetadata: ...
```

**Benefits**:
- Compile-time interface verification
- IDE autocompletion support
- Self-documenting code

---

### 4. Strategy Pattern

**Location**: `miesc/core/ml_orchestrator.py`, analysis profiles

The Strategy pattern allows MIESC to switch between different analysis strategies (quick, standard, thorough) at runtime.

```
┌─────────────────┐
│  AnalysisProfile │
│  (Strategy)      │
├─────────────────┤
│  - quick         │ → Fast analysis, fewer tools
│  - standard      │ → Balanced coverage
│  - thorough      │ → Maximum coverage, all layers
│  - paranoid      │ → Deep symbolic + formal
└─────────────────┘
```

**Configuration**: `miesc/data/config/miesc.yaml` (packaged)

```yaml
profiles:
  quick:
    tools: [slither, solhint]
    timeout: 60
  thorough:
    tools: [slither, mythril, echidna, certora]
    timeout: 600
```

---

### 5. Observer Pattern (Event-Driven)

**Location**: `miesc/core/ml_orchestrator.py`

The Observer pattern enables real-time progress reporting and event handling during analysis.

```
┌──────────────────┐     notify()     ┌─────────────────┐
│  MLOrchestrator  │ ───────────────► │  Progress UI    │
│  (Subject)       │                  │  (Observer)     │
└──────────────────┘                  └─────────────────┘
                    ───────────────► ┌─────────────────┐
                                     │  Logger         │
                                     │  (Observer)     │
                                     └─────────────────┘
```

**Benefits**:
- Decoupled UI from core logic
- Multiple observers (CLI, logs, metrics)
- Real-time progress updates

---

### 6. Factory Pattern

**Location**: `miesc/adapters/__init__.py`

The Factory pattern creates adapter instances based on configuration, abstracting instantiation details.

```python
def register_all_adapters():
    adapters_to_register = [
        ("slither", SlitherAdapter),
        ("mythril", MythrilAdapter),
        ...
    ]
    for name, adapter_class in adapters_to_register:
        adapter = adapter_class()  # Factory creates instance
        registry.register(adapter)
```

---

### 7. Singleton Pattern

**Location**: `miesc/core/tool_protocol.py`

The Singleton pattern ensures a single ToolRegistry instance throughout the application.

```python
# Module-level singleton
_registry = ToolRegistry()

def get_tool_registry() -> ToolRegistry:
    """Get singleton instance of tool registry"""
    return _registry
```

---

## Layer Architecture

MIESC implements a **9-layer defense-in-depth** architecture:

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 9: Advanced AI Ensemble                                │
│   LLMBugScanner, AuditConsensus, ExploitSynthesizer          │
├─────────────────────────────────────────────────────────────┤
│ Layer 8: Cross-Chain & ZK Security                           │
│   CrossChain, ZKCircuit, BridgeMonitor, L2Validator          │
├─────────────────────────────────────────────────────────────┤
│ Layer 7: Specialized Analysis                                │
│   ThreatModel, GasAnalyzer, MEVDetector, CloneDetector       │
├─────────────────────────────────────────────────────────────┤
│ Layer 6: ML Detection                                        │
│   DAGNN, SmartBugsML, SmartBugsDetector, SmartGuard, Peculiar│
├─────────────────────────────────────────────────────────────┤
│ Layer 5: AI Analysis                                         │
│   SmartLLM, GPTScan, LLMSmartAudit, GPTLens, LlamaAudit      │
├─────────────────────────────────────────────────────────────┤
│ Layer 4: Formal Verification                                │
│   Certora, SMTChecker, Wake                                 │
├─────────────────────────────────────────────────────────────┤
│ Layer 3: Symbolic Execution                                 │
│   Mythril, Manticore, Halmos                                │
├─────────────────────────────────────────────────────────────┤
│ Layer 2: Dynamic Testing                                    │
│   Echidna, Medusa, Foundry, DogeFuzz                        │
├─────────────────────────────────────────────────────────────┤
│ Layer 1: Static Analysis                                    │
│   Slither, Aderyn, Solhint                                  │
└─────────────────────────────────────────────────────────────┘
```

Each layer provides different analysis capabilities:

| Layer | Category | Tools | Focus |
|-------|----------|-------|-------|
| 1 | Static | 3 | Code patterns, AST analysis |
| 2 | Dynamic | 4 | Fuzzing, runtime behavior |
| 3 | Symbolic | 3 | Path exploration, constraints |
| 4 | Formal | 3 | Mathematical proofs |
| 5 | AI Analysis | 6 | LLM-powered detection |
| 6 | ML Detection | 5 | ML-based classification |
| 7 | Specialized Analysis | 7 | Domain-specific risks (gas, MEV, DeFi, upgradability) |
| 8 | Cross-Chain & ZK Security | 5 | Bridge & zero-knowledge circuit analysis |
| 9 | Advanced AI Ensemble | 5 | Multi-LLM consensus |

> Layers 8–9 (Cross-Chain & ZK Security, Advanced AI Ensemble) are experimental modules on the multi-chain roadmap; the EVM core is Layers 1–7.

---

## Data Flow

```
Contract.sol
     │
     ▼
┌─────────────────┐
│   CLI Entry     │  miesc/cli/main.py
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  MLOrchestrator │  Coordinates analysis
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  ToolRegistry   │  Selects tools by profile
└────────┬────────┘
         │
    ┌────┴────┬────────┬────────┐
    ▼         ▼        ▼        ▼
┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐
│Adapter│ │Adapter│ │Adapter│ │Adapter│
│   1   │ │   2   │ │   3   │ │  ...  │
└───┬───┘ └───┬───┘ └───┬───┘ └───┬───┘
    │         │        │        │
    └────┬────┴────────┴────────┘
         │
         ▼
┌─────────────────┐
│Finding Normalizer│  Unified format
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  ML Aggregator  │  False positive detection
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Report Generator│  PDF/HTML/MD/JSON
└─────────────────┘
```

---

## DPGA Compliance

MIESC is designed to meet Digital Public Goods Alliance requirements:

1. **No Vendor Lock-in**: All tools are marked `is_optional=True`
2. **Open Standards**: Uses standard formats (JSON, SWC, CWE)
3. **Extensible**: New tools can be added without core changes
4. **Transparent**: All analysis is auditable

```python
# Enforced in registration
non_optional = [a for a in registered if not a.get("optional", True)]
if non_optional:
    logger.warning(f"DPGA WARNING: Non-optional tools detected")
```

---

## Adding New Tools

To add a new security tool to MIESC:

1. **Create Adapter** in `miesc/adapters/`:

```python
# miesc/adapters/mytool_adapter.py
from miesc.core.tool_protocol import ToolAdapter, ToolMetadata, ToolStatus

class MyToolAdapter(ToolAdapter):
    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="mytool",
            version="1.0.0",
            category=ToolCategory.STATIC_ANALYSIS,
            author="Your Name",
            license="MIT",
            is_optional=True,  # Required for DPGA
            ...
        )

    def is_available(self) -> ToolStatus:
        # Check if tool is installed
        try:
            subprocess.run(["mytool", "--version"], check=True)
            return ToolStatus.AVAILABLE
        except:
            return ToolStatus.NOT_INSTALLED

    def analyze(self, contract_path: str, **kwargs) -> Dict:
        # Run tool and return results
        ...

    def normalize_findings(self, raw_output) -> List[Dict]:
        # Convert to MIESC format
        ...
```

2. **Register** in `miesc/adapters/__init__.py`:

```python
from miesc.adapters.mytool_adapter import MyToolAdapter

adapters_to_register = [
    ...
    ("mytool", MyToolAdapter),
]
```

3. **Test**:

```bash
python -m pytest tests/adapters/test_mytool_adapter.py
```

---

## References

- [Adapter Pattern - Design Patterns](https://refactoring.guru/design-patterns/adapter)
- [Registry Pattern](https://martinfowler.com/eaaCatalog/registry.html)
- [Python ABC Documentation](https://docs.python.org/3/library/abc.html)
- [DPGA Standard](https://digitalpublicgoods.net/standard/)

---

*Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>*
*Last Updated: January 2026*
