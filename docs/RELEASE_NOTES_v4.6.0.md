# MIESC v4.6.0 Release Notes

**Release Date:** January 26, 2026
**Tag:** [v4.6.0](https://github.com/fboiero/MIESC/releases/tag/v4.6.0)

---

## Overview

MIESC v4.6.0 is a major release focused on **improving EVM detection quality** through advanced static analysis techniques. This release introduces call graph analysis, taint tracking, Slither IR parsing, and semantic vulnerability detectors.

**Key Achievement:** Recall increased from 64% to **85.7%**, meeting the 85%+ target.

---

## Highlights

- **Call Graph Analysis**: Cross-function vulnerability detection
- **Taint Analysis**: Track user-controlled data to dangerous sinks
- **Slither IR Parser**: Leverage Slither's intermediate representation
- **Semantic Detectors**: Access Control and DoS analysis
- **Improved FP Filtering**: Per-detector FP rates and semantic context
- **SolidiFI Benchmark**: 350-contract evaluation framework

---

## New Modules

### Call Graph (`src/ml/call_graph.py`)

Constructs and analyzes function call graphs for smart contracts.

```python
from src.ml.call_graph import CallGraphBuilder, build_call_graph

# Build call graph from source
builder = CallGraphBuilder()
graph = builder.build_from_source(solidity_code)

# Find paths to dangerous sinks
paths = graph.paths_to_sink("selfdestruct")

# Analyze reentrancy risk
risky_paths = graph.get_reentrancy_risk_paths()
```

**Features:**
- Function-level call graph construction
- Entry point identification (external/public functions)
- Path finding to dangerous sinks (selfdestruct, delegatecall)
- External call chain analysis
- State variable read/write tracking

**Classes:**
- `FunctionNode` - Represents a function in the call graph
- `CallEdge` - Represents a call relationship
- `CallPath` - Represents a path through the graph
- `CallGraph` - The complete call graph with analysis methods
- `CallGraphBuilder` - Builds graphs from Solidity source

---

### Taint Analysis (`src/ml/taint_analysis.py`)

Tracks flow of user-controlled data to dangerous sinks.

```python
from src.ml.taint_analysis import TaintAnalyzer, analyze_taint

# Analyze taint flows
analyzer = TaintAnalyzer()
tainted_paths = analyzer.analyze(solidity_code)

# Find tainted sinks
for path in tainted_paths:
    print(f"Source: {path.source} -> Sink: {path.sink}")
```

**Taint Sources:**
- `msg.sender`, `msg.value`, `msg.data`
- `tx.origin`, `block.timestamp`
- Function parameters
- External call return values

**Taint Sinks:**
- `call`, `delegatecall`, `staticcall`
- `transfer`, `send`
- `selfdestruct`
- Storage writes (`sstore`)

**Sanitizers:**
- `require`, `assert` statements
- Conditional checks (`if`)
- SafeMath operations

---

### Slither IR Parser (`src/ml/slither_ir_parser.py`)

Parses Slither's intermediate representation for detailed analysis.

```python
from src.ml.slither_ir_parser import SlitherIRParser, parse_slither_ir

# Parse Slither output
parser = SlitherIRParser()
functions = parser.parse_slither_output(slither_json)

# Extract state transitions
transitions = parser.get_function_state_transitions("transfer")

# Get external calls
calls = parser.get_external_calls("withdraw")
```

**IR Opcodes Supported:**
- Assignments, Binary operations
- Internal/External calls
- Storage operations (SLOAD, SSTORE)
- Control flow (IF, RETURN, REVERT)

---

### Semantic Detectors

#### Access Control Semantic Detector

Detects access control vulnerabilities through semantic analysis.

```python
from src.ml.classic_patterns import AccessControlSemanticDetector

detector = AccessControlSemanticDetector()
findings = detector.analyze(solidity_code)
```

**Detects:**
- Unprotected privileged functions (mint, burn, pause, upgrade)
- Uninitialized owner variables
- Missing access control modifiers
- Delegatecall without access control

#### DoS Cross-Function Detector

Analyzes cross-function patterns for DoS vulnerabilities.

```python
from src.ml.classic_patterns import DoSCrossFunctionDetector

detector = DoSCrossFunctionDetector()
findings = detector.analyze(solidity_code)
```

**Detects:**
- Unbounded loops over user-growing arrays
- Push payment patterns in loops
- External calls in loops
- Gas-dependent operations

---

## Enhanced False Positive Filtering

### Per-Detector FP Rates

55 Slither detectors now have empirically-derived FP rates:

```python
from src.ml.false_positive_filter import SLITHER_DETECTOR_FP_RATES

# High FP rate detectors (likely benign)
SLITHER_DETECTOR_FP_RATES["reentrancy-benign"]  # 0.85
SLITHER_DETECTOR_FP_RATES["naming-convention"]  # 0.95

# Low FP rate detectors (likely real vulnerabilities)
SLITHER_DETECTOR_FP_RATES["suicidal"]           # 0.10
SLITHER_DETECTOR_FP_RATES["arbitrary-send-eth"] # 0.15
```

### Semantic Context Analyzer

Analyzes code context to adjust confidence:

```python
from src.ml.false_positive_filter import SemanticContextAnalyzer

analyzer = SemanticContextAnalyzer()
adjustment = analyzer.analyze_finding_context(finding, source_code)
```

**Context Checks:**
- ReentrancyGuard detection (-40% confidence)
- CEI pattern detection (-30% confidence)
- Solidity 0.8+ for arithmetic (-50% confidence)
- Modifier coverage analysis

---

## Cross-Validation Enforcement

Critical vulnerability types now require multi-tool validation:

```python
from src.ml.correlation_engine import CROSS_VALIDATION_REQUIRED

# These patterns require 2+ tools for high confidence
CROSS_VALIDATION_REQUIRED = {
    "reentrancy", "reentrancy-eth",
    "arbitrary-send", "controlled-delegatecall",
    "suicidal", "unprotected-upgrade"
}

# Single-tool findings capped at 60% confidence
SINGLE_TOOL_MAX_CONFIDENCE = 0.60
```

---

## New Vulnerability Patterns

### Integer Overflow/Underflow (Local Anti-patterns)

```python
ClassicVulnType.INTEGER_OVERFLOW   # Detects +=, *=, ++
ClassicVulnType.INTEGER_UNDERFLOW  # Detects -=, --
```

Anti-patterns now checked per-function context, not globally. Contracts with SafeMath library but vulnerable functions are now detected.

### Unchecked Send (Including .transfer())

```python
ClassicVulnType.UNCHECKED_SEND  # Detects .send() and .transfer()
```

Patterns cover both `.send()` (returns bool) and `.transfer()` (2300 gas limit issues).

---

## Benchmark Results

### SolidiFI Benchmark (70 contracts)

| Metric | Before | After | Target |
|--------|--------|-------|--------|
| **Recall** | 64.2% | **85.7%** | 85%+ |
| Precision | 24.9% | 26.7% | 60%+ |
| F1 Score | 36.1% | 40.7% | 70%+ |

### Per-Category Recall

| Category | Before | After |
|----------|--------|-------|
| Overflow-Underflow | 16.2% | **91.5%** |
| Re-entrancy | 80.6% | **84.0%** |
| Unchecked-Send | 0.0% | **79.1%** |
| tx.origin | 97.5% | **97.7%** |
| Timestamp | 92.9% | **93.0%** |
| Unhandled-Exceptions | 88.3% | **89.1%** |

---

## API Changes

### New Exports in `src/ml/__init__.py`

```python
# Call Graph
from src.ml import (
    CallGraph, CallGraphBuilder, FunctionNode,
    CallEdge, CallPath, build_call_graph,
    analyze_reentrancy_risk, Visibility, Mutability
)

# Taint Analysis
from src.ml import (
    TaintAnalyzer, TaintSource, TaintSink,
    TaintedVariable, TaintedPath, SanitizerType,
    analyze_taint, find_tainted_sinks
)

# Slither IR
from src.ml import (
    SlitherIRParser, IROpcode, IRInstruction,
    FunctionIR, StateTransition, IRCall,
    parse_slither_ir, get_function_state_transitions
)

# Semantic Detectors
from src.ml import (
    AccessControlSemanticDetector, AccessControlFinding,
    DoSCrossFunctionDetector, DoSFinding,
    detect_semantic_vulnerabilities
)

# Enhanced FP Filter
from src.ml import (
    SLITHER_DETECTOR_FP_RATES, SemanticContextAnalyzer
)
```

---

## Configuration Updates

### miesc.yaml

```yaml
version: "4.6.0"

ml:
  cross_validation_v2:
    enabled: true
    require_multi_tool:
      - reentrancy
      - arbitrary-send
      - controlled-delegatecall
    single_tool_max_confidence: 0.6
```

---

## Upgrade Guide

### From v4.5.x

1. Update package:
   ```bash
   pip install --upgrade miesc
   ```

2. No breaking API changes - existing code works as-is

3. New features are opt-in through new module imports

### Testing

```bash
# Run v4.6.0 test suite
pytest tests/test_v460_modules.py -v

# Run benchmark
python benchmarks/solidifi_benchmark.py --quick
```

---

## Known Limitations

1. **Precision vs Recall tradeoff**: High recall (85.7%) comes with lower precision (26.7%)
2. **Static analysis only**: No symbolic execution or fuzzing
3. **Pattern-based detection**: May miss novel vulnerability variants
4. **SolidiFI dataset bias**: Benchmark uses injected vulnerabilities

---

## Future Work (v4.7.0)

1. **Symbolic execution integration** - Mythril/Manticore for validation
2. **ML-based FP reduction** - Train classifier on confirmed vulnerabilities
3. **Real Slither integration** - Execute Slither for true cross-validation
4. **Formal verification hooks** - Certora/Echidna integration

---

## Contributors

- Fernando Boiero ([@fboiero](https://github.com/fboiero))

---

## License

MIESC is released under the AGPL-3.0 License.
