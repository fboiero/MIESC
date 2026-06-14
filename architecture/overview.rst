Architecture Overview
=====================

MIESC implements a multi-layer defense-in-depth architecture for smart contract security analysis.

.. contents:: Table of Contents
   :local:
   :depth: 2

System Architecture
-------------------

::

    ┌─────────────────────────────────────────────────────────────┐
    │                      MIESC CLI / API                        │
    └───────────────────────────┬─────────────────────────────────┘
                                │
    ┌───────────────────────────▼─────────────────────────────────┐
    │                    Orchestrator Layer                        │
    │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
    │  │ ML Pipeline │  │ LLM Router  │  │ Finding Correlator  │ │
    │  └─────────────┘  └─────────────┘  └─────────────────────┘ │
    └───────────────────────────┬─────────────────────────────────┘
                                │
    ┌───────────────────────────▼─────────────────────────────────┐
    │                    Analysis Layers (1-9)                     │
    │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │
    │  │Static   │ │Symbolic │ │Fuzzing  │ │Formal   │  ...      │
    │  │Analysis │ │Execution│ │Testing  │ │Verify   │           │
    │  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘           │
    └───────┼───────────┼───────────┼───────────┼─────────────────┘
            │           │           │           │
    ┌───────▼───────────▼───────────▼───────────▼─────────────────┐
    │                    Tool Adapters                             │
    │  Slither │ Mythril │ Echidna │ Certora │ GPTLens │ ...     │
    └─────────────────────────────────────────────────────────────┘

Core Components
---------------

Tool Adapters
~~~~~~~~~~~~~

Each external tool has a dedicated adapter implementing the ``ToolAdapter`` protocol:

.. code-block:: python

    class ToolAdapter(Protocol):
        def is_available(self) -> ToolStatus: ...
        def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]: ...
        def normalize_findings(self, raw_output: Any) -> List[Dict]: ...

Agents
~~~~~~

Agents orchestrate complex analysis workflows:

* **SmartLLM Agent**: Multi-stage LLM analysis
* **Coordinator Agent**: Cross-tool correlation
* **Policy Agent**: Security policy enforcement

Orchestrator
~~~~~~~~~~~~

The orchestrator manages:

* Tool selection based on availability
* Parallel execution
* Finding aggregation and deduplication
* ML-based false positive filtering

Data Flow
---------

1. **Input**: Solidity source code
2. **Preprocessing**: Framework detection, dependency resolution
3. **Analysis**: Multi-layer parallel analysis
4. **Post-processing**: Correlation, deduplication, FP filtering
5. **Output**: Unified findings with confidence scores

Finding Schema
--------------

All tools produce normalized findings:

.. code-block:: python

    Finding = {
        "id": str,
        "title": str,
        "severity": "Critical" | "High" | "Medium" | "Low" | "Info",
        "confidence": float,  # 0.0 - 1.0
        "location": {
            "file": str,
            "line": int,
            "function": str
        },
        "description": str,
        "recommendation": str,
        "swc_id": str | None,
        "cwe_id": str | None,
        "tool": str,
        "layer": int
    }

Configuration
-------------

MIESC uses YAML configuration:

.. code-block:: yaml

    layers:
      static:
        enabled: true
        tools: [slither, aderyn, solhint]
      symbolic:
        enabled: true
        timeout: 300
      fuzzing:
        enabled: false  # Requires external tools
      llm:
        enabled: true
        model: mistral:latest

    correlation:
      enabled: true
      min_confidence: 0.5
      dedup_threshold: 0.8
