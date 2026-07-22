Security Layers
===============

MIESC implements 9 specialized security layers, each targeting different vulnerability classes.

.. note::

   This page follows the canonical L1–L9 taxonomy defined in
   ``miesc/cli/constants.py`` (``LAYERS``), which the shipping CLI and REST API
   execute. Layers 8–9 (Cross-Chain & ZK Security, Advanced AI Ensemble) are
   experimental multi-chain/ensemble modules; the production EVM core is Layers 1–7.

.. contents:: Table of Contents
   :local:
   :depth: 2

Layer Overview
--------------

.. list-table::
   :header-rows: 1
   :widths: 8 26 40 26

   * - Layer
     - Name
     - Tools
     - Detection Focus
   * - 1
     - Static Analysis
     - Slither, Aderyn, Solhint, Semgrep
     - Code quality, known patterns
   * - 2
     - Dynamic Testing
     - Echidna, Foundry, Medusa
     - Fuzzing, property-based testing
   * - 3
     - Symbolic Execution
     - Mythril, Halmos, Manticore
     - Path exploration, constraints
   * - 4
     - Formal Verification
     - SMTChecker, Scribble, Certora, PropertyGPT
     - Mathematical proofs
   * - 5
     - AI Analysis
     - SmartLLM, GPTScan, LLMSmartAudit, GPTLens
     - Semantic understanding (LLM)
   * - 6
     - ML Detection
     - DA-GNN, SmartBugs-ML, SmartGuard, Peculiar
     - Learned classifiers
   * - 7
     - Specialized Analysis
     - Threat Model, Gas Analyzer, MEV Detector, Clone Detector, DeFi
     - Domain-specific security checks
   * - 8
     - Cross-Chain & ZK Security
     - Cross-Chain, ZK Circuit, Bridge Monitor, L2 Validator, Circom
     - Bridges, ZK circuits (experimental)
   * - 9
     - Advanced AI Ensemble
     - LLMBugScanner, Audit Consensus, Exploit Synthesizer, Vuln Verifier
     - Multi-LLM consensus + exploit validation

Layer 1: Static Analysis
------------------------

Fast, comprehensive code scanning without executing the contract:

* **Slither**: 90+ detectors, AST-based analysis
* **Aderyn**: Rust-based, fast detection
* **Solhint**: Linting and best practices
* **Semgrep**: Custom pattern rules

Strengths:

* Very fast (<10 seconds)
* Low false positive rate
* Catches common vulnerabilities

Limitations:

* Cannot detect runtime issues
* Limited cross-function analysis

Layer 2: Dynamic Testing
------------------------

Random and guided execution testing:

* **Echidna**: Property-based fuzzer
* **Foundry Fuzz**: Integrated testing
* **Medusa**: Coverage-guided, parallel fuzzer

Strengths:

* Finds edge cases and violates invariants
* Reproducible, low-false-positive findings
* Fast iteration

Limitations:

* Requires test harnesses / properties
* May miss rare paths

Layer 3: Symbolic Execution
---------------------------

Path exploration with constraint solving:

* **Mythril**: SMT-based symbolic execution
* **Halmos**: Symbolic testing framework
* **Manticore**: Multi-path exploration (deprecated)

Strengths:

* Finds deep logic bugs
* Generates exploit inputs

Limitations:

* Path explosion on complex code
* Slow (30s-5min per contract)

Layer 4: Formal Verification
----------------------------

Mathematical correctness proofs:

* **SMTChecker**: Solc built-in CHC verifier
* **Scribble**: Runtime verification instrumentation
* **Certora**: CVL specification language (requires API key)
* **PropertyGPT**: LLM-generated candidate properties

Strengths:

* Proves properties hold across all paths
* High confidence

Limitations:

* Requires specifications
* Complex to set up; false positives on timeouts

Layer 5: AI Analysis
--------------------

Large language model semantic analysis (local via Ollama):

* **SmartLLM**: Multi-stage RAG-enhanced analysis
* **GPTScan**: LLM + program analysis for logic bugs
* **LLMSmartAudit**: Multi-agent audit
* **GPTLens**: Auditor + Critic architecture

Strengths:

* Understands context and business logic
* Explains findings and generates fixes

Limitations:

* Hallucinations possible (mitigated by validation)
* Slower than static analysis

Layer 6: ML Detection
---------------------

Learned and feature-based classifiers:

* **DA-GNN**: Graph-based pattern analysis
* **SmartBugs-ML** / **SmartGuard** / **Peculiar**: heuristic classifiers

Strengths:

* Complements pattern and LLM layers
* Targets structural patterns

Limitations:

* Coverage bounded by the underlying heuristics

Layer 7: Specialized Analysis
-----------------------------

Domain-specific security checks:

* **Threat Model**: STRIDE/DREAD analysis
* **Gas Analyzer**: gas-optimization and DoS patterns
* **MEV Detector**: front-running, sandwich, and MEV patterns
* **Clone Detector**: known-exploit similarity
* **DeFi**: flash-loan, oracle, and price-manipulation checks
* **Advanced Detector** / **Upgradability Checker**: proxy and cross-cutting patterns

Strengths:

* Protocol- and domain-aware checks
* Cross-contract analysis

Limitations:

* Scoped to the modeled patterns

Layer 8: Cross-Chain & ZK Security (experimental)
-------------------------------------------------

Bridge and zero-knowledge circuit analysis for multi-chain deployments:

* **Cross-Chain** / **Bridge Monitor**: bridge-security and event analysis
* **ZK Circuit** / **Circom Analyzer**: zero-knowledge circuit checks
* **L2 Validator**: L2 validity checks

This layer is experimental and part of the multi-chain roadmap; the production
core is Layers 1–7 (EVM).

Layer 9: Advanced AI Ensemble
-----------------------------

Multi-LLM ensemble, cross-tool consensus, and exploit validation:

* **LLMBugScanner**: ensemble voting across LLM reasoners
* **Audit Consensus**: Bayesian meta-analysis (per-tool weights)
* **Exploit Synthesizer**: Foundry PoC generation and execution
* **Vuln Verifier** / **Remediation Validator**: Z3-based confirmation and patch verification

Strengths:

* Reduces single-model variance
* Confirms findings with executable evidence

Limitations:

* Higher latency; runs after the detection layers

Layer Selection
---------------

MIESC automatically selects layers based on:

1. Tool availability
2. Contract complexity
3. Time budget
4. Confidence requirements

.. code-block:: bash

    # Full analysis (all layers)
    miesc audit full contract.sol

    # Quick scan (fast static tools)
    miesc audit quick contract.sol

    # Run a specific layer
    miesc audit layer 5 contract.sol
