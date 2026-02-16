Security Layers
===============

MIESC implements 9 specialized security layers, each targeting different vulnerability classes.

.. contents:: Table of Contents
   :local:
   :depth: 2

Layer Overview
--------------

.. list-table::
   :header-rows: 1
   :widths: 10 25 30 35

   * - Layer
     - Name
     - Tools
     - Detection Focus
   * - 1
     - Static Analysis
     - Slither, Aderyn, Solhint
     - Code quality, known patterns
   * - 2
     - Pattern Detection
     - Semgrep, SmartBugs
     - Regex patterns, signatures
   * - 3
     - Symbolic Execution
     - Mythril, Halmos
     - Path exploration, constraints
   * - 4
     - Fuzzing
     - Echidna, Medusa, Foundry
     - Property-based testing
   * - 5
     - Formal Verification
     - Certora, SMTChecker
     - Mathematical proofs
   * - 6
     - ML Detection
     - DA-GNN, FP Classifier
     - Graph neural networks
   * - 7
     - LLM Analysis
     - SmartLLM, GPTLens
     - Semantic understanding
   * - 8
     - DeFi Security
     - DeFi Detector
     - Flash loans, oracles, MEV
   * - 9
     - Advanced Detection
     - Advanced Detector
     - Rug pulls, governance

Layer 1-2: Static Analysis
--------------------------

Fast, comprehensive code scanning:

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

Layer 3: Symbolic Execution
---------------------------

Path exploration with constraint solving:

* **Mythril**: SMT-based symbolic execution
* **Halmos**: Symbolic testing framework

Strengths:

* Finds deep logic bugs
* Proves absence of bugs
* Generates exploit inputs

Limitations:

* Path explosion on complex code
* Slow (30s-5min per contract)

Layer 4: Fuzzing
----------------

Random and guided testing:

* **Echidna**: Property-based fuzzer
* **Medusa**: Parallel fuzzer
* **Foundry Fuzz**: Integrated testing

Strengths:

* Finds edge cases
* Tests invariants
* Fast iteration

Limitations:

* Requires test harnesses
* May miss rare paths

Layer 5: Formal Verification
----------------------------

Mathematical correctness proofs:

* **Certora**: CVL specification language
* **SMTChecker**: Solc built-in verifier

Strengths:

* Proves properties hold
* Covers all paths
* High confidence

Limitations:

* Requires specifications
* Complex to set up
* False positives on timeouts

Layer 6: ML Detection
---------------------

Machine learning vulnerability detection:

* **DA-GNN**: Graph neural network
* **FP Classifier**: False positive reduction

Strengths:

* Learns from patterns
* Reduces false positives
* Adapts to new code

Limitations:

* Requires training data
* Black box predictions

Layer 7: LLM Analysis
---------------------

Large language model semantic analysis:

* **SmartLLM**: Multi-stage analysis
* **GPTLens**: Auditor + Critic architecture
* **LLMBugScanner**: Ensemble voting

Strengths:

* Understands context
* Explains findings
* Generates fixes

Limitations:

* Hallucinations possible
* Slow (30s-2min)
* API costs (for cloud models)

Layer 8: DeFi Security
----------------------

DeFi-specific vulnerability detection:

* Flash loan attacks
* Oracle manipulation
* Price manipulation
* MEV vulnerabilities
* Liquidation issues

Strengths:

* DeFi domain expertise
* Protocol-specific checks
* Cross-contract analysis

Limitations:

* Limited to DeFi patterns
* Requires protocol knowledge

Layer 9: Advanced Detection
---------------------------

Emerging threat detection:

* Rug pull patterns
* Governance attacks
* Honeypot detection
* Proxy vulnerabilities
* Centralization risks

Strengths:

* Catches modern attacks
* Token security analysis
* Upgrade safety

Limitations:

* Higher false positive rate
* Requires context

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

    # Quick scan (layers 1-2 only)
    miesc audit quick contract.sol

    # Static + LLM (layers 1-2, 7)
    miesc audit static contract.sol --llm-interpret
