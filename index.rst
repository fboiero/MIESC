MIESC API Documentation
========================

**Multi-layer Intelligent Evaluation for Smart Contracts**

MIESC is a comprehensive security analysis framework for Ethereum smart contracts,
implementing a defense-in-depth strategy across 9 specialized security layers.

.. toctree::
   :maxdepth: 2
   :caption: Getting Started

   installation
   quickstart

.. toctree::
   :maxdepth: 2
   :caption: API Reference

   api/adapters
   api/agents
   api/core
   api/detectors
   api/llm
   api/ml

.. toctree::
   :maxdepth: 2
   :caption: Architecture

   architecture/overview
   architecture/layers

.. toctree::
   :maxdepth: 1
   :caption: Development

   contributing
   changelog

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

Quick Links
-----------

* **GitHub Repository**: https://github.com/fboiero/MIESC
* **Issue Tracker**: https://github.com/fboiero/MIESC/issues
* **License**: AGPL-3.0

Overview
--------

MIESC provides multi-layer security analysis:

1. **Layer 1-2**: Static Analysis (Slither, Aderyn, Solhint)
2. **Layer 3**: Symbolic Execution (Mythril)
3. **Layer 4**: Fuzzing (Echidna, Medusa, Foundry)
4. **Layer 5**: Formal Verification (Certora, Halmos)
5. **Layer 6-7**: ML/AI Detection (SmartLLM, GPTLens)
6. **Layer 8-9**: DeFi & Advanced Detection

Key Features
------------

* **40+ security tools** integrated through unified adapter protocol
* **RAG-enhanced LLM analysis** with ChromaDB vector search
* **MCP (Model Context Protocol)** compatible
* **Multi-format reports** (HTML, PDF, JSON, SARIF)
* **Docker support** for isolated analysis

Example Usage
-------------

.. code-block:: python

    from miesc.cli import analyze_contract

    # Analyze a contract
    results = analyze_contract("MyContract.sol")

    # Access findings
    for finding in results.findings:
        print(f"{finding.severity}: {finding.title}")

.. code-block:: bash

    # CLI usage
    miesc audit full MyContract.sol --output results.json
    miesc report results.json --format pdf
