Quickstart Guide
================

Get started with MIESC in 5 minutes.

Basic Usage
-----------

Analyze a single contract:

.. code-block:: bash

    miesc audit full MyContract.sol

Quick scan (faster, fewer tools):

.. code-block:: bash

    miesc audit quick MyContract.sol

Static analysis only:

.. code-block:: bash

    miesc audit static MyContract.sol

Output Formats
--------------

Generate different output formats:

.. code-block:: bash

    # JSON output
    miesc audit full MyContract.sol -o results.json

    # Generate HTML report
    miesc report results.json -f html -o report.html

    # Generate PDF report
    miesc report results.json -f pdf -o report.pdf

    # SARIF format (for CI/CD)
    miesc audit full MyContract.sol -f sarif -o results.sarif

Python API
----------

Use MIESC programmatically:

.. code-block:: python

    from miesc.cli import analyze_contract

    # Analyze a contract
    results = analyze_contract("MyContract.sol", mode="full")

    # Print findings
    for finding in results.findings:
        print(f"[{finding.severity}] {finding.title}")
        print(f"  Location: {finding.location}")
        print(f"  Tool: {finding.tool}")

Using Adapters Directly
-----------------------

Use individual tool adapters:

.. code-block:: python

    from src.adapters.slither_adapter import SlitherAdapter

    # Initialize adapter
    adapter = SlitherAdapter()

    # Check availability
    if adapter.is_available():
        # Run analysis
        result = adapter.analyze("MyContract.sol")

        for finding in result["findings"]:
            print(f"{finding['severity']}: {finding['message']}")

LLM-Enhanced Analysis
---------------------

Enable LLM interpretation:

.. code-block:: bash

    # With Ollama (local)
    export OLLAMA_HOST=http://localhost:11434
    miesc audit full MyContract.sol --llm-interpret

    # Premium report with attack scenarios
    miesc report results.json -t premium --llm-interpret -f pdf

Docker Usage
------------

Run analysis in Docker:

.. code-block:: bash

    # Mount contract and output directories
    docker run --rm \\
        -v $(pwd)/contracts:/contracts \\
        -v $(pwd)/output:/output \\
        ghcr.io/fboiero/miesc:full \\
        audit full /contracts/MyContract.sol -o /output/results.json

With LLM (macOS):

.. code-block:: bash

    docker run --rm \\
        -v $(pwd)/contracts:/contracts \\
        -e OLLAMA_HOST=http://host.docker.internal:11434 \\
        ghcr.io/fboiero/miesc:full \\
        audit full /contracts/MyContract.sol --llm-interpret

Configuration
-------------

Create a configuration file:

.. code-block:: yaml

    # miesc.yaml
    analysis:
      default_mode: full
      timeout: 300
      skip_unavailable: true

    llm:
      backend: ollama
      model: mistral:latest
      temperature: 0.1

    output:
      format: json
      include_raw_output: false

Next Steps
----------

* Read the :doc:`API Reference <api/adapters>` for detailed documentation
* Check :doc:`Architecture Overview <architecture/overview>` for system design
* See :doc:`Contributing <contributing>` to contribute to MIESC
