Installation
============

This guide covers installing MIESC for development and production use.

Requirements
------------

* Python 3.12 or higher
* pip or pipx
* Optional: Docker for containerized analysis

Quick Install
-------------

Install the core package:

.. code-block:: bash

    pip install miesc

Install with all features:

.. code-block:: bash

    pip install miesc[full]

Development Install
-------------------

Clone and install in development mode:

.. code-block:: bash

    git clone https://github.com/fboiero/MIESC.git
    cd MIESC
    pip install -e ".[dev]"

Optional Dependencies
---------------------

MIESC has several optional dependency groups:

.. code-block:: bash

    # Development tools
    pip install miesc[dev]

    # LLM integration
    pip install miesc[llm]

    # RAG with embeddings
    pip install miesc[rag]

    # PDF report generation
    pip install miesc[pdf]

    # Web dashboard
    pip install miesc[web]

    # Full installation
    pip install miesc[full]

Docker Installation
-------------------

Using pre-built images:

.. code-block:: bash

    # Standard image
    docker pull ghcr.io/fboiero/miesc:latest

    # Full image with all tools
    docker pull ghcr.io/fboiero/miesc:full

Run analysis in Docker:

.. code-block:: bash

    docker run --rm -v $(pwd):/contracts \\
        ghcr.io/fboiero/miesc:full \\
        audit full /contracts/MyContract.sol

External Tools
--------------

For full analysis capability, install these external tools:

**Static Analysis:**

* Slither: ``pip install slither-analyzer``
* Solhint: ``npm install -g solhint``
* Aderyn: ``cargo install aderyn``

**Symbolic Execution:**

* Mythril: ``pip install mythril``
* Halmos: ``pip install halmos``

**Fuzzing:**

* Echidna: Download from `releases <https://github.com/crytic/echidna/releases>`_
* Medusa: ``go install github.com/crytic/medusa@latest``
* Foundry: ``curl -L https://foundry.paradigm.xyz | bash``

**Formal Verification:**

* Certora: Requires API key from `certora.com <https://www.certora.com>`_

Verifying Installation
----------------------

Check that MIESC is installed correctly:

.. code-block:: bash

    miesc --version
    miesc tools status

This will show the version and available tools.
