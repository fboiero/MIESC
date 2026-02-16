Adapters Module
===============

Tool adapters provide a unified interface to security analysis tools.
Each adapter implements the :class:`ToolAdapter` protocol for consistent
integration with the MIESC pipeline.

.. contents:: Table of Contents
   :local:
   :depth: 2

Base Protocol
-------------

.. automodule:: src.core.tool_protocol
   :members:
   :undoc-members:
   :show-inheritance:

Static Analysis Adapters
------------------------

Slither Adapter
~~~~~~~~~~~~~~~

.. automodule:: src.adapters.slither_adapter
   :members:
   :undoc-members:
   :show-inheritance:

Aderyn Adapter
~~~~~~~~~~~~~~

.. automodule:: src.adapters.aderyn_adapter
   :members:
   :undoc-members:
   :show-inheritance:

Solhint Adapter
~~~~~~~~~~~~~~~

.. automodule:: src.adapters.solhint_adapter
   :members:
   :undoc-members:
   :show-inheritance:

Semgrep Adapter
~~~~~~~~~~~~~~~

.. automodule:: src.adapters.semgrep_adapter
   :members:
   :undoc-members:
   :show-inheritance:

Symbolic Execution Adapters
---------------------------

Mythril Adapter
~~~~~~~~~~~~~~~

.. automodule:: src.adapters.mythril_adapter
   :members:
   :undoc-members:
   :show-inheritance:

Dynamic Testing Adapters
------------------------

Hardhat Adapter
~~~~~~~~~~~~~~~

.. automodule:: src.adapters.hardhat_adapter
   :members:
   :undoc-members:
   :show-inheritance:

DeFi Adapters
-------------

DeFi Adapter
~~~~~~~~~~~~

.. automodule:: src.adapters.defi_adapter
   :members:
   :undoc-members:
   :show-inheritance:

Advanced Detector Adapter
~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: src.adapters.advanced_detector_adapter
   :members:
   :undoc-members:
   :show-inheritance:

LLM Adapters
------------

SmartLLM Adapter
~~~~~~~~~~~~~~~~

.. automodule:: src.adapters.smartllm_adapter
   :members:
   :undoc-members:
   :show-inheritance:

GPTLens Adapter
~~~~~~~~~~~~~~~

.. automodule:: src.adapters.gptlens_adapter
   :members:
   :undoc-members:
   :show-inheritance:
