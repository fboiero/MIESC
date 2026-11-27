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

.. automodule:: miesc.core.tool_protocol
   :members:
   :undoc-members:
   :show-inheritance:

Static Analysis Adapters
------------------------

Slither Adapter
~~~~~~~~~~~~~~~

.. automodule:: miesc.adapters.slither_adapter
   :members:
   :undoc-members:
   :show-inheritance:

Aderyn Adapter
~~~~~~~~~~~~~~

.. automodule:: miesc.adapters.aderyn_adapter
   :members:
   :undoc-members:
   :show-inheritance:

Solhint Adapter
~~~~~~~~~~~~~~~

.. automodule:: miesc.adapters.solhint_adapter
   :members:
   :undoc-members:
   :show-inheritance:

Semgrep Adapter
~~~~~~~~~~~~~~~

.. automodule:: miesc.adapters.semgrep_adapter
   :members:
   :undoc-members:
   :show-inheritance:

Symbolic Execution Adapters
---------------------------

Mythril Adapter
~~~~~~~~~~~~~~~

.. automodule:: miesc.adapters.mythril_adapter
   :members:
   :undoc-members:
   :show-inheritance:

Dynamic Testing Adapters
------------------------

Hardhat Adapter
~~~~~~~~~~~~~~~

.. automodule:: miesc.adapters.hardhat_adapter
   :members:
   :undoc-members:
   :show-inheritance:

DeFi Adapters
-------------

DeFi Adapter
~~~~~~~~~~~~

.. automodule:: miesc.adapters.defi_adapter
   :members:
   :undoc-members:
   :show-inheritance:

Advanced Detector Adapter
~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: miesc.adapters.advanced_detector_adapter
   :members:
   :undoc-members:
   :show-inheritance:

LLM Adapters
------------

SmartLLM Adapter
~~~~~~~~~~~~~~~~

.. automodule:: miesc.adapters.smartllm_adapter
   :members:
   :undoc-members:
   :show-inheritance:

GPTLens Adapter
~~~~~~~~~~~~~~~

.. automodule:: miesc.adapters.gptlens_adapter
   :members:
   :undoc-members:
   :show-inheritance:
