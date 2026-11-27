Core Module
===========

Core infrastructure for MIESC including configuration, orchestration,
and utility functions.

.. contents:: Table of Contents
   :local:
   :depth: 2

Configuration
-------------

.. automodule:: miesc.core.config_loader
   :members:
   :undoc-members:
   :show-inheritance:

Tool Protocol
-------------

Base protocol for all tool adapters.

.. automodule:: miesc.core.tool_protocol
   :members:
   :undoc-members:
   :show-inheritance:

Agent Protocol
--------------

Base protocol for all analysis agents.

.. automodule:: miesc.core.agent_protocol
   :members:
   :undoc-members:
   :show-inheritance:

Agent Registry
--------------

Registry for agent discovery and management.

.. automodule:: miesc.core.agent_registry
   :members:
   :undoc-members:
   :show-inheritance:

Orchestration
-------------

ML Orchestrator
~~~~~~~~~~~~~~~

.. automodule:: miesc.core.ml_orchestrator
   :members:
   :undoc-members:
   :show-inheritance:

Exporters
---------

Export findings to various formats (SARIF, JSON, etc.).

.. automodule:: miesc.core.exporters
   :members:
   :undoc-members:
   :show-inheritance:

Framework Detection
-------------------

Detect project framework (Foundry, Hardhat, etc.).

.. automodule:: miesc.core.framework_detector
   :members:
   :undoc-members:
   :show-inheritance:

Rich CLI
--------

Terminal UI with rich formatting.

.. automodule:: miesc.core.rich_cli
   :members:
   :undoc-members:
   :show-inheritance:

Correlation API
---------------

Finding correlation and deduplication.

.. automodule:: miesc.core.correlation_api
   :members:
   :undoc-members:
   :show-inheritance:
