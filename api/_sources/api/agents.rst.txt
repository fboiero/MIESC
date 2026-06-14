Agents Module
=============

Agents orchestrate security analysis across multiple layers and tools.
Each agent specializes in a specific analysis domain.

.. contents:: Table of Contents
   :local:
   :depth: 2

Base Agent
----------

.. automodule:: src.agents.base_agent
   :members:
   :undoc-members:
   :show-inheritance:

LLM Agents
----------

SmartLLM Agent
~~~~~~~~~~~~~~

Multi-stage LLM analysis with Generator, Verificator, and Consensus stages.

.. automodule:: src.agents.smartllm_agent
   :members:
   :undoc-members:
   :show-inheritance:

GPTScan Agent
~~~~~~~~~~~~~

.. automodule:: src.agents.gptscan_agent
   :members:
   :undoc-members:
   :show-inheritance:

LLM SmartAudit Agent
~~~~~~~~~~~~~~~~~~~~

.. automodule:: src.agents.llm_smartaudit_agent
   :members:
   :undoc-members:
   :show-inheritance:

Ollama Agent
~~~~~~~~~~~~

Local LLM integration via Ollama.

.. automodule:: src.agents.ollama_agent
   :members:
   :undoc-members:
   :show-inheritance:

Static Analysis Agents
----------------------

Aderyn Agent
~~~~~~~~~~~~

.. automodule:: src.agents.aderyn_agent
   :members:
   :undoc-members:
   :show-inheritance:

Symbolic Execution Agents
-------------------------

Halmos Agent
~~~~~~~~~~~~

.. automodule:: src.agents.halmos_agent
   :members:
   :undoc-members:
   :show-inheritance:

SMTChecker Agent
~~~~~~~~~~~~~~~~

.. automodule:: src.agents.smtchecker_agent
   :members:
   :undoc-members:
   :show-inheritance:

Fuzzing Agents
--------------

Medusa Agent
~~~~~~~~~~~~

.. automodule:: src.agents.medusa_agent
   :members:
   :undoc-members:
   :show-inheritance:

Wake Agent
~~~~~~~~~~

.. automodule:: src.agents.wake_agent
   :members:
   :undoc-members:
   :show-inheritance:

Coordination
------------

CrewAI Coordinator
~~~~~~~~~~~~~~~~~~

Multi-agent coordination using CrewAI framework.

.. automodule:: src.agents.crewai_coordinator
   :members:
   :undoc-members:
   :show-inheritance:
