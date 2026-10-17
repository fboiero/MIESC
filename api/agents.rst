Agents Module
=============

Agents orchestrate security analysis across multiple layers and tools.
Each agent specializes in a specific analysis domain.

.. contents:: Table of Contents
   :local:
   :depth: 2

Base Agent
----------

.. automodule:: miesc.agents.base_agent
   :members:
   :undoc-members:
   :show-inheritance:

LLM Agents
----------

SmartLLM Agent
~~~~~~~~~~~~~~

Multi-stage LLM analysis with Generator, Verificator, and Consensus stages.

.. automodule:: miesc.agents.smartllm_agent
   :members:
   :undoc-members:
   :show-inheritance:

GPTScan Agent
~~~~~~~~~~~~~

.. automodule:: miesc.agents.gptscan_agent
   :members:
   :undoc-members:
   :show-inheritance:

LLM SmartAudit Agent
~~~~~~~~~~~~~~~~~~~~

.. automodule:: miesc.agents.llm_smartaudit_agent
   :members:
   :undoc-members:
   :show-inheritance:

Ollama Agent
~~~~~~~~~~~~

Local LLM integration via Ollama.

.. automodule:: miesc.agents.ollama_agent
   :members:
   :undoc-members:
   :show-inheritance:

Static Analysis Agents
----------------------

Aderyn Agent
~~~~~~~~~~~~

.. automodule:: miesc.agents.aderyn_agent
   :members:
   :undoc-members:
   :show-inheritance:

Symbolic Execution Agents
-------------------------

Halmos Agent
~~~~~~~~~~~~

.. automodule:: miesc.agents.halmos_agent
   :members:
   :undoc-members:
   :show-inheritance:

SMTChecker Agent
~~~~~~~~~~~~~~~~

.. automodule:: miesc.agents.smtchecker_agent
   :members:
   :undoc-members:
   :show-inheritance:

Fuzzing Agents
--------------

Medusa Agent
~~~~~~~~~~~~

.. automodule:: miesc.agents.medusa_agent
   :members:
   :undoc-members:
   :show-inheritance:

Wake Agent
~~~~~~~~~~

.. automodule:: miesc.agents.wake_agent
   :members:
   :undoc-members:
   :show-inheritance:

Coordination
------------

CrewAI Coordinator
~~~~~~~~~~~~~~~~~~

Multi-agent coordination using CrewAI framework.

.. automodule:: miesc.agents.crewai_coordinator
   :members:
   :undoc-members:
   :show-inheritance:
