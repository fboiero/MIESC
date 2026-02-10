Changelog
=========

All notable changes to MIESC are documented here.

[5.1.0] - 2026-02-10
--------------------

Added
~~~~~

* Sphinx API documentation with autodoc
* Test fixtures for vulnerable contracts (reentrancy, integer overflow, etc.)
* ToolAdapter helper methods for common patterns
* Architecture Decision Records (ADRs)

Changed
~~~~~~~

* Print statements migrated to logging with noqa annotations
* Coverage target increased to 70%
* Mypy strict mode enabled

[5.0.3] - 2026-02-04
--------------------

Added
~~~~~

* Automatic platform/architecture detection for ARM hosts
* Docker image testing guide
* ARM/Apple Silicon documentation

Fixed
~~~~~

* Dockerfile paths in build scripts
* Version alignment across all scripts

[5.0.0] - 2026-01-26
--------------------

Added
~~~~~

* RAG with ChromaDB embeddings for semantic search
* 39 vulnerability patterns in knowledge base
* Evaluation framework for RAG quality
* LLM adapter improvements (SmartLLM, GPTLens, LLMBugScanner)

Changed
~~~~~~~

* LLM architecture refactored for multi-backend support
* DeFi detection patterns enhanced

[4.2.0] - 2025-12-18
--------------------

Added
~~~~~

* Multi-layer analysis framework (9 layers)
* 40+ tool integrations
* Premium report generation with attack scenarios
* MCP (Model Context Protocol) support

Changed
~~~~~~~

* CLI redesigned with Rich formatting
* Report templates updated

[4.0.0] - 2025-11-01
--------------------

Added
~~~~~

* SmartLLM multi-stage analysis
* GPTLens auditor/critic architecture
* CrewAI multi-agent coordination
* SARIF export format

Changed
~~~~~~~

* Major architecture refactor
* Unified adapter protocol
* Centralized configuration

[3.0.0] - 2025-09-01
--------------------

Added
~~~~~

* Slither integration
* Mythril symbolic execution
* Basic LLM support
* HTML report generation

Initial Release
---------------

* Core analysis framework
* Static analysis integration
* JSON output format
