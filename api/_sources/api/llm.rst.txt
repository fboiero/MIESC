LLM Module
==========

Large Language Model integration for semantic vulnerability analysis.

.. contents:: Table of Contents
   :local:
   :depth: 2

LLM Orchestrator
----------------

Central orchestrator for LLM-based analysis.

.. automodule:: src.llm.llm_orchestrator
   :members:
   :undoc-members:
   :show-inheritance:

Embedding RAG
-------------

RAG (Retrieval-Augmented Generation) with ChromaDB embeddings.

.. automodule:: src.llm.embedding_rag
   :members:
   :undoc-members:
   :show-inheritance:

Architecture
------------

The LLM module uses a multi-stage architecture:

1. **Embedding RAG**: Semantic search over vulnerability patterns
2. **LLM Adapters**: GPTLens, SmartLLM, LLMBugScanner, etc.
3. **Consensus**: Multi-model voting for high-confidence findings

RAG Components
~~~~~~~~~~~~~~

.. code-block:: python

    from src.llm.embedding_rag import EmbeddingRAG

    # Initialize RAG with ChromaDB
    rag = EmbeddingRAG()

    # Search for relevant patterns
    results = rag.search("reentrancy external call", n_results=5)

    # Get LLM context for a finding
    context = rag.get_context_for_llm(finding, code_snippet)

Supported Models
~~~~~~~~~~~~~~~~

- **Ollama**: Local models (Mistral, Llama, CodeLlama)
- **OpenAI**: GPT-4, GPT-3.5
- **Anthropic**: Claude 3.5, Claude 3

Configuration
~~~~~~~~~~~~~

.. code-block:: yaml

    llm:
      backend: ollama
      model: mistral:latest
      temperature: 0.1
      max_tokens: 4096

    rag:
      enabled: true
      persist_directory: ~/.miesc/chromadb
      embedding_model: all-MiniLM-L6-v2
