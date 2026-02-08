# ADR 0005: RAG Architecture with ChromaDB

## Status

Accepted

## Date

2026-02-08

## Context

MIESC's LLM-based analysis (SmartLLM, GPTLens, LLMBugScanner) needed contextual knowledge about smart contract vulnerabilities to improve detection accuracy and reduce false positives.

### Requirements

1. **Semantic search**: Find relevant vulnerability patterns based on meaning, not keywords
2. **Fast retrieval**: Sub-100ms query latency for real-time analysis
3. **Local execution**: No external API calls (data sovereignty)
4. **Extensible**: Easy to add new vulnerability patterns
5. **Persistence**: Cache embeddings to avoid recomputation

### Alternatives Considered

| Option | Pros | Cons |
|--------|------|------|
| **ChromaDB** | Simple, local, persistent, good Python API | Limited to embeddings |
| **Pinecone** | Managed, scalable | Cloud-only, cost |
| **Weaviate** | Feature-rich, hybrid search | Complex setup |
| **FAISS** | Fast, Facebook-backed | No persistence built-in |
| **Elasticsearch** | Full-text + vector | Heavy, complex |

## Decision

We chose **ChromaDB** with **sentence-transformers** embeddings for the RAG system.

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     LLM Adapter                         │
│  (SmartLLM, GPTLens, LLMBugScanner, GPTScan, etc.)     │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│                   EmbeddingRAG                          │
│  - ChromaDB for vector storage                          │
│  - all-MiniLM-L6-v2 for embeddings (384 dims)          │
│  - 39 vulnerability patterns                            │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│                   ChromaDB                              │
│  - Persistent: ~/.miesc/chromadb/                       │
│  - Collections: vulnerabilities, patterns, defi         │
└─────────────────────────────────────────────────────────┘
```

### Components

1. **EmbeddingRAG** (`src/llm/embedding_rag.py`)
   - Main RAG interface for all LLM adapters
   - Handles embedding generation and retrieval
   - Provides `get_context_for_llm()` method

2. **HybridRAG** (optional enhancement)
   - Combines embedding similarity (70%) with BM25 keyword matching (30%)
   - Better for technical terms like "reentrancy", "delegatecall"

3. **Vulnerability Knowledge Base**
   - 39 patterns covering SWC, CWE, and DeFi vulnerabilities
   - Each pattern includes: description, example, detection hints, remediation

### Configuration

```python
# Default settings
EMBEDDING_MODEL = "all-MiniLM-L6-v2"  # 384 dimensions
CHROMADB_DIR = "~/.miesc/chromadb"
SIMILARITY_THRESHOLD = 0.7
TOP_K_RESULTS = 5
```

## Consequences

### Positive

- **Improved accuracy**: 17% precision improvement in SmartLLM
- **Reduced FP rate**: 52% fewer false positives with RAG context
- **Fast queries**: ~50ms average retrieval time
- **No cloud dependency**: Fully local execution
- **Persistence**: Embeddings cached between sessions

### Negative

- **Disk usage**: ~500MB for ChromaDB + embeddings
- **First-run delay**: ~30s to generate initial embeddings
- **Model download**: sentence-transformers model (~90MB)

### Metrics (Benchmark Results)

| Adapter | Without RAG | With RAG | Improvement |
|---------|-------------|----------|-------------|
| SmartLLM | 75% precision | 88% precision | +17% |
| GPTLens | 85% precision | 92% precision | +8% |
| LLMBugScanner | 70% F1 | 78% F1 | +11% |

## Related

- ADR-0001: Adapter Pattern for Tool Integration
- `src/llm/embedding_rag.py`: Implementation
- `docs/architecture/LLM_RAG_ARCHITECTURE.md`: Detailed documentation
