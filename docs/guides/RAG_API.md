# RAG API Guide - MIESC v5.1.0

This guide covers the Retrieval-Augmented Generation (RAG) system for vulnerability analysis in MIESC.

## Overview

The RAG system provides semantic search capabilities for the vulnerability knowledge base, enhancing LLM-based analysis with relevant context from known vulnerabilities.

```
Contract.sol → LLM Adapter → RAG Enrichment → Ollama Backend → Findings
                    ↓
            EmbeddingRAG (ChromaDB + all-MiniLM-L6-v2)
            59 vulnerability patterns
```

## Quick Start

```python
from src.llm.embedding_rag import (
    EmbeddingRAG,
    get_context_for_finding,
    batch_get_context_for_findings,
)

# Initialize RAG
rag = EmbeddingRAG()

# Search for similar vulnerabilities
results = rag.search("reentrancy external call state update")
for r in results:
    print(f"{r.document.title}: {r.similarity_score:.2f}")
```

## Core Classes

### EmbeddingRAG

The main RAG class using ChromaDB and sentence-transformers.

```python
class EmbeddingRAG:
    """
    ChromaDB-powered RAG for vulnerability analysis.

    Performance optimizations (v5.1.0):
    - O(1) document lookup via _doc_index
    - Query caching with 5-min TTL
    - Batch search support
    """

    def __init__(
        self,
        persist_directory: str = None,  # Default: ~/.miesc/chromadb/
        embedding_model: str = "all-MiniLM-L6-v2",
        top_k: int = 5,
        enable_cache: bool = True,
    ):
        ...
```

### VulnerabilityDocument

Data structure for vulnerability patterns in the knowledge base.

```python
@dataclass
class VulnerabilityDocument:
    id: str                    # Unique ID (e.g., "SWC-107")
    swc_id: Optional[str]      # Smart Contract Weakness ID
    cwe_id: Optional[str]      # Common Weakness Enumeration ID
    title: str                 # Vulnerability name
    description: str           # Detailed explanation
    vulnerable_code: str       # Example vulnerable code
    fixed_code: str            # Remediation example
    attack_scenario: str       # Step-by-step exploit explanation
    severity: str              # critical, high, medium, low, info
    category: str              # reentrancy, access-control, oracle, etc.
    real_exploit: str          # Historical case (e.g., "The DAO Hack")
    tags: List[str]            # Keywords for filtering
    references: List[str]      # Links to more info
```

## Search Methods

### Single Query Search

```python
# Basic search
results = rag.search("reentrancy vulnerability")

# With filters
results = rag.search(
    query="external call state update",
    filter_category="reentrancy",
    filter_severity="critical",
    n_results=10,
)
```

### Batch Search (Optimized)

For multiple queries, use batch search for 50-75% faster performance:

```python
queries = [
    "reentrancy vulnerability",
    "oracle price manipulation",
    "access control missing",
]

# Single call, multiple results
all_results = rag.batch_search(queries, n_results=5)

for i, results in enumerate(all_results):
    print(f"Query {i}: {len(results)} matches")
```

### Search by Finding

For security findings from other tools:

```python
finding = {
    "type": "reentrancy",
    "title": "Reentrancy in withdraw()",
    "description": "State update after external call",
    "swc_id": "SWC-107",
}

results = rag.search_by_finding(finding, code_context="function withdraw()...")
```

## Context Generation

### Single Finding Context

```python
from src.llm.embedding_rag import get_context_for_finding

finding = {"type": "reentrancy", "title": "..."}
context = get_context_for_finding(finding, code="...")
# Returns formatted string for LLM prompt
```

### Batch Context (Optimized)

For verificator stage with multiple findings:

```python
from src.llm.embedding_rag import batch_get_context_for_findings

findings = [
    {"type": "reentrancy", "title": "Finding 1"},
    {"type": "reentrancy", "title": "Finding 2"},  # Same type, shared query
    {"type": "oracle", "title": "Finding 3"},
]

# Groups by type, only 2 unique queries instead of 3
contexts = batch_get_context_for_findings(findings, code="...")

# contexts is a dict: {finding_title: context_string}
for title, ctx in contexts.items():
    print(f"{title}: {len(ctx)} chars")
```

## Cache Management

### Cache Statistics

```python
stats = rag.get_cache_stats()
# {
#     "hits": 45,
#     "misses": 5,
#     "hit_rate": "90.0%",
#     "cache_size": 50,
#     "max_size": 256,
# }
```

### Clear Cache

```python
rag.clear_cache()
```

### Cache Configuration

```python
# Custom cache settings
rag = EmbeddingRAG(enable_cache=True)
rag.CACHE_MAX_SIZE = 512      # Default: 256
rag.CACHE_TTL_SECONDS = 600   # Default: 300 (5 min)
```

## Knowledge Base

### Current Statistics

| Metric | Value |
|--------|-------|
| Total patterns | 59 |
| Critical severity | 20 |
| High severity | 22 |
| Medium severity | 14 |
| Low severity | 3 |
| With real exploits | 48 (81%) |
| With fix examples | 59 (100%) |

### Categories

| Category | Count | Examples |
|----------|-------|----------|
| reentrancy | 6 | Classic, cross-function, read-only, Vyper |
| mev | 4 | Sandwich, JIT liquidity, time-bandit |
| governance | 4 | Flash loan, timelock bypass |
| proxy | 4 | UUPS, Diamond storage, Beacon |
| bridge | 3 | Message replay, L2 sequencer |
| zk | 2 | Underconstrained circuit, nullifier |
| nft | 2 | Unlimited mint, royalty bypass |
| defi | 2 | Donation attack, interest rate |

### Add Custom Vulnerability

```python
from src.llm.embedding_rag import VulnerabilityDocument

custom_vuln = VulnerabilityDocument(
    id="CUSTOM-001",
    title="My Custom Vulnerability",
    description="Description of the vulnerability...",
    vulnerable_code="function vulnerable() { ... }",
    fixed_code="function fixed() { ... }",
    severity="high",
    category="custom",
    tags=["custom", "my-project"],
)

rag.add_custom_vulnerability(custom_vuln)
```

## Performance Tips

### 1. Use Batch Operations

```python
# BAD: Sequential searches (slow)
for finding in findings:
    ctx = get_context_for_finding(finding)

# GOOD: Batch search (50-75% faster)
contexts = batch_get_context_for_findings(findings)
```

### 2. Enable Caching

```python
# Cache is enabled by default
rag = EmbeddingRAG(enable_cache=True)

# Repeated identical queries hit cache (90%+ hit rate)
```

### 3. Filter by Category

```python
# More specific = faster + more relevant
results = rag.search(
    "vulnerability",
    filter_category="reentrancy",  # Narrows search space
)
```

## Integration with SmartLLM

The SmartLLM adapter uses RAG automatically in the verificator stage:

```python
# SmartLLM adapter pre-fetches all RAG context
# using batch_get_context_for_findings internally

adapter = SmartLLMAdapter(use_embedding_rag=True)
findings = adapter.analyze(contract_code)
# RAG context is fetched once per unique vulnerability type
```

## Troubleshooting

### ChromaDB Not Found

```bash
pip install chromadb sentence-transformers
```

### Slow First Query

First query loads the embedding model (~1-2 seconds). Subsequent queries are faster.

### Stale Cache

```python
# Clear cache if knowledge base was updated
rag.clear_cache()
```

### Missing Dependencies in Docker

```bash
# Use miesc:full image for RAG support
docker run ghcr.io/fboiero/miesc:full ...
```

## API Reference

### Functions

| Function | Description |
|----------|-------------|
| `get_rag()` | Get singleton RAG instance |
| `search_vulnerabilities(query)` | Quick search helper |
| `get_context_for_finding(finding)` | Get LLM context for one finding |
| `batch_get_context_for_findings(findings)` | Batch context for multiple findings |

### EmbeddingRAG Methods

| Method | Description |
|--------|-------------|
| `search(query, ...)` | Semantic search with optional filters |
| `batch_search(queries, ...)` | Batch search for multiple queries |
| `search_by_finding(finding)` | Search based on finding dict |
| `get_context_for_llm(finding)` | Generate LLM prompt context |
| `add_custom_vulnerability(doc)` | Add custom vulnerability to KB |
| `get_cache_stats()` | Get cache performance stats |
| `clear_cache()` | Clear query cache |

## See Also

- [Professional Audit Workflow](PROFESSIONAL_AUDIT_WORKFLOW.md)
- [SmartLLM Adapter Documentation](../../src/adapters/README.md)
- [Knowledge Base Source](../../src/llm/embedding_rag.py)
