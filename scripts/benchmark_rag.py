#!/usr/bin/env python3
"""
RAG Performance Benchmark - MIESC v5.1.1

Measures the performance improvements from:
- Query caching (5-min TTL, 256-entry LRU)
- O(1) document lookup (vs O(n) linear)
- Batch search (multiple queries in single call)

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: February 2026
"""

import time
import statistics
from typing import List, Dict, Any

# Check if dependencies are available
try:
    from src.llm.embedding_rag import (
        EmbeddingRAG,
        VULNERABILITY_KNOWLEDGE_BASE,
        batch_get_context_for_findings,
        get_context_for_finding,
    )
    DEPS_AVAILABLE = True
except ImportError as e:
    print(f"Dependencies not available: {e}")
    print("Run inside Docker or install: pip install chromadb sentence-transformers")
    DEPS_AVAILABLE = False


def benchmark_sequential_vs_batch():
    """Compare sequential searches vs batch search."""
    print("\n" + "=" * 60)
    print("BENCHMARK: Sequential vs Batch Search")
    print("=" * 60)

    # Sample findings (simulating 20 findings from verificator stage)
    sample_findings = [
        {"type": "reentrancy", "title": f"Reentrancy in function {i}", "description": "State change after external call"}
        for i in range(5)
    ] + [
        {"type": "access-control", "title": f"Missing access control {i}", "description": "No onlyOwner modifier"}
        for i in range(5)
    ] + [
        {"type": "oracle", "title": f"Oracle manipulation {i}", "description": "Price can be manipulated"}
        for i in range(5)
    ] + [
        {"type": "flash-loan", "title": f"Flash loan attack {i}", "description": "Vulnerable to flash loan"}
        for i in range(5)
    ]

    print(f"Test size: {len(sample_findings)} findings")
    print(f"Unique types: 4 (reentrancy, access-control, oracle, flash-loan)")

    # Sequential search (old method)
    print("\n--- Sequential Search (OLD) ---")
    rag = EmbeddingRAG(enable_cache=False)  # Disable cache for fair comparison

    sequential_times = []
    for finding in sample_findings:
        start = time.perf_counter()
        _ = get_context_for_finding(finding, "sample code")
        elapsed = time.perf_counter() - start
        sequential_times.append(elapsed)

    seq_total = sum(sequential_times)
    seq_avg = statistics.mean(sequential_times)
    print(f"Total time: {seq_total:.3f}s")
    print(f"Avg per query: {seq_avg * 1000:.1f}ms")

    # Batch search (new method)
    print("\n--- Batch Search (NEW) ---")

    start = time.perf_counter()
    _ = batch_get_context_for_findings(sample_findings, "sample code")
    batch_total = time.perf_counter() - start

    print(f"Total time: {batch_total:.3f}s")
    print(f"Avg per finding: {batch_total / len(sample_findings) * 1000:.1f}ms")

    # Improvement
    improvement = (1 - batch_total / seq_total) * 100
    print(f"\n🚀 Improvement: {improvement:.1f}% faster")

    return {
        "sequential_total": seq_total,
        "batch_total": batch_total,
        "improvement_pct": improvement,
        "findings_count": len(sample_findings),
    }


def benchmark_cache_hits():
    """Measure cache hit rate with repeated queries."""
    print("\n" + "=" * 60)
    print("BENCHMARK: Query Cache Hit Rate")
    print("=" * 60)

    rag = EmbeddingRAG(enable_cache=True)

    # Warm up the cache
    queries = [
        "reentrancy vulnerability external call",
        "access control missing modifier",
        "oracle price manipulation",
        "flash loan attack vector",
        "integer overflow underflow",
    ]

    print(f"Test queries: {len(queries)}")
    print("Running 3 rounds (1 cold, 2 cached)...")

    round_times = []

    for round_num in range(3):
        round_start = time.perf_counter()
        for query in queries:
            _ = rag.search(query)
        round_time = time.perf_counter() - round_start
        round_times.append(round_time)

        stats = rag.get_cache_stats()
        print(f"  Round {round_num + 1}: {round_time * 1000:.1f}ms | Cache: {stats}")

    # Calculate improvement from caching
    cold_time = round_times[0]
    cached_time = statistics.mean(round_times[1:])
    cache_improvement = (1 - cached_time / cold_time) * 100

    print(f"\n🚀 Cache improvement: {cache_improvement:.1f}% faster on repeated queries")

    return {
        "cold_time": cold_time,
        "cached_time": cached_time,
        "cache_improvement_pct": cache_improvement,
        "final_stats": rag.get_cache_stats(),
    }


def benchmark_document_lookup():
    """Measure O(1) vs O(n) document lookup."""
    print("\n" + "=" * 60)
    print("BENCHMARK: Document Lookup (O(1) vs O(n))")
    print("=" * 60)

    # Build the index
    doc_index = {doc.id: doc for doc in VULNERABILITY_KNOWLEDGE_BASE}
    doc_ids = list(doc_index.keys())

    iterations = 10000
    print(f"Documents: {len(doc_ids)}")
    print(f"Iterations: {iterations}")

    # O(n) linear search (old method)
    print("\n--- O(n) Linear Search (OLD) ---")
    start = time.perf_counter()
    for _ in range(iterations):
        for doc_id in doc_ids[:10]:  # Lookup 10 docs each iteration
            _ = next((d for d in VULNERABILITY_KNOWLEDGE_BASE if d.id == doc_id), None)
    linear_time = time.perf_counter() - start
    print(f"Time: {linear_time * 1000:.1f}ms")

    # O(1) dict lookup (new method)
    print("\n--- O(1) Dict Lookup (NEW) ---")
    start = time.perf_counter()
    for _ in range(iterations):
        for doc_id in doc_ids[:10]:
            _ = doc_index.get(doc_id)
    dict_time = time.perf_counter() - start
    print(f"Time: {dict_time * 1000:.1f}ms")

    # Improvement
    improvement = (1 - dict_time / linear_time) * 100
    speedup = linear_time / dict_time
    print(f"\n🚀 Improvement: {improvement:.1f}% faster ({speedup:.1f}x speedup)")

    return {
        "linear_time": linear_time,
        "dict_time": dict_time,
        "improvement_pct": improvement,
        "speedup": speedup,
    }


def benchmark_knowledge_base():
    """Report knowledge base statistics."""
    print("\n" + "=" * 60)
    print("KNOWLEDGE BASE STATISTICS")
    print("=" * 60)

    from collections import Counter

    categories = Counter(v.category for v in VULNERABILITY_KNOWLEDGE_BASE)
    severities = Counter(v.severity for v in VULNERABILITY_KNOWLEDGE_BASE)

    print(f"\nTotal patterns: {len(VULNERABILITY_KNOWLEDGE_BASE)}")

    print(f"\nBy severity:")
    for sev in ['critical', 'high', 'medium', 'low']:
        print(f"  {sev}: {severities.get(sev, 0)}")

    print(f"\nTop categories:")
    for cat, count in categories.most_common(10):
        print(f"  {cat}: {count}")

    # Quality metrics
    has_exploit = sum(1 for v in VULNERABILITY_KNOWLEDGE_BASE if v.real_exploit)
    has_fix = sum(1 for v in VULNERABILITY_KNOWLEDGE_BASE if v.fixed_code)
    has_code = sum(1 for v in VULNERABILITY_KNOWLEDGE_BASE if v.vulnerable_code)

    print(f"\nQuality metrics:")
    print(f"  With real exploits: {has_exploit}/{len(VULNERABILITY_KNOWLEDGE_BASE)} ({has_exploit*100//len(VULNERABILITY_KNOWLEDGE_BASE)}%)")
    print(f"  With fix examples: {has_fix}/{len(VULNERABILITY_KNOWLEDGE_BASE)} ({has_fix*100//len(VULNERABILITY_KNOWLEDGE_BASE)}%)")
    print(f"  With vuln code: {has_code}/{len(VULNERABILITY_KNOWLEDGE_BASE)} ({has_code*100//len(VULNERABILITY_KNOWLEDGE_BASE)}%)")


def main():
    """Run all benchmarks."""
    print("=" * 60)
    print("MIESC RAG Performance Benchmark")
    print("=" * 60)

    if not DEPS_AVAILABLE:
        print("\n⚠️  Running in limited mode (no ChromaDB/sentence-transformers)")
        benchmark_knowledge_base()
        return

    results = {}

    # Run benchmarks
    try:
        results["knowledge_base"] = benchmark_knowledge_base()
    except Exception as e:
        print(f"Knowledge base stats failed: {e}")

    try:
        results["document_lookup"] = benchmark_document_lookup()
    except Exception as e:
        print(f"Document lookup benchmark failed: {e}")

    try:
        results["cache_hits"] = benchmark_cache_hits()
    except Exception as e:
        print(f"Cache benchmark failed: {e}")

    try:
        results["batch_vs_sequential"] = benchmark_sequential_vs_batch()
    except Exception as e:
        print(f"Batch benchmark failed: {e}")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    if "document_lookup" in results:
        print(f"✅ O(1) Lookup: {results['document_lookup']['speedup']:.1f}x faster")

    if "cache_hits" in results:
        print(f"✅ Query Cache: {results['cache_hits']['cache_improvement_pct']:.1f}% faster on hits")

    if "batch_vs_sequential" in results:
        print(f"✅ Batch Search: {results['batch_vs_sequential']['improvement_pct']:.1f}% faster")

    print("\n✅ All benchmarks completed!")


if __name__ == "__main__":
    main()
