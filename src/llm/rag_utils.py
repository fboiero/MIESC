"""Utility helpers for RAG retrieval and caching."""

import hashlib
import time
from typing import Any, Dict, List, Optional, Tuple, TypeVar

T = TypeVar("T")


def make_cache_key(
    *,
    knowledge_base_version: str,
    query: str,
    filter_category: Optional[str],
    filter_severity: Optional[str],
    n_results: int,
    strategy: str = "semantic",
) -> str:
    """Generate a stable cache key for a RAG search query."""
    key_parts = [
        knowledge_base_version,
        strategy,
        query[:200],
        str(filter_category),
        str(filter_severity),
        str(n_results),
    ]
    return hashlib.md5("|".join(key_parts).encode()).hexdigest()


def get_cached_result(
    cache: Dict[str, Tuple[float, List[T]]],
    cache_key: str,
    *,
    enabled: bool,
    ttl_seconds: int,
) -> Tuple[Optional[List[T]], bool, bool]:
    """
    Read a cached result.

    Returns ``(result, hit, expired)`` so callers can keep their own cache
    counters without coupling this helper to a concrete RAG class.
    """
    if not enabled or cache_key not in cache:
        return None, False, False

    timestamp, results = cache[cache_key]
    if time.time() - timestamp > ttl_seconds:
        del cache[cache_key]
        return None, False, True

    return results, True, False


def store_cached_result(
    cache: Dict[str, Tuple[float, List[T]]],
    cache_key: str,
    results: List[T],
    *,
    enabled: bool,
    max_size: int,
) -> bool:
    """Store a cached result and evict the oldest entry if needed."""
    if not enabled:
        return False

    if len(cache) >= max_size:
        oldest_key = min(cache, key=lambda k: cache[k][0])
        del cache[oldest_key]

    cache[cache_key] = (time.time(), results)
    return True


def cache_stats(
    *,
    hits: int,
    misses: int,
    cache_size: int,
    max_size: int,
) -> Dict[str, Any]:
    """Format cache performance statistics."""
    total = hits + misses
    hit_rate = (hits / total * 100) if total > 0 else 0
    return {
        "hits": hits,
        "misses": misses,
        "hit_rate": f"{hit_rate:.1f}%",
        "cache_size": cache_size,
        "max_size": max_size,
    }


def build_metadata_filter(
    filter_category: Optional[str],
    filter_severity: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Build the ChromaDB metadata filter for category/severity constraints."""
    conditions = []
    if filter_category:
        conditions.append({"category": filter_category})
    if filter_severity:
        conditions.append({"severity": filter_severity})

    if not conditions:
        return None
    if len(conditions) == 1:
        return conditions[0]
    return {"$and": conditions}
