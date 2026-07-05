"""Utility helpers for RAG retrieval and caching."""

import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Tuple, TypeVar

from src.security.llm_output_validator import (
    extract_json_from_text,
    repair_common_json_errors,
)

T = TypeVar("T")


def _safe_text(value: Any) -> str:
    """Return plain text only, dropping malformed or control-character values."""
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text or any(ord(ch) < 32 for ch in text):
        return ""
    return text


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
    key_payload = {
        "filter_category": _safe_text(filter_category),
        "filter_severity": _safe_text(filter_severity),
        "knowledge_base_version": _safe_text(knowledge_base_version),
        "n_results": n_results,
        "query": _safe_text(query)[:200],
        "strategy": _safe_text(strategy) or "semantic",
    }
    content = json.dumps(key_payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(content.encode()).hexdigest()


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
    safe_category = _safe_text(filter_category)
    safe_severity = _safe_text(filter_severity)
    if safe_category:
        conditions.append({"category": safe_category})
    if safe_severity:
        conditions.append({"severity": safe_severity})

    if not conditions:
        return None
    if len(conditions) == 1:
        return conditions[0]
    return {"$and": conditions}


def parse_repaired_json_object(content: Any, *, max_json_chars: int = 50_000) -> Dict[str, Any]:
    """Extract and repair a bounded JSON object from an LLM/RAG response."""
    if not isinstance(content, str):
        return {}

    stripped = content.strip()
    if not stripped:
        return {}
    if stripped.startswith("["):
        return {}

    json_str = extract_json_from_text(content)
    if json_str is None:
        json_str = stripped if stripped.startswith("{") else None

    if not json_str or len(json_str) > max_json_chars:
        return {}

    try:
        parsed = json.loads(repair_common_json_errors(json_str))
    except json.JSONDecodeError:
        return {}

    if isinstance(parsed, dict):
        return parsed
    return {}
