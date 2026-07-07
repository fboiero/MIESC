"""Utility helpers for RAG retrieval and caching."""

import hashlib
import json
import math
import time
from typing import Any, Dict, List, Optional, Tuple, TypeVar

from src.security.llm_output_validator import (
    extract_json_from_text,
    repair_common_json_errors,
)

T = TypeVar("T")


MAX_CACHE_TEXT_CHARS = 200
MAX_FILTER_TEXT_CHARS = 120


def _safe_text(value: Any, *, limit: int = MAX_CACHE_TEXT_CHARS) -> str:
    """Return plain text only, dropping malformed or control-character values."""
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return ""
    if limit <= 0:
        return ""
    return text[:limit]


def _positive_int(value: Any, *, default: int, max_value: int) -> int:
    if isinstance(value, bool):
        return default
    try:
        normalized = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    if normalized < 1:
        return default
    return min(normalized, max_value)


def _non_negative_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        normalized = int(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    return max(0, normalized)


def _non_negative_float(value: Any) -> float:
    if isinstance(value, bool):
        return 0.0
    try:
        normalized = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return normalized if math.isfinite(normalized) and normalized >= 0 else 0.0


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
        "filter_category": _safe_text(filter_category, limit=MAX_FILTER_TEXT_CHARS),
        "filter_severity": _safe_text(filter_severity, limit=MAX_FILTER_TEXT_CHARS),
        "knowledge_base_version": _safe_text(knowledge_base_version),
        "n_results": _positive_int(n_results, default=10, max_value=100),
        "query": _safe_text(query),
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
    safe_key = _safe_text(cache_key)
    if not enabled or not isinstance(cache, dict) or not safe_key or safe_key not in cache:
        return None, False, False

    entry = cache[safe_key]
    if not isinstance(entry, (tuple, list)) or len(entry) != 2:
        del cache[safe_key]
        return None, False, True

    timestamp, results = entry
    timestamp_value = _non_negative_float(timestamp)
    ttl = _non_negative_float(ttl_seconds)
    if not isinstance(results, list):
        del cache[safe_key]
        return None, False, True
    if time.time() - timestamp_value > ttl:
        del cache[safe_key]
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
    safe_key = _safe_text(cache_key)
    if not enabled or not isinstance(cache, dict) or not safe_key or not isinstance(results, list):
        return False

    safe_max_size = _positive_int(max_size, default=1, max_value=10_000)
    while len(cache) >= safe_max_size:
        oldest_key = min(
            cache,
            key=lambda k: (
                _non_negative_float(cache[k][0])
                if isinstance(cache.get(k), (tuple, list)) and len(cache[k]) == 2
                else -1.0
            ),
        )
        del cache[oldest_key]

    cache[safe_key] = (time.time(), results)
    return True


def cache_stats(
    *,
    hits: int,
    misses: int,
    cache_size: int,
    max_size: int,
) -> Dict[str, Any]:
    """Format cache performance statistics."""
    safe_hits = _non_negative_int(hits)
    safe_misses = _non_negative_int(misses)
    safe_cache_size = _non_negative_int(cache_size)
    safe_max_size = _non_negative_int(max_size)
    total = safe_hits + safe_misses
    hit_rate = (safe_hits / total * 100) if total > 0 else 0
    return {
        "hits": safe_hits,
        "misses": safe_misses,
        "hit_rate": f"{hit_rate:.1f}%",
        "cache_size": safe_cache_size,
        "max_size": safe_max_size,
    }


def build_metadata_filter(
    filter_category: Optional[str],
    filter_severity: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Build the ChromaDB metadata filter for category/severity constraints."""
    conditions = []
    safe_category = _safe_text(filter_category, limit=MAX_FILTER_TEXT_CHARS)
    safe_severity = _safe_text(filter_severity, limit=MAX_FILTER_TEXT_CHARS)
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
    max_chars = _positive_int(max_json_chars, default=50_000, max_value=1_000_000)
    if not isinstance(content, str):
        return {}

    stripped = content.strip()
    if not stripped or any(ord(ch) == 0 or ord(ch) == 127 for ch in stripped):
        return {}
    if stripped.startswith("[") or stripped.lstrip().startswith("["):
        return {}
    first_object = stripped.find("{")
    first_array = stripped.find("[")
    if first_array != -1 and (first_object == -1 or first_array < first_object):
        return {}

    json_str = extract_json_from_text(content)
    if json_str is None:
        json_str = stripped if stripped.startswith("{") else None

    if not json_str or len(json_str) > max_chars or json_str.lstrip().startswith("["):
        return {}

    try:
        parsed = json.loads(repair_common_json_errors(json_str))
    except json.JSONDecodeError:
        return {}

    if isinstance(parsed, dict):
        return parsed
    return {}
