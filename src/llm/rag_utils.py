"""Utility helpers for RAG retrieval and caching."""

import hashlib
import json
import math
import time
import unicodedata
from typing import Any, Dict, List, Optional, Tuple, TypeVar

from src.security.llm_output_validator import (
    extract_json_from_text,
    repair_common_json_errors,
)

T = TypeVar("T")


MAX_CACHE_TEXT_CHARS = 200
MAX_FILTER_TEXT_CHARS = 120
MAX_CACHE_RESULT_ITEMS = 1_000
MAX_JSON_OBJECT_KEYS = 100
MAX_JSON_LIST_ITEMS = 100
MAX_JSON_TEXT_CHARS = 5_000
MAX_JSON_DEPTH = 8


def _safe_text(value: Any, *, limit: int = MAX_CACHE_TEXT_CHARS) -> str:
    """Return plain text only, dropping malformed or control-character values."""
    if not isinstance(value, str):
        return ""
    if isinstance(limit, bool):
        return ""
    try:
        safe_limit = int(limit)
    except (TypeError, ValueError, OverflowError):
        return ""
    if safe_limit <= 0:
        return ""
    safe_limit = min(safe_limit, MAX_CACHE_TEXT_CHARS)
    text = value.strip()
    if not text or any(_is_unsafe_text_char(ch) for ch in text):
        return ""
    return text[:safe_limit]


def _is_unsafe_text_char(ch: str) -> bool:
    if ord(ch) < 32 or ord(ch) == 127:
        return True
    category = unicodedata.category(ch)
    return category.startswith("C") or category in {"Zl", "Zp"}


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


def _safe_cache_get(cache: Dict[str, Tuple[float, List[T]]], cache_key: str) -> Any:
    try:
        return cache[cache_key]
    except (KeyError, TypeError, AttributeError, RuntimeError):
        return None


def _safe_cache_contains(cache: Dict[str, Tuple[float, List[T]]], cache_key: str) -> bool:
    try:
        return cache_key in cache
    except (TypeError, AttributeError, RuntimeError):
        return False


def _safe_cache_delete(cache: Dict[str, Tuple[float, List[T]]], cache_key: str) -> None:
    try:
        del cache[cache_key]
    except (KeyError, TypeError, AttributeError, RuntimeError):
        return


def _cache_entry_timestamp(cache: Dict[str, Tuple[float, List[T]]], cache_key: str) -> float:
    entry = _safe_cache_get(cache, cache_key)
    if isinstance(entry, (tuple, list)) and len(entry) == 2:
        return _non_negative_float(entry[0])
    return -1.0


def _bounded_result_copy(results: List[T]) -> List[T]:
    return list(results[:MAX_CACHE_RESULT_ITEMS])


def _safe_json_scalar_text(value: str) -> Optional[str]:
    if any(_is_unsafe_text_char(ch) for ch in value):
        return None
    return value[:MAX_JSON_TEXT_CHARS]


def _sanitize_json_value(value: Any, *, depth: int = 0) -> Tuple[bool, Any]:
    if depth > MAX_JSON_DEPTH:
        return False, None
    if value is None or isinstance(value, (bool, int, float)):
        return True, value
    if isinstance(value, str):
        safe_value = _safe_json_scalar_text(value)
        return (safe_value is not None), safe_value
    if isinstance(value, list):
        if len(value) > MAX_JSON_LIST_ITEMS:
            return False, None
        safe_items = []
        for item in value:
            ok, safe_item = _sanitize_json_value(item, depth=depth + 1)
            if not ok:
                return False, None
            safe_items.append(safe_item)
        return True, safe_items
    if isinstance(value, dict):
        if len(value) > MAX_JSON_OBJECT_KEYS:
            return False, None
        safe_obj = {}
        for key, item in value.items():
            safe_key = _safe_text(key, limit=MAX_FILTER_TEXT_CHARS)
            if not safe_key:
                return False, None
            ok, safe_item = _sanitize_json_value(item, depth=depth + 1)
            if not ok:
                return False, None
            safe_obj[safe_key] = safe_item
        return True, safe_obj
    return False, None


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
    if (
        not enabled
        or not isinstance(cache, dict)
        or not safe_key
        or not _safe_cache_contains(cache, safe_key)
    ):
        return None, False, False

    entry = _safe_cache_get(cache, safe_key)
    if not isinstance(entry, (tuple, list)) or len(entry) != 2:
        _safe_cache_delete(cache, safe_key)
        return None, False, True

    timestamp, results = entry
    timestamp_value = _non_negative_float(timestamp)
    ttl = _non_negative_float(ttl_seconds)
    if not isinstance(results, list):
        _safe_cache_delete(cache, safe_key)
        return None, False, True
    if time.time() - timestamp_value > ttl:
        _safe_cache_delete(cache, safe_key)
        return None, False, True

    return _bounded_result_copy(results), True, False


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
    while len(cache) >= safe_max_size and not _safe_cache_contains(cache, safe_key):
        oldest_key = min(
            cache,
            key=lambda k: _cache_entry_timestamp(cache, k),
        )
        _safe_cache_delete(cache, oldest_key)

    cache[safe_key] = (time.time(), _bounded_result_copy(results))
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
    if not stripped or any(
        ord(ch) in {0, 127} or unicodedata.category(ch) in {"Zl", "Zp"} for ch in stripped
    ):
        return {}
    if stripped.startswith("[") or stripped.lstrip().startswith("["):
        return {}
    first_object = stripped.find("{")
    first_array = stripped.find("[")
    if first_array != -1 and (first_object == -1 or first_array < first_object):
        return {}

    try:
        json_str = extract_json_from_text(content)
    except (TypeError, ValueError, RuntimeError):
        return {}
    if json_str is None:
        json_str = stripped if stripped.startswith("{") else None

    if not json_str or len(json_str) > max_chars or json_str.lstrip().startswith("["):
        return {}

    try:
        repaired = repair_common_json_errors(json_str)
        parsed = json.loads(repaired)
    except json.JSONDecodeError:
        return {}
    except (TypeError, ValueError, RuntimeError):
        return {}

    if isinstance(parsed, dict):
        ok, safe_parsed = _sanitize_json_value(parsed)
        return safe_parsed if ok and isinstance(safe_parsed, dict) else {}
    return {}
