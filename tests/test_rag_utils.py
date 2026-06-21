"""Tests for lightweight RAG utility helpers."""

import time

from src.llm.rag_utils import (
    build_metadata_filter,
    cache_stats,
    get_cached_result,
    make_cache_key,
    store_cached_result,
)


def test_make_cache_key_includes_strategy_and_filters():
    base = make_cache_key(
        knowledge_base_version="v1",
        query="reentrancy",
        filter_category=None,
        filter_severity=None,
        n_results=5,
    )
    filtered = make_cache_key(
        knowledge_base_version="v1",
        query="reentrancy",
        filter_category="reentrancy",
        filter_severity="high",
        n_results=5,
    )
    multi_step = make_cache_key(
        knowledge_base_version="v1",
        query="reentrancy",
        filter_category=None,
        filter_severity=None,
        n_results=5,
        strategy="multi_step",
    )

    assert base != filtered
    assert base != multi_step
    assert len(base) == 32


def test_cache_helpers_store_hit_expire_and_respect_disabled():
    cache = {}

    assert store_cached_result(cache, "a", [1], enabled=False, max_size=10) is False
    assert cache == {}

    assert store_cached_result(cache, "a", [1], enabled=True, max_size=10) is True
    result, hit, expired = get_cached_result(cache, "a", enabled=True, ttl_seconds=30)
    assert result == [1]
    assert hit is True
    assert expired is False

    result, hit, expired = get_cached_result(cache, "a", enabled=False, ttl_seconds=30)
    assert result is None
    assert hit is False
    assert expired is False

    cache["a"] = (time.time() - 31, [1])
    result, hit, expired = get_cached_result(cache, "a", enabled=True, ttl_seconds=30)
    assert result is None
    assert hit is False
    assert expired is True
    assert "a" not in cache


def test_store_cached_result_evicts_oldest_entry():
    cache = {
        "old": (1.0, ["old"]),
        "new": (2.0, ["new"]),
    }

    store_cached_result(cache, "latest", ["latest"], enabled=True, max_size=2)

    assert "old" not in cache
    assert "new" in cache
    assert "latest" in cache


def test_cache_stats_formats_hit_rate():
    assert cache_stats(hits=1, misses=3, cache_size=2, max_size=10) == {
        "hits": 1,
        "misses": 3,
        "hit_rate": "25.0%",
        "cache_size": 2,
        "max_size": 10,
    }


def test_build_metadata_filter():
    assert build_metadata_filter(None, None) is None
    assert build_metadata_filter("reentrancy", None) == {"category": "reentrancy"}
    assert build_metadata_filter(None, "high") == {"severity": "high"}
    assert build_metadata_filter("reentrancy", "high") == {
        "$and": [{"category": "reentrancy"}, {"severity": "high"}]
    }
