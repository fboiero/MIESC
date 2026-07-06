"""Tests for lightweight RAG utility helpers."""

import time

from src.llm.rag_utils import (
    _safe_text,
    build_metadata_filter,
    cache_stats,
    get_cached_result,
    make_cache_key,
    parse_repaired_json_object,
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
    assert len(base) == 64


def test_make_cache_key_preserves_field_boundaries():
    joined_collision_a = make_cache_key(
        knowledge_base_version="v1",
        strategy="semantic",
        query="alpha|beta",
        filter_category=None,
        filter_severity=None,
        n_results=5,
    )
    joined_collision_b = make_cache_key(
        knowledge_base_version="v1",
        strategy="semantic|alpha",
        query="beta",
        filter_category=None,
        filter_severity=None,
        n_results=5,
    )

    assert joined_collision_a != joined_collision_b


def test_make_cache_key_defaults_malformed_fields():
    malformed = make_cache_key(
        knowledge_base_version={"version": "v1"},  # type: ignore[arg-type]
        query=["alpha", "beta"],  # type: ignore[arg-type]
        filter_category={"category": "reentrancy"},  # type: ignore[arg-type]
        filter_severity=" high\npriority ",  # type: ignore[arg-type]
        n_results=5,
        strategy={"strategy": "semantic"},  # type: ignore[arg-type]
    )
    safe = make_cache_key(
        knowledge_base_version="",
        query="",
        filter_category="",
        filter_severity="",
        n_results=5,
    )

    assert malformed == safe


def test_safe_text_rejects_del_characters():
    assert _safe_text("  query  ") == "query"
    assert _safe_text("bad\x7fquery") == ""


def test_build_metadata_filter_ignores_malformed_text_boundaries():
    assert build_metadata_filter("reentrancy\naccess-control", "high") == {"severity": "high"}
    assert build_metadata_filter({"category": "reentrancy"}, " high ") == {"severity": "high"}


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


def test_parse_repaired_json_object_extracts_and_repairs_object_candidate():
    content = """
    RAG analysis:
    ```json
    {
        category: "reentrancy",
        "severity": "high",
    }
    ```
    """

    assert parse_repaired_json_object(content) == {
        "category": "reentrancy",
        "severity": "high",
    }


def test_parse_repaired_json_object_rejects_non_object_json_boundaries():
    assert parse_repaired_json_object('[{"category": "reentrancy"}]') == {}
    assert parse_repaired_json_object('"reentrancy"') == {}
    assert parse_repaired_json_object("no json {missing end") == {}
    assert parse_repaired_json_object({"category": "reentrancy"}) == {}


def test_parse_repaired_json_object_rejects_oversized_json_candidate():
    content = '{"description": "' + ("x" * 32) + '"}'

    assert parse_repaired_json_object(content, max_json_chars=20) == {}
