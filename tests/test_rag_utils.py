"""Tests for lightweight RAG utility helpers."""

import math
import time

import pytest

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


def test_safe_text_bounds_length_and_rejects_non_positive_limits():
    assert _safe_text("x" * 250) == "x" * 200
    assert _safe_text("abcdef", limit=3) == "abc"
    assert _safe_text("abcdef", limit=0) == ""


def test_safe_text_rejects_ascii_control_characters():
    assert _safe_text("bad\x00query") == ""
    assert _safe_text("bad\tquery") == ""
    assert _safe_text("  \n  ") == ""


def test_make_cache_key_normalizes_result_count():
    negative = make_cache_key(
        knowledge_base_version="v1",
        query="reentrancy",
        filter_category=None,
        filter_severity=None,
        n_results=-5,
    )
    default = make_cache_key(
        knowledge_base_version="v1",
        query="reentrancy",
        filter_category=None,
        filter_severity=None,
        n_results=10,
    )
    capped = make_cache_key(
        knowledge_base_version="v1",
        query="reentrancy",
        filter_category=None,
        filter_severity=None,
        n_results=10_000,
    )
    max_safe = make_cache_key(
        knowledge_base_version="v1",
        query="reentrancy",
        filter_category=None,
        filter_severity=None,
        n_results=100,
    )

    assert negative == default
    assert capped == max_safe


def test_make_cache_key_bounds_query_text():
    query = "a" * 220 + "left-out"
    bounded = make_cache_key(
        knowledge_base_version="v1",
        query=query,
        filter_category=None,
        filter_severity=None,
        n_results=5,
    )
    same_prefix = make_cache_key(
        knowledge_base_version="v1",
        query="a" * 200,
        filter_category=None,
        filter_severity=None,
        n_results=5,
    )

    assert bounded == same_prefix


def test_make_cache_key_defaults_blank_strategy():
    blank_strategy = make_cache_key(
        knowledge_base_version="v1",
        query="reentrancy",
        filter_category=None,
        filter_severity=None,
        n_results=5,
        strategy=" \t ",
    )
    default_strategy = make_cache_key(
        knowledge_base_version="v1",
        query="reentrancy",
        filter_category=None,
        filter_severity=None,
        n_results=5,
    )

    assert blank_strategy == default_strategy


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


@pytest.mark.parametrize("cache_key", [None, ["a"], "bad\nkey", ""])
def test_get_cached_result_rejects_malformed_cache_key(cache_key):
    cache = {"a": (time.time(), [1])}

    result, hit, expired = get_cached_result(cache, cache_key, enabled=True, ttl_seconds=30)  # type: ignore[arg-type]

    assert result is None
    assert hit is False
    assert expired is False
    assert "a" in cache


@pytest.mark.parametrize("entry", [None, [time.time()], (time.time(), [1], "extra"), "bad"])
def test_get_cached_result_evicts_malformed_entry_shape(entry):
    cache = {"a": entry}

    result, hit, expired = get_cached_result(cache, "a", enabled=True, ttl_seconds=30)

    assert result is None
    assert hit is False
    assert expired is True
    assert "a" not in cache


@pytest.mark.parametrize("timestamp", [None, "bad", float("nan"), float("inf"), -1])
def test_get_cached_result_evicts_malformed_timestamp(timestamp):
    cache = {"a": (timestamp, [1])}

    result, hit, expired = get_cached_result(cache, "a", enabled=True, ttl_seconds=30)

    assert result is None
    assert hit is False
    assert expired is True
    assert "a" not in cache


@pytest.mark.parametrize("results", [None, {"result": 1}, (1, 2), "not-list"])
def test_get_cached_result_evicts_malformed_results_container(results):
    cache = {"a": (time.time(), results)}

    result, hit, expired = get_cached_result(cache, "a", enabled=True, ttl_seconds=30)

    assert result is None
    assert hit is False
    assert expired is True
    assert "a" not in cache


@pytest.mark.parametrize("ttl_seconds", [0, -1, None, "bad", float("nan"), float("inf")])
def test_get_cached_result_normalizes_malformed_ttl_to_expired(ttl_seconds):
    cache = {"a": (time.time() - 1, [1])}

    result, hit, expired = get_cached_result(cache, "a", enabled=True, ttl_seconds=ttl_seconds)  # type: ignore[arg-type]

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


@pytest.mark.parametrize("cache_key", [None, ["a"], "bad\nkey", ""])
def test_store_cached_result_rejects_malformed_cache_key(cache_key):
    cache = {}

    assert store_cached_result(cache, cache_key, [1], enabled=True, max_size=10) is False  # type: ignore[arg-type]
    assert cache == {}


@pytest.mark.parametrize("results", [None, {"result": 1}, (1, 2), "not-list"])
def test_store_cached_result_rejects_malformed_results_container(results):
    cache = {}

    assert store_cached_result(cache, "a", results, enabled=True, max_size=10) is False  # type: ignore[arg-type]
    assert cache == {}


@pytest.mark.parametrize("max_size", [0, -1, None, "bad", True])
def test_store_cached_result_defaults_malformed_max_size(max_size):
    cache = {"old": (1.0, ["old"])}

    assert store_cached_result(cache, "new", ["new"], enabled=True, max_size=max_size) is True  # type: ignore[arg-type]

    assert cache == {"new": cache["new"]}


def test_store_cached_result_evicts_malformed_entries_first():
    cache = {
        "malformed": "bad",
        "valid": (2.0, ["valid"]),
    }

    store_cached_result(cache, "latest", ["latest"], enabled=True, max_size=2)

    assert "malformed" not in cache
    assert "valid" in cache
    assert "latest" in cache


def test_cache_stats_formats_hit_rate():
    assert cache_stats(hits=1, misses=3, cache_size=2, max_size=10) == {
        "hits": 1,
        "misses": 3,
        "hit_rate": "25.0%",
        "cache_size": 2,
        "max_size": 10,
    }


def test_cache_stats_normalizes_negative_and_malformed_scalars():
    assert cache_stats(hits=-1, misses="bad", cache_size=float("inf"), max_size=True) == {
        "hits": 0,
        "misses": 0,
        "hit_rate": "0.0%",
        "cache_size": 0,
        "max_size": 0,
    }


def test_cache_stats_normalizes_numeric_strings_and_nan():
    assert cache_stats(hits="2", misses=math.nan, cache_size="3", max_size="5") == {
        "hits": 2,
        "misses": 0,
        "hit_rate": "100.0%",
        "cache_size": 3,
        "max_size": 5,
    }


def test_build_metadata_filter():
    assert build_metadata_filter(None, None) is None
    assert build_metadata_filter("reentrancy", None) == {"category": "reentrancy"}
    assert build_metadata_filter(None, "high") == {"severity": "high"}
    assert build_metadata_filter("reentrancy", "high") == {
        "$and": [{"category": "reentrancy"}, {"severity": "high"}]
    }


def test_build_metadata_filter_bounds_long_values():
    assert build_metadata_filter("c" * 140, "s" * 140) == {
        "$and": [{"category": "c" * 120}, {"severity": "s" * 120}]
    }


def test_build_metadata_filter_normalizes_whitespace_only_values():
    assert build_metadata_filter(" \t ", " \n ") is None


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


@pytest.mark.parametrize("max_json_chars", [0, -1, None, "bad", True])
def test_parse_repaired_json_object_defaults_malformed_max_json_chars(max_json_chars):
    assert parse_repaired_json_object('{"ok": true}', max_json_chars=max_json_chars) == {"ok": True}  # type: ignore[arg-type]


def test_parse_repaired_json_object_rejects_control_char_boundaries():
    assert parse_repaired_json_object('{"ok": "bad\x00value"}') == {}
    assert parse_repaired_json_object('{"ok": "bad\x7fvalue"}') == {}


def test_parse_repaired_json_object_rejects_list_candidate_after_prose():
    content = 'analysis follows:\n[{"category": "reentrancy"}]'

    assert parse_repaired_json_object(content) == {}
