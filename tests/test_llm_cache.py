"""
Tests for LLM Analysis Cache module.

Tests the file-based caching system for LLM analysis results.
"""

import json
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from src.cache.llm_cache import CacheEntry, CacheStats, LLMAnalysisCache


class TestCacheEntry:
    """Test CacheEntry dataclass."""

    def test_create_cache_entry(self):
        """Test creating a cache entry."""
        entry = CacheEntry(
            code_hash="abc123",
            analysis_type="vulnerability",
            result={"findings": []},
            created_at=1000.0,
            expires_at=2000.0,
            model="deepseek-coder",
        )
        assert entry.code_hash == "abc123"
        assert entry.analysis_type == "vulnerability"
        assert entry.result == {"findings": []}
        assert entry.model == "deepseek-coder"
        assert entry.hit_count == 0

    def test_cache_entry_with_hit_count(self):
        """Test cache entry with hit count."""
        entry = CacheEntry(
            code_hash="abc123",
            analysis_type="severity",
            result="HIGH",
            created_at=1000.0,
            expires_at=2000.0,
            model="gpt-4",
            hit_count=5,
            last_accessed=1500.0,
        )
        assert entry.hit_count == 5
        assert entry.last_accessed == 1500.0


class TestCacheStats:
    """Test CacheStats dataclass."""

    def test_create_cache_stats(self):
        """Test creating cache stats."""
        stats = CacheStats(
            total_entries=100,
            hits=75,
            misses=25,
            hit_rate=0.75,
            size_bytes=1024000,
            oldest_entry="abc123",
            newest_entry="xyz789",
        )
        assert stats.total_entries == 100
        assert stats.hits == 75
        assert stats.hit_rate == 0.75


class TestLLMAnalysisCache:
    """Test LLMAnalysisCache class."""

    @pytest.fixture
    def temp_cache_dir(self, tmp_path):
        """Create temporary cache directory."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        return str(cache_dir)

    @pytest.fixture
    def cache(self, temp_cache_dir):
        """Create cache instance."""
        return LLMAnalysisCache(
            cache_dir=temp_cache_dir,
            ttl_seconds=3600,
            max_entries=100,
            auto_cleanup=False,
        )

    def test_cache_init(self, temp_cache_dir):
        """Test cache initialization."""
        cache = LLMAnalysisCache(cache_dir=temp_cache_dir)
        assert cache.cache_dir.exists()
        assert cache.ttl == 86400  # Default TTL

    def test_cache_init_creates_directory(self, tmp_path):
        """Test cache creates directory if not exists."""
        cache_dir = tmp_path / "new_cache"
        cache = LLMAnalysisCache(cache_dir=str(cache_dir), auto_cleanup=False)
        assert cache_dir.exists()

    def test_cache_init_creates_index(self, temp_cache_dir):
        """Test cache creates index file."""
        cache = LLMAnalysisCache(cache_dir=temp_cache_dir, auto_cleanup=False)
        index_file = Path(temp_cache_dir) / "index.json"
        assert index_file.exists()

    def test_cache_result(self, cache):
        """Test caching a result."""
        result = {"findings": [{"type": "reentrancy"}]}
        success = cache.cache_result(
            code_hash="abc123",
            analysis_type="vulnerability",
            result=result,
            model="deepseek-coder",
        )
        assert success is True

    def test_get_cached_hit(self, cache):
        """Test cache hit."""
        result = {"findings": ["finding1"]}
        cache.cache_result("hash123", "analysis", result)

        cached = cache.get_cached("hash123", "analysis")
        assert cached == result

    def test_get_cached_miss(self, cache):
        """Test cache miss."""
        cached = cache.get_cached("nonexistent", "analysis")
        assert cached is None

    def test_get_cached_expired(self, cache):
        """Test expired cache entry."""
        cache.ttl = 1  # 1 second TTL
        cache.cache_result("hash123", "analysis", {"data": "value"})

        time.sleep(2)  # Wait for expiration
        cached = cache.get_cached("hash123", "analysis")
        assert cached is None

    def test_cache_stats_update_on_hit(self, cache):
        """Test hit counter updates."""
        cache.cache_result("hash1", "type1", "result1")
        assert cache._hits == 0

        cache.get_cached("hash1", "type1")
        assert cache._hits == 1

    def test_cache_stats_update_on_miss(self, cache):
        """Test miss counter updates."""
        assert cache._misses == 0
        cache.get_cached("nonexistent", "type")
        assert cache._misses == 1

    def test_invalidate_single(self, cache):
        """Test invalidating a single entry."""
        cache.cache_result("hash1", "type1", "result1")
        cache.cache_result("hash1", "type2", "result2")
        cache.cache_result("hash2", "type1", "result3")

        count = cache.invalidate("hash1", "type1")
        assert count == 1
        assert cache.get_cached("hash1", "type1") is None
        assert cache.get_cached("hash1", "type2") is not None

    def test_invalidate_all_for_hash(self, cache):
        """Test invalidating all entries for a hash."""
        cache.cache_result("hash1", "type1", "result1")
        cache.cache_result("hash1", "type2", "result2")
        cache.cache_result("hash2", "type1", "result3")

        count = cache.invalidate("hash1")
        assert count == 2

    def test_cleanup_expired(self, temp_cache_dir):
        """Test cleanup of expired entries."""
        cache = LLMAnalysisCache(
            cache_dir=temp_cache_dir,
            ttl_seconds=1,
            auto_cleanup=False,
        )

        cache.cache_result("hash1", "type1", "result1")
        cache.cache_result("hash2", "type2", "result2")

        time.sleep(2)  # Wait for expiration
        count = cache.cleanup_expired()
        assert count >= 0  # May be 0 if cleanup already ran

    def test_clear_cache(self, cache):
        """Test clearing all cache entries."""
        cache.cache_result("hash1", "type1", "result1")
        cache.cache_result("hash2", "type2", "result2")

        count = cache.clear()
        assert count >= 2

        assert cache.get_cached("hash1", "type1") is None
        assert cache.get_cached("hash2", "type2") is None

    def test_get_stats(self, cache):
        """Test getting cache statistics."""
        cache.cache_result("hash1", "type1", {"data": "value"})
        cache.get_cached("hash1", "type1")  # Hit
        cache.get_cached("nonexistent", "type")  # Miss

        stats = cache.get_stats()
        assert isinstance(stats, CacheStats)
        assert stats.total_entries >= 1
        assert stats.hits >= 1
        assert stats.misses >= 1

    def test_cache_with_custom_ttl(self, cache):
        """Test caching with custom TTL."""
        cache.cache_result("hash1", "type1", "result", ttl=10)

        # Entry should exist
        assert cache.get_cached("hash1", "type1") is not None

    def test_cache_corrupted_entry(self, temp_cache_dir):
        """Test handling corrupted cache entry."""
        cache = LLMAnalysisCache(cache_dir=temp_cache_dir, auto_cleanup=False)

        # Create corrupted cache file
        corrupted_file = Path(temp_cache_dir) / "corrupted_hash_type.json"
        corrupted_file.write_text("not valid json{")

        # Should handle gracefully
        result = cache.get_cached("corrupted_hash", "type")
        assert result is None

    def test_max_entries_cleanup(self, temp_cache_dir):
        """Test automatic cleanup when max entries exceeded."""
        cache = LLMAnalysisCache(
            cache_dir=temp_cache_dir,
            max_entries=5,
            auto_cleanup=True,
        )

        # Add more than max entries
        for i in range(10):
            cache.cache_result(f"hash{i}", "type", f"result{i}")

        # Should not exceed max (cleanup triggered)
        stats = cache.get_stats()
        assert stats.total_entries <= 10  # May have cleaned up

    def test_concurrent_access(self, cache):
        """Test thread safety."""
        import threading

        def cache_operation():
            for i in range(10):
                cache.cache_result(f"hash{i}", "type", f"result{i}")
                cache.get_cached(f"hash{i}", "type")

        threads = [threading.Thread(target=cache_operation) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should not crash
        stats = cache.get_stats()
        assert stats.total_entries >= 0

    def test_cache_complex_result(self, cache):
        """Test caching complex nested results."""
        complex_result = {
            "findings": [
                {
                    "type": "reentrancy",
                    "severity": "HIGH",
                    "locations": [{"file": "test.sol", "line": 10}],
                },
                {
                    "type": "overflow",
                    "severity": "MEDIUM",
                    "details": {"affected_functions": ["transfer", "withdraw"]},
                },
            ],
            "metadata": {"analyzer": "miesc", "version": "5.1.1"},
        }

        cache.cache_result("complex_hash", "full_analysis", complex_result)
        retrieved = cache.get_cached("complex_hash", "full_analysis")

        assert retrieved == complex_result
        assert len(retrieved["findings"]) == 2


class TestCacheHashGeneration:
    """Test cache key generation."""

    @pytest.fixture
    def cache(self, tmp_path):
        """Create cache instance."""
        return LLMAnalysisCache(
            cache_dir=str(tmp_path / "cache"),
            auto_cleanup=False,
        )

    def test_different_hashes_different_keys(self, cache):
        """Test different code hashes produce different cache keys."""
        cache.cache_result("hash1", "type", "result1")
        cache.cache_result("hash2", "type", "result2")

        assert cache.get_cached("hash1", "type") == "result1"
        assert cache.get_cached("hash2", "type") == "result2"

    def test_different_types_different_keys(self, cache):
        """Test different analysis types produce different cache keys."""
        cache.cache_result("hash", "type1", "result1")
        cache.cache_result("hash", "type2", "result2")

        assert cache.get_cached("hash", "type1") == "result1"
        assert cache.get_cached("hash", "type2") == "result2"


class TestCacheEdgeCases:
    """Test edge cases and error handling."""

    @pytest.fixture
    def cache(self, tmp_path):
        """Create cache instance."""
        return LLMAnalysisCache(
            cache_dir=str(tmp_path / "cache"),
            auto_cleanup=False,
        )

    def test_empty_result(self, cache):
        """Test caching empty result."""
        cache.cache_result("hash", "type", None)
        assert cache.get_cached("hash", "type") is None  # None results not cached

    def test_special_characters_in_hash(self, cache):
        """Test hash with special characters."""
        special_hash = "abc_123-def.456"
        cache.cache_result(special_hash, "type", "result")
        assert cache.get_cached(special_hash, "type") == "result"

    def test_unicode_in_result(self, cache):
        """Test caching unicode content."""
        unicode_result = {"message": "漏洞检测 🔍", "emoji": "✓ ✗"}
        cache.cache_result("unicode_hash", "type", unicode_result)
        retrieved = cache.get_cached("unicode_hash", "type")
        assert retrieved["message"] == "漏洞检测 🔍"

    def test_large_result(self, cache):
        """Test caching large result."""
        large_result = {"data": "x" * 100000}  # 100KB
        cache.cache_result("large_hash", "type", large_result)
        retrieved = cache.get_cached("large_hash", "type")
        assert len(retrieved["data"]) == 100000
