"""
LLM Analysis Cache for MIESC
=============================

Caches LLM analysis results to avoid re-analyzing identical code.
Uses content-based hashing with configurable TTL.

Features:
- File-based cache with JSON storage
- Content hash-based lookup
- TTL (Time-To-Live) support
- Cache statistics
- Automatic cleanup

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Institution: UNDEF - IUA
Date: January 2026
"""

import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """A cached analysis result."""

    code_hash: str
    analysis_type: str
    result: Any
    created_at: float
    expires_at: float
    model: str
    hit_count: int = 0
    last_accessed: float = 0


@dataclass
class CacheStats:
    """Cache statistics."""

    total_entries: int
    hits: int
    misses: int
    hit_rate: float
    size_bytes: int
    oldest_entry: Optional[str]
    newest_entry: Optional[str]


class LLMAnalysisCache:
    """
    File-based cache for LLM analysis results.

    Stores analysis results keyed by content hash and analysis type.
    Supports TTL-based expiration and automatic cleanup.

    Usage:
        cache = LLMAnalysisCache(cache_dir=".miesc_cache")

        # Try cache first
        cached = cache.get_cached(code_hash, "vulnerability_analysis")
        if cached:
            return cached

        # Perform analysis
        result = await llm.analyze(code)

        # Store in cache
        cache.cache_result(code_hash, "vulnerability_analysis", result)
    """

    DEFAULT_TTL = 86400  # 24 hours
    DEFAULT_MAX_ENTRIES = 1000

    def __init__(
        self,
        cache_dir: str = ".miesc_cache",
        ttl_seconds: int = DEFAULT_TTL,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        auto_cleanup: bool = True,
    ):
        """
        Initialize the cache.

        Args:
            cache_dir: Directory for cache files
            ttl_seconds: Time-to-live for cache entries
            max_entries: Maximum number of entries to keep
            auto_cleanup: Automatically cleanup expired entries
        """
        self.cache_dir = Path(cache_dir)
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self.auto_cleanup = auto_cleanup

        # Statistics
        self._hits = 0
        self._misses = 0
        self._lock = Lock()

        # Create cache directory
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Create index file if not exists
        self._index_file = self.cache_dir / "index.json"
        if not self._index_file.exists():
            self._save_index({})

        logger.info(
            f"LLMAnalysisCache initialized at {cache_dir} "
            f"(ttl={ttl_seconds}s, max={max_entries})"
        )

        # Cleanup on init
        if auto_cleanup:
            self.cleanup_expired()

    def get_cached(
        self,
        code_hash: str,
        analysis_type: str,
    ) -> Optional[Any]:
        """
        Get cached analysis result.

        Args:
            code_hash: Hash of the code content
            analysis_type: Type of analysis (e.g., "vulnerability", "severity")

        Returns:
            Cached result or None if not found/expired
        """
        cache_key = self._make_key(code_hash, analysis_type)
        cache_file = self.cache_dir / f"{cache_key}.json"

        if not cache_file.exists():
            self._misses += 1
            return None

        try:
            with self._lock:
                data = json.loads(cache_file.read_text())
                entry = CacheEntry(**data)

                # Check expiration
                if time.time() > entry.expires_at:
                    logger.debug(f"Cache entry expired: {cache_key}")
                    cache_file.unlink(missing_ok=True)
                    self._misses += 1
                    return None

                # Update access stats
                entry.hit_count += 1
                entry.last_accessed = time.time()
                cache_file.write_text(json.dumps(asdict(entry)))

                self._hits += 1
                logger.debug(f"Cache hit: {cache_key}")
                return entry.result

        except (json.JSONDecodeError, TypeError, KeyError) as e:
            logger.warning(f"Cache read error for {cache_key}: {e}")
            cache_file.unlink(missing_ok=True)
            self._misses += 1
            return None

    def cache_result(
        self,
        code_hash: str,
        analysis_type: str,
        result: Any,
        model: str = "unknown",
        ttl: Optional[int] = None,
    ) -> bool:
        """
        Cache an analysis result.

        Args:
            code_hash: Hash of the code content
            analysis_type: Type of analysis
            result: The result to cache
            model: Model used for analysis
            ttl: Custom TTL (uses default if None)

        Returns:
            True if cached successfully
        """
        cache_key = self._make_key(code_hash, analysis_type)
        cache_file = self.cache_dir / f"{cache_key}.json"

        now = time.time()
        entry = CacheEntry(
            code_hash=code_hash,
            analysis_type=analysis_type,
            result=result,
            created_at=now,
            expires_at=now + (ttl or self.ttl),
            model=model,
            hit_count=0,
            last_accessed=now,
        )

        try:
            with self._lock:
                cache_file.write_text(json.dumps(asdict(entry), default=str))

                # Update index
                index = self._load_index()
                index[cache_key] = {
                    "created": now,
                    "type": analysis_type,
                    "model": model,
                }
                self._save_index(index)

            logger.debug(f"Cached result: {cache_key}")

            # Cleanup if over limit
            if self.auto_cleanup and len(index) > self.max_entries:
                self._cleanup_oldest(len(index) - self.max_entries)

            return True

        except Exception as e:
            logger.warning(f"Cache write error for {cache_key}: {e}")
            return False

    def invalidate(
        self,
        code_hash: str,
        analysis_type: Optional[str] = None,
    ) -> int:
        """
        Invalidate cache entries.

        Args:
            code_hash: Hash of code to invalidate
            analysis_type: Specific type to invalidate (all if None)

        Returns:
            Number of entries invalidated
        """
        count = 0

        with self._lock:
            index = self._load_index()
            keys_to_remove = []

            for key in index:
                if key.startswith(code_hash):
                    if analysis_type is None or f"_{analysis_type}" in key:
                        cache_file = self.cache_dir / f"{key}.json"
                        cache_file.unlink(missing_ok=True)
                        keys_to_remove.append(key)
                        count += 1

            for key in keys_to_remove:
                del index[key]

            self._save_index(index)

        logger.info(f"Invalidated {count} cache entries for {code_hash}")
        return count

    def cleanup_expired(self) -> int:
        """
        Remove expired cache entries.

        Returns:
            Number of entries removed
        """
        count = 0
        now = time.time()

        with self._lock:
            index = self._load_index()
            keys_to_remove = []

            for key in index:
                cache_file = self.cache_dir / f"{key}.json"
                if cache_file.exists():
                    try:
                        data = json.loads(cache_file.read_text())
                        if now > data.get("expires_at", 0):
                            cache_file.unlink()
                            keys_to_remove.append(key)
                            count += 1
                    except Exception:
                        # Remove corrupted entries
                        cache_file.unlink(missing_ok=True)
                        keys_to_remove.append(key)
                        count += 1
                else:
                    keys_to_remove.append(key)

            for key in keys_to_remove:
                if key in index:
                    del index[key]

            self._save_index(index)

        if count > 0:
            logger.info(f"Cleaned up {count} expired cache entries")

        return count

    def clear(self) -> int:
        """
        Clear all cache entries.

        Returns:
            Number of entries removed
        """
        count = 0

        with self._lock:
            for cache_file in self.cache_dir.glob("*.json"):
                if cache_file.name != "index.json":
                    cache_file.unlink()
                    count += 1

            self._save_index({})

        logger.info(f"Cleared {count} cache entries")
        return count

    def get_stats(self) -> CacheStats:
        """Get cache statistics."""
        index = self._load_index()

        # Calculate size
        size = sum(f.stat().st_size for f in self.cache_dir.glob("*.json") if f.exists())

        # Find oldest/newest
        oldest = None
        newest = None
        oldest_time = float("inf")
        newest_time = 0

        for key, meta in index.items():
            created = meta.get("created", 0)
            if created < oldest_time:
                oldest_time = created
                oldest = key
            if created > newest_time:
                newest_time = created
                newest = key

        total = self._hits + self._misses
        hit_rate = self._hits / total if total > 0 else 0.0

        return CacheStats(
            total_entries=len(index),
            hits=self._hits,
            misses=self._misses,
            hit_rate=hit_rate,
            size_bytes=size,
            oldest_entry=oldest,
            newest_entry=newest,
        )

    def _make_key(self, code_hash: str, analysis_type: str) -> str:
        """Create cache key from hash and type."""
        return f"{code_hash[:16]}_{analysis_type}"

    def _load_index(self) -> Dict[str, Any]:
        """Load the cache index."""
        try:
            if self._index_file.exists():
                return json.loads(self._index_file.read_text())
        except Exception as e:
            logger.warning(f"Failed to load cache index: {e}")
        return {}

    def _save_index(self, index: Dict[str, Any]) -> None:
        """Save the cache index."""
        try:
            self._index_file.write_text(json.dumps(index))
        except Exception as e:
            logger.warning(f"Failed to save cache index: {e}")

    def _cleanup_oldest(self, count: int) -> None:
        """Remove oldest entries."""
        index = self._load_index()

        # Sort by creation time
        sorted_keys = sorted(index.keys(), key=lambda k: index[k].get("created", 0))

        # Remove oldest
        removed = 0
        for key in sorted_keys[:count]:
            cache_file = self.cache_dir / f"{key}.json"
            cache_file.unlink(missing_ok=True)
            del index[key]
            removed += 1

        self._save_index(index)
        logger.debug(f"Removed {removed} oldest cache entries")


def hash_code(code: str) -> str:
    """
    Generate hash of code for cache key.

    Args:
        code: Source code to hash

    Returns:
        SHA-256 hash (first 32 chars)
    """
    # Normalize code (remove extra whitespace)
    normalized = " ".join(code.split())
    return hashlib.sha256(normalized.encode()).hexdigest()[:32]


def hash_finding(finding: Dict[str, Any]) -> str:
    """
    Generate hash of finding for deduplication.

    Args:
        finding: Finding dictionary

    Returns:
        Hash string
    """
    key_parts = [
        finding.get("type", ""),
        finding.get("severity", ""),
        str(finding.get("location", {})),
        finding.get("description", "")[:100],
    ]
    content = "|".join(key_parts)
    return hashlib.sha256(content.encode()).hexdigest()[:16]


# Singleton cache instance
_cache_instance: Optional[LLMAnalysisCache] = None


def get_cache(cache_dir: str = ".miesc_cache") -> LLMAnalysisCache:
    """
    Get the singleton cache instance.

    Args:
        cache_dir: Cache directory path

    Returns:
        LLMAnalysisCache instance
    """
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = LLMAnalysisCache(cache_dir=cache_dir)
    return _cache_instance


# Export
__all__ = [
    "LLMAnalysisCache",
    "CacheEntry",
    "CacheStats",
    "hash_code",
    "hash_finding",
    "get_cache",
]
