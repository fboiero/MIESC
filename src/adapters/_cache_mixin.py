"""Shared on-disk result cache for LLM adapters.

The LLM-layer adapters cache analysis results under ``~/.miesc/<name>_cache`` so
a re-scan of an unchanged contract does not re-run the (slow, sometimes paid)
model. Each adapter historically reimplemented the identical read/TTL/write
logic; GPTScan never got it at all and re-ran the LLM on every scan.

This mixin centralises that logic. Adapters call ``self._init_cache(name)`` in
``__init__`` and provide their own ``_get_cache_key`` (the key must include the
model(s) so a model change invalidates stale entries).
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import cast, Any, Dict, Optional

logger = logging.getLogger(__name__)

DEFAULT_CACHE_TTL = 86400  # 24 hours


def _cache_disabled() -> bool:
    """True when the on-disk LLM cache is disabled via env var.

    Set MIESC_DISABLE_LLM_CACHE=1 to force fresh model calls on every scan —
    required for variance experiments (e.g. the ablation's --runs N), where a
    cache hit would otherwise return an identical result and report SD=0.
    """
    return os.environ.get("MIESC_DISABLE_LLM_CACHE", "").strip().lower() in {"1", "true", "yes"}


class LLMCacheMixin:
    """File-backed, TTL'd result cache for adapters."""

    def _init_cache(self, name: str, ttl: int = DEFAULT_CACHE_TTL) -> None:
        self._cache_dir = Path.home() / ".miesc" / f"{name}_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache_ttl = ttl
        self._cache_name = name

    def _get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Return a fresh cached result, or None. Stale/corrupt entries deleted."""
        if _cache_disabled():
            return None
        cache_file = self._cache_dir / f"{cache_key}.json"
        if not cache_file.exists():
            return None
        try:
            if time.time() - cache_file.stat().st_mtime > self._cache_ttl:
                logger.info("%s: cache expired for %s", self._cache_name, cache_key[:16])
                cache_file.unlink(missing_ok=True)
                return None
            with open(cache_file, "r", encoding="utf-8") as f:
                return cast(dict[str, Any] | None, json.load(f))
        except json.JSONDecodeError:
            logger.warning("%s: corrupted cache file %s", self._cache_name, cache_file)
            cache_file.unlink(missing_ok=True)
            return None
        except Exception as e:  # noqa: BLE001 - cache is best-effort
            logger.error("%s: error reading cache: %s", self._cache_name, e)
            return None

    def _cache_result(self, cache_key: str, result: Dict[str, Any]) -> None:
        """Best-effort write of a result to the cache."""
        if _cache_disabled():
            return
        cache_file = self._cache_dir / f"{cache_key}.json"
        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            logger.info("%s: cached result for %s", self._cache_name, cache_key[:16])
        except Exception as e:  # noqa: BLE001 - cache is best-effort
            logger.error("%s: error writing cache: %s", self._cache_name, e)
