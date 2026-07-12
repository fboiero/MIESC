"""Tests for the shared LLMCacheMixin and GPTScan's adoption of it.

GPTScan previously had NO result cache and re-ran the LLM on every scan; it now
uses the shared mixin like the other LLM adapters.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from unittest.mock import patch

from miesc.adapters._cache_mixin import LLMCacheMixin
from miesc.adapters.gptscan_adapter import GPTScanAdapter
from src.core.tool_protocol import ToolStatus


def _harness(tmp_path, ttl=1000):
    class _H(LLMCacheMixin):
        pass

    h = _H()
    h._init_cache("unit", ttl=ttl)
    h._cache_dir = tmp_path
    return h


def test_cache_mixin_roundtrip_and_ttl(tmp_path):
    class _H(LLMCacheMixin):
        pass

    h = _H()
    h._init_cache("unit", ttl=1000)
    h._cache_dir = tmp_path
    assert h._get_cached_result("k") is None
    h._cache_result("k", {"status": "success", "findings": []})
    assert h._get_cached_result("k") == {"status": "success", "findings": []}


def test_expired_entry_is_deleted(tmp_path):
    h = _harness(tmp_path, ttl=10)
    h._cache_result("k", {"status": "success"})
    cache_file = tmp_path / "k.json"
    old = time.time() - 100
    os.utime(cache_file, (old, old))
    assert h._get_cached_result("k") is None
    assert not cache_file.exists()  # stale entry purged


def test_corrupt_entry_is_deleted(tmp_path):
    h = _harness(tmp_path, ttl=1000)
    bad = tmp_path / "bad.json"
    bad.write_text("{ not valid json", encoding="utf-8")
    assert h._get_cached_result("bad") is None
    assert not bad.exists()  # corrupt entry purged


def test_read_error_returns_none(tmp_path):
    h = _harness(tmp_path, ttl=1000)
    h._cache_result("k", {"status": "success"})
    with patch("miesc.adapters._cache_mixin.json.load", side_effect=RuntimeError("boom")):
        assert h._get_cached_result("k") is None  # generic error swallowed


def test_write_error_is_swallowed(tmp_path):
    h = _harness(tmp_path, ttl=1000)
    # A set is not JSON-serializable → json.dump raises mid-write; must not propagate.
    h._cache_result("k", {"bad": {1, 2, 3}})


def test_gptscan_inherits_cache_mixin():
    assert issubclass(GPTScanAdapter, LLMCacheMixin)


def test_gptscan_init_sets_rag_attributes():
    """Regression: _use_rag/_embedding_rag were dead code after a return in
    _get_cache_key, so __init__ never set them and _run_ollama_analysis crashed
    with AttributeError on every scan. The existing tests missed it because they
    mock _run_ollama_analysis (the very method that read the attribute).
    """
    adapter = GPTScanAdapter()
    assert hasattr(adapter, "_use_rag")
    assert hasattr(adapter, "_embedding_rag")
    # the exact access that used to raise AttributeError must be safe now
    _ = adapter._use_rag and adapter._embedding_rag


def test_gptscan_second_scan_hits_cache(tmp_path):
    adapter = GPTScanAdapter()
    adapter._cache_dir = tmp_path
    contract = tmp_path / "C.sol"
    contract.write_text("pragma solidity ^0.8.0; contract C {}")

    calls = {"n": 0}

    def _analysis(code, model, timeout):
        calls["n"] += 1
        return '{"vulnerabilities":[{"title":"X","severity":"high","type":"reentrancy"}]}'

    with (
        patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE),
        patch.object(adapter, "_detect_best_model", return_value="m"),
        patch.object(adapter, "_run_ollama_analysis", side_effect=_analysis),
    ):
        r1 = adapter.analyze(str(contract))
        r2 = adapter.analyze(str(contract))

    assert r1["from_cache"] is False
    assert r2["from_cache"] is True
    assert calls["n"] == 1  # LLM ran only once; second scan served from cache


def test_cache_disabled_env_parsing():
    from miesc.adapters._cache_mixin import _cache_disabled

    for val in ("1", "true", "TRUE", "yes", " Yes "):
        with patch.dict(os.environ, {"MIESC_DISABLE_LLM_CACHE": val}):
            assert _cache_disabled() is True
    for val in ("", "0", "false", "no", "off"):
        with patch.dict(os.environ, {"MIESC_DISABLE_LLM_CACHE": val}):
            assert _cache_disabled() is False
    with patch.dict(os.environ, {}, clear=True):
        assert _cache_disabled() is False


def test_bypass_skips_read_even_when_entry_exists(tmp_path):
    """With the bypass on, a fresh cached entry must NOT be served (variance runs)."""
    h = _harness(tmp_path, ttl=1000)
    h._cache_result("k", {"status": "success"})
    assert h._get_cached_result("k") == {"status": "success"}  # baseline: cache hits
    with patch.dict(os.environ, {"MIESC_DISABLE_LLM_CACHE": "1"}):
        assert h._get_cached_result("k") is None  # bypass forces a miss


def test_bypass_skips_write(tmp_path):
    """With the bypass on, results must not be written to disk."""
    h = _harness(tmp_path, ttl=1000)
    with patch.dict(os.environ, {"MIESC_DISABLE_LLM_CACHE": "1"}):
        h._cache_result("k", {"status": "success"})
    assert not list(Path(tmp_path).glob("*.json"))  # nothing persisted
    # and once the bypass is off, caching resumes normally
    h._cache_result("k", {"status": "success"})
    assert (tmp_path / "k.json").exists()


def test_gptscan_timeout_not_cached(tmp_path):
    """A timed-out run must NOT be cached (so it re-runs next time)."""
    adapter = GPTScanAdapter()
    adapter._cache_dir = tmp_path
    contract = tmp_path / "C.sol"
    contract.write_text("pragma solidity ^0.8.0; contract C {}")

    def _timeout(code, model, timeout):
        adapter._timed_out = True
        return ""

    with (
        patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE),
        patch.object(adapter, "_detect_best_model", return_value="m"),
        patch.object(adapter, "_run_ollama_analysis", side_effect=_timeout),
    ):
        r = adapter.analyze(str(contract))

    assert r["status"] == "timeout"
    assert not list(Path(tmp_path).glob("*.json"))  # nothing cached
