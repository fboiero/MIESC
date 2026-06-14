"""Tests for the shared LLMCacheMixin and GPTScan's adoption of it.

GPTScan previously had NO result cache and re-ran the LLM on every scan; it now
uses the shared mixin like the other LLM adapters.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from src.adapters._cache_mixin import LLMCacheMixin
from src.adapters.gptscan_adapter import GPTScanAdapter
from src.core.tool_protocol import ToolStatus


def test_cache_mixin_roundtrip_and_ttl(tmp_path):
    class _H(LLMCacheMixin):
        pass

    h = _H()
    h._init_cache("unit", ttl=1000)
    h._cache_dir = tmp_path
    assert h._get_cached_result("k") is None
    h._cache_result("k", {"status": "success", "findings": []})
    assert h._get_cached_result("k") == {"status": "success", "findings": []}


def test_gptscan_inherits_cache_mixin():
    assert issubclass(GPTScanAdapter, LLMCacheMixin)


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
