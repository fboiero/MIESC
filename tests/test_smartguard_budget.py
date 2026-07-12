"""SmartGuard per-contract time-budget: a single contract must not hang a scan.

SmartGuard makes one Ollama CoT call per RAG-matched function; on large contracts
that ran unbounded (40+ min). It now respects the runner's timeout.
"""

from __future__ import annotations

from unittest.mock import patch

from miesc.adapters.smartguard_adapter import SmartGuardAdapter
from miesc.core.tool_protocol import ToolStatus


def _patched(adapter, tmp_path):
    adapter._cache_dir = tmp_path
    code = "pragma solidity ^0.8.0; contract C { function a() public {} function b() public {} }"
    return patch.multiple(
        adapter,
        is_available=lambda: ToolStatus.AVAILABLE,
        _read_contract=lambda p: code,
        _get_cached=lambda k: None,
        _extract_functions=lambda c: [("a", "function a(){}"), ("b", "function b(){}")],
        _retrieve_similar_vulnerabilities=lambda fc: [{"vuln": "x"}],
        _analyze_with_cot=lambda fn, fc, sv, cp: [{"id": fn, "severity": "LOW", "title": "t"}],
    )


def test_time_budget_stops_loop_and_marks_partial(tmp_path):
    a = SmartGuardAdapter()
    with _patched(a, tmp_path):
        r = a.analyze("C.sol", timeout=0)  # budget exhausted immediately
    assert r["metadata"]["partial"] is True
    assert r["metadata"]["functions_analyzed"] == 0
    assert not list(tmp_path.glob("*.json"))  # partial result NOT cached


def test_normal_run_completes_and_caches(tmp_path):
    a = SmartGuardAdapter()
    with _patched(a, tmp_path):
        r = a.analyze("C.sol", timeout=300)
    assert r["metadata"]["partial"] is False
    assert r["metadata"]["functions_analyzed"] == 2
    assert list(tmp_path.glob("*.json"))  # complete result cached
