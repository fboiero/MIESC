"""--llm-timeout budget and the slowest-tools table (Product Excellence Plan, C4/B.6)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from miesc.cli import utils


@pytest.fixture(autouse=True)
def _clear_budget():
    utils.set_llm_timeout(None)
    yield
    utils.set_llm_timeout(None)


def test_budget_applies_only_to_llm_tools():
    with patch.object(utils.AdapterLoader, "llm_tools", return_value={"smartguard", "gptscan"}):
        assert utils.effective_tool_timeout("smartguard", 300) == 300
        utils.set_llm_timeout(45)
        assert utils.get_llm_timeout() == 45
        assert utils.effective_tool_timeout("smartguard", 300) == 45
        assert utils.effective_tool_timeout("slither", 300) == 300
        utils.set_llm_timeout(0)
        assert utils.get_llm_timeout() is None
        assert utils.effective_tool_timeout("gptscan", 120) == 120


def test_run_tool_hands_the_budget_to_llm_adapters(tmp_path):
    contract = tmp_path / "c.sol"
    contract.write_text("pragma solidity ^0.8.0;\ncontract C {}\n")
    seen = {}

    class FakeAdapter:
        def analyze(self, path, timeout=None, **kwargs):
            seen["timeout"] = timeout
            return {"tool": "smartguard", "status": "success", "findings": []}

    from miesc.core.tool_protocol import ToolStatus

    utils.set_llm_timeout(30)
    with patch.object(utils.AdapterLoader, "llm_tools", return_value={"smartguard"}):
        with patch.object(utils.AdapterLoader, "get_adapter", return_value=FakeAdapter()):
            with patch.object(
                utils.AdapterLoader, "get_availability", return_value=ToolStatus.AVAILABLE
            ):
                result = utils.run_tool("smartguard", str(contract), 600)
    assert seen["timeout"] == 30
    assert result["timeout_budget_s"] == 30


def test_print_tool_timing_plain_output(capsys):
    results = [
        {"tool": "slither", "status": "success", "execution_time": 0.8},
        {"tool": "smartguard", "status": "success", "execution_time": 42.5, "timeout_budget_s": 60},
        {"tool": "wake", "status": "skipped", "reason": "not_installed", "execution_time": 0},
    ]
    with patch.object(utils, "RICH_AVAILABLE", False):
        utils.print_tool_timing(results)
    out = capsys.readouterr().out
    assert "Slowest tools (of 2" in out
    assert out.index("smartguard") < out.index("slither")  # sorted by time, slowest first
    assert "wake" not in out  # skipped tools are not timing
    assert "budget=60" in out


def test_print_tool_timing_handles_empty(capsys):
    with patch.object(utils, "RICH_AVAILABLE", False):
        utils.print_tool_timing([])
        utils.print_tool_timing([{"tool": "x", "execution_time": "n/a"}])
    assert capsys.readouterr().out == ""


def test_ml_orchestrator_applies_budget_to_llm_adapters(tmp_path):
    from types import SimpleNamespace

    from miesc.core.ml_orchestrator import MLOrchestrator

    contract = tmp_path / "c.sol"
    contract.write_text("pragma solidity ^0.8.0;\ncontract C {}\n")
    seen = {}

    class FakeLLMAdapter:
        def get_metadata(self):
            return SimpleNamespace(requires_llm=True)

        def is_available(self):
            return "available"

        def analyze(self, path, timeout=None, **kwargs):
            seen["timeout"] = timeout
            return {"tool": "fake_llm", "status": "success", "findings": []}

    orch = MLOrchestrator(ml_enabled=False, cache_enabled=False)
    utils.set_llm_timeout(25)
    with patch.object(orch.discovery, "load_adapter", return_value=FakeLLMAdapter()):
        with patch.object(
            orch.config, "get_adapter_config", return_value=SimpleNamespace(timeout=None)
        ):
            result = orch._run_tool("fake_llm", str(contract), 300)
    assert seen["timeout"] == 25
    assert result["timeout_budget_s"] == 25


def test_ml_orchestrator_marks_cache_hits(tmp_path):
    from miesc.core.ml_orchestrator import MLOrchestrator

    orch = MLOrchestrator(ml_enabled=False, cache_enabled=True)
    stored = {"tool": "slither", "status": "success", "findings": [], "execution_time": 42.0}
    with patch.object(orch.cache, "get", return_value=stored):
        hit = orch._run_tool("slither", str(tmp_path / "c.sol"), 60)
    assert hit["from_cache"] is True
    assert "from_cache" not in stored  # the cached record itself is untouched
    # and the timing table reports it as cached, outside the run's total
    with patch.object(utils, "RICH_AVAILABLE", False):
        utils.print_tool_timing(
            [hit, {"tool": "aderyn", "status": "success", "execution_time": 1.5}]
        )
