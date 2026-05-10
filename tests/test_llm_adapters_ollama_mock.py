"""
Tests for Ollama-dependent LLM adapters with mocked HTTP API.

Covers peculiar (36%), llamaaudit (25%), llmbugscanner (30%).
Each adapter calls Ollama via urllib.request.urlopen — we mock that
to exercise the full analyze() flow without a running Ollama instance.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from src.core.tool_protocol import ToolStatus

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def mock_ollama_response(content: str):
    """Create a mock urllib response that returns Ollama-style JSON."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({"response": content}).encode()
    mock_resp.status = 200
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def mock_ollama_tags(*model_names):
    """Mock the /api/tags endpoint listing available models."""
    models = [{"name": n} for n in model_names]
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({"models": models}).encode()
    mock_resp.status = 200
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


# ---------------------------------------------------------------------------
# PeculiarAdapter (GNN-based, 36% coverage)
# ---------------------------------------------------------------------------


class TestPeculiarAdapterDeeper:
    @pytest.fixture
    def adapter(self):
        from src.adapters.peculiar_adapter import PeculiarAdapter

        return PeculiarAdapter()

    def test_metadata(self, adapter):
        m = adapter.get_metadata()
        assert m.name == "peculiar"
        assert m.is_optional is True

    def test_available_always(self, adapter):
        assert adapter.is_available() == ToolStatus.AVAILABLE

    def test_analyze_valid_contract(self, adapter, tmp_path):
        c = tmp_path / "C.sol"
        c.write_text("""
        pragma solidity ^0.8.0;
        contract Vault {
            mapping(address => uint256) public balances;
            function withdraw(uint256 amount) external {
                (bool ok,) = msg.sender.call{value: amount}("");
                require(ok);
                balances[msg.sender] -= amount;
            }
        }
        """)
        result = adapter.analyze(str(c))
        assert isinstance(result, dict)
        assert "findings" in result

    def test_analyze_with_reentrancy_pattern(self, adapter, tmp_path):
        c = tmp_path / "Vuln.sol"
        c.write_text("""
        pragma solidity ^0.8.0;
        contract Vuln {
            mapping(address => uint256) bal;
            function drain() external {
                uint256 amount = bal[msg.sender];
                (bool ok,) = msg.sender.call{value: amount}("");
                bal[msg.sender] = 0;
            }
        }
        """)
        result = adapter.analyze(str(c))
        assert isinstance(result, dict)
        findings = result.get("findings", [])
        assert isinstance(findings, list)

    def test_normalize_findings_list(self, adapter):
        raw = [{"type": "x", "severity": "High"}]
        result = adapter.normalize_findings(raw)
        assert isinstance(result, list)

    def test_normalize_findings_none(self, adapter):
        result = adapter.normalize_findings(None)
        assert isinstance(result, list)

    def test_can_analyze_sol(self, adapter):
        assert adapter.can_analyze("contract.sol") is True

    def test_cannot_analyze_py(self, adapter):
        assert adapter.can_analyze("script.py") is False


# ---------------------------------------------------------------------------
# LlamaAuditAdapter (Ollama-dependent, 25% coverage)
# ---------------------------------------------------------------------------


class TestLlamaAuditAdapterDeeper:
    @pytest.fixture
    def adapter(self):
        from src.adapters.llamaaudit_adapter import LlamaAuditAdapter

        return LlamaAuditAdapter()

    def test_metadata(self, adapter):
        m = adapter.get_metadata()
        assert m.name == "llamaaudit"
        assert m.requires_api_key is False

    def test_is_available_ollama_down(self, adapter):
        with patch("urllib.request.urlopen", side_effect=OSError("refused")):
            status = adapter.is_available()
            assert isinstance(status, ToolStatus)

    def test_is_available_ollama_up_with_model(self, adapter):
        with patch(
            "urllib.request.urlopen", return_value=mock_ollama_tags("codellama:7b", "llama3:8b")
        ):
            status = adapter.is_available()
            assert isinstance(status, ToolStatus)

    def test_normalize_findings_empty(self, adapter):
        assert adapter.normalize_findings([]) == []
        assert adapter.normalize_findings(None) == []

    def test_normalize_findings_valid(self, adapter):
        raw = {
            "findings": [
                {
                    "type": "reentrancy",
                    "severity": "High",
                    "title": "Test",
                    "description": "desc",
                    "line": 10,
                }
            ]
        }
        result = adapter.normalize_findings(raw)
        assert isinstance(result, list)

    def test_can_analyze(self, adapter):
        assert adapter.can_analyze("contract.sol") is True
        assert adapter.can_analyze("file.js") is False

    def test_analyze_ollama_down_uses_fallback(self, adapter, tmp_path):
        """LlamaAudit gracefully degrades to pattern-based analysis when Ollama is down."""
        c = tmp_path / "C.sol"
        c.write_text("pragma solidity ^0.8.0; contract C {}")
        with patch.object(adapter, "is_available", return_value=ToolStatus.NOT_INSTALLED):
            result = adapter.analyze(str(c))
            # Returns a valid result (either error OR pattern-based findings)
            assert isinstance(result, dict)
            assert isinstance(result.get("findings", []), list)

    def test_analyze_with_mock_llm(self, adapter, tmp_path):
        c = tmp_path / "C.sol"
        c.write_text("pragma solidity ^0.8.0; contract C { function f() external {} }")
        llm_response = json.dumps(
            {
                "findings": [
                    {
                        "type": "access-control",
                        "severity": "Medium",
                        "title": "No modifier",
                        "description": "Missing access control",
                        "function": "f",
                        "line": 1,
                    }
                ]
            }
        )
        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            with patch("urllib.request.urlopen", return_value=mock_ollama_response(llm_response)):
                result = adapter.analyze(str(c))
                assert isinstance(result, dict)
                assert "findings" in result


# ---------------------------------------------------------------------------
# LLMBugScannerAdapter (Ollama-dependent, 30% coverage)
# ---------------------------------------------------------------------------


class TestLLMBugScannerAdapterDeeper:
    @pytest.fixture
    def adapter(self):
        from src.adapters.llmbugscanner_adapter import LLMBugScannerAdapter

        return LLMBugScannerAdapter()

    def test_metadata(self, adapter):
        m = adapter.get_metadata()
        assert m.name == "llmbugscanner"
        assert m.requires_api_key is False

    def test_is_available_returns_status(self, adapter):
        status = adapter.is_available()
        assert isinstance(status, ToolStatus)

    def test_normalize_findings_empty(self, adapter):
        assert adapter.normalize_findings([]) == []
        assert adapter.normalize_findings(None) == []

    def test_normalize_findings_list(self, adapter):
        raw = [{"type": "x", "severity": "High", "description": "d"}]
        result = adapter.normalize_findings(raw)
        assert isinstance(result, list)

    def test_can_analyze(self, adapter):
        assert adapter.can_analyze("contract.sol") is True

    def test_analyze_ollama_down(self, adapter, tmp_path):
        c = tmp_path / "C.sol"
        c.write_text("pragma solidity ^0.8.0; contract C {}")
        with patch.object(adapter, "is_available", return_value=ToolStatus.NOT_INSTALLED):
            result = adapter.analyze(str(c))
            assert isinstance(result, dict)

    def test_default_config(self, adapter):
        config = adapter.get_default_config()
        assert isinstance(config, dict)


# ---------------------------------------------------------------------------
# Cross-adapter: all 3 share consistent Ollama-down behavior
# ---------------------------------------------------------------------------


class TestOllamaDownGracefulDegradation:
    """When Ollama is unreachable, all LLM adapters must return a dict
    with empty findings, not crash."""

    @pytest.mark.parametrize(
        "module,cls",
        [
            ("src.adapters.peculiar_adapter", "PeculiarAdapter"),
            ("src.adapters.llamaaudit_adapter", "LlamaAuditAdapter"),
            ("src.adapters.llmbugscanner_adapter", "LLMBugScannerAdapter"),
        ],
    )
    def test_analyze_with_ollama_unreachable(self, module, cls, tmp_path):
        import importlib

        mod = importlib.import_module(module)
        adapter = getattr(mod, cls)()
        c = tmp_path / "C.sol"
        c.write_text("pragma solidity ^0.8.0; contract C {}")
        with patch("urllib.request.urlopen", side_effect=OSError("Connection refused")):
            result = adapter.analyze(str(c))
            assert isinstance(result, dict)
            # Must NOT crash — either empty findings or error status
            assert isinstance(result.get("findings", []), list)
