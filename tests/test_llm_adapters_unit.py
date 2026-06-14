"""
Unit tests for LLM adapter metadata, availability, and prompt construction.

These tests exercise the 50-60% of LLM adapter code that does NOT require
Ollama running. The goal: push gptlens/iaudit/llamaaudit from 17-24% to
40-50% without any external service dependency.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from src.core.tool_protocol import ToolCategory, ToolStatus

# ---------------------------------------------------------------------------
# GPTLens Adapter
# ---------------------------------------------------------------------------


class TestGPTLensAdapter:
    @pytest.fixture
    def adapter(self):
        from src.adapters.gptlens_adapter import GPTLensAdapter

        return GPTLensAdapter()

    def test_metadata_name(self, adapter):
        meta = adapter.get_metadata()
        assert meta.name == "gptlens"
        assert meta.category == ToolCategory.AI_ANALYSIS

    def test_metadata_capabilities(self, adapter):
        meta = adapter.get_metadata()
        assert len(meta.capabilities) >= 1
        assert meta.requires_api_key is False

    def test_is_available_returns_status(self, adapter):
        status = adapter.is_available()
        assert isinstance(status, ToolStatus)

    def test_is_available_not_installed_when_ollama_down(self, adapter):
        with patch("urllib.request.urlopen", side_effect=OSError("refused")):
            status = adapter.is_available()
            assert status in (ToolStatus.NOT_INSTALLED, ToolStatus.CONFIGURATION_ERROR)

    def test_prompt_templates_are_strings(self):
        from src.adapters.gptlens_adapter import AUDITOR_PROMPT_TEMPLATE, CRITIC_PROMPT_TEMPLATE

        assert isinstance(AUDITOR_PROMPT_TEMPLATE, str)
        assert isinstance(CRITIC_PROMPT_TEMPLATE, str)
        assert "{contract_code}" in AUDITOR_PROMPT_TEMPLATE
        assert "{contract_code}" in CRITIC_PROMPT_TEMPLATE

    def test_prompt_templates_have_json_output_format(self):
        from src.adapters.gptlens_adapter import AUDITOR_PROMPT_TEMPLATE

        assert "JSON" in AUDITOR_PROMPT_TEMPLATE
        assert "findings" in AUDITOR_PROMPT_TEMPLATE
        assert "SWC-XXX" not in AUDITOR_PROMPT_TEMPLATE

    def test_can_analyze_solidity(self, adapter):
        assert adapter.can_analyze("contract.sol") is True

    def test_cannot_analyze_non_solidity(self, adapter):
        assert adapter.can_analyze("file.py") is False
        assert adapter.can_analyze("file.txt") is False

    def test_normalize_findings_empty(self, adapter):
        result = adapter.normalize_findings(None)
        assert result == [] or isinstance(result, list)

    def test_normalize_findings_valid_json(self, adapter):
        raw = {
            "findings": [
                {
                    "type": "reentrancy",
                    "severity": "High",
                    "title": "Test",
                    "description": "desc",
                    "function": "withdraw",
                    "line": 10,
                }
            ]
        }
        result = adapter.normalize_findings(raw)
        assert isinstance(result, list)

    def test_default_config(self, adapter):
        config = adapter.get_default_config()
        assert isinstance(config, dict)

    def test_analyze_returns_error_on_nonexistent(self, adapter):
        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            result = adapter.analyze("/nonexistent/path.sol")
            assert isinstance(result, dict)
            # Should contain error or empty findings
            assert result.get("findings") == [] or result.get("error")

    def test_analyze_reports_timeout_status_on_ollama_timeout(self, adapter, tmp_path):
        """C6: a clock-killed Ollama call must yield status='timeout', not a
        misleading clean-zero 'success' that masks a missed analysis."""
        contract = tmp_path / "C.sol"
        contract.write_text("pragma solidity ^0.8.0;\ncontract C {}\n")
        adapter._retry_delay = 0
        with (
            patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE),
            patch.object(adapter, "_get_cached_result", return_value=None),
            patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")),
        ):
            result = adapter.analyze(str(contract), timeout=10, skip_critic=True)
        assert result["status"] == "timeout"
        assert result.get("metadata", {}).get("timed_out") is True
        assert "incomplete" in (result.get("error") or "")


# ---------------------------------------------------------------------------
# iAudit Adapter
# ---------------------------------------------------------------------------


class TestIAuditAdapter:
    @pytest.fixture
    def adapter(self):
        from src.adapters.iaudit_adapter import IAuditAdapter

        return IAuditAdapter()

    def test_metadata_name(self, adapter):
        meta = adapter.get_metadata()
        assert meta.name == "iaudit"
        assert meta.category == ToolCategory.AI_ANALYSIS

    def test_is_available_returns_status(self, adapter):
        status = adapter.is_available()
        assert isinstance(status, ToolStatus)

    def test_analyze_reports_timeout_status_on_ollama_timeout(self, adapter, tmp_path):
        """C6: an LLM agent stage killed by the clock must yield status='timeout'
        (via the pattern fallback), not a clean-zero 'success'."""
        contract = tmp_path / "C.sol"
        contract.write_text("pragma solidity ^0.8.0;\ncontract C {}\n")

        def _timeout(*args, **kwargs):
            adapter._timed_out = True
            return None

        with (
            patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE),
            patch.object(adapter, "_get_cached_result", return_value=None),
            patch.object(adapter, "_call_ollama_api", side_effect=_timeout),
        ):
            result = adapter.analyze(str(contract), model="test-model")
        assert result["status"] == "timeout"
        assert result.get("metadata", {}).get("timed_out") is True

    def test_normalize_findings_removes_placeholder_taxonomy_ids(self, adapter):
        normalized = adapter.normalize_findings(
            {
                "findings": [
                    {
                        "id": "IAUDIT-001",
                        "type": "other",
                        "severity": "Medium",
                        "confidence": 0.7,
                        "swc_id": "SWC-XXX",
                        "cwe_id": "CWE-XXX",
                    }
                ]
            }
        )

        assert normalized[0]["swc_id"] is None
        assert normalized[0]["cwe_id"] is None

    def test_prompt_templates_imported(self):
        from src.adapters.iaudit_prompts import (
            DETECTOR_PROMPT,
            PLANNER_PROMPT,
            REVIEWER_PROMPT,
        )

        assert "{contract_code}" in PLANNER_PROMPT
        assert "{contract_code}" in DETECTOR_PROMPT
        assert "{contract_code}" in REVIEWER_PROMPT
        assert "{planner_output}" in DETECTOR_PROMPT
        assert "{detector_findings}" in REVIEWER_PROMPT

    def test_planner_prompt_has_json_schema(self):
        from src.adapters.iaudit_prompts import PLANNER_PROMPT

        assert "entry_points" in PLANNER_PROMPT
        assert "attack_surface" in PLANNER_PROMPT

    def test_model_priority_list(self, adapter):
        assert hasattr(adapter, "MODEL_PRIORITY")
        assert len(adapter.MODEL_PRIORITY) >= 3

    def test_normalize_findings_empty(self, adapter):
        result = adapter.normalize_findings([])
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# LlamaAudit Adapter
# ---------------------------------------------------------------------------


class TestLlamaAuditAdapter:
    @pytest.fixture
    def adapter(self):
        from src.adapters.llamaaudit_adapter import LlamaAuditAdapter

        return LlamaAuditAdapter()

    def test_metadata_name(self, adapter):
        meta = adapter.get_metadata()
        assert meta.name == "llamaaudit"

    def test_is_available_returns_status(self, adapter):
        status = adapter.is_available()
        assert isinstance(status, ToolStatus)

    def test_normalize_findings_handles_none(self, adapter):
        result = adapter.normalize_findings(None)
        assert isinstance(result, list)

    def test_analyze_reports_timeout_status_on_ollama_timeout(self, adapter, tmp_path):
        """C6: a clock-killed Ollama call must yield status='timeout', not a
        clean-zero 'success' from the pattern fallback."""
        contract = tmp_path / "C.sol"
        contract.write_text("pragma solidity ^0.8.0;\ncontract C {}\n")

        def _timeout(*args, **kwargs):
            adapter._timed_out = True
            return None

        with (
            patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE),
            patch.object(adapter, "_get_cached_result", return_value=None),
            patch.object(adapter, "_call_ollama_generate", side_effect=_timeout),
        ):
            result = adapter.analyze(str(contract))
        assert result["status"] == "timeout"
        assert result.get("metadata", {}).get("timed_out") is True


# ---------------------------------------------------------------------------
# LLMSmartAudit Adapter
# ---------------------------------------------------------------------------


class TestLLMSmartAuditAdapter:
    @pytest.fixture
    def adapter(self):
        from src.adapters.llmsmartaudit_adapter import LLMSmartAuditAdapter

        return LLMSmartAuditAdapter()

    def test_analyze_reports_timeout_status_on_ollama_timeout(self, adapter, tmp_path):
        """C6: a clock-killed Ollama HTTP call must yield status='timeout'."""
        contract = tmp_path / "C.sol"
        contract.write_text("pragma solidity ^0.8.0;\ncontract C {}\n")

        def _timeout(*args, **kwargs):
            adapter._timed_out = True
            return ""

        with (
            patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE),
            patch.object(adapter, "_get_cached_result", return_value=None),
            patch.object(adapter, "_run_ollama_audit", side_effect=_timeout),
        ):
            result = adapter.analyze(str(contract))
        assert result["status"] == "timeout"
        assert result.get("metadata", {}).get("timed_out") is True


# ---------------------------------------------------------------------------
# LLMBugScanner Adapter
# ---------------------------------------------------------------------------


class TestLLMBugScannerAdapter:
    @pytest.fixture
    def adapter(self):
        from src.adapters.llmbugscanner_adapter import LLMBugScannerAdapter

        return LLMBugScannerAdapter()

    def test_metadata_name(self, adapter):
        meta = adapter.get_metadata()
        assert meta.name == "llmbugscanner"

    def test_is_available_returns_status(self, adapter):
        status = adapter.is_available()
        assert isinstance(status, ToolStatus)


# ---------------------------------------------------------------------------
# Peculiar Adapter (GNN-based)
# ---------------------------------------------------------------------------


class TestPeculiarAdapter:
    @pytest.fixture
    def adapter(self):
        from src.adapters.peculiar_adapter import PeculiarAdapter

        return PeculiarAdapter()

    def test_metadata_name(self, adapter):
        meta = adapter.get_metadata()
        assert meta.name == "peculiar"

    def test_is_available_returns_available(self, adapter):
        status = adapter.is_available()
        assert status == ToolStatus.AVAILABLE

    def test_analyze_returns_dict(self, adapter, tmp_path):
        c = tmp_path / "C.sol"
        c.write_text("pragma solidity ^0.8.0; contract C { uint x; }")
        result = adapter.analyze(str(c))
        assert isinstance(result, dict)
        assert "findings" in result or "status" in result

    def test_analyze_nonexistent_returns_error(self, adapter):
        result = adapter.analyze("/nonexistent.sol")
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Cross-adapter contract: all LLM adapters share consistent shape
# ---------------------------------------------------------------------------


class TestLLMAdapterContract:
    """Verify all LLM adapters implement the same basic protocol."""

    @pytest.mark.parametrize(
        "module,cls",
        [
            ("src.adapters.gptlens_adapter", "GPTLensAdapter"),
            ("src.adapters.iaudit_adapter", "IAuditAdapter"),
            ("src.adapters.llamaaudit_adapter", "LlamaAuditAdapter"),
            ("src.adapters.llmbugscanner_adapter", "LLMBugScannerAdapter"),
            ("src.adapters.peculiar_adapter", "PeculiarAdapter"),
        ],
    )
    def test_has_required_methods(self, module, cls):
        import importlib

        mod = importlib.import_module(module)
        klass = getattr(mod, cls)
        instance = klass()
        assert hasattr(instance, "get_metadata")
        assert hasattr(instance, "is_available")
        assert hasattr(instance, "analyze")
        assert hasattr(instance, "normalize_findings")

    @pytest.mark.parametrize(
        "module,cls",
        [
            ("src.adapters.gptlens_adapter", "GPTLensAdapter"),
            ("src.adapters.iaudit_adapter", "IAuditAdapter"),
            ("src.adapters.llamaaudit_adapter", "LlamaAuditAdapter"),
            ("src.adapters.llmbugscanner_adapter", "LLMBugScannerAdapter"),
            ("src.adapters.peculiar_adapter", "PeculiarAdapter"),
        ],
    )
    def test_metadata_has_name_and_category(self, module, cls):
        import importlib

        mod = importlib.import_module(module)
        klass = getattr(mod, cls)
        meta = klass().get_metadata()
        assert meta.name
        assert meta.category


# ---------------------------------------------------------------------------
# C6 timeout-status regression for GPTScan and SmartLLM
# ---------------------------------------------------------------------------


class TestGPTScanTimeout:
    @pytest.fixture
    def adapter(self):
        from src.adapters.gptscan_adapter import GPTScanAdapter

        return GPTScanAdapter()

    def test_analyze_reports_timeout_status_on_ollama_timeout(self, adapter, tmp_path):
        """C6: a clock-killed Ollama HTTP call must yield status='timeout'."""
        contract = tmp_path / "C.sol"
        contract.write_text("pragma solidity ^0.8.0;\ncontract C {}\n")

        def _timeout(*args, **kwargs):
            adapter._timed_out = True
            return ""

        with (
            patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE),
            patch.object(adapter, "_run_ollama_analysis", side_effect=_timeout),
        ):
            result = adapter.analyze(str(contract))
        assert result["status"] == "timeout"
        assert result.get("metadata", {}).get("timed_out") is True


class TestSmartLLMTimeout:
    @pytest.fixture
    def adapter(self):
        from src.adapters.smartllm_adapter import SmartLLMAdapter

        return SmartLLMAdapter()

    def test_analyze_reports_timeout_status_on_ollama_timeout(self, adapter, tmp_path):
        """C6: a clock-killed generator call must yield status='timeout', not a
        degraded 'success'."""
        contract = tmp_path / "C.sol"
        contract.write_text("pragma solidity ^0.8.0;\ncontract C {}\n")

        def _timeout(*args, **kwargs):
            adapter._timed_out = True
            return None

        with (
            patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE),
            patch.object(adapter, "_get_cached_result", return_value=None),
            patch.object(adapter, "_call_ollama_with_retry", side_effect=_timeout),
        ):
            result = adapter.analyze(str(contract))
        assert result["status"] == "timeout"
        assert result.get("metadata", {}).get("timed_out") is True
