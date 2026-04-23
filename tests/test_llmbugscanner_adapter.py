"""
Tests for LLMBugScanner Adapter

Validates the multi-LLM ensemble adapter including availability checks,
finding parsing, consensus voting, and graceful degradation.

All Ollama HTTP calls are mocked — tests run without Ollama.

Author: Fernando Boiero
License: AGPL-3.0
"""

import json
import subprocess
import time
import urllib.error
import urllib.request
from io import BytesIO
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from src.core.tool_protocol import ToolStatus


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_adapter(ensemble=None):
    """Create an LLMBugScannerAdapter with mocked optional deps."""
    with patch("src.adapters.llmbugscanner_adapter._EMBEDDING_RAG_AVAILABLE", False):
        from src.adapters.llmbugscanner_adapter import LLMBugScannerAdapter

        adapter = LLMBugScannerAdapter(ensemble=ensemble)
    return adapter


def _make_http_response(data, status=200):
    """Create a fake urllib response object."""
    body = json.dumps(data).encode()
    resp = MagicMock()
    resp.status = status
    resp.read.return_value = body
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


# ---------------------------------------------------------------------------
# 1. test_is_available_no_ollama
# ---------------------------------------------------------------------------


class TestIsAvailableNoOllama:
    def test_is_available_no_ollama(self):
        """When Ollama is not reachable, returns NOT_INSTALLED."""
        adapter = _make_adapter()

        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("Connection refused"),
        ):
            status = adapter.is_available()

        assert status == ToolStatus.NOT_INSTALLED


# ---------------------------------------------------------------------------
# 2. test_is_available_no_models
# ---------------------------------------------------------------------------


class TestIsAvailableNoModels:
    def test_is_available_no_models(self):
        """Ollama reachable but no ensemble models -> CONFIGURATION_ERROR."""
        adapter = _make_adapter()

        # Ollama responds but with no matching models
        resp = _make_http_response({"models": [{"name": "llama2"}]})

        with patch("urllib.request.urlopen", return_value=resp):
            status = adapter.is_available()

        assert status == ToolStatus.CONFIGURATION_ERROR


# ---------------------------------------------------------------------------
# 3. test_analyze_no_available
# ---------------------------------------------------------------------------


class TestAnalyzeNoAvailable:
    def test_analyze_no_available(self):
        """When not available, returns error result."""
        adapter = _make_adapter()

        # Force is_available to return NOT_INSTALLED
        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("Connection refused"),
        ):
            result = adapter.analyze("/tmp/Contract.sol")

        assert result["status"] == "error"
        assert result["findings"] == []
        assert "error" in result
        assert result["tool"] == "llmbugscanner"


# ---------------------------------------------------------------------------
# 4. test_parse_findings_valid_json
# ---------------------------------------------------------------------------


class TestParseFindingsValidJson:
    def test_parse_findings_valid_json(self):
        """_parse_llm_response with valid JSON response."""
        adapter = _make_adapter()

        llm_response = json.dumps(
            {
                "findings": [
                    {
                        "type": "reentrancy",
                        "severity": "HIGH",
                        "title": "Reentrancy in withdraw()",
                        "description": "External call before state update",
                        "location": "withdraw()",
                        "impact": "Fund drainage",
                        "recommendation": "Use checks-effects-interactions",
                    }
                ]
            }
        )

        findings = adapter._parse_llm_response(
            llm_response, "/tmp/Contract.sol", "deepseek-coder"
        )

        assert len(findings) == 1
        assert findings[0]["title"] == "Reentrancy in withdraw()"
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["source_model"] == "deepseek-coder"
        assert findings[0]["location"]["file"] == "/tmp/Contract.sol"
        assert findings[0]["category"] == "reentrancy"
        assert findings[0]["id"] == "llmbugscanner-deepseek-coder-1"


# ---------------------------------------------------------------------------
# 5. test_parse_findings_malformed_json
# ---------------------------------------------------------------------------


class TestParseFindingsMalformedJson:
    def test_parse_findings_malformed_json(self):
        """_parse_llm_response with broken JSON -> empty list, no crash."""
        adapter = _make_adapter()

        malformed = "This is not valid JSON at all { broken"

        findings = adapter._parse_llm_response(
            malformed, "/tmp/Contract.sol", "codellama"
        )

        assert findings == []

    def test_parse_findings_partial_json(self):
        """_parse_llm_response with partial JSON -> empty list."""
        adapter = _make_adapter()

        partial = '{"findings": [{"type": "reentrancy", "severity": '

        findings = adapter._parse_llm_response(
            partial, "/tmp/Contract.sol", "codellama"
        )

        assert findings == []


# ---------------------------------------------------------------------------
# 6. test_parse_findings_empty_response
# ---------------------------------------------------------------------------


class TestParseFindingsEmptyResponse:
    def test_parse_findings_empty_response(self):
        """_parse_llm_response with empty string -> empty list."""
        adapter = _make_adapter()

        findings = adapter._parse_llm_response(
            "", "/tmp/Contract.sol", "mistral"
        )

        assert findings == []

    def test_parse_findings_no_json_braces(self):
        """_parse_llm_response with text but no JSON braces -> empty list."""
        adapter = _make_adapter()

        findings = adapter._parse_llm_response(
            "No vulnerabilities found in this contract.", "/tmp/Contract.sol", "mistral"
        )

        assert findings == []


# ---------------------------------------------------------------------------
# 7. test_consensus_vote_agreement
# ---------------------------------------------------------------------------


class TestConsensusVoteAgreement:
    def test_consensus_vote_agreement(self):
        """Two models agree -> higher confidence."""
        from src.adapters.llmbugscanner_adapter import ModelConfig

        adapter = _make_adapter()

        ensemble = [
            ModelConfig(name="deepseek-coder", weight=0.45, timeout=300, specialization="code_analysis"),
            ModelConfig(name="codellama", weight=0.35, timeout=300, specialization="code_understanding"),
            ModelConfig(name="mistral", weight=0.20, timeout=180, specialization="reasoning"),
        ]

        # Both deepseek-coder and codellama report a reentrancy finding
        all_findings = {
            "deepseek-coder": [
                {
                    "id": "llmbugscanner-deepseek-coder-1",
                    "title": "Reentrancy in withdraw",
                    "severity": "HIGH",
                    "category": "reentrancy",
                    "description": "External call before state change",
                    "type": "reentrancy",
                    "confidence": 0.7,
                    "source_model": "deepseek-coder",
                }
            ],
            "codellama": [
                {
                    "id": "llmbugscanner-codellama-1",
                    "title": "Reentrancy vulnerability",
                    "severity": "HIGH",
                    "category": "reentrancy",
                    "description": "Reentrancy issue in withdraw function",
                    "type": "reentrancy",
                    "confidence": 0.7,
                    "source_model": "codellama",
                }
            ],
            "mistral": [],
        }

        result = adapter._aggregate_with_consensus(
            all_findings, ensemble, threshold=0.35
        )

        # Two models agree on reentrancy → should pass consensus
        assert len(result) >= 1

        reentrancy_finding = result[0]
        # Consensus score should be (0.45 + 0.35) / 1.0 = 0.8
        assert reentrancy_finding.get("consensus_score", 0) > 0.5
        # Confidence should be elevated due to consensus
        assert reentrancy_finding.get("confidence", 0) > 0.7


# ---------------------------------------------------------------------------
# 8. test_consensus_vote_disagreement
# ---------------------------------------------------------------------------


class TestConsensusVoteDisagreement:
    def test_consensus_vote_disagreement(self):
        """Models disagree -> lower confidence or filtered out."""
        from src.adapters.llmbugscanner_adapter import ModelConfig

        adapter = _make_adapter()

        ensemble = [
            ModelConfig(name="deepseek-coder", weight=0.45, timeout=300, specialization="code_analysis"),
            ModelConfig(name="codellama", weight=0.35, timeout=300, specialization="code_understanding"),
            ModelConfig(name="mistral", weight=0.20, timeout=180, specialization="reasoning"),
        ]

        # Each model reports a DIFFERENT category → no overlap → no consensus
        all_findings = {
            "deepseek-coder": [
                {
                    "id": "llmbugscanner-deepseek-coder-1",
                    "title": "Reentrancy",
                    "severity": "MEDIUM",
                    "category": "reentrancy",
                    "description": "Possible reentrancy",
                    "type": "reentrancy",
                    "confidence": 0.7,
                    "source_model": "deepseek-coder",
                }
            ],
            "codellama": [
                {
                    "id": "llmbugscanner-codellama-1",
                    "title": "Integer overflow",
                    "severity": "MEDIUM",
                    "category": "integer_overflow",
                    "description": "Unchecked arithmetic overflow",
                    "type": "integer_overflow",
                    "confidence": 0.7,
                    "source_model": "codellama",
                }
            ],
            "mistral": [
                {
                    "id": "llmbugscanner-mistral-1",
                    "title": "Weak randomness",
                    "severity": "MEDIUM",
                    "category": "timestamp_dependence",
                    "description": "block.timestamp used for randomness",
                    "type": "timestamp_dependence",
                    "confidence": 0.7,
                    "source_model": "mistral",
                }
            ],
        }

        # High threshold (0.6) = need multiple models to agree
        result = adapter._aggregate_with_consensus(
            all_findings, ensemble, threshold=0.6
        )

        # No group has enough weight to pass 0.6 threshold
        # deepseek=0.45, codellama=0.35, mistral=0.20 — all below 0.6
        # Fallback: single-model CRITICAL/HIGH only → but these are MEDIUM
        assert len(result) == 0

    def test_single_model_high_severity_fallback(self):
        """Single-model HIGH findings included as fallback when no consensus."""
        from src.adapters.llmbugscanner_adapter import ModelConfig

        adapter = _make_adapter()

        ensemble = [
            ModelConfig(name="deepseek-coder", weight=0.45, timeout=300, specialization="code_analysis"),
            ModelConfig(name="codellama", weight=0.35, timeout=300, specialization="code_understanding"),
        ]

        all_findings = {
            "deepseek-coder": [
                {
                    "id": "llmbugscanner-deepseek-coder-1",
                    "title": "Critical access control flaw",
                    "severity": "CRITICAL",
                    "category": "access_control",
                    "description": "Missing onlyOwner modifier on admin function",
                    "type": "access_control",
                    "confidence": 0.7,
                    "source_model": "deepseek-coder",
                }
            ],
            "codellama": [
                {
                    "id": "llmbugscanner-codellama-1",
                    "title": "Reentrancy",
                    "severity": "HIGH",
                    "category": "reentrancy",
                    "description": "State change after external call",
                    "type": "reentrancy",
                    "confidence": 0.7,
                    "source_model": "codellama",
                }
            ],
        }

        # Very high threshold → no consensus group passes
        result = adapter._aggregate_with_consensus(
            all_findings, ensemble, threshold=0.99
        )

        # Fallback includes CRITICAL and HIGH severity single-model findings
        assert len(result) >= 1
        for f in result:
            assert f.get("severity") in ("CRITICAL", "HIGH")
            # Fallback confidence is lower
            assert f.get("confidence", 1.0) <= 0.5


# ---------------------------------------------------------------------------
# 9. test_analyze_timeout
# ---------------------------------------------------------------------------


class TestAnalyzeTimeout:
    def test_analyze_timeout(self):
        """Model query times out -> graceful degradation, returns empty findings."""
        from src.adapters.llmbugscanner_adapter import ModelConfig

        adapter = _make_adapter(
            ensemble=[
                ModelConfig(
                    name="deepseek-coder",
                    weight=1.0,
                    timeout=1,
                    specialization="code_analysis",
                )
            ]
        )

        # Make is_available return AVAILABLE
        adapter._available_models = {"deepseek-coder"}

        contract_code = "pragma solidity ^0.8.0; contract Test {}"

        # _analyze_with_model calls subprocess.run which may timeout
        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ollama", timeout=1)
        ), patch("time.sleep"):  # Skip retry delay
            findings = adapter._analyze_with_model(
                contract_code,
                "/tmp/Test.sol",
                adapter._ensemble[0],
            )

        # Timeout → empty findings, not a crash
        assert findings == []

    def test_analyze_full_timeout_returns_empty(self):
        """Full analyze() with all models timing out returns error or empty findings."""
        from src.adapters.llmbugscanner_adapter import ModelConfig

        adapter = _make_adapter(
            ensemble=[
                ModelConfig(
                    name="deepseek-coder",
                    weight=1.0,
                    timeout=1,
                    specialization="code_analysis",
                )
            ]
        )

        # Mock is_available to return AVAILABLE
        resp = _make_http_response(
            {"models": [{"name": "deepseek-coder:latest"}]}
        )

        # Create a temp contract file
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sol", delete=False
        ) as f:
            f.write("pragma solidity ^0.8.0;\ncontract Test { }")
            contract_path = f.name

        try:
            with patch("urllib.request.urlopen", return_value=resp), \
                 patch(
                     "subprocess.run",
                     side_effect=subprocess.TimeoutExpired(cmd="ollama", timeout=1),
                 ), \
                 patch("time.sleep"):  # Skip retry delay
                result = adapter.analyze(contract_path)

            # Should complete without crash
            assert result["tool"] == "llmbugscanner"
            assert isinstance(result["findings"], list)
        finally:
            os.unlink(contract_path)


# ---------------------------------------------------------------------------
# Additional: metadata and configuration tests
# ---------------------------------------------------------------------------


class TestLLMBugScannerMetadata:
    def test_get_metadata(self):
        """Verify adapter metadata is well-formed."""
        adapter = _make_adapter()
        meta = adapter.get_metadata()

        assert meta.name == "llmbugscanner"
        assert meta.requires_api_key is False
        assert meta.cost == 0.0
        assert len(meta.capabilities) == 3

    def test_can_analyze_sol(self):
        """can_analyze returns True for .sol files."""
        adapter = _make_adapter()
        assert adapter.can_analyze("/tmp/Token.sol") is True
        assert adapter.can_analyze("/tmp/Token.py") is False

    def test_normalize_findings(self):
        """normalize_findings extracts from dict or returns empty."""
        adapter = _make_adapter()

        result = {"findings": [{"id": "1"}]}
        assert adapter.normalize_findings(result) == [{"id": "1"}]

        assert adapter.normalize_findings("not a dict") == []
        assert adapter.normalize_findings({}) == []
