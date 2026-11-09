"""Coverage for the LlamaAudit (CodeLlama via Ollama) adapter.

Exercises the offline surface: the pattern-based fallback (no Ollama), the
LLM path with _call_ollama_generate mocked, availability probing (urllib
mocked), normalization, caching and error paths.
"""

import json
import uuid
from unittest.mock import MagicMock, patch

import pytest

from miesc.adapters.llamaaudit_adapter import LlamaAuditAdapter
from miesc.core.tool_protocol import ToolStatus

VULNERABLE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Bank {
    mapping(address => uint256) public balances;
    address owner;
    function withdraw(uint256 a) public {
        (bool ok, ) = msg.sender.call{value: a}("");
        balances[msg.sender] -= a;
    }
    function auth() public { require(tx.origin == owner); }
    function ping(address t) public { t.call(abi.encodeWithSignature("x()")); }
    function timed() public view returns (bool) { return block.timestamp > 100; }
}
"""

LLM_JSON = json.dumps(
    {
        "findings": [
            {
                "type": "reentrancy",
                "title": "Reentrancy",
                "severity": "High",
                "description": "ext call before state update",
                "line": 7,
                "confidence": 0.8,
            }
        ]
    }
)


@pytest.fixture
def adapter():
    return LlamaAuditAdapter()


def _write(tmp_path, body=VULNERABLE):
    p = tmp_path / "C.sol"
    p.write_text(f"{body}\n// nonce {uuid.uuid4()}\n", encoding="utf-8")
    return str(p)


class TestMetaConfig:
    def test_metadata(self, adapter):
        assert adapter.get_metadata().name in ("llamaaudit", "llama_audit", "LlamaAudit".lower())

    def test_can_analyze(self, adapter):
        assert adapter.can_analyze("C.sol") is True
        assert adapter.can_analyze("C.txt") is False

    def test_default_config(self, adapter):
        assert isinstance(adapter.get_default_config(), dict)

    def test_normalize_severity(self, adapter):
        assert adapter._normalize_severity("critical") == "Critical"
        assert adapter._normalize_severity("bogus") in ("Medium", "Low", "High", "Critical", "Info")

    def test_normalize_findings_variants(self, adapter):
        assert adapter.normalize_findings({"findings": [{"type": "reentrancy"}]})
        assert adapter.normalize_findings([{"type": "reentrancy"}])
        assert adapter.normalize_findings(7) == []


class TestIsAvailable:
    def _resp(self, payload):
        r = MagicMock()
        r.status = 200
        r.read.return_value = json.dumps(payload).encode()
        r.__enter__.return_value = r
        r.__exit__.return_value = False
        return r

    def test_available_with_model(self, adapter):
        with patch(
            "urllib.request.urlopen",
            return_value=self._resp({"models": [{"name": "codellama:13b"}]}),
        ):
            assert adapter.is_available() == ToolStatus.AVAILABLE

    def test_non_200_is_config_error(self, adapter):
        # A non-200 tags response is treated as a configuration error.
        r = self._resp({"models": []})
        r.status = 500
        with patch("urllib.request.urlopen", return_value=r):
            assert adapter.is_available() == ToolStatus.CONFIGURATION_ERROR

    def test_unreachable_is_not_installed(self, adapter):
        import urllib.error

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
            assert adapter.is_available() == ToolStatus.NOT_INSTALLED


class TestAnalyze:
    def test_unreadable_contract(self, adapter, tmp_path):
        result = adapter.analyze(str(tmp_path / "missing.sol"))
        assert result["status"] == "error"

    def test_pattern_fallback(self, adapter, tmp_path):
        with patch.object(adapter, "is_available", return_value=ToolStatus.NOT_INSTALLED):
            result = adapter.analyze(_write(tmp_path), use_fallback=True)
        assert result["status"] == "success"
        assert isinstance(result["findings"], list)
        assert result["findings"], "pattern fallback should flag the vulnerable contract"

    def test_fallback_disabled_errors(self, adapter, tmp_path):
        with patch.object(adapter, "is_available", return_value=ToolStatus.NOT_INSTALLED):
            result = adapter.analyze(_write(tmp_path), use_fallback=False)
        assert result["status"] == "error"

    def test_llm_path(self, adapter, tmp_path):
        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            with patch.object(adapter, "_call_ollama_generate", return_value=LLM_JSON):
                result = adapter.analyze(_write(tmp_path))
        assert result["status"] == "success"

    def test_cache_hit_second_call(self, adapter, tmp_path):
        path = _write(tmp_path)
        with patch.object(adapter, "is_available", return_value=ToolStatus.NOT_INSTALLED):
            first = adapter.analyze(path, use_fallback=True)
            second = adapter.analyze(path, use_fallback=True)
        assert first.get("from_cache") in (None, False)
        assert second.get("from_cache") is True
