"""Tests for FrontierLLMAdapter helpers that do not require a live API.

Covers provider detection, codebase preprocessing, Ollama probing, prompt
building, and availability — all via env/urllib mocking.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from miesc.adapters.frontier_llm_adapter import FrontierLLMAdapter
from miesc.core.tool_protocol import ToolStatus


class TestProviderDetection:
    def test_detect_anthropic(self):
        a = FrontierLLMAdapter()
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "x"}, clear=True):
            assert a._detect_provider() == "anthropic"

    def test_detect_openai(self):
        a = FrontierLLMAdapter()
        with patch.dict("os.environ", {"OPENAI_API_KEY": "x"}, clear=True):
            assert a._detect_provider() == "openai"

    def test_detect_none(self):
        a = FrontierLLMAdapter()
        with patch.dict("os.environ", {}, clear=True):
            assert a._detect_provider() is None

    def test_get_provider_explicit_overrides_auto(self):
        a = FrontierLLMAdapter(provider="openai")
        assert a._get_provider() == "openai"

    def test_is_available_no_key_not_installed(self):
        a = FrontierLLMAdapter(provider="auto")
        with patch.dict("os.environ", {}, clear=True):
            assert a.is_available() == ToolStatus.NOT_INSTALLED


class TestCheckOllama:
    def test_ollama_with_models_true(self):
        a = FrontierLLMAdapter()
        resp = MagicMock()
        resp.read.return_value = json.dumps({"models": [{"name": "x"}]}).encode("utf-8")
        with patch("urllib.request.urlopen", return_value=resp):
            assert a._check_ollama() is True

    def test_ollama_no_models_false(self):
        a = FrontierLLMAdapter()
        resp = MagicMock()
        resp.read.return_value = json.dumps({"models": []}).encode("utf-8")
        with patch("urllib.request.urlopen", return_value=resp):
            assert a._check_ollama() is False

    def test_ollama_unreachable_false(self):
        a = FrontierLLMAdapter()
        with patch("urllib.request.urlopen", side_effect=OSError("refused")):
            assert a._check_ollama() is False


class TestPreprocessAndPrompt:
    SRC = """
    contract Vault is Ownable {
        uint256 public total;
        function deposit(uint256 amount) external {
            total += amount;
            token.transfer(msg.sender, amount);
        }
    }
    """

    def test_preprocess_extracts_sections(self):
        a = FrontierLLMAdapter()
        out = a._preprocess_codebase(self.SRC)
        assert "CONTRACT HIERARCHY" in out
        assert "Vault" in out

    def test_preprocess_external_calls(self):
        a = FrontierLLMAdapter()
        out = a._preprocess_codebase(self.SRC)
        assert "EXTERNAL CALLS" in out

    def test_build_user_prompt_plain(self):
        a = FrontierLLMAdapter()
        prompt = a._build_user_prompt("contract C {}")
        assert "contract C {}" in prompt

    def test_build_user_prompt_with_rag(self):
        a = FrontierLLMAdapter()
        prompt = a._build_user_prompt("contract C {}", rag_context="reentrancy hint")
        assert "known_vulnerability_patterns" in prompt
        assert "reentrancy hint" in prompt


class TestParseResponse:
    def test_json_fenced(self):
        a = FrontierLLMAdapter()
        text = '```json\n{"findings":[{"title":"Reentrancy","severity":"high","line":5}]}\n```'
        out = a._parse_response(text)
        assert len(out) == 1
        assert (out[0].get("title") or out[0].get("type")) == "Reentrancy"

    def test_plain_json(self):
        a = FrontierLLMAdapter()
        out = a._parse_response('{"findings":[{"title":"Overflow","severity":"medium"}]}')
        assert len(out) == 1

    def test_unparseable_returns_empty(self):
        a = FrontierLLMAdapter()
        assert a._parse_response("no structured findings here") == []
