"""Coverage for the FrontierLLM adapter's offline surface.

Mocks at the client boundary (``make_client`` for cloud SDKs, ``urllib`` for
Ollama) so the real analyze/normalize/parse/dedup and provider-fallback logic
runs without any network. Does not touch the multi-turn tool-use loop.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from miesc.adapters.frontier_llm_adapter import FrontierLLMAdapter
from miesc.core.tool_protocol import ToolStatus

MOD = "miesc.adapters.frontier_llm_adapter"

MULTI_CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Token is ERC20 {
    function mint(address to, uint256 amt) external { _mint(to, amt); }
    function burn(uint256 amt) external { _burn(msg.sender, amt); }
}
contract Vault {
    function deposit() external payable {}
    function withdraw(uint256 a) external { msg.sender.call{value: a}(""); }
}
"""

FINDINGS_JSON = json.dumps(
    [
        {
            "title": "Reentrancy",
            "type": "reentrancy",
            "severity": "high",
            "location": "withdraw:12",
            "description": "ext call",
            "recommendation": "guard",
        },
        {
            "title": "Reentrancy",
            "type": "reentrancy",
            "severity": "high",
            "location": "withdraw:12",
            "description": "dup",
        },
        {"vulnerability": "No access control", "severity": "Medium", "function": "mint"},
    ]
)


def _urllib_resp(payload):
    resp = MagicMock()
    resp.read.return_value = json.dumps(payload).encode("utf-8")
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    return resp


@pytest.fixture
def adapter():
    return FrontierLLMAdapter(provider="auto")


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------
class TestPureHelpers:
    def test_preprocess_builds_protocol_map(self, adapter):
        out = adapter._preprocess_codebase(MULTI_CONTRACT)
        assert "CONTRACT HIERARCHY" in out
        assert "Token" in out and "Vault" in out

    def test_preprocess_empty_source(self, adapter):
        assert adapter._preprocess_codebase("// just a comment\n") == ""

    def test_build_user_prompt_includes_source_and_rag(self, adapter):
        p = adapter._build_user_prompt("contract C {}", "RAG-CONTEXT-XYZ")
        assert "contract C {}" in p
        assert "RAG-CONTEXT-XYZ" in p

    def test_parse_response_array(self, adapter):
        out = adapter._parse_response(FINDINGS_JSON)
        assert len(out) == 3
        assert out[0]["title"] == "Reentrancy"

    def test_parse_response_wrapped_dict(self, adapter):
        text = json.dumps({"vulnerabilities": [{"title": "X", "severity": "Low"}]})
        out = adapter._parse_response(text)
        assert out and out[0]["title"] == "X"

    def test_parse_response_prose_around_json(self, adapter):
        # The shared extractor recovers finding object(s) from prose-wrapped
        # output via its non-direct strategy; at least the first is returned.
        text = "Here is the result:\n" + FINDINGS_JSON + "\nThanks."
        assert len(adapter._parse_response(text)) >= 1

    def test_parse_response_no_json(self, adapter):
        assert adapter._parse_response("no findings here at all") == []

    def test_normalize_findings_variants(self, adapter):
        assert adapter.normalize_findings([{"a": 1}]) == [{"a": 1}]
        assert adapter.normalize_findings({"findings": [{"b": 2}]}) == [{"b": 2}]
        assert adapter.normalize_findings(42) == []

    def test_error_result_shape(self, adapter):
        r = adapter._error_result(0.0, "boom")
        assert r["status"] == "error"
        assert r["error"] == "boom"
        assert r["findings"] == []


# --------------------------------------------------------------------------
# Ollama model helpers (urllib mocked)
# --------------------------------------------------------------------------
class TestOllamaModelHelpers:
    def test_select_best_exact_match(self, adapter):
        payload = {"models": [{"name": "qwen2.5-coder:14b"}, {"name": "mistral:7b"}]}
        with patch("urllib.request.urlopen", return_value=_urllib_resp(payload)):
            assert adapter._select_best_ollama_model() == "qwen2.5-coder:14b"

    def test_select_best_default_on_error(self, adapter):
        with patch("urllib.request.urlopen", side_effect=OSError("down")):
            assert adapter._select_best_ollama_model() == "qwen2.5-coder:32b"

    def test_ensure_model_present(self, adapter):
        payload = {"models": [{"name": "qwen2.5-coder:32b"}]}
        with patch("urllib.request.urlopen", return_value=_urllib_resp(payload)):
            assert adapter._ensure_ollama_model("qwen2.5-coder:32b") is True

    def test_ensure_model_tags_unreachable(self, adapter):
        with patch("urllib.request.urlopen", side_effect=OSError("down")):
            assert adapter._ensure_ollama_model("qwen2.5-coder:32b") is False


# --------------------------------------------------------------------------
# Provider analyzers (client boundary mocked)
# --------------------------------------------------------------------------
class TestAnalyzers:
    def test_analyze_ollama(self, adapter):
        tags = {"models": [{"name": "qwen2.5-coder:14b"}]}
        chat = {"message": {"content": FINDINGS_JSON}}

        def fake_urlopen(req, timeout=None):
            url = req.full_url if hasattr(req, "full_url") else ""
            return _urllib_resp(tags if url.endswith("/api/tags") else chat)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            out = adapter._analyze_ollama("contract C {}", model="qwen2.5-coder:14b")
        assert len(out) == 3

    def test_analyze_openai_default_model(self, adapter):
        client = MagicMock()
        msg = MagicMock()
        msg.content = FINDINGS_JSON
        client.chat.completions.create.return_value.choices = [MagicMock(message=msg)]
        client.chat.completions.create.return_value.usage = None
        with patch(f"{MOD}.make_client", return_value=client):
            out = adapter._analyze_openai("contract C {}", model="gpt-4o")
        assert len(out) == 3
        # Default model uses max_tokens (not max_completion_tokens).
        _, kwargs = client.chat.completions.create.call_args
        assert "max_tokens" in kwargs

    def test_analyze_openai_reasoning_model_uses_completion_tokens(self, adapter):
        client = MagicMock()
        msg = MagicMock()
        msg.content = FINDINGS_JSON
        client.chat.completions.create.return_value.choices = [MagicMock(message=msg)]
        client.chat.completions.create.return_value.usage = None
        with patch(f"{MOD}.make_client", return_value=client):
            adapter._analyze_openai("contract C {}", model="gpt-5")
        _, kwargs = client.chat.completions.create.call_args
        assert kwargs.get("max_completion_tokens") == 32768
        assert kwargs.get("reasoning_effort") == "low"

    def test_analyze_anthropic(self, adapter):
        client = MagicMock()
        block = MagicMock()
        block.text = FINDINGS_JSON
        client.messages.create.return_value.content = [block]
        client.messages.create.return_value.usage = None
        with patch(f"{MOD}.make_client", return_value=client):
            out = adapter._analyze_anthropic("contract C {}", model="claude-opus-4-8")
        assert len(out) == 3


# --------------------------------------------------------------------------
# analyze() orchestration (normalize + dedup + control paths)
# --------------------------------------------------------------------------
class TestAnalyzeOrchestration:
    def _ollama_spec(self):
        from miesc.core.llm_providers import get_provider

        return get_provider("ollama")

    def test_analyze_success_normalizes_and_dedups(self, adapter, tmp_path):
        path = tmp_path / "C.sol"
        path.write_text(MULTI_CONTRACT, encoding="utf-8")
        raw = [
            {
                "title": "Reentrancy",
                "type": "reentrancy",
                "severity": "high",
                "location": "withdraw:12",
                "recommendation": "guard",
            },
            {
                "title": "Reentrancy",
                "type": "reentrancy",
                "severity": "high",
                "location": "withdraw:20",
            },  # same (fn,type) -> deduped
            {"vulnerability": "No access control", "severity": "Medium", "function": "mint"},
        ]
        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            with patch.object(adapter, "_get_provider", return_value="ollama"):
                with patch.object(adapter, "_spec", return_value=self._ollama_spec()):
                    with patch.object(adapter, "_get_rag_context", return_value=""):
                        with patch.object(adapter, "_analyze_ollama", return_value=raw):
                            result = adapter.analyze(str(path))
        assert result["status"] == "success"
        # Two reentrancy entries on the same function collapse to one.
        types = [f["type"] for f in result["findings"]]
        assert types.count("reentrancy") == 1
        # The entry whose issue came via the "vulnerability" key keeps that as
        # its title; with no type/category it normalizes to "logic_error".
        assert any(f["title"] == "No access control" for f in result["findings"])
        for f in result["findings"]:
            assert f["tool"] == "frontier-ollama"
            assert f["location"]["file"] == str(path)

    def test_analyze_not_available(self, adapter, tmp_path):
        with patch.object(adapter, "is_available", return_value=ToolStatus.NOT_INSTALLED):
            result = adapter.analyze(str(tmp_path / "C.sol"))
        assert result["status"] == "error"
        assert "not available" in result["error"]

    def test_analyze_unreadable_file(self, adapter, tmp_path):
        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            result = adapter.analyze(str(tmp_path / "missing.sol"))
        assert result["status"] == "error"
        assert "Cannot read" in result["error"]

    def test_analyze_deep_pass(self, adapter, tmp_path):
        path = tmp_path / "C.sol"
        path.write_text(MULTI_CONTRACT, encoding="utf-8")
        base = [{"title": "R", "type": "reentrancy", "severity": "high", "location": "withdraw"}]
        extra = [{"title": "Deep", "type": "logic_error", "severity": "High", "function": "mint"}]
        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            with patch.object(adapter, "_get_provider", return_value="ollama"):
                with patch.object(adapter, "_spec", return_value=self._ollama_spec()):
                    with patch.object(adapter, "_get_rag_context", return_value=""):
                        with patch.object(adapter, "_analyze_ollama", return_value=base):
                            with patch.object(adapter, "_deep_pass", return_value=extra) as dp:
                                result = adapter.analyze(str(path), deep=True)
        dp.assert_called_once()
        titles = {f["title"] for f in result["findings"]}
        assert "Deep" in titles

    def test_analyze_fallback_to_other_provider(self, adapter, tmp_path):
        from miesc.core.llm_providers import get_provider

        path = tmp_path / "C.sol"
        path.write_text("contract C {}", encoding="utf-8")
        fb = [{"title": "FB", "type": "reentrancy", "severity": "high", "location": "f"}]
        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            with patch.object(adapter, "_get_provider", return_value="anthropic"):
                with patch.object(adapter, "_spec", return_value=get_provider("anthropic")):
                    with patch.object(adapter, "_get_rag_context", return_value=""):
                        with patch.object(
                            adapter, "_analyze_anthropic", side_effect=RuntimeError("boom")
                        ):
                            with patch(f"{MOD}.is_configured", return_value=True):
                                with patch.object(
                                    adapter, "_analyze_openai", return_value=fb
                                ) as op:
                                    result = adapter.analyze(str(path))
        op.assert_called_once()
        assert result["status"] == "success"
        assert result["findings"][0]["title"] == "FB"
