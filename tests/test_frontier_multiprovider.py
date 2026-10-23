"""
Multi-provider routing for the business-logic detector (FrontierLLMAdapter).

Verifies the plumbing added in Fase 2: the OpenAI-compatible detection path builds its client
with the right base URL and API key per provider (OpenAI / DeepSeek / Moonshot-Kimi), resolved
from the shared `miesc.llm.provider_registry`. All mocked: no network, no real keys. The
constructor is isolated by making `.create` raise, so the test asserts only the client wiring.
"""

from __future__ import annotations

import openai

from miesc.adapters.frontier_llm_adapter import FrontierLLMAdapter
from miesc.core.tool_protocol import ToolStatus


def _capture_openai_ctor(monkeypatch):
    """Patch openai.OpenAI to record its kwargs and stop right after construction."""
    cap: dict = {}

    def fake_ctor(**kwargs):
        cap.update(kwargs)

        class _Client:
            class chat:  # noqa: N801
                class completions:  # noqa: N801
                    @staticmethod
                    def create(*a, **k):
                        raise RuntimeError("stop after ctor")

        return _Client()

    monkeypatch.setattr(openai, "OpenAI", fake_ctor)
    return cap


class TestDetectorProviderRouting:
    def _run(self, adapter):
        try:
            adapter._analyze_openai("contract C {}", model=adapter._model_hint)
        except Exception:
            pass  # constructor already captured; parsing/create is out of scope

    def test_kimi_routes_to_moonshot_base_url(self, monkeypatch):
        for v in ("OPENAI_API_KEY", "MOONSHOT_API_KEY"):
            monkeypatch.delenv(v, raising=False)
        monkeypatch.setenv("KIMI_API_KEY", "kk")
        cap = _capture_openai_ctor(monkeypatch)
        a = FrontierLLMAdapter(provider="kimi")
        a._model_hint = "moonshot-v1-8k"
        self._run(a)
        assert cap["base_url"].startswith("https://api.moonshot.ai")
        assert cap["api_key"] == "kk"

    def test_kimi_accepts_moonshot_api_key(self, monkeypatch):
        monkeypatch.delenv("KIMI_API_KEY", raising=False)
        monkeypatch.setenv("MOONSHOT_API_KEY", "mk")
        cap = _capture_openai_ctor(monkeypatch)
        a = FrontierLLMAdapter(provider="kimi")
        a._model_hint = "moonshot-v1-8k"
        self._run(a)
        assert cap["api_key"] == "mk"

    def test_deepseek_routes_to_deepseek_base_url(self, monkeypatch):
        monkeypatch.setenv("DEEPSEEK_API_KEY", "dk")
        cap = _capture_openai_ctor(monkeypatch)
        a = FrontierLLMAdapter(provider="deepseek")
        a._model_hint = "deepseek-chat"
        self._run(a)
        assert cap["base_url"].startswith("https://api.deepseek.com")
        assert cap["api_key"] == "dk"

    def test_plain_openai_uses_default_client(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "ok")
        cap = _capture_openai_ctor(monkeypatch)
        a = FrontierLLMAdapter(provider="openai")
        a._model_hint = "gpt-4o"
        self._run(a)
        # plain OpenAI(): no base_url/api_key override (SDK reads OPENAI_API_KEY itself)
        assert "base_url" not in cap


class TestDetectorIsAvailable:
    def test_kimi_available_with_key(self, monkeypatch):
        monkeypatch.delenv("MOONSHOT_API_KEY", raising=False)
        monkeypatch.setenv("KIMI_API_KEY", "kk")
        assert FrontierLLMAdapter(provider="kimi").is_available() == ToolStatus.AVAILABLE

    def test_kimi_config_error_without_key(self, monkeypatch):
        for v in ("KIMI_API_KEY", "MOONSHOT_API_KEY"):
            monkeypatch.delenv(v, raising=False)
        assert FrontierLLMAdapter(provider="kimi").is_available() == ToolStatus.CONFIGURATION_ERROR

    def test_deepseek_available_with_key(self, monkeypatch):
        monkeypatch.setenv("DEEPSEEK_API_KEY", "dk")
        assert FrontierLLMAdapter(provider="deepseek").is_available() == ToolStatus.AVAILABLE


def test_registry_is_the_single_source_of_truth():
    # the detector imports the same provider spec the verifier uses
    from miesc.llm.provider_registry import PROVIDERS, parse_model

    assert set(PROVIDERS) == {"deepseek", "openai", "kimi", "anthropic"}
    assert parse_model("kimi") == ("kimi", None)
    assert parse_model("claude:claude-3-5-sonnet") == ("anthropic", "claude-3-5-sonnet")
