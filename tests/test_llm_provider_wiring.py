"""The CLI, the orchestrator and doctor read LLM providers from the registry (no network)."""

import sys
import types

import pytest
from click.testing import CliRunner

from miesc.cli.main import cli
from miesc.core import llm_providers as lp
from miesc.llm import llm_orchestrator as orch


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "DEEPSEEK_API_KEY",
        "MOONSHOT_API_KEY",
        "KIMI_API_KEY",
        "MIESC_LLM_PROVIDER",
        "MIESC_LLM_MODEL",
        "MIESC_LLM_BASE_URL",
        "DEEPSEEK_BASE_URL",
        "MOONSHOT_BASE_URL",
        "ANTHROPIC_BASE_URL",
        "OPENAI_BASE_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(lp, "get_llm_config", lambda: {})


class TestOrchestrator:
    def test_kimi_is_an_openai_compatible_backend_with_its_base_url(self, monkeypatch):
        monkeypatch.setenv("MOONSHOT_API_KEY", "k")
        config = orch.config_for_provider("kimi")
        assert config.provider is orch.LLMProvider.KIMI
        assert config.base_url == "https://api.moonshot.ai/v1" and config.api_key == "k"
        assert config.model == "kimi-k2-turbo-preview"
        o = orch.LLMOrchestrator(configs=[config])
        backend = o.backends["kimi:kimi-k2-turbo-preview"]
        assert (
            isinstance(backend, orch.OpenAIBackend)
            and backend.base_url == "https://api.moonshot.ai/v1"
        )

    def test_custom_openai_compatible_provider_from_config(self, monkeypatch):
        monkeypatch.setattr(
            lp,
            "get_llm_config",
            lambda: {
                "providers": {
                    "vllm": {
                        "kind": "openai",
                        "base_url": "http://gpu-box:8000/v1",
                        "api_key_env": "VLLM_API_KEY",
                        "default_model": "Qwen/Qwen2.5-Coder-32B-Instruct",
                    }
                }
            },
        )
        monkeypatch.setenv("VLLM_API_KEY", "local")
        config = orch.config_for_provider("vllm", model="Qwen/Qwen2.5-Coder-7B")
        assert config.provider is orch.LLMProvider.OPENAI
        assert (
            config.base_url == "http://gpu-box:8000/v1" and config.model == "Qwen/Qwen2.5-Coder-7B"
        )

    def test_unknown_provider_is_none(self):
        assert orch.config_for_provider("nope") is None

    def test_env_provider_goes_through_the_registry(self, monkeypatch):
        monkeypatch.setenv("MIESC_LLM_PROVIDER", "kimi")
        monkeypatch.setenv("MIESC_LLM_MODEL", "kimi-k2-thinking")
        monkeypatch.setenv("MOONSHOT_API_KEY", "k")
        config = orch.LLMOrchestrator()._default_config_from_env()
        assert (config.provider, config.model) == (orch.LLMProvider.KIMI, "kimi-k2-thinking")
        assert config.base_url == "https://api.moonshot.ai/v1"

    def test_env_ollama_default_is_unchanged(self, monkeypatch):
        config = orch.LLMOrchestrator()._default_config_from_env()
        assert config.provider is orch.LLMProvider.OLLAMA

    def test_openai_backend_passes_base_url_to_the_sdk(self, monkeypatch):
        seen = {}

        class FakeAsyncOpenAI:
            def __init__(self, **kwargs):
                seen.update(kwargs)
                self.chat = types.SimpleNamespace(
                    completions=types.SimpleNamespace(create=self._create)
                )

            async def _create(self, **kwargs):
                message = types.SimpleNamespace(content="ok")
                return types.SimpleNamespace(
                    choices=[types.SimpleNamespace(message=message)], usage=None
                )

        monkeypatch.setitem(
            sys.modules, "openai", types.SimpleNamespace(AsyncOpenAI=FakeAsyncOpenAI)
        )
        monkeypatch.setenv("MOONSHOT_API_KEY", "k")
        backend = orch.OpenAIBackend(orch.config_for_provider("kimi"))
        import asyncio

        response = asyncio.run(backend.analyze("hello"))
        assert seen["base_url"] == "https://api.moonshot.ai/v1" and seen["api_key"] == "k"
        assert response.provider == "kimi"


class TestCli:
    def test_scan_rejects_unknown_provider_at_parse_time(self, tmp_path):
        sol = tmp_path / "a.sol"
        sol.write_text("pragma solidity ^0.8.0; contract A {}")
        result = CliRunner().invoke(cli, ["scan", "--model", "nope:x", str(sol)])
        assert result.exit_code == 2 and "Known providers" in result.output

    def test_audit_deep_rejects_unknown_provider(self, tmp_path):
        result = CliRunner().invoke(cli, ["audit", "deep", "--llm-provider", "nope", "x.sol"])
        assert result.exit_code == 2 and "Known providers" in result.output

    def test_doctor_lists_registry_providers_without_keys(self, monkeypatch):
        monkeypatch.setenv("MOONSHOT_API_KEY", "sk-moon-secret")
        import importlib

        doctor_module = importlib.import_module("miesc.cli.commands.doctor")
        monkeypatch.setattr(
            doctor_module,
            "fetch_openai_compatible_model_ids",
            lambda *a, **k: _coro({"kimi-k2-turbo-preview", "kimi-k2-thinking"}),
        )
        result = CliRunner().invoke(cli, ["doctor"])
        assert result.exit_code == 0
        assert "Kimi" in result.output and "ready" in result.output
        assert "DeepSeek" in result.output and "Anthropic" in result.output
        assert "sk-moon-secret" not in result.output


async def _coro(value):
    return value
