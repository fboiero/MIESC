"""
Tests for LLM Orchestrator Module

Tests the multi-backend LLM orchestration for security analysis.
"""

import asyncio
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from src.llm.llm_orchestrator import (
    AnthropicBackend,
    DeepSeekBackend,
    LLMBackend,
    LLMConfig,
    LLMOrchestrator,
    LLMProvider,
    LLMResponse,
    OllamaBackend,
    OpenAIBackend,
    VulnerabilityAnalysis,
    _bounded_confidence,
    _cache_key_context,
    _cache_key_dict_key,
    _is_safe_backend_name,
    _non_negative_int_stat,
    _normalized_model_identifier,
    _safe_backend_error_text,
    analyze_solidity,
)


def _aiohttp_session_with_response(method: str, response: MagicMock) -> MagicMock:
    """Build an aiohttp.ClientSession mock whose request method is an async CM."""
    request_context = MagicMock()
    request_context.__aenter__ = AsyncMock(return_value=response)
    request_context.__aexit__ = AsyncMock(return_value=None)

    session_instance = MagicMock()
    setattr(session_instance, method, MagicMock(return_value=request_context))

    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session_instance)
    session.__aexit__ = AsyncMock(return_value=None)
    return session


class TestLLMProvider:
    """Test LLMProvider enum."""

    def test_provider_values(self):
        """Test provider enum values."""
        assert LLMProvider.OLLAMA.value == "ollama"
        assert LLMProvider.OPENAI.value == "openai"
        assert LLMProvider.ANTHROPIC.value == "anthropic"
        assert LLMProvider.DEEPSEEK.value == "deepseek"
        assert LLMProvider.LOCAL.value == "local"

    def test_all_providers(self):
        """Test all providers are accessible."""
        providers = list(LLMProvider)
        assert len(providers) == 5


class TestLLMConfig:
    """Test LLMConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = LLMConfig(provider=LLMProvider.OLLAMA, model="test-model")
        assert config.provider == LLMProvider.OLLAMA
        assert config.model == "test-model"
        assert config.api_key is None
        assert config.base_url is None
        assert config.temperature == 0.2
        assert config.max_tokens == 4096
        assert config.timeout == 120
        assert config.retry_attempts == 3
        assert config.retry_delay == 1.0

    def test_custom_config(self):
        """Test custom configuration."""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model="gpt-4",
            api_key="test-key",
            temperature=0.5,
            max_tokens=2048,
            timeout=60,
            retry_attempts=5,
        )
        assert config.api_key == "test-key"
        assert config.temperature == 0.5
        assert config.max_tokens == 2048
        assert config.timeout == 60
        assert config.retry_attempts == 5


class TestLLMResponse:
    """Test LLMResponse dataclass."""

    def test_default_response(self):
        """Test default response values."""
        response = LLMResponse(content="test content", provider="ollama", model="test-model")
        assert response.content == "test content"
        assert response.provider == "ollama"
        assert response.model == "test-model"
        assert response.tokens_used == 0
        assert response.latency_ms == 0
        assert response.cached is False
        assert response.metadata == {}

    def test_full_response(self):
        """Test response with all fields."""
        response = LLMResponse(
            content="analysis result",
            provider="openai",
            model="gpt-4",
            tokens_used=1500,
            latency_ms=2500.5,
            cached=True,
            metadata={"request_id": "123"},
        )
        assert response.tokens_used == 1500
        assert response.latency_ms == 2500.5
        assert response.cached is True
        assert response.metadata == {"request_id": "123"}


class TestVulnerabilityAnalysis:
    """Test VulnerabilityAnalysis dataclass."""

    def test_vulnerability_analysis(self):
        """Test vulnerability analysis structure."""
        vulnerabilities = [
            {
                "type": "reentrancy",
                "severity": "high",
                "title": "Reentrancy in withdraw",
                "confidence": 0.9,
            }
        ]
        analysis = VulnerabilityAnalysis(
            vulnerabilities=vulnerabilities,
            severity_assessment={"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            recommendations=["Use ReentrancyGuard"],
            confidence_score=0.9,
            analysis_summary="Found 1 high severity vulnerability",
            raw_response='{"vulnerabilities": []}',
        )
        assert len(analysis.vulnerabilities) == 1
        assert analysis.severity_assessment["high"] == 1
        assert analysis.confidence_score == 0.9


class TestLLMBackend:
    """Test LLMBackend abstract class."""

    def test_backend_init(self):
        """Test backend initialization."""
        config = LLMConfig(provider=LLMProvider.OLLAMA, model="test")

        # Create concrete implementation for testing
        class TestBackend(LLMBackend):
            async def analyze(self, prompt, context=None):
                return LLMResponse(content="test", provider="test", model="test")

            async def health_check(self):
                return True

        backend = TestBackend(config)
        assert backend.config == config
        assert backend.available is False

    def test_system_prompt(self):
        """Test system prompt generation."""
        config = LLMConfig(provider=LLMProvider.OLLAMA, model="test")

        class TestBackend(LLMBackend):
            async def analyze(self, prompt, context=None):
                return LLMResponse(content="test", provider="test", model="test")

            async def health_check(self):
                return True

        backend = TestBackend(config)
        prompt = backend.get_system_prompt()

        assert "Solidity" in prompt
        assert "security" in prompt.lower()
        assert "vulnerabilities" in prompt.lower()
        assert "JSON" in prompt

    def test_system_prompt_has_no_taxonomy_placeholders(self):
        """Taxonomy examples should not teach models to emit placeholders."""
        config = LLMConfig(provider=LLMProvider.OLLAMA, model="test")

        class TestBackend(LLMBackend):
            async def analyze(self, prompt, context=None):
                return LLMResponse(content="test", provider="test", model="test")

            async def health_check(self):
                return True

        prompt = TestBackend(config).get_system_prompt()
        assert "SWC-XXX" not in prompt
        assert "CWE-XXX" not in prompt
        assert "SWC-107" in prompt
        assert "CWE-841" in prompt


class TestOllamaBackend:
    """Test OllamaBackend implementation."""

    def test_init_default_url(self):
        """Test default base URL."""
        config = LLMConfig(provider=LLMProvider.OLLAMA, model="codellama")
        backend = OllamaBackend(config)
        assert backend.base_url == "http://localhost:11434"

    def test_init_custom_url(self):
        """Test custom base URL."""
        config = LLMConfig(
            provider=LLMProvider.OLLAMA, model="codellama", base_url="http://custom:8080"
        )
        backend = OllamaBackend(config)
        assert backend.base_url == "http://custom:8080"

    def test_health_check_unavailable(self):
        """Test health check when server unavailable."""
        config = LLMConfig(
            provider=LLMProvider.OLLAMA, model="codellama", base_url="http://nonexistent:11434"
        )
        backend = OllamaBackend(config)
        result = asyncio.run(backend.health_check())
        assert result is False
        assert backend.available is False

    def test_health_check_structure(self):
        """Test health check method structure."""
        config = LLMConfig(provider=LLMProvider.OLLAMA, model="codellama")
        backend = OllamaBackend(config)
        assert hasattr(backend, "health_check")
        assert backend.config.model == "codellama"

    def test_analyze_structure(self):
        """Test analyze method structure."""
        config = LLMConfig(provider=LLMProvider.OLLAMA, model="codellama")
        backend = OllamaBackend(config)
        assert hasattr(backend, "analyze")
        assert hasattr(backend, "config")

    def test_analyze_context_prompt_sorts_keys(self):
        """Test context serialization is deterministic in provider prompts."""

        async def run_test():
            config = LLMConfig(provider=LLMProvider.OLLAMA, model="codellama")
            backend = OllamaBackend(config)

            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "message": {"content": "{}"},
                    "eval_count": 1,
                    "prompt_eval_count": 2,
                }
            )
            mock_session = _aiohttp_session_with_response("post", mock_response)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                await backend.analyze("prompt", {"z_key": 1, "a_key": 2})

            post_payload = mock_session.__aenter__.return_value.post.call_args.kwargs["json"]
            system_prompt = post_payload["messages"][0]["content"]
            assert system_prompt.index('"a_key"') < system_prompt.index('"z_key"')

        asyncio.run(run_test())

    def test_analyze_context_prompt_sanitizes_non_json_shapes(self):
        """Test provider context prompt serialization handles opaque objects safely."""

        class OpaqueContext:
            pass

        async def run_test():
            config = LLMConfig(provider=LLMProvider.OLLAMA, model="codellama")
            backend = OllamaBackend(config)

            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "message": {"content": "{}"},
                    "eval_count": 1,
                    "prompt_eval_count": 2,
                }
            )
            mock_session = _aiohttp_session_with_response("post", mock_response)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                await backend.analyze(
                    "prompt",
                    {
                        "opaque": OpaqueContext(),
                        "raw_bytes": b"secret bytes",
                        "nested": {"values": {3, 1, 2}},
                    },
                )

            post_payload = mock_session.__aenter__.return_value.post.call_args.kwargs["json"]
            system_prompt = post_payload["messages"][0]["content"]
            assert '"opaque": "<non-serializable:OpaqueContext>"' in system_prompt
            assert '"raw_bytes": "<bytes:12>"' in system_prompt
            assert '"values": [\n      1,\n      2,\n      3\n    ]' in system_prompt
            assert "object at 0x" not in system_prompt
            assert "secret bytes" not in system_prompt

        asyncio.run(run_test())

    def test_analyze_rejects_malformed_response_object(self):
        """Test malformed Ollama response payloads fail as provider errors."""

        async def run_test():
            config = LLMConfig(provider=LLMProvider.OLLAMA, model="codellama")
            backend = OllamaBackend(config)

            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=["not", "an", "object"])
            mock_session = _aiohttp_session_with_response("post", mock_response)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                with pytest.raises(ValueError, match="expected object"):
                    await backend.analyze("prompt")

        asyncio.run(run_test())

    def test_analyze_rejects_malformed_response_content(self):
        """Test malformed Ollama message content cannot become an LLMResponse."""

        async def run_test():
            config = LLMConfig(provider=LLMProvider.OLLAMA, model="codellama")
            backend = OllamaBackend(config)

            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "message": {"content": {"text": "not a string"}},
                    "eval_count": 1,
                    "prompt_eval_count": 2,
                }
            )
            mock_session = _aiohttp_session_with_response("post", mock_response)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                with pytest.raises(ValueError, match="content must be str"):
                    await backend.analyze("prompt")

        asyncio.run(run_test())

    def test_analyze_rejects_bool_token_counts(self):
        """Test boolean Ollama token counts cannot cross the response boundary."""

        async def run_test():
            config = LLMConfig(provider=LLMProvider.OLLAMA, model="codellama")
            backend = OllamaBackend(config)

            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "message": {"content": "{}"},
                    "eval_count": True,
                    "prompt_eval_count": 2,
                }
            )
            mock_session = _aiohttp_session_with_response("post", mock_response)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                with pytest.raises(ValueError, match="token counts must be integers"):
                    await backend.analyze("prompt")

        asyncio.run(run_test())

    def test_analyze_rejects_negative_token_counts(self):
        """Test negative Ollama token counts cannot cross the response boundary."""

        async def run_test():
            config = LLMConfig(provider=LLMProvider.OLLAMA, model="codellama")
            backend = OllamaBackend(config)

            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "message": {"content": "{}"},
                    "eval_count": -1,
                    "prompt_eval_count": 2,
                }
            )
            mock_session = _aiohttp_session_with_response("post", mock_response)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                with pytest.raises(ValueError, match="token counts must be non-negative"):
                    await backend.analyze("prompt")

        asyncio.run(run_test())


class TestOpenAIBackend:
    """Test OpenAIBackend implementation."""

    def test_init_with_env_key(self):
        """Test initialization with environment key."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model="gpt-4")

        with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}):
            backend = OpenAIBackend(config)
            assert backend.api_key == "test-key"

    def test_init_with_config_key(self):
        """Test initialization with config key."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model="gpt-4", api_key="config-key")
        backend = OpenAIBackend(config)
        assert backend.api_key == "config-key"

    def test_health_check_with_key(self):
        """Test health check with API key."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model="gpt-4", api_key="test-key")
        backend = OpenAIBackend(config)
        result = asyncio.run(backend.health_check())
        assert result is True
        assert backend.available is True

    def test_health_check_no_key(self):
        """Test health check without API key."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model="gpt-4")
        backend = OpenAIBackend(config)
        backend.api_key = None
        result = asyncio.run(backend.health_check())
        assert result is False

    def test_analyze_rejects_malformed_usage_tokens(self):
        """Test malformed OpenAI token stats cannot cross the response boundary."""

        async def run_test():
            class FakeAsyncOpenAI:
                def __init__(self, **_kwargs):
                    self.chat = SimpleNamespace(
                        completions=SimpleNamespace(create=AsyncMock(return_value=response))
                    )

            response = SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content="{}"))],
                usage=SimpleNamespace(total_tokens="12"),
            )
            fake_openai = SimpleNamespace(AsyncOpenAI=FakeAsyncOpenAI)
            config = LLMConfig(provider=LLMProvider.OPENAI, model="gpt-4", api_key="key")
            backend = OpenAIBackend(config)

            with patch.dict(sys.modules, {"openai": fake_openai}):
                with pytest.raises(ValueError, match="usage.total_tokens must be int"):
                    await backend.analyze("prompt")

        asyncio.run(run_test())


class TestAnthropicBackend:
    """Test AnthropicBackend implementation."""

    def test_init_with_env_key(self):
        """Test initialization with environment key."""
        config = LLMConfig(provider=LLMProvider.ANTHROPIC, model="claude-3-opus")

        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            backend = AnthropicBackend(config)
            assert backend.api_key == "test-key"

    def test_init_with_config_key(self):
        """Test initialization with config key."""
        config = LLMConfig(
            provider=LLMProvider.ANTHROPIC, model="claude-3-opus", api_key="config-key"
        )
        backend = AnthropicBackend(config)
        assert backend.api_key == "config-key"

    def test_health_check_with_key(self):
        """Test health check with API key."""
        config = LLMConfig(
            provider=LLMProvider.ANTHROPIC, model="claude-3-opus", api_key="test-key"
        )
        backend = AnthropicBackend(config)
        result = asyncio.run(backend.health_check())
        assert result is True

    def test_health_check_no_key(self):
        """Test health check without API key."""
        config = LLMConfig(provider=LLMProvider.ANTHROPIC, model="claude-3-opus")
        backend = AnthropicBackend(config)
        backend.api_key = None
        result = asyncio.run(backend.health_check())
        assert result is False

    def test_analyze_rejects_malformed_usage_tokens(self):
        """Test malformed Anthropic token stats cannot cross the response boundary."""

        async def run_test():
            class FakeAsyncAnthropic:
                def __init__(self, **_kwargs):
                    self.messages = SimpleNamespace(create=AsyncMock(return_value=response))

            response = SimpleNamespace(
                content=[SimpleNamespace(text="{}")],
                usage=SimpleNamespace(input_tokens=1, output_tokens=-1),
            )
            fake_anthropic = SimpleNamespace(AsyncAnthropic=FakeAsyncAnthropic)
            config = LLMConfig(
                provider=LLMProvider.ANTHROPIC,
                model="claude-3-opus",
                api_key="key",
            )
            backend = AnthropicBackend(config)

            with patch.dict(sys.modules, {"anthropic": fake_anthropic}):
                with pytest.raises(ValueError, match="usage.output_tokens must be non-negative"):
                    await backend.analyze("prompt")

        asyncio.run(run_test())


class TestDeepSeekBackend:
    """Test DeepSeekBackend implementation."""

    def test_init_with_env_key(self):
        """Test initialization with environment key."""
        config = LLMConfig(provider=LLMProvider.DEEPSEEK, model="deepseek-v4-flash")

        with patch.dict("os.environ", {"DEEPSEEK_API_KEY": "test-key"}):
            backend = DeepSeekBackend(config)
            assert backend.api_key == "test-key"
            assert backend.base_url == "https://api.deepseek.com"

    def test_init_with_config_key_and_base_url(self):
        """Test initialization with explicit key and base URL."""
        config = LLMConfig(
            provider=LLMProvider.DEEPSEEK,
            model="deepseek-v4-pro",
            api_key="config-key",
            base_url="https://custom.deepseek.example",
        )
        backend = DeepSeekBackend(config)
        assert backend.api_key == "config-key"
        assert backend.base_url == "https://custom.deepseek.example"

    def test_health_check_with_key(self):
        """Test health check with API key and configured model returned by API."""
        config = LLMConfig(
            provider=LLMProvider.DEEPSEEK,
            model="deepseek-v4-flash",
            api_key="test-key",
        )
        backend = DeepSeekBackend(config)

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"data": [{"id": "deepseek-v4-flash"}]})
        mock_session = _aiohttp_session_with_response("get", mock_response)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = asyncio.run(backend.health_check())

        assert result is True
        assert backend.available is True

    def test_health_check_missing_model(self):
        """Test health check fails when DeepSeek does not expose the configured model."""
        config = LLMConfig(
            provider=LLMProvider.DEEPSEEK,
            model="deepseek-v4-pro",
            api_key="test-key",
        )
        backend = DeepSeekBackend(config)

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"data": [{"id": "deepseek-v4-flash"}]})
        mock_session = _aiohttp_session_with_response("get", mock_response)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = asyncio.run(backend.health_check())

        assert result is False
        assert backend.available is False

    def test_health_check_connection_error(self):
        """Test health check handles DeepSeek endpoint failures."""
        config = LLMConfig(
            provider=LLMProvider.DEEPSEEK,
            model="deepseek-v4-flash",
            api_key="test-key",
        )
        backend = DeepSeekBackend(config)

        mock_session_instance = MagicMock()
        mock_session_instance.get.side_effect = aiohttp.ClientError("Connection refused")

        mock_session = MagicMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session_instance)
        mock_session.__aexit__ = AsyncMock(return_value=None)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = asyncio.run(backend.health_check())

        assert result is False
        assert backend.available is False

    def test_health_check_no_key(self):
        """Test health check without API key."""
        config = LLMConfig(provider=LLMProvider.DEEPSEEK, model="deepseek-v4-flash")
        backend = DeepSeekBackend(config)
        backend.api_key = None
        result = asyncio.run(backend.health_check())
        assert result is False

    def test_analyze_rejects_bool_usage_tokens(self):
        """Test boolean DeepSeek token stats cannot cross the response boundary."""

        async def run_test():
            class FakeAsyncOpenAI:
                def __init__(self, **_kwargs):
                    self.chat = SimpleNamespace(
                        completions=SimpleNamespace(create=AsyncMock(return_value=response))
                    )

            response = SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content="{}"))],
                usage=SimpleNamespace(total_tokens=True),
            )
            fake_openai = SimpleNamespace(AsyncOpenAI=FakeAsyncOpenAI)
            config = LLMConfig(
                provider=LLMProvider.DEEPSEEK,
                model="deepseek-v4-flash",
                api_key="key",
            )
            backend = DeepSeekBackend(config)

            with patch.dict(sys.modules, {"openai": fake_openai}):
                with pytest.raises(ValueError, match="usage.total_tokens must be int"):
                    await backend.analyze("prompt")

        asyncio.run(run_test())


class TestLLMOrchestrator:
    """Test LLMOrchestrator class."""

    def test_default_init(self):
        """Test default initialization."""
        orchestrator = LLMOrchestrator()
        assert len(orchestrator.backends) > 0
        assert orchestrator.cache == {}
        assert orchestrator.cache_ttl == 3600

    def test_default_init_uses_deepseek_env_provider(self):
        """Test default initialization can use DeepSeek from environment."""
        with patch.dict(
            "os.environ",
            {
                "MIESC_LLM_PROVIDER": "deepseek",
                "MIESC_LLM_MODEL": "deepseek-v4-pro",
                "DEEPSEEK_API_KEY": "test-key",
            },
        ):
            orchestrator = LLMOrchestrator()

        assert "deepseek:deepseek-v4-pro" in orchestrator.backends
        assert orchestrator.primary_provider == "deepseek:deepseek-v4-pro"

    def test_default_init_unknown_env_provider_falls_back_to_ollama(self):
        """Test unknown env provider falls back to Ollama."""
        with patch.dict("os.environ", {"MIESC_LLM_PROVIDER": "unknown"}, clear=False):
            orchestrator = LLMOrchestrator()

        assert "ollama:deepseek-coder:6.7b" in orchestrator.backends

    def test_custom_init(self):
        """Test custom initialization."""
        configs = [
            LLMConfig(provider=LLMProvider.OLLAMA, model="codellama"),
            LLMConfig(provider=LLMProvider.OPENAI, model="gpt-4", api_key="key"),
            LLMConfig(provider=LLMProvider.DEEPSEEK, model="deepseek-v4-flash", api_key="key"),
        ]
        orchestrator = LLMOrchestrator(configs)
        assert len(orchestrator.backends) == 3

    def test_add_backend(self):
        """Test adding backends."""
        orchestrator = LLMOrchestrator([])
        config = LLMConfig(provider=LLMProvider.OLLAMA, model="test")
        orchestrator._add_backend(config)
        assert "ollama:test" in orchestrator.backends

    def test_add_backend_ignores_malformed_model_identity(self):
        """Test malformed model identities are not registered as backend keys."""
        orchestrator = LLMOrchestrator([])
        config = LLMConfig(provider=LLMProvider.OLLAMA, model="test")
        config.model = ["not", "a", "model"]

        orchestrator._add_backend(config)

        assert orchestrator.backends == {}
        assert orchestrator.primary_provider is None

    def test_add_backend_strips_model_identity(self):
        """Test model identities are normalized before backend registration."""
        orchestrator = LLMOrchestrator([])
        config = LLMConfig(provider=LLMProvider.OLLAMA, model="  codellama  ")

        orchestrator._add_backend(config)

        assert "ollama:codellama" in orchestrator.backends
        assert orchestrator.primary_provider == "ollama:codellama"
        assert orchestrator.backends["ollama:codellama"].config.model == "codellama"

    def test_add_backend_rejects_control_character_model_identity(self):
        """Test control characters cannot cross the model identifier boundary."""
        orchestrator = LLMOrchestrator([])
        config = LLMConfig(provider=LLMProvider.OLLAMA, model="codellama\nopenai:gpt-4")

        orchestrator._add_backend(config)

        assert orchestrator.backends == {}
        assert orchestrator.primary_provider is None

    def test_normalized_model_identifier_accepts_bytes_and_strips(self):
        """Test bytes model identifiers are decoded and normalized."""
        assert _normalized_model_identifier(b"  codellama  ") == "codellama"

    def test_safe_backend_name_rejects_overlong_values(self):
        """Test backend names are bounded before being exposed in status output."""
        assert _is_safe_backend_name("codellama:13b") is True
        assert _is_safe_backend_name("x" * 129) is False

    def test_add_backend_allows_colon_model_identity(self):
        """Test normal provider model identifiers with colons remain valid."""
        orchestrator = LLMOrchestrator([])
        config = LLMConfig(provider=LLMProvider.OLLAMA, model="deepseek-coder:6.7b")

        orchestrator._add_backend(config)

        assert "ollama:deepseek-coder:6.7b" in orchestrator.backends

    def test_add_deepseek_backend(self):
        """Test adding DeepSeek backend."""
        orchestrator = LLMOrchestrator([])
        config = LLMConfig(
            provider=LLMProvider.DEEPSEEK,
            model="deepseek-v4-flash",
            api_key="key",
        )
        orchestrator._add_backend(config)
        assert "deepseek:deepseek-v4-flash" in orchestrator.backends

    def test_add_unknown_backend(self):
        """Test adding unknown backend type."""
        orchestrator = LLMOrchestrator([])
        # Create a config with an unsupported provider type
        config = MagicMock()
        config.provider = MagicMock()
        config.provider.value = "unknown"

        # This should log a warning but not crash
        initial_count = len(orchestrator.backends)
        orchestrator._add_backend(config)
        assert len(orchestrator.backends) == initial_count

    def test_initialize(self):
        """Test backend initialization."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model="gpt-4", api_key="test-key")
        orchestrator = LLMOrchestrator([config])
        status = asyncio.run(orchestrator.initialize())

        assert "openai:gpt-4" in status
        assert status["openai:gpt-4"] is True

    def test_initialize_treats_malformed_availability_as_unavailable(self):
        """Test malformed health-check availability cannot mark a backend available."""

        async def run_test():
            config = LLMConfig(provider=LLMProvider.OLLAMA, model="malformed")
            orchestrator = LLMOrchestrator([config])
            backend = orchestrator.backends["ollama:malformed"]
            backend.available = True
            backend.health_check = AsyncMock(return_value={"available": True})

            status = await orchestrator.initialize()

            assert status == {"ollama:malformed": False}
            assert backend.available is False

        asyncio.run(run_test())

    def test_get_available_providers_treats_malformed_status_as_unavailable(self):
        """Test malformed backend availability fields cannot cross status helpers."""
        config = LLMConfig(provider=LLMProvider.OLLAMA, model="malformed")
        orchestrator = LLMOrchestrator([config])
        backend = orchestrator.backends["ollama:malformed"]
        backend.available = {"available": True}

        assert orchestrator.get_available_providers() == []
        assert backend.available is False

    def test_get_available_providers_ignores_malformed_backend_key(self):
        """Test malformed backend keys cannot cross provider status output."""
        config = LLMConfig(provider=LLMProvider.OLLAMA, model="healthy")
        orchestrator = LLMOrchestrator([config])
        orchestrator.backends["ollama:healthy"].available = True

        malformed_backend = MagicMock()
        malformed_backend.available = True
        orchestrator.backends[("ollama", "malformed")] = malformed_backend

        assert orchestrator.get_available_providers() == ["ollama:healthy"]

    def test_get_available_providers_ignores_unsafe_backend_name(self):
        """Test unsafe backend names cannot cross provider status output."""
        config = LLMConfig(provider=LLMProvider.OLLAMA, model="healthy")
        orchestrator = LLMOrchestrator([config])
        orchestrator.backends["ollama:healthy"].available = True

        malformed_backend = MagicMock()
        malformed_backend.available = True
        orchestrator.backends["openai:gpt-4\nollama:shadow"] = malformed_backend
        orchestrator.backends[" anthropic:claude "] = malformed_backend

        assert orchestrator.get_available_providers() == ["ollama:healthy"]

    def test_initialize_ignores_unsafe_backend_name_in_status_export(self):
        """Test unsafe backend names cannot cross initialization status output."""

        async def run_test():
            config = LLMConfig(provider=LLMProvider.OLLAMA, model="healthy")
            orchestrator = LLMOrchestrator([config])
            orchestrator.backends["ollama:healthy"].health_check = AsyncMock(return_value=True)

            malformed_backend = MagicMock()
            malformed_backend.health_check = AsyncMock(return_value=True)
            orchestrator.backends["deepseek:model\rshadow"] = malformed_backend

            status = await orchestrator.initialize()

            assert status == {"ollama:healthy": True}
            malformed_backend.health_check.assert_not_awaited()

        asyncio.run(run_test())

    def test_cache_key_generation(self):
        """Test cache key generation."""
        orchestrator = LLMOrchestrator([])

        key1 = orchestrator._get_cache_key("prompt1", None)
        key2 = orchestrator._get_cache_key("prompt1", None)
        key3 = orchestrator._get_cache_key("prompt2", None)
        key4 = orchestrator._get_cache_key("prompt1", {"context": "test"})
        key5 = orchestrator._get_cache_key("prompt1", {"z": 1, "a": 2})
        key6 = orchestrator._get_cache_key("prompt1", {"a": 2, "z": 1})
        key7 = orchestrator._get_cache_key("prompt1{}", None)

        assert key1 == key2  # Same prompt, same key
        assert key1 != key3  # Different prompt
        assert key1 != key4  # Different context
        assert key5 == key6  # Context key order is stable
        assert key1 != key7  # Prompt/context boundary is explicit

    def test_cache_key_generation_sanitizes_non_json_context(self):
        """Test cache key generation handles non-JSON context shapes."""

        class OpaqueContext:
            pass

        orchestrator = LLMOrchestrator([])

        key1 = orchestrator._get_cache_key(
            "prompt",
            {
                OpaqueContext(): "opaque key",
                "opaque": OpaqueContext(),
                "raw_bytes": b"secret bytes",
                "values": {3, 1, 2},
            },
        )
        key2 = orchestrator._get_cache_key(
            "prompt",
            {
                OpaqueContext(): "opaque key",
                "opaque": OpaqueContext(),
                "raw_bytes": b"secret bytes",
                "values": {2, 3, 1},
            },
        )

        assert len(key1) == 16
        assert key1 == key2

    def test_cache_key_generation_handles_malformed_context_truthiness(self):
        """Test malformed context truthiness cannot break cache key generation."""

        class MalformedContext(dict):
            def __len__(self):
                raise ValueError("bad context length")

        orchestrator = LLMOrchestrator([])

        key1 = orchestrator._get_cache_key("prompt", MalformedContext({"a": 1}))
        key2 = orchestrator._get_cache_key("prompt", MalformedContext({"b": 2}))

        assert len(key1) == 16
        assert key1 != key2

    def test_cache_key_generation_handles_malformed_context_items(self):
        """Test malformed context item traversal falls back at the boundary."""

        class MalformedContext(dict):
            def items(self):
                raise TypeError("bad context items")

        orchestrator = LLMOrchestrator([])

        key1 = orchestrator._get_cache_key("prompt", MalformedContext({"a": 1}))
        key2 = orchestrator._get_cache_key("prompt", MalformedContext({"b": 2}))

        assert len(key1) == 16
        assert key1 == key2

    def test_cache_key_generation_handles_non_string_prompt(self):
        """Test malformed non-string prompts cannot break cache key generation."""
        orchestrator = LLMOrchestrator([])

        bytes_prompt_key = orchestrator._get_cache_key(b"prompt", None)
        string_prompt_key = orchestrator._get_cache_key("prompt", None)
        list_prompt_key = orchestrator._get_cache_key(["prompt"], None)

        assert len(bytes_prompt_key) == 16
        assert bytes_prompt_key != string_prompt_key
        assert bytes_prompt_key != list_prompt_key

    def test_cache_key_generation_handles_opaque_prompt(self):
        """Test opaque prompt objects fall back to a stable type boundary."""

        class OpaquePrompt:
            pass

        orchestrator = LLMOrchestrator([])

        key1 = orchestrator._get_cache_key(OpaquePrompt(), {"a": 1})
        key2 = orchestrator._get_cache_key(OpaquePrompt(), {"a": 1})
        key3 = orchestrator._get_cache_key(OpaquePrompt(), {"a": 2})

        assert len(key1) == 16
        assert key1 == key2
        assert key1 != key3

    def test_cache_key_generation_preserves_non_string_key_boundaries(self):
        """Test non-string context keys cannot collide with same-looking strings."""
        orchestrator = LLMOrchestrator([])

        string_key = orchestrator._get_cache_key("prompt", {"1": "string key"})
        int_key = orchestrator._get_cache_key("prompt", {1: "string key"})
        true_key = orchestrator._get_cache_key("prompt", {True: "bool key"})
        true_string_key = orchestrator._get_cache_key("prompt", {"True": "bool key"})
        none_key = orchestrator._get_cache_key("prompt", {None: "none key"})
        none_string_key = orchestrator._get_cache_key("prompt", {"None": "none key"})

        assert string_key != int_key
        assert true_key != true_string_key
        assert none_key != none_string_key

    def test_cache_key_context_rejects_control_chars(self):
        """Test cache key context helpers collapse control-char text safely."""
        assert _cache_key_context("  safe value  ") == "safe value"
        assert _cache_key_context("safe\nvalue") == {"__text__": "<malformed>"}
        assert _cache_key_dict_key("safe\tkey") == ["str", "<malformed>"]

    def test_safe_backend_error_text_escapes_control_chars(self):
        assert _safe_backend_error_text(RuntimeError("bad\nerror\tmsg")) == "bad\\nerror\\tmsg"

    def test_safe_backend_error_text_truncates_long_messages(self):
        text = _safe_backend_error_text(RuntimeError("x" * 600))
        assert text.endswith("...<truncated>")
        assert len(text) > 500

    def test_cache_key_generation_preserves_nested_key_boundaries(self):
        """Test nested context key normalization remains stable without collisions."""
        orchestrator = LLMOrchestrator([])

        nested_string_key = orchestrator._get_cache_key(
            "prompt",
            {"nested": {"2": "value"}, "ordered": {"z": 1, "a": 2}},
        )
        nested_int_key = orchestrator._get_cache_key(
            "prompt",
            {"ordered": {"a": 2, "z": 1}, "nested": {2: "value"}},
        )
        nested_int_key_reordered = orchestrator._get_cache_key(
            "prompt",
            {"nested": {2: "value"}, "ordered": {"z": 1, "a": 2}},
        )

        assert nested_string_key != nested_int_key
        assert nested_int_key == nested_int_key_reordered

    def test_parse_analysis_valid_json(self):
        """Test parsing valid JSON response."""
        orchestrator = LLMOrchestrator([])
        response = LLMResponse(
            content='{"vulnerabilities": [{"type": "reentrancy", "severity": "high", "confidence": 0.9}], "summary": "Found issues"}',
            provider="test",
            model="test",
        )

        analysis = orchestrator._parse_analysis(response)

        assert len(analysis.vulnerabilities) == 1
        assert analysis.vulnerabilities[0]["type"] == "reentrancy"
        assert analysis.severity_assessment["high"] == 1
        assert "Found issues" in analysis.analysis_summary

    def test_parse_analysis_embedded_json(self):
        """Test parsing JSON embedded in text."""
        orchestrator = LLMOrchestrator([])
        response = LLMResponse(
            content='Here is the analysis:\n{"vulnerabilities": [], "summary": "No issues"}\nEnd of analysis.',
            provider="test",
            model="test",
        )

        analysis = orchestrator._parse_analysis(response)
        assert analysis.vulnerabilities == []
        assert "No issues" in analysis.analysis_summary

    def test_parse_analysis_legacy_fallback_repairs_common_json_errors(self, monkeypatch):
        """Test legacy fallback repairs recoverable LLM JSON formatting errors."""

        class InvalidValidation:
            is_valid = False
            data = None
            errors = ["forced invalid schema"]

        monkeypatch.setattr(
            "src.llm.llm_orchestrator.safe_parse_llm_json",
            lambda *_args, **_kwargs: InvalidValidation(),
        )

        orchestrator = LLMOrchestrator([])
        response = LLMResponse(
            content="""
            Analysis:
            {
                vulnerabilities: [
                    {"type": "regex", "severity": "low", "confidence": 0.4, "description": "pattern \\d+",},
                ],
                "summary": "Recovered by fallback",
            }
            """,
            provider="test",
            model="test",
        )

        analysis = orchestrator._parse_analysis(response)

        assert len(analysis.vulnerabilities) == 1
        assert analysis.vulnerabilities[0]["description"] == r"pattern \d+"
        assert analysis.severity_assessment["low"] == 1
        assert analysis.analysis_summary == "Recovered by fallback"

    def test_parse_analysis_legacy_fallback_filters_invalid_vulnerabilities(self, monkeypatch):
        """Test legacy fallback ignores non-list/non-dict vulnerabilities."""

        class InvalidValidation:
            is_valid = False
            data = None
            errors = ["forced invalid schema"]

        monkeypatch.setattr(
            "src.llm.llm_orchestrator.safe_parse_llm_json",
            lambda *_args, **_kwargs: InvalidValidation(),
        )

        orchestrator = LLMOrchestrator([])
        response = LLMResponse(
            content='{"vulnerabilities": {"severity": "high"}, "summary": "Bad shape"}',
            provider="test",
            model="test",
        )

        analysis = orchestrator._parse_analysis(response)

        assert analysis.vulnerabilities == []
        assert analysis.severity_assessment["high"] == 0
        assert analysis.analysis_summary == "Bad shape"

        mixed_response = LLMResponse(
            content=(
                '{"vulnerabilities": ["noise", {"severity": "high", "type": "reentrancy"}], '
                '"summary": "Mixed shape"}'
            ),
            provider="test",
            model="test",
        )

        mixed_analysis = orchestrator._parse_analysis(mixed_response)

        assert mixed_analysis.vulnerabilities == [{"severity": "high", "type": "reentrancy"}]
        assert mixed_analysis.severity_assessment["high"] == 1

    def test_parse_analysis_invalid_json(self):
        """Test parsing invalid JSON response."""
        orchestrator = LLMOrchestrator([])
        response = LLMResponse(content="This is not JSON at all", provider="test", model="test")

        analysis = orchestrator._parse_analysis(response)
        assert analysis.vulnerabilities == []
        # With no vulnerabilities, confidence is 0 (0 / max(0, 1) = 0)
        assert analysis.confidence_score == 0.0

    def test_parse_analysis_severity_counts(self):
        """Test severity counting in analysis."""
        orchestrator = LLMOrchestrator([])
        response = LLMResponse(
            content='{"vulnerabilities": [{"severity": "critical"}, {"severity": "high"}, {"severity": "high"}, {"severity": "medium"}, {"severity": "low"}, {"severity": "info"}]}',
            provider="test",
            model="test",
        )

        analysis = orchestrator._parse_analysis(response)
        assert analysis.severity_assessment["critical"] == 1
        assert analysis.severity_assessment["high"] == 2
        assert analysis.severity_assessment["medium"] == 1
        assert analysis.severity_assessment["low"] == 1
        assert analysis.severity_assessment["info"] == 1

    def test_select_model_for_task(self):
        """Test model selection for tasks."""
        configs = [
            LLMConfig(provider=LLMProvider.OLLAMA, model="deepseek-coder:6.7b"),
            LLMConfig(provider=LLMProvider.DEEPSEEK, model="deepseek-v4-flash", api_key="key"),
            LLMConfig(provider=LLMProvider.OPENAI, model="gpt-4", api_key="key"),
        ]
        orchestrator = LLMOrchestrator(configs)

        # Mark backends as available
        for backend in orchestrator.backends.values():
            backend.available = True

        selected = orchestrator.select_model_for_task("vulnerability_detection")
        assert selected in orchestrator.backends

    def test_select_model_unknown_task(self):
        """Test model selection for unknown task."""
        config = LLMConfig(provider=LLMProvider.OLLAMA, model="test")
        orchestrator = LLMOrchestrator([config])
        orchestrator.backends["ollama:test"].available = True

        selected = orchestrator.select_model_for_task("unknown_task")
        assert selected == "ollama:test"

    def test_select_model_fallback_skips_malformed_backend_status(self):
        """Test model selection fallback keeps malformed status out of metrics boundary."""
        configs = [
            LLMConfig(provider=LLMProvider.OLLAMA, model="primary"),
            LLMConfig(provider=LLMProvider.ANTHROPIC, model="healthy", api_key="key"),
        ]
        orchestrator = LLMOrchestrator(configs)
        orchestrator.backends["ollama:primary"].available = {"available": True}
        orchestrator.backends["anthropic:healthy"].available = True

        selected = orchestrator.select_model_for_task("vulnerability_detection")

        assert selected == "anthropic:healthy"
        assert orchestrator.backends["ollama:primary"].available is False

    def test_select_model_skips_malformed_backend_values(self):
        """Test model selection ignores malformed backend registry values."""
        config = LLMConfig(provider=LLMProvider.OLLAMA, model="healthy")
        orchestrator = LLMOrchestrator([config])
        orchestrator.backends["ollama:healthy"].available = True
        orchestrator.backends["ollama:shadow"] = object()

        selected = orchestrator.select_model_for_task("vulnerability_detection")

        assert selected == "ollama:healthy"

    def test_preferred_models_rejects_malformed_list_container(self):
        """Test malformed preferred model list containers fall back safely."""
        orchestrator = LLMOrchestrator([])

        assert orchestrator._preferred_models_for_task({"model": "ollama:test"}) == []
        assert orchestrator._preferred_models_for_task("ollama:test") == []
        assert orchestrator._preferred_models_for_task(None) == []

    def test_preferred_models_filters_malformed_entries(self):
        """Test malformed preferred model entries cannot cross selection boundary."""
        orchestrator = LLMOrchestrator([])

        preferences = orchestrator._preferred_models_for_task(
            ["ollama:codellama", None, "", {"model": "openai:gpt-4"}, "openai:gpt-4"]
        )

        assert preferences == ["ollama:codellama", "openai:gpt-4"]

    def test_preferred_models_filters_unsafe_backend_names(self):
        """Test unsafe preferred backend/model names cannot cross selection boundary."""
        orchestrator = LLMOrchestrator([])

        preferences = orchestrator._preferred_models_for_task(
            [
                "ollama:codellama",
                " openai:gpt-4",
                "deepseek:model\nshadow",
                "anthropic:claude\t3",
                "openai:gpt-4",
            ]
        )

        assert preferences == ["ollama:codellama", "openai:gpt-4"]

    def test_preferred_models_accepts_sequence_aliases(self):
        """Test preferred backend alias sequences can be normalized from tuples."""
        orchestrator = LLMOrchestrator([])

        preferences = orchestrator._preferred_models_for_task(
            ("ollama:codellama", None, "openai:gpt-4")
        )

        assert preferences == ["ollama:codellama", "openai:gpt-4"]

    def test_preferred_models_rejects_malformed_list_contents(self):
        """Test malformed preferred model list iteration falls back safely."""

        class MalformedPreferredModels(list):
            def __iter__(self):
                raise ValueError("bad preferred models")

        orchestrator = LLMOrchestrator([])

        assert (
            orchestrator._preferred_models_for_task(MalformedPreferredModels(["ollama:test"]))
            == []
        )

    def test_default_config_from_env_sanitizes_malformed_overrides(self, monkeypatch):
        """Test env-derived defaults reject malformed provider/model/base_url values."""
        monkeypatch.setenv("MIESC_LLM_PROVIDER", "deepseek\x7f")
        monkeypatch.setenv("MIESC_LLM_MODEL", "  custom-model  ")
        monkeypatch.setenv("OLLAMA_HOST", "http://local\nhost")
        monkeypatch.setenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com\n")

        orchestrator = LLMOrchestrator([])
        config = orchestrator._default_config_from_env()

        assert config.provider == LLMProvider.OLLAMA
        assert config.model == "deepseek-coder:6.7b"
        assert config.base_url == "http://localhost:11434"

    def test_response_boundary_error_rejects_blank_strings(self):
        """Test malformed response boundary strings are rejected."""
        orchestrator = LLMOrchestrator([])

        assert (
            orchestrator._response_boundary_error(
                LLMResponse(content=" ", provider="ollama", model="test"),
                "cache",
            )
            is not None
        )
        assert (
            orchestrator._response_boundary_error(
                LLMResponse(content="ok", provider=" ", model="test"),
                "cache",
            )
            is not None
        )

    def test_backend_is_available_resets_malformed_state(self):
        """Test malformed backend availability is normalized in place."""
        orchestrator = LLMOrchestrator([])
        config = LLMConfig(provider=LLMProvider.OLLAMA, model="test")
        backend = OllamaBackend(config)
        backend.available = {"available": True}

        assert orchestrator._backend_is_available("ollama:test", backend) is False
        assert backend.available is False

    def test_get_available_providers(self):
        """Test getting available providers."""
        configs = [
            LLMConfig(provider=LLMProvider.OLLAMA, model="test1"),
            LLMConfig(provider=LLMProvider.OPENAI, model="test2", api_key="key"),
        ]
        orchestrator = LLMOrchestrator(configs)

        # Mark one as available
        orchestrator.backends["openai:test2"].available = True

        available = orchestrator.get_available_providers()
        assert "openai:test2" in available
        assert "ollama:test1" not in available

    def test_clear_cache(self):
        """Test cache clearing."""
        orchestrator = LLMOrchestrator([])
        orchestrator.cache["key1"] = "value1"
        orchestrator.cache["key2"] = "value2"
        orchestrator.cache_timestamps["key1"] = 1.0

        orchestrator.clear_cache()
        assert len(orchestrator.cache) == 0
        assert orchestrator.cache_timestamps == {}

    def test_query_no_backends(self):
        """Test query with no available backends."""
        orchestrator = LLMOrchestrator([])
        orchestrator.backends = {}
        orchestrator.primary_provider = None

        with pytest.raises(RuntimeError, match="No LLM backends available"):
            asyncio.run(orchestrator.query("test prompt"))

    def test_query_from_cache(self):
        """Test query returns cached response."""
        orchestrator = LLMOrchestrator([])

        cached_response = LLMResponse(content="cached content", provider="cache", model="cache")
        cache_key = orchestrator._get_cache_key("test prompt", None)
        orchestrator.cache[cache_key] = cached_response

        result = asyncio.run(orchestrator.query("test prompt"))
        assert result.content == "cached content"
        assert result.cached is True

    def test_query_ignores_malformed_cached_response(self):
        """Test query evicts malformed cache entries and uses an available backend."""

        async def run_test():
            config = LLMConfig(
                provider=LLMProvider.OLLAMA,
                model="fresh",
                retry_attempts=1,
                retry_delay=0,
            )
            orchestrator = LLMOrchestrator([config])
            orchestrator.backends["ollama:fresh"].available = True

            cache_key = orchestrator._get_cache_key("test prompt", None)
            orchestrator.cache[cache_key] = {"content": "cached dict is malformed"}

            fresh_response = LLMResponse(content="fresh content", provider="ollama", model="fresh")
            analyze = AsyncMock(return_value=fresh_response)
            orchestrator.backends["ollama:fresh"].analyze = analyze

            result = await orchestrator.query("test prompt")

            assert result is fresh_response
            assert orchestrator.cache[cache_key] is fresh_response
            analyze.assert_awaited_once()

        asyncio.run(run_test())

    def test_query_ignores_cached_response_with_malformed_content(self):
        """Test query evicts cached LLMResponse entries with non-string content."""

        async def run_test():
            config = LLMConfig(
                provider=LLMProvider.OLLAMA,
                model="fresh",
                retry_attempts=1,
                retry_delay=0,
            )
            orchestrator = LLMOrchestrator([config])
            orchestrator.backends["ollama:fresh"].available = True

            cache_key = orchestrator._get_cache_key("test prompt", None)
            orchestrator.cache[cache_key] = LLMResponse(
                content=["cached", "list"],
                provider="cache",
                model="cache",
            )

            fresh_response = LLMResponse(content="fresh content", provider="ollama", model="fresh")
            analyze = AsyncMock(return_value=fresh_response)
            orchestrator.backends["ollama:fresh"].analyze = analyze

            result = await orchestrator.query("test prompt")

            assert result is fresh_response
            assert orchestrator.cache[cache_key] is fresh_response
            analyze.assert_awaited_once()

        asyncio.run(run_test())

    def test_query_ignores_cached_response_with_malformed_identity_status(self):
        """Test cached LLMResponse identity/status fields cannot cross the boundary."""

        async def run_test():
            config = LLMConfig(
                provider=LLMProvider.OLLAMA,
                model="fresh",
                retry_attempts=1,
                retry_delay=0,
            )
            orchestrator = LLMOrchestrator([config])
            orchestrator.backends["ollama:fresh"].available = True

            cache_key = orchestrator._get_cache_key("test prompt", None)
            cached_response = LLMResponse(
                content="cached content",
                provider="cache",
                model="cache",
            )
            cached_response.provider = ["cache"]
            cached_response.model = {"model": "cache"}
            cached_response.cached = "yes"
            orchestrator.cache[cache_key] = cached_response

            fresh_response = LLMResponse(content="fresh content", provider="ollama", model="fresh")
            analyze = AsyncMock(return_value=fresh_response)
            orchestrator.backends["ollama:fresh"].analyze = analyze

            result = await orchestrator.query("test prompt")

            assert result is fresh_response
            assert orchestrator.cache[cache_key] is fresh_response
            analyze.assert_awaited_once()

        asyncio.run(run_test())

    def test_query_evicts_oldest_cache_entry_at_size_limit(self):
        """Test response caching evicts the oldest entry after crossing the size limit."""

        async def run_test():
            config = LLMConfig(
                provider=LLMProvider.OLLAMA,
                model="fresh",
                retry_attempts=1,
                retry_delay=0,
            )
            orchestrator = LLMOrchestrator([config])
            orchestrator.cache_max_entries = 2
            orchestrator.backends["ollama:fresh"].available = True

            oldest_response = LLMResponse(content="oldest", provider="cache", model="cache")
            middle_response = LLMResponse(content="middle", provider="cache", model="cache")
            oldest_key = orchestrator._get_cache_key("oldest prompt", None)
            middle_key = orchestrator._get_cache_key("middle prompt", None)
            orchestrator.cache[oldest_key] = oldest_response
            orchestrator.cache[middle_key] = middle_response

            fresh_response = LLMResponse(content="fresh content", provider="ollama", model="fresh")
            orchestrator.backends["ollama:fresh"].analyze = AsyncMock(return_value=fresh_response)

            result = await orchestrator.query("fresh prompt")

            assert result is fresh_response
            assert oldest_key not in orchestrator.cache
            assert list(orchestrator.cache.values()) == [middle_response, fresh_response]

        asyncio.run(run_test())

    def test_query_uses_conservative_limit_for_malformed_cache_size(self):
        """Test malformed cache size config cannot break cache eviction."""

        async def run_test():
            config = LLMConfig(
                provider=LLMProvider.OLLAMA,
                model="fresh",
                retry_attempts=1,
                retry_delay=0,
            )
            orchestrator = LLMOrchestrator([config])
            orchestrator.cache_max_entries = "many"
            orchestrator.backends["ollama:fresh"].available = True

            stale_response = LLMResponse(content="stale", provider="cache", model="cache")
            stale_key = orchestrator._get_cache_key("stale prompt", None)
            orchestrator.cache[stale_key] = stale_response

            fresh_response = LLMResponse(content="fresh content", provider="ollama", model="fresh")
            orchestrator.backends["ollama:fresh"].analyze = AsyncMock(return_value=fresh_response)

            result = await orchestrator.query("fresh prompt")

            assert result is fresh_response
            assert list(orchestrator.cache.values()) == [fresh_response]

        asyncio.run(run_test())

    def test_query_evicts_expired_cache_entry(self):
        """Test timestamped cache entries expire after the configured TTL."""

        async def run_test():
            config = LLMConfig(
                provider=LLMProvider.OLLAMA,
                model="fresh",
                retry_attempts=1,
                retry_delay=0,
            )
            orchestrator = LLMOrchestrator([config])
            orchestrator.backends["ollama:fresh"].available = True
            orchestrator.cache_ttl = 1

            cache_key = orchestrator._get_cache_key("test prompt", None)
            cached_response = LLMResponse(content="cached content", provider="cache", model="cache")
            orchestrator.cache[cache_key] = cached_response
            orchestrator.cache_timestamps[cache_key] = 1.0

            fresh_response = LLMResponse(content="fresh content", provider="ollama", model="fresh")
            analyze = AsyncMock(return_value=fresh_response)
            orchestrator.backends["ollama:fresh"].analyze = analyze

            with patch("src.llm.llm_orchestrator.time.time", return_value=3.0):
                result = await orchestrator.query("test prompt")

            assert result is fresh_response
            assert orchestrator.cache[cache_key] is fresh_response
            analyze.assert_awaited_once()

        asyncio.run(run_test())

    def test_query_uses_zero_ttl_for_malformed_cache_ttl(self):
        """Test malformed cache TTL config cannot break cache freshness checks."""

        async def run_test():
            config = LLMConfig(
                provider=LLMProvider.OLLAMA,
                model="fresh",
                retry_attempts=1,
                retry_delay=0,
            )
            orchestrator = LLMOrchestrator([config])
            orchestrator.backends["ollama:fresh"].available = True
            orchestrator.cache_ttl = "forever"

            cache_key = orchestrator._get_cache_key("test prompt", None)
            cached_response = LLMResponse(content="cached content", provider="cache", model="cache")
            orchestrator.cache[cache_key] = cached_response
            orchestrator.cache_timestamps[cache_key] = 1.0

            fresh_response = LLMResponse(content="fresh content", provider="ollama", model="fresh")
            analyze = AsyncMock(return_value=fresh_response)
            orchestrator.backends["ollama:fresh"].analyze = analyze

            with patch("src.llm.llm_orchestrator.time.time", return_value=1.1):
                result = await orchestrator.query("test prompt")

            assert result is fresh_response
            assert orchestrator.cache[cache_key] is fresh_response
            analyze.assert_awaited_once()

        asyncio.run(run_test())

    def test_query_resets_malformed_cache_state_before_writing_response(self):
        """Test malformed orchestrator cache state cannot break response caching."""

        async def run_test():
            config = LLMConfig(
                provider=LLMProvider.OLLAMA,
                model="fresh",
                retry_attempts=1,
                retry_delay=0,
            )
            orchestrator = LLMOrchestrator([config])
            orchestrator.cache = ["not", "a", "cache"]
            orchestrator.backends["ollama:fresh"].available = True

            fresh_response = LLMResponse(content="fresh content", provider="ollama", model="fresh")
            orchestrator.backends["ollama:fresh"].analyze = AsyncMock(return_value=fresh_response)

            result = await orchestrator.query("fresh prompt")

            assert result is fresh_response
            assert orchestrator.cache == {
                orchestrator._get_cache_key("fresh prompt", None): fresh_response
            }

        asyncio.run(run_test())

    def test_clear_cache_resets_malformed_cache_state(self):
        """Test malformed orchestrator cache state cannot break cache clearing."""
        orchestrator = LLMOrchestrator([])
        orchestrator.cache = ("not", "a", "cache")

        orchestrator.clear_cache()

        assert orchestrator.cache == {}

    def test_query_falls_back_after_client_error(self):
        """Test query falls back when primary backend has a client error."""

        async def run_test():
            configs = [
                LLMConfig(
                    provider=LLMProvider.OLLAMA,
                    model="primary",
                    retry_attempts=1,
                    retry_delay=0,
                ),
                LLMConfig(
                    provider=LLMProvider.OPENAI,
                    model="fallback",
                    api_key="key",
                    retry_attempts=1,
                    retry_delay=0,
                ),
            ]
            orchestrator = LLMOrchestrator(configs)
            orchestrator.backends["ollama:primary"].available = True
            orchestrator.backends["openai:fallback"].available = True

            primary_analyze = AsyncMock(side_effect=aiohttp.ClientError("connection reset"))
            fallback_response = LLMResponse(
                content="fallback content",
                provider="openai",
                model="fallback",
            )
            fallback_analyze = AsyncMock(return_value=fallback_response)
            orchestrator.backends["ollama:primary"].analyze = primary_analyze
            orchestrator.backends["openai:fallback"].analyze = fallback_analyze

            result = await orchestrator.query("test prompt")

            assert result is fallback_response
            primary_analyze.assert_awaited_once()
            fallback_analyze.assert_awaited_once()

        asyncio.run(run_test())

    def test_query_falls_back_after_malformed_provider_response(self):
        """Test query falls back when a backend returns an invalid result shape."""

        async def run_test():
            configs = [
                LLMConfig(
                    provider=LLMProvider.OLLAMA,
                    model="primary",
                    retry_attempts=1,
                    retry_delay=0,
                ),
                LLMConfig(
                    provider=LLMProvider.OPENAI,
                    model="fallback",
                    api_key="key",
                    retry_attempts=1,
                    retry_delay=0,
                ),
            ]
            orchestrator = LLMOrchestrator(configs)
            orchestrator.backends["ollama:primary"].available = True
            orchestrator.backends["openai:fallback"].available = True

            malformed_response = {"content": "dict shape is not an LLMResponse"}
            fallback_response = LLMResponse(
                content="fallback content",
                provider="openai",
                model="fallback",
            )
            primary_analyze = AsyncMock(return_value=malformed_response)
            fallback_analyze = AsyncMock(return_value=fallback_response)
            orchestrator.backends["ollama:primary"].analyze = primary_analyze
            orchestrator.backends["openai:fallback"].analyze = fallback_analyze

            result = await orchestrator.query("test prompt")

            assert result is fallback_response
            assert list(orchestrator.cache.values()) == [fallback_response]
            primary_analyze.assert_awaited_once()
            fallback_analyze.assert_awaited_once()

        asyncio.run(run_test())

    def test_query_falls_back_after_malformed_response_content(self):
        """Test query falls back when a backend returns non-string content."""

        async def run_test():
            configs = [
                LLMConfig(
                    provider=LLMProvider.OLLAMA,
                    model="primary",
                    retry_attempts=1,
                    retry_delay=0,
                ),
                LLMConfig(
                    provider=LLMProvider.OPENAI,
                    model="fallback",
                    api_key="key",
                    retry_attempts=1,
                    retry_delay=0,
                ),
            ]
            orchestrator = LLMOrchestrator(configs)
            orchestrator.backends["ollama:primary"].available = True
            orchestrator.backends["openai:fallback"].available = True

            malformed_response = LLMResponse(
                content=["not", "text"],
                provider="ollama",
                model="primary",
            )
            fallback_response = LLMResponse(
                content="fallback content",
                provider="openai",
                model="fallback",
            )
            primary_analyze = AsyncMock(return_value=malformed_response)
            fallback_analyze = AsyncMock(return_value=fallback_response)
            orchestrator.backends["ollama:primary"].analyze = primary_analyze
            orchestrator.backends["openai:fallback"].analyze = fallback_analyze

            result = await orchestrator.query("test prompt")

            assert result is fallback_response
            assert list(orchestrator.cache.values()) == [fallback_response]
            primary_analyze.assert_awaited_once()
            fallback_analyze.assert_awaited_once()

        asyncio.run(run_test())

    def test_query_falls_back_after_malformed_response_usage_metadata(self):
        """Test query falls back when response usage or metadata fields are malformed."""

        async def run_test():
            configs = [
                LLMConfig(
                    provider=LLMProvider.OLLAMA,
                    model="primary",
                    retry_attempts=1,
                    retry_delay=0,
                ),
                LLMConfig(
                    provider=LLMProvider.OPENAI,
                    model="fallback",
                    api_key="key",
                    retry_attempts=1,
                    retry_delay=0,
                ),
            ]
            orchestrator = LLMOrchestrator(configs)
            orchestrator.backends["ollama:primary"].available = True
            orchestrator.backends["openai:fallback"].available = True

            malformed_response = LLMResponse(
                content="primary content",
                provider="ollama",
                model="primary",
                tokens_used=-1,
                metadata=["not", "metadata"],
            )
            fallback_response = LLMResponse(
                content="fallback content",
                provider="openai",
                model="fallback",
                tokens_used=12,
                metadata={"request_id": "ok"},
            )
            primary_analyze = AsyncMock(return_value=malformed_response)
            fallback_analyze = AsyncMock(return_value=fallback_response)
            orchestrator.backends["ollama:primary"].analyze = primary_analyze
            orchestrator.backends["openai:fallback"].analyze = fallback_analyze

            result = await orchestrator.query("test prompt")

            assert result is fallback_response
            assert list(orchestrator.cache.values()) == [fallback_response]
            primary_analyze.assert_awaited_once()
            fallback_analyze.assert_awaited_once()

        asyncio.run(run_test())

    def test_query_uses_single_attempt_for_malformed_retry_attempts(self):
        """Test malformed retry_attempts cannot crash the query attempt loop."""

        async def run_test():
            config = LLMConfig(
                provider=LLMProvider.OLLAMA,
                model="primary",
                retry_attempts=3,
                retry_delay=0,
            )
            config.retry_attempts = True
            orchestrator = LLMOrchestrator([config])
            orchestrator.backends["ollama:primary"].available = True

            response = LLMResponse(
                content="primary content",
                provider="ollama",
                model="primary",
            )
            analyze = AsyncMock(return_value=response)
            orchestrator.backends["ollama:primary"].analyze = analyze

            result = await orchestrator.query("test prompt")

            assert result is response
            analyze.assert_awaited_once()

        asyncio.run(run_test())

    def test_query_uses_zero_delay_for_malformed_retry_delay(self):
        """Test malformed retry_delay cannot break retry sleep handling."""

        async def run_test():
            config = LLMConfig(
                provider=LLMProvider.OLLAMA,
                model="primary",
                retry_attempts=2,
                retry_delay=0,
            )
            config.retry_delay = "soon"
            orchestrator = LLMOrchestrator([config])
            orchestrator.backends["ollama:primary"].available = True

            response = LLMResponse(
                content="primary content",
                provider="ollama",
                model="primary",
            )
            analyze = AsyncMock(side_effect=[aiohttp.ClientError("transient"), response])
            orchestrator.backends["ollama:primary"].analyze = analyze

            with patch("asyncio.sleep", new_callable=AsyncMock) as sleep:
                result = await orchestrator.query("test prompt")

            assert result is response
            assert analyze.await_count == 2
            sleep.assert_awaited_once_with(0.0)

        asyncio.run(run_test())

    def test_query_ignores_malformed_provider_route(self):
        """Test query falls back when provider routing input has an invalid shape."""

        async def run_test():
            config = LLMConfig(
                provider=LLMProvider.OLLAMA,
                model="primary",
                retry_attempts=1,
                retry_delay=0,
            )
            orchestrator = LLMOrchestrator([config])
            orchestrator.backends["ollama:primary"].available = True

            response = LLMResponse(
                content="primary content",
                provider="ollama",
                model="primary",
            )
            analyze = AsyncMock(return_value=response)
            orchestrator.backends["ollama:primary"].analyze = analyze

            result = await orchestrator.query("test prompt", provider=["not", "a", "key"])

            assert result is response
            analyze.assert_awaited_once()

        asyncio.run(run_test())

    def test_query_ignores_malformed_backend_key(self):
        """Test fallback routing skips malformed internal backend keys."""

        async def run_test():
            config = LLMConfig(
                provider=LLMProvider.OLLAMA,
                model="primary",
                retry_attempts=1,
                retry_delay=0,
            )
            orchestrator = LLMOrchestrator([config])
            orchestrator.primary_provider = None
            orchestrator.backends["ollama:primary"].available = True

            malformed_backend = MagicMock()
            malformed_backend.available = True
            malformed_backend.analyze = AsyncMock(
                return_value=LLMResponse(
                    content="malformed-key content",
                    provider="ollama",
                    model="malformed",
                )
            )
            orchestrator.backends[("ollama", "malformed")] = malformed_backend

            response = LLMResponse(
                content="primary content",
                provider="ollama",
                model="primary",
            )
            analyze = AsyncMock(return_value=response)
            orchestrator.backends["ollama:primary"].analyze = analyze

            result = await orchestrator.query("test prompt")

            assert result is response
            malformed_backend.analyze.assert_not_awaited()
            analyze.assert_awaited_once()

        asyncio.run(run_test())

    def test_query_skips_backend_with_malformed_status_payload(self):
        """Test query routing treats malformed backend status as unavailable."""

        async def run_test():
            config = LLMConfig(
                provider=LLMProvider.OLLAMA,
                model="primary",
                retry_attempts=1,
                retry_delay=0,
            )
            orchestrator = LLMOrchestrator([config])
            backend = orchestrator.backends["ollama:primary"]
            backend.available = {"available": True}
            backend.analyze = AsyncMock(
                return_value=LLMResponse(
                    content="primary content",
                    provider="ollama",
                    model="primary",
                )
            )

            with pytest.raises(RuntimeError, match="All LLM backends failed"):
                await orchestrator.query("test prompt")

            backend.analyze.assert_not_awaited()
            assert backend.available is False

        asyncio.run(run_test())

    def test_query_bounds_backend_exception_text(self):
        """Test backend exception text cannot cross the final error boundary raw."""

        async def run_test():
            config = LLMConfig(
                provider=LLMProvider.OLLAMA,
                model="primary",
                retry_attempts=1,
                retry_delay=0,
            )
            orchestrator = LLMOrchestrator([config])
            backend = orchestrator.backends["ollama:primary"]
            backend.available = True
            backend.analyze = AsyncMock(
                side_effect=RuntimeError("bad\nline\tname\x00" + ("x" * 600))
            )

            with pytest.raises(RuntimeError) as exc_info:
                await orchestrator.query("test prompt")

            message = str(exc_info.value)
            assert "bad\\nline\\tname\\x00" in message
            assert "\x00" not in message
            assert "\n" not in message
            assert "...<truncated>" in message
            assert len(message) < 700

        asyncio.run(run_test())

    def test_query_handles_unprintable_backend_exception(self):
        """Test backend exceptions with broken __str__ stay inside query errors."""

        class UnprintableRuntimeError(RuntimeError):
            def __str__(self):
                raise ValueError("broken exception string")

        async def run_test():
            config = LLMConfig(
                provider=LLMProvider.OLLAMA,
                model="primary",
                retry_attempts=1,
                retry_delay=0,
            )
            orchestrator = LLMOrchestrator([config])
            backend = orchestrator.backends["ollama:primary"]
            backend.available = True
            backend.analyze = AsyncMock(side_effect=UnprintableRuntimeError())

            with pytest.raises(RuntimeError) as exc_info:
                await orchestrator.query("test prompt")

            assert "<unprintable:UnprintableRuntimeError>" in str(exc_info.value)

        asyncio.run(run_test())

    def test_analyze_contract_structure(self):
        """Test analyze_contract method structure."""
        config = LLMConfig(provider=LLMProvider.OPENAI, model="gpt-4", api_key="test-key")
        orchestrator = LLMOrchestrator([config])

        # Mock the query method
        mock_response = LLMResponse(
            content='{"vulnerabilities": [], "summary": "Safe"}', provider="openai", model="gpt-4"
        )

        async def mock_query(*args, **kwargs):
            return mock_response

        orchestrator.query = mock_query

        result = asyncio.run(orchestrator.analyze_contract("contract Test {}"))

        assert isinstance(result, VulnerabilityAnalysis)
        assert result.analysis_summary == "Safe"


class TestAnalyzeSolidity:
    """Test the convenience function."""

    def test_analyze_solidity_callable(self):
        """Test analyze_solidity function is callable."""
        assert callable(analyze_solidity)

    def test_analyze_solidity_structure(self):
        """Test analyze_solidity function structure with mock."""
        # We just test that the function exists and has the right signature
        with patch.object(LLMOrchestrator, "initialize", new_callable=AsyncMock) as mock_init:
            with patch.object(
                LLMOrchestrator, "analyze_contract", new_callable=AsyncMock
            ) as mock_analyze:
                mock_init.return_value = {"ollama:deepseek-coder:6.7b": False}
                mock_analyze.return_value = VulnerabilityAnalysis(
                    vulnerabilities=[],
                    severity_assessment={
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "info": 0,
                    },
                    recommendations=[],
                    confidence_score=1.0,
                    analysis_summary="No issues",
                    raw_response="",
                )

                # This should not raise
                assert True


class TestIntegration:
    """Integration tests for LLM Orchestrator."""

    def test_full_workflow_structure(self):
        """Test the full analysis workflow structure."""
        # Create orchestrator with multiple backends
        configs = [
            LLMConfig(provider=LLMProvider.OLLAMA, model="codellama"),
            LLMConfig(provider=LLMProvider.OPENAI, model="gpt-4", api_key="test"),
            LLMConfig(provider=LLMProvider.ANTHROPIC, model="claude-3", api_key="test"),
            LLMConfig(
                provider=LLMProvider.DEEPSEEK,
                model="deepseek-v4-flash",
                api_key="test",
            ),
        ]

        orchestrator = LLMOrchestrator(configs)

        # Verify all backends are registered
        assert len(orchestrator.backends) == 4
        assert "ollama:codellama" in orchestrator.backends
        assert "openai:gpt-4" in orchestrator.backends
        assert "anthropic:claude-3" in orchestrator.backends
        assert "deepseek:deepseek-v4-flash" in orchestrator.backends

    def test_backend_fallback_order(self):
        """Test backend fallback ordering."""
        configs = [
            LLMConfig(provider=LLMProvider.OLLAMA, model="primary"),
            LLMConfig(provider=LLMProvider.OPENAI, model="fallback", api_key="key"),
        ]

        orchestrator = LLMOrchestrator(configs)

        # Primary provider should be the first one added
        assert orchestrator.primary_provider == "ollama:primary"

    def test_confidence_score_calculation(self):
        """Test confidence score averaging."""
        orchestrator = LLMOrchestrator([])

        # Test with multiple vulnerabilities with different confidence scores
        response = LLMResponse(
            content='{"vulnerabilities": [{"confidence": 0.8}, {"confidence": 0.6}, {"confidence": 1.0}]}',
            provider="test",
            model="test",
        )

        analysis = orchestrator._parse_analysis(response)
        expected_avg = (0.8 + 0.6 + 1.0) / 3
        assert abs(analysis.confidence_score - expected_avg) < 0.001

    def test_confidence_score_bounds_malformed_legacy_values(self, monkeypatch):
        """Test malformed legacy confidence values are bounded before averaging."""
        orchestrator = LLMOrchestrator([])
        monkeypatch.setattr(
            "src.llm.llm_orchestrator.safe_parse_llm_json",
            lambda *_args, **_kwargs: MagicMock(is_valid=False, data=None, errors=["forced"]),
        )

        response = LLMResponse(
            content=(
                '{"vulnerabilities": ['
                '{"confidence": "high"}, '
                '{"confidence": 1.5}, '
                '{"confidence": -0.25}'
                "]}"
            ),
            provider="test",
            model="test",
        )

        analysis = orchestrator._parse_analysis(response)

        assert [vuln["confidence"] for vuln in analysis.vulnerabilities] == [0.5, 1.0, 0.0]
        assert abs(analysis.confidence_score - 0.5) < 0.001

    def test_bounded_confidence_sanitizes_string_inputs(self):
        assert _bounded_confidence(" 0.75 ") == 0.75
        assert _bounded_confidence("0.75\x7f") == 0.5
        assert _bounded_confidence(b"0.6") == 0.6
        assert _bounded_confidence(b"0.6\n") == 0.5

    def test_non_negative_int_stat_rejects_malformed_strings(self):
        assert _non_negative_int_stat(3, "tokens", "ollama") == 3
        with pytest.raises(ValueError):
            _non_negative_int_stat("3", "tokens", "ollama")

    def test_recommendations_extraction(self):
        """Test recommendations extraction from vulnerabilities."""
        orchestrator = LLMOrchestrator([])

        response = LLMResponse(
            content='{"vulnerabilities": [{"remediation": "Fix A"}, {"remediation": "Fix B"}, {}]}',
            provider="test",
            model="test",
        )

        analysis = orchestrator._parse_analysis(response)
        assert "Fix A" in analysis.recommendations
        assert "Fix B" in analysis.recommendations
        assert len(analysis.recommendations) == 2  # Empty remediation excluded
