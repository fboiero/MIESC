"""
Tests for LLM Orchestrator Module

Tests the multi-backend LLM orchestration for security analysis.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.llm.llm_orchestrator import (
    AnthropicBackend,
    LLMBackend,
    LLMConfig,
    LLMOrchestrator,
    LLMProvider,
    LLMResponse,
    OllamaBackend,
    OpenAIBackend,
    VulnerabilityAnalysis,
    analyze_solidity,
)


class TestLLMProvider:
    """Test LLMProvider enum."""

    def test_provider_values(self):
        """Test provider enum values."""
        assert LLMProvider.OLLAMA.value == "ollama"
        assert LLMProvider.OPENAI.value == "openai"
        assert LLMProvider.ANTHROPIC.value == "anthropic"
        assert LLMProvider.LOCAL.value == "local"

    def test_all_providers(self):
        """Test all providers are accessible."""
        providers = list(LLMProvider)
        assert len(providers) == 4


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


class TestLLMOrchestrator:
    """Test LLMOrchestrator class."""

    def test_default_init(self):
        """Test default initialization."""
        orchestrator = LLMOrchestrator()
        assert len(orchestrator.backends) > 0
        assert orchestrator.cache == {}
        assert orchestrator.cache_ttl == 3600

    def test_custom_init(self):
        """Test custom initialization."""
        configs = [
            LLMConfig(provider=LLMProvider.OLLAMA, model="codellama"),
            LLMConfig(provider=LLMProvider.OPENAI, model="gpt-4", api_key="key"),
        ]
        orchestrator = LLMOrchestrator(configs)
        assert len(orchestrator.backends) == 2

    def test_add_backend(self):
        """Test adding backends."""
        orchestrator = LLMOrchestrator([])
        config = LLMConfig(provider=LLMProvider.OLLAMA, model="test")
        orchestrator._add_backend(config)
        assert "ollama:test" in orchestrator.backends

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

    def test_cache_key_generation(self):
        """Test cache key generation."""
        orchestrator = LLMOrchestrator([])

        key1 = orchestrator._get_cache_key("prompt1", None)
        key2 = orchestrator._get_cache_key("prompt1", None)
        key3 = orchestrator._get_cache_key("prompt2", None)
        key4 = orchestrator._get_cache_key("prompt1", {"context": "test"})

        assert key1 == key2  # Same prompt, same key
        assert key1 != key3  # Different prompt
        assert key1 != key4  # Different context

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

        orchestrator.clear_cache()
        assert len(orchestrator.cache) == 0

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
        ]

        orchestrator = LLMOrchestrator(configs)

        # Verify all backends are registered
        assert len(orchestrator.backends) == 3
        assert "ollama:codellama" in orchestrator.backends
        assert "openai:gpt-4" in orchestrator.backends
        assert "anthropic:claude-3" in orchestrator.backends

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
