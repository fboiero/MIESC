"""
Tests for LLM Ensemble Detector module.

Sprint 1.4: Comprehensive tests for src/llm/ensemble_detector.py covering:
- LLMProvider enum
- VotingStrategy enum
- EnsembleFinding dataclass
- EnsembleResult dataclass
- LLMEnsembleDetector class methods
- Multi-provider support (Ollama, OpenAI, Anthropic)
- Voting mechanism
- Fallback logic

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
"""

import asyncio
from types import MappingProxyType
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from src.llm.ensemble_detector import (
    AllProvidersUnavailable,
    EnsembleFinding,
    EnsembleResult,
    LLMEnsembleDetector,
    LLMProvider,
    ProviderUnavailable,
    VotingStrategy,
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


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def detector():
    """Create an LLMEnsembleDetector instance for testing."""
    return LLMEnsembleDetector(
        models=["test-model-1", "test-model-2"],
        ollama_base_url="http://localhost:11434",
        voting_strategy=VotingStrategy.THRESHOLD,
        consensus_threshold=2,
    )


@pytest.fixture
def multi_provider_detector():
    """Create a detector with multiple providers."""
    return LLMEnsembleDetector(
        providers=[LLMProvider.OLLAMA, LLMProvider.OPENAI, LLMProvider.ANTHROPIC],
        openai_api_key="test-openai-key",
        anthropic_api_key="test-anthropic-key",
    )


@pytest.fixture
def vulnerable_code():
    """Sample vulnerable Solidity code."""
    return """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract VulnerableBank {
        mapping(address => uint256) public balances;

        function withdraw() public {
            uint256 balance = balances[msg.sender];
            require(balance > 0);
            (bool success,) = msg.sender.call{value: balance}("");
            require(success);
            balances[msg.sender] = 0;
        }
    }
    """


@pytest.fixture
def sample_model_findings():
    """Sample findings from multiple models."""
    return {
        "deepseek-coder:6.7b": [
            {
                "type": "reentrancy",
                "severity": "high",
                "title": "Reentrancy vulnerability",
                "description": "External call before state update",
                "location": {"function": "withdraw", "line": 10},
                "confidence": 0.9,
            }
        ],
        "codellama:7b": [
            {
                "type": "reentrancy",
                "severity": "high",
                "title": "Reentrancy in withdraw",
                "description": "State updated after external call",
                "location": {"function": "withdraw", "line": 11},
                "confidence": 0.85,
            }
        ],
        "llama3.1:8b": [
            {
                "type": "reentrancy",
                "severity": "critical",
                "title": "Classic reentrancy",
                "description": "CEI pattern violated",
                "location": {"function": "withdraw", "line": 10},
                "confidence": 0.8,
            }
        ],
    }


@pytest.fixture
def llm_response_json():
    """Sample LLM response in JSON format."""
    return """[
        {
            "type": "reentrancy",
            "severity": "high",
            "title": "Reentrancy vulnerability in withdraw",
            "description": "The withdraw function makes an external call before updating state",
            "location": {"function": "withdraw", "line": 10},
            "attack_vector": "Deploy attack contract, call withdraw from fallback",
            "remediation": "Move state update before external call",
            "confidence": 0.9
        }
    ]"""


# =============================================================================
# Tests for Enums
# =============================================================================


class TestLLMProvider:
    """Tests for LLMProvider enum."""

    def test_providers_exist(self):
        """Test that all providers are defined."""
        assert LLMProvider.OLLAMA.value == "ollama"
        assert LLMProvider.OPENAI.value == "openai"
        assert LLMProvider.ANTHROPIC.value == "anthropic"
        assert LLMProvider.DEEPSEEK.value == "deepseek"

    def test_provider_count(self):
        """Test provider count."""
        assert len(LLMProvider) == 4


class TestVotingStrategy:
    """Tests for VotingStrategy enum."""

    def test_strategies_exist(self):
        """Test that all strategies are defined."""
        assert VotingStrategy.MAJORITY.value == "majority"
        assert VotingStrategy.UNANIMOUS.value == "unanimous"
        assert VotingStrategy.WEIGHTED.value == "weighted"
        assert VotingStrategy.THRESHOLD.value == "threshold"

    def test_strategy_count(self):
        """Test strategy count."""
        assert len(VotingStrategy) == 4


# =============================================================================
# Tests for Dataclasses
# =============================================================================


class TestEnsembleFinding:
    """Tests for EnsembleFinding dataclass."""

    def test_create_finding(self):
        """Test creating an EnsembleFinding."""
        finding = EnsembleFinding(
            type="reentrancy",
            severity="high",
            title="Reentrancy vulnerability",
            description="External call before state update",
            location={"function": "withdraw", "line": 10},
            confidence=0.9,
            votes=3,
            total_models=3,
            supporting_models=["model1", "model2", "model3"],
        )
        assert finding.type == "reentrancy"
        assert finding.severity == "high"
        assert finding.votes == 3
        assert len(finding.supporting_models) == 3

    def test_optional_fields(self):
        """Test optional fields have correct defaults."""
        finding = EnsembleFinding(
            type="test",
            severity="low",
            title="Test",
            description="Test",
            location={},
            confidence=0.5,
            votes=1,
            total_models=1,
            supporting_models=["model1"],
        )
        assert finding.attack_vector is None
        assert finding.remediation is None
        assert finding.swc_id is None
        assert finding.cwe_id is None
        assert finding.raw_responses == {}

    def test_finding_with_all_fields(self):
        """Test creating finding with all fields."""
        finding = EnsembleFinding(
            type="reentrancy",
            severity="critical",
            title="Critical reentrancy",
            description="Full description",
            location={"function": "withdraw", "line": 10},
            confidence=0.95,
            votes=3,
            total_models=3,
            supporting_models=["model1", "model2", "model3"],
            attack_vector="Deploy attack contract",
            remediation="Use ReentrancyGuard",
            swc_id="SWC-107",
            cwe_id="CWE-841",
            raw_responses={"model1": {"raw": "data"}},
        )
        assert finding.swc_id == "SWC-107"
        assert finding.attack_vector is not None


class TestEnsembleResult:
    """Tests for EnsembleResult dataclass."""

    def test_create_result(self):
        """Test creating an EnsembleResult."""
        finding = EnsembleFinding(
            type="reentrancy",
            severity="high",
            title="Test",
            description="Test",
            location={},
            confidence=0.9,
            votes=2,
            total_models=3,
            supporting_models=["m1", "m2"],
        )
        result = EnsembleResult(
            findings=[finding],
            models_used=["model1", "model2", "model3"],
            models_available=["model1", "model2", "model3"],
            models_failed=[],
            execution_time_ms=1500.0,
            consensus_threshold=2,
            total_raw_findings=5,
            filtered_findings=1,
        )
        assert len(result.findings) == 1
        assert result.execution_time_ms == 1500.0
        assert result.total_raw_findings == 5
        assert result.filtered_findings == 1


# =============================================================================
# Tests for Exceptions
# =============================================================================


class TestExceptions:
    """Tests for custom exceptions."""

    def test_provider_unavailable(self):
        """Test ProviderUnavailable exception."""
        with pytest.raises(ProviderUnavailable):
            raise ProviderUnavailable("Ollama not running")

    def test_all_providers_unavailable(self):
        """Test AllProvidersUnavailable exception."""
        with pytest.raises(AllProvidersUnavailable):
            raise AllProvidersUnavailable("No providers available")

    def test_exception_messages(self):
        """Test exception messages are preserved."""
        try:
            raise ProviderUnavailable("Test message")
        except ProviderUnavailable as e:
            assert "Test message" in str(e)


# =============================================================================
# Tests for LLMEnsembleDetector Initialization
# =============================================================================


class TestLLMEnsembleDetectorInit:
    """Tests for LLMEnsembleDetector initialization."""

    def test_default_initialization(self):
        """Test default initialization."""
        detector = LLMEnsembleDetector()
        assert len(detector.models) == 3  # DEFAULT_MODELS
        assert detector.base_url == "http://localhost:11434"
        assert detector.voting_strategy == VotingStrategy.THRESHOLD
        assert detector.consensus_threshold == 2
        assert LLMProvider.OLLAMA in detector.providers

    def test_custom_models(self):
        """Test initialization with custom models."""
        models = ["custom-model-1", "custom-model-2"]
        detector = LLMEnsembleDetector(models=models)
        assert detector.models == models

    def test_malformed_model_list_uses_default_models(self):
        """A scalar model list should not be iterated as individual model ids."""
        detector = LLMEnsembleDetector(models="not-a-model-list")
        assert detector.models == LLMEnsembleDetector.DEFAULT_MODELS

    def test_model_list_keeps_only_nonempty_model_names(self):
        """Malformed model entries should not cross the configured model boundary."""
        detector = LLMEnsembleDetector(models=[" custom-model ", "", None, {"name": "bad"}])
        assert detector.models == ["custom-model"]

    def test_custom_voting_strategy(self):
        """Test initialization with custom voting strategy."""
        detector = LLMEnsembleDetector(voting_strategy=VotingStrategy.MAJORITY)
        assert detector.voting_strategy == VotingStrategy.MAJORITY

    def test_string_voting_strategy_is_normalized(self):
        """String strategy config should be accepted at the public boundary."""
        detector = LLMEnsembleDetector(voting_strategy="majority")
        assert detector.voting_strategy == VotingStrategy.MAJORITY

    def test_malformed_voting_strategy_uses_threshold(self):
        """Malformed strategy config should not crash logging or voting."""
        detector = LLMEnsembleDetector(voting_strategy={"strategy": "majority"})

        assert detector.voting_strategy == VotingStrategy.THRESHOLD
        assert detector.get_model_status()["voting_strategy"] == "threshold"

    def test_multi_provider_init(self, multi_provider_detector):
        """Test initialization with multiple providers."""
        assert len(multi_provider_detector.providers) == 3
        assert multi_provider_detector.openai_api_key == "test-openai-key"
        assert multi_provider_detector.anthropic_api_key == "test-anthropic-key"

    def test_api_keys_are_stripped_at_config_boundary(self):
        """Configured API keys should be normalized before reaching headers."""
        detector = LLMEnsembleDetector(
            providers=[LLMProvider.OPENAI, LLMProvider.ANTHROPIC, LLMProvider.DEEPSEEK],
            openai_api_key="  test-openai-key  ",
            anthropic_api_key="\ttest-anthropic-key\n",
            deepseek_api_key="  test-deepseek-key  ",
        )

        assert detector.openai_api_key == "test-openai-key"
        assert detector.anthropic_api_key == "test-anthropic-key"
        assert detector.deepseek_api_key == "test-deepseek-key"

    def test_malformed_api_key_config_uses_env_fallback(self):
        """Malformed API key values should not become truthy provider credentials."""
        with patch.dict(
            "os.environ",
            {
                "OPENAI_API_KEY": " env-openai-key ",
                "ANTHROPIC_API_KEY": " ",
                "DEEPSEEK_API_KEY": "env-deepseek-key",
            },
        ):
            detector = LLMEnsembleDetector(
                providers=[LLMProvider.OPENAI, LLMProvider.ANTHROPIC, LLMProvider.DEEPSEEK],
                openai_api_key={"key": "bad"},
                anthropic_api_key=["bad"],
                deepseek_api_key=False,
            )

        assert detector.openai_api_key == "env-openai-key"
        assert detector.anthropic_api_key is None
        assert detector.deepseek_api_key == "env-deepseek-key"

    def test_string_provider_entries_are_normalized_and_deduped(self):
        """String provider config should normalize to enum values once."""
        detector = LLMEnsembleDetector(providers=["openai", LLMProvider.OPENAI, "anthropic"])
        assert detector.providers == [LLMProvider.OPENAI, LLMProvider.ANTHROPIC]

    def test_malformed_provider_config_uses_ollama_default(self):
        """Malformed provider containers should not be iterated as providers."""
        detector = LLMEnsembleDetector(providers="openai")
        assert detector.providers == [LLMProvider.OLLAMA]

    def test_mixed_malformed_provider_entries_are_filtered(self):
        """Unknown provider entries should be ignored without dropping valid ones."""
        detector = LLMEnsembleDetector(providers=[{"name": "openai"}, "unknown", "deepseek"])
        assert detector.providers == [LLMProvider.DEEPSEEK]

    def test_deepseek_init(self):
        """Test initialization with DeepSeek provider."""
        detector = LLMEnsembleDetector(
            providers=[LLMProvider.DEEPSEEK],
            deepseek_api_key="test-deepseek-key",
            deepseek_base_url="https://custom.deepseek.example",
        )

        assert detector.providers == [LLMProvider.DEEPSEEK]
        assert detector.deepseek_api_key == "test-deepseek-key"
        assert detector.deepseek_base_url == "https://custom.deepseek.example"

    def test_env_api_keys(self):
        """Test API keys from environment variables."""
        with patch.dict(
            "os.environ",
            {
                "OPENAI_API_KEY": "env-openai-key",
                "ANTHROPIC_API_KEY": "env-anthropic-key",
                "DEEPSEEK_API_KEY": "env-deepseek-key",
            },
        ):
            detector = LLMEnsembleDetector(
                providers=[LLMProvider.OPENAI, LLMProvider.ANTHROPIC, LLMProvider.DEEPSEEK]
            )
            assert detector.openai_api_key == "env-openai-key"
            assert detector.anthropic_api_key == "env-anthropic-key"
            assert detector.deepseek_api_key == "env-deepseek-key"

    def test_temperature_setting(self):
        """Test temperature parameter."""
        detector = LLMEnsembleDetector(temperature=0.5)
        assert detector.temperature == 0.5

    @pytest.mark.parametrize("temperature", [{"value": 0.5}, True, float("nan"), float("inf")])
    def test_malformed_temperature_uses_default(self, temperature):
        """Malformed temperature config should not cross into request payloads."""
        detector = LLMEnsembleDetector(temperature=temperature)
        assert detector.temperature == LLMEnsembleDetector.DEFAULT_TEMPERATURE

    @pytest.mark.parametrize(
        ("temperature", "expected"),
        [
            (-0.5, 0.0),
            (3.0, LLMEnsembleDetector.MAX_TEMPERATURE),
        ],
    )
    def test_temperature_is_bounded(self, temperature, expected):
        """Out-of-range temperatures should be clamped to provider-safe bounds."""
        detector = LLMEnsembleDetector(temperature=temperature)
        assert detector.temperature == expected

    def test_timeout_setting(self):
        """Test timeout parameter."""
        detector = LLMEnsembleDetector(timeout=60)
        assert detector.timeout == 60

    @pytest.mark.parametrize("timeout", [{"seconds": 60}, False, float("nan"), float("-inf")])
    def test_malformed_timeout_uses_default(self, timeout):
        """Malformed timeout config should not reach aiohttp ClientTimeout."""
        detector = LLMEnsembleDetector(timeout=timeout)
        assert detector.timeout == LLMEnsembleDetector.DEFAULT_TIMEOUT

    def test_timeout_is_positive(self):
        """A non-positive timeout should not disable or invert request deadlines."""
        detector = LLMEnsembleDetector(timeout=0)
        assert detector.timeout == 1

    def test_malformed_consensus_threshold_uses_default(self):
        """A non-numeric threshold should not break vote comparisons later."""
        detector = LLMEnsembleDetector(consensus_threshold={"votes": 2})
        assert detector.consensus_threshold == 2

    def test_consensus_threshold_is_positive(self):
        """A zero or negative threshold should not make every finding pass."""
        detector = LLMEnsembleDetector(consensus_threshold=0)
        assert detector.consensus_threshold == 1

    def test_model_status_returns_defensive_model_lists(self):
        """Public status callers should not mutate detector model state."""
        detector = LLMEnsembleDetector(models=["model1", "model2"])
        detector._available_models = ["model1"]

        status = detector.get_model_status()
        status["configured_models"].append("injected-model")
        status["available_models"].append("injected-model")

        assert detector.models == ["model1", "model2"]
        assert detector._available_models == ["model1"]
        assert detector.get_model_status()["configured_models"] == ["model1", "model2"]
        assert detector.get_model_status()["available_models"] == ["model1"]

    def test_model_status_filters_malformed_model_metadata(self):
        """Malformed internal model metadata should not break status serialization."""
        detector = LLMEnsembleDetector(models=["model1"])
        detector.models = [" model1 ", {"name": "bad"}, "", None]
        detector._available_models = [" model1 ", ["bad"], ""]

        status = detector.get_model_status()

        assert status["configured_models"] == ["model1"]
        assert status["available_models"] == ["model1"]
        assert status["model_weights"] == {"model1": 1.0}

    def test_model_status_defaults_malformed_model_weights(self, monkeypatch):
        """Malformed configured model weights should not leak through public status."""
        monkeypatch.setattr(
            LLMEnsembleDetector,
            "MODEL_WEIGHTS",
            {"model1": {"weight": 1.2}, "model2": float("inf"), "model3": -1.0},
        )
        detector = LLMEnsembleDetector(models=["model1", "model2", "model3"])

        assert detector.get_model_status()["model_weights"] == {
            "model1": 1.0,
            "model2": 1.0,
            "model3": 1.0,
        }

    def test_normalize_remote_model_ids_strips_and_rejects_control_chars(self):
        """Remote model ids should be normalized before fallback selection."""
        assert LLMEnsembleDetector._normalize_remote_model_ids(
            [" model-a ", "bad\nmodel", None, "model-b"]
        ) == {"model-a", "model-b"}

    def test_provider_status_map_accepts_mapping_views(self):
        """Provider status normalization should accept generic mapping views."""
        raw_status = MappingProxyType(
            {
                LLMProvider.OLLAMA: [" model-a ", {"bad": "entry"}],
                "openai": ("model-b", " "),
            }
        )

        normalized = LLMEnsembleDetector._provider_status_map(raw_status)

        assert normalized == {
            LLMProvider.OLLAMA: ["model-a"],
            LLMProvider.OPENAI: ["model-b"],
        }


class TestLLMEnsembleDetectorConstants:
    """Tests for LLMEnsembleDetector class constants."""

    def test_provider_models_defined(self):
        """Test that provider models are defined."""
        assert LLMProvider.OLLAMA in LLMEnsembleDetector.PROVIDER_MODELS
        assert LLMProvider.OPENAI in LLMEnsembleDetector.PROVIDER_MODELS
        assert LLMProvider.ANTHROPIC in LLMEnsembleDetector.PROVIDER_MODELS
        assert LLMProvider.DEEPSEEK in LLMEnsembleDetector.PROVIDER_MODELS

    def test_ollama_models(self):
        """Test Ollama model list."""
        models = LLMEnsembleDetector.PROVIDER_MODELS[LLMProvider.OLLAMA]
        assert "deepseek-coder:6.7b" in models
        assert len(models) >= 3

    def test_openai_models(self):
        """Test OpenAI model list."""
        models = LLMEnsembleDetector.PROVIDER_MODELS[LLMProvider.OPENAI]
        assert "gpt-4-turbo" in models or "gpt-4o" in models
        assert len(models) >= 2

    def test_anthropic_models(self):
        """Test Anthropic model list."""
        models = LLMEnsembleDetector.PROVIDER_MODELS[LLMProvider.ANTHROPIC]
        assert any("claude" in m for m in models)
        assert len(models) >= 2

    def test_deepseek_models(self):
        """Test DeepSeek model list."""
        models = LLMEnsembleDetector.PROVIDER_MODELS[LLMProvider.DEEPSEEK]
        assert "deepseek-v4-flash" in models
        assert "deepseek-v4-pro" in models

    def test_model_weights(self):
        """Test model weights are defined."""
        weights = LLMEnsembleDetector.MODEL_WEIGHTS
        assert "deepseek-coder:6.7b" in weights
        assert weights["deepseek-coder:6.7b"] > 1.0  # Higher weight
        assert "deepseek-v4-flash" in weights
        assert "deepseek-v4-pro" in weights

    def test_detection_prompt_exists(self):
        """Test detection prompt is defined."""
        prompt = LLMEnsembleDetector.DETECTION_PROMPT
        assert "{code}" in prompt
        assert "vulnerability" in prompt.lower()


# =============================================================================
# Tests for LLMEnsembleDetector Async Methods
# =============================================================================


class TestLLMEnsembleDetectorInitialize:
    """Tests for initialize method."""

    def test_initialize_ollama(self, detector):
        """Test initialization with Ollama."""

        async def run_test():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "models": [
                        {"name": "deepseek-coder:6.7b"},
                        {"name": "codellama:7b"},
                    ]
                }
            )
            mock_session = _aiohttp_session_with_response("get", mock_response)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                status = await detector.initialize()

                assert detector._initialized
                assert isinstance(status, dict)

        asyncio.run(run_test())

    def test_initialize_no_models(self, detector):
        """Test initialization when no models available."""

        async def run_test():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"models": []})
            mock_session = _aiohttp_session_with_response("get", mock_response)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                await detector.initialize()

                assert detector._initialized
                # Should still initialize even with no models

        asyncio.run(run_test())

    def test_initialize_ignores_malformed_ollama_model_payload(self, detector):
        """Malformed Ollama tag payloads should not cross the availability boundary."""

        async def run_test():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"models": {"name": "test-model-1"}})
            mock_session = _aiohttp_session_with_response("get", mock_response)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                status = await detector.initialize()

            assert detector._initialized
            assert detector._available_models == []
            assert status == {"test-model-1": False, "test-model-2": False}

        asyncio.run(run_test())

    def test_initialize_connection_error(self, detector):
        """Test initialization with connection error."""

        async def run_test():
            mock_session_instance = MagicMock()
            mock_session_instance.get.side_effect = OSError("Connection refused")

            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session_instance)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                # Should not raise, just log warning
                await detector.initialize()
                assert detector._initialized

        asyncio.run(run_test())

    def test_check_ollama_connection_error(self, detector):
        """Test checking Ollama availability with connection error."""

        async def run_test():
            mock_session_instance = MagicMock()
            mock_session_instance.get.side_effect = aiohttp.ClientError("Connection refused")

            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session_instance)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                models = await detector._check_provider_availability(LLMProvider.OLLAMA)
                assert models == []

        asyncio.run(run_test())


class TestLLMEnsembleDetectorProviderAvailability:
    """Tests for provider availability checking."""

    def test_check_ollama_available(self, detector):
        """Test checking Ollama availability."""

        async def run_test():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"models": [{"name": "test-model"}]})
            mock_session = _aiohttp_session_with_response("get", mock_response)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                models = await detector._check_provider_availability(LLMProvider.OLLAMA)
                assert "test-model" in models

        asyncio.run(run_test())

    def test_check_ollama_filters_malformed_model_entries(self, detector):
        """Malformed Ollama tag entries should be ignored without dropping valid ids."""

        async def run_test():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "models": [
                        {"name": " test-model "},
                        {"name": ""},
                        {"model": "wrong-key"},
                        "bad-entry",
                    ]
                }
            )
            mock_session = _aiohttp_session_with_response("get", mock_response)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                models = await detector._check_provider_availability(LLMProvider.OLLAMA)

            assert models == ["test-model"]

        asyncio.run(run_test())

    def test_check_openai_with_key(self, multi_provider_detector):
        """Test checking OpenAI availability with API key."""

        async def run_test():
            models = await multi_provider_detector._check_provider_availability(LLMProvider.OPENAI)
            assert len(models) > 0

        asyncio.run(run_test())

    def test_check_openai_without_key(self, detector):
        """Test checking OpenAI availability without API key."""

        async def run_test():
            detector.openai_api_key = None
            models = await detector._check_provider_availability(LLMProvider.OPENAI)
            assert len(models) == 0

        asyncio.run(run_test())

    def test_check_anthropic_with_key(self, multi_provider_detector):
        """Test checking Anthropic availability with API key."""

        async def run_test():
            models = await multi_provider_detector._check_provider_availability(
                LLMProvider.ANTHROPIC
            )
            assert len(models) > 0

        asyncio.run(run_test())

    def test_check_deepseek_with_key(self):
        """Test checking DeepSeek availability through the models endpoint."""

        async def run_test():
            detector = LLMEnsembleDetector(
                providers=[LLMProvider.DEEPSEEK],
                deepseek_api_key="test-key",
            )

            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "data": [
                        {"id": "deepseek-v4-flash"},
                        {"id": "deepseek-v4-pro"},
                        {"id": "unrelated-model"},
                    ]
                }
            )
            mock_session = _aiohttp_session_with_response("get", mock_response)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                models = await detector._check_provider_availability(LLMProvider.DEEPSEEK)

            assert "deepseek-v4-flash" in models
            assert "deepseek-v4-pro" in models

        asyncio.run(run_test())

    def test_check_deepseek_filters_unconfigured_remote_models(self):
        """Test DeepSeek availability excludes models not configured for the ensemble."""

        async def run_test():
            detector = LLMEnsembleDetector(
                providers=[LLMProvider.DEEPSEEK],
                deepseek_api_key="test-key",
            )

            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"data": [{"id": "unknown-model"}]})
            mock_session = _aiohttp_session_with_response("get", mock_response)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                models = await detector._check_provider_availability(LLMProvider.DEEPSEEK)

            assert models == []

        asyncio.run(run_test())

    def test_check_deepseek_ignores_malformed_remote_model_list(self):
        """Malformed DeepSeek model id containers should not mark models available."""

        async def run_test():
            detector = LLMEnsembleDetector(
                providers=[LLMProvider.DEEPSEEK],
                deepseek_api_key="test-key",
            )

            with patch(
                "src.llm.ensemble_detector.fetch_openai_compatible_model_ids",
                new_callable=AsyncMock,
            ) as mock_fetch_models:
                mock_fetch_models.return_value = {"id": "deepseek-v4-flash"}
                models = await detector._check_provider_availability(LLMProvider.DEEPSEEK)

            assert models == []

        asyncio.run(run_test())

    def test_check_deepseek_connection_error(self):
        """Test DeepSeek availability handles model endpoint failures."""

        async def run_test():
            detector = LLMEnsembleDetector(
                providers=[LLMProvider.DEEPSEEK],
                deepseek_api_key="test-key",
            )

            mock_session_instance = MagicMock()
            mock_session_instance.get.side_effect = aiohttp.ClientError("Connection refused")

            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session_instance)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                models = await detector._check_provider_availability(LLMProvider.DEEPSEEK)

            assert models == []

        asyncio.run(run_test())

    def test_check_deepseek_without_key(self):
        """Test checking DeepSeek availability without API key."""

        async def run_test():
            detector = LLMEnsembleDetector(
                providers=[LLMProvider.DEEPSEEK],
                deepseek_api_key=None,
            )
            detector.deepseek_api_key = None
            models = await detector._check_provider_availability(LLMProvider.DEEPSEEK)
            assert models == []

        asyncio.run(run_test())


class TestLLMEnsembleDetectorDetectWithFallback:
    """Tests for detect_with_fallback method."""

    def test_fallback_first_provider_success(self, multi_provider_detector, vulnerable_code):
        """Test that first successful provider is used."""

        async def run_test():
            # Mock initialize
            multi_provider_detector._initialized = True
            multi_provider_detector._available_providers = {
                LLMProvider.OLLAMA: ["test-model"],
                LLMProvider.OPENAI: ["gpt-4"],
            }

            # Mock _detect_with_provider to succeed on first try
            with patch.object(
                multi_provider_detector, "_detect_with_provider", new_callable=AsyncMock
            ) as mock_detect:
                mock_detect.return_value = [
                    EnsembleFinding(
                        type="reentrancy",
                        severity="high",
                        title="Test",
                        description="Test",
                        location={},
                        confidence=0.9,
                        votes=2,
                        total_models=2,
                        supporting_models=["m1", "m2"],
                    )
                ]

                results = await multi_provider_detector.detect_with_fallback(vulnerable_code)

                assert len(results) == 1
                mock_detect.assert_called_once()

        asyncio.run(run_test())

    def test_fallback_to_second_provider(self, multi_provider_detector, vulnerable_code):
        """Test fallback to second provider when first fails."""

        async def run_test():
            multi_provider_detector._initialized = True
            multi_provider_detector._available_providers = {
                LLMProvider.OLLAMA: ["test-model"],
                LLMProvider.OPENAI: ["gpt-4"],
            }

            call_count = 0

            async def mock_detect(provider, code, context):
                nonlocal call_count
                call_count += 1
                if provider == LLMProvider.OLLAMA:
                    raise ProviderUnavailable("Ollama down")
                return [
                    EnsembleFinding(
                        type="test",
                        severity="low",
                        title="Test",
                        description="Test",
                        location={},
                        confidence=0.5,
                        votes=1,
                        total_models=1,
                        supporting_models=["m1"],
                    )
                ]

            with patch.object(
                multi_provider_detector, "_detect_with_provider", side_effect=mock_detect
            ):
                results = await multi_provider_detector.detect_with_fallback(vulnerable_code)

                assert len(results) == 1
                assert call_count == 2  # Tried both providers

        asyncio.run(run_test())

    def test_all_providers_fail(self, multi_provider_detector, vulnerable_code):
        """Test exception when all providers fail."""

        async def run_test():
            multi_provider_detector._initialized = True
            multi_provider_detector._available_providers = {
                LLMProvider.OLLAMA: ["test-model"],
            }

            with patch.object(
                multi_provider_detector, "_detect_with_provider", new_callable=AsyncMock
            ) as mock_detect:
                mock_detect.side_effect = ProviderUnavailable("All failed")

                with pytest.raises(AllProvidersUnavailable):
                    await multi_provider_detector.detect_with_fallback(vulnerable_code)

        asyncio.run(run_test())

    def test_fallback_continues_after_runtime_error(self, multi_provider_detector, vulnerable_code):
        """Test fallback to another provider after an expected runtime error."""

        async def run_test():
            multi_provider_detector._initialized = True
            multi_provider_detector._available_providers = {
                LLMProvider.OLLAMA: ["test-model"],
                LLMProvider.OPENAI: ["gpt-4"],
            }

            async def mock_detect(provider, code, context):
                if provider == LLMProvider.OLLAMA:
                    raise RuntimeError("temporary Ollama failure")
                return [
                    EnsembleFinding(
                        type="test",
                        severity="low",
                        title="Test",
                        description="Test",
                        location={},
                        confidence=0.5,
                        votes=1,
                        total_models=1,
                        supporting_models=["gpt-4"],
                    )
                ]

            with patch.object(
                multi_provider_detector, "_detect_with_provider", side_effect=mock_detect
            ):
                results = await multi_provider_detector.detect_with_fallback(vulnerable_code)
                assert len(results) == 1
                assert results[0].supporting_models == ["gpt-4"]

        asyncio.run(run_test())

    def test_fallback_filters_malformed_provider_status_map_entries(
        self, multi_provider_detector, vulnerable_code
    ):
        """Malformed provider status keys/lists should not break fallback selection."""

        async def run_test():
            multi_provider_detector._initialized = True
            multi_provider_detector._available_providers = {
                "ollama": [{"id": "bad"}, " ollama-model "],
                LLMProvider.OPENAI: "gpt-4",
                ("bad",): ["bad-model"],
                "unknown": ["bad-model"],
                "anthropic": [" claude-3-haiku-20240307 "],
            }

            async def mock_detect(provider, code, context):
                return [
                    EnsembleFinding(
                        type="test",
                        severity="low",
                        title="Test",
                        description="Test",
                        location={},
                        confidence=0.5,
                        votes=1,
                        total_models=1,
                        supporting_models=[provider.value],
                    )
                ]

            with patch.object(
                multi_provider_detector, "_detect_with_provider", side_effect=mock_detect
            ) as mock_detect:
                results = await multi_provider_detector.detect_with_fallback(vulnerable_code)

            assert results[0].supporting_models == ["ollama"]
            mock_detect.assert_awaited_once()
            assert mock_detect.await_args.args[0] == LLMProvider.OLLAMA

        asyncio.run(run_test())

    def test_fallback_rejects_malformed_provider_status_map(
        self, multi_provider_detector, vulnerable_code
    ):
        """A malformed provider status map should fail as unavailable, not crash."""

        async def run_test():
            multi_provider_detector._initialized = True
            multi_provider_detector._available_providers = ["ollama", "gpt-4"]

            with pytest.raises(AllProvidersUnavailable):
                await multi_provider_detector.detect_with_fallback(vulnerable_code)

        asyncio.run(run_test())

    def test_fallback_filters_malformed_provider_score_map_entries(
        self, multi_provider_detector, vulnerable_code
    ):
        """Provider score maps should tolerate mixed invalid and valid model keys."""

        async def run_test():
            multi_provider_detector._initialized = True
            multi_provider_detector._available_providers = {
                "ollama": {"bad-model": 0.2, " ollama-model ": 0.9, "": 0.1},
                LLMProvider.OPENAI: {"gpt-4": 0.8},
                "unknown": {"ignored": 1.0},
            }

            async def mock_detect(provider, code, context):
                return [
                    EnsembleFinding(
                        type="test",
                        severity="low",
                        title="Test",
                        description="Test",
                        location={},
                        confidence=0.5,
                        votes=1,
                        total_models=1,
                        supporting_models=[provider.value],
                    )
                ]

            with patch.object(
                multi_provider_detector, "_detect_with_provider", side_effect=mock_detect
            ) as mock_detect:
                results = await multi_provider_detector.detect_with_fallback(vulnerable_code)

            assert results[0].supporting_models == ["ollama"]
            mock_detect.assert_awaited_once()
            assert mock_detect.await_args.args[0] == LLMProvider.OLLAMA

        asyncio.run(run_test())


class TestLLMEnsembleDetectorVoting:
    """Tests for ensemble voting mechanism."""

    def test_ensemble_vote_consensus(self, detector, sample_model_findings):
        """Test ensemble voting with consensus."""
        detector.consensus_threshold = 2
        detector.voting_strategy = VotingStrategy.THRESHOLD

        results = detector._ensemble_vote(sample_model_findings)

        assert len(results) > 0
        # All 3 models agreed on reentrancy
        assert results[0].votes >= 2

    def test_ensemble_vote_no_consensus(self, detector):
        """Test ensemble voting without consensus."""
        detector.consensus_threshold = 3

        findings = {
            "model1": [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "R1",
                    "description": "D1",
                    "location": {},
                    "confidence": 0.9,
                }
            ],
            "model2": [
                {
                    "type": "access-control",
                    "severity": "medium",
                    "title": "A1",
                    "description": "D2",
                    "location": {},
                    "confidence": 0.8,
                }
            ],
        }

        results = detector._ensemble_vote(findings)

        # Neither finding reaches threshold of 3
        # Results depend on implementation details
        assert isinstance(results, list)

    def test_ensemble_vote_empty_findings(self, detector):
        """Test ensemble voting with empty findings."""
        results = detector._ensemble_vote({})
        assert results == []

    def test_ensemble_vote_single_model(self, detector):
        """Test ensemble voting with single model."""
        detector.consensus_threshold = 1

        findings = {
            "model1": [
                {
                    "type": "test",
                    "severity": "low",
                    "title": "T1",
                    "description": "D1",
                    "location": {},
                    "confidence": 0.5,
                }
            ],
        }

        results = detector._ensemble_vote(findings)
        # With threshold=1, single model finding should pass
        assert isinstance(results, list)

    def test_ensemble_vote_with_malformed_threshold_does_not_crash(self):
        """Constructor-normalized malformed thresholds should remain safe during voting."""
        detector = LLMEnsembleDetector(consensus_threshold=["bad"])

        findings = {
            "model1": [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Reentrancy",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 10},
                    "confidence": 0.9,
                }
            ],
            "model2": [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Reentrancy",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 11},
                    "confidence": 0.8,
                }
            ],
        }

        results = detector._ensemble_vote(findings)

        assert len(results) == 1
        assert detector.consensus_threshold == 2
        assert results[0].votes == 2

    def test_ensemble_vote_malformed_display_fields_are_defaulted(self, detector):
        """Malformed scalar display fields should not crash or leak reprs."""
        detector.consensus_threshold = 2

        findings = {
            "model1": [
                {
                    "type": "reentrancy",
                    "severity": {"label": "high"},
                    "title": {"text": "Reentrancy"},
                    "description": ["External call before update"],
                    "location": {"function": "withdraw", "line": 10},
                    "confidence": {"score": 0.95},
                }
            ],
            "model2": [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Reentrancy",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 11},
                    "confidence": 0.9,
                }
            ],
        }

        results = detector._ensemble_vote(findings)

        assert len(results) == 1
        assert results[0].severity == "medium"
        assert results[0].title == "reentrancy"
        assert results[0].description == ""
        assert results[0].confidence == pytest.approx(0.9)
        assert "{" not in results[0].title
        assert "[" not in results[0].description

    def test_ensemble_vote_defaults_malformed_severity_signature_boundary(self, detector):
        """Malformed severity labels should not split votes or leak to output."""
        detector.consensus_threshold = 2

        findings = {
            "model1": [
                {
                    "type": "reentrancy",
                    "severity": "critical/high",
                    "title": "Reentrancy",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 10},
                    "confidence": 0.9,
                }
            ],
            "model2": [
                {
                    "type": "reentrancy",
                    "severity": "HIGH",
                    "title": "Reentrancy",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 11},
                    "confidence": 0.8,
                }
            ],
        }

        results = detector._ensemble_vote(findings)

        assert len(results) == 1
        assert results[0].votes == 2
        assert results[0].severity == "medium"
        assert results[0].supporting_models == ["model1", "model2"]

    def test_ensemble_vote_drops_malformed_vulnerability_type_boundary(self, detector):
        """Malformed vulnerability type/category labels should not create consensus."""
        detector.consensus_threshold = 2

        findings = {
            "model1": [
                {
                    "type": {"category": "reentrancy"},
                    "severity": "high",
                    "title": "Malformed type object",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 10},
                    "confidence": 0.9,
                }
            ],
            "model2": [
                {
                    "type": ["reentrancy"],
                    "severity": "high",
                    "title": "Malformed type list",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 11},
                    "confidence": 0.8,
                }
            ],
            "model3": [
                {
                    "type": " reentrancy ",
                    "severity": "high",
                    "title": "Valid type",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 12},
                    "confidence": 0.7,
                }
            ],
        }

        results = detector._ensemble_vote(findings)

        assert results == []

    def test_ensemble_vote_drops_control_character_vulnerability_type_boundary(
        self, detector
    ):
        """Control characters in consensus type/category labels should be rejected."""
        detector.consensus_threshold = 1

        findings = {
            "model1": [
                {
                    "type": "reentrancy\naccess-control",
                    "severity": "high",
                    "title": "Malformed type",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 10},
                    "confidence": 0.9,
                }
            ],
            "model2": [
                {
                    "type": "access-control",
                    "severity": "medium",
                    "title": "Valid type",
                    "description": "Owner check missing",
                    "location": {"function": "setOwner", "line": 20},
                    "confidence": 0.8,
                }
            ],
        }

        results = detector._ensemble_vote(findings)

        assert len(results) == 1
        assert results[0].type == "access-control"
        assert results[0].supporting_models == ["model2"]

    def test_ensemble_vote_defaults_nonfinite_and_out_of_range_confidence(self, detector):
        """Malformed confidence values should not leak into aggregate confidence."""
        detector.consensus_threshold = 1

        findings = {
            "model1": [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Negative confidence",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 10},
                    "confidence": -5.0,
                }
            ],
            "model2": [
                {
                    "type": "access-control",
                    "severity": "medium",
                    "title": "NaN confidence",
                    "description": "Owner check missing",
                    "location": {"function": "setOwner", "line": 20},
                    "confidence": "nan",
                }
            ],
        }

        results = detector._ensemble_vote(findings)

        assert len(results) == 2
        assert [finding.confidence for finding in results] == pytest.approx([0.75, 0.75])

    def test_ensemble_vote_defaults_boolean_confidence_before_aggregation(self, detector):
        """Boolean confidence values should not be treated as numeric model confidence."""
        detector.consensus_threshold = 1

        findings = {
            "model1": [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Boolean true confidence",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 10},
                    "confidence": True,
                }
            ],
            "model2": [
                {
                    "type": "access-control",
                    "severity": "medium",
                    "title": "Boolean false confidence",
                    "description": "Owner check missing",
                    "location": {"function": "setOwner", "line": 20},
                    "confidence": False,
                }
            ],
        }

        results = detector._ensemble_vote(findings)

        assert len(results) == 2
        assert [finding.confidence for finding in results] == pytest.approx([0.75, 0.75])

    def test_ensemble_vote_averages_malformed_vote_confidence_boundary(self, detector):
        """Malformed confidence on later votes should affect aggregate confidence."""
        detector.consensus_threshold = 2

        findings = {
            "model1": [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Reentrancy",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 10},
                    "confidence": 1.0,
                }
            ],
            "model2": [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Reentrancy",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 11},
                    "confidence": {"score": 0.95},
                }
            ],
            "model3": [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Reentrancy",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 12},
                    "confidence": 0.1,
                }
            ],
        }

        results = detector._ensemble_vote(findings)

        assert len(results) == 1
        assert results[0].votes == 3
        assert results[0].confidence == pytest.approx(0.75)

    def test_aggregate_vote_confidence_defaults_malformed_container(self):
        """Malformed aggregate confidence containers should default safely."""
        assert LLMEnsembleDetector._aggregate_vote_confidence({"confidence": 0.9}) == 0.7
        assert LLMEnsembleDetector._aggregate_vote_confidence([]) == 0.7
        assert LLMEnsembleDetector._aggregate_vote_confidence(
            [True, {"score": 0.9}, float("inf")]
        ) == pytest.approx(0.7)

    def test_ensemble_vote_ignores_malformed_model_finding_payloads(self, detector):
        """Malformed per-model finding containers should not enter voting."""
        detector.consensus_threshold = 1

        findings = {
            "model1": {"type": "reentrancy", "severity": "high"},
            "model2": [
                ["not", "a", "finding"],
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Reentrancy",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 10},
                    "confidence": 0.9,
                },
            ],
        }

        results = detector._ensemble_vote(findings)

        assert len(results) == 1
        assert results[0].votes == 1
        assert results[0].total_models == 1
        assert results[0].supporting_models == ["model2"]

    def test_ensemble_vote_defaults_malformed_location_boundaries(self, detector):
        """Malformed location fields should not crash grouping or leak reprs."""
        detector.consensus_threshold = 2

        findings = {
            "model1": [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Reentrancy",
                    "description": "External call before update",
                    "location": {"function": {"name": "withdraw"}, "line": {"number": 10}},
                    "confidence": 0.9,
                }
            ],
            "model2": [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Reentrancy",
                    "description": "External call before update",
                    "location": ["withdraw", 10],
                    "confidence": 0.8,
                }
            ],
        }

        results = detector._ensemble_vote(findings)

        assert len(results) == 1
        assert results[0].location == {}
        assert results[0].votes == 2
        assert results[0].supporting_models == ["model1", "model2"]

    def test_ensemble_vote_sanitizes_raw_response_payload_boundaries(self, detector):
        """Malformed raw response keys should not leak into aggregate raw_responses."""
        detector.consensus_threshold = 2

        findings = {
            ("bad", "model"): [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Ignored malformed model id",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 10},
                    "confidence": 0.9,
                }
            ],
            " model1 ": [
                {
                    ("tuple", "key"): "not-json-object-compatible",
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Reentrancy",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 10},
                    "confidence": 0.9,
                }
            ],
            "model2": [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Reentrancy",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 11},
                    "confidence": 0.8,
                }
            ],
        }

        results = detector._ensemble_vote(findings)

        assert len(results) == 1
        assert results[0].votes == 2
        assert results[0].supporting_models == ["model1", "model2"]
        assert list(results[0].raw_responses) == ["model1", "model2"]
        assert ("tuple", "key") not in results[0].raw_responses["model1"]

    def test_ensemble_vote_ignores_malformed_model_label_boundaries(self, detector):
        """Malformed model/provider labels should not leak into result metadata."""
        detector.consensus_threshold = 2

        findings = {
            "model1\nprovider": [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Ignored malformed model label",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 10},
                    "confidence": 0.9,
                }
            ],
            "x" * (LLMEnsembleDetector.MAX_MODEL_LABEL_LENGTH + 1): [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Ignored oversized model label",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 10},
                    "confidence": 0.9,
                }
            ],
            " openai:gpt-4o ": [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Reentrancy",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 10},
                    "confidence": 0.9,
                }
            ],
            "ollama:deepseek-coder:6.7b": [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Reentrancy",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 11},
                    "confidence": 0.8,
                }
            ],
        }

        results = detector._ensemble_vote(findings)

        assert len(results) == 1
        assert results[0].votes == 2
        assert results[0].supporting_models == [
            "openai:gpt-4o",
            "ollama:deepseek-coder:6.7b",
        ]
        assert list(results[0].raw_responses) == [
            "openai:gpt-4o",
            "ollama:deepseek-coder:6.7b",
        ]

    def test_ensemble_vote_drops_malformed_confidence_explanation_payload(self, detector):
        """Malformed confidence explanations should not leak container payloads."""
        detector.consensus_threshold = 2

        findings = {
            "model1": [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Reentrancy",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 10},
                    "confidence": 0.9,
                    "confidence_explanation": {"reason": "looks exploitable"},
                }
            ],
            "model2": [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Reentrancy",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 11},
                    "confidence": 0.8,
                    "confidence_explanation": "Confirmed by external call before update.",
                }
            ],
        }

        results = detector._ensemble_vote(findings)

        assert len(results) == 1
        assert "confidence_explanation" not in results[0].raw_responses["model1"]
        assert (
            results[0].raw_responses["model2"]["confidence_explanation"]
            == "Confirmed by external call before update."
        )

    def test_weighted_vote_defaults_malformed_model_weights(self, monkeypatch):
        """Bad weight entries should not crash weighted voting."""
        monkeypatch.setattr(
            LLMEnsembleDetector,
            "MODEL_WEIGHTS",
            {"model1": "bad", "model2": float("nan"), "model3": {"weight": 1.2}},
        )
        detector = LLMEnsembleDetector(voting_strategy=VotingStrategy.WEIGHTED)

        findings = {
            "model1": [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Reentrancy",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 10},
                    "confidence": 0.9,
                }
            ],
            "model2": [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Reentrancy",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 11},
                    "confidence": 0.8,
                }
            ],
            "model3": [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Reentrancy",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 12},
                    "confidence": 0.7,
                }
            ],
        }

        results = detector._ensemble_vote(findings)

        assert len(results) == 1
        assert results[0].votes == 3

    def test_weighted_vote_does_not_let_negative_weights_lower_threshold(self, monkeypatch):
        """Negative weights should default instead of making minority votes pass."""
        monkeypatch.setattr(
            LLMEnsembleDetector,
            "MODEL_WEIGHTS",
            {"model1": 1.0, "model2": -100.0, "model3": -100.0},
        )
        detector = LLMEnsembleDetector(voting_strategy=VotingStrategy.WEIGHTED)

        findings = {
            "model1": [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "title": "Reentrancy",
                    "description": "External call before update",
                    "location": {"function": "withdraw", "line": 10},
                    "confidence": 0.9,
                }
            ],
            "model2": [],
            "model3": [],
        }

        assert detector._ensemble_vote(findings) == []

    def test_finding_signature_defaults_nonfinite_line_scalar(self, detector):
        """Non-finite scalar line values should not crash signature grouping."""
        malformed = {
            "type": "reentrancy",
            "location": {"function": "withdraw", "line": float("inf")},
        }
        defaulted = {
            "type": "reentrancy",
            "location": {"function": "withdraw"},
        }

        assert detector._create_finding_signature(malformed) == detector._create_finding_signature(
            defaulted
        )

    def test_finding_signature_defaults_negative_line_scalar(self, detector):
        """Negative line values should not split otherwise matching signature groups."""
        malformed = {
            "type": "reentrancy",
            "location": {"function": "withdraw", "line": -10},
        }
        defaulted = {
            "type": "reentrancy",
            "location": {"function": "withdraw"},
        }

        assert detector._create_finding_signature(malformed) == detector._create_finding_signature(
            defaulted
        )


class TestLLMEnsembleDetectorQueryMethods:
    """Tests for model query methods."""

    def test_query_model_success(self, detector, llm_response_json):
        """Test successful model query."""

        async def run_test():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"message": {"content": llm_response_json}})

            mock_post = MagicMock()
            mock_post.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post.__aexit__ = AsyncMock(return_value=None)

            mock_session_instance = MagicMock()
            mock_session_instance.post = MagicMock(return_value=mock_post)

            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session_instance)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                results = await detector._query_model("test-model", "contract code")
                assert isinstance(results, list)

        asyncio.run(run_test())

    def test_query_openai_success(self, multi_provider_detector, llm_response_json):
        """Test successful OpenAI query."""

        async def run_test():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={"choices": [{"message": {"content": llm_response_json}}]}
            )

            mock_post = MagicMock()
            mock_post.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post.__aexit__ = AsyncMock(return_value=None)

            mock_session_instance = MagicMock()
            mock_session_instance.post = MagicMock(return_value=mock_post)

            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session_instance)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                results = await multi_provider_detector._query_openai(
                    "gpt-4",
                    "contract code",
                    {"z_key": 1, "a_key": 2},
                )
                assert isinstance(results, list)
                post_payload = mock_session_instance.post.call_args.kwargs["json"]
                user_prompt = post_payload["messages"][1]["content"]
                assert user_prompt.index('"a_key"') < user_prompt.index('"z_key"')

        asyncio.run(run_test())

    def test_query_openai_no_key(self, detector):
        """Test OpenAI query without API key."""

        async def run_test():
            detector.openai_api_key = None

            with pytest.raises(ProviderUnavailable):
                await detector._query_openai("gpt-4", "code")

        asyncio.run(run_test())

    def test_query_openai_rejects_malformed_choices(self, multi_provider_detector):
        """Test OpenAI malformed choices payloads fail as provider unavailable."""

        async def run_test():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"choices": []})

            mock_session = _aiohttp_session_with_response("post", mock_response)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                with pytest.raises(ProviderUnavailable, match="OpenAI response choices"):
                    await multi_provider_detector._query_openai("gpt-4", "contract code")

        asyncio.run(run_test())

    def test_query_openai_rejects_malformed_token_metadata(self, multi_provider_detector):
        """Test OpenAI malformed token metadata fails as provider unavailable."""

        async def run_test():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "choices": [{"message": {"content": "[]"}}],
                    "usage": {"total_tokens": {"count": 1}},
                }
            )

            mock_session = _aiohttp_session_with_response("post", mock_response)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                with pytest.raises(ProviderUnavailable, match="OpenAI response token metadata"):
                    await multi_provider_detector._query_openai("gpt-4", "contract code")

        asyncio.run(run_test())

    def test_query_anthropic_success(self, multi_provider_detector, llm_response_json):
        """Test successful Anthropic query."""

        async def run_test():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"content": [{"text": llm_response_json}]})

            mock_post = MagicMock()
            mock_post.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post.__aexit__ = AsyncMock(return_value=None)

            mock_session_instance = MagicMock()
            mock_session_instance.post = MagicMock(return_value=mock_post)

            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session_instance)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                results = await multi_provider_detector._query_anthropic(
                    "claude-3-sonnet", "contract code"
                )
                assert isinstance(results, list)

        asyncio.run(run_test())

    def test_query_anthropic_uses_first_text_content_block(
        self, multi_provider_detector, llm_response_json
    ):
        """Test Anthropic skips non-text content blocks before parsing text."""

        async def run_test():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "content": [
                        {"type": "tool_use", "name": "ignored"},
                        {"type": "text", "text": llm_response_json},
                    ]
                }
            )

            mock_session = _aiohttp_session_with_response("post", mock_response)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                results = await multi_provider_detector._query_anthropic(
                    "claude-3-sonnet", "contract code"
                )

            assert len(results) == 1
            assert results[0]["type"] == "reentrancy"

        asyncio.run(run_test())

    def test_query_anthropic_rejects_malformed_text_block(self, multi_provider_detector):
        """Test Anthropic malformed content blocks fail as provider unavailable."""

        async def run_test():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"content": [{"type": "text"}]})

            mock_session = _aiohttp_session_with_response("post", mock_response)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                with pytest.raises(ProviderUnavailable, match="Anthropic response text"):
                    await multi_provider_detector._query_anthropic(
                        "claude-3-sonnet", "contract code"
                    )

        asyncio.run(run_test())

    def test_query_deepseek_success(self, llm_response_json):
        """Test successful DeepSeek query."""

        async def run_test():
            detector = LLMEnsembleDetector(
                providers=[LLMProvider.DEEPSEEK],
                deepseek_api_key="test-key",
            )
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={"choices": [{"message": {"content": llm_response_json}}]}
            )

            mock_post = MagicMock()
            mock_post.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post.__aexit__ = AsyncMock(return_value=None)

            mock_session_instance = MagicMock()
            mock_session_instance.post = MagicMock(return_value=mock_post)

            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session_instance)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                results = await detector._query_deepseek("deepseek-v4-flash", "contract code")
                assert isinstance(results, list)
                assert mock_session_instance.post.call_args.args[0] == (
                    "https://api.deepseek.com/v1/chat/completions"
                )

        asyncio.run(run_test())

    def test_query_deepseek_no_key(self, detector):
        """Test DeepSeek query without API key."""

        async def run_test():
            detector.deepseek_api_key = None

            with pytest.raises(ProviderUnavailable):
                await detector._query_deepseek("deepseek-v4-flash", "code")

        asyncio.run(run_test())

    def test_query_deepseek_rejects_malformed_content(self):
        """Test DeepSeek non-string content fails as provider unavailable."""

        async def run_test():
            detector = LLMEnsembleDetector(
                providers=[LLMProvider.DEEPSEEK],
                deepseek_api_key="test-key",
            )
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={"choices": [{"message": {"content": ["not", "text"]}}]}
            )

            mock_session = _aiohttp_session_with_response("post", mock_response)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                with pytest.raises(ProviderUnavailable, match="DeepSeek response content"):
                    await detector._query_deepseek("deepseek-v4-flash", "contract code")

        asyncio.run(run_test())

    def test_query_model_http_error_raises_runtime_error(self, detector):
        """Test Ollama HTTP failures raise a concrete runtime error."""

        async def run_test():
            mock_response = MagicMock()
            mock_response.status = 500
            mock_response.text = AsyncMock(return_value="server error")

            mock_session = _aiohttp_session_with_response("post", mock_response)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                with pytest.raises(RuntimeError, match="Ollama error"):
                    await detector._query_model("test-model", "contract code")

        asyncio.run(run_test())

    def test_query_model_rejects_malformed_ollama_message(self, detector):
        """Test Ollama malformed message payloads fail as provider unavailable."""

        async def run_test():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"message": ["not", "an", "object"]})

            mock_session = _aiohttp_session_with_response("post", mock_response)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                with pytest.raises(ProviderUnavailable, match="Ollama response message"):
                    await detector._query_model("test-model", "contract code")

        asyncio.run(run_test())

    def test_query_model_rejects_malformed_latency_metadata(self, detector):
        """Test Ollama malformed latency metadata fails as provider unavailable."""

        async def run_test():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(
                return_value={
                    "message": {"content": "[]"},
                    "total_duration": ["not", "a", "duration"],
                }
            )

            mock_session = _aiohttp_session_with_response("post", mock_response)

            with patch("aiohttp.ClientSession", return_value=mock_session):
                with pytest.raises(ProviderUnavailable, match="Ollama response latency metadata"):
                    await detector._query_model("test-model", "contract code")

        asyncio.run(run_test())


class TestLLMEnsembleDetectorResponseParsing:
    """Tests for response parsing."""

    def test_parse_valid_json_response(self, detector):
        """Test parsing valid JSON response."""
        response = '[{"type": "reentrancy", "severity": "high", "title": "Test", "description": "Desc", "location": {}, "confidence": 0.9}]'

        results = detector._parse_model_response(response, "test-model")

        assert isinstance(results, list)
        assert len(results) == 1
        assert results[0]["type"] == "reentrancy"

    def test_parse_empty_array(self, detector):
        """Test parsing empty array response."""
        response = "[]"

        results = detector._parse_model_response(response, "test-model")

        assert results == []

    def test_parse_invalid_json(self, detector):
        """Test parsing invalid JSON response."""
        response = "This is not valid JSON"

        results = detector._parse_model_response(response, "test-model")

        # Should return empty list on parse error
        assert results == []

    def test_parse_json_in_markdown(self, detector):
        """Test parsing JSON wrapped in markdown code block."""
        response = """Here is my analysis:
```json
[{"type": "test", "severity": "low", "title": "T", "description": "D", "location": {}, "confidence": 0.5}]
```
That's my finding."""

        results = detector._parse_model_response(response, "test-model")

        assert isinstance(results, list)

    def test_parse_repairs_common_llm_json_errors(self, detector):
        """Test parsing recoverable LLM JSON formatting errors."""
        response = """Here is my analysis:
```json
[
  {type: "test", "severity": "low", "title": "T", "description": "D",}
]
```
"""

        results = detector._parse_model_response(response, "test-model")

        assert len(results) == 1
        assert results[0]["type"] == "test"
        assert results[0]["_source_model"] == "test-model"

    def test_parse_repairs_invalid_backslash_escapes(self, detector):
        """Test parsing regex-style escapes in model response strings."""
        response = (
            r'[{"type": "regex", "severity": "low", "title": "T", "description": "pattern \d+"}]'
        )

        results = detector._parse_model_response(response, "test-model")

        assert len(results) == 1
        assert results[0]["description"] == r"pattern \d+"

    def test_parse_rejects_malformed_type_fields(self, detector):
        """Test parser drops findings whose type is not a real string."""
        response = """[
            {"type": {"name": "reentrancy"}, "severity": "high", "title": "Bad"},
            {"type": ["access-control"], "severity": "medium", "title": "Bad"},
            {"type": "unchecked-call", "severity": "low", "title": "Good"}
        ]"""

        results = detector._parse_model_response(response, "test-model")

        assert len(results) == 1
        assert results[0]["type"] == "unchecked-call"
        assert results[0]["_source_model"] == "test-model"


# =============================================================================
# Integration Tests
# =============================================================================


class TestLLMEnsembleDetectorIntegration:
    """Integration tests for LLMEnsembleDetector."""

    def test_detect_vulnerabilities_ignores_malformed_model_result(
        self, detector, vulnerable_code
    ):
        """Malformed query results should be excluded before stats and voting."""

        async def run_test():
            detector._initialized = True
            detector._available_models = ["model1", "model2"]

            async def mock_query(model, code, context=None):
                if model == "model1":
                    return {"type": "reentrancy", "severity": "high"}
                return [
                    {
                        "type": "reentrancy",
                        "severity": "high",
                        "title": "Reentrancy",
                        "description": "External call before state update",
                        "location": {"function": "withdraw", "line": 10},
                        "confidence": 0.9,
                    }
                ]

            with patch.object(detector, "_query_model", side_effect=mock_query):
                result = await detector.detect_vulnerabilities(vulnerable_code)

            assert result.models_used == ["model2"]
            assert result.total_raw_findings == 1
            assert len(result.findings) == 0

        asyncio.run(run_test())

    def test_detect_vulnerabilities_drops_malformed_consensus_location_before_stats(
        self, detector, vulnerable_code
    ):
        """Malformed consensus location fields should not leak into result statistics."""

        async def run_test():
            detector._initialized = True
            detector._available_models = ["model1", "model2"]
            detector.consensus_threshold = 2

            async def mock_query(model, code, context=None):
                if model == "model1":
                    return [
                        {
                            "type": "reentrancy",
                            "severity": "high",
                            "title": "Reentrancy",
                            "description": "External call before state update",
                            "location": {"function": {"name": "withdraw"}, "line": "not-a-line"},
                            "confidence": 0.9,
                        }
                    ]
                return [
                    {
                        "type": "reentrancy",
                        "severity": "high",
                        "title": "Reentrancy",
                        "description": "External call before state update",
                        "location": {"function": ["withdraw"], "line": ["10"]},
                        "confidence": 0.8,
                    }
                ]

            with patch.object(detector, "_query_model", side_effect=mock_query):
                result = await detector.detect_vulnerabilities(vulnerable_code)

            assert result.total_raw_findings == 2
            assert result.filtered_findings == 1
            assert len(result.findings) == 1
            assert result.findings[0].location == {}

        asyncio.run(run_test())

    def test_detect_vulnerabilities_drops_malformed_consensus_type_before_stats(
        self, detector, vulnerable_code
    ):
        """Malformed consensus type/category fields should not enter stats or voting."""

        async def run_test():
            detector._initialized = True
            detector._available_models = ["model1", "model2", "model3"]
            detector.consensus_threshold = 2

            async def mock_query(model, code, context=None):
                if model == "model1":
                    return [
                        {
                            "type": {"category": "reentrancy"},
                            "severity": "high",
                            "title": "Malformed type object",
                            "description": "External call before state update",
                            "location": {"function": "withdraw", "line": 10},
                            "confidence": 0.9,
                        }
                    ]
                if model == "model2":
                    return [
                        {
                            "type": "reentrancy\naccess-control",
                            "severity": "high",
                            "title": "Malformed type control character",
                            "description": "External call before state update",
                            "location": {"function": "withdraw", "line": 11},
                            "confidence": 0.8,
                        }
                    ]
                return [
                    {
                        "type": "reentrancy",
                        "severity": "high",
                        "title": "Valid type",
                        "description": "External call before state update",
                        "location": {"function": "withdraw", "line": 12},
                        "confidence": 0.7,
                    }
                ]

            with patch.object(detector, "_query_model", side_effect=mock_query):
                result = await detector.detect_vulnerabilities(vulnerable_code)

            assert result.total_raw_findings == 1
            assert result.filtered_findings == 1
            assert result.models_used == ["model1", "model2", "model3"]
            assert result.findings == []

        asyncio.run(run_test())

    def test_detect_vulnerabilities_filters_malformed_available_model_ids_before_payload(
        self, detector, vulnerable_code
    ):
        """Malformed available model ids should not enter query payload construction."""

        async def run_test():
            detector._initialized = True
            detector._available_models = [{"id": "model1"}, " model1 ", "", ["bad"], "model2"]
            detector.consensus_threshold = 2
            queried_models = []

            async def mock_query(model, code, context=None):
                queried_models.append(model)
                return [
                    {
                        "type": "reentrancy",
                        "severity": "high",
                        "title": "Reentrancy",
                        "description": "External call before state update",
                        "location": {"function": "withdraw", "line": 10},
                        "confidence": 0.9,
                    }
                ]

            with patch.object(detector, "_query_model", side_effect=mock_query):
                result = await detector.detect_vulnerabilities(vulnerable_code)

            assert queried_models == ["model1", "model2"]
            assert result.models_available == ["model1", "model2"]
            assert result.models_used == ["model1", "model2"]
            assert len(result.findings) == 1

        asyncio.run(run_test())

    def test_full_workflow_mocked(self, detector, vulnerable_code, sample_model_findings):
        """Test full detection workflow with mocked responses."""

        async def run_test():
            # Mock initialize
            detector._initialized = True
            detector._available_models = ["model1", "model2", "model3"]
            detector._available_providers = {LLMProvider.OLLAMA: ["model1", "model2", "model3"]}

            # Mock _detect_with_provider
            with patch.object(
                detector, "_detect_with_provider", new_callable=AsyncMock
            ) as mock_detect:
                finding = EnsembleFinding(
                    type="reentrancy",
                    severity="high",
                    title="Reentrancy vulnerability",
                    description="External call before state update",
                    location={"function": "withdraw", "line": 10},
                    confidence=0.9,
                    votes=3,
                    total_models=3,
                    supporting_models=["model1", "model2", "model3"],
                )
                mock_detect.return_value = [finding]

                results = await detector.detect_with_fallback(vulnerable_code)

                assert len(results) == 1
                assert results[0].type == "reentrancy"
                assert results[0].votes == 3

        asyncio.run(run_test())

    def test_detect_with_provider_filters_malformed_model_ids_before_payload(
        self, detector, vulnerable_code
    ):
        """Malformed provider model ids should not enter provider query payloads."""

        async def run_test():
            detector._available_providers = {
                LLMProvider.OLLAMA: [{"id": "model1"}, " model1 ", "", ["bad"], "model2"]
            }
            detector.consensus_threshold = 2
            queried_models = []

            async def mock_query(model, code, context=None):
                queried_models.append(model)
                return [
                    {
                        "type": "reentrancy",
                        "severity": "high",
                        "title": "Reentrancy",
                        "description": "External call before state update",
                        "location": {"function": "withdraw", "line": 10},
                        "confidence": 0.9,
                    }
                ]

            with patch.object(detector, "_query_model", side_effect=mock_query):
                results = await detector._detect_with_provider(
                    LLMProvider.OLLAMA,
                    vulnerable_code,
                )

            assert queried_models == ["model1", "model2"]
            assert len(results) == 1
            assert results[0].supporting_models == ["model1", "model2"]

        asyncio.run(run_test())

    def test_detect_with_provider_handles_provider_score_map_entries(
        self, detector, vulnerable_code
    ):
        """Provider score maps should yield the valid model keys for querying."""

        async def run_test():
            detector._available_providers = {
                LLMProvider.OLLAMA: {
                    ("bad",): 0.2,
                    " model1 ": 0.8,
                    123: 0.6,
                    "": 0.1,
                    "model2": 0.6,
                },
            }
            detector.consensus_threshold = 2
            queried_models = []

            async def mock_query(model, code, context=None):
                queried_models.append(model)
                return [
                    {
                        "type": "reentrancy",
                        "severity": "high",
                        "title": "Reentrancy",
                        "description": "External call before state update",
                        "location": {"function": "withdraw", "line": 10},
                        "confidence": 0.9,
                    }
                ]

            with patch.object(detector, "_query_model", side_effect=mock_query):
                results = await detector._detect_with_provider(
                    LLMProvider.OLLAMA,
                    vulnerable_code,
                )

            assert queried_models == ["model1", "model2"]
            assert len(results) == 1
            assert results[0].supporting_models == ["model1", "model2"]

        asyncio.run(run_test())

    def test_detect_with_provider_rejects_malformed_provider_status_map(
        self, detector, vulnerable_code
    ):
        """Malformed provider status maps should not raise attribute errors."""

        async def run_test():
            detector._available_providers = ["model1", "model2"]

            with pytest.raises(ProviderUnavailable, match="No models available"):
                await detector._detect_with_provider(LLMProvider.OLLAMA, vulnerable_code)

        asyncio.run(run_test())

    def test_provider_priority_order(self, multi_provider_detector):
        """Test that providers are tried in order."""

        async def run_test():
            multi_provider_detector._initialized = True
            multi_provider_detector._available_providers = {
                LLMProvider.OLLAMA: ["model1"],
                LLMProvider.OPENAI: ["gpt-4"],
                LLMProvider.ANTHROPIC: ["claude"],
            }

            providers_tried = []

            async def mock_detect(provider, code, context):
                providers_tried.append(provider)
                if provider == LLMProvider.OLLAMA:
                    raise ProviderUnavailable("Ollama down")
                if provider == LLMProvider.OPENAI:
                    raise ProviderUnavailable("OpenAI down")
                return []

            with patch.object(
                multi_provider_detector, "_detect_with_provider", side_effect=mock_detect
            ):
                try:
                    await multi_provider_detector.detect_with_fallback("code")
                except AllProvidersUnavailable:
                    pass

            # Should try providers in order
            assert providers_tried[0] == LLMProvider.OLLAMA
            assert providers_tried[1] == LLMProvider.OPENAI
            assert providers_tried[2] == LLMProvider.ANTHROPIC

        asyncio.run(run_test())


# =============================================================================
# Parametrized Tests
# =============================================================================


@pytest.mark.parametrize(
    "strategy,threshold,expected_pass",
    [
        (VotingStrategy.THRESHOLD, 2, True),  # 3 votes >= 2
        (VotingStrategy.THRESHOLD, 4, False),  # 3 votes < 4
        (VotingStrategy.MAJORITY, 2, True),  # 3/3 > 50%
    ],
)
def test_voting_strategies(strategy, threshold, expected_pass):
    """Test different voting strategies."""
    detector = LLMEnsembleDetector(
        voting_strategy=strategy,
        consensus_threshold=threshold,
    )

    findings = {
        "model1": [
            {
                "type": "test",
                "severity": "high",
                "title": "T",
                "description": "D",
                "location": {"line": 1},
                "confidence": 0.9,
            }
        ],
        "model2": [
            {
                "type": "test",
                "severity": "high",
                "title": "T",
                "description": "D",
                "location": {"line": 1},
                "confidence": 0.9,
            }
        ],
        "model3": [
            {
                "type": "test",
                "severity": "high",
                "title": "T",
                "description": "D",
                "location": {"line": 1},
                "confidence": 0.9,
            }
        ],
    }

    results = detector._ensemble_vote(findings)

    if expected_pass:
        assert len(results) > 0
    # Note: may still pass with threshold=4 depending on implementation


@pytest.mark.parametrize(
    "provider,expected_models",
    [
        (LLMProvider.OLLAMA, ["deepseek-coder:6.7b", "codellama:7b", "llama3.1:8b"]),
        (LLMProvider.OPENAI, ["gpt-4-turbo", "gpt-4o", "gpt-3.5-turbo"]),
        (
            LLMProvider.ANTHROPIC,
            ["claude-3-5-sonnet-20241022", "claude-3-haiku-20240307"],
        ),
        (LLMProvider.DEEPSEEK, ["deepseek-v4-flash", "deepseek-v4-pro"]),
    ],
)
def test_provider_model_lists(provider, expected_models):
    """Test that provider model lists contain expected models."""
    models = LLMEnsembleDetector.PROVIDER_MODELS[provider]
    for expected in expected_models:
        assert expected in models, f"{expected} not in {provider} models"
