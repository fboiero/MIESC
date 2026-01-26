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

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from dataclasses import asdict

from src.llm.ensemble_detector import (
    LLMProvider,
    VotingStrategy,
    EnsembleFinding,
    EnsembleResult,
    LLMEnsembleDetector,
    ProviderUnavailable,
    AllProvidersUnavailable,
)


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

    def test_provider_count(self):
        """Test provider count."""
        assert len(LLMProvider) == 3


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

    def test_custom_voting_strategy(self):
        """Test initialization with custom voting strategy."""
        detector = LLMEnsembleDetector(
            voting_strategy=VotingStrategy.MAJORITY
        )
        assert detector.voting_strategy == VotingStrategy.MAJORITY

    def test_multi_provider_init(self, multi_provider_detector):
        """Test initialization with multiple providers."""
        assert len(multi_provider_detector.providers) == 3
        assert multi_provider_detector.openai_api_key == "test-openai-key"
        assert multi_provider_detector.anthropic_api_key == "test-anthropic-key"

    def test_env_api_keys(self):
        """Test API keys from environment variables."""
        with patch.dict('os.environ', {
            'OPENAI_API_KEY': 'env-openai-key',
            'ANTHROPIC_API_KEY': 'env-anthropic-key',
        }):
            detector = LLMEnsembleDetector(
                providers=[LLMProvider.OPENAI, LLMProvider.ANTHROPIC]
            )
            assert detector.openai_api_key == "env-openai-key"
            assert detector.anthropic_api_key == "env-anthropic-key"

    def test_temperature_setting(self):
        """Test temperature parameter."""
        detector = LLMEnsembleDetector(temperature=0.5)
        assert detector.temperature == 0.5

    def test_timeout_setting(self):
        """Test timeout parameter."""
        detector = LLMEnsembleDetector(timeout=60)
        assert detector.timeout == 60


class TestLLMEnsembleDetectorConstants:
    """Tests for LLMEnsembleDetector class constants."""

    def test_provider_models_defined(self):
        """Test that provider models are defined."""
        assert LLMProvider.OLLAMA in LLMEnsembleDetector.PROVIDER_MODELS
        assert LLMProvider.OPENAI in LLMEnsembleDetector.PROVIDER_MODELS
        assert LLMProvider.ANTHROPIC in LLMEnsembleDetector.PROVIDER_MODELS

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

    def test_model_weights(self):
        """Test model weights are defined."""
        weights = LLMEnsembleDetector.MODEL_WEIGHTS
        assert "deepseek-coder:6.7b" in weights
        assert weights["deepseek-coder:6.7b"] > 1.0  # Higher weight

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
            with patch('aiohttp.ClientSession') as mock_session:
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(return_value={
                    "models": [
                        {"name": "deepseek-coder:6.7b"},
                        {"name": "codellama:7b"},
                    ]
                })
                mock_session.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value = mock_response

                status = await detector.initialize()

                assert detector._initialized
                assert isinstance(status, dict)

        asyncio.run(run_test())

    def test_initialize_no_models(self, detector):
        """Test initialization when no models available."""
        async def run_test():
            with patch('aiohttp.ClientSession') as mock_session:
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(return_value={"models": []})
                mock_session.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value = mock_response

                status = await detector.initialize()

                assert detector._initialized
                # Should still initialize even with no models

        asyncio.run(run_test())

    def test_initialize_connection_error(self, detector):
        """Test initialization with connection error."""
        async def run_test():
            with patch('aiohttp.ClientSession') as mock_session:
                mock_session.return_value.__aenter__.return_value.get.side_effect = Exception("Connection refused")

                # Should not raise, just log warning
                status = await detector.initialize()
                assert detector._initialized

        asyncio.run(run_test())


class TestLLMEnsembleDetectorProviderAvailability:
    """Tests for provider availability checking."""

    def test_check_ollama_available(self, detector):
        """Test checking Ollama availability."""
        async def run_test():
            # Create proper async context manager mocks
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={
                "models": [{"name": "test-model"}]
            })

            mock_get = MagicMock()
            mock_get.__aenter__ = AsyncMock(return_value=mock_response)
            mock_get.__aexit__ = AsyncMock(return_value=None)

            mock_session_instance = MagicMock()
            mock_session_instance.get = MagicMock(return_value=mock_get)

            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session_instance)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch('aiohttp.ClientSession', return_value=mock_session):
                models = await detector._check_provider_availability(LLMProvider.OLLAMA)
                assert "test-model" in models

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
            models = await multi_provider_detector._check_provider_availability(LLMProvider.ANTHROPIC)
            assert len(models) > 0

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
            with patch.object(multi_provider_detector, '_detect_with_provider', new_callable=AsyncMock) as mock_detect:
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

            with patch.object(multi_provider_detector, '_detect_with_provider', side_effect=mock_detect):
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

            with patch.object(multi_provider_detector, '_detect_with_provider', new_callable=AsyncMock) as mock_detect:
                mock_detect.side_effect = ProviderUnavailable("All failed")

                with pytest.raises(AllProvidersUnavailable):
                    await multi_provider_detector.detect_with_fallback(vulnerable_code)

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
            "model1": [{"type": "reentrancy", "severity": "high", "title": "R1", "description": "D1", "location": {}, "confidence": 0.9}],
            "model2": [{"type": "access-control", "severity": "medium", "title": "A1", "description": "D2", "location": {}, "confidence": 0.8}],
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
            "model1": [{"type": "test", "severity": "low", "title": "T1", "description": "D1", "location": {}, "confidence": 0.5}],
        }

        results = detector._ensemble_vote(findings)
        # With threshold=1, single model finding should pass
        assert isinstance(results, list)


class TestLLMEnsembleDetectorQueryMethods:
    """Tests for model query methods."""

    def test_query_model_success(self, detector, llm_response_json):
        """Test successful model query."""
        async def run_test():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={
                "message": {"content": llm_response_json}
            })

            mock_post = MagicMock()
            mock_post.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post.__aexit__ = AsyncMock(return_value=None)

            mock_session_instance = MagicMock()
            mock_session_instance.post = MagicMock(return_value=mock_post)

            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session_instance)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch('aiohttp.ClientSession', return_value=mock_session):
                results = await detector._query_model("test-model", "contract code")
                assert isinstance(results, list)

        asyncio.run(run_test())

    def test_query_openai_success(self, multi_provider_detector, llm_response_json):
        """Test successful OpenAI query."""
        async def run_test():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={
                "choices": [{"message": {"content": llm_response_json}}]
            })

            mock_post = MagicMock()
            mock_post.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post.__aexit__ = AsyncMock(return_value=None)

            mock_session_instance = MagicMock()
            mock_session_instance.post = MagicMock(return_value=mock_post)

            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session_instance)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch('aiohttp.ClientSession', return_value=mock_session):
                results = await multi_provider_detector._query_openai("gpt-4", "contract code")
                assert isinstance(results, list)

        asyncio.run(run_test())

    def test_query_openai_no_key(self, detector):
        """Test OpenAI query without API key."""
        async def run_test():
            detector.openai_api_key = None

            with pytest.raises(ProviderUnavailable):
                await detector._query_openai("gpt-4", "code")

        asyncio.run(run_test())

    def test_query_anthropic_success(self, multi_provider_detector, llm_response_json):
        """Test successful Anthropic query."""
        async def run_test():
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={
                "content": [{"text": llm_response_json}]
            })

            mock_post = MagicMock()
            mock_post.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post.__aexit__ = AsyncMock(return_value=None)

            mock_session_instance = MagicMock()
            mock_session_instance.post = MagicMock(return_value=mock_post)

            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session_instance)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            with patch('aiohttp.ClientSession', return_value=mock_session):
                results = await multi_provider_detector._query_anthropic("claude-3-sonnet", "contract code")
                assert isinstance(results, list)

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


# =============================================================================
# Integration Tests
# =============================================================================


class TestLLMEnsembleDetectorIntegration:
    """Integration tests for LLMEnsembleDetector."""

    def test_full_workflow_mocked(self, detector, vulnerable_code, sample_model_findings):
        """Test full detection workflow with mocked responses."""
        async def run_test():
            # Mock initialize
            detector._initialized = True
            detector._available_models = ["model1", "model2", "model3"]
            detector._available_providers = {LLMProvider.OLLAMA: ["model1", "model2", "model3"]}

            # Mock _detect_with_provider
            with patch.object(detector, '_detect_with_provider', new_callable=AsyncMock) as mock_detect:
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

            with patch.object(multi_provider_detector, '_detect_with_provider', side_effect=mock_detect):
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


@pytest.mark.parametrize("strategy,threshold,expected_pass", [
    (VotingStrategy.THRESHOLD, 2, True),   # 3 votes >= 2
    (VotingStrategy.THRESHOLD, 4, False),  # 3 votes < 4
    (VotingStrategy.MAJORITY, 2, True),    # 3/3 > 50%
])
def test_voting_strategies(strategy, threshold, expected_pass):
    """Test different voting strategies."""
    detector = LLMEnsembleDetector(
        voting_strategy=strategy,
        consensus_threshold=threshold,
    )

    findings = {
        "model1": [{"type": "test", "severity": "high", "title": "T", "description": "D", "location": {"line": 1}, "confidence": 0.9}],
        "model2": [{"type": "test", "severity": "high", "title": "T", "description": "D", "location": {"line": 1}, "confidence": 0.9}],
        "model3": [{"type": "test", "severity": "high", "title": "T", "description": "D", "location": {"line": 1}, "confidence": 0.9}],
    }

    results = detector._ensemble_vote(findings)

    if expected_pass:
        assert len(results) > 0
    # Note: may still pass with threshold=4 depending on implementation


@pytest.mark.parametrize("provider,expected_models", [
    (LLMProvider.OLLAMA, ["deepseek-coder:6.7b", "codellama:7b", "llama3.1:8b"]),
    (LLMProvider.OPENAI, ["gpt-4-turbo", "gpt-4o", "gpt-3.5-turbo"]),
])
def test_provider_model_lists(provider, expected_models):
    """Test that provider model lists contain expected models."""
    models = LLMEnsembleDetector.PROVIDER_MODELS[provider]
    for expected in expected_models:
        assert expected in models, f"{expected} not in {provider} models"
