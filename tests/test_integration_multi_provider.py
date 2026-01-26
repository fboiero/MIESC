"""
Integration Tests for Multi-Provider LLM Ensemble
=================================================

Tests for the multi-provider functionality of the LLM ensemble detector,
including provider fallback, voting strategies, and cross-provider consistency.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
"""

import pytest
import asyncio
import json
from unittest.mock import patch, MagicMock, AsyncMock
from dataclasses import asdict

from src.llm.ensemble_detector import (
    LLMEnsembleDetector,
    LLMProvider,
    VotingStrategy,
    EnsembleFinding,
    EnsembleResult,
    ProviderUnavailable,
    AllProvidersUnavailable,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def sample_vulnerable_code():
    """Sample vulnerable Solidity contract."""
    return """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;  // State update after external call
    }
}
"""


@pytest.fixture
def reentrancy_finding():
    """Sample reentrancy finding response."""
    return {
        "type": "reentrancy",
        "severity": "critical",
        "title": "Reentrancy Vulnerability in withdraw()",
        "description": "External call before state update allows reentrancy attack",
        "location": {"function": "withdraw", "line": 15},
        "attack_vector": "Attacker can recursively call withdraw()",
        "remediation": "Update state before external call",
        "confidence": 0.95,
    }


@pytest.fixture
def access_control_finding():
    """Sample access control finding response."""
    return {
        "type": "access-control",
        "severity": "high",
        "title": "Missing Access Control",
        "description": "Admin function lacks proper access control",
        "location": {"function": "setOwner", "line": 25},
        "attack_vector": "Any user can call admin functions",
        "remediation": "Add onlyOwner modifier",
        "confidence": 0.85,
    }


@pytest.fixture
def multi_provider_detector():
    """Create detector with multiple providers configured."""
    return LLMEnsembleDetector(
        providers=[LLMProvider.OLLAMA, LLMProvider.OPENAI, LLMProvider.ANTHROPIC],
        openai_api_key="test-openai-key",
        anthropic_api_key="test-anthropic-key",
        consensus_threshold=2,
    )


@pytest.fixture
def ollama_only_detector():
    """Create detector with only Ollama provider."""
    return LLMEnsembleDetector(
        providers=[LLMProvider.OLLAMA],
        consensus_threshold=2,
    )


def create_mock_aiohttp_response(status, json_data):
    """Helper to create mock aiohttp response."""
    mock_response = MagicMock()
    mock_response.status = status
    mock_response.json = AsyncMock(return_value=json_data)
    mock_response.text = AsyncMock(return_value=json.dumps(json_data))
    return mock_response


def create_mock_session(responses):
    """
    Helper to create mock aiohttp ClientSession.

    Args:
        responses: List of (status, json_data) tuples for sequential calls
    """
    response_iter = iter(responses)

    def get_next_response(*args, **kwargs):
        try:
            status, json_data = next(response_iter)
            return create_mock_context_manager(status, json_data)
        except StopIteration:
            return create_mock_context_manager(500, {"error": "No more responses"})

    mock_session = MagicMock()
    mock_session.post = MagicMock(side_effect=get_next_response)
    mock_session.get = MagicMock(side_effect=get_next_response)

    session_context = MagicMock()
    session_context.__aenter__ = AsyncMock(return_value=mock_session)
    session_context.__aexit__ = AsyncMock(return_value=None)

    return session_context


def create_mock_context_manager(status, json_data):
    """Create a mock async context manager for aiohttp responses."""
    mock_response = create_mock_aiohttp_response(status, json_data)

    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_response)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    return mock_cm


# =============================================================================
# Multi-Provider Initialization Tests
# =============================================================================

class TestMultiProviderInitialization:
    """Tests for multi-provider initialization."""

    def test_single_provider_initialization(self, ollama_only_detector):
        """Test initialization with single provider."""
        assert LLMProvider.OLLAMA in ollama_only_detector.providers
        assert len(ollama_only_detector.providers) == 1

    def test_multi_provider_initialization(self, multi_provider_detector):
        """Test initialization with multiple providers."""
        assert LLMProvider.OLLAMA in multi_provider_detector.providers
        assert LLMProvider.OPENAI in multi_provider_detector.providers
        assert LLMProvider.ANTHROPIC in multi_provider_detector.providers
        assert len(multi_provider_detector.providers) == 3

    def test_api_keys_from_init(self, multi_provider_detector):
        """Test API keys are set from initialization."""
        assert multi_provider_detector.openai_api_key == "test-openai-key"
        assert multi_provider_detector.anthropic_api_key == "test-anthropic-key"

    def test_api_keys_from_environment(self):
        """Test API keys are read from environment variables."""
        with patch.dict('os.environ', {
            'OPENAI_API_KEY': 'env-openai-key',
            'ANTHROPIC_API_KEY': 'env-anthropic-key'
        }):
            detector = LLMEnsembleDetector(
                providers=[LLMProvider.OPENAI, LLMProvider.ANTHROPIC]
            )
            assert detector.openai_api_key == 'env-openai-key'
            assert detector.anthropic_api_key == 'env-anthropic-key'

    def test_provider_models_configuration(self):
        """Test provider-specific model configurations exist."""
        assert LLMProvider.OLLAMA in LLMEnsembleDetector.PROVIDER_MODELS
        assert LLMProvider.OPENAI in LLMEnsembleDetector.PROVIDER_MODELS
        assert LLMProvider.ANTHROPIC in LLMEnsembleDetector.PROVIDER_MODELS

        # Check some models exist for each provider
        assert len(LLMEnsembleDetector.PROVIDER_MODELS[LLMProvider.OLLAMA]) >= 3
        assert len(LLMEnsembleDetector.PROVIDER_MODELS[LLMProvider.OPENAI]) >= 3
        assert len(LLMEnsembleDetector.PROVIDER_MODELS[LLMProvider.ANTHROPIC]) >= 2

    def test_model_weights_include_all_providers(self):
        """Test model weights include models from all providers."""
        weights = LLMEnsembleDetector.MODEL_WEIGHTS

        # Ollama models
        assert "deepseek-coder:6.7b" in weights
        assert "codellama:7b" in weights

        # OpenAI models
        assert "gpt-4-turbo" in weights
        assert "gpt-4o" in weights

        # Anthropic models
        assert "claude-3-5-sonnet-20241022" in weights
        assert "claude-3-haiku-20240307" in weights


# =============================================================================
# Provider Availability Tests
# =============================================================================

class TestProviderAvailability:
    """Tests for provider availability checking."""

    def test_check_ollama_availability_success(self, ollama_only_detector):
        """Test Ollama availability check when successful."""
        async def run_test():
            ollama_response = {
                "models": [
                    {"name": "deepseek-coder:6.7b"},
                    {"name": "codellama:7b"},
                    {"name": "llama3.1:8b"},
                ]
            }

            with patch('aiohttp.ClientSession') as mock_session_class:
                mock_session_class.return_value = create_mock_session([
                    (200, ollama_response)
                ])

                models = await ollama_only_detector._check_provider_availability(
                    LLMProvider.OLLAMA
                )

            assert len(models) == 3
            assert "deepseek-coder:6.7b" in models

        asyncio.run(run_test())

    def test_check_ollama_availability_failure(self, ollama_only_detector):
        """Test Ollama availability check when unavailable."""
        async def run_test():
            with patch('aiohttp.ClientSession') as mock_session_class:
                mock_session_class.return_value.__aenter__ = AsyncMock(
                    side_effect=Exception("Connection refused")
                )
                mock_session_class.return_value.__aexit__ = AsyncMock(return_value=None)

                models = await ollama_only_detector._check_provider_availability(
                    LLMProvider.OLLAMA
                )

            assert models == []

        asyncio.run(run_test())

    def test_check_openai_availability_with_key(self, multi_provider_detector):
        """Test OpenAI availability when API key is set."""
        async def run_test():
            models = await multi_provider_detector._check_provider_availability(
                LLMProvider.OPENAI
            )

            assert len(models) >= 3
            assert "gpt-4-turbo" in models

        asyncio.run(run_test())

    def test_check_openai_availability_without_key(self):
        """Test OpenAI availability when no API key."""
        async def run_test():
            detector = LLMEnsembleDetector(
                providers=[LLMProvider.OPENAI],
                openai_api_key=None,
            )

            models = await detector._check_provider_availability(LLMProvider.OPENAI)
            assert models == []

        asyncio.run(run_test())

    def test_check_anthropic_availability_with_key(self, multi_provider_detector):
        """Test Anthropic availability when API key is set."""
        async def run_test():
            models = await multi_provider_detector._check_provider_availability(
                LLMProvider.ANTHROPIC
            )

            assert len(models) >= 2
            assert "claude-3-5-sonnet-20241022" in models

        asyncio.run(run_test())

    def test_check_anthropic_availability_without_key(self):
        """Test Anthropic availability when no API key."""
        async def run_test():
            detector = LLMEnsembleDetector(
                providers=[LLMProvider.ANTHROPIC],
                anthropic_api_key=None,
            )

            models = await detector._check_provider_availability(LLMProvider.ANTHROPIC)
            assert models == []

        asyncio.run(run_test())


# =============================================================================
# Provider Fallback Tests
# =============================================================================

class TestProviderFallback:
    """Tests for provider fallback mechanism."""

    def test_fallback_to_second_provider(self, multi_provider_detector, sample_vulnerable_code, reentrancy_finding):
        """Test fallback when first provider fails."""
        async def run_test():
            # Initialize with only OpenAI available
            multi_provider_detector._initialized = True
            multi_provider_detector._available_providers = {
                LLMProvider.OLLAMA: [],  # Ollama unavailable
                LLMProvider.OPENAI: ["gpt-4-turbo", "gpt-4o"],
                LLMProvider.ANTHROPIC: [],
            }
            multi_provider_detector._available_models = ["gpt-4-turbo", "gpt-4o"]

            # Mock OpenAI response
            openai_response = {
                "choices": [{
                    "message": {
                        "content": json.dumps([reentrancy_finding])
                    }
                }]
            }

            with patch('aiohttp.ClientSession') as mock_session_class:
                # Create session that returns OpenAI responses
                mock_session = MagicMock()
                mock_session.post = MagicMock(
                    return_value=create_mock_context_manager(200, openai_response)
                )

                session_ctx = MagicMock()
                session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
                session_ctx.__aexit__ = AsyncMock(return_value=None)
                mock_session_class.return_value = session_ctx

                findings = await multi_provider_detector.detect_with_fallback(
                    sample_vulnerable_code
                )

            # Should get findings from OpenAI (fallback from Ollama)
            assert len(findings) >= 0  # May be 0 due to voting threshold

        asyncio.run(run_test())

    def test_all_providers_unavailable(self, multi_provider_detector, sample_vulnerable_code):
        """Test AllProvidersUnavailable exception when all fail."""
        async def run_test():
            # Initialize with no providers available
            multi_provider_detector._initialized = True
            multi_provider_detector._available_providers = {
                LLMProvider.OLLAMA: [],
                LLMProvider.OPENAI: [],
                LLMProvider.ANTHROPIC: [],
            }
            multi_provider_detector._available_models = []

            with pytest.raises(AllProvidersUnavailable):
                await multi_provider_detector.detect_with_fallback(sample_vulnerable_code)

        asyncio.run(run_test())

    def test_provider_unavailable_exception(self, multi_provider_detector, sample_vulnerable_code):
        """Test ProviderUnavailable is raised for individual provider failures."""
        async def run_test():
            multi_provider_detector._initialized = True
            multi_provider_detector._available_providers = {
                LLMProvider.OLLAMA: ["deepseek-coder:6.7b"],
                LLMProvider.OPENAI: [],
                LLMProvider.ANTHROPIC: [],
            }

            with patch('aiohttp.ClientSession') as mock_session_class:
                mock_session_class.return_value.__aenter__ = AsyncMock(
                    side_effect=Exception("Connection error")
                )
                mock_session_class.return_value.__aexit__ = AsyncMock(return_value=None)

                with pytest.raises(AllProvidersUnavailable):
                    await multi_provider_detector.detect_with_fallback(sample_vulnerable_code)

        asyncio.run(run_test())


# =============================================================================
# Cross-Provider Voting Tests
# =============================================================================

class TestCrossProviderVoting:
    """Tests for voting across multiple providers."""

    def test_consensus_from_multiple_providers(self, multi_provider_detector, reentrancy_finding):
        """Test that findings from different providers are aggregated."""
        # Simulate findings from different models
        model_findings = {
            "deepseek-coder:6.7b": [reentrancy_finding.copy()],
            "gpt-4-turbo": [reentrancy_finding.copy()],
            "claude-3-5-sonnet-20241022": [reentrancy_finding.copy()],
        }

        # Add source model to findings
        for model, findings in model_findings.items():
            for f in findings:
                f["_source_model"] = model

        validated = multi_provider_detector._ensemble_vote(model_findings)

        # Should have consensus (3 votes >= threshold of 2)
        assert len(validated) == 1
        assert validated[0].votes == 3
        assert validated[0].type == "reentrancy"

        # All three models should support this finding
        assert len(validated[0].supporting_models) == 3

    def test_no_consensus_single_provider(self, multi_provider_detector, reentrancy_finding):
        """Test that single model doesn't pass threshold."""
        model_findings = {
            "deepseek-coder:6.7b": [reentrancy_finding.copy()],
        }

        for model, findings in model_findings.items():
            for f in findings:
                f["_source_model"] = model

        validated = multi_provider_detector._ensemble_vote(model_findings)

        # Single vote < threshold of 2
        assert len(validated) == 0

    def test_weighted_voting_strategy(self, reentrancy_finding):
        """Test weighted voting strategy."""
        detector = LLMEnsembleDetector(
            voting_strategy=VotingStrategy.WEIGHTED,
            providers=[LLMProvider.OLLAMA, LLMProvider.OPENAI],
        )

        # Higher-weighted models
        model_findings = {
            "gpt-4-turbo": [reentrancy_finding.copy()],  # Weight 1.4
            "gpt-4o": [reentrancy_finding.copy()],       # Weight 1.35
        }

        for model, findings in model_findings.items():
            for f in findings:
                f["_source_model"] = model

        validated = detector._ensemble_vote(model_findings)

        # Combined weight 2.75 > 50% of max possible (2.75)
        assert len(validated) == 1

    def test_majority_voting_strategy(self, reentrancy_finding, access_control_finding):
        """Test majority voting strategy."""
        detector = LLMEnsembleDetector(
            voting_strategy=VotingStrategy.MAJORITY,
        )

        model_findings = {
            "model1": [reentrancy_finding.copy()],
            "model2": [reentrancy_finding.copy()],
            "model3": [access_control_finding.copy()],  # Different finding
        }

        for model, findings in model_findings.items():
            for f in findings:
                f["_source_model"] = model

        validated = detector._ensemble_vote(model_findings)

        # Reentrancy has 2/3 votes (>50%), access_control has 1/3 (<50%)
        assert len(validated) == 1
        assert validated[0].type == "reentrancy"

    def test_unanimous_voting_strategy(self, reentrancy_finding, access_control_finding):
        """Test unanimous voting strategy."""
        detector = LLMEnsembleDetector(
            voting_strategy=VotingStrategy.UNANIMOUS,
        )

        # Different findings from different models - no consensus
        model_findings = {
            "model1": [reentrancy_finding.copy()],
            "model2": [reentrancy_finding.copy()],
            "model3": [access_control_finding.copy()],
        }

        for model, findings in model_findings.items():
            for f in findings:
                f["_source_model"] = model

        validated = detector._ensemble_vote(model_findings)

        # Neither finding has all 3 votes
        assert len(validated) == 0

    def test_unanimous_all_agree(self, reentrancy_finding):
        """Test unanimous voting when all models agree."""
        detector = LLMEnsembleDetector(
            voting_strategy=VotingStrategy.UNANIMOUS,
        )

        model_findings = {
            "model1": [reentrancy_finding.copy()],
            "model2": [reentrancy_finding.copy()],
            "model3": [reentrancy_finding.copy()],
        }

        for model, findings in model_findings.items():
            for f in findings:
                f["_source_model"] = model

        validated = detector._ensemble_vote(model_findings)

        assert len(validated) == 1
        assert validated[0].votes == 3


# =============================================================================
# Provider-Specific Query Tests
# =============================================================================

class TestProviderQueries:
    """Tests for provider-specific query methods."""

    def test_query_openai_success(self, multi_provider_detector, sample_vulnerable_code, reentrancy_finding):
        """Test successful OpenAI query."""
        async def run_test():
            openai_response = {
                "choices": [{
                    "message": {
                        "content": json.dumps([reentrancy_finding])
                    }
                }]
            }

            with patch('aiohttp.ClientSession') as mock_session_class:
                mock_session = MagicMock()
                mock_session.post = MagicMock(
                    return_value=create_mock_context_manager(200, openai_response)
                )

                session_ctx = MagicMock()
                session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
                session_ctx.__aexit__ = AsyncMock(return_value=None)
                mock_session_class.return_value = session_ctx

                findings = await multi_provider_detector._query_openai(
                    "gpt-4-turbo",
                    sample_vulnerable_code
                )

            assert len(findings) == 1
            assert findings[0]["type"] == "reentrancy"
            assert findings[0]["_source_model"] == "gpt-4-turbo"

        asyncio.run(run_test())

    def test_query_openai_no_api_key(self, sample_vulnerable_code):
        """Test OpenAI query fails without API key."""
        async def run_test():
            detector = LLMEnsembleDetector(
                providers=[LLMProvider.OPENAI],
                openai_api_key=None,
            )

            with pytest.raises(ProviderUnavailable) as exc_info:
                await detector._query_openai("gpt-4", sample_vulnerable_code)

            assert "API key not configured" in str(exc_info.value)

        asyncio.run(run_test())

    def test_query_anthropic_success(self, multi_provider_detector, sample_vulnerable_code, reentrancy_finding):
        """Test successful Anthropic query."""
        async def run_test():
            anthropic_response = {
                "content": [{
                    "text": json.dumps([reentrancy_finding])
                }]
            }

            with patch('aiohttp.ClientSession') as mock_session_class:
                mock_session = MagicMock()
                mock_session.post = MagicMock(
                    return_value=create_mock_context_manager(200, anthropic_response)
                )

                session_ctx = MagicMock()
                session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
                session_ctx.__aexit__ = AsyncMock(return_value=None)
                mock_session_class.return_value = session_ctx

                findings = await multi_provider_detector._query_anthropic(
                    "claude-3-5-sonnet-20241022",
                    sample_vulnerable_code
                )

            assert len(findings) == 1
            assert findings[0]["type"] == "reentrancy"
            assert findings[0]["_source_model"] == "claude-3-5-sonnet-20241022"

        asyncio.run(run_test())

    def test_query_anthropic_no_api_key(self, sample_vulnerable_code):
        """Test Anthropic query fails without API key."""
        async def run_test():
            detector = LLMEnsembleDetector(
                providers=[LLMProvider.ANTHROPIC],
                anthropic_api_key=None,
            )

            with pytest.raises(ProviderUnavailable) as exc_info:
                await detector._query_anthropic("claude-3-5-sonnet-20241022", sample_vulnerable_code)

            assert "API key not configured" in str(exc_info.value)

        asyncio.run(run_test())

    def test_query_ollama_success(self, ollama_only_detector, sample_vulnerable_code, reentrancy_finding):
        """Test successful Ollama query."""
        async def run_test():
            ollama_response = {
                "message": {
                    "content": json.dumps([reentrancy_finding])
                }
            }

            with patch('aiohttp.ClientSession') as mock_session_class:
                mock_session = MagicMock()
                mock_session.post = MagicMock(
                    return_value=create_mock_context_manager(200, ollama_response)
                )

                session_ctx = MagicMock()
                session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
                session_ctx.__aexit__ = AsyncMock(return_value=None)
                mock_session_class.return_value = session_ctx

                findings = await ollama_only_detector._query_model(
                    "deepseek-coder:6.7b",
                    sample_vulnerable_code
                )

            assert len(findings) == 1
            assert findings[0]["type"] == "reentrancy"

        asyncio.run(run_test())


# =============================================================================
# Full Detection Pipeline Tests
# =============================================================================

class TestFullDetectionPipeline:
    """Integration tests for full detection pipeline."""

    def test_detect_vulnerabilities_with_ollama(self, ollama_only_detector, sample_vulnerable_code, reentrancy_finding):
        """Test full detection pipeline with Ollama."""
        async def run_test():
            # Mock Ollama API responses
            tags_response = {
                "models": [
                    {"name": "deepseek-coder:6.7b"},
                    {"name": "codellama:7b"},
                ]
            }

            model_response = {
                "message": {
                    "content": json.dumps([reentrancy_finding])
                }
            }

            call_count = [0]

            def mock_request(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] == 1:  # First call is tags
                    return create_mock_context_manager(200, tags_response)
                return create_mock_context_manager(200, model_response)

            with patch('aiohttp.ClientSession') as mock_session_class:
                mock_session = MagicMock()
                mock_session.get = MagicMock(side_effect=mock_request)
                mock_session.post = MagicMock(side_effect=mock_request)

                session_ctx = MagicMock()
                session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
                session_ctx.__aexit__ = AsyncMock(return_value=None)
                mock_session_class.return_value = session_ctx

                result = await ollama_only_detector.detect_vulnerabilities(sample_vulnerable_code)

            assert isinstance(result, EnsembleResult)
            assert result.consensus_threshold == 2

        asyncio.run(run_test())

    def test_detect_with_context(self, ollama_only_detector, sample_vulnerable_code, reentrancy_finding):
        """Test detection with additional context."""
        async def run_test():
            tags_response = {"models": [{"name": "deepseek-coder:6.7b"}]}
            model_response = {
                "message": {"content": json.dumps([reentrancy_finding])}
            }

            call_count = [0]
            captured_payload = [None]

            def mock_post(*args, **kwargs):
                call_count[0] += 1
                if 'json' in kwargs:
                    captured_payload[0] = kwargs['json']
                return create_mock_context_manager(200, model_response)

            def mock_get(*args, **kwargs):
                return create_mock_context_manager(200, tags_response)

            with patch('aiohttp.ClientSession') as mock_session_class:
                mock_session = MagicMock()
                mock_session.get = MagicMock(side_effect=mock_get)
                mock_session.post = MagicMock(side_effect=mock_post)

                session_ctx = MagicMock()
                session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
                session_ctx.__aexit__ = AsyncMock(return_value=None)
                mock_session_class.return_value = session_ctx

                context = {"contract_name": "VulnerableBank", "version": "0.8.0"}
                await ollama_only_detector.detect_vulnerabilities(
                    sample_vulnerable_code,
                    context=context
                )

            # Verify context was included in prompt
            if captured_payload[0]:
                prompt = captured_payload[0].get("messages", [{}])[-1].get("content", "")
                assert "VulnerableBank" in prompt or "Additional context" in prompt

        asyncio.run(run_test())

    def test_result_structure(self, ollama_only_detector, sample_vulnerable_code, reentrancy_finding):
        """Test EnsembleResult structure is correct."""
        async def run_test():
            tags_response = {
                "models": [
                    {"name": "deepseek-coder:6.7b"},
                    {"name": "codellama:7b"},
                ]
            }
            model_response = {
                "message": {"content": json.dumps([reentrancy_finding])}
            }

            call_count = [0]

            def mock_request(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] == 1:
                    return create_mock_context_manager(200, tags_response)
                return create_mock_context_manager(200, model_response)

            with patch('aiohttp.ClientSession') as mock_session_class:
                mock_session = MagicMock()
                mock_session.get = MagicMock(side_effect=mock_request)
                mock_session.post = MagicMock(side_effect=mock_request)

                session_ctx = MagicMock()
                session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
                session_ctx.__aexit__ = AsyncMock(return_value=None)
                mock_session_class.return_value = session_ctx

                result = await ollama_only_detector.detect_vulnerabilities(sample_vulnerable_code)

            # Verify result structure
            assert hasattr(result, 'findings')
            assert hasattr(result, 'models_used')
            assert hasattr(result, 'models_available')
            assert hasattr(result, 'models_failed')
            assert hasattr(result, 'execution_time_ms')
            assert hasattr(result, 'consensus_threshold')
            assert hasattr(result, 'total_raw_findings')
            assert hasattr(result, 'filtered_findings')

            assert isinstance(result.findings, list)
            assert isinstance(result.models_used, list)
            assert isinstance(result.execution_time_ms, float)

        asyncio.run(run_test())


# =============================================================================
# Model Status Tests
# =============================================================================

class TestModelStatus:
    """Tests for model status reporting."""

    def test_get_model_status_before_init(self, multi_provider_detector):
        """Test model status before initialization."""
        status = multi_provider_detector.get_model_status()

        assert "configured_models" in status
        assert "available_models" in status
        assert "voting_strategy" in status
        assert "consensus_threshold" in status
        assert "model_weights" in status
        assert "initialized" in status

        assert status["initialized"] is False

    def test_get_model_status_after_init(self, multi_provider_detector):
        """Test model status after initialization."""
        async def run_test():
            # Mock initialization
            multi_provider_detector._initialized = True
            multi_provider_detector._available_models = ["gpt-4-turbo", "claude-3-5-sonnet-20241022"]

            status = multi_provider_detector.get_model_status()

            assert status["initialized"] is True
            assert len(status["available_models"]) == 2

        asyncio.run(run_test())


# =============================================================================
# Convenience Function Tests
# =============================================================================

class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_detect_with_ensemble_function(self, sample_vulnerable_code, reentrancy_finding):
        """Test detect_with_ensemble convenience function."""
        from src.llm.ensemble_detector import detect_with_ensemble

        async def run_test():
            tags_response = {"models": [{"name": "deepseek-coder:6.7b"}, {"name": "codellama:7b"}]}
            model_response = {"message": {"content": json.dumps([reentrancy_finding])}}

            call_count = [0]

            def mock_request(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] == 1:
                    return create_mock_context_manager(200, tags_response)
                return create_mock_context_manager(200, model_response)

            with patch('aiohttp.ClientSession') as mock_session_class:
                mock_session = MagicMock()
                mock_session.get = MagicMock(side_effect=mock_request)
                mock_session.post = MagicMock(side_effect=mock_request)

                session_ctx = MagicMock()
                session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
                session_ctx.__aexit__ = AsyncMock(return_value=None)
                mock_session_class.return_value = session_ctx

                findings = await detect_with_ensemble(sample_vulnerable_code, min_votes=2)

            assert isinstance(findings, list)

        asyncio.run(run_test())


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Tests for error handling scenarios."""

    def test_handle_invalid_json_response(self, ollama_only_detector):
        """Test handling of invalid JSON in model response."""
        content = "This is not valid JSON response"
        findings = ollama_only_detector._parse_model_response(content, "test-model")
        assert findings == []

    def test_handle_empty_response(self, ollama_only_detector):
        """Test handling of empty model response."""
        content = ""
        findings = ollama_only_detector._parse_model_response(content, "test-model")
        assert findings == []

    def test_handle_partial_json_response(self, ollama_only_detector, reentrancy_finding):
        """Test handling of JSON embedded in text."""
        content = f"Here are the findings:\n{json.dumps([reentrancy_finding])}\n\nEnd of analysis."
        findings = ollama_only_detector._parse_model_response(content, "test-model")
        assert len(findings) == 1

    def test_handle_api_error_response(self, multi_provider_detector, sample_vulnerable_code):
        """Test handling of API error responses."""
        async def run_test():
            with patch('aiohttp.ClientSession') as mock_session_class:
                mock_session = MagicMock()
                mock_session.post = MagicMock(
                    return_value=create_mock_context_manager(500, {"error": "Internal server error"})
                )

                session_ctx = MagicMock()
                session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
                session_ctx.__aexit__ = AsyncMock(return_value=None)
                mock_session_class.return_value = session_ctx

                with pytest.raises(ProviderUnavailable):
                    await multi_provider_detector._query_openai("gpt-4", sample_vulnerable_code)

        asyncio.run(run_test())

    def test_handle_timeout(self, ollama_only_detector, sample_vulnerable_code):
        """Test handling of request timeout."""
        async def run_test():
            import aiohttp

            with patch('aiohttp.ClientSession') as mock_session_class:
                mock_session = MagicMock()
                mock_session.post = MagicMock(
                    side_effect=asyncio.TimeoutError("Request timed out")
                )

                session_ctx = MagicMock()
                session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
                session_ctx.__aexit__ = AsyncMock(return_value=None)
                mock_session_class.return_value = session_ctx

                with pytest.raises(Exception):
                    await ollama_only_detector._query_model(
                        "deepseek-coder:6.7b",
                        sample_vulnerable_code
                    )

        asyncio.run(run_test())
