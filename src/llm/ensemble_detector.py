"""
LLM Ensemble Detector for MIESC
================================

Ensemble voting with multiple LLMs for vulnerability detection.
Based on LLMBugScanner paper (2024): 60% top-5 detection rate.

Features:
- Multi-model ensemble voting
- Parallel model execution
- Confidence aggregation
- Vulnerability type consensus
- Multi-provider support (Ollama, OpenAI, Anthropic) (v4.4.0)

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Institution: UNDEF - IUA
Date: January 2026
"""

import asyncio
import hashlib
import json
import logging
import math
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import aiohttp

from src.llm.provider_health import fetch_openai_compatible_model_ids
from src.security.llm_output_validator import repair_common_json_errors

logger = logging.getLogger(__name__)

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

ENSEMBLE_RUNTIME_ERRORS = (
    aiohttp.ClientError,
    asyncio.TimeoutError,
    TimeoutError,
    OSError,
    RuntimeError,
    ValueError,
    json.JSONDecodeError,
)


class LLMProvider(Enum):
    """Supported LLM providers."""

    OLLAMA = "ollama"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    DEEPSEEK = "deepseek"


class ProviderUnavailable(Exception):
    """Exception raised when a provider is unavailable."""

    pass


class AllProvidersUnavailable(Exception):
    """Exception raised when all providers are unavailable."""

    pass


class VotingStrategy(Enum):
    """Voting strategies for ensemble."""

    MAJORITY = "majority"  # Finding valid if >= 50% models agree
    UNANIMOUS = "unanimous"  # All models must agree
    WEIGHTED = "weighted"  # Weighted by model expertise
    THRESHOLD = "threshold"  # At least N models must agree


@dataclass
class EnsembleFinding:
    """A finding validated by ensemble voting."""

    type: str
    severity: str
    title: str
    description: str
    location: Dict[str, Any]
    confidence: float
    votes: int
    total_models: int
    supporting_models: List[str]
    attack_vector: Optional[str] = None
    remediation: Optional[str] = None
    swc_id: Optional[str] = None
    cwe_id: Optional[str] = None
    raw_responses: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EnsembleResult:
    """Result from ensemble detection."""

    findings: List[EnsembleFinding]
    models_used: List[str]
    models_available: List[str]
    models_failed: List[str]
    execution_time_ms: float
    consensus_threshold: int
    total_raw_findings: int
    filtered_findings: int


class LLMEnsembleDetector:
    """
    Ensemble of LLMs for vulnerability detection.

    Uses multiple models with voting to improve detection accuracy
    and reduce false positives through consensus.

    Supported providers (v4.4.0):
    - Ollama: deepseek-coder:6.7b, codellama:7b, llama3.1:8b
    - OpenAI: gpt-4-turbo, gpt-4o, gpt-3.5-turbo
    - Anthropic: claude-3-5-sonnet-20241022, claude-3-haiku-20240307
    - DeepSeek: deepseek-v4-flash, deepseek-v4-pro

    Voting: A finding is valid if >= 2 models independently identify it.
    """

    # Provider-specific model configurations (v4.4.0)
    PROVIDER_MODELS = {
        LLMProvider.OLLAMA: [
            "deepseek-coder:6.7b",  # Primary - best for code
            "codellama:7b",  # Secondary - code specialist
            "llama3.1:8b",  # Tertiary - general reasoning
        ],
        LLMProvider.OPENAI: [
            "gpt-4-turbo",  # Best for complex analysis
            "gpt-4o",  # Fast and capable
            "gpt-3.5-turbo",  # Fallback
        ],
        LLMProvider.ANTHROPIC: [
            "claude-3-5-sonnet-20241022",  # Best for code analysis
            "claude-3-haiku-20240307",  # Fast and efficient
        ],
        LLMProvider.DEEPSEEK: [
            "deepseek-v4-flash",  # Fast/cost-efficient code reasoning
            "deepseek-v4-pro",  # Higher capability fallback
        ],
    }

    # Default models for ensemble (ordered by priority)
    DEFAULT_MODELS = [
        "deepseek-coder:6.7b",  # Primary - best for code
        "codellama:7b",  # Secondary - code specialist
        "llama3.1:8b",  # Tertiary - general reasoning
    ]
    DEFAULT_TIMEOUT = 120
    DEFAULT_TEMPERATURE = 0.1
    MAX_TEMPERATURE = 2.0
    MAX_MODEL_LABEL_LENGTH = 200
    VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})

    # Model weights based on code analysis expertise
    MODEL_WEIGHTS = {
        # Ollama models
        "deepseek-coder:6.7b": 1.3,
        "deepseek-coder:1.3b": 1.0,
        "codellama:7b": 1.2,
        "codellama:13b": 1.3,
        "llama3.1:8b": 1.0,
        "llama3:8b": 0.9,
        "mistral:7b": 0.8,
        # OpenAI models (v4.4.0)
        "gpt-4-turbo": 1.4,
        "gpt-4o": 1.35,
        "gpt-4": 1.3,
        "gpt-3.5-turbo": 1.0,
        # Anthropic models (v4.4.0)
        "claude-3-5-sonnet-20241022": 1.4,
        "claude-3-opus-20240229": 1.5,
        "claude-3-haiku-20240307": 1.1,
        # DeepSeek API models
        "deepseek-v4-flash": 1.25,
        "deepseek-v4-pro": 1.35,
    }

    # Vulnerability detection prompt
    DETECTION_PROMPT = """You are an expert Solidity smart contract security auditor.
Analyze the following smart contract code for security vulnerabilities.

IMPORTANT: Only report vulnerabilities you are CONFIDENT about. Do not guess.

For each vulnerability found, provide:
1. Type (reentrancy, access-control, arithmetic, unchecked-call, etc.)
2. Severity (critical, high, medium, low, info)
3. Title (brief description)
4. Description (detailed explanation)
5. Location (function name, approximate line)
6. Attack vector (how it can be exploited)
7. Remediation (how to fix it)
8. Confidence (0.0-1.0)

Respond with a JSON array of findings. If no vulnerabilities found, return [].

Code to analyze:
```solidity
{code}
```

Response (JSON array only):"""

    def __init__(
        self,
        models: Optional[List[str]] = None,
        ollama_base_url: str = "http://localhost:11434",
        voting_strategy: VotingStrategy = VotingStrategy.THRESHOLD,
        consensus_threshold: int = 2,
        timeout: int = 120,
        temperature: float = 0.1,
        providers: Optional[List[LLMProvider]] = None,
        openai_api_key: Optional[str] = None,
        anthropic_api_key: Optional[str] = None,
        deepseek_api_key: Optional[str] = None,
        deepseek_base_url: Optional[str] = None,
    ):
        """
        Initialize the ensemble detector.

        Args:
            models: List of model names to use (default: DEFAULT_MODELS)
            ollama_base_url: Ollama API base URL
            voting_strategy: How to aggregate model votes
            consensus_threshold: Minimum votes for THRESHOLD strategy
            timeout: Request timeout in seconds
            temperature: LLM temperature (lower = more deterministic)
            providers: List of providers to use (default: [OLLAMA])
            openai_api_key: OpenAI API key (or from OPENAI_API_KEY env)
            anthropic_api_key: Anthropic API key (or from ANTHROPIC_API_KEY env)
            deepseek_api_key: DeepSeek API key (or from DEEPSEEK_API_KEY env)
            deepseek_base_url: DeepSeek API base URL
        """
        self.models = self._normalize_configured_models(models)
        self.base_url = ollama_base_url
        self.voting_strategy = self._normalize_voting_strategy(voting_strategy)
        self.consensus_threshold = self._normalize_consensus_threshold(consensus_threshold)
        self.timeout = self._normalize_timeout(timeout)
        self.temperature = self._normalize_temperature(temperature)

        # Multi-provider support (v4.4.0)
        self.providers = self._normalize_providers(providers)
        self.openai_api_key = self._normalize_api_key(openai_api_key, "OPENAI_API_KEY")
        self.anthropic_api_key = self._normalize_api_key(
            anthropic_api_key, "ANTHROPIC_API_KEY"
        )
        self.deepseek_api_key = self._normalize_api_key(deepseek_api_key, "DEEPSEEK_API_KEY")
        self.deepseek_base_url = (
            deepseek_base_url or os.environ.get("DEEPSEEK_BASE_URL") or "https://api.deepseek.com"
        )

        self._available_models: List[str] = []
        self._available_providers: Dict[LLMProvider, List[str]] = {}
        self._initialized = False

        logger.info(
            f"LLMEnsembleDetector initialized with {len(self.models)} models, "
            f"providers={[p.value for p in self.providers]}, "
            f"strategy={self.voting_strategy.value}, threshold={self.consensus_threshold}"
        )

    @classmethod
    def _normalize_configured_models(cls, models: Any) -> List[str]:
        """Return configured model ids without treating malformed containers as models."""
        if models is None:
            return list(cls.DEFAULT_MODELS)

        if not isinstance(models, (list, tuple, set)):
            logger.warning("Ignoring malformed ensemble model list; using defaults")
            return list(cls.DEFAULT_MODELS)

        normalized = [model.strip() for model in models if isinstance(model, str) and model.strip()]
        if not normalized:
            logger.warning("No valid ensemble model names configured; using defaults")
            return list(cls.DEFAULT_MODELS)

        return normalized

    @staticmethod
    def _normalize_consensus_threshold(consensus_threshold: Any) -> int:
        """Return a positive integer threshold for vote comparisons."""
        if isinstance(consensus_threshold, bool):
            logger.warning("Ignoring malformed ensemble consensus threshold; using default")
            return 2

        try:
            threshold = int(consensus_threshold)
        except (TypeError, ValueError):
            logger.warning("Ignoring malformed ensemble consensus threshold; using default")
            return 2

        return max(1, threshold)

    @classmethod
    def _normalize_timeout(cls, timeout: Any) -> int:
        """Return a positive finite request timeout in seconds."""
        if isinstance(timeout, bool):
            logger.warning("Ignoring malformed ensemble timeout; using default")
            return cls.DEFAULT_TIMEOUT

        try:
            normalized_timeout = float(timeout)
        except (TypeError, ValueError):
            logger.warning("Ignoring malformed ensemble timeout; using default")
            return cls.DEFAULT_TIMEOUT

        if not math.isfinite(normalized_timeout):
            logger.warning("Ignoring malformed ensemble timeout; using default")
            return cls.DEFAULT_TIMEOUT

        return max(1, int(normalized_timeout))

    @classmethod
    def _normalize_temperature(cls, temperature: Any) -> float:
        """Return a finite LLM temperature bounded to provider-safe values."""
        if isinstance(temperature, bool):
            logger.warning("Ignoring malformed ensemble temperature; using default")
            return cls.DEFAULT_TEMPERATURE

        try:
            normalized_temperature = float(temperature)
        except (TypeError, ValueError):
            logger.warning("Ignoring malformed ensemble temperature; using default")
            return cls.DEFAULT_TEMPERATURE

        if not math.isfinite(normalized_temperature):
            logger.warning("Ignoring malformed ensemble temperature; using default")
            return cls.DEFAULT_TEMPERATURE

        return min(cls.MAX_TEMPERATURE, max(0.0, normalized_temperature))

    @staticmethod
    def _normalize_api_key(api_key: Any, env_name: str) -> Optional[str]:
        """Return a non-empty API key string from config or environment."""
        if isinstance(api_key, str):
            normalized = api_key.strip()
            if normalized:
                return normalized
        elif api_key is not None:
            logger.warning("Ignoring malformed ensemble API key for %s", env_name)

        env_value = os.environ.get(env_name)
        if not isinstance(env_value, str):
            return None

        normalized_env_value = env_value.strip()
        return normalized_env_value or None

    @staticmethod
    def _normalize_voting_strategy(voting_strategy: Any) -> VotingStrategy:
        """Return a supported voting strategy without trusting enum-like inputs."""
        if isinstance(voting_strategy, VotingStrategy):
            return voting_strategy

        if isinstance(voting_strategy, str):
            try:
                return VotingStrategy(voting_strategy.strip().lower())
            except ValueError:
                pass

        logger.warning("Ignoring malformed ensemble voting strategy; using threshold")
        return VotingStrategy.THRESHOLD

    @staticmethod
    def _normalize_providers(providers: Any) -> List[LLMProvider]:
        """Return configured providers while filtering malformed provider entries."""
        if providers is None:
            return [LLMProvider.OLLAMA]

        if not isinstance(providers, (list, tuple, set)):
            logger.warning("Ignoring malformed ensemble provider list; using Ollama")
            return [LLMProvider.OLLAMA]

        normalized: List[LLMProvider] = []
        for provider in providers:
            if isinstance(provider, LLMProvider):
                normalized_provider = provider
            elif isinstance(provider, str):
                try:
                    normalized_provider = LLMProvider(provider.strip().lower())
                except ValueError:
                    logger.warning("Ignoring unknown ensemble provider: %r", provider)
                    continue
            else:
                logger.warning("Ignoring malformed ensemble provider entry: %r", provider)
                continue

            if normalized_provider not in normalized:
                normalized.append(normalized_provider)

        if not normalized:
            logger.warning("No valid ensemble providers configured; using Ollama")
            return [LLMProvider.OLLAMA]

        return normalized

    @staticmethod
    def _extract_availability_model_ids(data: Any, list_key: str, id_key: str) -> List[str]:
        """Return string model ids from provider availability payloads."""
        if not isinstance(data, dict):
            logger.warning("Ignoring malformed provider model availability payload")
            return []

        models = data.get(list_key, [])
        if not isinstance(models, list):
            logger.warning("Ignoring malformed provider model availability list")
            return []

        model_ids = []
        for model in models:
            if not isinstance(model, dict):
                logger.warning("Ignoring malformed provider model availability entry: %r", model)
                continue

            model_id = model.get(id_key)
            if isinstance(model_id, str) and model_id.strip():
                model_ids.append(model_id.strip())
            else:
                logger.warning("Ignoring malformed provider model id: %r", model_id)

        return model_ids

    @staticmethod
    def _normalize_remote_model_ids(model_ids: Any) -> set[str]:
        """Return string model ids from a provider-health model id result."""
        if not isinstance(model_ids, (list, tuple, set)):
            logger.warning("Ignoring malformed provider remote model id list")
            return set()

        return {model_id.strip() for model_id in model_ids if isinstance(model_id, str) and model_id.strip()}

    async def initialize(self) -> Dict[str, bool]:
        """
        Initialize detector and check model availability across all providers.

        Returns:
            Dict mapping model name to availability status
        """
        status = {}
        self._available_models = []
        self._available_providers = {}

        # Check each provider
        for provider in self.providers:
            provider_models = await self._check_provider_availability(provider)
            self._available_providers[provider] = provider_models

            for model in provider_models:
                status[f"{provider.value}:{model}"] = True
                if model not in self._available_models:
                    self._available_models.append(model)

        # Also check explicitly configured models with Ollama
        if LLMProvider.OLLAMA in self.providers:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"{self.base_url}/api/tags", timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            installed_models = self._extract_availability_model_ids(
                                data, "models", "name"
                            )

                            for model in self.models:
                                # Check exact match or prefix match
                                available = model in installed_models or any(
                                    m.startswith(model.split(":")[0]) for m in installed_models
                                )
                                status[model] = available
                                if available and model not in self._available_models:
                                    self._available_models.append(model)
            except ENSEMBLE_RUNTIME_ERRORS as e:
                logger.warning(f"Failed to check Ollama models: {e}")

        self._initialized = True
        total_available = len(self._available_models)
        logger.info(
            f"Ensemble detector: {total_available} models available across "
            f"{len([p for p, m in self._available_providers.items() if m])} providers"
        )
        return status

    async def _check_provider_availability(self, provider: LLMProvider) -> List[str]:
        """
        Check availability of models for a specific provider.

        Args:
            provider: The LLM provider to check

        Returns:
            List of available model names for this provider
        """
        available = []

        if provider == LLMProvider.OLLAMA:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"{self.base_url}/api/tags", timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            available = self._extract_availability_model_ids(
                                data, "models", "name"
                            )
            except ENSEMBLE_RUNTIME_ERRORS as e:
                logger.debug(f"Ollama not available: {e}")

        elif provider == LLMProvider.OPENAI:
            if self.openai_api_key:
                # OpenAI models are available if API key is set
                available = self.PROVIDER_MODELS[LLMProvider.OPENAI]
                logger.debug(f"OpenAI available with {len(available)} models")
            else:
                logger.debug("OpenAI not available: no API key")

        elif provider == LLMProvider.ANTHROPIC:
            if self.anthropic_api_key:
                # Anthropic models are available if API key is set
                available = self.PROVIDER_MODELS[LLMProvider.ANTHROPIC]
                logger.debug(f"Anthropic available with {len(available)} models")
            else:
                logger.debug("Anthropic not available: no API key")

        elif provider == LLMProvider.DEEPSEEK:
            if not self.deepseek_api_key:
                logger.debug("DeepSeek not available: no API key")
                return available

            remote_models = await fetch_openai_compatible_model_ids(
                self.deepseek_base_url,
                self.deepseek_api_key,
                provider_name="DeepSeek",
            )
            remote_model_ids = self._normalize_remote_model_ids(remote_models)
            configured = self.PROVIDER_MODELS[LLMProvider.DEEPSEEK]
            available = [model for model in configured if model in remote_model_ids]
            logger.debug("DeepSeek available with %s configured models", len(available))

        return available

    async def detect_with_fallback(
        self,
        code: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[EnsembleFinding]:
        """
        Detect vulnerabilities with provider fallback.

        Tries providers in order until one succeeds.

        Args:
            code: Solidity source code to analyze
            context: Optional additional context

        Returns:
            List of validated findings

        Raises:
            AllProvidersUnavailable: If no providers can process the request
        """
        if not self._initialized:
            await self.initialize()

        last_error: Optional[BaseException] = None

        for provider in self.providers:
            if provider not in self._available_providers:
                continue

            provider_models = self._available_providers.get(provider, [])
            if not provider_models:
                continue

            try:
                logger.info(f"Trying provider: {provider.value}")
                result = await self._detect_with_provider(provider, code, context)
                return result
            except ProviderUnavailable as e:
                logger.warning(f"Provider {provider.value} unavailable: {e}")
                last_error = e
                continue
            except ENSEMBLE_RUNTIME_ERRORS as e:
                logger.warning(f"Provider {provider.value} failed: {e}")
                last_error = e
                continue

        raise AllProvidersUnavailable(f"All providers failed. Last error: {last_error}")

    async def _detect_with_provider(
        self,
        provider: LLMProvider,
        code: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[EnsembleFinding]:
        """
        Run detection with a specific provider.

        Args:
            provider: The LLM provider to use
            code: Solidity source code
            context: Optional context

        Returns:
            List of findings from this provider
        """
        models = self._status_model_list(self._available_providers.get(provider, []))[:3]

        if not models:
            raise ProviderUnavailable(f"No models available for {provider.value}")

        tasks = []
        for model in models:
            if provider == LLMProvider.OLLAMA:
                tasks.append(self._query_model(model, code, context))
            elif provider == LLMProvider.OPENAI:
                tasks.append(self._query_openai(model, code, context))
            elif provider == LLMProvider.ANTHROPIC:
                tasks.append(self._query_anthropic(model, code, context))
            elif provider == LLMProvider.DEEPSEEK:
                tasks.append(self._query_deepseek(model, code, context))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        model_findings: Dict[str, List[Dict]] = {}

        for model, result in zip(models, results, strict=False):
            if isinstance(result, BaseException):
                logger.warning(f"Model {model} failed: {result}")
            else:
                model_findings[model] = result

        model_findings = self._normalize_model_findings(model_findings)

        if not model_findings:
            raise ProviderUnavailable(f"All models failed for {provider.value}")

        return self._ensemble_vote(model_findings)

    async def _query_openai(
        self,
        model: str,
        code: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Query OpenAI API for vulnerabilities.

        Args:
            model: OpenAI model name
            code: Solidity code
            context: Optional context

        Returns:
            List of findings from this model
        """
        if not self.openai_api_key:
            raise ProviderUnavailable("OpenAI API key not configured")

        prompt = self.DETECTION_PROMPT.format(code=code)
        if context:
            prompt += f"\n\nAdditional context:\n{json.dumps(context, indent=2, sort_keys=True)}"

        headers = {
            "Authorization": f"Bearer {self.openai_api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are an expert smart contract security auditor. Respond only with valid JSON.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": self.temperature,
            "max_tokens": 4096,
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.openai.com/v1/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if resp.status != 200:
                        error_text = await resp.text()
                        raise ProviderUnavailable(f"OpenAI error: {error_text}")

                    data = await resp.json()
                    self._validate_optional_response_metadata(data, "OpenAI")
                    content = self._extract_openai_compatible_content(data, "OpenAI")

                    return self._parse_model_response(content, model)

        except aiohttp.ClientError as e:
            raise ProviderUnavailable(f"OpenAI connection error: {e}") from e

    async def _query_deepseek(
        self,
        model: str,
        code: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Query DeepSeek API for vulnerabilities.

        DeepSeek exposes an OpenAI-compatible chat completions endpoint.
        """
        if not self.deepseek_api_key:
            raise ProviderUnavailable("DeepSeek API key not configured")

        prompt = self.DETECTION_PROMPT.format(code=code)
        if context:
            prompt += f"\n\nAdditional context:\n{json.dumps(context, indent=2, sort_keys=True)}"

        headers = {
            "Authorization": f"Bearer {self.deepseek_api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are an expert smart contract security auditor. Respond only with valid JSON.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": self.temperature,
            "max_tokens": 4096,
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.deepseek_base_url.rstrip('/')}/v1/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if resp.status != 200:
                        error_text = await resp.text()
                        raise ProviderUnavailable(f"DeepSeek error: {error_text}")

                    data = await resp.json()
                    self._validate_optional_response_metadata(data, "DeepSeek")
                    content = self._extract_openai_compatible_content(data, "DeepSeek")

                    return self._parse_model_response(content, model)

        except aiohttp.ClientError as e:
            raise ProviderUnavailable(f"DeepSeek connection error: {e}") from e

    @staticmethod
    def _extract_openai_compatible_content(data: Any, provider_name: str) -> str:
        """Extract chat content from OpenAI-compatible response payloads."""
        if not isinstance(data, dict):
            raise ProviderUnavailable(f"{provider_name} response payload is malformed")

        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ProviderUnavailable(f"{provider_name} response choices are malformed")

        first_choice = choices[0]
        if not isinstance(first_choice, dict):
            raise ProviderUnavailable(f"{provider_name} response choice is malformed")

        message = first_choice.get("message")
        if not isinstance(message, dict):
            raise ProviderUnavailable(f"{provider_name} response message is malformed")

        content = message.get("content")
        if not isinstance(content, str):
            raise ProviderUnavailable(f"{provider_name} response content is malformed")

        return content

    @classmethod
    def _validate_optional_response_metadata(cls, data: Any, provider_name: str) -> None:
        """Reject malformed optional latency/token metadata on provider responses."""
        if not isinstance(data, dict):
            raise ProviderUnavailable(f"{provider_name} response payload is malformed")

        usage = data.get("usage")
        if usage is not None:
            if not isinstance(usage, dict):
                raise ProviderUnavailable(f"{provider_name} response usage is malformed")
            for key in (
                "prompt_tokens",
                "completion_tokens",
                "total_tokens",
                "input_tokens",
                "output_tokens",
            ):
                if key in usage and not cls._is_nonnegative_finite_scalar(usage[key]):
                    raise ProviderUnavailable(f"{provider_name} response token metadata is malformed")

        for key in (
            "total_duration",
            "load_duration",
            "prompt_eval_duration",
            "eval_duration",
        ):
            if key in data and not cls._is_nonnegative_finite_scalar(data[key]):
                raise ProviderUnavailable(f"{provider_name} response latency metadata is malformed")

        for key in ("prompt_eval_count", "eval_count"):
            if key in data and not cls._is_nonnegative_finite_scalar(data[key]):
                raise ProviderUnavailable(f"{provider_name} response token metadata is malformed")

    @staticmethod
    def _extract_anthropic_content(data: Any) -> str:
        """Extract the first text block from an Anthropic messages response."""
        if not isinstance(data, dict):
            raise ProviderUnavailable("Anthropic response payload is malformed")

        content_blocks = data.get("content")
        if not isinstance(content_blocks, list) or not content_blocks:
            raise ProviderUnavailable("Anthropic response content is malformed")

        for block in content_blocks:
            if not isinstance(block, dict):
                continue
            if block.get("type", "text") != "text":
                continue
            text = block.get("text")
            if isinstance(text, str):
                return text

        raise ProviderUnavailable("Anthropic response text is malformed")

    @staticmethod
    def _extract_ollama_content(data: Any) -> str:
        """Extract chat content from an Ollama response payload."""
        if not isinstance(data, dict):
            raise ProviderUnavailable("Ollama response payload is malformed")

        message = data.get("message")
        if not isinstance(message, dict):
            raise ProviderUnavailable("Ollama response message is malformed")

        content = message.get("content")
        if not isinstance(content, str):
            raise ProviderUnavailable("Ollama response content is malformed")

        return content

    async def _query_anthropic(
        self,
        model: str,
        code: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Query Anthropic API for vulnerabilities.

        Args:
            model: Anthropic model name
            code: Solidity code
            context: Optional context

        Returns:
            List of findings from this model
        """
        if not self.anthropic_api_key:
            raise ProviderUnavailable("Anthropic API key not configured")

        prompt = self.DETECTION_PROMPT.format(code=code)
        if context:
            prompt += f"\n\nAdditional context:\n{json.dumps(context, indent=2, sort_keys=True)}"

        headers = {
            "x-api-key": self.anthropic_api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }

        payload = {
            "model": model,
            "max_tokens": 4096,
            "system": "You are an expert smart contract security auditor. Respond only with valid JSON.",
            "messages": [{"role": "user", "content": prompt}],
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.anthropic.com/v1/messages",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if resp.status != 200:
                        error_text = await resp.text()
                        raise ProviderUnavailable(f"Anthropic error: {error_text}")

                    data = await resp.json()
                    self._validate_optional_response_metadata(data, "Anthropic")
                    content = self._extract_anthropic_content(data)

                    return self._parse_model_response(content, model)

        except aiohttp.ClientError as e:
            raise ProviderUnavailable(f"Anthropic connection error: {e}") from e

    async def detect_vulnerabilities(
        self,
        code: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> EnsembleResult:
        """
        Execute vulnerability detection with ensemble voting.

        Args:
            code: Solidity source code to analyze
            context: Optional additional context

        Returns:
            EnsembleResult with validated findings
        """
        import time

        start_time = time.time()

        if not self._initialized:
            await self.initialize()

        available_models = self._status_model_list(self._available_models)

        if not available_models:
            logger.error("No LLM models available for ensemble detection")
            return EnsembleResult(
                findings=[],
                models_used=[],
                models_available=[],
                models_failed=self.models,
                execution_time_ms=0,
                consensus_threshold=self.consensus_threshold,
                total_raw_findings=0,
                filtered_findings=0,
            )

        # Query all available models in parallel
        tasks = [self._query_model(model, code, context) for model in available_models]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        model_findings: Dict[str, List[Dict]] = {}
        failed_models: List[str] = []

        for model, result in zip(available_models, results, strict=False):
            if isinstance(result, BaseException):
                logger.warning(f"Model {model} failed: {result}")
                failed_models.append(model)
            else:
                model_findings[model] = result

        model_findings = self._normalize_model_findings(model_findings)

        # Aggregate with voting
        validated_findings = self._ensemble_vote(model_findings)

        execution_time = (time.time() - start_time) * 1000

        # Calculate statistics
        total_raw = sum(len(f) for f in model_findings.values())

        logger.info(
            f"Ensemble detection complete: {len(validated_findings)} findings "
            f"from {total_raw} raw ({len(model_findings)} models)"
        )

        return EnsembleResult(
            findings=validated_findings,
            models_used=list(model_findings.keys()),
            models_available=available_models,
            models_failed=failed_models,
            execution_time_ms=execution_time,
            consensus_threshold=self.consensus_threshold,
            total_raw_findings=total_raw,
            filtered_findings=total_raw - len(validated_findings),
        )

    async def _query_model(
        self,
        model: str,
        code: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Query a single model for vulnerabilities.

        Args:
            model: Model name
            code: Solidity code
            context: Optional context

        Returns:
            List of findings from this model
        """
        prompt = self.DETECTION_PROMPT.format(code=code)

        if context:
            prompt += f"\n\nAdditional context:\n{json.dumps(context, indent=2, sort_keys=True)}"

        payload = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are an expert smart contract security auditor. Respond only with valid JSON.",
                },
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": 4096,
            },
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/api/chat",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if resp.status != 200:
                        raise RuntimeError(f"Ollama error: {await resp.text()}")

                    data = await resp.json()
                    self._validate_optional_response_metadata(data, "Ollama")
                    content = self._extract_ollama_content(data)

                    return self._parse_model_response(content, model)

        except ENSEMBLE_RUNTIME_ERRORS as e:
            logger.warning(f"Model {model} query failed: {e}")
            raise

    def _parse_model_response(self, content: str, model: str) -> List[Dict[str, Any]]:
        """Parse model response into findings list."""
        try:
            # Extract JSON from response
            json_start = content.find("[")
            json_end = content.rfind("]") + 1

            if json_start >= 0 and json_end > json_start:
                json_str = content[json_start:json_end]
                findings = json.loads(repair_common_json_errors(json_str))

                # Normalize findings
                normalized = []
                for f in findings:
                    if isinstance(f, dict) and self._safe_text(f.get("type"), "").strip():
                        # Add source model
                        f["_source_model"] = model
                        normalized.append(f)

                return normalized
            else:
                # Try parsing entire content
                if content.strip().startswith("["):
                    findings = json.loads(repair_common_json_errors(content))
                    for f in findings:
                        if isinstance(f, dict) and self._safe_text(f.get("type"), "").strip():
                            f["_source_model"] = model
                    return [f for f in findings if isinstance(f, dict) and "_source_model" in f]

        except json.JSONDecodeError as e:
            logger.debug(f"JSON parse error for {model}: {e}")

        return []

    def _ensemble_vote(
        self,
        model_findings: Dict[str, List[Dict]],
    ) -> List[EnsembleFinding]:
        """
        Aggregate findings using voting strategy.

        Findings are grouped by type and location, then validated
        based on the voting strategy.
        """
        model_findings = self._normalize_model_findings(model_findings)

        if not model_findings:
            return []

        # Group findings by type + location signature
        finding_groups: Dict[str, Dict[str, Any]] = {}

        for model, findings in model_findings.items():
            for finding in findings:
                # Create signature for grouping similar findings
                signature = self._create_finding_signature(finding)

                if signature not in finding_groups:
                    finding_groups[signature] = {
                        "finding": finding,
                        "votes": [],
                        "confidences": [],
                        "models": [],
                        "raw_responses": {},
                    }

                finding_groups[signature]["votes"].append(self._model_weight(model))
                finding_groups[signature]["confidences"].append(
                    self._safe_confidence(finding.get("confidence"), 0.7)
                )
                finding_groups[signature]["models"].append(model)
                finding_groups[signature]["raw_responses"][model] = (
                    self._safe_raw_response_payload(finding)
                )

        # Apply voting strategy
        validated = []
        total_models = len(model_findings)

        for _signature, group in finding_groups.items():
            votes = len(group["votes"])
            weighted_votes = sum(group["votes"])

            # Check if finding passes voting threshold
            passes = False

            if self.voting_strategy == VotingStrategy.MAJORITY:
                passes = votes > total_models / 2

            elif self.voting_strategy == VotingStrategy.UNANIMOUS:
                passes = votes == total_models

            elif self.voting_strategy == VotingStrategy.THRESHOLD:
                passes = votes >= self.consensus_threshold

            elif self.voting_strategy == VotingStrategy.WEIGHTED:
                # Weighted threshold based on available model weights
                max_possible_weight = sum(
                    self._model_weight(m) for m in model_findings.keys()
                )
                passes = weighted_votes >= max_possible_weight * 0.5

            if passes:
                finding = group["finding"]

                # Calculate aggregated confidence
                base_confidence = self._aggregate_vote_confidence(group["confidences"])
                vote_bonus = min(0.2, votes * 0.05)  # Up to +0.2 for votes
                aggregated_confidence = min(0.99, base_confidence + vote_bonus)
                vuln_type = self._safe_text(finding.get("type"), "unknown")

                validated.append(
                    EnsembleFinding(
                        type=vuln_type,
                        severity=self._safe_severity(finding.get("severity")),
                        title=self._safe_text(finding.get("title"), vuln_type),
                        description=self._safe_text(finding.get("description"), ""),
                        location=self._safe_location(finding.get("location")),
                        confidence=aggregated_confidence,
                        votes=votes,
                        total_models=total_models,
                        supporting_models=group["models"],
                        attack_vector=finding.get("attack_vector"),
                        remediation=finding.get("remediation"),
                        swc_id=finding.get("swc_id") or finding.get("swc"),
                        cwe_id=finding.get("cwe_id") or finding.get("cwe"),
                        raw_responses=group["raw_responses"],
                    )
                )

        # Sort by severity and confidence
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        validated.sort(key=lambda f: (severity_order.get(f.severity, 5), -f.confidence))

        return validated

    @staticmethod
    def _aggregate_vote_confidence(confidences: Any) -> float:
        """Return bounded mean confidence across model votes."""
        if not isinstance(confidences, list) or not confidences:
            return 0.7

        normalized = [
            LLMEnsembleDetector._safe_confidence(confidence, 0.7)
            for confidence in confidences
        ]
        return sum(normalized) / len(normalized)

    @staticmethod
    def _normalize_model_findings(
        model_findings: Dict[str, Any],
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Keep only per-model finding lists and dict finding entries."""
        normalized: Dict[str, List[Dict[str, Any]]] = {}

        for model, findings in model_findings.items():
            model_id = LLMEnsembleDetector._safe_model_label(model)
            if model_id is None:
                logger.warning("Ignoring malformed ensemble model id in findings payload")
                continue
            if not isinstance(findings, list):
                logger.warning("Ignoring malformed findings payload from model %s", model_id)
                continue
            normalized.setdefault(model_id, []).extend(
                finding for finding in findings if isinstance(finding, dict)
            )

        return normalized

    @classmethod
    def _model_weight(cls, model: Any) -> float:
        """Return a finite positive model weight, defaulting malformed entries."""
        if not isinstance(model, str) or not model.strip():
            return 1.0

        weights = cls.MODEL_WEIGHTS
        if not isinstance(weights, dict):
            logger.warning("Ignoring malformed ensemble model weights; using default")
            return 1.0

        weight = weights.get(model.strip(), 1.0)
        if isinstance(weight, bool) or isinstance(weight, (dict, list, tuple, set)):
            logger.warning("Ignoring malformed ensemble model weight for %s", model.strip())
            return 1.0

        try:
            normalized_weight = float(weight)
        except (TypeError, ValueError):
            logger.warning("Ignoring malformed ensemble model weight for %s", model.strip())
            return 1.0

        if not math.isfinite(normalized_weight) or normalized_weight <= 0.0:
            logger.warning("Ignoring malformed ensemble model weight for %s", model.strip())
            return 1.0

        return normalized_weight

    @staticmethod
    def _safe_raw_response_payload(finding: Any) -> Dict[str, Any]:
        """Return a shallow raw response copy with JSON-object-compatible keys."""
        if not isinstance(finding, dict):
            return {}
        payload = {key: value for key, value in finding.items() if isinstance(key, str)}
        if "confidence_explanation" in payload and not isinstance(
            payload["confidence_explanation"], str
        ):
            payload.pop("confidence_explanation")
        return payload

    @staticmethod
    def _safe_float(value: Any, default: float) -> float:
        """Return a float for scalar values without accepting container reprs."""
        if isinstance(value, (dict, list, tuple, set)):
            return default
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _is_nonnegative_finite_scalar(value: Any) -> bool:
        """Return whether response metadata is a finite non-negative scalar."""
        if isinstance(value, bool) or isinstance(value, (dict, list, tuple, set)):
            return False
        try:
            normalized = float(value)
        except (TypeError, ValueError):
            return False
        return math.isfinite(normalized) and normalized >= 0

    @staticmethod
    def _safe_confidence(value: Any, default: float) -> float:
        """Return a finite model confidence bounded to the documented 0.0-1.0 range."""
        if isinstance(value, bool):
            return default
        confidence = LLMEnsembleDetector._safe_float(value, default)
        if not math.isfinite(confidence) or confidence < 0.0 or confidence > 1.0:
            return default
        return confidence

    @staticmethod
    def _safe_text(value: Any, default: str) -> str:
        """Return text fields only when the model supplied an actual string."""
        if isinstance(value, str):
            return value
        return default

    @classmethod
    def _safe_model_label(cls, value: Any) -> Optional[str]:
        """Return a safe model/provider label for result metadata keys."""
        if not isinstance(value, str):
            return None

        label = value.strip()
        if not label or len(label) > cls.MAX_MODEL_LABEL_LENGTH:
            return None

        if any(ord(char) < 32 or ord(char) == 127 for char in label):
            return None

        return label

    @classmethod
    def _safe_severity(cls, value: Any) -> str:
        """Return a normalized known severity, defaulting malformed labels."""
        severity = cls._safe_text(value, "").strip().lower()
        if severity in cls.VALID_SEVERITIES:
            return severity
        return "medium"

    @staticmethod
    def _safe_int(value: Any, default: int) -> int:
        """Return an int for scalar values without accepting container reprs."""
        if isinstance(value, bool) or isinstance(value, (dict, list, tuple, set)):
            return default
        try:
            return int(value)
        except (OverflowError, TypeError, ValueError):
            return default

    @classmethod
    def _safe_location(cls, value: Any) -> Dict[str, Any]:
        """Return scalar location fields only when the model supplied an object."""
        if not isinstance(value, dict):
            return {}
        location: Dict[str, Any] = {}
        for key, field_value in value.items():
            if not isinstance(key, str) or isinstance(field_value, (dict, list, tuple, set)):
                continue
            if key == "line":
                line = cls._safe_int(field_value, 0)
                if cls._is_nonnegative_finite_scalar(field_value):
                    location[key] = line
                continue
            location[key] = field_value
        return location

    def _create_finding_signature(self, finding: Dict[str, Any]) -> str:
        """
        Create a unique signature for grouping similar findings.

        Findings are considered similar if they have the same type
        and approximately the same location.
        """
        vuln_type = self._safe_text(finding.get("type"), "").lower()
        location = self._safe_location(finding.get("location"))

        # Extract location components
        func = self._safe_text(location.get("function"), "")
        line = self._safe_int(location.get("line"), 0)
        if line < 0:
            line = 0
        # Round line to nearest 5 for approximate matching.
        line_group = (line // 5) * 5 if line else 0

        # Create signature
        sig_content = f"{vuln_type}:{func}:{line_group}"
        return hashlib.sha256(sig_content.encode()).hexdigest()[:16]

    def get_model_status(self) -> Dict[str, Any]:
        """Get current model status information."""
        configured_models = self._status_model_list(self.models)
        available_models = self._status_model_list(self._available_models)
        return {
            "configured_models": configured_models,
            "available_models": available_models,
            "voting_strategy": self.voting_strategy.value,
            "consensus_threshold": self.consensus_threshold,
            "model_weights": {m: self._model_weight(m) for m in configured_models},
            "initialized": self._initialized,
        }

    @staticmethod
    def _status_model_list(models: Any) -> List[str]:
        """Return a defensive, serializable model id list for public status."""
        if not isinstance(models, (list, tuple, set)):
            logger.warning("Ignoring malformed ensemble model status list")
            return []

        return [model.strip() for model in models if isinstance(model, str) and model.strip()]


# Convenience function for simple usage
async def detect_with_ensemble(
    code: str,
    models: Optional[List[str]] = None,
    min_votes: int = 2,
) -> List[EnsembleFinding]:
    """
    Detect vulnerabilities using LLM ensemble.

    Args:
        code: Solidity source code
        models: Models to use (default: deepseek-coder, codellama, llama3.1)
        min_votes: Minimum votes for a finding to be valid

    Returns:
        List of validated findings
    """
    detector = LLMEnsembleDetector(
        models=models,
        consensus_threshold=min_votes,
    )
    result = await detector.detect_vulnerabilities(code)
    return result.findings


# Export
__all__ = [
    "LLMEnsembleDetector",
    "EnsembleFinding",
    "EnsembleResult",
    "VotingStrategy",
    "LLMProvider",
    "ProviderUnavailable",
    "AllProvidersUnavailable",
    "detect_with_ensemble",
]
