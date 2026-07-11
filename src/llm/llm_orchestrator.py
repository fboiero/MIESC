"""
LLM Orchestrator for MIESC

Orchestrates multiple LLM backends for intelligent security analysis.
Supports Ollama (local), OpenAI, Anthropic, and custom models.

Author: Fernando Boiero
License: AGPL-3.0
"""

import asyncio
import json
import logging
import math
import os
import time
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

from src.llm.provider_health import fetch_openai_compatible_model_ids
from miesc.security.llm_output_validator import (
    AnalysisResponse,
    repair_common_json_errors,
    safe_parse_llm_json,
)

# LLM Security imports (v5.1.2+)
from miesc.security.prompt_sanitizer import (
    InjectionRiskLevel,
    detect_prompt_injection,
    sanitize_code_for_prompt,
    sanitize_context,
)

logger = logging.getLogger(__name__)

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

LLM_RUNTIME_ERRORS = (
    aiohttp.ClientError,
    ImportError,
    OSError,
    RuntimeError,
    TimeoutError,
    ValueError,
    asyncio.TimeoutError,
    json.JSONDecodeError,
)

_BACKEND_ERROR_TEXT_LIMIT = 500
_MAX_CONTEXT_ITEMS = 100
_MAX_CONTEXT_SEQUENCE_ITEMS = 100
_MAX_ANALYSIS_VULNERABILITIES = 200
_MAX_RECOMMENDATIONS = 200
_MAX_RESPONSE_SEQUENCE_ITEMS = 100
_MAX_TIMEOUT_SECONDS = 600
_MAX_TOKEN_LIMIT = 32_768


def _is_unsafe_text_char(ch: str) -> bool:
    ordinal = ord(ch)
    return ordinal < 32 or ordinal == 127 or ordinal in {0x2028, 0x2029}


def _safe_mapping_get(mapping: Any, key: str, default: Any = None) -> Any:
    if not isinstance(mapping, dict):
        return default
    try:
        return mapping.get(key, default)
    except (AttributeError, TypeError, RuntimeError, ValueError):
        return default


def _safe_mapping_items(mapping: Any) -> List[Tuple[Any, Any]]:
    if not isinstance(mapping, dict):
        return []
    try:
        return list(mapping.items())[:_MAX_CONTEXT_ITEMS]
    except (AttributeError, TypeError, RuntimeError, ValueError):
        return []


def _safe_text(value: Any) -> str:
    """Return stripped safe text, or an empty string for malformed values."""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="replace")
        except Exception:
            return ""
    if not isinstance(value, str):
        return ""
    try:
        text = value.strip()
    except Exception:
        return ""
    if not text or any(_is_unsafe_text_char(ch) for ch in text):
        return ""
    return text


def _safe_backend_error_text(error: Any) -> str:
    """Return bounded printable backend error text without trusting __str__."""
    try:
        text = str(error)
    except Exception:
        return f"<unprintable:{type(error).__name__}>"

    if not text:
        return f"<empty:{type(error).__name__}>"

    safe_chars = []
    for char in text[:_BACKEND_ERROR_TEXT_LIMIT]:
        ordinal = ord(char)
        if char == "\n":
            safe_chars.append("\\n")
        elif char == "\r":
            safe_chars.append("\\r")
        elif char == "\t":
            safe_chars.append("\\t")
        elif ordinal == 0x2028:
            safe_chars.append("\\u2028")
        elif ordinal == 0x2029:
            safe_chars.append("\\u2029")
        elif ordinal < 32 or ordinal == 127:
            safe_chars.append(f"\\x{ordinal:02x}")
        else:
            safe_chars.append(char)

    safe_text = "".join(safe_chars)
    if len(text) > _BACKEND_ERROR_TEXT_LIMIT:
        safe_text += "...<truncated>"
    return safe_text


def _json_safe_context(value: Any, seen: Optional[set[int]] = None) -> Any:
    """Return a JSON-serializable context shape without object repr fallbacks."""
    if seen is None:
        seen = set()

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, bytes):
        return f"<bytes:{len(value)}>"

    value_id = id(value)
    if value_id in seen:
        return f"<circular:{type(value).__name__}>"

    if isinstance(value, dict):
        seen.add(value_id)
        safe_dict = {}
        for key, item in _safe_mapping_items(value):
            if isinstance(key, str):
                safe_key = key if not any(_is_unsafe_text_char(ch) for ch in key) else "<malformed>"
            elif key is None or isinstance(key, (bool, int, float)):
                safe_key = str(key)
            else:
                safe_key = f"<key:{type(key).__name__}>"
            safe_dict[safe_key] = _json_safe_context(item, seen)
        seen.remove(value_id)
        return safe_dict

    if isinstance(value, (list, tuple)):
        seen.add(value_id)
        safe_list = [_json_safe_context(item, seen) for item in value[:_MAX_CONTEXT_SEQUENCE_ITEMS]]
        seen.remove(value_id)
        return safe_list
    if isinstance(value, set):
        seen.add(value_id)
        safe_list = [
            _json_safe_context(item, seen) for item in list(value)[:_MAX_CONTEXT_SEQUENCE_ITEMS]
        ]
        seen.remove(value_id)
        return sorted(safe_list, key=lambda item: json.dumps(item, sort_keys=True))

    return f"<non-serializable:{type(value).__name__}>"


def _context_json(value: Dict) -> str:
    """Serialize context for provider prompts using the safe context shape."""
    return json.dumps(_json_safe_context(value), indent=2, sort_keys=True)


def _cache_key_context(value: Any, seen: Optional[set[int]] = None) -> Any:
    """Return a JSON-safe context shape that preserves dict key type boundaries."""
    if seen is None:
        seen = set()

    if isinstance(value, str):
        text = value.strip()
        if not text or any(_is_unsafe_text_char(ch) for ch in text):
            return {"__text__": "<malformed>"}
        return text
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, bytes):
        return {"__bytes_len__": len(value)}

    value_id = id(value)
    if value_id in seen:
        return {"__circular__": type(value).__name__}

    if isinstance(value, dict):
        seen.add(value_id)
        safe_items = [
            [_cache_key_dict_key(key), _cache_key_context(item, seen)]
            for key, item in _safe_mapping_items(value)
        ]
        seen.remove(value_id)
        return sorted(safe_items, key=lambda item: json.dumps(item, sort_keys=True))

    if isinstance(value, (list, tuple)):
        seen.add(value_id)
        safe_list = [_cache_key_context(item, seen) for item in value[:_MAX_CONTEXT_SEQUENCE_ITEMS]]
        seen.remove(value_id)
        return safe_list
    if isinstance(value, set):
        seen.add(value_id)
        safe_list = [
            _cache_key_context(item, seen) for item in list(value)[:_MAX_CONTEXT_SEQUENCE_ITEMS]
        ]
        seen.remove(value_id)
        return sorted(safe_list, key=lambda item: json.dumps(item, sort_keys=True))

    return {"__non_serializable__": type(value).__name__}


def _cache_key_dict_key(key: Any) -> List[Any]:
    """Encode dict keys without collapsing non-string keys into string keys."""
    if isinstance(key, str):
        text = key.strip()
        if not text or any(_is_unsafe_text_char(ch) for ch in text):
            return ["str", "<malformed>"]
        return ["str", text]
    if key is None:
        return ["none", None]
    if isinstance(key, bool):
        return ["bool", key]
    if isinstance(key, int):
        return ["int", key]
    if isinstance(key, float):
        return ["float", key if math.isfinite(key) else None]
    if isinstance(key, bytes):
        return ["bytes", len(key)]
    return ["non_serializable", type(key).__name__]


def _bounded_confidence(value: Any, default: float = 0.5) -> float:
    """Return a finite confidence value in the expected 0..1 range."""
    if isinstance(value, bool):
        return default
    if isinstance(value, str):
        if any(_is_unsafe_text_char(ch) for ch in value):
            return default
        text = value.strip()
        value = text
    elif isinstance(value, bytes):
        raw_value = value.decode("utf-8", errors="replace")
        if any(_is_unsafe_text_char(ch) for ch in raw_value):
            return default
        text = raw_value.strip()
        value = text
    if not isinstance(value, (int, float)) and not isinstance(value, str):
        return default
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(numeric):
        return default
    return min(max(numeric, 0.0), 1.0)


def _non_negative_int_stat(value: Any, field_name: str, source: str) -> int:
    """Return a strict non-negative integer stat from a backend response."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"Malformed {source}: {field_name} must be int, got {type(value).__name__}"
        )
    if value < 0:
        raise ValueError(f"Malformed {source}: {field_name} must be non-negative")
    return value


def _bounded_output_text(value: Any, *, default: str = "", limit: int = 2000) -> str:
    """Return safe bounded output text for externally supplied analysis fields."""
    text = _safe_text(value)
    if not text:
        return default
    return text[:limit]


def _optional_output_text(value: Any, *, limit: int = 2000) -> Optional[str]:
    """Return safe bounded optional output text."""
    text = _bounded_output_text(value, limit=limit)
    return text or None


def _normalized_severity(value: Any, default: str = "medium") -> str:
    """Return a known severity label for analysis aggregation."""
    severity = _safe_text(value).lower()
    if severity == "informational":
        return "info"
    if severity in {"critical", "high", "medium", "low", "info"}:
        return severity
    return default


def _response_sequence(value: Any, field_name: str, source: str) -> Sequence[Any]:
    """Return a non-empty response sequence, rejecting string-like containers."""
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"Malformed {source}: {field_name} must be non-empty sequence")
    if not value:
        raise ValueError(f"Malformed {source}: {field_name} must be non-empty sequence")
    return value[:_MAX_RESPONSE_SEQUENCE_ITEMS]


def _bounded_positive_int(value: Any, default: int, max_value: int) -> int:
    if isinstance(value, bool):
        return default
    try:
        normalized = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    if normalized < 1:
        return default
    return min(normalized, max_value)


def _bounded_temperature(value: Any, default: float = 0.2) -> float:
    if isinstance(value, bool):
        return default
    try:
        normalized = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    if not math.isfinite(normalized):
        return default
    return min(max(normalized, 0.0), 2.0)


def _openai_compatible_chat_content(response: Any, source: str) -> str:
    """Extract strict text content from an OpenAI-compatible chat response."""
    choices = _response_sequence(getattr(response, "choices", None), "choices", source)
    message = getattr(choices[0], "message", None)
    if message is None:
        raise ValueError(f"Malformed {source}: choices[0].message is required")
    content = getattr(message, "content", None)
    text = _safe_text(content)
    if not text:
        raise ValueError(f"Malformed {source}: choices[0].message.content must be safe text")
    return text


def _anthropic_response_text(response: Any) -> str:
    """Extract strict text content from an Anthropic message response."""
    content_blocks = _response_sequence(
        getattr(response, "content", None),
        "content",
        "Anthropic response",
    )
    text = _safe_text(getattr(content_blocks[0], "text", None))
    if not text:
        raise ValueError("Malformed Anthropic response: content[0].text must be safe text")
    return text


def _normalized_model_identifier(value: Any) -> Optional[str]:
    """Return a safe model identifier, or None for malformed config values."""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="replace")
        except (AttributeError, TypeError, ValueError, UnicodeDecodeError):
            return None
    if not isinstance(value, str):
        return None
    model = value.strip()
    if not model or any(_is_unsafe_text_char(char) for char in model):
        return None
    return model


def _is_safe_backend_name(value: Any) -> bool:
    """Return whether a backend name is safe to expose in status outputs."""
    if not isinstance(value, str):
        return False
    return len(value) <= 128 and _normalized_model_identifier(value) == value


class LLMProvider(Enum):
    """Supported LLM providers."""

    OLLAMA = "ollama"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    DEEPSEEK = "deepseek"
    LOCAL = "local"


@dataclass
class LLMConfig:
    """Configuration for LLM backend."""

    provider: LLMProvider
    model: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0.2
    max_tokens: int = 4096
    timeout: int = 120
    retry_attempts: int = 3
    retry_delay: float = 1.0


@dataclass
class LLMResponse:
    """Response from LLM analysis."""

    content: str
    provider: str
    model: str
    tokens_used: int = 0
    latency_ms: float = 0
    cached: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnerabilityAnalysis:
    """Structured vulnerability analysis result."""

    vulnerabilities: List[Dict[str, Any]]
    severity_assessment: Dict[str, int]
    recommendations: List[str]
    confidence_score: float
    analysis_summary: str
    raw_response: str


class LLMBackend(ABC):
    """Abstract base class for LLM backends."""

    def __init__(self, config: LLMConfig):
        self.config = config
        self.available = False

    @abstractmethod
    async def analyze(self, prompt: str, context: Optional[Dict] = None) -> LLMResponse:
        """Run analysis with the LLM."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the backend is available."""
        pass

    def get_system_prompt(self) -> str:
        """Get the security analysis system prompt."""
        return """You are an expert Solidity smart contract security auditor.
Your task is to analyze smart contract code for security vulnerabilities.

When analyzing code, you should:
1. Identify potential vulnerabilities (reentrancy, overflow, access control, etc.)
2. Assess the severity of each finding (critical, high, medium, low, info)
3. Explain the attack vector and potential impact
4. Provide specific remediation recommendations with code examples
5. Reference relevant CWE and SWC identifiers when applicable

Format your response as JSON with the following structure:
{
    "vulnerabilities": [
        {
            "type": "vulnerability_type",
            "severity": "critical|high|medium|low|info",
            "title": "Brief title",
            "description": "Detailed description",
            "location": {"line": number, "function": "name"},
            "attack_vector": "How it can be exploited",
            "impact": "Potential consequences",
            "remediation": "How to fix",
            "cwe": "CWE-841",
            "swc": "SWC-107",
            "confidence": 0.0-1.0
        }
    ],
    "summary": "Overall security assessment",
    "risk_score": 0-100
}

Use real CWE/SWC identifiers only when applicable. Use null for identifiers
that do not apply; never emit made-up or placeholder taxonomy values."""


class OllamaBackend(LLMBackend):
    """Ollama backend for local LLM inference."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.base_url = config.base_url or "http://localhost:11434"

    async def health_check(self) -> bool:
        """Check if Ollama is running."""
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/api/tags", timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status == 200 and not isinstance(resp.status, bool):
                        data = await resp.json()
                        if not isinstance(data, dict):
                            self.available = False
                            return self.available
                        models_value = _safe_mapping_get(data, "models", [])
                        models = []
                        if isinstance(models_value, list):
                            for model_entry in models_value[:_MAX_CONTEXT_SEQUENCE_ITEMS]:
                                name = (
                                    _safe_mapping_get(model_entry, "name")
                                    if isinstance(model_entry, dict)
                                    else None
                                )
                                safe_name = _safe_text(name)
                                if safe_name:
                                    models.append(safe_name)
                        self.available = self.config.model in models or any(
                            self.config.model in m for m in models
                        )
                        return self.available
        except LLM_RUNTIME_ERRORS as e:
            logger.debug("Ollama health check failed: %s", _safe_backend_error_text(e))
        return False

    async def analyze(self, prompt: str, context: Optional[Dict] = None) -> LLMResponse:
        """Run analysis with Ollama."""
        import aiohttp

        start_time = time.time()

        system_prompt = self.get_system_prompt()
        if context:
            system_prompt += f"\n\nAdditional context:\n{_context_json(context)}"

        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            },
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout),
            ) as resp:
                status = resp.status
                if not isinstance(status, int) or isinstance(status, bool):
                    raise RuntimeError("Ollama error: malformed status")
                if status != 200:
                    try:
                        error_text = _safe_backend_error_text(await resp.text())
                    except LLM_RUNTIME_ERRORS:
                        error_text = "error"
                    raise RuntimeError(f"Ollama error: {error_text}")

                data = await resp.json()
                if not isinstance(data, dict):
                    raise ValueError(
                        f"Malformed Ollama response: expected object, got {type(data).__name__}"
                    )
                message = _safe_mapping_get(data, "message", {})
                if not isinstance(message, dict):
                    raise ValueError(
                        "Malformed Ollama response: message must be object, "
                        f"got {type(message).__name__}"
                    )
                content = _safe_mapping_get(message, "content", "")
                if not isinstance(content, str) or not _safe_text(content):
                    raise ValueError(
                        "Malformed Ollama response: content must be str, "
                        f"got {type(content).__name__}"
                    )
                eval_count = _safe_mapping_get(data, "eval_count", 0)
                prompt_eval_count = _safe_mapping_get(data, "prompt_eval_count", 0)
                if (
                    isinstance(eval_count, bool)
                    or isinstance(prompt_eval_count, bool)
                    or not isinstance(eval_count, int)
                    or not isinstance(prompt_eval_count, int)
                ):
                    raise ValueError("Malformed Ollama response: token counts must be integers")
                if eval_count < 0 or prompt_eval_count < 0:
                    raise ValueError("Malformed Ollama response: token counts must be non-negative")
                tokens = eval_count + prompt_eval_count

        return LLMResponse(
            content=content,
            provider="ollama",
            model=self.config.model,
            tokens_used=tokens,
            latency_ms=(time.time() - start_time) * 1000,
        )


class OpenAIBackend(LLMBackend):
    """OpenAI backend."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.api_key = config.api_key or os.getenv("OPENAI_API_KEY")

    async def health_check(self) -> bool:
        """Check if OpenAI is configured."""
        self.available = bool(self.api_key)
        return self.available

    async def analyze(self, prompt: str, context: Optional[Dict] = None) -> LLMResponse:
        """Run analysis with OpenAI."""
        try:
            import openai
        except ImportError as e:
            raise ImportError("openai package not installed. Run: pip install openai") from e

        start_time = time.time()
        client = openai.AsyncOpenAI(api_key=self.api_key)

        system_prompt = self.get_system_prompt()
        if context:
            system_prompt += f"\n\nAdditional context:\n{_context_json(context)}"

        response = await client.chat.completions.create(
            model=self.config.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            temperature=_bounded_temperature(self.config.temperature),
            max_tokens=_bounded_positive_int(self.config.max_tokens, 4096, _MAX_TOKEN_LIMIT),
        )

        usage = getattr(response, "usage", None)
        tokens = (
            _non_negative_int_stat(
                getattr(usage, "total_tokens", 0),
                "usage.total_tokens",
                "OpenAI response",
            )
            if usage
            else 0
        )

        return LLMResponse(
            content=_openai_compatible_chat_content(response, "OpenAI response"),
            provider="openai",
            model=self.config.model,
            tokens_used=tokens,
            latency_ms=(time.time() - start_time) * 1000,
        )


class DeepSeekBackend(LLMBackend):
    """DeepSeek backend using its OpenAI-compatible chat completions API."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.api_key = config.api_key or os.getenv("DEEPSEEK_API_KEY")
        self.base_url = (
            config.base_url or os.getenv("DEEPSEEK_BASE_URL") or "https://api.deepseek.com"
        )

    async def health_check(self) -> bool:
        """Check if DeepSeek is configured and exposes the requested model."""
        if not self.api_key:
            self.available = False
            return self.available

        models = await fetch_openai_compatible_model_ids(
            self.base_url,
            self.api_key,
            provider_name="DeepSeek",
        )
        self.available = self.config.model in models
        return self.available

    async def analyze(self, prompt: str, context: Optional[Dict] = None) -> LLMResponse:
        """Run analysis with DeepSeek."""
        try:
            import openai
        except ImportError as e:
            raise ImportError("openai package not installed. Run: pip install openai") from e

        start_time = time.time()
        client = openai.AsyncOpenAI(api_key=self.api_key, base_url=self.base_url)

        system_prompt = self.get_system_prompt()
        if context:
            system_prompt += f"\n\nAdditional context:\n{_context_json(context)}"

        response = await client.chat.completions.create(
            model=self.config.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            temperature=self.config.temperature,
            max_tokens=_bounded_positive_int(self.config.max_tokens, 4096, _MAX_TOKEN_LIMIT),
        )

        usage = getattr(response, "usage", None)
        tokens = (
            _non_negative_int_stat(
                getattr(usage, "total_tokens", 0),
                "usage.total_tokens",
                "DeepSeek response",
            )
            if usage
            else 0
        )

        return LLMResponse(
            content=_openai_compatible_chat_content(response, "DeepSeek response"),
            provider="deepseek",
            model=self.config.model,
            tokens_used=tokens,
            latency_ms=(time.time() - start_time) * 1000,
        )


class AnthropicBackend(LLMBackend):
    """Anthropic Claude backend."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.api_key = config.api_key or os.getenv("ANTHROPIC_API_KEY")

    async def health_check(self) -> bool:
        """Check if Anthropic is configured."""
        self.available = bool(self.api_key)
        return self.available

    async def analyze(self, prompt: str, context: Optional[Dict] = None) -> LLMResponse:
        """Run analysis with Anthropic."""
        try:
            import anthropic
        except ImportError as e:
            raise ImportError("anthropic package not installed. Run: pip install anthropic") from e

        start_time = time.time()
        client = anthropic.AsyncAnthropic(api_key=self.api_key)

        system_prompt = self.get_system_prompt()
        if context:
            system_prompt += f"\n\nAdditional context:\n{_context_json(context)}"

        response = await client.messages.create(
            model=self.config.model,
            max_tokens=_bounded_positive_int(self.config.max_tokens, 4096, _MAX_TOKEN_LIMIT),
            system=system_prompt,
            messages=[{"role": "user", "content": prompt}],
        )

        content = _anthropic_response_text(response)
        usage = getattr(response, "usage", None)
        tokens = 0
        if usage:
            tokens = _non_negative_int_stat(
                getattr(usage, "input_tokens", 0),
                "usage.input_tokens",
                "Anthropic response",
            ) + _non_negative_int_stat(
                getattr(usage, "output_tokens", 0),
                "usage.output_tokens",
                "Anthropic response",
            )

        return LLMResponse(
            content=content,
            provider="anthropic",
            model=self.config.model,
            tokens_used=tokens,
            latency_ms=(time.time() - start_time) * 1000,
        )


class LLMOrchestrator:
    """
    Orchestrates multiple LLM backends for security analysis.

    Features:
    - Automatic fallback between providers
    - Response caching
    - Retry logic
    - Provider selection based on task
    """

    def __init__(self, configs: Optional[List[LLMConfig]] = None):
        """Initialize orchestrator with backend configurations."""
        self.backends: Dict[str, LLMBackend] = {}
        self.primary_provider: Optional[str] = None
        self.cache: Dict[str, LLMResponse] = {}
        self.cache_timestamps: Dict[str, float] = {}
        self.cache_ttl: int = 3600  # 1 hour
        self.cache_max_entries: int = 128

        # Default configurations if none provided
        if configs is None:
            configs = [self._default_config_from_env()]

        # Initialize backends
        for config in configs:
            self._add_backend(config)

    def _default_config_from_env(self) -> LLMConfig:
        """Build the default backend config from MIESC_LLM_* environment variables."""
        provider_name_raw = _safe_text(os.getenv("MIESC_LLM_PROVIDER", LLMProvider.OLLAMA.value))
        provider = LLMProvider.OLLAMA
        provider_from_env_is_valid = False
        if provider_name_raw:
            try:
                provider = LLMProvider(provider_name_raw.lower())
                provider_from_env_is_valid = True
            except ValueError:
                logger.warning(
                    "Unknown MIESC_LLM_PROVIDER=%s; falling back to Ollama",
                    provider_name_raw,
                )
        else:
            logger.warning(
                "Malformed MIESC_LLM_PROVIDER=%r; falling back to Ollama",
                os.getenv("MIESC_LLM_PROVIDER", LLMProvider.OLLAMA.value),
            )

        default_models = {
            LLMProvider.OLLAMA: "deepseek-coder:6.7b",
            LLMProvider.OPENAI: "gpt-4",
            LLMProvider.ANTHROPIC: "claude-3-5-sonnet-20241022",
            LLMProvider.DEEPSEEK: "deepseek-v4-flash",
            LLMProvider.LOCAL: "deepseek-coder:6.7b",
        }
        model_from_env = _normalized_model_identifier(os.getenv("MIESC_LLM_MODEL"))
        model = (model_from_env if provider_from_env_is_valid else None) or default_models[provider]

        base_url_env = _safe_text(os.getenv("MIESC_LLM_BASE_URL"))
        if not base_url_env:
            base_url_env = None

        if provider == LLMProvider.OLLAMA:
            ollama_host = _safe_text(os.getenv("OLLAMA_HOST", "http://localhost:11434"))
            if not ollama_host:
                ollama_host = "http://localhost:11434"
            return LLMConfig(
                provider=provider,
                model=model,
                base_url=base_url_env or ollama_host,
            )
        if provider == LLMProvider.DEEPSEEK:
            deepseek_base_url = _safe_text(
                os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
            )
            if not deepseek_base_url:
                deepseek_base_url = "https://api.deepseek.com"
            return LLMConfig(
                provider=provider,
                model=model,
                base_url=base_url_env or deepseek_base_url,
            )
        return LLMConfig(provider=provider, model=model)

    def _add_backend(self, config: LLMConfig) -> None:
        """Add a backend based on configuration."""
        backend: LLMBackend
        model = _normalized_model_identifier(config.model)
        if model is None:
            logger.warning(
                "Ignoring LLM backend with malformed model identity: %r",
                config.model,
            )
            return

        if model != config.model:
            config = replace(config, model=model)

        if config.provider == LLMProvider.OLLAMA:
            backend = OllamaBackend(config)
        elif config.provider == LLMProvider.OPENAI:
            backend = OpenAIBackend(config)
        elif config.provider == LLMProvider.ANTHROPIC:
            backend = AnthropicBackend(config)
        elif config.provider == LLMProvider.DEEPSEEK:
            backend = DeepSeekBackend(config)
        else:
            logger.warning(f"Unknown provider: {config.provider}")
            return

        key = f"{config.provider.value}:{config.model}"
        self.backends[key] = backend

        if self.primary_provider is None:
            self.primary_provider = key

    async def initialize(self) -> Dict[str, bool]:
        """Initialize all backends and check availability."""
        status = {}
        for key, backend in self._backend_items():
            try:
                raw_available = await backend.health_check()
                if not isinstance(raw_available, bool):
                    logger.warning(
                        "Backend %s health check returned malformed availability %s; "
                        "treating as unavailable",
                        key,
                        type(raw_available).__name__,
                    )
                    raw_available = False
                available = raw_available
                backend.available = available
                status[key] = available
                if available and self.primary_provider is None:
                    self.primary_provider = key
                logger.info(f"Backend {key}: {'available' if available else 'unavailable'}")
            except LLM_RUNTIME_ERRORS as e:
                status[key] = False
                logger.warning(
                    "Backend %s health check failed: %s",
                    key,
                    _safe_backend_error_text(e),
                )
        return status

    async def analyze_contract(
        self, code: str, context: Optional[Dict] = None, provider: Optional[str] = None
    ) -> VulnerabilityAnalysis:
        """
        Analyze a smart contract for vulnerabilities.

        Args:
            code: Solidity source code
            context: Additional context (tool results, metadata)
            provider: Specific provider to use (optional)

        Returns:
            Structured vulnerability analysis
        """
        # SECURITY: Detect prompt injection attempts (v5.1.2+)
        injection_result = detect_prompt_injection(code)
        if injection_result.risk_level in (InjectionRiskLevel.HIGH, InjectionRiskLevel.CRITICAL):
            logger.warning(
                f"Prompt injection detected in contract: "
                f"risk={injection_result.risk_level.value}, "
                f"patterns={injection_result.patterns_found}"
            )

        # SECURITY: Sanitize contract code before embedding (v5.1.2+)
        safe_code = sanitize_code_for_prompt(code, wrap_in_tags=True, tag_name="solidity-contract")

        # SECURITY: Sanitize context if provided (v5.1.2+)
        safe_context = sanitize_context(context) if context else None

        prompt = f"""Analyze the following Solidity smart contract for security vulnerabilities.
IMPORTANT: Only analyze the code within the <solidity-contract> tags.

{safe_code}

Provide a comprehensive security analysis in JSON format."""

        # Get LLM response
        response = await self.query(prompt, safe_context, provider)

        # Parse response
        return self._parse_analysis(response)

    async def query(
        self, prompt: str, context: Optional[Dict] = None, provider: Optional[str] = None
    ) -> LLMResponse:
        """
        Send a query to the LLM with automatic fallback.

        Args:
            prompt: The prompt to send
            context: Additional context
            provider: Specific provider to use

        Returns:
            LLM response
        """
        # Check cache
        cache_key = self._get_cache_key(prompt, context)
        cache = self._cache_state()
        if cache_key in cache:
            cached = cache[cache_key]
            cache_error = self._response_boundary_error(cached, "cache")
            if cache_error is not None:
                logger.warning("Ignoring malformed cached LLM response for key %s", cache_key)
                cache.pop(cache_key, None)
                self.cache_timestamps.pop(cache_key, None)
            elif not self._cache_entry_is_fresh(cache_key):
                logger.warning("Ignoring expired cached LLM response for key %s", cache_key)
                cache.pop(cache_key, None)
                self.cache_timestamps.pop(cache_key, None)
            else:
                cached.cached = True
                return cached

        # Select backend
        backend_key = provider if provider is not None else self.primary_provider
        if backend_key is not None and not isinstance(backend_key, str):
            logger.warning(
                "Ignoring malformed LLM backend route of type %s",
                type(backend_key).__name__,
            )
            backend_key = None
        if not backend_key and not self.backends:
            raise RuntimeError("No LLM backends available")

        # Try with fallback
        errors = []
        backends_to_try = []
        if backend_key:
            backends_to_try.append(backend_key)
        backends_to_try.extend(k for k, _backend in self._backend_items() if k != backend_key)

        for key in backends_to_try:
            backend = self.backends.get(key)
            if not backend or not self._backend_is_available(key, backend):
                continue

            retry_attempts = self._retry_attempt_count(backend)
            retry_delay = self._retry_delay_seconds(backend)
            for attempt in range(retry_attempts):
                try:
                    response = await backend.analyze(prompt, context)
                    response_error = self._response_boundary_error(response, key)
                    if response_error is not None:
                        raise ValueError(response_error)
                    self._cache_response(cache_key, response)
                    return response
                except LLM_RUNTIME_ERRORS as e:
                    errors.append(f"{key} attempt {attempt + 1}: {_safe_backend_error_text(e)}")
                    if attempt < retry_attempts - 1:
                        await asyncio.sleep(retry_delay)

        raise RuntimeError(f"All LLM backends failed: {'; '.join(errors)}")

    def _response_boundary_error(self, response: Any, source: str) -> Optional[str]:
        """Return a validation error for malformed response boundary fields."""
        if not isinstance(response, LLMResponse):
            return (
                f"Malformed LLM response from {source}: "
                f"expected LLMResponse, got {type(response).__name__}"
            )
        content = _safe_text(response.content)
        if not content:
            return (
                f"Malformed LLM response from {source}: "
                f"content must be str, got {type(response.content).__name__}"
            )
        provider = _safe_text(response.provider)
        if not provider:
            return (
                f"Malformed LLM response from {source}: "
                f"provider must be str, got {type(response.provider).__name__}"
            )
        model = _safe_text(response.model)
        if not model:
            return (
                f"Malformed LLM response from {source}: "
                f"model must be str, got {type(response.model).__name__}"
            )
        if isinstance(response.tokens_used, bool) or not isinstance(response.tokens_used, int):
            return (
                f"Malformed LLM response from {source}: "
                f"tokens_used must be int, got {type(response.tokens_used).__name__}"
            )
        if response.tokens_used < 0:
            return (
                f"Malformed LLM response from {source}: "
                f"tokens_used must be non-negative, got {response.tokens_used}"
            )
        if (
            isinstance(response.latency_ms, bool)
            or not isinstance(response.latency_ms, (int, float))
            or not math.isfinite(response.latency_ms)
            or response.latency_ms < 0
        ):
            return (
                f"Malformed LLM response from {source}: "
                f"latency_ms must be finite non-negative number, got {response.latency_ms!r}"
            )
        if not isinstance(response.metadata, dict):
            return (
                f"Malformed LLM response from {source}: "
                f"metadata must be dict, got {type(response.metadata).__name__}"
            )
        if not isinstance(response.cached, bool):
            return (
                f"Malformed LLM response from {source}: "
                f"cached must be bool, got {type(response.cached).__name__}"
            )
        return None

    def _backend_is_available(self, key: str, backend: LLMBackend) -> bool:
        """Return a strict backend availability status for routing/status helpers."""
        if isinstance(backend.available, bool):
            return backend.available
        logger.warning(
            "Backend %s has malformed availability %s; treating as unavailable",
            key,
            type(backend.available).__name__,
        )
        backend.available = False
        return False

    def _backend_items(self) -> List[Tuple[str, LLMBackend]]:
        """Return backend entries with strict string keys for routing/status boundaries."""
        valid_backends = []
        for key, backend in self.backends.items():
            if not isinstance(backend, LLMBackend):
                logger.warning(
                    "Ignoring malformed LLM backend value for key %r: %s",
                    key,
                    type(backend).__name__,
                )
                continue
            if _is_safe_backend_name(key):
                valid_backends.append((key, backend))
                continue
            logger.warning(
                "Ignoring malformed LLM backend key of type %s",
                type(key).__name__,
            )
        return valid_backends

    def _retry_attempt_count(self, backend: LLMBackend) -> int:
        """Return a conservative retry count for malformed backend config."""
        raw_attempts = backend.config.retry_attempts
        if isinstance(raw_attempts, bool) or not isinstance(raw_attempts, int) or raw_attempts < 1:
            logger.warning(
                "Backend %s:%s has malformed retry_attempts=%r; using 1",
                backend.config.provider.value,
                backend.config.model,
                raw_attempts,
            )
            return 1
        return min(raw_attempts, 5)

    def _retry_delay_seconds(self, backend: LLMBackend) -> float:
        """Return a conservative retry delay for malformed backend config."""
        raw_delay = backend.config.retry_delay
        if (
            not isinstance(raw_delay, (int, float))
            or isinstance(raw_delay, bool)
            or not math.isfinite(raw_delay)
            or raw_delay < 0
        ):
            logger.warning(
                "Backend %s:%s has malformed retry_delay=%r; using 0",
                backend.config.provider.value,
                backend.config.model,
                raw_delay,
            )
            return 0.0
        return min(float(raw_delay), 10.0)

    def _cache_entry_limit(self) -> int:
        """Return a conservative cache size limit for malformed orchestrator state."""
        raw_limit = self.cache_max_entries
        if isinstance(raw_limit, bool) or not isinstance(raw_limit, int) or raw_limit < 1:
            logger.warning("Malformed LLM cache_max_entries=%r; using 1", raw_limit)
            return 1
        return raw_limit

    def _cache_ttl_seconds(self) -> float:
        """Return a conservative finite cache TTL for malformed orchestrator state."""
        raw_ttl = self.cache_ttl
        if (
            isinstance(raw_ttl, bool)
            or not isinstance(raw_ttl, (int, float))
            or not math.isfinite(raw_ttl)
            or raw_ttl < 0
        ):
            logger.warning("Malformed LLM cache_ttl=%r; using 0", raw_ttl)
            return 0.0
        return float(raw_ttl)

    def _cache_state(self) -> Dict[str, LLMResponse]:
        """Return a usable cache mapping, resetting malformed in-memory state."""
        if isinstance(self.cache, dict):
            return self.cache
        logger.warning(
            "Malformed LLM cache state %s; resetting response cache",
            type(self.cache).__name__,
        )
        self.cache = {}
        self.cache_timestamps = {}
        return self.cache

    def _cache_timestamps_state(self) -> Dict[str, float]:
        """Return a usable timestamp mapping, resetting malformed in-memory state."""
        if isinstance(self.cache_timestamps, dict):
            return self.cache_timestamps
        logger.warning(
            "Malformed LLM cache timestamp state %s; resetting timestamp cache",
            type(self.cache_timestamps).__name__,
        )
        self.cache_timestamps = {}
        return self.cache_timestamps

    def _cache_entry_is_fresh(self, cache_key: str) -> bool:
        """Return whether a cached response is still within the configured TTL."""
        cached_at = self._cache_timestamps_state().get(cache_key)
        if cached_at is None:
            return True
        if (
            isinstance(cached_at, bool)
            or not isinstance(cached_at, (int, float))
            or not math.isfinite(cached_at)
        ):
            logger.warning(
                "Malformed LLM cache timestamp for key %s; treating as expired",
                cache_key,
            )
            return False
        return time.time() - float(cached_at) <= self._cache_ttl_seconds()

    def _cache_response(self, cache_key: str, response: LLMResponse) -> None:
        """Store a response and evict oldest cache entries beyond the size limit."""
        cache = self._cache_state()
        cache_timestamps = self._cache_timestamps_state()
        cache[cache_key] = response
        cache_timestamps[cache_key] = time.time()
        entry_limit = self._cache_entry_limit()
        while len(cache) > entry_limit:
            oldest_key = next(iter(cache), None)
            if oldest_key is None:
                break
            cache.pop(oldest_key, None)
            cache_timestamps.pop(oldest_key, None)

    def _get_cache_key(self, prompt: str, context: Optional[Dict]) -> str:
        """Generate cache key from prompt and context."""
        import hashlib

        if isinstance(prompt, str):
            safe_prompt = prompt
        else:
            logger.warning(
                "Malformed LLM cache key prompt of type %s; using fallback boundary",
                type(prompt).__name__,
            )
            safe_prompt = {"__malformed_prompt__": type(prompt).__name__}

        try:
            safe_context = _cache_key_context({} if context is None else context)
        except (TypeError, ValueError, RecursionError) as e:
            logger.warning(
                "Malformed LLM cache key context of type %s; using fallback boundary: %s",
                type(context).__name__,
                _safe_backend_error_text(e),
            )
            safe_context = {"__malformed_context__": type(context).__name__}

        content = json.dumps(
            {"context": safe_context, "prompt": safe_prompt},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _analysis_vulnerability_dict(self, vulnerability: Any) -> Optional[Dict[str, Any]]:
        """Normalize a validated or legacy vulnerability object into safe output fields."""
        known_fields = {
            "type",
            "severity",
            "title",
            "description",
            "confidence",
            "swc_id",
            "cwe_id",
            "remediation",
            "attack_scenario",
        }
        if isinstance(vulnerability, dict):

            def get_field(key: str, default: Any = None) -> Any:
                return _safe_mapping_get(vulnerability, key, default)

            try:
                has_known_field = any(field in vulnerability for field in known_fields)
            except (AttributeError, TypeError, RuntimeError, ValueError):
                has_known_field = False
        else:

            def get_field(key: str, default: Any = None) -> Any:
                try:
                    return getattr(vulnerability, key, default)
                except (AttributeError, TypeError, RuntimeError, ValueError):
                    return default

            has_known_field = any(get_field(field, None) is not None for field in known_fields)

        vuln_type = _bounded_output_text(get_field("type", "unknown"), default="unknown", limit=200)
        severity = _normalized_severity(get_field("severity", "medium"))
        title = _bounded_output_text(get_field("title", ""), limit=500)
        description = _bounded_output_text(get_field("description", ""), limit=5000)
        remediation = _optional_output_text(get_field("remediation", None), limit=2000)
        attack_scenario = _optional_output_text(get_field("attack_scenario", None), limit=2000)

        if not has_known_field:
            return None

        return {
            "type": vuln_type,
            "severity": severity,
            "title": title,
            "description": description,
            "confidence": _bounded_confidence(get_field("confidence", 0.5)),
            "swc_id": _optional_output_text(get_field("swc_id", None), limit=100),
            "cwe_id": _optional_output_text(get_field("cwe_id", None), limit=100),
            "remediation": remediation,
            "attack_scenario": attack_scenario,
        }

    def _severity_assessment(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Aggregate normalized vulnerability severities."""
        return {
            "critical": sum(1 for v in vulnerabilities if v.get("severity") == "critical"),
            "high": sum(1 for v in vulnerabilities if v.get("severity") == "high"),
            "medium": sum(1 for v in vulnerabilities if v.get("severity") == "medium"),
            "low": sum(1 for v in vulnerabilities if v.get("severity") == "low"),
            "info": sum(1 for v in vulnerabilities if v.get("severity") == "info"),
        }

    def _parse_analysis(self, response: LLMResponse) -> VulnerabilityAnalysis:
        """Parse LLM response into structured analysis with Pydantic validation (v5.1.2+)."""
        content = response.content

        # SECURITY: Use Pydantic validation for LLM output (v5.1.2+)
        validation_result = safe_parse_llm_json(content, AnalysisResponse)

        if validation_result.is_valid and validation_result.data:
            # Successfully validated response
            validated = validation_result.data

            # Log any validation warnings
            if validation_result.has_warnings:
                logger.warning(f"LLM output validation warnings: {validation_result.warnings}")

            # Convert validated findings to dict format
            # Handle both Pydantic objects and raw dicts (from model_construct in lenient mode)
            vulnerabilities: List[Dict[str, Any]] = []
            vulnerabilities_source = (
                validated.vulnerabilities if isinstance(validated.vulnerabilities, list) else []
            )
            for vuln in vulnerabilities_source[:_MAX_ANALYSIS_VULNERABILITIES]:
                vuln_dict = self._analysis_vulnerability_dict(vuln)
                if vuln_dict is not None:
                    vulnerabilities.append(vuln_dict)

            return VulnerabilityAnalysis(
                vulnerabilities=vulnerabilities,
                severity_assessment=self._severity_assessment(vulnerabilities),
                recommendations=[
                    v.get("remediation", "")
                    for v in vulnerabilities[:_MAX_RECOMMENDATIONS]
                    if v.get("remediation")
                ],
                confidence_score=sum(v.get("confidence", 0.5) for v in vulnerabilities)
                / max(len(vulnerabilities), 1),
                analysis_summary=_bounded_output_text(
                    getattr(validated, "summary", None),
                    default="Analysis completed",
                    limit=2000,
                ),
                raw_response=content,
            )

        # Validation failed - fall back to legacy parsing with logging
        logger.warning(f"LLM output validation failed: {validation_result.errors}")

        try:
            # Legacy JSON extraction
            json_start = content.find("{")
            json_end = content.rfind("}") + 1

            if json_start >= 0 and json_end > json_start:
                json_str = content[json_start:json_end]
                data = json.loads(repair_common_json_errors(json_str))
            else:
                data = {}

            raw_vulnerabilities = _safe_mapping_get(data, "vulnerabilities", [])
            vulnerabilities = []
            if isinstance(raw_vulnerabilities, list):
                for vuln in raw_vulnerabilities[:_MAX_ANALYSIS_VULNERABILITIES]:
                    if not isinstance(vuln, dict):
                        continue
                    vuln_dict = self._analysis_vulnerability_dict(vuln)
                    if vuln_dict is not None:
                        vulnerabilities.append(vuln_dict)

            return VulnerabilityAnalysis(
                vulnerabilities=vulnerabilities,
                severity_assessment=self._severity_assessment(vulnerabilities),
                recommendations=[
                    v.get("remediation", "")
                    for v in vulnerabilities[:_MAX_RECOMMENDATIONS]
                    if v.get("remediation")
                ],
                confidence_score=sum(
                    _bounded_confidence(v.get("confidence", 0.5)) for v in vulnerabilities
                )
                / max(len(vulnerabilities), 1),
                analysis_summary=_bounded_output_text(
                    _safe_mapping_get(data, "summary"),
                    default="Analysis completed",
                    limit=2000,
                ),
                raw_response=content,
            )

        except json.JSONDecodeError:
            # Return unstructured analysis
            return VulnerabilityAnalysis(
                vulnerabilities=[],
                severity_assessment={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                recommendations=[],
                confidence_score=0.5,
                analysis_summary=_bounded_output_text(
                    content,
                    default="Analysis failed",
                    limit=500,
                ),
                raw_response=content,
            )

    def select_model_for_task(self, task: str) -> str:
        """Select the best model for a specific task type."""
        task_preferences = {
            "vulnerability_detection": [
                "ollama:deepseek-coder:6.7b",
                "deepseek:deepseek-v4-flash",
                "openai:gpt-4",
            ],
            "code_review": [
                "anthropic:claude-3-opus",
                "deepseek:deepseek-v4-pro",
                "openai:gpt-4",
            ],
            "remediation": [
                "ollama:codellama:13b",
                "deepseek:deepseek-v4-flash",
                "openai:gpt-4",
            ],
            "explanation": ["anthropic:claude-3-sonnet", "ollama:llama2:13b"],
        }

        preferences = self._preferred_models_for_task(task_preferences.get(task))
        if not preferences:
            preferences = [key for key, _backend in self._backend_items()]

        for pref in preferences:
            if pref in self.backends and self._backend_is_available(pref, self.backends[pref]):
                return pref

        for key, backend in self._backend_items():
            if self._backend_is_available(key, backend):
                return key

        if (
            isinstance(self.primary_provider, str)
            and self.primary_provider
            and self.primary_provider in self.backends
        ):
            return self.primary_provider
        raise RuntimeError("No LLM backends available")

    def _preferred_models_for_task(self, preferred_models: Any) -> List[str]:
        """Return strict preferred model keys from a potentially malformed sequence."""
        if preferred_models is None:
            return []
        if not isinstance(preferred_models, Sequence) or isinstance(
            preferred_models, (str, bytes, bytearray)
        ):
            logger.warning(
                "Ignoring malformed preferred model list of type %s",
                type(preferred_models).__name__,
            )
            return []
        try:
            raw_models = list(preferred_models)
        except (TypeError, ValueError):
            logger.warning("Ignoring malformed preferred model list contents")
            return []

        models = [model for model in raw_models if _is_safe_backend_name(model)]
        if len(models) != len(raw_models):
            logger.warning("Ignoring malformed preferred model entries")
        return models

    def get_available_providers(self) -> List[str]:
        """Get list of available providers."""
        return [k for k, v in self._backend_items() if self._backend_is_available(k, v)]

    def clear_cache(self) -> None:
        """Clear the response cache."""
        self._cache_state().clear()
        self._cache_timestamps_state().clear()


# Convenience function for simple usage
async def analyze_solidity(code: str, model: str = "deepseek-coder:6.7b") -> VulnerabilityAnalysis:
    """
    Analyze Solidity code for vulnerabilities.

    Args:
        code: Solidity source code
        model: Model to use (default: deepseek-coder:6.7b)

    Returns:
        Vulnerability analysis result
    """
    config = LLMConfig(provider=LLMProvider.OLLAMA, model=model)
    orchestrator = LLMOrchestrator([config])
    await orchestrator.initialize()
    return await orchestrator.analyze_contract(code)


if __name__ == "__main__":
    # Example usage
    async def main() -> None:
        code = """
        pragma solidity ^0.8.0;

        contract Vulnerable {
            mapping(address => uint256) public balances;

            function withdraw(uint256 amount) external {
                require(balances[msg.sender] >= amount);
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success);
                balances[msg.sender] -= amount;
            }
        }
        """

        result = await analyze_solidity(code)
        print(f"Found {len(result.vulnerabilities)} vulnerabilities")  # noqa: T201
        print(f"Severity: {result.severity_assessment}")  # noqa: T201
        print(f"Summary: {result.analysis_summary}")  # noqa: T201

    asyncio.run(main())
