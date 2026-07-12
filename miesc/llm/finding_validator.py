"""
LLM Finding Validator - MIESC v4.2.0
====================================

Validates security findings using local LLM (Ollama) before including them
in the final report. Reduces false positives by applying semantic analysis
to understand code context and vulnerability patterns.

This module provides:
- Async validation of findings using Ollama API
- Confidence adjustment based on LLM analysis
- Severity re-classification when appropriate
- Batch validation for efficiency

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Institution: UNDEF - IUA
Date: January 2026
Version: 1.0.0
"""

import asyncio
import json
import logging
import math
import os
import re
from dataclasses import dataclass, fields, replace
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp

from miesc.security.llm_output_validator import (
    extract_json_from_text,
    repair_common_json_errors,
)

logger = logging.getLogger(__name__)

MAX_VALIDATION_RESPONSE_CHARS = 50_000
MAX_VALIDATION_JSON_KEYS = 100
MAX_VALIDATOR_TEXT_CHARS = 100_000
MAX_BATCH_FINDINGS = 500
MAX_AVAILABLE_MODELS = 200
MAX_VALIDATOR_MODEL_NAME_CHARS = 128
DEFAULT_OLLAMA_HOST = "http://localhost:11434"
_OLLAMA_MODEL_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")

VALIDATOR_RUNTIME_ERRORS = (
    aiohttp.ClientError,
    asyncio.TimeoutError,
    TimeoutError,
    OSError,
    RuntimeError,
    ValueError,
    json.JSONDecodeError,
)


def _is_unsafe_text_char(ch: str, *, allow_multiline: bool = False) -> bool:
    codepoint = ord(ch)
    if codepoint == 127:
        return True
    if allow_multiline and ch in {"\n", "\r", "\t"}:
        return False
    if codepoint < 32:
        return True
    return codepoint in {0x2028, 0x2029}


def _safe_mapping_get(mapping: Any, key: str, default: Any = None) -> Any:
    if not isinstance(mapping, dict):
        return default
    try:
        return mapping.get(key, default)
    except (AttributeError, TypeError, RuntimeError, ValueError):
        return default


def _safe_text(value: Any, *, allow_multiline: bool = False, limit: int = MAX_VALIDATOR_TEXT_CHARS) -> str:
    """Return bounded safe text, preserving normal surrounding whitespace trimming."""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="replace")
        except Exception:
            return ""
    if not isinstance(value, str):
        return ""
    if any(
        ord(ch) == 127 or ord(ch) in {0x2028, 0x2029} or (ord(ch) < 32 and ch not in "\n\r\t ")
        for ch in value
    ):
        return ""
    try:
        text = value.strip()
    except (AttributeError, TypeError, ValueError, RuntimeError):
        return ""
    if not text:
        return ""
    if allow_multiline:
        if any(_is_unsafe_text_char(ch, allow_multiline=True) for ch in text):
            return ""
    elif any(_is_unsafe_text_char(ch) for ch in text):
        return ""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        limit = MAX_VALIDATOR_TEXT_CHARS
    return text[:limit]


def _bounded_list(value: Any, *, limit: int) -> List[Any]:
    """Return a bounded list copy without trusting list subclass slicing/len."""
    if not isinstance(value, list):
        return []
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        limit = MAX_BATCH_FINDINGS
    copied = []
    try:
        iterator = iter(value)
    except (TypeError, RuntimeError, ValueError):
        return []
    try:
        for item in iterator:
            if len(copied) >= limit:
                break
            copied.append(item)
    except (TypeError, RuntimeError, ValueError):
        return copied
    return copied


class ValidationResult(Enum):
    """Result of LLM validation."""

    VALID = "valid"  # Confirmed vulnerability
    LIKELY_VALID = "likely_valid"  # Probably real but needs review
    UNCERTAIN = "uncertain"  # Cannot determine
    LIKELY_FP = "likely_fp"  # Probably false positive
    FALSE_POSITIVE = "false_positive"  # Confirmed FP


@dataclass
class LLMValidation:
    """Result of LLM validation for a finding."""

    finding_id: str
    result: ValidationResult
    confidence: float  # 0.0 - 1.0
    reasoning: str
    suggested_severity: Optional[str] = None
    code_context_analysis: Optional[str] = None
    remediation_hint: Optional[str] = None
    validation_time_ms: int = 0


@dataclass
class ValidatorConfig:
    """Configuration for the LLM validator."""

    ollama_host: str = "http://localhost:11434"
    model: str = "deepseek-coder:6.7b"
    temperature: float = 0.1
    max_tokens: int = 1024
    timeout_seconds: int = 60
    min_severity_to_validate: str = "medium"  # Only validate >= this severity
    batch_size: int = 5
    enabled: bool = True


class LLMFindingValidator:
    """
    Validates security findings using local LLM (Ollama).

    Uses semantic analysis to:
    1. Understand code context around the finding
    2. Analyze if the vulnerability pattern is actually exploitable
    3. Check for protective patterns that might mitigate the issue
    4. Suggest severity adjustments when appropriate
    """

    # Prompt template for validation
    VALIDATION_PROMPT = """You are an expert smart contract security auditor. Analyze this security finding and determine if it's a real vulnerability or a false positive.

## Finding Details
- **Type**: {finding_type}
- **Reported Severity**: {severity}
- **Tool**: {tool}
- **Location**: {file}:{line}
- **Message**: {message}

## Code Context
```solidity
{code_snippet}
```

## Contract Context
{contract_context}

## Your Task
Analyze this finding carefully. Consider:
1. Is the vulnerability pattern actually present and exploitable?
2. Are there any protective patterns (ReentrancyGuard, onlyOwner, require checks) that mitigate it?
3. Is this in test/mock code that wouldn't be deployed?
4. Could this be a false positive due to the tool's limitations?

## Response Format
Respond ONLY with a valid JSON object (no markdown, no extra text):
{{
    "is_valid": true or false,
    "confidence": 0.0 to 1.0,
    "result": "valid" | "likely_valid" | "uncertain" | "likely_fp" | "false_positive",
    "reasoning": "Brief explanation of your analysis (1-2 sentences)",
    "suggested_severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | null,
    "remediation_hint": "Brief fix suggestion if valid" or null
}}"""

    # Severity order for filtering
    SEVERITY_ORDER = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
        "informational": 0,
    }

    def __init__(self, config: Optional[ValidatorConfig] = None):
        """
        Initialize the LLM validator.

        Args:
            config: Validator configuration, uses defaults if not provided
        """
        default_config = ValidatorConfig()
        self.config = self._normalize_config(config, default_config)

        # Environment values fill defaults, but an explicit caller config wins.
        if os.environ.get("OLLAMA_HOST") and self.config.ollama_host == default_config.ollama_host:
            self.config.ollama_host = os.environ["OLLAMA_HOST"]
        if os.environ.get("MIESC_LLM_MODEL") and self.config.model == default_config.model:
            self.config.model = os.environ["MIESC_LLM_MODEL"]
        self.config.ollama_host = self._normalize_ollama_host(
            self.config.ollama_host,
            default_config.ollama_host,
        )
        self.config.model = self._normalize_model_name(self.config.model, default_config.model)
        if (
            isinstance(self.config.timeout_seconds, bool)
            or not isinstance(self.config.timeout_seconds, (int, float))
            or self.config.timeout_seconds <= 0
            or self.config.timeout_seconds > 600
        ):
            self.config.timeout_seconds = default_config.timeout_seconds
        if (
            isinstance(self.config.temperature, bool)
            or not isinstance(self.config.temperature, (int, float))
            or not math.isfinite(float(self.config.temperature))
            or not 0 <= float(self.config.temperature) <= 2
        ):
            self.config.temperature = default_config.temperature
        else:
            self.config.temperature = float(self.config.temperature)
        if (
            isinstance(self.config.max_tokens, bool)
            or not isinstance(self.config.max_tokens, int)
            or self.config.max_tokens <= 0
            or self.config.max_tokens > 16_384
        ):
            self.config.max_tokens = default_config.max_tokens
        if (
            isinstance(self.config.batch_size, bool)
            or not isinstance(self.config.batch_size, int)
            or self.config.batch_size <= 0
            or self.config.batch_size > 50
        ):
            self.config.batch_size = default_config.batch_size
        if not isinstance(self.config.enabled, bool):
            self.config.enabled = default_config.enabled
        if isinstance(self.config.min_severity_to_validate, str):
            min_severity = self.config.min_severity_to_validate.strip().lower()
        else:
            min_severity = ""
        if min_severity in self.SEVERITY_ORDER:
            self.config.min_severity_to_validate = min_severity
        else:
            self.config.min_severity_to_validate = default_config.min_severity_to_validate

        self._session: Optional[aiohttp.ClientSession] = None
        self._validated_count = 0
        self._fp_detected_count = 0

        logger.info(
            f"LLM Validator initialized: model={self.config.model}, host={self.config.ollama_host}"
        )

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(
                total=self._safe_timeout_seconds(self.config.timeout_seconds)
            )
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def close(self) -> None:
        """Close the aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def is_available(self) -> bool:
        """Check if Ollama is available and the model is loaded."""
        try:
            session = await self._get_session()
            async with session.get(f"{self._safe_ollama_host()}/api/tags") as resp:
                status = resp.status
                if not isinstance(status, int) or isinstance(status, bool) or status != 200:
                    return False
                data = await resp.json()
                if not isinstance(data, dict):
                    return False

                models = _bounded_list(
                    _safe_mapping_get(data, "models", []),
                    limit=MAX_AVAILABLE_MODELS,
                )
                model_names = [
                    name.strip()
                    for model in models
                    if isinstance(model, dict)
                    and isinstance(name := _safe_mapping_get(model, "name"), str)
                    and self._safe_model_name(name)
                ]
                return any(
                    self._model_name_matches_configured_model(self._safe_model_name(self.config.model), name)
                    for name in model_names
                )
        except VALIDATOR_RUNTIME_ERRORS as e:
            logger.debug("Ollama not available: %s", self._exception_reason(e))
            return False

    def should_validate(self, finding: Any) -> bool:
        """
        Determine if a finding should be validated by LLM.

        Args:
            finding: The finding to check

        Returns:
            True if should validate, False otherwise
        """
        if not self.config.enabled or not isinstance(finding, dict):
            return False

        severity_value = _safe_mapping_get(finding, "severity", "")
        severity = severity_value.lower() if isinstance(severity_value, str) else ""
        min_severity_value = self.config.min_severity_to_validate
        min_severity = min_severity_value.lower() if isinstance(min_severity_value, str) else ""

        finding_level = self.SEVERITY_ORDER.get(severity, 0)
        min_level = self.SEVERITY_ORDER.get(min_severity, 0)

        return finding_level >= min_level

    async def validate_finding(
        self,
        finding: Dict[str, Any],
        code_context: str = "",
        contract_context: str = "",
    ) -> LLMValidation:
        """
        Validate a single finding using LLM.

        Args:
            finding: The security finding to validate
            code_context: Code snippet around the finding location
            contract_context: Additional context about the contract

        Returns:
            LLMValidation result
        """
        import time

        start_time = time.time()

        if not isinstance(finding, dict):
            return LLMValidation(
                finding_id="unknown",
                result=ValidationResult.UNCERTAIN,
                confidence=0.5,
                reasoning="Malformed finding container",
                validation_time_ms=0,
            )

        safe_finding = finding if isinstance(finding, dict) else {}
        finding_id = self._parse_text(_safe_mapping_get(safe_finding, "id"), "unknown")

        try:
            location_value = _safe_mapping_get(safe_finding, "location", {})
            location = location_value if isinstance(location_value, dict) else {}
            message = self._parse_text(
                _safe_mapping_get(safe_finding, "message"),
                self._parse_text(_safe_mapping_get(safe_finding, "description"), "No message"),
            )
            code_snippet = self._prompt_text(code_context, limit=1500) or "Not available"
            contract_snippet = self._prompt_text(contract_context, limit=500) or "Not available"

            # Build prompt
            prompt = self.VALIDATION_PROMPT.format(
                finding_type=self._parse_text(_safe_mapping_get(safe_finding, "type"), "unknown"),
                severity=self._parse_text(_safe_mapping_get(safe_finding, "severity"), "unknown"),
                tool=self._parse_text(_safe_mapping_get(safe_finding, "tool"), "unknown"),
                file=self._parse_text(_safe_mapping_get(location, "file"), "unknown"),
                line=self._parse_location_line(_safe_mapping_get(location, "line")),
                message=message,
                code_snippet=code_snippet,
                contract_context=contract_snippet,
            )

            # Call Ollama API
            response = await self._call_ollama(prompt)

            # Parse response
            validation = self._parse_response(response, finding_id)
            validation.validation_time_ms = self._parse_nonnegative_int(
                int((time.time() - start_time) * 1000)
            )

            self._validated_count += 1
            if validation.result in [ValidationResult.LIKELY_FP, ValidationResult.FALSE_POSITIVE]:
                self._fp_detected_count += 1

            logger.debug(
                f"Validated {finding_id}: {validation.result.value} "
                f"(confidence: {validation.confidence:.2f})"
            )

            return validation

        except VALIDATOR_RUNTIME_ERRORS as e:
            reason = self._exception_reason(e)
            logger.warning("LLM validation failed for %s: %s", finding_id, reason)
            return LLMValidation(
                finding_id=finding_id,
                result=ValidationResult.UNCERTAIN,
                confidence=0.5,
                reasoning=f"Validation failed: {reason}",
                validation_time_ms=self._parse_nonnegative_int(
                    int((time.time() - start_time) * 1000)
                ),
            )

    async def _call_ollama(self, prompt: str) -> str:
        """Call Ollama API and return response."""
        session = await self._get_session()

        payload = {
            "model": self._safe_model_name(self.config.model) or ValidatorConfig().model,
            "prompt": self._prompt_text(prompt, limit=MAX_VALIDATION_RESPONSE_CHARS),
            "stream": False,
            "options": {
                "temperature": self._safe_temperature(self.config.temperature),
                "num_predict": self._safe_max_tokens(self.config.max_tokens),
            },
        }

        async with session.post(
            f"{self._safe_ollama_host()}/api/generate",
            json=payload,
        ) as resp:
            status = resp.status
            if not isinstance(status, int) or isinstance(status, bool):
                raise RuntimeError("Ollama API error unknown: malformed status")
            if status != 200:
                try:
                    error_text = await resp.text()
                except VALIDATOR_RUNTIME_ERRORS:
                    error_text = "error"
                safe_error = self._parse_text(error_text, "error")[:200]
                raise RuntimeError(f"Ollama API error {status}: {safe_error}")

            data = await resp.json()
            if not isinstance(data, dict):
                return ""

            response = _safe_mapping_get(data, "response", "")
            return _safe_text(
                response,
                allow_multiline=True,
                limit=MAX_VALIDATION_RESPONSE_CHARS,
            )

    def _parse_response(self, response: str, finding_id: str) -> LLMValidation:
        """Parse LLM response into LLMValidation."""
        finding_id = self._parse_text(finding_id, "unknown")[:200] or "unknown"
        if not isinstance(response, str):
            response = ""
        elif len(response) > MAX_VALIDATION_RESPONSE_CHARS:
            response = ""
        else:
            try:
                response = response.strip()
            except (AttributeError, TypeError, ValueError, RuntimeError):
                response = ""
        try:
            stripped = response
            if not stripped:
                raise ValueError("No response")
            json_str = (
                stripped if stripped.startswith(("[", "{")) else extract_json_from_text(response)
            )
            if not json_str:
                raise ValueError("No JSON found in response")
            if not isinstance(json_str, str) or len(json_str) > MAX_VALIDATION_RESPONSE_CHARS:
                raise ValueError("Validation response JSON is too large")

            data = json.loads(repair_common_json_errors(json_str))
            if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict):
                data = data[0]
            if not isinstance(data, dict):
                return LLMValidation(
                    finding_id=finding_id,
                    result=ValidationResult.UNCERTAIN,
                    confidence=0.5,
                    reasoning="LLM validation response must be a JSON object",
                )
            if len(data) > MAX_VALIDATION_JSON_KEYS:
                raise ValueError("Validation response has too many keys")

            # Map result string to enum
            result_value = _safe_mapping_get(data, "result", "")
            result_str = (
                result_value.strip().lower().replace("-", "_")
                if isinstance(result_value, str)
                else ""
            )
            result_map = {
                "valid": ValidationResult.VALID,
                "likely_valid": ValidationResult.LIKELY_VALID,
                "uncertain": ValidationResult.UNCERTAIN,
                "likely_fp": ValidationResult.LIKELY_FP,
                "false_positive": ValidationResult.FALSE_POSITIVE,
            }
            result = result_map.get(result_str, ValidationResult.UNCERTAIN)

            # Handle is_valid field for simpler responses
            is_valid = _safe_mapping_get(data, "is_valid")
            if isinstance(is_valid, bool) and result_str not in result_map:
                result = ValidationResult.VALID if is_valid else ValidationResult.LIKELY_FP

            return LLMValidation(
                finding_id=finding_id,
                result=result,
                confidence=self._parse_confidence(_safe_mapping_get(data, "confidence", 0.5)),
                reasoning=self._parse_text(
                    _safe_mapping_get(data, "reasoning"), "No reasoning provided"
                )[:2000],
                suggested_severity=self._parse_suggested_severity(
                    _safe_mapping_get(data, "suggested_severity")
                ),
                remediation_hint=self._parse_optional_text(
                    _safe_mapping_get(data, "remediation_hint")
                ),
            )

        except (json.JSONDecodeError, RecursionError, RuntimeError, TypeError, ValueError) as e:
            logger.warning(f"Failed to parse LLM response: {e}")
            # Fallback: try to infer from text
            response_lower = response.lower()
            if "false positive" in response_lower or "not a vulnerability" in response_lower:
                result = ValidationResult.LIKELY_FP
                confidence = 0.6
            elif "valid" in response_lower or "real vulnerability" in response_lower:
                result = ValidationResult.LIKELY_VALID
                confidence = 0.6
            else:
                result = ValidationResult.UNCERTAIN
                confidence = 0.5

            return LLMValidation(
                finding_id=finding_id,
                result=result,
                confidence=confidence,
                reasoning=(self._parse_text(response, "Parse error") or "Parse error")[:200],
            )

    @staticmethod
    def _parse_confidence(value: Any, default: float = 0.5) -> float:
        """Parse confidence from LLM JSON without trusting malformed shapes."""
        if isinstance(value, bool):
            return default
        try:
            if isinstance(value, str):
                text = value.strip()
                if not text or any(_is_unsafe_text_char(ch) for ch in text):
                    return default
                value = text
            confidence = float(value)
        except (TypeError, ValueError):
            return default
        if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            return default
        return confidence

    @staticmethod
    def _parse_text(value: Any, default: str) -> str:
        """Return text only when the LLM field has a string shape."""
        if not isinstance(value, str):
            return default
        text = value.strip()
        if not text or any(_is_unsafe_text_char(ch) for ch in text):
            return default
        return text

    @classmethod
    def _parse_optional_text(cls, value: Any) -> Optional[str]:
        """Return optional text only when the LLM field has a string shape."""
        text = cls._parse_text(value, "").strip()
        if any(_is_unsafe_text_char(ch) for ch in text):
            return None
        if len(text) > 500:
            text = text[:500]
        return text or None

    @classmethod
    def _parse_suggested_severity(cls, value: Any) -> Optional[str]:
        """Return only known severity labels from optional LLM output."""
        text = cls._parse_optional_text(value)
        if not text:
            return None
        normalized = text.lower()
        return text.upper() if normalized in cls.SEVERITY_ORDER else None

    @staticmethod
    def _prompt_text(value: Any, *, limit: int) -> str:
        """Return prompt text for code/context while allowing normal multiline code."""
        if not isinstance(value, str):
            return ""
        text = value.strip()
        if not text or any(_is_unsafe_text_char(ch, allow_multiline=True) for ch in text):
            return ""
        return text[:limit]

    @staticmethod
    def _exception_reason(exc: BaseException) -> str:
        """Describe validation exceptions without trusting malformed __str__."""
        try:
            detail = str(exc)
        except Exception:
            detail = exc.__class__.__name__
        detail = detail.strip()
        if not detail or any(_is_unsafe_text_char(ch) for ch in detail):
            detail = exc.__class__.__name__
        return f"Exception: {detail}"[:200]

    @staticmethod
    def _parse_location_line(value: Any) -> Any:
        """Return a prompt-safe line value for known scalar line shapes."""
        if isinstance(value, bool):
            return 0
        if isinstance(value, int):
            return value if 0 <= value <= 10_000_000 else 0
        if isinstance(value, str):
            text = value.strip()
            if not text or any(_is_unsafe_text_char(ch) for ch in text) or not text.isdecimal():
                return 0
            return text if int(text) <= 10_000_000 else 0
        return 0

    @staticmethod
    def _normalize_ollama_host(value: Any, default: str = DEFAULT_OLLAMA_HOST) -> str:
        """Return an origin-only HTTP(S) Ollama host."""
        text = _safe_text(value, limit=2_000)
        if not text:
            return default
        parsed = urlparse(text)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return default
        if parsed.username or parsed.password or not parsed.hostname:
            return default
        if any(char.isspace() for char in parsed.netloc):
            return default
        if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
            return default
        return text.rstrip("/")

    @staticmethod
    def _normalize_model_name(value: Any, default: str = "deepseek-coder:6.7b") -> str:
        """Return a bounded Ollama model id without path or whitespace syntax."""
        text = _safe_text(value)
        if not text or len(text) > MAX_VALIDATOR_MODEL_NAME_CHARS:
            return default
        if not _OLLAMA_MODEL_RE.fullmatch(text):
            return default
        return text

    def _safe_ollama_host(self) -> str:
        return self._normalize_ollama_host(
            self._safe_getattr(self.config, "ollama_host", DEFAULT_OLLAMA_HOST)
        )

    @staticmethod
    def _safe_temperature(value: Any) -> float:
        if isinstance(value, bool):
            return ValidatorConfig().temperature
        try:
            normalized = float(value)
        except (TypeError, ValueError, OverflowError):
            return ValidatorConfig().temperature
        if not math.isfinite(normalized) or not 0 <= normalized <= 2:
            return ValidatorConfig().temperature
        return normalized

    @staticmethod
    def _safe_max_tokens(value: Any) -> int:
        if isinstance(value, bool):
            return ValidatorConfig().max_tokens
        try:
            normalized = int(value)
        except (TypeError, ValueError, OverflowError):
            return ValidatorConfig().max_tokens
        if normalized <= 0 or normalized > 16_384:
            return ValidatorConfig().max_tokens
        return normalized

    @staticmethod
    def _safe_timeout_seconds(value: Any) -> float:
        if isinstance(value, bool):
            return ValidatorConfig().timeout_seconds
        try:
            normalized = float(value)
        except (TypeError, ValueError, OverflowError):
            return ValidatorConfig().timeout_seconds
        if not math.isfinite(normalized) or normalized <= 0 or normalized > 600:
            return ValidatorConfig().timeout_seconds
        return normalized

    @classmethod
    def _normalize_config(cls, config: Any, default_config: ValidatorConfig) -> ValidatorConfig:
        """Copy known config fields from dataclass-compatible or config-like objects."""
        if config is None:
            return replace(default_config)
        if isinstance(config, ValidatorConfig):
            return replace(config)
        values = {
            field.name: cls._safe_getattr(config, field.name, getattr(default_config, field.name))
            for field in fields(ValidatorConfig)
        }
        try:
            return ValidatorConfig(**values)
        except (TypeError, ValueError):
            return replace(default_config)

    @classmethod
    def _safe_model_name(cls, value: Any) -> str:
        normalized = cls._normalize_model_name(value, "")
        return normalized if normalized != "" else ""

    @classmethod
    def _model_name_matches_configured_model(cls, configured: Any, available: Any) -> bool:
        configured_text = cls._safe_model_name(configured).lower()
        available_text = cls._safe_model_name(available).lower()
        if not configured_text or not available_text:
            return False
        if configured_text == available_text:
            return True
        configured_base = configured_text.split(":", 1)[0]
        available_base = available_text.split(":", 1)[0]
        return bool(configured_base and configured_base == available_base)

    @staticmethod
    def _parse_nonnegative_int(value: Any, default: int = 0) -> int:
        """Return non-negative integer metadata only for scalar numeric shapes."""
        if isinstance(value, bool):
            return default
        if isinstance(value, str):
            text = value.strip()
            if not text or any(_is_unsafe_text_char(ch) for ch in text):
                return default
            try:
                value = int(text)
            except (TypeError, ValueError):
                return default
        if isinstance(value, int):
            return value if value >= 0 else default
        if isinstance(value, float) and math.isfinite(value):
            return int(value) if value >= 0 else default
        return default

    @staticmethod
    def _safe_getattr(obj: Any, key: str, default: Any) -> Any:
        try:
            return getattr(obj, key, default)
        except (AttributeError, TypeError, RuntimeError, ValueError):
            return default

    async def validate_findings_batch(
        self,
        findings: List[Dict[str, Any]],
        code_contexts: Optional[Dict[str, str]] = None,
    ) -> Tuple[List[Dict[str, Any]], List[LLMValidation]]:
        """
        Validate a batch of findings.

        Args:
            findings: List of findings to validate
            code_contexts: Optional dict mapping file paths to code content

        Returns:
            Tuple of (validated_findings, validations)
        """
        if not self._config_enabled(self.config):
            return findings, []
        if not isinstance(findings, list):
            logger.warning("Skipping malformed findings container for LLM validation")
            return [], []
        safe_findings = _bounded_list(findings, limit=MAX_BATCH_FINDINGS)
        if not safe_findings:
            return [], []

        # Check availability
        try:
            available = await self.is_available()
        except VALIDATOR_RUNTIME_ERRORS as e:
            logger.warning("LLM availability check failed: %s", self._exception_reason(e))
            available = False
        if not available:
            logger.warning("LLM not available, skipping validation")
            return findings, []

        # Filter to findings that need validation
        to_validate = [f for f in safe_findings if self.should_validate(f)]

        if not to_validate:
            logger.info("No findings require LLM validation")
            return findings, []

        logger.info(f"Validating {len(to_validate)} findings with LLM...")

        validations = []
        validated_findings = []
        batch_size = self._safe_runtime_batch_size(
            self._safe_getattr(self.config, "batch_size", ValidatorConfig().batch_size)
        )

        # Process in batches
        for i in range(0, len(to_validate), batch_size):
            batch = to_validate[i : i + batch_size]

            # Validate batch concurrently
            tasks = []
            for finding in batch:
                location_value = _safe_mapping_get(finding, "location", {})
                location = location_value if isinstance(location_value, dict) else {}
                file_path = self._parse_text(_safe_mapping_get(location, "file"), "")
                snippet = self._parse_text(_safe_mapping_get(location, "snippet"), "")
                code_context = ""
                if isinstance(code_contexts, dict) and file_path:
                    code_context = self._parse_text(
                        _safe_mapping_get(code_contexts, file_path), ""
                    )[:1500]
                elif snippet:
                    code_context = snippet[:1500]

                tasks.append(self.validate_finding(finding, code_context))

            batch_validations = await asyncio.gather(*tasks, return_exceptions=True)

            for finding, validation in zip(batch, batch_validations, strict=False):
                if isinstance(validation, BaseException):
                    logger.warning("Validation exception: %s", self._exception_reason(validation))
                    validations.append(
                        LLMValidation(
                            finding_id=self._parse_text(
                                _safe_mapping_get(finding, "id"), "unknown"
                            ),
                            result=ValidationResult.UNCERTAIN,
                            confidence=0.5,
                            reasoning=self._exception_reason(validation),
                        )
                    )
                    validated_findings.append(finding)
                else:
                    validations.append(validation)

                    # Update finding based on validation
                    updated_finding = self._apply_validation(finding, validation)
                    if updated_finding:  # None means filtered out
                        validated_findings.append(updated_finding)

        # Add findings that didn't need validation
        not_validated = [f for f in safe_findings if not self.should_validate(f)]
        validated_findings.extend(not_validated)

        logger.info(
            f"LLM Validation: {self._validated_count} validated, "
            f"{self._fp_detected_count} FPs detected"
        )

        return validated_findings, validations

    @staticmethod
    def _safe_runtime_batch_size(value: Any) -> int:
        if isinstance(value, bool):
            return ValidatorConfig().batch_size
        try:
            normalized = int(value)
        except (TypeError, ValueError, OverflowError):
            return ValidatorConfig().batch_size
        if normalized <= 0:
            return ValidatorConfig().batch_size
        return min(normalized, 50)

    def _apply_validation(
        self,
        finding: Dict[str, Any],
        validation: LLMValidation,
    ) -> Optional[Dict[str, Any]]:
        """
        Apply validation result to finding.

        Returns None if finding should be filtered out.
        """
        result = self._safe_getattr(validation, "result", ValidationResult.UNCERTAIN)
        if not isinstance(result, ValidationResult):
            result = ValidationResult.UNCERTAIN
        confidence = self._parse_confidence(self._safe_getattr(validation, "confidence", 0.5))
        reasoning = self._parse_text(
            self._safe_getattr(validation, "reasoning", "No reasoning provided"),
            "No reasoning provided",
        )[:2000]
        suggested_severity = self._parse_suggested_severity(
            self._safe_getattr(validation, "suggested_severity", None)
        )
        validation_time_ms = self._parse_nonnegative_int(
            self._safe_getattr(validation, "validation_time_ms", 0)
        )

        # Filter out confirmed false positives
        if result == ValidationResult.FALSE_POSITIVE:
            logger.debug("Filtering FP: %s", _safe_mapping_get(finding, "id"))
            return None

        # Create updated finding
        try:
            updated = finding.copy() if isinstance(finding, dict) else {}
        except (AttributeError, TypeError, RuntimeError, ValueError):
            updated = {}

        # Add validation metadata
        updated["_llm_validation"] = {
            "result": result.value,
            "confidence": confidence,
            "reasoning": reasoning,
            "suggested_severity": suggested_severity,
            "validation_time_ms": validation_time_ms,
        }

        # Adjust confidence based on validation
        original_confidence = self._parse_confidence(
            _safe_mapping_get(finding, "confidence", 0.7), default=0.7
        )

        if result == ValidationResult.VALID:
            # Boost confidence for confirmed valid
            updated["confidence"] = min(original_confidence + 0.15, 0.99)
        elif result == ValidationResult.LIKELY_VALID:
            # Small boost
            updated["confidence"] = min(original_confidence + 0.05, 0.95)
        elif result == ValidationResult.LIKELY_FP:
            # Reduce confidence significantly
            updated["confidence"] = original_confidence * 0.6
        elif result == ValidationResult.UNCERTAIN:
            # Keep original confidence
            pass

        # Apply severity suggestion if provided and different
        if suggested_severity:
            suggested = suggested_severity.lower()
            current = self._parse_text(_safe_mapping_get(finding, "severity"), "").lower()
            if suggested in self.SEVERITY_ORDER and suggested != current:
                logger.debug(f"Severity adjustment suggested: {current} -> {suggested}")
                updated["_llm_validation"]["severity_adjusted"] = True
                # Don't auto-adjust severity, just note it

        return updated

    def get_statistics(self) -> Dict[str, Any]:
        """Get validator statistics."""
        validated_count = self._safe_counter(self._validated_count)
        fp_detected_count = min(self._safe_counter(self._fp_detected_count), validated_count)
        return {
            "validated_count": validated_count,
            "fp_detected_count": fp_detected_count,
            "fp_rate": (fp_detected_count / max(validated_count, 1)),
            "config": {
                "model": self._config_text(self.config, "model", ValidatorConfig().model),
                "min_severity": self._config_text(
                    self.config,
                    "min_severity_to_validate",
                    ValidatorConfig().min_severity_to_validate,
                ),
                "enabled": self._config_enabled(self.config),
            },
        }

    @staticmethod
    def _safe_counter(value: Any) -> int:
        """Return non-negative integer counters for mutable statistics."""
        if isinstance(value, bool):
            return 0
        try:
            counter = int(value)
        except (TypeError, ValueError, OverflowError):
            return 0
        return max(counter, 0)

    @staticmethod
    def _config_text(config: Any, key: str, default: str) -> str:
        """Read config text fields without trusting the container shape."""
        value = LLMFindingValidator._safe_getattr(config, key, default)
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-8", errors="replace")
            except Exception:
                return default
        if not isinstance(value, str):
            return default
        try:
            text = value.strip()
        except (AttributeError, TypeError, ValueError):
            return default
        if not text or any(_is_unsafe_text_char(ch) for ch in text):
            return default
        return text

    @staticmethod
    def _config_enabled(config: Any) -> bool:
        """Read the enabled flag without trusting the container shape."""
        return LLMFindingValidator._safe_getattr(config, "enabled", False) is True


# Convenience function for synchronous usage
def validate_findings_sync(
    findings: List[Dict[str, Any]],
    code_contexts: Optional[Dict[str, str]] = None,
    config: Optional[ValidatorConfig] = None,
) -> Tuple[List[Dict[str, Any]], List[LLMValidation]]:
    """
    Synchronous wrapper for finding validation.

    Args:
        findings: List of findings to validate
        code_contexts: Optional code context by file path
        config: Optional validator configuration

    Returns:
        Tuple of (validated_findings, validations)
    """
    if not isinstance(findings, list):
        logger.warning("Skipping malformed findings container for synchronous LLM validation")
        return [], []

    validator = LLMFindingValidator(config)

    async def run() -> Tuple[List[Dict[str, Any]], List[LLMValidation]]:
        try:
            return await validator.validate_findings_batch(findings, code_contexts)
        finally:
            await validator.close()

    return asyncio.run(run())


# Export
__all__ = [
    "LLMFindingValidator",
    "LLMValidation",
    "ValidationResult",
    "ValidatorConfig",
    "validate_findings_sync",
]
