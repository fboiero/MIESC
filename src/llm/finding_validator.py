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
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

from src.security.llm_output_validator import (
    extract_json_from_text,
    repair_common_json_errors,
)

logger = logging.getLogger(__name__)

VALIDATOR_RUNTIME_ERRORS = (
    aiohttp.ClientError,
    asyncio.TimeoutError,
    TimeoutError,
    OSError,
    RuntimeError,
    ValueError,
    json.JSONDecodeError,
)


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
        self.config = replace(config or default_config)

        # Environment values fill defaults, but an explicit caller config wins.
        if os.environ.get("OLLAMA_HOST") and self.config.ollama_host == default_config.ollama_host:
            self.config.ollama_host = os.environ["OLLAMA_HOST"]
        if os.environ.get("MIESC_LLM_MODEL") and self.config.model == default_config.model:
            self.config.model = os.environ["MIESC_LLM_MODEL"]
        if not isinstance(self.config.ollama_host, str) or not self.config.ollama_host.strip():
            self.config.ollama_host = default_config.ollama_host
        else:
            self.config.ollama_host = self.config.ollama_host.strip()
        if not isinstance(self.config.model, str) or not self.config.model.strip():
            self.config.model = default_config.model
        else:
            self.config.model = self.config.model.strip()
        if (
            isinstance(self.config.timeout_seconds, bool)
            or not isinstance(self.config.timeout_seconds, (int, float))
            or self.config.timeout_seconds <= 0
        ):
            self.config.timeout_seconds = default_config.timeout_seconds
        if (
            isinstance(self.config.batch_size, bool)
            or not isinstance(self.config.batch_size, int)
            or self.config.batch_size <= 0
        ):
            self.config.batch_size = default_config.batch_size
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
            timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)
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
            async with session.get(f"{self.config.ollama_host}/api/tags") as resp:
                status = resp.status
                if not isinstance(status, int) or isinstance(status, bool) or status != 200:
                    return False
                data = await resp.json()
                if not isinstance(data, dict):
                    return False

                models_value = data.get("models", [])
                models = models_value if isinstance(models_value, list) else []
                model_names = [
                    name.strip()
                    for model in models
                    if isinstance(model, dict) and isinstance(name := model.get("name"), str)
                    and name.strip()
                ]
                # Check if our model is available
                model_base = self.config.model.split(":")[0]
                return any(model_base in name for name in model_names)
        except VALIDATOR_RUNTIME_ERRORS as e:
            logger.debug(f"Ollama not available: {e}")
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

        severity_value = finding.get("severity", "")
        severity = severity_value.lower() if isinstance(severity_value, str) else ""
        min_severity = self.config.min_severity_to_validate.lower()

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

        finding_id = self._parse_text(finding.get("id"), "unknown")
        location_value = finding.get("location", {})
        location = location_value if isinstance(location_value, dict) else {}
        message = self._parse_text(
            finding.get("message"),
            self._parse_text(finding.get("description"), "No message"),
        )

        # Build prompt
        prompt = self.VALIDATION_PROMPT.format(
            finding_type=self._parse_text(finding.get("type"), "unknown"),
            severity=self._parse_text(finding.get("severity"), "unknown"),
            tool=self._parse_text(finding.get("tool"), "unknown"),
            file=self._parse_text(location.get("file"), "unknown"),
            line=self._parse_location_line(location.get("line")),
            message=message,
            code_snippet=code_context[:1500] if code_context else "Not available",
            contract_context=(
                self._parse_text(contract_context, "")[:500] if contract_context else "Not available"
            ),
        )

        try:
            # Call Ollama API
            response = await self._call_ollama(prompt)

            # Parse response
            validation = self._parse_response(response, finding_id)
            validation.validation_time_ms = int((time.time() - start_time) * 1000)

            self._validated_count += 1
            if validation.result in [ValidationResult.LIKELY_FP, ValidationResult.FALSE_POSITIVE]:
                self._fp_detected_count += 1

            logger.debug(
                f"Validated {finding_id}: {validation.result.value} "
                f"(confidence: {validation.confidence:.2f})"
            )

            return validation

        except VALIDATOR_RUNTIME_ERRORS as e:
            logger.warning(f"LLM validation failed for {finding_id}: {e}")
            return LLMValidation(
                finding_id=finding_id,
                result=ValidationResult.UNCERTAIN,
                confidence=0.5,
                reasoning=f"Validation failed: {str(e)}",
                validation_time_ms=int((time.time() - start_time) * 1000),
            )

    async def _call_ollama(self, prompt: str) -> str:
        """Call Ollama API and return response."""
        session = await self._get_session()

        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            },
        }

        async with session.post(
            f"{self.config.ollama_host}/api/generate",
            json=payload,
        ) as resp:
            if resp.status != 200:
                error_text = await resp.text()
                raise RuntimeError(f"Ollama API error {resp.status}: {error_text}")

            data = await resp.json()
            if not isinstance(data, dict):
                return ""

            response = data.get("response", "")
            return response if isinstance(response, str) else ""

    def _parse_response(self, response: str, finding_id: str) -> LLMValidation:
        """Parse LLM response into LLMValidation."""
        finding_id = self._parse_text(finding_id, "unknown")[:200] or "unknown"
        response = self._parse_text(response, "")
        try:
            stripped = response.strip()
            json_str = stripped if stripped.startswith("[") else extract_json_from_text(response)
            if not json_str:
                raise ValueError("No JSON found in response")

            data = json.loads(repair_common_json_errors(json_str))
            if (
                isinstance(data, list)
                and len(data) == 1
                and isinstance(data[0], dict)
            ):
                data = data[0]
            if not isinstance(data, dict):
                return LLMValidation(
                    finding_id=finding_id,
                    result=ValidationResult.UNCERTAIN,
                    confidence=0.5,
                    reasoning="LLM validation response must be a JSON object",
                )

            # Map result string to enum
            result_value = data.get("result", "")
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
            is_valid = data.get("is_valid")
            if isinstance(is_valid, bool) and result_str not in result_map:
                result = ValidationResult.VALID if is_valid else ValidationResult.LIKELY_FP

            return LLMValidation(
                finding_id=finding_id,
                result=result,
                confidence=self._parse_confidence(data.get("confidence", 0.5)),
                reasoning=self._parse_text(data.get("reasoning"), "No reasoning provided")[:2000],
                suggested_severity=self._parse_suggested_severity(
                    data.get("suggested_severity")
                ),
                remediation_hint=self._parse_optional_text(data.get("remediation_hint")),
            )

        except (json.JSONDecodeError, ValueError) as e:
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
                if not text or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
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
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            return default
        return value

    @classmethod
    def _parse_optional_text(cls, value: Any) -> Optional[str]:
        """Return optional text only when the LLM field has a string shape."""
        text = cls._parse_text(value, "").strip()
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
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
    def _exception_reason(exc: BaseException) -> str:
        """Describe validation exceptions without trusting malformed __str__."""
        try:
            detail = str(exc)
        except Exception:
            detail = exc.__class__.__name__
        return f"Exception: {detail}"[:200]

    @staticmethod
    def _parse_location_line(value: Any) -> Any:
        """Return a prompt-safe line value for known scalar line shapes."""
        if isinstance(value, bool):
            return 0
        if isinstance(value, (int, str)):
            if isinstance(value, str):
                text = value.strip()
                if not text or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
                    return 0
                return text
            return value
        return 0

    @staticmethod
    def _parse_nonnegative_int(value: Any, default: int = 0) -> int:
        """Return non-negative integer metadata only for scalar numeric shapes."""
        if isinstance(value, bool):
            return default
        if isinstance(value, int):
            return value if value >= 0 else default
        if isinstance(value, float) and math.isfinite(value):
            return int(value) if value >= 0 else default
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
        if not self.config.enabled:
            return findings, []
        if not isinstance(findings, list):
            logger.warning("Skipping malformed findings container for LLM validation")
            return [], []

        # Check availability
        if not await self.is_available():
            logger.warning("LLM not available, skipping validation")
            return findings, []

        # Filter to findings that need validation
        to_validate = [f for f in findings if self.should_validate(f)]

        if not to_validate:
            logger.info("No findings require LLM validation")
            return findings, []

        logger.info(f"Validating {len(to_validate)} findings with LLM...")

        validations = []
        validated_findings = []

        # Process in batches
        for i in range(0, len(to_validate), self.config.batch_size):
            batch = to_validate[i : i + self.config.batch_size]

            # Validate batch concurrently
            tasks = []
            for finding in batch:
                location_value = finding.get("location", {})
                location = location_value if isinstance(location_value, dict) else {}
                file_path = self._parse_text(location.get("file"), "")
                snippet = self._parse_text(location.get("snippet"), "")
                code_context = ""
                if isinstance(code_contexts, dict) and file_path:
                    code_context = self._parse_text(code_contexts.get(file_path), "")[:1500]
                elif snippet:
                    code_context = snippet[:1500]

                tasks.append(self.validate_finding(finding, code_context))

            batch_validations = await asyncio.gather(*tasks, return_exceptions=True)

            for finding, validation in zip(batch, batch_validations, strict=False):
                if isinstance(validation, BaseException):
                    logger.warning("Validation exception: %s", self._exception_reason(validation))
                    validations.append(
                        LLMValidation(
                            finding_id=self._parse_text(finding.get("id"), "unknown"),
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
        not_validated = [f for f in findings if not self.should_validate(f)]
        validated_findings.extend(not_validated)

        logger.info(
            f"LLM Validation: {self._validated_count} validated, "
            f"{self._fp_detected_count} FPs detected"
        )

        return validated_findings, validations

    def _apply_validation(
        self,
        finding: Dict[str, Any],
        validation: LLMValidation,
    ) -> Optional[Dict[str, Any]]:
        """
        Apply validation result to finding.

        Returns None if finding should be filtered out.
        """
        # Filter out confirmed false positives
        if validation.result == ValidationResult.FALSE_POSITIVE:
            logger.debug(f"Filtering FP: {finding.get('id')}")
            return None

        # Create updated finding
        updated = finding.copy()

        # Add validation metadata
        updated["_llm_validation"] = {
            "result": validation.result.value,
            "confidence": validation.confidence,
            "reasoning": validation.reasoning,
            "suggested_severity": validation.suggested_severity,
            "validation_time_ms": self._parse_nonnegative_int(validation.validation_time_ms),
        }

        # Adjust confidence based on validation
        original_confidence = self._parse_confidence(finding.get("confidence", 0.7), default=0.7)

        if validation.result == ValidationResult.VALID:
            # Boost confidence for confirmed valid
            updated["confidence"] = min(original_confidence + 0.15, 0.99)
        elif validation.result == ValidationResult.LIKELY_VALID:
            # Small boost
            updated["confidence"] = min(original_confidence + 0.05, 0.95)
        elif validation.result == ValidationResult.LIKELY_FP:
            # Reduce confidence significantly
            updated["confidence"] = original_confidence * 0.6
        elif validation.result == ValidationResult.UNCERTAIN:
            # Keep original confidence
            pass

        # Apply severity suggestion if provided and different
        if validation.suggested_severity:
            suggested = validation.suggested_severity.lower()
            current = self._parse_text(finding.get("severity"), "").lower()
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
        if isinstance(value, bool) or not isinstance(value, int):
            return 0
        return max(value, 0)

    @staticmethod
    def _config_text(config: Any, key: str, default: str) -> str:
        """Read config text fields without trusting the container shape."""
        value = LLMFindingValidator._parse_text(getattr(config, key, default), default)
        if not isinstance(value, str):
            return default
        try:
            text = value.strip()
        except (AttributeError, TypeError, ValueError):
            return default
        if not text or any(ord(ch) < 32 for ch in text):
            return default
        return text

    @staticmethod
    def _config_enabled(config: Any) -> bool:
        """Read the enabled flag without trusting the container shape."""
        return getattr(config, "enabled", False) is True


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
