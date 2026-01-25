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
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum

import aiohttp

logger = logging.getLogger(__name__)


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
        self.config = config or ValidatorConfig()

        # Check for environment overrides
        if os.environ.get("OLLAMA_HOST"):
            self.config.ollama_host = os.environ["OLLAMA_HOST"]
        if os.environ.get("MIESC_LLM_MODEL"):
            self.config.model = os.environ["MIESC_LLM_MODEL"]

        self._session: Optional[aiohttp.ClientSession] = None
        self._validated_count = 0
        self._fp_detected_count = 0

        logger.info(
            f"LLM Validator initialized: model={self.config.model}, "
            f"host={self.config.ollama_host}"
        )

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def close(self):
        """Close the aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def is_available(self) -> bool:
        """Check if Ollama is available and the model is loaded."""
        try:
            session = await self._get_session()
            async with session.get(f"{self.config.ollama_host}/api/tags") as resp:
                if resp.status != 200:
                    return False
                data = await resp.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                # Check if our model is available
                model_base = self.config.model.split(":")[0]
                return any(model_base in m for m in models)
        except Exception as e:
            logger.debug(f"Ollama not available: {e}")
            return False

    def should_validate(self, finding: Dict[str, Any]) -> bool:
        """
        Determine if a finding should be validated by LLM.

        Args:
            finding: The finding to check

        Returns:
            True if should validate, False otherwise
        """
        if not self.config.enabled:
            return False

        severity = finding.get("severity", "").lower()
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

        finding_id = finding.get("id", "unknown")

        # Build prompt
        prompt = self.VALIDATION_PROMPT.format(
            finding_type=finding.get("type", "unknown"),
            severity=finding.get("severity", "unknown"),
            tool=finding.get("tool", "unknown"),
            file=finding.get("location", {}).get("file", "unknown"),
            line=finding.get("location", {}).get("line", 0),
            message=finding.get("message", finding.get("description", "No message")),
            code_snippet=code_context[:1500] if code_context else "Not available",
            contract_context=contract_context[:500] if contract_context else "Not available",
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

        except Exception as e:
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
                raise Exception(f"Ollama API error {resp.status}: {error_text}")

            data = await resp.json()
            return data.get("response", "")

    def _parse_response(self, response: str, finding_id: str) -> LLMValidation:
        """Parse LLM response into LLMValidation."""
        try:
            # Try to extract JSON from response
            json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
            if not json_match:
                raise ValueError("No JSON found in response")

            data = json.loads(json_match.group())

            # Map result string to enum
            result_str = data.get("result", "uncertain").lower()
            result_map = {
                "valid": ValidationResult.VALID,
                "likely_valid": ValidationResult.LIKELY_VALID,
                "uncertain": ValidationResult.UNCERTAIN,
                "likely_fp": ValidationResult.LIKELY_FP,
                "false_positive": ValidationResult.FALSE_POSITIVE,
            }
            result = result_map.get(result_str, ValidationResult.UNCERTAIN)

            # Handle is_valid field for simpler responses
            if "is_valid" in data and result_str not in result_map:
                result = ValidationResult.VALID if data["is_valid"] else ValidationResult.LIKELY_FP

            return LLMValidation(
                finding_id=finding_id,
                result=result,
                confidence=float(data.get("confidence", 0.5)),
                reasoning=data.get("reasoning", "No reasoning provided"),
                suggested_severity=data.get("suggested_severity"),
                remediation_hint=data.get("remediation_hint"),
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
                reasoning=response[:200] if response else "Parse error",
            )

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
            batch = to_validate[i:i + self.config.batch_size]

            # Validate batch concurrently
            tasks = []
            for finding in batch:
                file_path = finding.get("location", {}).get("file", "")
                code_context = ""
                if code_contexts and file_path:
                    code_context = code_contexts.get(file_path, "")
                elif finding.get("location", {}).get("snippet"):
                    code_context = finding["location"]["snippet"]

                tasks.append(self.validate_finding(finding, code_context))

            batch_validations = await asyncio.gather(*tasks, return_exceptions=True)

            for finding, validation in zip(batch, batch_validations):
                if isinstance(validation, Exception):
                    logger.warning(f"Validation exception: {validation}")
                    validations.append(LLMValidation(
                        finding_id=finding.get("id", "unknown"),
                        result=ValidationResult.UNCERTAIN,
                        confidence=0.5,
                        reasoning=f"Exception: {validation}",
                    ))
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
        }

        # Adjust confidence based on validation
        original_confidence = finding.get("confidence", 0.7)

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
            current = finding.get("severity", "").lower()
            if suggested != current:
                logger.debug(
                    f"Severity adjustment suggested: {current} -> {suggested}"
                )
                updated["_llm_validation"]["severity_adjusted"] = True
                # Don't auto-adjust severity, just note it

        return updated

    def get_statistics(self) -> Dict[str, Any]:
        """Get validator statistics."""
        return {
            "validated_count": self._validated_count,
            "fp_detected_count": self._fp_detected_count,
            "fp_rate": (
                self._fp_detected_count / max(self._validated_count, 1)
            ),
            "config": {
                "model": self.config.model,
                "min_severity": self.config.min_severity_to_validate,
                "enabled": self.config.enabled,
            },
        }


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
    validator = LLMFindingValidator(config)

    async def run():
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
