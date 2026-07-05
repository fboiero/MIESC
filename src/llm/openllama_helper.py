"""
OpenLLaMA Helper - Sovereign LLM Integration for MIESC v3.5.0
==============================================================

Provides intelligent post-processing of security analysis results using
Ollama/deepseek-coder. Can be used by any adapter across all 7 layers.

Key Features:
- 100% sovereign (no external APIs)
- DPGA compliant
- Enhances findings with natural language explanations
- Prioritizes vulnerabilities intelligently
- Generates remediation advice
- Explains technical output in accessible language

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: November 11, 2025
Version: 1.0.0
"""

import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from src.security.llm_output_validator import (
    extract_json_from_text,
    repair_common_json_errors,
)

logger = logging.getLogger(__name__)

OLLAMA_RUNTIME_ERRORS = (
    FileNotFoundError,
    OSError,
    RuntimeError,
    TimeoutError,
    subprocess.SubprocessError,
)
LLM_PROCESSING_ERRORS = (AttributeError, KeyError, TypeError, ValueError, RuntimeError)
MAX_PRIORITY_RESPONSE_CHARS = 20_000
MAX_PRIORITY_TEXT_CHARS = 1_000
MAX_ANALYZE_RESPONSE_CHARS = 4_000
MAX_REMEDIATION_RESPONSE_CHARS = 4_000
MAX_GENERATE_RESPONSE_BYTES = 64 * 1024
MAX_OLLAMA_MODEL_NAME_CHARS = 256
DEFAULT_OLLAMA_HOST = "http://localhost:11434"
MIN_LLM_TIMEOUT_SECONDS = 1.0
MAX_LLM_TIMEOUT_SECONDS = 600.0
MAX_LLM_RETRY_ATTEMPTS = 10


@dataclass
class LLMConfig:
    """Configuration for LLM calls."""

    model: str = "qwen2.5-coder:14b"
    temperature: float = 0.1  # Low for precise technical analysis
    max_tokens: int = 4000
    timeout: int = 120  # 2 minutes default
    retry_attempts: int = 2
    retry_delay: float = 1.0


class OpenLLaMAHelper:
    """
    Helper class for integrating Ollama LLM across MIESC adapters.

    Usage:
        helper = OpenLLaMAHelper()
        if helper.is_available():
            enhanced = helper.enhance_findings(findings, contract_code)
    """

    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or LLMConfig()
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        """Check if Ollama is available with the configured model."""
        if self._available is not None:
            return self._available

        try:
            result = subprocess.run(["ollama", "list"], capture_output=True, timeout=5, text=True)

            returncode = self._subprocess_returncode(result)
            model_list = self._subprocess_text(result, "stdout")

            if self._successful_returncode(returncode) and self._ollama_model_available(
                self.config.model, model_list
            ):
                self._available = True
                logger.info(f"OpenLLaMA: {self.config.model} available")
            else:
                self._available = False
                stderr = self._subprocess_text(result, "stderr", limit=500)
                detail = f": {stderr}" if stderr else ""
                logger.warning(f"OpenLLaMA: {self.config.model} not found{detail}")

        except OLLAMA_RUNTIME_ERRORS as e:
            self._available = False
            logger.debug(f"OpenLLaMA not available: {e}")

        return self._available

    def enhance_findings(
        self, findings: List[Dict[str, Any]], context: str, adapter_name: str
    ) -> List[Dict[str, Any]]:
        """
        Enhance findings with LLM-generated insights.

        Args:
            findings: List of findings from adapter
            context: Contract code or relevant context
            adapter_name: Name of the adapter generating findings

        Returns:
            Enhanced findings with additional 'llm_insights' field
        """
        if not isinstance(findings, list):
            return findings
        if not self.is_available() or not findings:
            return findings

        try:
            valid_findings = [finding for finding in findings if isinstance(finding, dict)]
            if not valid_findings:
                return findings
            prompt_context = context if isinstance(context, str) else ""
            prompt_adapter_name = adapter_name if isinstance(adapter_name, str) else "adapter"

            # Select top findings to process (avoid overwhelming LLM)
            top_findings = sorted(
                valid_findings,
                key=lambda f: self._severity_score(f.get("severity", "LOW")),
                reverse=True,
            )[
                :5
            ]  # Top 5 most severe

            for finding in top_findings:
                insights = self._generate_insights(finding, prompt_context, prompt_adapter_name)
                if insights:
                    finding["llm_insights"] = insights
                    finding["llm_enhanced"] = True

            return findings

        except LLM_PROCESSING_ERRORS as e:
            logger.error(f"Error enhancing findings: {e}")
            return findings

    def explain_technical_output(self, technical_output: str, adapter_name: str) -> str:
        """
        Explain technical tool output in accessible language.

        Args:
            technical_output: Raw technical output from tool
            adapter_name: Name of the tool/adapter

        Returns:
            Human-readable explanation
        """
        fallback_output = self._prompt_text(technical_output)
        if not self.is_available():
            return fallback_output

        prompt = f"""You are a security expert. Explain this technical output from {self._prompt_text(adapter_name, default='adapter')} in clear, accessible language.

TECHNICAL OUTPUT:
{self._prompt_text(technical_output, limit=2000)}  # Truncate to fit context

INSTRUCTIONS:
1. Summarize what the tool found
2. Explain the implications in simple terms
3. Suggest next steps
4. Keep it concise (3-5 sentences)

OUTPUT (plain text):"""

        response = self._call_llm(prompt)
        return self._llm_text_response(response) or fallback_output

    def prioritize_findings(
        self, findings: List[Dict[str, Any]], contract_code: str
    ) -> List[Dict[str, Any]]:
        """
        Use LLM to intelligently prioritize findings based on context.

        Args:
            findings: List of findings
            contract_code: Contract source code

        Returns:
            Findings with updated 'priority' field (1-10, 10=highest)
        """
        if not isinstance(findings, list):
            return findings
        if not self.is_available() or not findings:
            return findings

        try:
            # Create summary of findings
            findings_summary = self._create_findings_summary(findings[:10])

            prompt = f"""Analyze these security findings for a smart contract and assign priority scores (1-10, 10=critical).

CONTRACT CONTEXT:
{self._prompt_text(contract_code, limit=1000)}  # First 1000 chars

FINDINGS:
{findings_summary}

INSTRUCTIONS:
1. Consider severity, exploitability, and business impact
2. Prioritize findings that could lead to fund loss
3. Deprioritize informational/style issues
4. Output JSON array with [finding_index, priority_score]

OUTPUT (JSON only):
{{
  "priorities": [
    {{"index": 0, "priority": 9, "reason": "Critical reentrancy"}},
    ...
  ]
}}"""

            response = self._call_llm(prompt)
            if response:
                priorities = self._parse_priorities(response)
                if not isinstance(priorities, dict):
                    return findings
                for idx, priority_data in priorities.items():
                    if (
                        0 <= idx < len(findings)
                        and isinstance(findings[idx], dict)
                        and isinstance(priority_data, dict)
                    ):
                        priority = priority_data.get("priority", 5)
                        reason = priority_data.get("reason", "")
                        findings[idx]["llm_priority"] = (
                            priority
                            if isinstance(priority, int)
                            and not isinstance(priority, bool)
                            and 1 <= priority <= 10
                            else 5
                        )
                        findings[idx]["llm_reason"] = reason if isinstance(reason, str) else ""

            return findings

        except LLM_PROCESSING_ERRORS as e:
            logger.error(f"Error prioritizing findings: {e}")
            return findings

    def generate_remediation_advice(self, finding: Dict[str, Any], contract_code: str) -> str:
        """
        Generate specific remediation advice for a finding.

        Args:
            finding: Single finding dict
            contract_code: Contract source code

        Returns:
            Remediation advice string
        """
        if not self.is_available():
            return self._recommendation_fallback(finding)

        normalized_finding = finding if isinstance(finding, dict) else {}
        prompt = f"""Generate specific remediation advice for this vulnerability.

VULNERABILITY:
Title: {self._prompt_text(self._mapping_get(normalized_finding, 'title'), default='Unknown')}
Severity: {self._prompt_text(self._mapping_get(normalized_finding, 'severity'), default='UNKNOWN')}
Description: {self._prompt_text(self._mapping_get(normalized_finding, 'description'))}
Location: {self._prompt_location(self._mapping_get(normalized_finding, 'location'))}

CONTRACT CODE (excerpt):
{self._prompt_text(contract_code, limit=1500)}

INSTRUCTIONS:
1. Provide specific code-level fix recommendations
2. Suggest best practices to follow
3. Mention relevant OpenZeppelin contracts if applicable
4. Include example code snippet if helpful
5. Keep response under 200 words

REMEDIATION ADVICE:"""

        response = self._call_llm(prompt)
        return self._llm_text_response(
            response, limit=MAX_REMEDIATION_RESPONSE_CHARS
        ) or self._recommendation_fallback(finding)

    # ============================================================================
    # PRIVATE HELPER METHODS
    # ============================================================================

    @staticmethod
    def _ollama_model_available(model: Any, model_list: Any) -> bool:
        """Return true only for exact model names from `ollama list` output."""
        model_name = OpenLLaMAHelper._ollama_model_name(model)
        if model_name is None:
            return False
        return model_name in OpenLLaMAHelper._ollama_list_model_names(model_list)

    @staticmethod
    def _ollama_list_model_names(model_list: Any) -> tuple[str, ...]:
        """Extract bounded model names from Ollama list output."""
        if not isinstance(model_list, str):
            return ()

        try:
            lines = model_list.splitlines()
        except (AttributeError, TypeError, ValueError, RuntimeError):
            return ()

        names = []
        for line in lines:
            if not isinstance(line, str):
                continue
            try:
                columns = line.split(maxsplit=1)
            except (AttributeError, TypeError, ValueError, RuntimeError):
                continue
            if not columns:
                continue
            model_name = OpenLLaMAHelper._ollama_model_name(columns[0])
            if model_name is not None and model_name != "NAME":
                names.append(model_name)
        return tuple(names)

    @staticmethod
    def _ollama_model_name(value: Any) -> Optional[str]:
        """Normalize a single Ollama model identifier without accepting malformed text."""
        if not isinstance(value, str):
            return None
        model = value.strip()
        if not model or len(model) > MAX_OLLAMA_MODEL_NAME_CHARS:
            return None
        if any(char.isspace() for char in model):
            return None
        return model

    @staticmethod
    def _subprocess_returncode(result: Any) -> Optional[int]:
        """Return a real integer subprocess return code, rejecting bools and bad accessors."""
        try:
            returncode = result.returncode
        except (AttributeError, TypeError, ValueError, RuntimeError):
            return None
        if isinstance(returncode, int) and not isinstance(returncode, bool):
            return returncode
        return None

    @staticmethod
    def _successful_returncode(returncode: Any) -> bool:
        """Return true only for a valid successful process return code."""
        return isinstance(returncode, int) and not isinstance(returncode, bool) and returncode == 0

    @staticmethod
    def _subprocess_text(result: Any, attr: str, limit: int = 20_000) -> str:
        """Read subprocess text attributes without trusting malformed result objects."""
        try:
            value = getattr(result, attr)
        except (AttributeError, TypeError, ValueError, RuntimeError):
            return ""
        if not isinstance(value, str):
            return ""
        return value[:limit]

    def _call_llm(self, prompt: str) -> Optional[str]:
        """Call Ollama LLM via HTTP API (clean output, no ANSI escapes)."""
        import urllib.error
        import urllib.parse
        import urllib.request

        host = self._ollama_generate_host(os.environ.get("OLLAMA_HOST", DEFAULT_OLLAMA_HOST))
        timeout = self._bounded_number(
            getattr(self.config, "timeout", LLMConfig.timeout),
            default=LLMConfig.timeout,
            minimum=MIN_LLM_TIMEOUT_SECONDS,
            maximum=MAX_LLM_TIMEOUT_SECONDS,
        )
        retry_attempts = int(
            self._bounded_number(
                getattr(self.config, "retry_attempts", LLMConfig.retry_attempts),
                default=LLMConfig.retry_attempts,
                minimum=1,
                maximum=MAX_LLM_RETRY_ATTEMPTS,
            )
        )
        retry_delay = self._bounded_number(
            getattr(self.config, "retry_delay", LLMConfig.retry_delay),
            default=LLMConfig.retry_delay,
            minimum=0.0,
            maximum=60.0,
        )

        if not host.startswith(("http://", "https://")):
            host = f"http://{host}"
        parsed_host = urllib.parse.urlparse(host)
        if parsed_host.scheme not in {"http", "https"} or not parsed_host.netloc:
            host = DEFAULT_OLLAMA_HOST
        host = host.rstrip("/")

        payload = self._ollama_generate_payload(prompt)

        for attempt in range(1, retry_attempts + 1):
            try:
                req = urllib.request.Request(
                    f"{host}/api/generate",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    raw_body = resp.read()
                    if isinstance(raw_body, str):
                        payload_size = len(raw_body.encode("utf-8"))
                    elif isinstance(raw_body, (bytes, bytearray)):
                        payload_size = len(raw_body)
                    else:
                        continue
                    if payload_size > MAX_GENERATE_RESPONSE_BYTES:
                        logger.warning("LLM generate response payload too large to parse safely")
                        continue

                    response = self._ollama_generate_response_text(raw_body)
                    if response:
                        return response

            except (urllib.error.URLError, urllib.error.HTTPError) as e:
                logger.warning(f"LLM HTTP attempt {attempt} failed: {e}")
            except (
                json.JSONDecodeError,
                OSError,
                RuntimeError,
                TimeoutError,
                TypeError,
                ValueError,
            ) as e:
                logger.error(f"LLM call attempt {attempt} error: {e}")

            if attempt < retry_attempts:
                time.sleep(retry_delay)

        return None

    @staticmethod
    def _ollama_generate_response_text(raw_body: Any) -> Optional[str]:
        """Extract a non-empty Ollama response string from bounded JSON/line JSON."""
        try:
            data = json.loads(raw_body)
        except (json.JSONDecodeError, TypeError, ValueError, RuntimeError):
            return OpenLLaMAHelper._ollama_generate_line_response_text(raw_body)
        if not isinstance(data, dict):
            return None
        try:
            raw_response = data.get("response", "")
        except (AttributeError, TypeError, ValueError, RuntimeError):
            return None
        if not isinstance(raw_response, str):
            return None
        try:
            response = raw_response.strip()
        except (AttributeError, TypeError, ValueError, RuntimeError):
            return None
        return response or None

    @staticmethod
    def _ollama_generate_line_response_text(raw_body: Any) -> Optional[str]:
        """Extract text from newline-delimited Ollama response fragments."""
        if not isinstance(raw_body, (str, bytes, bytearray)):
            return None

        try:
            lines = raw_body.splitlines()
        except (AttributeError, TypeError, ValueError, RuntimeError):
            return None

        fragments = []
        for line in lines:
            if not line:
                continue
            try:
                data = json.loads(line)
            except (json.JSONDecodeError, TypeError, ValueError, RuntimeError):
                continue
            if not isinstance(data, dict):
                continue
            try:
                raw_response = data.get("response", "")
            except (AttributeError, TypeError, ValueError, RuntimeError):
                continue
            if not isinstance(raw_response, str):
                continue
            try:
                has_text = bool(raw_response.strip())
            except (AttributeError, TypeError, ValueError, RuntimeError):
                continue
            if has_text:
                fragments.append(raw_response)

        response_text = "".join(fragments).strip()
        return response_text or None

    @staticmethod
    def _bounded_number(value: Any, *, default: float, minimum: float, maximum: float) -> float:
        """Return a finite numeric config value within a defensive range."""
        if isinstance(value, bool):
            return float(default)
        try:
            normalized = float(value)
        except (TypeError, ValueError):
            return float(default)
        if not minimum <= normalized <= maximum:
            return float(default)
        return normalized

    def _ollama_generate_payload(self, prompt: Any) -> bytes:
        """Build a JSON-safe Ollama generate request body."""
        model = getattr(self.config, "model", LLMConfig.model)
        if not isinstance(model, str) or not model.strip():
            model = LLMConfig.model

        options = {
            "temperature": self._bounded_number(
                LLMConfig.temperature,
                default=LLMConfig.temperature,
                minimum=0.0,
                maximum=2.0,
            ),
            "num_predict": int(
                self._bounded_number(
                    500,
                    default=500,
                    minimum=1,
                    maximum=128_000,
                )
            ),
        }
        body = {
            "model": model,
            "prompt": prompt if isinstance(prompt, str) else "",
            "stream": False,
            "options": options,
        }
        encoded = json.dumps(body, allow_nan=False).encode()
        parsed = json.loads(encoded)
        if not isinstance(parsed, dict) or not isinstance(parsed.get("options"), dict):
            raise ValueError("Malformed Ollama request body")
        return encoded

    @staticmethod
    def _ollama_generate_host(value: Any) -> str:
        """Return a stripped endpoint string or the default Ollama host."""
        if not isinstance(value, str):
            return DEFAULT_OLLAMA_HOST
        endpoint = value.strip()
        return endpoint or DEFAULT_OLLAMA_HOST

    def _generate_insights(
        self, finding: Dict[str, Any], context: str, adapter_name: str
    ) -> Optional[str]:
        """Generate insights for a single finding."""
        finding_json = self._prompt_finding_json(finding)
        prompt = f"""Analyze this security finding from {self._prompt_text(adapter_name, default='adapter')} and provide expert insights.

FINDING:
{finding_json}

CONTRACT CONTEXT:
{self._prompt_text(context, limit=1000)}

Provide 2-3 sentence expert analysis focusing on:
1. Why this matters
2. Potential attack scenarios
3. Business impact

INSIGHTS:"""

        return self._llm_text_response(self._call_llm(prompt), limit=MAX_ANALYZE_RESPONSE_CHARS)

    def _severity_score(self, severity: Any) -> int:
        """Convert severity string to numeric score."""
        severity_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        if not isinstance(severity, str):
            return 0
        return severity_map.get(severity.upper(), 0)

    def _recommendation_fallback(self, finding: Dict[str, Any]) -> str:
        """Return a string remediation fallback for malformed finding shapes."""
        if not isinstance(finding, dict):
            return "Review and address the identified issue"
        recommendation = self._mapping_get(finding, "recommendation")
        if isinstance(recommendation, str):
            recommendation = recommendation.strip()
            if recommendation:
                return recommendation[:MAX_REMEDIATION_RESPONSE_CHARS]
        return "Review and address the identified issue"

    @staticmethod
    def _llm_text_response(value: Any, limit: Optional[int] = None) -> Optional[str]:
        """Return stripped LLM text while rejecting malformed response shapes."""
        if not isinstance(value, str):
            return None
        response = value.strip()
        if limit is not None and len(response) > limit:
            response = response[:limit]
        return response or None

    @staticmethod
    def _mapping_get(mapping: Any, key: str, default: Any = None) -> Any:
        """Read optional mapping fields without trusting malformed dict subclasses."""
        if not isinstance(mapping, dict):
            return default
        try:
            return mapping.get(key, default)
        except (AttributeError, TypeError, ValueError, RuntimeError, RecursionError):
            return default

    @staticmethod
    def _priority_item_text(value: Any) -> str:
        """Return bounded text for optional priority item string fields."""
        if not isinstance(value, str):
            return ""
        return value[:MAX_PRIORITY_TEXT_CHARS]

    def _create_findings_summary(self, findings: List[Dict[str, Any]]) -> str:
        """Create concise summary of findings for LLM."""
        summary_lines = []
        for idx, finding in enumerate(findings):
            if not isinstance(finding, dict):
                finding = {}
            severity = self._summary_field_text(
                finding.get("severity"), default="UNKNOWN", limit=40
            )
            title = self._summary_field_text(finding.get("title"), default="Unknown", limit=200)
            description = self._summary_field_text(finding.get("description"), limit=100)
            line = f"{idx}. [{severity}] {title} - {description}"
            summary_lines.append(line)
        return "\n".join(summary_lines)

    @staticmethod
    def _truncate_text(value: Any, limit: int) -> str:
        """Return a bounded string only when the input is textual."""
        if not isinstance(value, str):
            return ""
        return value[:limit]

    @staticmethod
    def _summary_field_text(value: Any, default: str = "", limit: Optional[int] = None) -> str:
        """Return bounded single-line text for finding summaries."""
        if not isinstance(value, str):
            return default
        text = value if limit is None else value[:limit]
        return " ".join(text.split()) if text else default

    @staticmethod
    def _prompt_text(value: Any, default: str = "", limit: Optional[int] = None) -> str:
        """Return stable prompt text without serializing malformed field shapes."""
        if not isinstance(value, str):
            return default
        text = value if limit is None else value[:limit]
        return text if text else default

    @classmethod
    def _prompt_location(cls, value: Any) -> str:
        """Render supported location shapes without leaking Python reprs."""
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            normalized = {str(key): cls._prompt_json_value(item) for key, item in value.items()}
            return json.dumps(normalized, sort_keys=True)
        return "{}"

    @classmethod
    def _prompt_finding_json(cls, finding: Any) -> str:
        """Render a finding as bounded JSON with unsupported field shapes defaulted."""
        try:
            if not isinstance(finding, dict):
                normalized: Dict[str, Any] = {}
            else:
                normalized = {
                    str(key): cls._prompt_json_value(value) for key, value in finding.items()
                }
        except (AttributeError, TypeError, ValueError, RuntimeError, RecursionError):
            normalized = {}
        return json.dumps(normalized, indent=2, sort_keys=True)

    @classmethod
    def _prompt_json_value(cls, value: Any) -> Any:
        """Keep JSON-safe scalar values and recursively default malformed shapes."""
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        if isinstance(value, list):
            return [cls._prompt_json_value(item) for item in value]
        if isinstance(value, dict):
            return {str(key): cls._prompt_json_value(item) for key, item in value.items()}
        return ""

    def _parse_priorities(self, llm_response: str) -> Dict[int, Dict[str, Any]]:
        """Parse priority assignments from LLM response."""
        try:
            if not isinstance(llm_response, str):
                return {}
            if len(llm_response) > MAX_PRIORITY_RESPONSE_CHARS:
                logger.warning("Priority response too large to parse safely")
                return {}

            stripped = llm_response.strip()
            json_str = stripped if stripped.startswith("[") else extract_json_from_text(llm_response)
            if json_str is None:
                json_str = stripped

            if not json_str:
                return {}

            parsed = json.loads(repair_common_json_errors(json_str))
            if not isinstance(parsed, dict):
                return {}

            priority_items = parsed.get("priorities", [])
            if not isinstance(priority_items, list):
                return {}

            priorities = {}
            for item in priority_items:
                if not isinstance(item, dict):
                    continue
                idx = item.get("index")
                if isinstance(idx, int) and not isinstance(idx, bool):
                    priority = item.get("priority", 5)
                    reason = self._priority_item_text(item.get("reason", ""))
                    priorities[idx] = {
                        "priority": priority
                        if isinstance(priority, int)
                        and not isinstance(priority, bool)
                        and 1 <= priority <= 10
                        else 5,
                        "reason": reason,
                    }

            return priorities

        except (AttributeError, TypeError, ValueError, json.JSONDecodeError) as e:
            logger.error(f"Error parsing priorities: {e}")
            return {}


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================


def enhance_findings_with_llm(
    findings: List[Dict[str, Any]],
    contract_code: str,
    adapter_name: str,
    config: Optional[LLMConfig] = None,
) -> List[Dict[str, Any]]:
    """
    Convenience function to enhance findings with LLM.

    Usage:
        enhanced = enhance_findings_with_llm(findings, code, "mythril")
    """
    helper = OpenLLaMAHelper(config)
    return helper.enhance_findings(findings, contract_code, adapter_name)


def explain_technical_output(
    output: str, adapter_name: str, config: Optional[LLMConfig] = None
) -> str:
    """
    Convenience function to explain technical output.

    Usage:
        explanation = explain_technical_output(mythril_output, "mythril")
    """
    helper = OpenLLaMAHelper(config)
    return helper.explain_technical_output(output, adapter_name)


def prioritize_findings(
    findings: List[Dict[str, Any]], contract_code: str, config: Optional[LLMConfig] = None
) -> List[Dict[str, Any]]:
    """
    Convenience function to prioritize findings.

    Usage:
        prioritized = prioritize_findings(findings, contract_code)
    """
    helper = OpenLLaMAHelper(config)
    return helper.prioritize_findings(findings, contract_code)


def generate_remediation_advice(
    finding: Dict[str, Any], contract_code: str, config: Optional[LLMConfig] = None
) -> str:
    """
    Convenience function to generate remediation advice.

    Usage:
        advice = generate_remediation_advice(finding, contract_code)
    """
    helper = OpenLLaMAHelper(config)
    return helper.generate_remediation_advice(finding, contract_code)


__all__ = [
    "OpenLLaMAHelper",
    "LLMConfig",
    "enhance_findings_with_llm",
    "explain_technical_output",
    "prioritize_findings",
    "generate_remediation_advice",
]
