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
from typing import Any, Dict, List, Optional, cast

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

            if result.returncode == 0 and self.config.model in result.stdout:
                self._available = True
                logger.info(f"OpenLLaMA: {self.config.model} available")
            else:
                self._available = False
                logger.warning(f"OpenLLaMA: {self.config.model} not found")

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
        if not self.is_available() or not findings:
            return findings

        try:
            # Select top findings to process (avoid overwhelming LLM)
            top_findings = sorted(
                findings, key=lambda f: self._severity_score(f.get("severity", "LOW")), reverse=True
            )[
                :5
            ]  # Top 5 most severe

            for finding in top_findings:
                insights = self._generate_insights(finding, context, adapter_name)
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
        if not self.is_available():
            return technical_output

        prompt = f"""You are a security expert. Explain this technical output from {adapter_name} in clear, accessible language.

TECHNICAL OUTPUT:
{technical_output[:2000]}  # Truncate to fit context

INSTRUCTIONS:
1. Summarize what the tool found
2. Explain the implications in simple terms
3. Suggest next steps
4. Keep it concise (3-5 sentences)

OUTPUT (plain text):"""

        response = self._call_llm(prompt)
        return response if response else technical_output

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
        if not self.is_available() or not findings:
            return findings

        try:
            # Create summary of findings
            findings_summary = self._create_findings_summary(findings[:10])

            prompt = f"""Analyze these security findings for a smart contract and assign priority scores (1-10, 10=critical).

CONTRACT CONTEXT:
{contract_code[:1000]}  # First 1000 chars

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
                for idx, priority_data in priorities.items():
                    if 0 <= idx < len(findings):
                        findings[idx]["llm_priority"] = priority_data["priority"]
                        findings[idx]["llm_reason"] = priority_data["reason"]

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
            return cast(str, finding.get("recommendation", "Review and address the identified issue"))

        prompt = f"""Generate specific remediation advice for this vulnerability.

VULNERABILITY:
Title: {finding.get('title', 'Unknown')}
Severity: {finding.get('severity', 'UNKNOWN')}
Description: {finding.get('description', '')}
Location: {finding.get('location', {})}

CONTRACT CODE (excerpt):
{contract_code[:1500]}

INSTRUCTIONS:
1. Provide specific code-level fix recommendations
2. Suggest best practices to follow
3. Mention relevant OpenZeppelin contracts if applicable
4. Include example code snippet if helpful
5. Keep response under 200 words

REMEDIATION ADVICE:"""

        response = self._call_llm(prompt)
        return response if response else finding.get("recommendation", "")

    # ============================================================================
    # PRIVATE HELPER METHODS
    # ============================================================================

    def _call_llm(self, prompt: str) -> Optional[str]:
        """Call Ollama LLM via HTTP API (clean output, no ANSI escapes)."""
        import urllib.error
        import urllib.request

        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        if not host.startswith("http"):
            host = f"http://{host}"

        payload = json.dumps(
            {
                "model": self.config.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "num_predict": 500,
                },
            }
        ).encode()

        for attempt in range(1, self.config.retry_attempts + 1):
            try:
                req = urllib.request.Request(
                    f"{host}/api/generate",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                    data = json.loads(resp.read())
                    response = data.get("response", "").strip()
                    if response:
                        return cast(Optional[str], response)

            except (urllib.error.URLError, urllib.error.HTTPError) as e:
                logger.warning(f"LLM HTTP attempt {attempt} failed: {e}")
            except (json.JSONDecodeError, OSError, TimeoutError, ValueError) as e:
                logger.error(f"LLM call attempt {attempt} error: {e}")

            if attempt < self.config.retry_attempts:
                time.sleep(self.config.retry_delay)

        return None

    def _generate_insights(
        self, finding: Dict[str, Any], context: str, adapter_name: str
    ) -> Optional[str]:
        """Generate insights for a single finding."""
        prompt = f"""Analyze this security finding from {adapter_name} and provide expert insights.

FINDING:
{json.dumps(finding, indent=2, sort_keys=True)}

CONTRACT CONTEXT:
{context[:1000]}

Provide 2-3 sentence expert analysis focusing on:
1. Why this matters
2. Potential attack scenarios
3. Business impact

INSIGHTS:"""

        return self._call_llm(prompt)

    def _severity_score(self, severity: str) -> int:
        """Convert severity string to numeric score."""
        severity_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        return severity_map.get(severity.upper(), 0)

    def _create_findings_summary(self, findings: List[Dict[str, Any]]) -> str:
        """Create concise summary of findings for LLM."""
        summary_lines = []
        for idx, finding in enumerate(findings):
            line = f"{idx}. [{finding.get('severity', 'UNKNOWN')}] {finding.get('title', 'Unknown')} - {finding.get('description', '')[:100]}"
            summary_lines.append(line)
        return "\n".join(summary_lines)

    def _parse_priorities(self, llm_response: str) -> Dict[int, Dict[str, Any]]:
        """Parse priority assignments from LLM response."""
        try:
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
                if idx is not None:
                    priorities[idx] = {
                        "priority": item.get("priority", 5),
                        "reason": item.get("reason", ""),
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
