"""
LLM Report Interpreter - AI-Powered Report Enhancement for MIESC
================================================================

Interprets security findings using Ollama to generate:
- Executive summaries with business context
- Risk narratives in accessible language
- Critical finding interpretations with attack scenarios
- Prioritized remediation recommendations

Uses deepseek-coder:6.7b (configurable) via Ollama for 100% sovereign operation.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
Version: 1.0.0
"""

import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class LLMInterpreterConfig:
    """Configuration for LLM Report Interpreter."""
    model: str = "deepseek-coder:6.7b"
    ollama_host: str = "http://localhost:11434"
    temperature: float = 0.2  # Slightly creative for summaries
    max_tokens: int = 2000
    timeout: int = 180  # 3 minutes for longer interpretations
    retry_attempts: int = 2
    retry_delay: float = 2.0


class LLMReportInterpreter:
    """
    Interprets security findings using Ollama LLM for enhanced reporting.

    Usage:
        interpreter = LLMReportInterpreter()
        if interpreter.is_available():
            summary = interpreter.generate_executive_interpretation(findings, summary, "MyContract")
    """

    def __init__(self, config: Optional[LLMInterpreterConfig] = None):
        self.config = config or LLMInterpreterConfig()
        self._available: Optional[bool] = None

        # Check for environment overrides
        if os.environ.get("OLLAMA_HOST"):
            self.config.ollama_host = os.environ["OLLAMA_HOST"]
        if os.environ.get("MIESC_LLM_MODEL"):
            self.config.model = os.environ["MIESC_LLM_MODEL"]

    def is_available(self) -> bool:
        """Check if Ollama is available with the configured model."""
        if self._available is not None:
            return self._available

        try:
            # Set OLLAMA_HOST for the subprocess if configured
            env = os.environ.copy()
            if self.config.ollama_host and self.config.ollama_host != "http://localhost:11434":
                env["OLLAMA_HOST"] = self.config.ollama_host

            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                timeout=10,
                text=True,
                env=env
            )

            if result.returncode == 0:
                # Check if our model is available
                model_base = self.config.model.split(":")[0]
                if model_base in result.stdout or self.config.model in result.stdout:
                    self._available = True
                    logger.info(f"LLM Interpreter: {self.config.model} available")
                else:
                    # Model not pulled yet, try to check if ollama is running
                    self._available = True
                    logger.warning(f"LLM Interpreter: Model {self.config.model} not found, will attempt to use")
            else:
                self._available = False
                logger.warning("LLM Interpreter: Ollama not available")

        except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
            self._available = False
            logger.debug(f"LLM Interpreter not available: {e}")

        return self._available

    def generate_executive_interpretation(
        self,
        findings: List[Dict[str, Any]],
        summary: Dict[str, Any],
        contract_name: str
    ) -> str:
        """
        Generate an executive-level interpretation of the audit findings.

        Args:
            findings: List of findings from the audit
            summary: Summary dict with severity counts
            contract_name: Name of the audited contract

        Returns:
            Executive summary text suitable for non-technical stakeholders
        """
        if not self.is_available() or not findings:
            return ""

        # Prepare findings summary for the prompt
        critical = summary.get("critical", 0)
        high = summary.get("high", 0)
        medium = summary.get("medium", 0)
        low = summary.get("low", 0)
        total = len(findings)

        # Get top critical/high findings for context
        top_issues = []
        for f in findings[:5]:
            severity = f.get("severity", "unknown").upper()
            title = f.get("title") or f.get("type") or f.get("message", "Unknown")[:50]
            top_issues.append(f"- [{severity}] {title}")

        issues_text = "\n".join(top_issues) if top_issues else "No critical issues identified"

        prompt = f"""You are a senior blockchain security consultant writing an executive summary for a smart contract audit report.

CONTRACT: {contract_name}

FINDINGS SUMMARY:
- Critical: {critical}
- High: {high}
- Medium: {medium}
- Low: {low}
- Total Issues: {total}

TOP ISSUES:
{issues_text}

TASK: Write a concise executive summary (150-200 words) that:
1. States the overall security posture in business terms
2. Highlights the most significant risks and their potential business impact
3. Provides a clear recommendation on deployment readiness
4. Uses professional but accessible language for non-technical executives

Do NOT use technical jargon. Focus on business risk and financial implications.

EXECUTIVE SUMMARY:"""

        response = self._call_llm(prompt)
        return response if response else ""

    def generate_risk_narrative(
        self,
        summary: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> str:
        """
        Generate a risk narrative explaining the overall security posture.

        Args:
            summary: Summary dict with severity counts
            findings: List of findings

        Returns:
            Risk narrative text
        """
        if not self.is_available():
            return ""

        critical = summary.get("critical", 0)
        high = summary.get("high", 0)
        medium = summary.get("medium", 0)

        # Categorize findings by type
        categories = {}
        for f in findings:
            cat = f.get("category") or f.get("type", "General")
            categories[cat] = categories.get(cat, 0) + 1

        categories_text = "\n".join([f"- {cat}: {count} issues" for cat, count in sorted(categories.items(), key=lambda x: -x[1])[:8]])

        prompt = f"""You are a security analyst explaining audit results to a development team.

SEVERITY BREAKDOWN:
- Critical: {critical}
- High: {high}
- Medium: {medium}

ISSUE CATEGORIES:
{categories_text}

TASK: Write a risk assessment narrative (100-150 words) that:
1. Explains what these findings mean for the contract's security
2. Identifies the primary attack vectors based on the issue categories
3. Assesses the likelihood of exploitation
4. Recommends immediate actions

Keep it technical but understandable. Focus on actionable insights.

RISK NARRATIVE:"""

        response = self._call_llm(prompt)
        return response if response else ""

    def interpret_critical_findings(
        self,
        critical_findings: List[Dict[str, Any]],
        contract_code: str = ""
    ) -> List[Dict[str, Any]]:
        """
        Interpret critical/high findings with detailed context.

        Args:
            critical_findings: List of critical/high severity findings
            contract_code: Optional contract source code for context

        Returns:
            List of findings with added 'llm_interpretation' field
        """
        if not self.is_available() or not critical_findings:
            return critical_findings

        interpreted = []
        for finding in critical_findings[:5]:  # Limit to top 5
            title = finding.get("title") or finding.get("type") or "Unknown"
            description = finding.get("description", "")[:500]
            severity = finding.get("severity", "unknown").upper()
            location = finding.get("location", {})

            if isinstance(location, dict):
                loc_str = f"{location.get('file', 'unknown')}:{location.get('line', '?')}"
            else:
                loc_str = str(location)

            code_context = ""
            if contract_code:
                code_context = f"\nCONTRACT CODE EXCERPT:\n{contract_code[:1500]}"

            prompt = f"""Analyze this smart contract security finding and provide expert interpretation.

FINDING:
- Title: {title}
- Severity: {severity}
- Location: {loc_str}
- Description: {description}
{code_context}

TASK: Provide a brief analysis (80-100 words) covering:
1. Why this vulnerability is dangerous
2. A realistic attack scenario
3. Potential financial/operational impact
4. One key mitigation recommendation

Be specific and actionable. No generic advice.

ANALYSIS:"""

            interpretation = self._call_llm(prompt)

            interpreted.append({
                "title": title,
                "severity": severity,
                "location": loc_str,
                "original_description": description,
                "llm_interpretation": interpretation if interpretation else "Analysis not available",
            })

        return interpreted

    def suggest_remediation_priority(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Suggest prioritized remediation order with justification.

        Args:
            findings: List of findings to prioritize

        Returns:
            List of findings with priority order and justification
        """
        if not self.is_available() or not findings:
            return []

        # Prepare findings list for the prompt
        findings_text = []
        for i, f in enumerate(findings[:10], 1):
            title = f.get("title") or f.get("type") or "Unknown"
            severity = f.get("severity", "unknown").upper()
            desc = (f.get("description", "") or f.get("message", ""))[:100]
            findings_text.append(f"{i}. [{severity}] {title}: {desc}")

        findings_list = "\n".join(findings_text)

        prompt = f"""You are a security remediation specialist. Prioritize these smart contract vulnerabilities.

FINDINGS:
{findings_list}

TASK: Return a JSON array prioritizing these findings for remediation.
Consider: exploitability, business impact, fix complexity, dependencies between issues.

Output ONLY valid JSON in this format:
{{
  "priorities": [
    {{"index": 1, "priority": 1, "reason": "Brief justification"}},
    {{"index": 2, "priority": 2, "reason": "Brief justification"}}
  ]
}}

Highest priority = 1. Include all findings.

JSON:"""

        response = self._call_llm(prompt)
        if not response:
            return []

        try:
            # Extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1

            if json_start == -1 or json_end == 0:
                return []

            json_str = response[json_start:json_end]
            parsed = json.loads(json_str)

            priorities = []
            for item in parsed.get("priorities", []):
                idx = item.get("index", 0) - 1  # Convert to 0-based
                if 0 <= idx < len(findings):
                    f = findings[idx]
                    priorities.append({
                        "priority": item.get("priority", idx + 1),
                        "title": f.get("title") or f.get("type") or "Unknown",
                        "severity": f.get("severity", "unknown"),
                        "reason": item.get("reason", ""),
                    })

            return sorted(priorities, key=lambda x: x["priority"])

        except (json.JSONDecodeError, Exception) as e:
            logger.error(f"Error parsing priority response: {e}")
            return []

    def generate_tool_output_explanation(
        self,
        tool_name: str,
        tool_output: str
    ) -> str:
        """
        Explain technical tool output in accessible language.

        Args:
            tool_name: Name of the security tool
            tool_output: Raw output from the tool

        Returns:
            Human-readable explanation
        """
        if not self.is_available() or not tool_output:
            return ""

        prompt = f"""Explain this output from {tool_name} (a smart contract security tool) in plain language.

TOOL OUTPUT:
{tool_output[:2000]}

TASK: Provide a brief explanation (50-80 words) covering:
1. What the tool found
2. What it means for security
3. Any immediate concerns

Keep it simple and actionable.

EXPLANATION:"""

        response = self._call_llm(prompt)
        return response if response else ""

    # =========================================================================
    # Private Helper Methods
    # =========================================================================

    def _call_llm(self, prompt: str) -> Optional[str]:
        """Call Ollama LLM with retry logic."""
        env = os.environ.copy()
        if self.config.ollama_host and self.config.ollama_host != "http://localhost:11434":
            env["OLLAMA_HOST"] = self.config.ollama_host

        for attempt in range(1, self.config.retry_attempts + 1):
            try:
                result = subprocess.run(
                    ["ollama", "run", self.config.model, prompt],
                    capture_output=True,
                    timeout=self.config.timeout,
                    text=True,
                    env=env
                )

                if result.returncode == 0 and result.stdout:
                    return result.stdout.strip()

                logger.warning(f"LLM call attempt {attempt} failed: {result.stderr}")

            except subprocess.TimeoutExpired:
                logger.warning(f"LLM call attempt {attempt} timeout")
            except Exception as e:
                logger.error(f"LLM call attempt {attempt} error: {e}")

            if attempt < self.config.retry_attempts:
                time.sleep(self.config.retry_delay)

        return None


# =============================================================================
# Convenience Functions
# =============================================================================

def generate_llm_report_insights(
    findings: List[Dict[str, Any]],
    summary: Dict[str, Any],
    contract_name: str,
    contract_code: str = "",
    config: Optional[LLMInterpreterConfig] = None
) -> Dict[str, Any]:
    """
    Generate all LLM insights for a report in one call.

    Usage:
        insights = generate_llm_report_insights(findings, summary, "MyContract", code)
        if insights["available"]:
            print(insights["executive_summary"])
    """
    interpreter = LLMReportInterpreter(config)

    if not interpreter.is_available():
        return {"available": False}

    return {
        "available": True,
        "executive_summary": interpreter.generate_executive_interpretation(
            findings, summary, contract_name
        ),
        "risk_narrative": interpreter.generate_risk_narrative(summary, findings),
        "critical_interpretations": interpreter.interpret_critical_findings(
            [f for f in findings if f.get("severity", "").lower() in ("critical", "high")][:5],
            contract_code
        ),
        "remediation_priority": interpreter.suggest_remediation_priority(findings[:10]),
    }


__all__ = [
    "LLMReportInterpreter",
    "LLMInterpreterConfig",
    "generate_llm_report_insights",
]
