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
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class LLMInterpreterConfig:
    """Configuration for LLM Report Interpreter."""
    model: str = "mistral:latest"
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
        """Check if Ollama is available with the configured model via HTTP API."""
        if self._available is not None:
            return self._available

        try:
            # Use HTTP API to check availability (works in Docker without CLI)
            url = f"{self.config.ollama_host}/api/tags"
            req = urllib.request.Request(url, method="GET")
            req.add_header("Content-Type", "application/json")

            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                models = [m.get("name", "") for m in data.get("models", [])]

                # Check if our model is available
                model_base = self.config.model.split(":")[0]
                model_found = any(
                    self.config.model in m or model_base in m
                    for m in models
                )

                if model_found:
                    self._available = True
                    logger.info(f"LLM Interpreter: {self.config.model} available via HTTP API")
                else:
                    # Ollama is running but model not found - will try to use anyway
                    self._available = True
                    logger.warning(
                        f"LLM Interpreter: Model {self.config.model} not found in {models}, "
                        "will attempt to use"
                    )

        except urllib.error.URLError as e:
            self._available = False
            logger.debug(f"LLM Interpreter not available (URL error): {e}")
        except Exception as e:
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
    # Premium Report Methods
    # =========================================================================

    def generate_attack_scenario(
        self,
        finding: Dict[str, Any],
        contract_code: str = ""
    ) -> Dict[str, Any]:
        """
        Generate detailed attack scenario for a vulnerability.

        Args:
            finding: The vulnerability finding
            contract_code: Optional contract source code

        Returns:
            Dict with attack scenario, steps, and impact
        """
        if not self.is_available():
            return {}

        title = finding.get("title") or finding.get("type") or "Unknown"
        severity = finding.get("severity", "unknown").upper()
        description = finding.get("description", "")[:800]
        location = finding.get("location", {})

        if isinstance(location, dict):
            loc_str = f"{location.get('file', 'unknown')}:{location.get('line', '?')}"
        else:
            loc_str = str(location)

        code_context = ""
        if contract_code:
            code_context = f"\nRELEVANT CODE:\n```solidity\n{contract_code[:1200]}\n```"

        prompt = f"""You are a smart contract security researcher creating an attack scenario for a security report.

VULNERABILITY:
- Title: {title}
- Severity: {severity}
- Location: {loc_str}
- Description: {description}
{code_context}

TASK: Create a detailed attack scenario in JSON format:

{{
  "scenario_description": "Brief narrative of how an attacker would exploit this (50-80 words)",
  "prerequisites": ["What the attacker needs before exploiting"],
  "attack_steps": [
    "Step 1: Specific action",
    "Step 2: Specific action",
    "Step 3: ..."
  ],
  "expected_outcome": "What the attacker achieves",
  "financial_impact": "Estimated impact (e.g., 'Total loss of contract funds', 'Up to X ETH at risk')",
  "difficulty": "Low/Medium/High - difficulty for attacker"
}}

Return ONLY valid JSON. Be specific to this vulnerability, not generic.

JSON:"""

        response = self._call_llm(prompt)
        if not response:
            return {}

        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start == -1 or json_end == 0:
                return {}

            return json.loads(response[json_start:json_end])
        except (json.JSONDecodeError, Exception) as e:
            logger.error(f"Error parsing attack scenario: {e}")
            return {}

    def generate_code_remediation(
        self,
        finding: Dict[str, Any],
        contract_code: str
    ) -> Dict[str, Any]:
        """
        Generate code remediation with before/after diff.

        Args:
            finding: The vulnerability finding
            contract_code: Contract source code

        Returns:
            Dict with vulnerable code, fixed code, and explanation
        """
        if not self.is_available() or not contract_code:
            return {}

        title = finding.get("title") or finding.get("type") or "Unknown"
        description = finding.get("description", "")[:500]
        location = finding.get("location", {})

        if isinstance(location, dict):
            line = location.get("line", 0)
        else:
            line = 0

        # Extract relevant code section
        lines = contract_code.split('\n')
        start = max(0, line - 10)
        end = min(len(lines), line + 15)
        code_excerpt = '\n'.join(lines[start:end])

        prompt = f"""You are a Solidity security expert providing code remediation.

VULNERABILITY: {title}
DESCRIPTION: {description}

CODE AROUND LINE {line}:
```solidity
{code_excerpt}
```

TASK: Provide code remediation in JSON format:

{{
  "vulnerable_code": "The specific vulnerable code snippet (just the problematic lines)",
  "fixed_code": "The corrected code with the vulnerability fixed",
  "diff": "A git-style diff showing the changes (use - for removed, + for added)",
  "explanation": "Brief explanation of the fix (30-50 words)",
  "effort": "Low/Medium/High - implementation effort",
  "fix_time": "Estimated time (e.g., '30 min', '1-2 hours')"
}}

Return ONLY valid JSON. Provide working Solidity code.

JSON:"""

        response = self._call_llm(prompt)
        if not response:
            return {}

        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start == -1 or json_end == 0:
                return {}

            return json.loads(response[json_start:json_end])
        except (json.JSONDecodeError, Exception) as e:
            logger.error(f"Error parsing code remediation: {e}")
            return {}

    def generate_deployment_recommendation(
        self,
        findings: List[Dict[str, Any]],
        summary: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate deployment recommendation (GO/NO-GO/CONDITIONAL).

        Args:
            findings: List of findings
            summary: Summary with severity counts

        Returns:
            Dict with recommendation, justification, and action items
        """
        if not self.is_available():
            return {
                "recommendation": "UNKNOWN",
                "justification": "LLM not available for analysis",
                "action_items": []
            }

        critical = summary.get("critical", 0)
        high = summary.get("high", 0)
        medium = summary.get("medium", 0)
        low = summary.get("low", 0)
        total = len(findings)

        # Get top issues
        top_issues = []
        for f in findings[:8]:
            severity = f.get("severity", "unknown").upper()
            title = f.get("title") or f.get("type") or "Unknown"
            top_issues.append(f"[{severity}] {title}")

        issues_text = "\n".join(top_issues) if top_issues else "No issues found"

        prompt = f"""You are a senior security auditor making a deployment recommendation.

AUDIT RESULTS:
- Critical vulnerabilities: {critical}
- High severity: {high}
- Medium severity: {medium}
- Low severity: {low}
- Total issues: {total}

TOP FINDINGS:
{issues_text}

TASK: Provide deployment recommendation in JSON format:

{{
  "recommendation": "GO" or "NO-GO" or "CONDITIONAL",
  "justification": "Clear explanation for the recommendation (50-80 words)",
  "risk_level": "Critical/High/Medium/Low",
  "action_items": [
    "Specific action 1 before deployment",
    "Specific action 2",
    "..."
  ],
  "conditions": ["If CONDITIONAL, list conditions that must be met"],
  "timeline": "Recommended timeline for fixes before re-assessment"
}}

Criteria:
- GO: No critical, max 1 high (if easily fixable), few medium issues
- CONDITIONAL: Some high/medium issues that need attention but aren't blockers
- NO-GO: Any critical, multiple high severity, or systemic security issues

Return ONLY valid JSON.

JSON:"""

        response = self._call_llm(prompt)
        if not response:
            return {
                "recommendation": "CONDITIONAL",
                "justification": "Unable to generate LLM recommendation",
                "action_items": ["Review findings manually"]
            }

        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start == -1 or json_end == 0:
                return {
                    "recommendation": "CONDITIONAL",
                    "justification": "Unable to parse LLM response",
                    "action_items": ["Review findings manually"]
                }

            return json.loads(response[json_start:json_end])
        except (json.JSONDecodeError, Exception) as e:
            logger.error(f"Error parsing deployment recommendation: {e}")
            return {
                "recommendation": "CONDITIONAL",
                "justification": f"Parse error: {str(e)[:50]}",
                "action_items": ["Review findings manually"]
            }

    def generate_premium_finding_analysis(
        self,
        finding: Dict[str, Any],
        contract_code: str = ""
    ) -> Dict[str, Any]:
        """
        Generate comprehensive premium analysis for a single finding.

        Combines attack scenario, code remediation, and interpretation.

        Args:
            finding: The vulnerability finding
            contract_code: Optional contract source code

        Returns:
            Dict with all premium analysis components
        """
        result = {
            "finding_id": finding.get("id", "UNK"),
            "title": finding.get("title") or finding.get("type") or "Unknown",
            "severity": finding.get("severity", "Medium"),
        }

        # Generate attack scenario for critical/high findings
        if finding.get("severity", "").lower() in ("critical", "high"):
            attack_scenario = self.generate_attack_scenario(finding, contract_code)
            if attack_scenario:
                result["attack_scenario"] = attack_scenario.get("scenario_description", "")
                result["attack_steps"] = attack_scenario.get("attack_steps", [])
                result["attack_difficulty"] = attack_scenario.get("difficulty", "Unknown")

        # Generate code remediation if code is provided
        if contract_code:
            remediation = self.generate_code_remediation(finding, contract_code)
            if remediation:
                result["remediation_code"] = remediation.get("diff", "")
                result["remediation_effort"] = remediation.get("effort", "Medium")
                result["fix_time"] = remediation.get("fix_time", "Unknown")

        return result

    # =========================================================================
    # Private Helper Methods
    # =========================================================================

    def _call_llm(self, prompt: str) -> Optional[str]:
        """Call Ollama LLM via HTTP API with retry logic."""
        url = f"{self.config.ollama_host}/api/generate"

        payload = json.dumps({
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            }
        }).encode("utf-8")

        for attempt in range(1, self.config.retry_attempts + 1):
            try:
                req = urllib.request.Request(url, data=payload, method="POST")
                req.add_header("Content-Type", "application/json")

                with urllib.request.urlopen(req, timeout=self.config.timeout) as response:
                    data = json.loads(response.read().decode())
                    result = data.get("response", "").strip()

                    if result:
                        return result

                    logger.warning(f"LLM call attempt {attempt}: empty response")

            except urllib.error.URLError as e:
                logger.warning(f"LLM call attempt {attempt} URL error: {e}")
            except TimeoutError:
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


def generate_premium_report_insights(
    findings: List[Dict[str, Any]],
    summary: Dict[str, Any],
    contract_name: str,
    contract_code: str = "",
    config: Optional[LLMInterpreterConfig] = None
) -> Dict[str, Any]:
    """
    Generate comprehensive LLM insights for premium audit reports.

    Includes all standard insights plus:
    - Deployment recommendation (GO/NO-GO/CONDITIONAL)
    - Attack scenarios for critical/high findings
    - Code remediation suggestions with diffs
    - Enhanced prioritization with effort estimates

    Usage:
        insights = generate_premium_report_insights(findings, summary, "MyContract", code)
        if insights["available"]:
            print(insights["deployment_recommendation"])
            print(insights["attack_scenarios"])
    """
    interpreter = LLMReportInterpreter(config)

    if not interpreter.is_available():
        return {"available": False}

    # Get standard insights
    standard = generate_llm_report_insights(findings, summary, contract_name, contract_code, config)
    if not standard.get("available"):
        return standard

    # Generate deployment recommendation
    deployment = interpreter.generate_deployment_recommendation(findings, summary)

    # Generate attack scenarios for critical/high findings
    critical_high = [f for f in findings if f.get("severity", "").lower() in ("critical", "high")]
    attack_scenarios = []
    for finding in critical_high[:3]:  # Limit to top 3
        scenario = interpreter.generate_attack_scenario(finding, contract_code)
        if scenario:
            attack_scenarios.append({
                "finding_id": finding.get("id", "UNK"),
                "title": finding.get("title") or finding.get("type", "Unknown"),
                **scenario
            })

    # Generate code remediations if code is provided
    code_remediations = []
    if contract_code:
        for finding in findings[:5]:  # Limit to top 5
            remediation = interpreter.generate_code_remediation(finding, contract_code)
            if remediation:
                code_remediations.append({
                    "finding_id": finding.get("id", "UNK"),
                    "title": finding.get("title") or finding.get("type", "Unknown"),
                    **remediation
                })

    # Add effort estimates to remediation priority
    enhanced_priority = []
    for item in standard.get("remediation_priority", []):
        item["effort"] = "Medium"  # Default
        for finding in findings:
            if finding.get("title") == item.get("title"):
                # Estimate effort based on category
                category = finding.get("category", "").lower()
                if "reentrancy" in category or "access" in category:
                    item["effort"] = "High"
                elif "visibility" in category or "pragma" in category:
                    item["effort"] = "Low"
                break
        enhanced_priority.append(item)

    return {
        **standard,
        "deployment_recommendation": deployment.get("recommendation", "CONDITIONAL"),
        "deployment_justification": deployment.get("justification", ""),
        "deployment_risk_level": deployment.get("risk_level", "Medium"),
        "deployment_action_items": deployment.get("action_items", []),
        "deployment_conditions": deployment.get("conditions", []),
        "deployment_timeline": deployment.get("timeline", ""),
        "attack_scenarios": attack_scenarios,
        "code_remediations": code_remediations,
        "remediation_priority": enhanced_priority,
    }


__all__ = [
    "LLMReportInterpreter",
    "LLMInterpreterConfig",
    "generate_llm_report_insights",
    "generate_premium_report_insights",
]
