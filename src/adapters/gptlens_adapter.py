"""
GPTLens Adapter - Dual-Role LLM Vulnerability Detection (ICSE 2024)
====================================================================

Implements the GPTLens dual-role architecture for smart contract auditing:
  - Auditor LLM: Generates vulnerability findings from contract source
  - Critic LLM: Evaluates each finding to filter false positives

Based on: "GPTLens: Employing LLMs for Smart Contract Vulnerability Detection
via Dual-Role Interaction" (ICSE 2024)

The key insight from GPTLens is that using two separate LLM roles -
one to generate findings and another to critique them - significantly
reduces false positive rates compared to single-pass LLM analysis.

Architecture:
    Contract Source --> [Auditor LLM] --> Raw Findings
    Raw Findings --> [Critic LLM] --> Filtered Findings (FP removed)

Uses Ollama HTTP API for local LLM inference (DPGA-compliant, no API keys).
Auditor role uses deepseek-coder for code-level pattern detection.
Critic role uses codellama for logical reasoning and verification.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
Date: January 2026
Version: 1.0.0
"""

import hashlib
import json
import logging
import re
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.core.llm_config import get_ollama_host
from src.core.tool_protocol import (
    ToolAdapter,
    ToolCapability,
    ToolCategory,
    ToolMetadata,
    ToolStatus,
)

logger = logging.getLogger(__name__)

# ============================================================================
# Constants
# ============================================================================

# Ollama URL resolved at runtime via get_ollama_host()
# Supports OLLAMA_HOST env var and config/miesc.yaml

# Default models for each role
DEFAULT_AUDITOR_MODEL = "deepseek-coder"
DEFAULT_CRITIC_MODEL = "codellama"

# Timeouts (seconds)
OLLAMA_HEALTH_TIMEOUT = 5
AUDITOR_TIMEOUT = 300
CRITIC_TIMEOUT = 120

# Maximum contract size before truncation (characters)
MAX_CONTRACT_SIZE = 24000

# Cache TTL in seconds (24 hours)
CACHE_TTL = 86400

# SWC mappings for vulnerability types
VULNERABILITY_SWC_MAP = {
    "reentrancy": {"swc": "SWC-107", "cwe": "CWE-841", "owasp": "SC03"},
    "access_control": {"swc": "SWC-105", "cwe": "CWE-284", "owasp": "SC01"},
    "logic_error": {"swc": "SWC-110", "cwe": "CWE-670", "owasp": "SC04"},
    "oracle_manipulation": {"swc": "SWC-120", "cwe": "CWE-829", "owasp": "SC06"},
    "front_running": {"swc": "SWC-114", "cwe": "CWE-362", "owasp": "SC07"},
    "integer_overflow": {"swc": "SWC-101", "cwe": "CWE-190", "owasp": "SC02"},
    "unchecked_return": {"swc": "SWC-104", "cwe": "CWE-252", "owasp": "SC05"},
    "tx_origin": {"swc": "SWC-115", "cwe": "CWE-477", "owasp": "SC01"},
    "delegatecall": {"swc": "SWC-112", "cwe": "CWE-829", "owasp": "SC08"},
    "timestamp_dependence": {"swc": "SWC-116", "cwe": "CWE-330", "owasp": "SC09"},
}

# Severity levels ordered by priority
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

# Pattern-based detection keywords for fallback analysis
PATTERN_KEYWORDS = {
    "reentrancy": [
        ".call{value:", ".call(", "transfer(", "send(",
        "external call", "re-entrancy", "reentrant",
    ],
    "access_control": [
        "onlyOwner", "require(msg.sender", "admin", "auth",
        "modifier", "role", "permission",
    ],
    "logic_error": [
        "logic", "business logic", "incorrect", "wrong calculation",
        "invariant", "assertion",
    ],
    "oracle_manipulation": [
        "oracle", "price feed", "chainlink", "getPrice",
        "latestRoundData", "twap",
    ],
    "front_running": [
        "front-run", "frontrun", "sandwich", "mev",
        "slippage", "deadline",
    ],
    "integer_overflow": [
        "overflow", "underflow", "SafeMath", "unchecked {",
        "uint256", "uint8",
    ],
    "unchecked_return": [
        "unchecked", "return value", "low-level call",
        "(bool success", "require(success",
    ],
    "tx_origin": [
        "tx.origin", "phishing", "origin",
    ],
    "delegatecall": [
        "delegatecall", "proxy", "storage collision",
        "implementation", "upgradeable",
    ],
    "timestamp_dependence": [
        "block.timestamp", "block.number", "now",
        "timestamp", "time-dependent",
    ],
}

# Default severity for vulnerability types
DEFAULT_SEVERITY_MAP = {
    "reentrancy": "Critical",
    "access_control": "High",
    "logic_error": "High",
    "oracle_manipulation": "High",
    "front_running": "Medium",
    "integer_overflow": "High",
    "unchecked_return": "Medium",
    "tx_origin": "Medium",
    "delegatecall": "High",
    "timestamp_dependence": "Low",
}


# ============================================================================
# Auditor Prompt
# ============================================================================

AUDITOR_PROMPT_TEMPLATE = """You are an expert smart contract security auditor \
performing a comprehensive security review.

Your task is to analyze the following Solidity smart contract for security \
vulnerabilities with the depth and rigor of a professional audit firm.

VULNERABILITY CATEGORIES TO CHECK:
1. Reentrancy (SWC-107): External calls before state updates
2. Access Control (SWC-105): Missing or incorrect access restrictions
3. Logic Errors (SWC-110): Flawed business logic, incorrect calculations
4. Oracle Manipulation (SWC-120): Price feed manipulation, stale data
5. Front-Running (SWC-114): Transaction ordering dependence
6. Integer Overflow/Underflow (SWC-101): Arithmetic issues
7. Unchecked Return Values (SWC-104): Ignored call results
8. tx.origin Authentication (SWC-115): Phishing via tx.origin
9. Delegatecall Injection (SWC-112): Storage collision, proxy issues
10. Timestamp Dependence (SWC-116): Block timestamp manipulation

ANALYSIS METHODOLOGY:
- Trace each function's control flow carefully
- Identify all external calls and state modifications
- Check the ordering of effects (checks-effects-interactions)
- Verify access control on sensitive functions
- Analyze arithmetic operations for overflow potential
- Check for proper input validation
- Review event emissions and error handling

CONTRACT SOURCE CODE:
```solidity
{contract_code}
```

OUTPUT FORMAT (strict JSON):
{{
    "findings": [
        {{
            "type": "vulnerability_category",
            "severity": "Critical|High|Medium|Low",
            "confidence": 0.85,
            "title": "Short descriptive title",
            "description": "Detailed technical description of the vulnerability",
            "function": "affectedFunction",
            "line": 42,
            "attack_scenario": "Step-by-step exploitation scenario",
            "impact": "What an attacker could achieve",
            "recommendation": "Specific remediation guidance",
            "swc_id": "SWC-XXX"
        }}
    ]
}}

IMPORTANT RULES:
- Report ONLY vulnerabilities that actually exist in THIS contract
- Do NOT report generic best practices that are not violated
- Include specific line numbers and function names when possible
- Assess confidence honestly (0.0 to 1.0)
- Respond with ONLY valid JSON, no additional text outside the JSON"""


# ============================================================================
# Critic Prompt
# ============================================================================

CRITIC_PROMPT_TEMPLATE = """You are an independent smart contract security \
reviewer acting as a Critic. Your job is to evaluate whether a reported \
vulnerability finding is a TRUE POSITIVE or a FALSE POSITIVE.

You must be rigorous and objective. Many automated tools produce false \
positives. Your role is to verify each finding against the actual code.

REPORTED FINDING:
- Type: {finding_type}
- Severity: {finding_severity}
- Title: {finding_title}
- Description: {finding_description}
- Function: {finding_function}
- Line: {finding_line}
- Attack Scenario: {finding_attack}

RELEVANT CONTRACT CODE:
```solidity
{contract_code}
```

EVALUATION CRITERIA:
1. CODE EXISTENCE: Does the reported code pattern actually exist?
2. EXPLOITABILITY: Can the vulnerability actually be exploited?
3. MITIGATION CHECK: Are there existing guards/mitigations in the code?
4. CONTEXT ANALYSIS: Does the surrounding code prevent exploitation?
5. SEVERITY ACCURACY: Is the reported severity appropriate?

RESPOND WITH ONLY ONE OF:
- "TRUE_POSITIVE" if the finding is valid and exploitable
- "FALSE_POSITIVE" if the finding is incorrect or not exploitable

Then provide a brief explanation (1-2 sentences) of your reasoning.

Your verdict:"""


class GPTLensAdapter(ToolAdapter):
    """
    GPTLens dual-role LLM adapter for smart contract vulnerability detection.

    Implements the two-phase architecture from the ICSE 2024 paper:
    Phase 1 (Auditor): deepseek-coder scans contract for vulnerabilities
    Phase 2 (Critic): codellama reviews each finding to filter false positives

    This dual-role approach achieves significantly better precision than
    single-pass LLM analysis by leveraging adversarial verification.

    All inference runs locally via Ollama HTTP API. No external API keys
    or cloud services required (DPGA-compliant, sovereign execution).
    """

    def __init__(
        self,
        auditor_model: str = DEFAULT_AUDITOR_MODEL,
        critic_model: str = DEFAULT_CRITIC_MODEL,
        ollama_url: str = None,
    ):
        """
        Initialize GPTLens adapter.

        Args:
            auditor_model: Ollama model name for the Auditor role
            critic_model: Ollama model name for the Critic role
            ollama_url: Base URL for Ollama HTTP API
        """
        super().__init__()
        self._auditor_model = auditor_model
        self._critic_model = critic_model
        self._ollama_url = ollama_url or get_ollama_host()
        self._generate_url = f"{self._ollama_url}/api/generate"
        self._cache_dir = Path.home() / ".miesc" / "gptlens_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._max_retries = 2
        self._retry_delay = 2

    # ========================================================================
    # ToolAdapter Interface Implementation
    # ========================================================================

    def get_metadata(self) -> ToolMetadata:
        """Return GPTLens tool metadata."""
        return ToolMetadata(
            name="gptlens",
            version="1.0.0",
            category=ToolCategory.AI_ANALYSIS,
            author="Fernando Boiero <fboiero@frvm.utn.edu.ar>",
            license="AGPL-3.0",
            homepage="https://arxiv.org/abs/2310.01152",
            repository="https://github.com/GPTLens/GPTLens",
            documentation="https://arxiv.org/abs/2310.01152",
            installation_cmd=(
                "curl -fsSL https://ollama.com/install.sh | sh && "
                "ollama pull deepseek-coder && "
                "ollama pull codellama"
            ),
            capabilities=[
                ToolCapability(
                    name="dual_role_analysis",
                    description=(
                        "Dual-role LLM vulnerability detection with "
                        "Auditor-Critic architecture for FP reduction"
                    ),
                    supported_languages=["solidity"],
                    detection_types=[
                        "reentrancy",
                        "access_control",
                        "logic_error",
                        "oracle_manipulation",
                        "front_running",
                        "integer_overflow",
                        "unchecked_return",
                        "tx_origin",
                        "delegatecall",
                        "timestamp_dependence",
                    ],
                ),
                ToolCapability(
                    name="false_positive_filtering",
                    description=(
                        "Critic LLM evaluates each finding to reduce "
                        "false positive rate via adversarial verification"
                    ),
                    supported_languages=["solidity"],
                    detection_types=["false_positive_reduction"],
                ),
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True,
        )

    def is_available(self) -> ToolStatus:
        """
        Check if Ollama is running and accessible at localhost:11434.

        Performs an HTTP GET to the Ollama health endpoint to verify
        the service is up and responsive.

        Returns:
            ToolStatus indicating availability
        """
        try:
            req = urllib.request.Request(
                self._ollama_url,
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=OLLAMA_HEALTH_TIMEOUT) as resp:
                if resp.status == 200:
                    logger.info("GPTLens: Ollama is available at %s", self._ollama_url)
                    return ToolStatus.AVAILABLE
                else:
                    logger.warning(
                        "GPTLens: Ollama returned status %d", resp.status
                    )
                    return ToolStatus.CONFIGURATION_ERROR
        except urllib.error.URLError as e:
            logger.info("GPTLens: Ollama not reachable at %s: %s", self._ollama_url, e)
            return ToolStatus.NOT_INSTALLED
        except Exception as e:
            logger.error("GPTLens: Error checking Ollama availability: %s", e)
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Execute GPTLens dual-role analysis on a Solidity contract.

        Phase 1 (Auditor): Sends contract to deepseek-coder with a detailed
        security audit prompt. Parses structured JSON findings.

        Phase 2 (Critic): For each finding from the Auditor, sends it to
        codellama asking for true positive / false positive classification.
        Findings confirmed as TP get a confidence boost; FPs are filtered out.

        Falls back to pattern-based analysis if LLM calls fail.

        Args:
            contract_path: Path to the Solidity contract file
            **kwargs: Optional overrides:
                - auditor_model: Override auditor model name
                - critic_model: Override critic model name
                - skip_critic: If True, skip Phase 2 (default: False)
                - timeout: Override default timeout

        Returns:
            Normalized analysis results dictionary
        """
        start_time = time.time()
        tool_name = "gptlens"
        version = "1.0.0"

        # Check tool availability
        status = self.is_available()
        if status != ToolStatus.AVAILABLE:
            return self._build_result(
                tool_name, version, "error", [], start_time,
                error=(
                    "Ollama not available. Install from https://ollama.com "
                    "and ensure it is running. Then pull models: "
                    "ollama pull deepseek-coder && ollama pull codellama"
                ),
            )

        try:
            # Read contract source code
            contract_code = self._read_contract(contract_path)
            if not contract_code:
                return self._build_result(
                    tool_name, version, "error", [], start_time,
                    error=f"Could not read contract file: {contract_path}",
                )

            # Check cache
            cache_key = self._get_cache_key(contract_code)
            cached = self._get_cached_result(cache_key)
            if cached:
                logger.info("GPTLens: Using cached result for %s", contract_path)
                cached["from_cache"] = True
                cached["execution_time"] = time.time() - start_time
                return cached

            # Truncate long contracts to fit context window
            contract_code = self._truncate_code(contract_code)

            # Get model overrides from kwargs
            auditor_model = kwargs.get("auditor_model", self._auditor_model)
            critic_model = kwargs.get("critic_model", self._critic_model)
            skip_critic = kwargs.get("skip_critic", False)

            # ==============================================================
            # PHASE 1: Auditor - Generate vulnerability findings
            # ==============================================================
            logger.info(
                "GPTLens Phase 1/2: Auditor (%s) scanning %s",
                auditor_model, contract_path,
            )
            auditor_prompt = AUDITOR_PROMPT_TEMPLATE.format(
                contract_code=contract_code,
            )
            auditor_response = self._call_ollama(
                model=auditor_model,
                prompt=auditor_prompt,
                timeout=AUDITOR_TIMEOUT,
            )

            # Parse auditor findings
            if auditor_response:
                raw_findings = self._parse_auditor_response(
                    auditor_response, contract_path,
                )
            else:
                logger.warning(
                    "GPTLens: Auditor LLM returned no response, "
                    "falling back to pattern-based analysis"
                )
                raw_findings = self._pattern_based_analysis(
                    contract_code, contract_path,
                )

            logger.info(
                "GPTLens Phase 1 complete: %d raw findings from Auditor",
                len(raw_findings),
            )

            # ==============================================================
            # PHASE 2: Critic - Filter false positives
            # ==============================================================
            if skip_critic or not raw_findings:
                final_findings = raw_findings
                critic_stats = {
                    "skipped": True,
                    "reason": "skip_critic flag" if skip_critic else "no findings",
                }
            else:
                logger.info(
                    "GPTLens Phase 2/2: Critic (%s) evaluating %d findings",
                    critic_model, len(raw_findings),
                )
                final_findings, critic_stats = self._critic_evaluate(
                    contract_code=contract_code,
                    findings=raw_findings,
                    critic_model=critic_model,
                )
                logger.info(
                    "GPTLens Phase 2 complete: %d/%d findings confirmed as TP",
                    len(final_findings), len(raw_findings),
                )

            # Sort findings by severity then confidence
            final_findings.sort(
                key=lambda f: (
                    SEVERITY_ORDER.get(f.get("severity", "Info"), 4),
                    -f.get("confidence", 0),
                )
            )

            # Assign sequential IDs
            for idx, finding in enumerate(final_findings):
                finding["id"] = f"gptlens-{idx + 1}"

            # Build result
            result = self._build_result(
                tool_name, version, "success", final_findings, start_time,
                metadata={
                    "auditor_model": auditor_model,
                    "critic_model": critic_model,
                    "backend": "ollama",
                    "ollama_url": self._ollama_url,
                    "raw_findings_count": len(raw_findings),
                    "confirmed_findings_count": len(final_findings),
                    "false_positives_removed": len(raw_findings) - len(final_findings),
                    "critic_stats": critic_stats,
                    "sovereign": True,
                    "dpga_compliant": True,
                },
            )

            # Cache result
            self._cache_result(cache_key, result)

            return result

        except Exception as e:
            logger.error("GPTLens analysis error: %s", e, exc_info=True)
            return self._build_result(
                tool_name, version, "error", [], start_time,
                error=str(e),
            )

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """
        Normalize findings from raw output to MIESC format.

        Findings are already normalized during analyze(), so this method
        extracts the findings list from the result dictionary.

        Args:
            raw_output: Raw output from analyze()

        Returns:
            List of normalized finding dictionaries
        """
        if isinstance(raw_output, dict):
            return raw_output.get("findings", [])
        return []

    def can_analyze(self, contract_path: str) -> bool:
        """Check if adapter can analyze the given contract file."""
        return Path(contract_path).suffix == ".sol"

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for GPTLens adapter."""
        return {
            "auditor_model": DEFAULT_AUDITOR_MODEL,
            "critic_model": DEFAULT_CRITIC_MODEL,
            "ollama_url": get_ollama_host(),
            "auditor_timeout": AUDITOR_TIMEOUT,
            "critic_timeout": CRITIC_TIMEOUT,
            "skip_critic": False,
            "max_retries": 2,
            "cache_ttl": CACHE_TTL,
        }

    # ========================================================================
    # Phase 1: Auditor Methods
    # ========================================================================

    def _parse_auditor_response(
        self, response: str, contract_path: str
    ) -> List[Dict[str, Any]]:
        """
        Parse the Auditor LLM response into structured findings.

        Attempts multiple JSON extraction strategies:
        1. Direct JSON block extraction (```json ... ```)
        2. Find JSON starting with {"findings"
        3. Simple first-{ to last-} extraction
        4. Regex-based finding extraction
        5. Fallback to text keyword analysis

        Args:
            response: Raw text response from the Auditor LLM
            contract_path: Path to the analyzed contract

        Returns:
            List of normalized finding dictionaries
        """
        findings = []

        # Strategy 1: Extract JSON from code block
        parsed = self._extract_json_from_response(response)

        if parsed and "findings" in parsed:
            raw_findings = parsed["findings"]
            if isinstance(raw_findings, list):
                for raw in raw_findings:
                    if not isinstance(raw, dict):
                        continue
                    finding = self._normalize_auditor_finding(raw, contract_path)
                    if finding:
                        findings.append(finding)

        # Strategy 2: If no JSON found, try regex extraction
        if not findings:
            logger.warning(
                "GPTLens Auditor: JSON parsing failed, trying regex extraction"
            )
            findings = self._extract_findings_from_text(response, contract_path)

        # Strategy 3: If still nothing, use keyword-based text analysis
        if not findings:
            logger.warning(
                "GPTLens Auditor: Regex extraction failed, using text analysis"
            )
            findings = self._extract_findings_from_keywords(response, contract_path)

        logger.info("GPTLens Auditor: Extracted %d findings", len(findings))
        return findings

    def _normalize_auditor_finding(
        self, raw: Dict[str, Any], contract_path: str
    ) -> Optional[Dict[str, Any]]:
        """
        Normalize a single finding from the Auditor LLM response.

        Maps the LLM output fields to the MIESC normalized format,
        including SWC/CWE/OWASP identifiers where applicable.

        Args:
            raw: Raw finding dictionary from the Auditor
            contract_path: Path to the analyzed contract

        Returns:
            Normalized finding dictionary or None if invalid
        """
        vuln_type = self._classify_vulnerability_type(raw)
        severity = self._normalize_severity(raw.get("severity", "Medium"))
        confidence = raw.get("confidence", 0.75)

        # Clamp confidence to valid range
        if not isinstance(confidence, (int, float)):
            confidence = 0.75
        confidence = max(0.0, min(1.0, float(confidence)))

        # Get SWC/CWE/OWASP mappings
        swc_info = VULNERABILITY_SWC_MAP.get(vuln_type, {})
        swc_id = raw.get("swc_id", swc_info.get("swc", ""))
        cwe_id = swc_info.get("cwe", "")
        owasp_category = swc_info.get("owasp", "")

        title = raw.get("title", f"{vuln_type.replace('_', ' ').title()} Vulnerability")
        description = raw.get("description", "")
        function_name = raw.get("function", "")
        line_number = raw.get("line", 0)

        # Validate line number
        if not isinstance(line_number, int):
            try:
                line_number = int(line_number)
            except (ValueError, TypeError):
                line_number = 0

        recommendation = raw.get(
            "recommendation",
            f"Review and address the {vuln_type.replace('_', ' ')} vulnerability.",
        )

        finding = {
            "id": "",  # Assigned later after critic filtering
            "type": vuln_type,
            "severity": severity,
            "confidence": confidence,
            "title": title,
            "description": description,
            "location": {
                "file": contract_path,
                "line": line_number,
                "function": function_name,
            },
            "message": description,
            "recommendation": recommendation,
            "swc_id": swc_id,
            "cwe_id": cwe_id,
            "owasp_category": owasp_category,
            "attack_scenario": raw.get("attack_scenario", ""),
            "impact": raw.get("impact", ""),
            "source": "gptlens_auditor",
            "critic_verdict": None,  # Filled in Phase 2
        }

        return finding

    def _classify_vulnerability_type(self, raw: Dict[str, Any]) -> str:
        """
        Classify the vulnerability type from a raw finding.

        Examines the 'type', 'title', and 'description' fields to match
        against known vulnerability categories.

        Args:
            raw: Raw finding dictionary

        Returns:
            Normalized vulnerability type string
        """
        combined_text = (
            f"{raw.get('type', '')} {raw.get('title', '')} "
            f"{raw.get('description', '')}"
        ).lower()

        for vuln_type, keywords in PATTERN_KEYWORDS.items():
            for keyword in keywords:
                if keyword.lower() in combined_text:
                    return vuln_type

        return raw.get("type", "logic_error")

    def _normalize_severity(self, severity: str) -> str:
        """
        Normalize severity string to MIESC standard format.

        Args:
            severity: Raw severity string (case-insensitive)

        Returns:
            Normalized severity: "Critical", "High", "Medium", "Low", or "Info"
        """
        severity_map = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Info",
            "informational": "Info",
            "warning": "Medium",
            "error": "High",
        }
        return severity_map.get(severity.strip().lower(), "Medium")

    # ========================================================================
    # Phase 2: Critic Methods
    # ========================================================================

    def _critic_evaluate(
        self,
        contract_code: str,
        findings: List[Dict[str, Any]],
        critic_model: str,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Evaluate findings using the Critic LLM role.

        For each finding, sends the finding details and relevant contract
        code to the Critic LLM, asking it to classify the finding as
        TRUE_POSITIVE or FALSE_POSITIVE.

        True positives get a confidence boost (+0.10, capped at 0.95).
        False positives are removed from the final results.
        On Critic failure, findings are kept conservatively.

        Args:
            contract_code: The full contract source code
            findings: List of findings from the Auditor phase
            critic_model: Model name for the Critic role

        Returns:
            Tuple of (filtered_findings, critic_statistics)
        """
        confirmed = []
        rejected_count = 0
        error_count = 0
        verdicts = []

        for finding in findings:
            verdict, explanation = self._critic_judge_finding(
                contract_code=contract_code,
                finding=finding,
                critic_model=critic_model,
            )

            if verdict == "TRUE_POSITIVE":
                # Confirmed: boost confidence
                finding["critic_verdict"] = "true_positive"
                finding["critic_explanation"] = explanation
                original_conf = finding.get("confidence", 0.75)
                finding["confidence"] = min(original_conf + 0.10, 0.95)
                confirmed.append(finding)
                verdicts.append({"title": finding.get("title"), "verdict": "TP"})

            elif verdict == "FALSE_POSITIVE":
                # Rejected: filter out
                rejected_count += 1
                verdicts.append({"title": finding.get("title"), "verdict": "FP"})
                logger.info(
                    "GPTLens Critic: Filtered FP - %s (%s)",
                    finding.get("title", "unknown"),
                    explanation[:100] if explanation else "no explanation",
                )

            else:
                # Uncertain or error: keep conservatively with slight penalty
                finding["critic_verdict"] = "uncertain"
                finding["critic_explanation"] = explanation or "Critic evaluation failed"
                original_conf = finding.get("confidence", 0.75)
                finding["confidence"] = max(original_conf - 0.05, 0.40)
                confirmed.append(finding)
                error_count += 1
                verdicts.append({"title": finding.get("title"), "verdict": "uncertain"})

        stats = {
            "total_evaluated": len(findings),
            "true_positives": len(findings) - rejected_count - error_count,
            "false_positives": rejected_count,
            "uncertain": error_count,
            "verdicts": verdicts,
        }

        return confirmed, stats

    def _critic_judge_finding(
        self,
        contract_code: str,
        finding: Dict[str, Any],
        critic_model: str,
    ) -> Tuple[str, str]:
        """
        Ask the Critic LLM to judge a single finding.

        Sends the finding details and contract code to the Critic with
        a structured evaluation prompt. Parses the response for
        TRUE_POSITIVE or FALSE_POSITIVE verdict.

        Args:
            contract_code: Contract source code
            finding: Finding to evaluate
            critic_model: Ollama model for the Critic role

        Returns:
            Tuple of (verdict, explanation) where verdict is one of:
            "TRUE_POSITIVE", "FALSE_POSITIVE", or "UNCERTAIN"
        """
        # Build the critic prompt
        prompt = CRITIC_PROMPT_TEMPLATE.format(
            finding_type=finding.get("type", "unknown"),
            finding_severity=finding.get("severity", "Medium"),
            finding_title=finding.get("title", "Unknown vulnerability"),
            finding_description=finding.get("description", "No description"),
            finding_function=finding.get("location", {}).get("function", "N/A"),
            finding_line=finding.get("location", {}).get("line", "N/A"),
            finding_attack=finding.get("attack_scenario", "N/A"),
            contract_code=contract_code[:6000],  # Limit code for critic context
        )

        response = self._call_ollama(
            model=critic_model,
            prompt=prompt,
            timeout=CRITIC_TIMEOUT,
        )

        if not response:
            logger.warning(
                "GPTLens Critic: No response for finding '%s'",
                finding.get("title", "unknown"),
            )
            return "UNCERTAIN", "Critic LLM did not respond"

        return self._parse_critic_verdict(response)

    def _parse_critic_verdict(self, response: str) -> Tuple[str, str]:
        """
        Parse the Critic LLM response to extract verdict and explanation.

        Looks for TRUE_POSITIVE or FALSE_POSITIVE markers in the response.
        Extracts the reasoning that follows the verdict marker.

        Args:
            response: Raw text response from the Critic LLM

        Returns:
            Tuple of (verdict, explanation)
        """
        response_upper = response.strip().upper()
        response_clean = response.strip()

        # Check for explicit markers
        if "TRUE_POSITIVE" in response_upper or "TRUE POSITIVE" in response_upper:
            # Extract explanation after the verdict
            explanation = self._extract_explanation(response_clean, "TRUE_POSITIVE")
            if not explanation:
                explanation = self._extract_explanation(response_clean, "TRUE POSITIVE")
            return "TRUE_POSITIVE", explanation or "Confirmed by Critic LLM"

        if "FALSE_POSITIVE" in response_upper or "FALSE POSITIVE" in response_upper:
            explanation = self._extract_explanation(response_clean, "FALSE_POSITIVE")
            if not explanation:
                explanation = self._extract_explanation(response_clean, "FALSE POSITIVE")
            return "FALSE_POSITIVE", explanation or "Rejected by Critic LLM"

        # Secondary heuristics
        if any(word in response_upper for word in ["VALID", "CONFIRMED", "EXPLOITABLE"]):
            return "TRUE_POSITIVE", response_clean[:300]

        if any(word in response_upper for word in [
            "INVALID", "NOT EXPLOITABLE", "NOT VULNERABLE", "NO VULNERABILITY"
        ]):
            return "FALSE_POSITIVE", response_clean[:300]

        # Ambiguous response
        return "UNCERTAIN", response_clean[:300]

    def _extract_explanation(self, response: str, marker: str) -> str:
        """
        Extract explanation text following a verdict marker.

        Args:
            response: Full critic response text
            marker: The verdict marker string to search for

        Returns:
            Explanation text or empty string
        """
        # Case-insensitive search
        idx = response.upper().find(marker.upper())
        if idx == -1:
            return ""

        after_marker = response[idx + len(marker):].strip()
        # Remove common separators
        for sep in [":", "-", ".", "\n"]:
            if after_marker.startswith(sep):
                after_marker = after_marker[1:].strip()

        # Take first meaningful chunk (up to 500 chars or first double newline)
        double_newline = after_marker.find("\n\n")
        if double_newline > 0:
            after_marker = after_marker[:double_newline]

        return after_marker[:500].strip()

    # ========================================================================
    # Ollama HTTP API Methods
    # ========================================================================

    def _call_ollama(
        self,
        model: str,
        prompt: str,
        timeout: int = 300,
    ) -> Optional[str]:
        """
        Call the Ollama HTTP API /api/generate endpoint.

        Sends a POST request with the model name and prompt, then
        collects the streamed response tokens. Uses urllib.request
        to avoid external dependencies.

        Implements retry logic with configurable attempts and delay.

        Args:
            model: Ollama model name (e.g., "deepseek-coder")
            prompt: The prompt text to send
            timeout: Request timeout in seconds

        Returns:
            Complete response text or None on failure
        """
        payload = json.dumps({
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_ctx": 8192,
            },
        }).encode("utf-8")

        for attempt in range(1, self._max_retries + 1):
            try:
                logger.debug(
                    "GPTLens: Calling Ollama %s (attempt %d/%d)",
                    model, attempt, self._max_retries,
                )

                req = urllib.request.Request(
                    self._generate_url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )

                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if resp.status == 200:
                        body = resp.read().decode("utf-8")
                        parsed = json.loads(body)
                        response_text = parsed.get("response", "")
                        if response_text:
                            logger.debug(
                                "GPTLens: Got response from %s (%d chars)",
                                model, len(response_text),
                            )
                            return response_text
                        else:
                            logger.warning(
                                "GPTLens: Empty response from %s", model
                            )
                    else:
                        logger.warning(
                            "GPTLens: Ollama returned status %d for %s",
                            resp.status, model,
                        )

            except urllib.error.HTTPError as e:
                logger.warning(
                    "GPTLens: HTTP error %d from Ollama for %s (attempt %d): %s",
                    e.code, model, attempt, e.reason,
                )
            except urllib.error.URLError as e:
                logger.warning(
                    "GPTLens: URL error calling Ollama for %s (attempt %d): %s",
                    model, attempt, e.reason,
                )
            except json.JSONDecodeError as e:
                logger.warning(
                    "GPTLens: Invalid JSON from Ollama for %s (attempt %d): %s",
                    model, attempt, e,
                )
            except Exception as e:
                logger.error(
                    "GPTLens: Unexpected error calling Ollama for %s (attempt %d): %s",
                    model, attempt, e,
                )

            # Wait before retry
            if attempt < self._max_retries:
                time.sleep(self._retry_delay)

        logger.error(
            "GPTLens: All %d attempts failed for model %s",
            self._max_retries, model,
        )
        return None

    # ========================================================================
    # JSON Parsing Utilities
    # ========================================================================

    def _extract_json_from_response(self, response: str) -> Optional[Dict[str, Any]]:
        """
        Extract JSON object from an LLM response using multiple strategies.

        Strategy 1: Look for ```json ... ``` code blocks
        Strategy 2: Find JSON starting with {"findings"
        Strategy 3: Find first { to last } and parse
        Strategy 4: Attempt JSON repair (trailing commas, etc.)

        Args:
            response: Raw LLM response text

        Returns:
            Parsed JSON dictionary or None
        """
        # Strategy 1: JSON code block
        json_block = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", response, re.DOTALL)
        if json_block:
            try:
                return json.loads(json_block.group(1))
            except json.JSONDecodeError:
                pass

        # Strategy 2: Find {"findings"
        findings_match = re.search(r'\{\s*"findings"\s*:', response)
        if findings_match:
            start = findings_match.start()
            depth = 0
            for i, char in enumerate(response[start:]):
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(response[start:start + i + 1])
                        except json.JSONDecodeError:
                            break

        # Strategy 3: First { to last }
        json_start = response.find("{")
        json_end = response.rfind("}") + 1
        if json_start != -1 and json_end > json_start:
            json_str = response[json_start:json_end]
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                pass

            # Strategy 4: Repair common issues
            repaired = self._repair_json(json_str)
            if repaired:
                try:
                    return json.loads(repaired)
                except json.JSONDecodeError:
                    pass

        return None

    def _repair_json(self, json_str: str) -> Optional[str]:
        """
        Attempt to repair common JSON issues in LLM output.

        Fixes:
        - Trailing commas before ] or }
        - Unescaped newlines in string values
        - Single quotes instead of double quotes

        Args:
            json_str: Malformed JSON string

        Returns:
            Repaired JSON string or None
        """
        # Remove trailing commas
        repaired = re.sub(r",\s*([}\]])", r"\1", json_str)

        # Replace single quotes with double quotes (simple heuristic)
        # Only if the string doesn't already use double quotes properly
        if '"findings"' not in repaired and "'findings'" in repaired:
            repaired = repaired.replace("'", '"')

        # Replace actual newlines inside string values with \n
        lines = repaired.split("\n")
        fixed_lines = []
        in_string = False
        buffer = ""

        for line in lines:
            quote_count = line.count('"') - line.count('\\"')
            if in_string:
                buffer += "\\n" + line
                if quote_count % 2 == 1:
                    fixed_lines.append(buffer)
                    buffer = ""
                    in_string = False
            else:
                if quote_count % 2 == 1:
                    in_string = True
                    buffer = line
                else:
                    fixed_lines.append(line)

        if buffer:
            fixed_lines.append(buffer)

        return "\n".join(fixed_lines)

    # ========================================================================
    # Fallback Analysis Methods
    # ========================================================================

    def _extract_findings_from_text(
        self, response: str, contract_path: str
    ) -> List[Dict[str, Any]]:
        """
        Extract findings from unstructured text response using regex patterns.

        Looks for patterns like "CRITICAL: Reentrancy vulnerability..." or
        "SWC-107: ..." in the LLM response text.

        Args:
            response: Raw text response from the LLM
            contract_path: Path to the analyzed contract

        Returns:
            List of extracted findings
        """
        findings = []
        seen_types = set()

        # Regex patterns for common vulnerability mentions
        regex_patterns = [
            (r"(?:CRITICAL|HIGH)\s*[:\-]?\s*([Rr]eentrancy[^\n]{10,})", "Critical", "reentrancy"),
            (r"(?:CRITICAL|HIGH)\s*[:\-]?\s*([Aa]ccess\s+[Cc]ontrol[^\n]{10,})", "High", "access_control"),
            (r"(?:HIGH|MEDIUM)\s*[:\-]?\s*([Ll]ogic\s+[Ee]rror[^\n]{10,})", "High", "logic_error"),
            (r"(?:HIGH|MEDIUM)\s*[:\-]?\s*([Oo]racle[^\n]{10,})", "High", "oracle_manipulation"),
            (r"(?:MEDIUM)\s*[:\-]?\s*([Ff]ront[\s-]*[Rr]unning[^\n]{10,})", "Medium", "front_running"),
            (r"(?:HIGH|MEDIUM)\s*[:\-]?\s*([Ii]nteger\s+[Oo]verflow[^\n]{10,})", "High", "integer_overflow"),
            (r"(?:MEDIUM)\s*[:\-]?\s*([Uu]nchecked[^\n]{10,})", "Medium", "unchecked_return"),
            (r"(?:MEDIUM)\s*[:\-]?\s*([Tt]x\.origin[^\n]{10,})", "Medium", "tx_origin"),
            (r"(?:HIGH)\s*[:\-]?\s*([Dd]elegatecall[^\n]{10,})", "High", "delegatecall"),
            (r"(?:LOW|MEDIUM)\s*[:\-]?\s*([Tt]imestamp[^\n]{10,})", "Low", "timestamp_dependence"),
            (r"SWC-107[:\s]+([^\n]+)", "Critical", "reentrancy"),
            (r"SWC-105[:\s]+([^\n]+)", "High", "access_control"),
            (r"SWC-101[:\s]+([^\n]+)", "High", "integer_overflow"),
            (r"SWC-104[:\s]+([^\n]+)", "Medium", "unchecked_return"),
            (r"SWC-115[:\s]+([^\n]+)", "Medium", "tx_origin"),
            (r"SWC-112[:\s]+([^\n]+)", "High", "delegatecall"),
            (r"SWC-116[:\s]+([^\n]+)", "Low", "timestamp_dependence"),
        ]

        for pattern, severity, vuln_type in regex_patterns:
            matches = re.findall(pattern, response, re.IGNORECASE)
            for match in matches:
                if vuln_type not in seen_types and len(match.strip()) > 10:
                    swc_info = VULNERABILITY_SWC_MAP.get(vuln_type, {})
                    findings.append({
                        "id": "",
                        "type": vuln_type,
                        "severity": severity,
                        "confidence": 0.60,
                        "title": f"{vuln_type.replace('_', ' ').title()} Vulnerability",
                        "description": match.strip()[:500],
                        "location": {
                            "file": contract_path,
                            "line": 0,
                            "function": "",
                        },
                        "message": match.strip()[:500],
                        "recommendation": f"Review {vuln_type.replace('_', ' ')} issue.",
                        "swc_id": swc_info.get("swc", ""),
                        "cwe_id": swc_info.get("cwe", ""),
                        "owasp_category": swc_info.get("owasp", ""),
                        "source": "gptlens_auditor_text",
                        "critic_verdict": None,
                    })
                    seen_types.add(vuln_type)

        return findings

    def _extract_findings_from_keywords(
        self, response: str, contract_path: str
    ) -> List[Dict[str, Any]]:
        """
        Extract findings using simple keyword matching as last-resort fallback.

        Scans the response text for known vulnerability keywords and creates
        low-confidence findings for each detected category.

        Args:
            response: Raw text response from the LLM
            contract_path: Path to the analyzed contract

        Returns:
            List of keyword-matched findings
        """
        findings = []
        response_lower = response.lower()

        for vuln_type, keywords in PATTERN_KEYWORDS.items():
            for keyword in keywords:
                if keyword.lower() in response_lower:
                    swc_info = VULNERABILITY_SWC_MAP.get(vuln_type, {})
                    severity = DEFAULT_SEVERITY_MAP.get(vuln_type, "Medium")
                    findings.append({
                        "id": "",
                        "type": vuln_type,
                        "severity": severity,
                        "confidence": 0.50,
                        "title": f"Potential {vuln_type.replace('_', ' ').title()}",
                        "description": (
                            f"LLM analysis mentions '{keyword}' pattern. "
                            f"Manual review recommended."
                        ),
                        "location": {
                            "file": contract_path,
                            "line": 0,
                            "function": "",
                        },
                        "message": f"Keyword '{keyword}' detected in LLM analysis output.",
                        "recommendation": (
                            f"Review contract for {vuln_type.replace('_', ' ')} "
                            f"vulnerability patterns."
                        ),
                        "swc_id": swc_info.get("swc", ""),
                        "cwe_id": swc_info.get("cwe", ""),
                        "owasp_category": swc_info.get("owasp", ""),
                        "source": "gptlens_keyword_fallback",
                        "critic_verdict": None,
                    })
                    break  # One finding per vulnerability type

        return findings

    def _pattern_based_analysis(
        self, contract_code: str, contract_path: str
    ) -> List[Dict[str, Any]]:
        """
        Perform pattern-based static analysis as fallback when LLM is unavailable.

        Scans the contract source code directly for known vulnerability patterns
        using regex and keyword matching. This provides basic coverage when the
        Ollama LLM calls fail.

        Detection covers all 10 vulnerability categories with pattern-specific
        regex rules.

        Args:
            contract_code: Solidity source code
            contract_path: Path to the contract file

        Returns:
            List of pattern-matched findings
        """
        findings = []
        code_lower = contract_code.lower()
        lines = contract_code.split("\n")

        # Pattern detectors - each returns a finding or None
        pattern_checks = [
            self._detect_reentrancy_pattern,
            self._detect_access_control_pattern,
            self._detect_integer_overflow_pattern,
            self._detect_unchecked_return_pattern,
            self._detect_tx_origin_pattern,
            self._detect_delegatecall_pattern,
            self._detect_timestamp_pattern,
            self._detect_oracle_pattern,
            self._detect_front_running_pattern,
        ]

        for check in pattern_checks:
            result = check(contract_code, lines, contract_path)
            if result:
                findings.append(result)

        logger.info(
            "GPTLens: Pattern-based fallback found %d potential issues",
            len(findings),
        )
        return findings

    def _detect_reentrancy_pattern(
        self, code: str, lines: List[str], path: str
    ) -> Optional[Dict[str, Any]]:
        """Detect reentrancy patterns: external calls before state updates."""
        # Look for .call{value: or .call( patterns
        call_match = re.search(r"\.call\{?\s*value\s*:", code)
        if not call_match:
            call_match = re.search(r"\.call\(", code)
        if not call_match:
            return None

        call_pos = call_match.start()
        after_call = code[call_pos:]

        # Check if state update happens after the call
        if re.search(r"(?:balances|_balances)\[.*\]\s*[-+]=", after_call):
            line_num = code[:call_pos].count("\n") + 1
            func_name = self._find_enclosing_function(code, call_pos)
            return self._make_pattern_finding(
                vuln_type="reentrancy",
                title="Reentrancy: State Update After External Call",
                description=(
                    "An external call is made before updating contract state. "
                    "An attacker could re-enter the function before the state "
                    "update completes, potentially draining funds."
                ),
                path=path,
                line=line_num,
                function=func_name,
                confidence=0.70,
            )

        return None

    def _detect_access_control_pattern(
        self, code: str, lines: List[str], path: str
    ) -> Optional[Dict[str, Any]]:
        """Detect missing access control on sensitive functions."""
        # Find functions that transfer funds or change ownership without modifiers
        sensitive_patterns = [
            (r"function\s+(\w*[Ww]ithdraw\w*)\s*\([^)]*\)\s*(?:public|external)(?!\s+only)",
             "Withdrawal function without access control modifier"),
            (r"function\s+(\w*[Ss]elfdestruct\w*)\s*\([^)]*\)\s*(?:public|external)(?!\s+only)",
             "Self-destruct function without access control modifier"),
            (r"function\s+(\w*[Ss]et[Oo]wner\w*)\s*\([^)]*\)\s*(?:public|external)(?!\s+only)",
             "Owner change function without access control modifier"),
        ]

        for pattern, description in sensitive_patterns:
            match = re.search(pattern, code)
            if match:
                func_name = match.group(1)
                line_num = code[:match.start()].count("\n") + 1
                return self._make_pattern_finding(
                    vuln_type="access_control",
                    title=f"Missing Access Control on {func_name}",
                    description=description,
                    path=path,
                    line=line_num,
                    function=func_name,
                    confidence=0.65,
                )

        return None

    def _detect_integer_overflow_pattern(
        self, code: str, lines: List[str], path: str
    ) -> Optional[Dict[str, Any]]:
        """Detect potential integer overflow in pre-0.8.0 contracts."""
        # Check Solidity version
        version_match = re.search(r"pragma solidity\s*[\^~]?\s*(\d+\.\d+)", code)
        if version_match:
            version = version_match.group(1)
            major, minor = version.split(".")
            if int(minor) >= 8:
                return None  # Solidity >= 0.8.0 has built-in overflow checks

        # Look for unchecked arithmetic on uint types
        if re.search(r"uint\d*\s+\w+\s*=\s*\w+\s*[+\-*]\s*\w+", code):
            if "SafeMath" not in code and "unchecked" not in code:
                match = re.search(r"uint\d*\s+\w+\s*=\s*\w+\s*[+\-*]", code)
                if match:
                    line_num = code[:match.start()].count("\n") + 1
                    func_name = self._find_enclosing_function(code, match.start())
                    return self._make_pattern_finding(
                        vuln_type="integer_overflow",
                        title="Potential Integer Overflow/Underflow",
                        description=(
                            "Arithmetic operation without SafeMath or Solidity >= 0.8.0 "
                            "overflow protection. May allow integer overflow/underflow."
                        ),
                        path=path,
                        line=line_num,
                        function=func_name,
                        confidence=0.60,
                    )

        return None

    def _detect_unchecked_return_pattern(
        self, code: str, lines: List[str], path: str
    ) -> Optional[Dict[str, Any]]:
        """Detect unchecked return values from low-level calls."""
        # Look for .call( without checking the return value
        pattern = re.compile(
            r"(?:address\([^)]+\)|[a-zA-Z_]\w*)\.call\{?[^}]*\}?\([^)]*\)\s*;",
        )
        match = pattern.search(code)
        if match:
            # Verify return value is not captured
            before_call = code[max(0, match.start() - 50):match.start()]
            if "bool" not in before_call and "(" not in before_call.split("\n")[-1]:
                line_num = code[:match.start()].count("\n") + 1
                func_name = self._find_enclosing_function(code, match.start())
                return self._make_pattern_finding(
                    vuln_type="unchecked_return",
                    title="Unchecked Return Value from Low-Level Call",
                    description=(
                        "Return value from a low-level .call() is not checked. "
                        "The call may silently fail without reverting the transaction."
                    ),
                    path=path,
                    line=line_num,
                    function=func_name,
                    confidence=0.65,
                )

        return None

    def _detect_tx_origin_pattern(
        self, code: str, lines: List[str], path: str
    ) -> Optional[Dict[str, Any]]:
        """Detect tx.origin usage for authentication."""
        match = re.search(r"require\s*\(\s*tx\.origin\s*==", code)
        if not match:
            match = re.search(r"if\s*\(\s*tx\.origin\s*==", code)
        if match:
            line_num = code[:match.start()].count("\n") + 1
            func_name = self._find_enclosing_function(code, match.start())
            return self._make_pattern_finding(
                vuln_type="tx_origin",
                title="Authentication via tx.origin",
                description=(
                    "tx.origin is used for authentication. This is vulnerable to "
                    "phishing attacks where a malicious contract tricks a user into "
                    "calling it, inheriting the user's tx.origin."
                ),
                path=path,
                line=line_num,
                function=func_name,
                confidence=0.85,
            )

        return None

    def _detect_delegatecall_pattern(
        self, code: str, lines: List[str], path: str
    ) -> Optional[Dict[str, Any]]:
        """Detect potentially unsafe delegatecall usage."""
        match = re.search(r"\.delegatecall\(", code)
        if match:
            line_num = code[:match.start()].count("\n") + 1
            func_name = self._find_enclosing_function(code, match.start())
            # Check if the target is user-controlled
            before = code[max(0, match.start() - 200):match.start()]
            if "function" in before.lower() and ("address" in before or "bytes" in before):
                return self._make_pattern_finding(
                    vuln_type="delegatecall",
                    title="Potentially Unsafe Delegatecall",
                    description=(
                        "delegatecall is used with a potentially user-controlled "
                        "target address. This could allow an attacker to execute "
                        "arbitrary code in the context of the calling contract, "
                        "modifying its storage."
                    ),
                    path=path,
                    line=line_num,
                    function=func_name,
                    confidence=0.60,
                )

        return None

    def _detect_timestamp_pattern(
        self, code: str, lines: List[str], path: str
    ) -> Optional[Dict[str, Any]]:
        """Detect timestamp dependence in critical operations."""
        # Look for block.timestamp in conditions or assignments
        timestamp_patterns = [
            r"require\s*\([^)]*block\.timestamp",
            r"if\s*\([^)]*block\.timestamp",
            r"block\.timestamp\s*[<>=!]+",
        ]
        for pat in timestamp_patterns:
            match = re.search(pat, code)
            if match:
                line_num = code[:match.start()].count("\n") + 1
                func_name = self._find_enclosing_function(code, match.start())
                return self._make_pattern_finding(
                    vuln_type="timestamp_dependence",
                    title="Block Timestamp Dependence",
                    description=(
                        "Contract logic depends on block.timestamp which can be "
                        "manipulated by miners within a ~15 second window. This "
                        "should not be used for critical timing or randomness."
                    ),
                    path=path,
                    line=line_num,
                    function=func_name,
                    confidence=0.55,
                )

        return None

    def _detect_oracle_pattern(
        self, code: str, lines: List[str], path: str
    ) -> Optional[Dict[str, Any]]:
        """Detect oracle manipulation risks."""
        oracle_indicators = [
            r"latestRoundData\s*\(",
            r"getPrice\s*\(",
            r"IChainlink",
            r"AggregatorV3Interface",
        ]
        for pat in oracle_indicators:
            match = re.search(pat, code)
            if match:
                # Check if staleness check exists
                has_staleness = bool(re.search(
                    r"updatedAt|answeredInRound|staleness|stale",
                    code, re.IGNORECASE,
                ))
                if not has_staleness:
                    line_num = code[:match.start()].count("\n") + 1
                    func_name = self._find_enclosing_function(code, match.start())
                    return self._make_pattern_finding(
                        vuln_type="oracle_manipulation",
                        title="Oracle Price Feed Without Staleness Check",
                        description=(
                            "Oracle price feed is consumed without checking data "
                            "freshness. Stale or manipulated prices could lead to "
                            "incorrect calculations and potential fund loss."
                        ),
                        path=path,
                        line=line_num,
                        function=func_name,
                        confidence=0.65,
                    )

        return None

    def _detect_front_running_pattern(
        self, code: str, lines: List[str], path: str
    ) -> Optional[Dict[str, Any]]:
        """Detect front-running vulnerabilities."""
        # Look for swap/trade functions without slippage protection
        swap_match = re.search(
            r"function\s+(\w*[Ss]wap\w*)\s*\(",
            code,
        )
        if swap_match:
            func_name = swap_match.group(1)
            func_body_start = code.find("{", swap_match.end())
            if func_body_start != -1:
                # Find closing brace of function
                depth = 1
                pos = func_body_start + 1
                while pos < len(code) and depth > 0:
                    if code[pos] == "{":
                        depth += 1
                    elif code[pos] == "}":
                        depth -= 1
                    pos += 1
                func_body = code[func_body_start:pos]

                if "deadline" not in func_body.lower() and "slippage" not in func_body.lower():
                    line_num = code[:swap_match.start()].count("\n") + 1
                    return self._make_pattern_finding(
                        vuln_type="front_running",
                        title=f"Front-Running Risk in {func_name}",
                        description=(
                            "Swap/trade function lacks deadline and slippage "
                            "protection parameters. Transactions may be vulnerable "
                            "to sandwich attacks by MEV bots."
                        ),
                        path=path,
                        line=line_num,
                        function=func_name,
                        confidence=0.55,
                    )

        return None

    def _make_pattern_finding(
        self,
        vuln_type: str,
        title: str,
        description: str,
        path: str,
        line: int,
        function: str,
        confidence: float,
    ) -> Dict[str, Any]:
        """
        Create a standardized finding from pattern-based detection.

        Args:
            vuln_type: Vulnerability type identifier
            title: Short descriptive title
            description: Detailed description
            path: Contract file path
            line: Line number
            function: Function name
            confidence: Confidence score (0.0-1.0)

        Returns:
            Normalized finding dictionary
        """
        swc_info = VULNERABILITY_SWC_MAP.get(vuln_type, {})
        severity = DEFAULT_SEVERITY_MAP.get(vuln_type, "Medium")

        finding_data = f"{vuln_type}:{path}:{line}:{function}"
        finding_id = hashlib.sha256(finding_data.encode()).hexdigest()[:12]

        return {
            "id": f"gptlens-pat-{finding_id}",
            "type": vuln_type,
            "severity": severity,
            "confidence": confidence,
            "title": title,
            "description": description,
            "location": {
                "file": path,
                "line": line,
                "function": function,
            },
            "message": description,
            "recommendation": (
                f"Review and address the {vuln_type.replace('_', ' ')} "
                f"vulnerability. Refer to {swc_info.get('swc', 'SWC Registry')} "
                f"for mitigation guidance."
            ),
            "swc_id": swc_info.get("swc", ""),
            "cwe_id": swc_info.get("cwe", ""),
            "owasp_category": swc_info.get("owasp", ""),
            "source": "gptlens_pattern_fallback",
            "critic_verdict": None,
        }

    # ========================================================================
    # Utility Methods
    # ========================================================================

    def _find_enclosing_function(self, code: str, position: int) -> str:
        """
        Find the name of the function enclosing a given position in code.

        Searches backward from the position to find the nearest
        'function <name>' declaration.

        Args:
            code: Full source code
            position: Character position to search from

        Returns:
            Function name or empty string if not found
        """
        before = code[:position]
        match = re.findall(r"function\s+(\w+)", before)
        if match:
            return match[-1]
        return ""

    def _read_contract(self, contract_path: str) -> Optional[str]:
        """
        Read contract file content with UTF-8 encoding.

        Args:
            contract_path: Path to the Solidity contract file

        Returns:
            File content as string or None on error
        """
        try:
            with open(contract_path, "r", encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            logger.error("GPTLens: Contract file not found: %s", contract_path)
            return None
        except PermissionError:
            logger.error("GPTLens: Permission denied reading: %s", contract_path)
            return None
        except Exception as e:
            logger.error("GPTLens: Error reading contract %s: %s", contract_path, e)
            return None

    def _truncate_code(self, code: str) -> str:
        """
        Truncate contract code to fit within LLM context window.

        Args:
            code: Original contract source code

        Returns:
            Truncated code (with marker) or original if within limits
        """
        if len(code) <= MAX_CONTRACT_SIZE:
            return code

        logger.warning(
            "GPTLens: Contract truncated from %d to %d chars",
            len(code), MAX_CONTRACT_SIZE,
        )
        return code[:MAX_CONTRACT_SIZE] + "\n// ... (truncated for analysis)"

    def _build_result(
        self,
        tool: str,
        version: str,
        status: str,
        findings: List[Dict[str, Any]],
        start_time: float,
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build a standardized result dictionary.

        Args:
            tool: Tool name
            version: Tool version
            status: "success", "error", or "timeout"
            findings: List of findings
            start_time: Analysis start timestamp
            error: Error message if applicable
            metadata: Additional metadata

        Returns:
            Standardized result dictionary
        """
        result = {
            "tool": tool,
            "version": version,
            "status": status,
            "findings": findings,
            "execution_time": time.time() - start_time,
            "from_cache": False,
        }

        if error:
            result["error"] = error

        if metadata:
            result["metadata"] = metadata

        return result

    # ========================================================================
    # Cache Methods
    # ========================================================================

    def _get_cache_key(self, contract_code: str) -> str:
        """
        Generate a deterministic cache key from contract code and model config.

        Includes model names in the key so cache is invalidated when
        models change.

        Args:
            contract_code: Contract source code

        Returns:
            SHA-256 hex digest as cache key
        """
        key_data = (
            f"{contract_code}:"
            f"{self._auditor_model}:"
            f"{self._critic_model}"
        )
        return hashlib.sha256(key_data.encode("utf-8")).hexdigest()

    def _get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a cached analysis result if available and fresh.

        Cache entries older than CACHE_TTL (24 hours) are considered stale
        and automatically deleted.

        Args:
            cache_key: SHA-256 cache key

        Returns:
            Cached result dictionary or None
        """
        cache_file = self._cache_dir / f"{cache_key}.json"

        if not cache_file.exists():
            return None

        try:
            age_seconds = time.time() - cache_file.stat().st_mtime
            if age_seconds > CACHE_TTL:
                logger.info("GPTLens: Cache expired for key %s", cache_key[:16])
                cache_file.unlink()
                return None

            with open(cache_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.warning("GPTLens: Corrupted cache file %s", cache_file)
            cache_file.unlink(missing_ok=True)
            return None
        except Exception as e:
            logger.error("GPTLens: Error reading cache: %s", e)
            return None

    def _cache_result(self, cache_key: str, result: Dict[str, Any]) -> None:
        """
        Cache an analysis result for future use.

        Args:
            cache_key: SHA-256 cache key
            result: Analysis result dictionary to cache
        """
        cache_file = self._cache_dir / f"{cache_key}.json"

        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            logger.info("GPTLens: Cached result for key %s", cache_key[:16])
        except Exception as e:
            logger.error("GPTLens: Error writing cache: %s", e)


__all__ = ["GPTLensAdapter"]
