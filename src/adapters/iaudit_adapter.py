"""
iAudit - Multi-Agent Collaborative Auditing Adapter for MIESC.

Based on: "iAudit: A Multi-Agent Collaborative Auditing Framework for Smart Contracts"
(2024 research on multi-agent LLM collaboration for security auditing)

Architecture:
    3 specialized agents communicate via Ollama to produce high-quality audit results:

    1. Planner Agent  - Identifies audit scope, entry points, attack surface, and
                        critical paths. Produces a structured audit plan.
    2. Detector Agent - Receives the planner output and contract code, performs
                        targeted vulnerability detection based on the audit plan.
    3. Reviewer Agent - Validates detector findings against the contract code,
                        filters false positives, adjusts severity and confidence.

    Pipeline: Contract -> Planner -> Detector -> Reviewer -> Normalized Findings

Uses Ollama HTTP API (http://localhost:11434/api/generate) for model inference.
Falls back to pattern-based heuristic analysis when Ollama is unavailable.

Runs entirely locally - no API keys required (DPGA-compliant, sovereign).

Ollama: https://ollama.com
Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
Date: January 2026
"""

import hashlib
import json
import logging
import re
import subprocess
import time
import urllib.error
import urllib.request
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

# ---------------------------------------------------------------------------
# Vulnerability knowledge base for pattern-based fallback
# ---------------------------------------------------------------------------
VULNERABILITY_PATTERNS: Dict[str, Dict[str, Any]] = {
    "reentrancy": {
        "patterns": [
            r"\.call\{value:",
            r"\.call\(",
            r"\.send\(",
            r"\.transfer\(",
        ],
        "state_update": [r"-=", r"\+=", r"=\s*0", r"delete\s+"],
        "severity": "Critical",
        "swc_id": "SWC-107",
        "cwe_id": "CWE-841",
        "title": "Reentrancy Vulnerability",
        "description": (
            "External call detected before state variable update. "
            "An attacker can re-enter the function before the state is "
            "finalized, potentially draining funds."
        ),
        "recommendation": (
            "Apply the checks-effects-interactions pattern. Update all "
            "state variables before making external calls. Consider using "
            "OpenZeppelin ReentrancyGuard."
        ),
    },
    "access_control": {
        "patterns": [
            r"tx\.origin",
            r"function\s+\w+\s*\([^)]*\)\s*public(?!\s+view)(?!\s+pure)",
        ],
        "negative_patterns": [
            r"onlyOwner",
            r"require\s*\(\s*msg\.sender\s*==",
            r"modifier\s+only",
        ],
        "severity": "High",
        "swc_id": "SWC-115",
        "cwe_id": "CWE-284",
        "title": "Access Control Issue",
        "description": (
            "Public or external function without adequate access control. "
            "May allow unauthorized callers to execute privileged operations."
        ),
        "recommendation": (
            "Add appropriate access control modifiers (onlyOwner, role-based). "
            "Avoid using tx.origin for authorization; use msg.sender instead."
        ),
    },
    "integer_overflow": {
        "patterns": [
            r"\+\s*\d+",
            r"\*\s*\d+",
            r"\+\+",
        ],
        "negative_patterns": [
            r"pragma solidity\s*[\^~]?0\.8",
            r"using SafeMath",
        ],
        "severity": "High",
        "swc_id": "SWC-101",
        "cwe_id": "CWE-190",
        "title": "Integer Overflow / Underflow",
        "description": (
            "Arithmetic operation without overflow protection detected in a "
            "contract that may be compiled with Solidity < 0.8.0."
        ),
        "recommendation": (
            "Upgrade to Solidity >= 0.8.0 which has built-in overflow checks, "
            "or use OpenZeppelin SafeMath library."
        ),
    },
    "unchecked_call": {
        "patterns": [
            r"\.call\(",
            r"\.delegatecall\(",
            r"\.staticcall\(",
        ],
        "negative_patterns": [
            r"require\s*\(",
            r"\(bool\s+success",
        ],
        "severity": "Medium",
        "swc_id": "SWC-104",
        "cwe_id": "CWE-252",
        "title": "Unchecked Low-Level Call",
        "description": (
            "Return value of a low-level call is not checked. "
            "If the call fails silently, subsequent logic may operate "
            "on incorrect assumptions."
        ),
        "recommendation": (
            "Always check the return value of low-level calls. "
            'Use require(success, "Call failed") or revert on failure.'
        ),
    },
    "selfdestruct": {
        "patterns": [
            r"selfdestruct\s*\(",
            r"suicide\s*\(",
        ],
        "severity": "High",
        "swc_id": "SWC-106",
        "cwe_id": "CWE-284",
        "title": "Unprotected Self-Destruct",
        "description": (
            "selfdestruct is present in the contract. If not properly "
            "protected, an attacker could destroy the contract and send "
            "remaining Ether to an arbitrary address."
        ),
        "recommendation": (
            "Remove selfdestruct if not necessary, or protect it with "
            "strict access control and multi-sig authorization."
        ),
    },
    "timestamp_dependence": {
        "patterns": [
            r"block\.timestamp",
            r"\bnow\b",
        ],
        "severity": "Low",
        "swc_id": "SWC-116",
        "cwe_id": "CWE-829",
        "title": "Timestamp Dependence",
        "description": (
            "Contract logic depends on block.timestamp which can be "
            "slightly manipulated by miners (up to ~15 seconds)."
        ),
        "recommendation": (
            "Avoid using block.timestamp for critical logic such as "
            "randomness or strict time-sensitive conditions. Use block "
            "numbers for ordering guarantees."
        ),
    },
    "delegatecall": {
        "patterns": [
            r"\.delegatecall\(",
        ],
        "severity": "High",
        "swc_id": "SWC-112",
        "cwe_id": "CWE-829",
        "title": "Delegatecall to Untrusted Callee",
        "description": (
            "delegatecall executes code in the context of the calling "
            "contract, preserving storage layout. If the target is "
            "untrusted or upgradeable, storage corruption may occur."
        ),
        "recommendation": (
            "Only delegatecall to trusted, audited contracts. Ensure "
            "storage layouts are compatible. Use well-tested proxy "
            "patterns (UUPS, Transparent Proxy)."
        ),
    },
    "dos_gas": {
        "patterns": [
            r"for\s*\(",
            r"while\s*\(",
        ],
        "severity": "Medium",
        "swc_id": "SWC-128",
        "cwe_id": "CWE-400",
        "title": "Denial of Service via Gas Limit",
        "description": (
            "Unbounded loop iterating over a dynamic array or mapping. "
            "If the array grows large enough, the transaction may exceed "
            "the block gas limit and always revert."
        ),
        "recommendation": (
            "Implement pagination or pull-over-push patterns. Avoid "
            "iterating over unbounded data structures in a single "
            "transaction."
        ),
    },
    "front_running": {
        "patterns": [
            r"approve\s*\(",
            r"transferFrom\s*\(",
        ],
        "severity": "Medium",
        "swc_id": "SWC-114",
        "cwe_id": "CWE-362",
        "title": "Front-Running / Transaction Ordering Dependence",
        "description": (
            "approve() followed by transferFrom() is susceptible to "
            "the known ERC-20 front-running attack on allowance changes."
        ),
        "recommendation": (
            "Use increaseAllowance/decreaseAllowance instead of approve. "
            "Alternatively use permit (EIP-2612) for gasless approvals."
        ),
    },
    "uninitialized_storage": {
        "patterns": [
            r"address\s+\w+\s*;",
            r"uint\d*\s+\w+\s*;",
        ],
        "negative_patterns": [
            r"=\s*",
            r"constructor\s*\(",
        ],
        "severity": "Medium",
        "swc_id": "SWC-109",
        "cwe_id": "CWE-457",
        "title": "Uninitialized Storage Variable",
        "description": (
            "State variable declared without initialization. Depending on "
            "the storage slot, this may point to unexpected data."
        ),
        "recommendation": (
            "Explicitly initialize all state variables in the constructor "
            "or at declaration."
        ),
    },
}

# ---------------------------------------------------------------------------
# Agent prompt templates
# ---------------------------------------------------------------------------
PLANNER_PROMPT = """You are the PLANNER AGENT in a multi-agent smart contract audit team.

Your role is to analyze the contract and produce a structured audit plan that the
DETECTOR agent will use to find vulnerabilities.

SMART CONTRACT:
```solidity
{contract_code}
```

Produce a JSON audit plan with this structure:
{{
    "contract_name": "Name of the contract",
    "solidity_version": "Detected pragma version",
    "entry_points": [
        {{
            "function": "functionName",
            "visibility": "public/external",
            "modifiers": ["onlyOwner"],
            "state_changes": true,
            "external_calls": true,
            "payable": false,
            "risk_level": "high/medium/low"
        }}
    ],
    "attack_surface": {{
        "external_calls": ["list of external call sites"],
        "state_variables": ["critical state variables"],
        "access_control": "description of access control model",
        "value_handling": "how ETH/tokens are managed",
        "upgrade_mechanism": "proxy pattern if any"
    }},
    "inheritance_chain": ["BaseContract", "Interface"],
    "critical_paths": [
        {{
            "description": "Fund withdrawal flow",
            "functions": ["deposit", "withdraw"],
            "risk": "high"
        }}
    ],
    "standards_compliance": ["ERC-20", "ERC-721"],
    "priority_checks": [
        "reentrancy in withdraw",
        "access control on admin functions",
        "integer overflow in calculations"
    ]
}}

RULES:
- Focus on ACTUAL code patterns, not hypothetical scenarios
- Identify ALL public/external functions as entry points
- Map the complete attack surface
- Prioritize checks based on actual risk
- Output ONLY valid JSON, no additional text"""

DETECTOR_PROMPT = """You are the DETECTOR AGENT in a multi-agent smart contract audit team.

The PLANNER agent has already analyzed the contract and produced an audit plan.
Your job is to systematically check each priority item and entry point for
real vulnerabilities.

SMART CONTRACT:
```solidity
{contract_code}
```

AUDIT PLAN FROM PLANNER:
{planner_output}

Based on the audit plan, systematically check for vulnerabilities:

1. For each entry point identified by the Planner:
   - Trace the execution path
   - Check for reentrancy (external call before state update)
   - Verify access control
   - Check input validation

2. For each critical path:
   - Verify the invariants hold
   - Check for edge cases
   - Validate error handling

3. For each priority check:
   - Perform the specific analysis requested by the Planner

OUTPUT FORMAT (JSON only):
{{
    "findings": [
        {{
            "id": "IAUDIT-001",
            "type": "reentrancy|access_control|integer_overflow|unchecked_call|logic_error|dos|front_running|other",
            "severity": "Critical|High|Medium|Low|Info",
            "title": "Short descriptive title",
            "description": "Detailed description of the vulnerability",
            "location": {{
                "function": "functionName",
                "line_hint": "approximate line or code snippet reference",
                "contract": "ContractName"
            }},
            "impact": "What an attacker could achieve",
            "attack_scenario": "Step-by-step exploitation",
            "swc_id": "SWC-XXX",
            "cwe_id": "CWE-XXX",
            "recommendation": "How to fix the issue",
            "confidence": 0.85,
            "planner_reference": "Which priority check or entry point this relates to"
        }}
    ]
}}

RULES:
- Report ONLY vulnerabilities that exist in this specific code
- Do NOT report generic best practices unless they are actually violated
- Include SWC and CWE IDs where applicable
- Provide step-by-step attack scenarios for Critical/High findings
- Reference the Planner's audit plan items
- Output ONLY valid JSON"""

REVIEWER_PROMPT = """You are the REVIEWER AGENT in a multi-agent smart contract audit team.

The DETECTOR agent has found potential vulnerabilities. Your job is to
VERIFY each finding against the actual contract code and determine if it
is a TRUE POSITIVE or FALSE POSITIVE.

SMART CONTRACT:
```solidity
{contract_code}
```

FINDINGS TO REVIEW:
{detector_findings}

For EACH finding, perform this chain-of-thought analysis:

1. CODE VERIFICATION: Does the reported code pattern actually exist?
2. EXPLOITABILITY: Can this vulnerability actually be exploited given the
   contract's access control, state machine, and invariants?
3. EXISTING MITIGATIONS: Are there guards, modifiers, or patterns that
   already prevent exploitation?
4. SEVERITY VALIDATION: Is the severity rating appropriate given the
   actual impact and exploitability?
5. CONFIDENCE ADJUSTMENT: Based on your analysis, should confidence be
   raised, lowered, or kept?

OUTPUT FORMAT (JSON only):
{{
    "reviewed_findings": [
        {{
            "original_id": "IAUDIT-001",
            "verdict": "confirmed|false_positive|downgraded|needs_context",
            "original_severity": "Critical",
            "adjusted_severity": "Critical|High|Medium|Low|Info",
            "adjusted_confidence": 0.92,
            "reasoning": "Step-by-step reasoning for the verdict",
            "additional_context": "Any extra observations",
            "mitigations_found": ["ReentrancyGuard", "checks-effects-interactions"],
            "exploitable": true
        }}
    ],
    "summary": {{
        "total_reviewed": 5,
        "confirmed": 3,
        "false_positives": 1,
        "downgraded": 1,
        "overall_risk": "High"
    }}
}}

RULES:
- Be STRICT but FAIR: filter genuine false positives but do not dismiss
  real vulnerabilities
- For Critical findings, require strong evidence before marking as false positive
- Consider the ENTIRE contract context, not just the finding location
- Adjust confidence based on how certain you are of your verdict
- Output ONLY valid JSON"""


class IAuditAdapter(ToolAdapter):
    """
    iAudit multi-agent collaborative auditing adapter.

    Implements a three-agent pipeline (Planner -> Detector -> Reviewer)
    using local Ollama models for comprehensive smart contract security
    auditing. Falls back to pattern-based heuristic analysis when Ollama
    is unavailable.

    This adapter is fully sovereign and DPGA-compliant:
    - Runs entirely locally via Ollama
    - No external API keys required
    - No vendor lock-in (is_optional=True)

    Reference:
        iAudit: A Multi-Agent Collaborative Auditing Framework for
        Smart Contracts (2024)
    """

    # Ollama URLs resolved at runtime via get_ollama_host()

    # Supported model names in priority order
    MODEL_PRIORITY = [
        "qwen2.5-coder:7b",
        "deepseek-coder:6.7b",
        "codellama:7b",
        "llama3:8b",
        "mistral:7b",
    ]

    # Default timeouts (seconds)
    DEFAULT_PLANNER_TIMEOUT = 120
    DEFAULT_DETECTOR_TIMEOUT = 180
    DEFAULT_REVIEWER_TIMEOUT = 120
    DEFAULT_HTTP_TIMEOUT = 10

    # Maximum characters to send to the LLM (context window safety)
    MAX_CONTRACT_CHARS = 24000

    def __init__(
        self,
        ollama_url: str = None,
        model: Optional[str] = None,
        planner_timeout: int = DEFAULT_PLANNER_TIMEOUT,
        detector_timeout: int = DEFAULT_DETECTOR_TIMEOUT,
        reviewer_timeout: int = DEFAULT_REVIEWER_TIMEOUT,
    ):
        super().__init__()
        _base = (ollama_url or get_ollama_host()).rstrip("/")
        self._ollama_api_url = f"{_base}/api/generate"
        self._ollama_tags_url = f"{_base}/api/tags"
        self._ollama_url = _base
        self._api_generate = self._ollama_api_url
        self._api_tags = self._ollama_tags_url
        self._model = model
        self._planner_timeout = planner_timeout
        self._detector_timeout = detector_timeout
        self._reviewer_timeout = reviewer_timeout

        # Cache
        self._cache_dir = Path.home() / ".miesc" / "iaudit_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)

        # Resolved model (set during analysis if not provided)
        self._resolved_model: Optional[str] = None

    # ========================================================================
    # ToolAdapter interface implementation
    # ========================================================================

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="iaudit",
            version="1.0.0",
            category=ToolCategory.AI_ANALYSIS,
            author="Fernando Boiero <fboiero@frvm.utn.edu.ar>",
            license="AGPL-3.0",
            homepage="https://ollama.com",
            repository="https://github.com/ollama/ollama",
            documentation="https://arxiv.org/abs/2404.xxxxx",
            installation_cmd=(
                "curl -fsSL https://ollama.com/install.sh | sh && "
                "ollama pull qwen2.5-coder:7b"
            ),
            capabilities=[
                ToolCapability(
                    name="multi_agent_audit",
                    description=(
                        "Multi-agent collaborative auditing with Planner, "
                        "Detector, and Reviewer agents for comprehensive "
                        "vulnerability detection"
                    ),
                    supported_languages=["solidity"],
                    detection_types=[
                        "reentrancy",
                        "access_control",
                        "integer_overflow",
                        "unchecked_calls",
                        "logic_errors",
                        "denial_of_service",
                        "front_running",
                        "delegatecall_risks",
                    ],
                ),
                ToolCapability(
                    name="audit_planning",
                    description=(
                        "Automated audit scope identification, entry point "
                        "mapping, and attack surface analysis"
                    ),
                    supported_languages=["solidity"],
                    detection_types=[
                        "attack_surface_mapping",
                        "critical_path_analysis",
                    ],
                ),
                ToolCapability(
                    name="finding_review",
                    description=(
                        "AI-powered false positive filtering with "
                        "chain-of-thought verification"
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
        """Check if Ollama is running and a suitable model is available."""
        try:
            # Try the HTTP API first (more reliable than CLI)
            req = urllib.request.Request(
                self._api_tags,
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=self.DEFAULT_HTTP_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            models = data.get("models", [])
            model_names = [m.get("name", "") for m in models]
            model_names_lower = [n.lower() for n in model_names]

            # Check for any suitable model
            suitable_keywords = [
                "qwen2.5-coder",
                "deepseek-coder",
                "codellama",
                "llama3",
                "mistral",
            ]
            for keyword in suitable_keywords:
                for name in model_names_lower:
                    if keyword in name:
                        logger.info(f"iAudit: Found suitable model '{name}'")
                        return ToolStatus.AVAILABLE

            logger.warning(
                "iAudit: No suitable model found. "
                "Run: ollama pull qwen2.5-coder:7b"
            )
            return ToolStatus.CONFIGURATION_ERROR

        except urllib.error.URLError:
            # Try CLI fallback
            return self._check_ollama_cli()
        except Exception as e:
            logger.error(f"iAudit: Error checking Ollama availability: {e}")
            return self._check_ollama_cli()

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze a Solidity smart contract using the multi-agent pipeline.

        The analysis proceeds through three stages:
          1. Planner   - scope and attack surface identification
          2. Detector  - vulnerability detection guided by planner
          3. Reviewer  - finding validation and false positive filtering

        If Ollama is unavailable, falls back to pattern-based analysis.

        Args:
            contract_path: Absolute path to a .sol file
            **kwargs: Optional overrides:
                - model: str          (Ollama model to use)
                - planner_timeout: int
                - detector_timeout: int
                - reviewer_timeout: int
                - skip_reviewer: bool (skip reviewer stage)
                - fallback_only: bool (force pattern-based fallback)

        Returns:
            Normalized result dictionary (MIESC standard format)
        """
        start_time = time.time()

        # Read contract
        contract_code = self._read_contract(contract_path)
        if not contract_code:
            return self._error_result(
                start_time,
                f"Could not read contract file: {contract_path}",
            )

        # Check cache
        cache_key = self._get_cache_key(contract_code)
        cached = self._get_cached_result(cache_key)
        if cached:
            logger.info(f"iAudit: Using cached result for {contract_path}")
            cached["from_cache"] = True
            cached["execution_time"] = time.time() - start_time
            return cached

        # Determine if we should use Ollama or fallback
        force_fallback = kwargs.get("fallback_only", False)
        ollama_available = False

        if not force_fallback:
            status = self.is_available()
            ollama_available = status == ToolStatus.AVAILABLE

        if ollama_available:
            result = self._run_multi_agent_pipeline(
                contract_code, contract_path, start_time, **kwargs
            )
        else:
            logger.info(
                "iAudit: Ollama not available, using pattern-based fallback"
            )
            result = self._run_pattern_fallback(
                contract_code, contract_path, start_time
            )

        # Cache result
        if result.get("status") == "success":
            self._cache_result(cache_key, result)

        return result

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """
        Normalize findings to MIESC standard format.

        If raw_output is the full result dict from analyze(), extracts
        the findings list. Otherwise attempts to parse it as a list.

        Args:
            raw_output: Raw output from analyze() or a list of findings

        Returns:
            List of MIESC-normalized finding dictionaries
        """
        if isinstance(raw_output, dict):
            findings = raw_output.get("findings", [])
        elif isinstance(raw_output, list):
            findings = raw_output
        else:
            return []

        normalized = []
        for idx, f in enumerate(findings):
            if not isinstance(f, dict):
                continue

            # Map severity to standard format
            severity = self._normalize_severity(f.get("severity", "Medium"))

            # Parse location
            location = f.get("location", {})
            if isinstance(location, str):
                location = {"file": "", "details": location}

            normalized.append({
                "id": f.get("id", f"iaudit-{idx + 1}"),
                "type": f.get("type", f.get("category", "ai_detected")),
                "severity": severity,
                "confidence": float(f.get("confidence", 0.7)),
                "location": {
                    "file": location.get("file", ""),
                    "line": location.get("line", location.get("line_hint", 0)),
                    "function": location.get(
                        "function", location.get("details", "")
                    ),
                },
                "message": f.get("title", ""),
                "description": f.get("description", ""),
                "recommendation": f.get("recommendation", ""),
                "swc_id": f.get("swc_id"),
                "cwe_id": f.get("cwe_id"),
                "owasp_category": f.get("owasp_category"),
            })

        return normalized

    def can_analyze(self, contract_path: str) -> bool:
        """Check if the adapter can analyze the given file."""
        return Path(contract_path).suffix == ".sol"

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for iAudit."""
        return {
            "model": "qwen2.5-coder:7b",
            "planner_timeout": self.DEFAULT_PLANNER_TIMEOUT,
            "detector_timeout": self.DEFAULT_DETECTOR_TIMEOUT,
            "reviewer_timeout": self.DEFAULT_REVIEWER_TIMEOUT,
            "skip_reviewer": False,
            "fallback_only": False,
        }

    # ========================================================================
    # Multi-agent pipeline
    # ========================================================================

    def _run_multi_agent_pipeline(
        self,
        contract_code: str,
        contract_path: str,
        start_time: float,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Execute the full Planner -> Detector -> Reviewer pipeline.

        Each agent communicates through structured JSON. If any stage
        fails, the pipeline degrades gracefully.

        Args:
            contract_code: Solidity source code
            contract_path: Path to the contract file
            start_time: Timestamp when analysis started
            **kwargs: Configuration overrides

        Returns:
            Analysis result dictionary
        """
        # Resolve model
        model = kwargs.get("model") or self._model or self._detect_best_model()
        self._resolved_model = model

        # Truncate contract if necessary
        truncated_code = self._truncate_code(contract_code)

        planner_timeout = kwargs.get("planner_timeout", self._planner_timeout)
        detector_timeout = kwargs.get("detector_timeout", self._detector_timeout)
        reviewer_timeout = kwargs.get("reviewer_timeout", self._reviewer_timeout)
        skip_reviewer = kwargs.get("skip_reviewer", False)

        metadata = {
            "model": model,
            "backend": "ollama",
            "pipeline": "planner-detector-reviewer",
            "sovereign": True,
            "dpga_compliant": True,
        }

        # ------------------------------------------------------------------
        # STAGE 1: Planner Agent
        # ------------------------------------------------------------------
        logger.info(f"iAudit Stage 1/3: Planner Agent (model={model})")
        planner_output = self._run_planner(truncated_code, model, planner_timeout)

        if not planner_output:
            logger.warning(
                "iAudit: Planner agent failed, falling back to pattern analysis"
            )
            return self._run_pattern_fallback(
                contract_code, contract_path, start_time
            )

        metadata["planner_output_length"] = len(planner_output)

        # ------------------------------------------------------------------
        # STAGE 2: Detector Agent
        # ------------------------------------------------------------------
        logger.info("iAudit Stage 2/3: Detector Agent")
        detector_output = self._run_detector(
            truncated_code, planner_output, model, detector_timeout
        )

        if not detector_output:
            logger.warning(
                "iAudit: Detector agent failed, falling back to pattern analysis"
            )
            return self._run_pattern_fallback(
                contract_code, contract_path, start_time
            )

        # Parse detector findings
        detector_findings = self._parse_detector_output(
            detector_output, contract_path
        )
        metadata["detector_findings_count"] = len(detector_findings)

        if not detector_findings:
            logger.info("iAudit: Detector found no vulnerabilities")
            return {
                "tool": "iaudit",
                "version": "1.0.0",
                "status": "success",
                "findings": [],
                "metadata": metadata,
                "execution_time": time.time() - start_time,
                "from_cache": False,
            }

        # ------------------------------------------------------------------
        # STAGE 3: Reviewer Agent
        # ------------------------------------------------------------------
        final_findings = detector_findings

        if not skip_reviewer and len(detector_findings) > 0:
            logger.info(
                f"iAudit Stage 3/3: Reviewer Agent "
                f"(reviewing {len(detector_findings)} findings)"
            )
            reviewed = self._run_reviewer(
                truncated_code,
                detector_findings,
                model,
                reviewer_timeout,
            )

            if reviewed is not None:
                final_findings = reviewed
                metadata["reviewer_applied"] = True
                metadata["findings_after_review"] = len(final_findings)
                metadata["false_positives_removed"] = (
                    len(detector_findings) - len(final_findings)
                )
            else:
                logger.warning(
                    "iAudit: Reviewer agent failed, keeping raw detector findings"
                )
                metadata["reviewer_applied"] = False
        else:
            metadata["reviewer_applied"] = False

        return {
            "tool": "iaudit",
            "version": "1.0.0",
            "status": "success",
            "findings": final_findings,
            "metadata": metadata,
            "execution_time": time.time() - start_time,
            "from_cache": False,
        }

    # ========================================================================
    # Agent implementations
    # ========================================================================

    def _run_planner(
        self, contract_code: str, model: str, timeout: int
    ) -> Optional[str]:
        """
        Run the Planner agent to produce an audit plan.

        Sends the contract to the LLM with the planning prompt and
        returns the raw response text containing the audit plan JSON.

        Args:
            contract_code: Solidity source code (possibly truncated)
            model: Ollama model name
            timeout: Maximum seconds for LLM generation

        Returns:
            Raw LLM response string, or None on failure
        """
        prompt = PLANNER_PROMPT.format(contract_code=contract_code)
        response = self._call_ollama_api(prompt, model, timeout)

        if not response:
            logger.error("iAudit Planner: No response from Ollama")
            return None

        # Validate that the response contains JSON-like structure
        if "{" not in response:
            logger.warning("iAudit Planner: Response does not contain JSON")
            return None

        logger.info(
            f"iAudit Planner: Generated audit plan "
            f"({len(response)} chars)"
        )
        return response

    def _run_detector(
        self,
        contract_code: str,
        planner_output: str,
        model: str,
        timeout: int,
    ) -> Optional[str]:
        """
        Run the Detector agent to find vulnerabilities.

        Sends the contract code along with the Planner's audit plan
        to the LLM for targeted vulnerability detection.

        Args:
            contract_code: Solidity source code
            planner_output: Raw output from the Planner agent
            model: Ollama model name
            timeout: Maximum seconds for LLM generation

        Returns:
            Raw LLM response with findings JSON, or None on failure
        """
        # Truncate planner output if necessary to fit context window
        max_planner_chars = 4000
        planner_text = planner_output[:max_planner_chars]
        if len(planner_output) > max_planner_chars:
            planner_text += "\n... (truncated)"

        prompt = DETECTOR_PROMPT.format(
            contract_code=contract_code,
            planner_output=planner_text,
        )
        response = self._call_ollama_api(prompt, model, timeout)

        if not response:
            logger.error("iAudit Detector: No response from Ollama")
            return None

        if "{" not in response:
            logger.warning("iAudit Detector: Response does not contain JSON")
            return None

        logger.info(
            f"iAudit Detector: Generated findings "
            f"({len(response)} chars)"
        )
        return response

    def _run_reviewer(
        self,
        contract_code: str,
        detector_findings: List[Dict[str, Any]],
        model: str,
        timeout: int,
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Run the Reviewer agent to validate findings.

        Sends all detector findings to the Reviewer for verification.
        Returns the filtered and adjusted list of findings.

        Args:
            contract_code: Solidity source code
            detector_findings: Parsed findings from the Detector
            model: Ollama model name
            timeout: Maximum seconds for LLM generation

        Returns:
            Reviewed and filtered findings list, or None on failure
        """
        # Serialize findings for the prompt
        findings_json = json.dumps(
            [
                {
                    "id": f.get("id", ""),
                    "type": f.get("type", ""),
                    "severity": f.get("severity", ""),
                    "title": f.get("title", ""),
                    "description": f.get("description", "")[:300],
                    "location": f.get("location", {}),
                    "recommendation": f.get("recommendation", "")[:200],
                }
                for f in detector_findings
            ],
            indent=2,
        )

        # Truncate findings JSON if too long
        max_findings_chars = 6000
        if len(findings_json) > max_findings_chars:
            findings_json = findings_json[:max_findings_chars] + "\n...]"

        prompt = REVIEWER_PROMPT.format(
            contract_code=contract_code,
            detector_findings=findings_json,
        )

        response = self._call_ollama_api(prompt, model, timeout)

        if not response:
            logger.error("iAudit Reviewer: No response from Ollama")
            return None

        return self._apply_reviewer_verdicts(detector_findings, response)

    # ========================================================================
    # Ollama HTTP API communication
    # ========================================================================

    def _call_ollama_api(
        self, prompt: str, model: str, timeout: int
    ) -> Optional[str]:
        """
        Call Ollama HTTP API for text generation.

        Uses urllib.request to send a POST to /api/generate and
        collects the streamed response tokens.

        Args:
            prompt: The full prompt text
            model: Ollama model name (e.g. "codellama:7b")
            timeout: Maximum seconds to wait

        Returns:
            Complete generated text, or None on failure
        """
        payload = json.dumps({
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_ctx": 8192,
                "num_predict": 4096,
            },
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
        }

        try:
            req = urllib.request.Request(
                self._api_generate,
                data=payload,
                headers=headers,
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=timeout) as resp:
                response_data = json.loads(resp.read().decode("utf-8"))

            generated_text = response_data.get("response", "")

            if not generated_text:
                logger.warning("iAudit: Empty response from Ollama API")
                return None

            return generated_text

        except urllib.error.URLError as e:
            logger.error(f"iAudit: Ollama API connection error: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"iAudit: Failed to decode Ollama response: {e}")
            return None
        except TimeoutError:
            logger.error(
                f"iAudit: Ollama API timeout after {timeout}s"
            )
            return None
        except Exception as e:
            logger.error(f"iAudit: Unexpected Ollama API error: {e}")
            return None

    def _check_ollama_cli(self) -> ToolStatus:
        """
        Fallback availability check using the ollama CLI.

        Used when the HTTP API is unreachable.

        Returns:
            ToolStatus indicating availability
        """
        try:
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                timeout=10,
                text=True,
            )

            if result.returncode != 0:
                logger.warning("iAudit: Ollama CLI not responding")
                return ToolStatus.CONFIGURATION_ERROR

            models = result.stdout.lower()
            suitable = [
                "qwen2.5-coder",
                "deepseek-coder",
                "codellama",
                "llama3",
                "mistral",
            ]
            for keyword in suitable:
                if keyword in models:
                    logger.info(f"iAudit: Found model via CLI ({keyword})")
                    return ToolStatus.AVAILABLE

            logger.warning(
                "iAudit: No suitable model found via CLI. "
                "Run: ollama pull qwen2.5-coder:7b"
            )
            return ToolStatus.CONFIGURATION_ERROR

        except FileNotFoundError:
            logger.info(
                "iAudit: Ollama not installed. "
                "Install from https://ollama.com"
            )
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            logger.warning("iAudit: Ollama CLI timeout")
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"iAudit: Ollama CLI check error: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def _detect_best_model(self) -> str:
        """
        Detect the best available Ollama model.

        Queries the Ollama API for installed models and returns
        the highest-priority one.

        Returns:
            Model name string (e.g. "qwen2.5-coder:7b")
        """
        try:
            req = urllib.request.Request(self._api_tags, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            models = data.get("models", [])
            model_names = [m.get("name", "").lower() for m in models]

            for priority_model in self.MODEL_PRIORITY:
                keyword = priority_model.split(":")[0]
                for name in model_names:
                    if keyword in name:
                        logger.info(f"iAudit: Selected model '{name}'")
                        return name

        except Exception as e:
            logger.debug(f"iAudit: Model detection via API failed: {e}")

        # CLI fallback
        try:
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                timeout=5,
                text=True,
            )
            if result.returncode == 0:
                models_text = result.stdout.lower()
                for priority_model in self.MODEL_PRIORITY:
                    keyword = priority_model.split(":")[0]
                    if keyword in models_text:
                        return priority_model
        except Exception:
            pass

        # Final fallback
        return "codellama:7b"

    # ========================================================================
    # Response parsing
    # ========================================================================

    def _parse_detector_output(
        self, raw_output: str, contract_path: str
    ) -> List[Dict[str, Any]]:
        """
        Parse the Detector agent's raw response into structured findings.

        Attempts multiple JSON extraction strategies.

        Args:
            raw_output: Raw LLM text from the Detector agent
            contract_path: Path to the contract (for location info)

        Returns:
            List of parsed finding dictionaries
        """
        findings = []

        parsed = self._extract_json_robust(raw_output)
        if parsed is None:
            logger.warning(
                "iAudit Detector: Could not parse JSON from response"
            )
            return findings

        raw_findings = parsed.get("findings", [])
        if isinstance(parsed, list):
            raw_findings = parsed

        for idx, f in enumerate(raw_findings):
            if not isinstance(f, dict):
                continue

            # Normalize location
            location = f.get("location", {})
            if isinstance(location, str):
                location = {"function": location, "line_hint": "", "contract": ""}

            finding = {
                "id": f.get("id", f"iaudit-{idx + 1}"),
                "type": f.get("type", "other"),
                "severity": self._normalize_severity(
                    f.get("severity", "Medium")
                ),
                "title": f.get("title", "Detected vulnerability"),
                "description": f.get("description", ""),
                "location": {
                    "file": contract_path,
                    "function": location.get("function", ""),
                    "line_hint": location.get("line_hint", ""),
                    "contract": location.get("contract", ""),
                },
                "impact": f.get("impact", ""),
                "attack_scenario": f.get("attack_scenario", ""),
                "swc_id": f.get("swc_id"),
                "cwe_id": f.get("cwe_id"),
                "recommendation": f.get("recommendation", ""),
                "confidence": float(f.get("confidence", 0.75)),
                "planner_reference": f.get("planner_reference", ""),
                "source": "iaudit-detector",
            }
            findings.append(finding)

        logger.info(f"iAudit Detector: Parsed {len(findings)} findings")
        return findings

    def _apply_reviewer_verdicts(
        self,
        detector_findings: List[Dict[str, Any]],
        reviewer_response: str,
    ) -> List[Dict[str, Any]]:
        """
        Apply the Reviewer agent's verdicts to detector findings.

        Merges review verdicts with original findings: confirmed
        findings are kept (with adjusted severity/confidence),
        false positives are removed, and downgraded findings have
        their severity reduced.

        Args:
            detector_findings: Original findings from the Detector
            reviewer_response: Raw LLM output from the Reviewer

        Returns:
            Filtered and adjusted findings list
        """
        parsed = self._extract_json_robust(reviewer_response)
        if parsed is None:
            logger.warning(
                "iAudit Reviewer: Could not parse review output, "
                "using text-based fallback"
            )
            return self._apply_reviewer_text_fallback(
                detector_findings, reviewer_response
            )

        reviewed_items = parsed.get("reviewed_findings", [])
        if not reviewed_items:
            logger.warning(
                "iAudit Reviewer: No reviewed_findings in response"
            )
            return detector_findings

        # Build verdict map by original_id
        verdict_map: Dict[str, Dict[str, Any]] = {}
        for item in reviewed_items:
            if isinstance(item, dict):
                original_id = item.get("original_id", "")
                if original_id:
                    verdict_map[original_id] = item

        final_findings = []
        for finding in detector_findings:
            finding_id = finding.get("id", "")
            verdict_info = verdict_map.get(finding_id)

            if verdict_info is None:
                # No review for this finding - keep it with lower confidence
                finding["reviewed"] = False
                finding["confidence"] = max(
                    finding.get("confidence", 0.75) - 0.1, 0.4
                )
                final_findings.append(finding)
                continue

            verdict = verdict_info.get("verdict", "").lower().strip()

            if verdict == "confirmed":
                finding["reviewed"] = True
                finding["review_reasoning"] = verdict_info.get("reasoning", "")
                # Adjust confidence upward
                adj_conf = verdict_info.get("adjusted_confidence")
                if adj_conf is not None:
                    finding["confidence"] = float(adj_conf)
                else:
                    finding["confidence"] = min(
                        finding.get("confidence", 0.75) + 0.1, 0.95
                    )
                # Apply adjusted severity if present
                adj_sev = verdict_info.get("adjusted_severity")
                if adj_sev:
                    finding["severity"] = self._normalize_severity(adj_sev)
                final_findings.append(finding)
                logger.info(f"iAudit Reviewer: CONFIRMED - {finding.get('title')}")

            elif verdict == "false_positive":
                severity = finding.get("severity", "").lower()
                # For Critical findings, keep with reduced confidence
                if severity == "critical":
                    finding["reviewed"] = True
                    finding["review_verdict"] = "false_positive_overridden"
                    finding["review_reasoning"] = verdict_info.get("reasoning", "")
                    finding["confidence"] = max(
                        finding.get("confidence", 0.75) - 0.25, 0.35
                    )
                    final_findings.append(finding)
                    logger.warning(
                        f"iAudit Reviewer: Critical finding kept despite FP verdict: "
                        f"{finding.get('title')}"
                    )
                else:
                    logger.info(
                        f"iAudit Reviewer: FALSE POSITIVE removed - "
                        f"{finding.get('title')}"
                    )

            elif verdict == "downgraded":
                finding["reviewed"] = True
                finding["review_reasoning"] = verdict_info.get("reasoning", "")
                adj_sev = verdict_info.get("adjusted_severity")
                if adj_sev:
                    finding["severity"] = self._normalize_severity(adj_sev)
                adj_conf = verdict_info.get("adjusted_confidence")
                if adj_conf is not None:
                    finding["confidence"] = float(adj_conf)
                final_findings.append(finding)
                logger.info(
                    f"iAudit Reviewer: DOWNGRADED - {finding.get('title')} "
                    f"to {finding['severity']}"
                )

            elif verdict == "needs_context":
                # Keep finding but flag it
                finding["reviewed"] = True
                finding["needs_context"] = True
                finding["review_reasoning"] = verdict_info.get("reasoning", "")
                final_findings.append(finding)
                logger.info(
                    f"iAudit Reviewer: NEEDS CONTEXT - {finding.get('title')}"
                )

            else:
                # Unknown verdict - keep conservatively
                finding["reviewed"] = False
                final_findings.append(finding)

        removed = len(detector_findings) - len(final_findings)
        logger.info(
            f"iAudit Reviewer: {len(detector_findings)} -> {len(final_findings)} "
            f"({removed} false positives removed)"
        )
        return final_findings

    def _apply_reviewer_text_fallback(
        self,
        detector_findings: List[Dict[str, Any]],
        reviewer_text: str,
    ) -> List[Dict[str, Any]]:
        """
        Apply reviewer verdicts when JSON parsing fails.

        Falls back to keyword-based analysis of the raw reviewer text.

        Args:
            detector_findings: Original detector findings
            reviewer_text: Raw text from the Reviewer agent

        Returns:
            Filtered findings based on text analysis
        """
        text_lower = reviewer_text.lower()
        final_findings = []

        for finding in detector_findings:
            title = finding.get("title", "").lower()
            finding_id = finding.get("id", "").lower()

            # Check if this finding is explicitly called out as false positive
            is_fp = False
            for marker in [title[:30], finding_id]:
                if not marker:
                    continue
                # Look for false_positive near the finding reference
                idx = text_lower.find(marker)
                if idx != -1:
                    context = text_lower[max(0, idx - 100):idx + len(marker) + 200]
                    if "false_positive" in context or "false positive" in context:
                        is_fp = True
                        break

            if is_fp:
                severity = finding.get("severity", "").lower()
                if severity == "critical":
                    finding["reviewed"] = True
                    finding["confidence"] = max(
                        finding.get("confidence", 0.75) - 0.2, 0.4
                    )
                    final_findings.append(finding)
                else:
                    logger.info(
                        f"iAudit Reviewer (text): FALSE POSITIVE - "
                        f"{finding.get('title')}"
                    )
            else:
                finding["reviewed"] = True
                final_findings.append(finding)

        return final_findings

    # ========================================================================
    # Pattern-based fallback analysis
    # ========================================================================

    def _run_pattern_fallback(
        self,
        contract_code: str,
        contract_path: str,
        start_time: float,
    ) -> Dict[str, Any]:
        """
        Run pattern-based heuristic analysis as a fallback.

        When Ollama is not available, this method scans the contract
        source code for known vulnerability patterns using regex.

        Args:
            contract_code: Solidity source code
            contract_path: Path to the contract file
            start_time: Analysis start timestamp

        Returns:
            Analysis result dictionary with pattern-matched findings
        """
        findings = []
        lines = contract_code.split("\n")
        finding_counter = 0

        for vuln_type, vuln_info in VULNERABILITY_PATTERNS.items():
            matched_lines = self._search_patterns(
                contract_code, lines, vuln_info.get("patterns", [])
            )

            if not matched_lines:
                continue

            # Check negative patterns (mitigations)
            negative_patterns = vuln_info.get("negative_patterns", [])
            has_mitigation = self._has_negative_patterns(
                contract_code, negative_patterns
            )

            # Special handling for reentrancy: check if state update is after call
            if vuln_type == "reentrancy":
                if not self._check_reentrancy_pattern(contract_code):
                    continue

            # Adjust severity and confidence based on mitigations
            severity = vuln_info["severity"]
            confidence = 0.70

            if has_mitigation:
                # Downgrade if mitigations are present
                severity = self._downgrade_severity(severity)
                confidence = 0.45
            else:
                confidence = 0.75

            for line_no, line_text in matched_lines[:3]:
                finding_counter += 1
                func_name = self._find_enclosing_function(lines, line_no)

                findings.append({
                    "id": f"iaudit-pattern-{finding_counter}",
                    "type": vuln_type,
                    "severity": severity,
                    "title": vuln_info["title"],
                    "description": vuln_info["description"],
                    "location": {
                        "file": contract_path,
                        "line": line_no + 1,
                        "function": func_name,
                        "line_hint": line_text.strip()[:120],
                    },
                    "impact": (
                        f"Potential {vuln_type} vulnerability detected "
                        f"via pattern analysis"
                    ),
                    "attack_scenario": "",
                    "swc_id": vuln_info.get("swc_id"),
                    "cwe_id": vuln_info.get("cwe_id"),
                    "recommendation": vuln_info["recommendation"],
                    "confidence": confidence,
                    "source": "iaudit-pattern-fallback",
                    "has_mitigation": has_mitigation,
                })

        # Sort by severity
        severity_order = {
            "Critical": 0,
            "High": 1,
            "Medium": 2,
            "Low": 3,
            "Info": 4,
        }
        findings.sort(
            key=lambda f: (
                severity_order.get(f.get("severity", "Low"), 4),
                -f.get("confidence", 0),
            )
        )

        return {
            "tool": "iaudit",
            "version": "1.0.0",
            "status": "success",
            "findings": findings,
            "metadata": {
                "backend": "pattern-fallback",
                "model": None,
                "pipeline": "pattern-based",
                "sovereign": True,
                "dpga_compliant": True,
                "note": (
                    "Ollama not available; results from pattern-based "
                    "heuristic analysis. Install Ollama for full multi-agent "
                    "auditing capability."
                ),
            },
            "execution_time": time.time() - start_time,
            "from_cache": False,
        }

    def _search_patterns(
        self,
        code: str,
        lines: List[str],
        patterns: List[str],
    ) -> List[Tuple[int, str]]:
        """
        Search for regex patterns in source code and return matching lines.

        Args:
            code: Full source code string
            lines: Source code split into lines
            patterns: List of regex patterns to search

        Returns:
            List of (line_number, line_text) tuples for matches
        """
        matched = []
        for pattern in patterns:
            try:
                regex = re.compile(pattern)
                for i, line in enumerate(lines):
                    if regex.search(line):
                        matched.append((i, line))
            except re.error as e:
                logger.debug(f"iAudit: Invalid regex pattern '{pattern}': {e}")
        return matched

    def _has_negative_patterns(
        self, code: str, negative_patterns: List[str]
    ) -> bool:
        """
        Check if any negative patterns (mitigations) are present.

        Args:
            code: Full source code string
            negative_patterns: Patterns that indicate mitigations

        Returns:
            True if any mitigation pattern is found
        """
        for pattern in negative_patterns:
            try:
                if re.search(pattern, code):
                    return True
            except re.error:
                pass
        return False

    def _check_reentrancy_pattern(self, code: str) -> bool:
        """
        Check if there is an actual reentrancy pattern (external call
        before state update) in the contract.

        This performs a simple positional check: finds external call
        sites and verifies if state-modifying operations come after them
        within the same function body.

        Args:
            code: Full source code

        Returns:
            True if a reentrancy-like pattern is detected
        """
        # Find external call positions
        call_patterns = [r"\.call\{", r"\.call\(", r"\.send\("]
        state_patterns = [r"-=", r"\+=", r"=\s*0\s*;", r"delete\s+"]

        for call_pat in call_patterns:
            for match in re.finditer(call_pat, code):
                call_pos = match.start()
                # Look for state updates after this call within 500 chars
                # (approximate function body)
                after_call = code[call_pos:call_pos + 500]
                for state_pat in state_patterns:
                    if re.search(state_pat, after_call):
                        return True
        return False

    def _find_enclosing_function(
        self, lines: List[str], target_line: int
    ) -> str:
        """
        Find the name of the function enclosing a given line number.

        Searches backward from the target line for a function declaration.

        Args:
            lines: Source code lines
            target_line: 0-based line index

        Returns:
            Function name or empty string if not found
        """
        func_pattern = re.compile(
            r"function\s+(\w+)\s*\("
        )
        for i in range(target_line, -1, -1):
            match = func_pattern.search(lines[i])
            if match:
                return match.group(1)
        return ""

    def _downgrade_severity(self, severity: str) -> str:
        """
        Downgrade severity by one level.

        Args:
            severity: Current severity string

        Returns:
            One-level lower severity
        """
        downgrade_map = {
            "Critical": "High",
            "High": "Medium",
            "Medium": "Low",
            "Low": "Info",
            "Info": "Info",
        }
        return downgrade_map.get(severity, severity)

    # ========================================================================
    # JSON extraction utilities
    # ========================================================================

    def _extract_json_robust(self, text: str) -> Optional[Dict[str, Any]]:
        """
        Extract JSON from LLM output using multiple strategies.

        Strategy order:
          1. JSON code block (```json ... ```)
          2. Find {"findings" or {"reviewed_findings" start
          3. First { to last }
          4. Aggressive repair (trailing commas, unescaped newlines)

        Args:
            text: Raw LLM output text

        Returns:
            Parsed JSON dict, or None if extraction fails
        """
        if not text or not text.strip():
            return None

        # Strategy 1: JSON code block
        json_block = re.search(r"```json\s*(.*?)\s*```", text, re.DOTALL)
        if json_block:
            try:
                return json.loads(json_block.group(1))
            except json.JSONDecodeError:
                pass

        # Strategy 2: Find known key patterns
        for key in ['"findings"', '"reviewed_findings"']:
            pattern = re.search(r'\{\s*' + re.escape(key) + r'\s*:', text)
            if pattern:
                start = pattern.start()
                result = self._extract_balanced_json(text, start)
                if result is not None:
                    return result

        # Strategy 3: First { to last }
        json_start = text.find("{")
        json_end = text.rfind("}") + 1
        if json_start != -1 and json_end > json_start:
            json_str = text[json_start:json_end]
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                pass

            # Strategy 4: Repair and retry
            repaired = self._repair_json(json_str)
            if repaired:
                try:
                    return json.loads(repaired)
                except json.JSONDecodeError:
                    pass

        return None

    def _extract_balanced_json(
        self, text: str, start: int
    ) -> Optional[Dict[str, Any]]:
        """
        Extract a balanced JSON object starting from a given position.

        Tracks brace depth to find the matching closing brace.

        Args:
            text: Full text
            start: Position of the opening brace

        Returns:
            Parsed JSON dict, or None
        """
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        return None
        return None

    def _repair_json(self, json_str: str) -> Optional[str]:
        """
        Attempt to repair common JSON issues from LLM output.

        Fixes:
          - Trailing commas before ] or }
          - Unescaped newlines inside strings
          - Single quotes instead of double quotes

        Args:
            json_str: Possibly malformed JSON string

        Returns:
            Repaired JSON string, or None if repair fails
        """
        # Remove trailing commas
        repaired = re.sub(r",\s*([}\]])", r"\1", json_str)

        # Replace single quotes with double quotes (basic heuristic)
        # Only apply if no double quotes are present in values
        if "'" in repaired and repaired.count('"') < repaired.count("'"):
            repaired = repaired.replace("'", '"')

        # Try to fix unescaped newlines in string values
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
    # Utility methods
    # ========================================================================

    def _read_contract(self, contract_path: str) -> Optional[str]:
        """
        Read a Solidity contract file.

        Args:
            contract_path: Path to the .sol file

        Returns:
            File contents as string, or None on error
        """
        try:
            path = Path(contract_path)
            if not path.exists():
                logger.error(f"iAudit: Contract file not found: {contract_path}")
                return None
            if not path.suffix == ".sol":
                logger.warning(
                    f"iAudit: Non-Solidity file: {contract_path}"
                )
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            logger.error(f"iAudit: Error reading contract: {e}")
            return None

    def _truncate_code(self, code: str) -> str:
        """
        Truncate contract code to fit within context window limits.

        Args:
            code: Full contract source code

        Returns:
            Possibly truncated code with indicator
        """
        if len(code) <= self.MAX_CONTRACT_CHARS:
            return code
        logger.warning(
            f"iAudit: Contract truncated from {len(code)} "
            f"to {self.MAX_CONTRACT_CHARS} chars"
        )
        return (
            code[:self.MAX_CONTRACT_CHARS]
            + "\n// ... (truncated for analysis)"
        )

    def _normalize_severity(self, severity: str) -> str:
        """
        Normalize severity string to MIESC standard format.

        Args:
            severity: Raw severity string from LLM

        Returns:
            One of: Critical, High, Medium, Low, Info
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
        return severity_map.get(severity.lower().strip(), "Medium")

    def _error_result(
        self, start_time: float, error: str
    ) -> Dict[str, Any]:
        """
        Create a standardized error result.

        Args:
            start_time: Analysis start timestamp
            error: Error message

        Returns:
            Error result dictionary
        """
        return {
            "tool": "iaudit",
            "version": "1.0.0",
            "status": "error",
            "findings": [],
            "execution_time": time.time() - start_time,
            "error": error,
        }

    # ========================================================================
    # Caching
    # ========================================================================

    def _get_cache_key(self, contract_code: str) -> str:
        """
        Generate a cache key from contract code content.

        Args:
            contract_code: Solidity source code

        Returns:
            SHA-256 hex digest
        """
        model_str = self._model or "auto"
        return hashlib.sha256(
            f"iaudit:{model_str}:{contract_code}".encode()
        ).hexdigest()

    def _get_cached_result(
        self, cache_key: str
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve a cached analysis result.

        Cache entries expire after 24 hours.

        Args:
            cache_key: SHA-256 hex key

        Returns:
            Cached result dict, or None if not found/expired
        """
        cache_file = self._cache_dir / f"{cache_key}.json"

        if not cache_file.exists():
            return None

        try:
            age_seconds = time.time() - cache_file.stat().st_mtime
            if age_seconds > 86400:  # 24 hours
                logger.info(f"iAudit: Cache expired for {cache_key[:16]}...")
                cache_file.unlink()
                return None

            with open(cache_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"iAudit: Error reading cache: {e}")
            return None

    def _cache_result(
        self, cache_key: str, result: Dict[str, Any]
    ) -> None:
        """
        Cache an analysis result to disk.

        Args:
            cache_key: SHA-256 hex key
            result: Analysis result dictionary
        """
        cache_file = self._cache_dir / f"{cache_key}.json"

        try:
            with open(cache_file, "w") as f:
                json.dump(result, f, indent=2)
            logger.info(f"iAudit: Cached result for {cache_key[:16]}...")
        except Exception as e:
            logger.error(f"iAudit: Error writing cache: {e}")


__all__ = ["IAuditAdapter"]
