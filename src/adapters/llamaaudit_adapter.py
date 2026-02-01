"""
LlamaAudit Adapter - CodeLlama Fine-tuned for Smart Contract Auditing via Ollama.
==================================================================================

AI-powered smart contract security analysis using CodeLlama through the Ollama
HTTP API. Provides deep semantic understanding of Solidity code for vulnerability
detection, with a fallback to pattern-based analysis when Ollama is unavailable.

Key Features:
- CodeLlama-based security analysis via Ollama HTTP API
- Structured prompt engineering for smart contract auditing
- Fallback pattern-based analysis (no external dependencies)
- Normalized findings in MIESC format (SWC/CWE mapped)
- Result caching for efficiency (24-hour TTL)
- Proper timeout handling for HTTP requests

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
License: AGPL-3.0
"""

import hashlib
import json
import logging
import re
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional

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
# SWC / CWE MAPPING TABLE
# ============================================================================
# Maps common vulnerability types to their SWC and CWE identifiers for
# standardized reporting across security tools.

VULNERABILITY_REGISTRY = {
    "reentrancy": {
        "swc_id": "SWC-107",
        "cwe_id": "CWE-841",
        "severity": "Critical",
        "description": "A function makes an external call before updating its own state, "
                       "allowing the callee to re-enter and exploit stale state.",
    },
    "integer_overflow": {
        "swc_id": "SWC-101",
        "cwe_id": "CWE-190",
        "severity": "High",
        "description": "Arithmetic operations that exceed the maximum or minimum "
                       "value of the data type without proper checks.",
    },
    "access_control": {
        "swc_id": "SWC-105",
        "cwe_id": "CWE-284",
        "severity": "High",
        "description": "Missing or improper access control modifiers on sensitive "
                       "functions that should be restricted.",
    },
    "unchecked_call": {
        "swc_id": "SWC-104",
        "cwe_id": "CWE-252",
        "severity": "Medium",
        "description": "Return value from a low-level call, send, or delegatecall "
                       "is not checked for success or failure.",
    },
    "tx_origin": {
        "swc_id": "SWC-115",
        "cwe_id": "CWE-477",
        "severity": "Medium",
        "description": "Usage of tx.origin for authorization, which can be exploited "
                       "via phishing contracts.",
    },
    "timestamp_dependence": {
        "swc_id": "SWC-116",
        "cwe_id": "CWE-829",
        "severity": "Low",
        "description": "Reliance on block.timestamp for critical logic, which miners "
                       "can manipulate within a ~15 second window.",
    },
    "delegatecall": {
        "swc_id": "SWC-112",
        "cwe_id": "CWE-829",
        "severity": "High",
        "description": "Delegatecall to an untrusted contract can overwrite storage "
                       "variables in unexpected ways.",
    },
    "selfdestruct": {
        "swc_id": "SWC-106",
        "cwe_id": "CWE-284",
        "severity": "High",
        "description": "Unprotected selfdestruct allows unauthorized contract destruction "
                       "and fund extraction.",
    },
    "front_running": {
        "swc_id": "SWC-114",
        "cwe_id": "CWE-362",
        "severity": "Medium",
        "description": "Transaction ordering dependence allows miners or observers to "
                       "front-run user transactions for profit.",
    },
    "denial_of_service": {
        "swc_id": "SWC-113",
        "cwe_id": "CWE-400",
        "severity": "High",
        "description": "A function can be blocked from executing due to gas limits, "
                       "unbounded loops, or external call failures.",
    },
    "uninitialized_storage": {
        "swc_id": "SWC-109",
        "cwe_id": "CWE-824",
        "severity": "High",
        "description": "Uninitialized local storage variables can point to unexpected "
                       "storage slots, leading to state corruption.",
    },
    "floating_pragma": {
        "swc_id": "SWC-103",
        "cwe_id": "CWE-1103",
        "severity": "Info",
        "description": "Floating pragma version allows compilation with different "
                       "compiler versions, potentially introducing bugs.",
    },
}

# Pattern-based fallback rules for offline analysis
FALLBACK_PATTERNS = [
    {
        "name": "reentrancy",
        "pattern": r"\.call\{.*value.*\}|\.call\.value\(",
        "context_pattern": r"(balances?\[.*\]\s*[-+]?=|_balances?\[.*\]\s*[-+]?=)",
        "severity": "Critical",
        "confidence": 0.70,
        "message": "Potential reentrancy: external call detected with state-modifying code",
        "recommendation": "Apply checks-effects-interactions pattern. Update state variables "
                          "before making external calls. Consider using ReentrancyGuard.",
    },
    {
        "name": "access_control",
        "pattern": r"(function\s+\w+\s*\([^)]*\)\s*(public|external)\s+(?!.*\b(onlyOwner|onlyAdmin|"
                   r"onlyRole|require\s*\(\s*msg\.sender|modifier)\b))",
        "context_pattern": None,
        "severity": "High",
        "confidence": 0.55,
        "message": "Public/external function without access control modifier",
        "recommendation": "Add appropriate access control modifier (onlyOwner, onlyRole) "
                          "or require() check for sender authorization.",
    },
    {
        "name": "tx_origin",
        "pattern": r"tx\.origin",
        "context_pattern": None,
        "severity": "Medium",
        "confidence": 0.85,
        "message": "Usage of tx.origin for authorization is vulnerable to phishing attacks",
        "recommendation": "Replace tx.origin with msg.sender for authorization checks.",
    },
    {
        "name": "unchecked_call",
        "pattern": r"\.call\{|\.call\(|\.send\(",
        "context_pattern": r"^(?!.*(?:require|assert|bool\s+\w+\s*,?\s*)\s*=)",
        "severity": "Medium",
        "confidence": 0.60,
        "message": "Low-level call without explicit return value check",
        "recommendation": "Always check the boolean return value of low-level calls. "
                          "Use require() to ensure the call succeeded.",
    },
    {
        "name": "selfdestruct",
        "pattern": r"selfdestruct\s*\(",
        "context_pattern": None,
        "severity": "High",
        "confidence": 0.80,
        "message": "selfdestruct usage detected; ensure it is properly access-controlled",
        "recommendation": "Protect selfdestruct with onlyOwner or multi-sig authorization. "
                          "Consider if selfdestruct is truly necessary.",
    },
    {
        "name": "delegatecall",
        "pattern": r"\.delegatecall\s*\(",
        "context_pattern": None,
        "severity": "High",
        "confidence": 0.75,
        "message": "delegatecall to potentially untrusted address detected",
        "recommendation": "Ensure delegatecall targets are trusted and immutable. "
                          "Validate storage layout compatibility.",
    },
    {
        "name": "timestamp_dependence",
        "pattern": r"block\.timestamp|now\b",
        "context_pattern": r"(require|if|while|assert|>|<|>=|<=|==)",
        "severity": "Low",
        "confidence": 0.65,
        "message": "Block timestamp used in logic; miners can manipulate within ~15s",
        "recommendation": "Avoid using block.timestamp for time-critical logic. "
                          "Use block numbers or an oracle for more reliable timing.",
    },
    {
        "name": "floating_pragma",
        "pattern": r"pragma\s+solidity\s+\^",
        "context_pattern": None,
        "severity": "Info",
        "confidence": 0.90,
        "message": "Floating pragma version detected; pin to a specific compiler version",
        "recommendation": "Use a fixed pragma version (e.g., pragma solidity 0.8.20;) "
                          "to ensure deterministic compilation.",
    },
    {
        "name": "integer_overflow",
        "pattern": r"(\+\+|\-\-|\+=|\-=|\*=|\/=)",
        "context_pattern": r"pragma\s+solidity\s+[\^~]?0\.[0-7]\.",
        "severity": "High",
        "confidence": 0.60,
        "message": "Arithmetic operation in pre-0.8.x contract without overflow protection",
        "recommendation": "Upgrade to Solidity 0.8.x for built-in overflow checks, "
                          "or use SafeMath library.",
    },
    {
        "name": "denial_of_service",
        "pattern": r"for\s*\([^)]*\.length",
        "context_pattern": None,
        "severity": "Medium",
        "confidence": 0.55,
        "message": "Unbounded loop iterating over dynamic array length",
        "recommendation": "Limit loop iterations or use pagination to prevent "
                          "exceeding the block gas limit.",
    },
]


# ============================================================================
# MAIN ADAPTER CLASS
# ============================================================================

class LlamaAuditAdapter(ToolAdapter):
    """
    LlamaAudit - CodeLlama fine-tuned for smart contract auditing via Ollama.

    Uses the Ollama HTTP API (http://localhost:11434) to run codellama model
    for security-focused analysis of Solidity smart contracts. Falls back to
    pattern-based analysis when Ollama is unavailable.

    Capabilities:
    - Semantic vulnerability detection via LLM
    - Pattern-based fallback analysis (offline mode)
    - SWC/CWE mapped findings
    - Result caching (24-hour TTL)
    """

    # Audit prompt optimized for CodeLlama security analysis
    AUDIT_PROMPT = """You are an expert smart contract security auditor performing a \
comprehensive audit. Analyze the following Solidity contract for security vulnerabilities.

IMPORTANT ANALYSIS GUIDELINES:
- Focus ONLY on vulnerabilities that EXIST in this specific code
- Trace execution paths and identify exploitable patterns
- Consider the Solidity compiler version for version-specific bugs
- Map each finding to SWC Registry and CWE identifiers
- Provide concrete attack scenarios for Critical/High findings

VULNERABILITY CHECKLIST:
1. Reentrancy (SWC-107): External calls before state updates
2. Integer overflow/underflow (SWC-101): Unchecked arithmetic
3. Access control (SWC-105): Missing authorization checks
4. Unchecked return values (SWC-104): Ignored call results
5. Denial of service (SWC-113): Gas limit, unbounded loops
6. Front-running (SWC-114): Transaction ordering dependence
7. Timestamp dependence (SWC-116): block.timestamp reliance
8. Delegatecall injection (SWC-112): Untrusted delegatecall targets
9. tx.origin phishing (SWC-115): Authorization via tx.origin
10. Unprotected selfdestruct (SWC-106): Missing access control

CONTRACT CODE:
```solidity
%CONTRACT_CODE%
```

OUTPUT FORMAT - Respond with ONLY valid JSON:
{
    "findings": [
        {
            "type": "vulnerability_category",
            "severity": "Critical|High|Medium|Low|Info",
            "confidence": 0.85,
            "title": "Short descriptive title",
            "description": "Detailed description of the vulnerability",
            "line": 42,
            "function": "functionName",
            "swc_id": "SWC-107",
            "cwe_id": "CWE-841",
            "attack_scenario": "Step-by-step exploitation scenario",
            "recommendation": "Specific fix recommendation"
        }
    ]
}

Respond with ONLY the JSON object. No explanations outside JSON."""

    # Ollama URLs resolved at runtime via get_ollama_host()
    # Supports OLLAMA_HOST env var and config/miesc.yaml

    def __init__(self):
        super().__init__()
        _base = get_ollama_host()
        self._ollama_base_url = _base
        self._ollama_generate_url = f"{_base}/api/generate"
        self._ollama_tags_url = f"{_base}/api/tags"
        self._model = "codellama"
        self._default_timeout = 180
        self._http_timeout = 10
        self._cache_dir = Path.home() / ".miesc" / "llamaaudit_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._max_retries = 2
        self._retry_delay = 2
        self._max_contract_chars = 24000

    def get_metadata(self) -> ToolMetadata:
        """Return tool metadata for MIESC registry."""
        return ToolMetadata(
            name="llamaaudit",
            version="1.0.0",
            category=ToolCategory.AI_ANALYSIS,
            author="Fernando Boiero <fboiero@frvm.utn.edu.ar>",
            license="AGPL-3.0",
            homepage="https://ollama.com",
            repository="https://github.com/ollama/ollama",
            documentation="https://github.com/ollama/ollama/blob/main/docs/api.md",
            installation_cmd=(
                "curl -fsSL https://ollama.com/install.sh | sh && "
                "ollama pull codellama"
            ),
            capabilities=[
                ToolCapability(
                    name="llm_security_audit",
                    description=(
                        "CodeLlama-based semantic security analysis for Solidity "
                        "smart contracts via Ollama HTTP API"
                    ),
                    supported_languages=["solidity"],
                    detection_types=[
                        "reentrancy",
                        "integer_overflow",
                        "access_control",
                        "unchecked_calls",
                        "denial_of_service",
                        "front_running",
                        "timestamp_dependence",
                        "delegatecall_injection",
                        "tx_origin_phishing",
                        "selfdestruct_abuse",
                    ],
                ),
                ToolCapability(
                    name="pattern_fallback",
                    description=(
                        "Regex pattern-based vulnerability detection as "
                        "fallback when Ollama is unavailable"
                    ),
                    supported_languages=["solidity"],
                    detection_types=[
                        "reentrancy",
                        "access_control",
                        "tx_origin",
                        "unchecked_call",
                        "selfdestruct",
                        "delegatecall",
                        "timestamp_dependence",
                        "floating_pragma",
                    ],
                ),
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True,
        )

    def is_available(self) -> ToolStatus:
        """
        Check if Ollama is running and codellama model is available.

        Performs an HTTP GET to the Ollama tags endpoint to verify
        the service is reachable and the required model is pulled.
        """
        try:
            req = urllib.request.Request(
                self._ollama_tags_url,
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=self._http_timeout) as resp:
                if resp.status != 200:
                    logger.warning(f"Ollama tags endpoint returned status {resp.status}")
                    return ToolStatus.CONFIGURATION_ERROR

                data = json.loads(resp.read().decode("utf-8"))
                models = data.get("models", [])

                # Check if codellama is among available models
                model_names = [m.get("name", "").lower() for m in models]
                has_codellama = any("codellama" in name for name in model_names)

                if has_codellama:
                    logger.info("LlamaAudit: codellama model available via Ollama")
                    return ToolStatus.AVAILABLE

                # Check for alternative compatible models
                compatible = ["llama3", "deepseek-coder", "qwen2.5-coder"]
                for alt in compatible:
                    if any(alt in name for name in model_names):
                        self._model = alt
                        logger.info(
                            f"LlamaAudit: Using alternative model '{alt}' "
                            f"(codellama not found)"
                        )
                        return ToolStatus.AVAILABLE

                logger.warning(
                    "LlamaAudit: No suitable model found. "
                    "Run: ollama pull codellama"
                )
                return ToolStatus.CONFIGURATION_ERROR

        except urllib.error.URLError as e:
            logger.info(f"Ollama not reachable at {self._ollama_base_url}: {e}")
            return ToolStatus.NOT_INSTALLED
        except ConnectionRefusedError:
            logger.info("Ollama service not running")
            return ToolStatus.NOT_INSTALLED
        except Exception as e:
            logger.error(f"Error checking Ollama availability: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze a Solidity contract using CodeLlama via Ollama HTTP API.

        If Ollama is unavailable, falls back to pattern-based analysis.

        Args:
            contract_path: Path to the Solidity contract file
            **kwargs: Optional configuration (timeout, model, use_fallback)

        Returns:
            Analysis results in MIESC normalized format
        """
        start_time = time.time()
        timeout = kwargs.get("timeout", self._default_timeout)
        use_fallback = kwargs.get("use_fallback", True)

        # Read contract source code
        contract_code = self._read_contract(contract_path)
        if not contract_code:
            return self._error_result(
                start_time, f"Could not read contract file: {contract_path}"
            )

        # Check cache
        cache_key = self._get_cache_key(contract_code)
        cached = self._get_cached_result(cache_key)
        if cached:
            logger.info(f"LlamaAudit: Using cached result for {contract_path}")
            cached["from_cache"] = True
            cached["execution_time"] = time.time() - start_time
            return cached

        # Check Ollama availability
        ollama_status = self.is_available()

        if ollama_status == ToolStatus.AVAILABLE:
            # Primary path: LLM-based analysis via Ollama HTTP API
            result = self._analyze_with_ollama(
                contract_code, contract_path, timeout, **kwargs
            )
        elif use_fallback:
            # Fallback path: pattern-based analysis
            logger.warning(
                "LlamaAudit: Ollama unavailable, using pattern-based fallback"
            )
            result = self._analyze_with_patterns(
                contract_code, contract_path, start_time
            )
        else:
            return self._error_result(
                start_time,
                "Ollama not available and fallback disabled. "
                "Install Ollama from https://ollama.com and run: ollama pull codellama",
            )

        # Cache successful results
        if result.get("status") == "success":
            self._cache_result(cache_key, result)

        result["execution_time"] = time.time() - start_time
        return result

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """
        Normalize findings from raw LLM or fallback output to MIESC format.

        Handles both structured JSON from the LLM and pattern-based findings.

        Args:
            raw_output: Raw output (dict with 'findings' or list of dicts)

        Returns:
            List of normalized MIESC findings
        """
        if isinstance(raw_output, dict):
            findings = raw_output.get("findings", [])
        elif isinstance(raw_output, list):
            findings = raw_output
        else:
            return []

        normalized = []
        for idx, finding in enumerate(findings):
            if not isinstance(finding, dict):
                continue

            vuln_type = finding.get("type", finding.get("category", "unknown"))
            registry_entry = VULNERABILITY_REGISTRY.get(vuln_type, {})

            # Determine severity with validation
            raw_severity = finding.get("severity", "Medium")
            severity = self._normalize_severity(raw_severity)

            # Determine confidence
            confidence = finding.get("confidence", 0.70)
            if isinstance(confidence, str):
                try:
                    confidence = float(confidence)
                except ValueError:
                    confidence = 0.70
            confidence = max(0.0, min(1.0, confidence))

            # Build location object
            location = finding.get("location", {})
            if isinstance(location, str):
                location = {"file": "", "line": 0, "function": location}
            if not isinstance(location, dict):
                location = {}

            norm_finding = {
                "id": finding.get("id", f"llamaaudit-{idx + 1}"),
                "type": vuln_type,
                "severity": severity,
                "confidence": round(confidence, 2),
                "location": {
                    "file": location.get("file", finding.get("file", "")),
                    "line": location.get("line", finding.get("line", 0)),
                    "function": location.get(
                        "function", finding.get("function", "")
                    ),
                },
                "message": finding.get(
                    "message",
                    finding.get("title", "Vulnerability detected"),
                ),
                "description": finding.get(
                    "description",
                    registry_entry.get("description", ""),
                ),
                "recommendation": finding.get(
                    "recommendation", "Review and address the identified issue"
                ),
                "swc_id": finding.get(
                    "swc_id", registry_entry.get("swc_id", None)
                ),
                "cwe_id": finding.get(
                    "cwe_id", registry_entry.get("cwe_id", None)
                ),
            }

            normalized.append(norm_finding)

        return normalized

    def can_analyze(self, contract_path: str) -> bool:
        """Check if this adapter can analyze the given file."""
        return Path(contract_path).suffix == ".sol"

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration for the adapter."""
        return {
            "timeout": 180,
            "model": "codellama",
            "use_fallback": True,
            "max_retries": 2,
            "retry_delay": 2,
            "max_contract_chars": 24000,
        }

    # ============================================================================
    # PRIVATE: OLLAMA HTTP API METHODS
    # ============================================================================

    def _call_ollama_generate(
        self, prompt: str, timeout: int = 180
    ) -> Optional[str]:
        """
        Call Ollama generate API via HTTP POST.

        Sends a prompt to the codellama model and collects the streamed
        response into a single string.

        Args:
            prompt: The full prompt to send to the model
            timeout: Request timeout in seconds

        Returns:
            Complete response text, or None on failure
        """
        payload = json.dumps({
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_ctx": 8192,
                "top_p": 0.9,
            },
        }).encode("utf-8")

        req = urllib.request.Request(
            self._ollama_generate_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        for attempt in range(1, self._max_retries + 1):
            try:
                logger.info(
                    f"LlamaAudit: Calling Ollama generate "
                    f"(attempt {attempt}/{self._max_retries}, "
                    f"model={self._model})"
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if resp.status != 200:
                        logger.warning(
                            f"Ollama generate returned status {resp.status}"
                        )
                        continue

                    data = json.loads(resp.read().decode("utf-8"))
                    response_text = data.get("response", "")

                    if response_text:
                        logger.info(
                            f"LlamaAudit: Received response "
                            f"({len(response_text)} chars)"
                        )
                        return response_text
                    else:
                        logger.warning("Ollama returned empty response")

            except urllib.error.URLError as e:
                logger.warning(
                    f"LlamaAudit: HTTP error (attempt {attempt}): {e}"
                )
            except TimeoutError:
                logger.warning(
                    f"LlamaAudit: Request timeout after {timeout}s "
                    f"(attempt {attempt})"
                )
            except json.JSONDecodeError as e:
                logger.warning(
                    f"LlamaAudit: Invalid JSON response (attempt {attempt}): {e}"
                )
            except Exception as e:
                logger.error(
                    f"LlamaAudit: Unexpected error (attempt {attempt}): {e}"
                )

            if attempt < self._max_retries:
                time.sleep(self._retry_delay)

        return None

    def _check_ollama_available(self) -> bool:
        """Quick check if Ollama HTTP API is reachable."""
        try:
            req = urllib.request.Request(self._ollama_tags_url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False

    # ============================================================================
    # PRIVATE: LLM-BASED ANALYSIS
    # ============================================================================

    def _analyze_with_ollama(
        self,
        contract_code: str,
        contract_path: str,
        timeout: int,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Run security analysis using CodeLlama via Ollama HTTP API.

        Args:
            contract_code: Solidity source code
            contract_path: Path to the contract file
            timeout: Analysis timeout in seconds

        Returns:
            MIESC-formatted analysis result
        """
        start_time = time.time()

        # Truncate large contracts to fit context window
        truncated_code = self._truncate_code(contract_code)

        # Build audit prompt
        prompt = self.AUDIT_PROMPT.replace("%CONTRACT_CODE%", truncated_code)

        # Call Ollama
        raw_response = self._call_ollama_generate(prompt, timeout=timeout)

        if not raw_response:
            # LLM call failed - try fallback if enabled
            if kwargs.get("use_fallback", True):
                logger.warning(
                    "LlamaAudit: Ollama call failed, falling back to "
                    "pattern-based analysis"
                )
                return self._analyze_with_patterns(
                    contract_code, contract_path, start_time
                )
            return self._error_result(
                start_time, "Failed to get response from Ollama codellama model"
            )

        # Parse LLM response into findings
        raw_findings = self._parse_llm_response(raw_response, contract_path)

        # Normalize findings to MIESC format
        findings = self.normalize_findings({"findings": raw_findings})

        return {
            "tool": "llamaaudit",
            "version": "1.0.0",
            "status": "success",
            "findings": findings,
            "metadata": {
                "model": self._model,
                "backend": "ollama_http",
                "analysis_mode": "llm",
                "raw_findings_count": len(raw_findings),
                "normalized_count": len(findings),
                "sovereign": True,
                "dpga_compliant": True,
            },
            "execution_time": time.time() - start_time,
            "from_cache": False,
        }

    def _parse_llm_response(
        self, llm_response: str, contract_path: str
    ) -> List[Dict[str, Any]]:
        """
        Parse CodeLlama response and extract vulnerability findings.

        Attempts multiple parsing strategies:
        1. JSON block extraction (```json ... ```)
        2. Direct JSON object extraction ({ ... })
        3. Regex-based extraction as last resort

        Args:
            llm_response: Raw text response from CodeLlama
            contract_path: Path to the analyzed contract

        Returns:
            List of parsed finding dictionaries
        """
        findings = []

        # Strategy 1: Extract JSON from code block
        parsed = self._extract_json_block(llm_response)

        # Strategy 2: Extract raw JSON object
        if parsed is None:
            parsed = self._extract_json_object(llm_response)

        # Strategy 3: Regex extraction fallback
        if parsed is None:
            logger.warning(
                "LlamaAudit: JSON parsing failed, using regex extraction"
            )
            return self._extract_findings_regex(llm_response, contract_path)

        # Process parsed JSON findings
        llm_findings = parsed.get("findings", [])
        if isinstance(parsed, list):
            llm_findings = parsed

        for idx, f in enumerate(llm_findings):
            if not isinstance(f, dict):
                continue

            finding = {
                "id": f"llamaaudit-{idx + 1}",
                "type": f.get("type", "unknown"),
                "severity": f.get("severity", "Medium"),
                "confidence": f.get("confidence", 0.75),
                "title": f.get("title", "LLM-detected vulnerability"),
                "message": f.get("title", "LLM-detected vulnerability"),
                "description": f.get("description", ""),
                "location": {
                    "file": contract_path,
                    "line": f.get("line", 0),
                    "function": f.get("function", ""),
                },
                "recommendation": f.get(
                    "recommendation", "Review and address the identified issue"
                ),
                "swc_id": f.get("swc_id", None),
                "cwe_id": f.get("cwe_id", None),
                "attack_scenario": f.get("attack_scenario", ""),
            }
            findings.append(finding)

        logger.info(f"LlamaAudit: Parsed {len(findings)} findings from LLM")
        return findings

    def _extract_json_block(self, text: str) -> Optional[Dict]:
        """Extract JSON from a ```json code block."""
        match = re.search(r"```json\s*(.*?)\s*```", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass
        return None

    def _extract_json_object(self, text: str) -> Optional[Dict]:
        """Extract the outermost JSON object from text."""
        # Try finding {"findings": pattern first
        findings_match = re.search(r'\{\s*"findings"\s*:', text)
        if findings_match:
            start = findings_match.start()
            depth = 0
            for i, char in enumerate(text[start:]):
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[start:start + i + 1])
                        except json.JSONDecodeError:
                            break

        # Fallback: first { to last }
        json_start = text.find("{")
        json_end = text.rfind("}") + 1
        if json_start != -1 and json_end > json_start:
            try:
                return json.loads(text[json_start:json_end])
            except json.JSONDecodeError:
                # Try removing trailing commas
                cleaned = re.sub(r",\s*([}\]])", r"\1", text[json_start:json_end])
                try:
                    return json.loads(cleaned)
                except json.JSONDecodeError:
                    pass

        return None

    def _extract_findings_regex(
        self, text: str, contract_path: str
    ) -> List[Dict[str, Any]]:
        """
        Extract findings from LLM text using regex patterns.

        Last resort when JSON parsing fails entirely.
        """
        findings = []
        text_lower = text.lower()

        keyword_map = {
            "reentrancy": ("Critical", "reentrancy"),
            "re-entrancy": ("Critical", "reentrancy"),
            "integer overflow": ("High", "integer_overflow"),
            "integer underflow": ("High", "integer_overflow"),
            "access control": ("High", "access_control"),
            "authorization": ("High", "access_control"),
            "unchecked call": ("Medium", "unchecked_call"),
            "unchecked return": ("Medium", "unchecked_call"),
            "denial of service": ("High", "denial_of_service"),
            "front-run": ("Medium", "front_running"),
            "frontrun": ("Medium", "front_running"),
            "tx.origin": ("Medium", "tx_origin"),
            "selfdestruct": ("High", "selfdestruct"),
            "delegatecall": ("High", "delegatecall"),
            "timestamp": ("Low", "timestamp_dependence"),
        }

        seen_types = set()
        for keyword, (severity, vuln_type) in keyword_map.items():
            if keyword in text_lower and vuln_type not in seen_types:
                seen_types.add(vuln_type)
                registry_entry = VULNERABILITY_REGISTRY.get(vuln_type, {})

                findings.append({
                    "id": f"llamaaudit-regex-{len(findings) + 1}",
                    "type": vuln_type,
                    "severity": severity,
                    "confidence": 0.55,
                    "title": f"Potential {vuln_type.replace('_', ' ').title()}",
                    "message": f"LLM analysis mentions {keyword} vulnerability",
                    "description": registry_entry.get(
                        "description",
                        f"Potential {vuln_type} issue detected by LLM analysis.",
                    ),
                    "location": {
                        "file": contract_path,
                        "line": 0,
                        "function": "",
                    },
                    "recommendation": f"Review contract for {keyword} vulnerabilities.",
                    "swc_id": registry_entry.get("swc_id", None),
                    "cwe_id": registry_entry.get("cwe_id", None),
                })

        return findings

    # ============================================================================
    # PRIVATE: PATTERN-BASED FALLBACK ANALYSIS
    # ============================================================================

    def _analyze_with_patterns(
        self,
        contract_code: str,
        contract_path: str,
        start_time: float,
    ) -> Dict[str, Any]:
        """
        Perform pattern-based vulnerability analysis as fallback.

        Uses regex patterns to detect common Solidity vulnerability patterns
        without requiring an LLM backend.

        Args:
            contract_code: Solidity source code
            contract_path: Path to the contract file
            start_time: Analysis start timestamp

        Returns:
            MIESC-formatted analysis result
        """
        raw_findings = []
        lines = contract_code.split("\n")

        for rule in FALLBACK_PATTERNS:
            pattern = re.compile(rule["pattern"], re.MULTILINE | re.IGNORECASE)

            # Check context pattern if specified (e.g., Solidity version check)
            if rule.get("context_pattern"):
                context = re.compile(
                    rule["context_pattern"], re.MULTILINE | re.IGNORECASE
                )
                if not context.search(contract_code):
                    continue

            matches = list(pattern.finditer(contract_code))
            if not matches:
                continue

            for match_idx, match in enumerate(matches):
                # Calculate line number from match position
                line_num = contract_code[:match.start()].count("\n") + 1

                # Try to determine the enclosing function name
                function_name = self._find_enclosing_function(
                    lines, line_num - 1
                )

                registry_entry = VULNERABILITY_REGISTRY.get(rule["name"], {})

                finding = {
                    "id": f"llamaaudit-pattern-{rule['name']}-{match_idx + 1}",
                    "type": rule["name"],
                    "severity": rule["severity"],
                    "confidence": rule["confidence"],
                    "title": f"Pattern: {rule['name'].replace('_', ' ').title()}",
                    "message": rule["message"],
                    "description": registry_entry.get(
                        "description", rule["message"]
                    ),
                    "location": {
                        "file": contract_path,
                        "line": line_num,
                        "function": function_name,
                    },
                    "recommendation": rule["recommendation"],
                    "swc_id": registry_entry.get("swc_id", None),
                    "cwe_id": registry_entry.get("cwe_id", None),
                }
                raw_findings.append(finding)

        # Deduplicate findings by type + function to avoid noise
        deduped = self._deduplicate_findings(raw_findings)

        # Normalize through the standard pipeline
        findings = self.normalize_findings({"findings": deduped})

        return {
            "tool": "llamaaudit",
            "version": "1.0.0",
            "status": "success",
            "findings": findings,
            "metadata": {
                "model": "none",
                "backend": "pattern_fallback",
                "analysis_mode": "pattern",
                "raw_matches": len(raw_findings),
                "deduplicated_count": len(deduped),
                "normalized_count": len(findings),
                "note": "Ollama unavailable; results from pattern-based analysis only",
            },
            "execution_time": time.time() - start_time,
            "from_cache": False,
        }

    def _find_enclosing_function(
        self, lines: List[str], target_line: int
    ) -> str:
        """
        Find the name of the function enclosing the given line.

        Scans backward from the target line looking for a function declaration.
        """
        func_pattern = re.compile(
            r"function\s+(\w+)\s*\(", re.IGNORECASE
        )
        for i in range(target_line, max(target_line - 50, -1), -1):
            if i < 0 or i >= len(lines):
                continue
            match = func_pattern.search(lines[i])
            if match:
                return match.group(1)
        return ""

    def _deduplicate_findings(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Remove duplicate findings based on type + function combination.

        Keeps the finding with the highest confidence when duplicates exist.
        """
        seen = {}
        for finding in findings:
            key = (
                finding.get("type", ""),
                finding.get("location", {}).get("function", ""),
            )
            if key not in seen:
                seen[key] = finding
            else:
                # Keep the one with higher confidence
                if finding.get("confidence", 0) > seen[key].get("confidence", 0):
                    seen[key] = finding

        return list(seen.values())

    # ============================================================================
    # PRIVATE: UTILITY METHODS
    # ============================================================================

    def _read_contract(self, contract_path: str) -> Optional[str]:
        """Read contract file content."""
        try:
            with open(contract_path, "r", encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            logger.error(f"Contract file not found: {contract_path}")
            return None
        except PermissionError:
            logger.error(f"Permission denied reading: {contract_path}")
            return None
        except Exception as e:
            logger.error(f"Error reading contract: {e}")
            return None

    def _truncate_code(self, code: str) -> str:
        """Truncate contract code to fit within the model context window."""
        if len(code) <= self._max_contract_chars:
            return code
        logger.warning(
            f"LlamaAudit: Contract truncated from {len(code)} to "
            f"{self._max_contract_chars} chars"
        )
        return code[:self._max_contract_chars] + "\n// ... (truncated for analysis)"

    def _normalize_severity(self, raw_severity: str) -> str:
        """Normalize severity string to MIESC standard values."""
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
        return severity_map.get(raw_severity.strip().lower(), "Medium")

    def _error_result(self, start_time: float, error: str) -> Dict[str, Any]:
        """Create a standardized error result."""
        return {
            "tool": "llamaaudit",
            "version": "1.0.0",
            "status": "error",
            "findings": [],
            "metadata": {},
            "execution_time": time.time() - start_time,
            "error": error,
        }

    # ============================================================================
    # PRIVATE: CACHING
    # ============================================================================

    def _get_cache_key(self, contract_code: str) -> str:
        """Generate a deterministic cache key from contract code and model."""
        content = f"{self._model}:{contract_code}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached analysis result if available and fresh."""
        cache_file = self._cache_dir / f"{cache_key}.json"

        if not cache_file.exists():
            return None

        try:
            age_seconds = time.time() - cache_file.stat().st_mtime
            if age_seconds > 86400:  # 24-hour TTL
                logger.info(f"LlamaAudit: Cache expired for {cache_key[:12]}...")
                cache_file.unlink()
                return None

            with open(cache_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading cache: {e}")
            return None

    def _cache_result(self, cache_key: str, result: Dict[str, Any]) -> None:
        """Store analysis result in cache."""
        cache_file = self._cache_dir / f"{cache_key}.json"

        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            logger.info(f"LlamaAudit: Cached result for {cache_key[:12]}...")
        except Exception as e:
            logger.error(f"Error writing cache: {e}")


__all__ = ["LlamaAuditAdapter"]
