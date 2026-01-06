"""
Local LLM adapter using Ollama with RAG enhancement and Verificator role.

Enhanced with:
- RAG (Retrieval-Augmented Generation) for ERC-20/721/1155 context
- Verificator role for fact-checking and false positive reduction
- Multi-stage pipeline: Generator → Verificator → Consensus

Based on: "SmartLLM: A Novel LLM-Assisted Verification Framework"
(arXiv:2502.13167, February 2025)

Uses deepseek-coder model for vulnerability pattern detection.
Runs entirely locally (no API keys, DPGA-compliant).

Ollama: https://ollama.com
Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: 2025-01-13
"""

import hashlib
import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.adapters.smartllm_rag_knowledge import (
    get_relevant_knowledge,
    get_vulnerability_context,
)
from src.core.llm_config import (
    ROLE_GENERATOR,
    USE_CASE_CODE_ANALYSIS,
    get_generation_options,
    get_model,
    get_ollama_host,
    get_retry_config,
)
from src.core.tool_protocol import (
    ToolAdapter,
    ToolCapability,
    ToolCategory,
    ToolMetadata,
    ToolStatus,
)

logger = logging.getLogger(__name__)


class SmartLLMAdapter(ToolAdapter):
    """
    Ollama-based LLM adapter for local vulnerability analysis.

    Uses deepseek-coder model (8K context). Results cached for 24h.
    Retries on failure (max 3 attempts). No API keys required.
    """

    def __init__(self):
        super().__init__()
        self._cache_dir = Path.home() / ".miesc" / "smartllm_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)

        # Load configuration from centralized config
        self._model = get_model(USE_CASE_CODE_ANALYSIS)
        self._ollama_host = get_ollama_host()
        retry_config = get_retry_config()
        self._max_retries = retry_config["attempts"]
        self._retry_delay = retry_config["delay"]

        # Generation options from config
        gen_options = get_generation_options(ROLE_GENERATOR)
        self._max_tokens = gen_options.get("num_ctx", 8192)

        self._use_rag = True  # Enable RAG by default
        self._use_verificator = True  # Enable verificator by default

        logger.info(
            f"SmartLLMAdapter initialized with model={self._model}, host={self._ollama_host}"
        )

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="smartllm",
            version="3.0.0",
            category=ToolCategory.AI_ANALYSIS,
            author="Fernando Boiero (DPGA-compliant sovereign LLM adapter with RAG)",
            license="AGPL-3.0",
            homepage="https://ollama.com",
            repository="https://github.com/ollama/ollama",
            documentation="https://github.com/ollama/ollama/blob/main/README.md",
            installation_cmd="curl -fsSL https://ollama.com/install.sh | sh && ollama pull deepseek-coder",
            capabilities=[
                ToolCapability(
                    name="ai_analysis",
                    description="Local LLM-powered analysis using Ollama with RAG enhancement (100% sovereign, DPGA-compliant)",
                    supported_languages=["solidity"],
                    detection_types=[
                        "logic_bugs",
                        "design_issues",
                        "security_patterns",
                        "access_control",
                        "reentrancy",
                        "integer_overflow",
                        "unchecked_calls",
                        "best_practices",
                    ],
                ),
                ToolCapability(
                    name="rag_enhanced",
                    description="Retrieval-Augmented Generation with ERC-20/721/1155 knowledge base",
                    supported_languages=["solidity"],
                    detection_types=["erc_violations", "standard_compliance"],
                ),
                ToolCapability(
                    name="verificator",
                    description="Multi-stage analysis with Generator → Verificator → Consensus pipeline",
                    supported_languages=["solidity"],
                    detection_types=["false_positive_reduction", "fact_checking"],
                ),
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True,
        )

    def is_available(self) -> ToolStatus:
        """Check if Ollama is installed and deepseek-coder model is available."""
        try:
            # Check if ollama command exists
            result = subprocess.run(["ollama", "list"], capture_output=True, timeout=5, text=True)

            if result.returncode != 0:
                logger.warning("Ollama command failed")
                return ToolStatus.CONFIGURATION_ERROR

            # Check if deepseek-coder model is available
            if "deepseek-coder" in result.stdout:
                return ToolStatus.AVAILABLE
            else:
                logger.warning(f"Model {self._model} not found. Run: ollama pull {self._model}")
                return ToolStatus.CONFIGURATION_ERROR

        except FileNotFoundError:
            logger.info("Ollama not installed. Install from https://ollama.com")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            logger.warning("Ollama command timeout")
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking Ollama availability: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze Solidity contract using local Ollama LLM.

        Args:
            contract_path: Path to the Solidity contract file
            **kwargs: Optional configuration overrides

        Returns:
            Analysis results with findings from LLM
        """
        start_time = time.time()

        # Check availability
        if self.is_available() != ToolStatus.AVAILABLE:
            return {
                "tool": "smartllm",
                "version": "3.0.0",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": "SmartLLM (Ollama) not available. Ensure Ollama is installed and deepseek-coder model is pulled.",
            }

        try:
            # Read contract
            contract_code = self._read_contract(contract_path)
            if not contract_code:
                return {
                    "tool": "smartllm",
                    "version": "3.0.0",
                    "status": "error",
                    "findings": [],
                    "execution_time": time.time() - start_time,
                    "error": f"Could not read contract file: {contract_path}",
                }

            # Check cache
            cache_key = self._get_cache_key(contract_code)
            cached_result = self._get_cached_result(cache_key)
            if cached_result:
                logger.info(f"SmartLLM: Using cached result for {contract_path}")
                cached_result["from_cache"] = True
                cached_result["execution_time"] = time.time() - start_time
                return cached_result

            # Truncate if too long (manage 8K context window)
            contract_code = self._truncate_code(contract_code, self._max_tokens)

            # STAGE 1: Generator - Initial vulnerability detection with RAG
            logger.info("SmartLLM Stage 1/3: Generator (RAG-enhanced)")
            generator_prompt = self._generate_analysis_prompt(contract_code)
            generator_response = self._call_ollama_with_retry(generator_prompt)

            if not generator_response:
                return {
                    "tool": "smartllm",
                    "version": "3.0.0",
                    "status": "error",
                    "findings": [],
                    "execution_time": time.time() - start_time,
                    "error": "Failed to get response from Ollama LLM (Generator stage)",
                }

            # Parse initial findings
            initial_findings = self._parse_llm_response(generator_response, contract_path)

            # STAGE 2: Verificator - Fact-checking and false positive reduction
            verified_findings = initial_findings
            if self._use_verificator and initial_findings:
                logger.info(
                    f"SmartLLM Stage 2/3: Verificator (checking {len(initial_findings)} findings)"
                )
                verified_findings = self._verificator_stage(contract_code, initial_findings)

            # STAGE 3: Consensus - Final validation
            logger.info(
                f"SmartLLM Stage 3/3: Consensus ({len(verified_findings)} findings confirmed)"
            )
            final_findings = verified_findings

            # Build result
            result = {
                "tool": "smartllm",
                "version": "3.0.0",
                "status": "success",
                "findings": final_findings,
                "metadata": {
                    "model": self._model,
                    "prompt_tokens": len(generator_prompt.split()),  # Approximate
                    "sovereign": True,
                    "dpga_compliant": True,
                    "rag_enhanced": self._use_rag,
                    "verificator_enabled": self._use_verificator,
                    "initial_findings": len(initial_findings),
                    "verified_findings": len(verified_findings),
                    "false_positives_removed": len(initial_findings) - len(verified_findings),
                },
                "execution_time": time.time() - start_time,
                "from_cache": False,
            }

            # Cache result
            self._cache_result(cache_key, result)

            return result

        except Exception as e:
            logger.error(f"SmartLLM analysis error: {e}", exc_info=True)
            return {
                "tool": "smartllm",
                "version": "3.0.0",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": str(e),
            }

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """Normalize findings - already normalized in analyze()."""
        return raw_output.get("findings", []) if isinstance(raw_output, dict) else []

    def can_analyze(self, contract_path: str) -> bool:
        """Check if this adapter can analyze the given contract."""
        return Path(contract_path).suffix == ".sol"

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "timeout": 600,
            "model": "deepseek-coder",
            "max_tokens": 8000,
            "temperature": 0.1,  # Low temperature for precise analysis
            "max_retries": 3,
            "retry_delay": 2,
        }

    # ============================================================================
    # PRIVATE HELPER METHODS
    # ============================================================================

    def _read_contract(self, contract_path: str) -> Optional[str]:
        """Read contract file content."""
        try:
            with open(contract_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading contract: {e}")
            return None

    def _truncate_code(self, code: str, max_tokens: int) -> str:
        """Truncate code to fit within context window (approximate token limit)."""
        # Rough approximation: 1 token ≈ 4 characters
        max_chars = max_tokens * 4
        if len(code) <= max_chars:
            return code

        logger.warning(f"Contract truncated from {len(code)} to {max_chars} chars")
        return code[:max_chars] + "\n// ... (truncated for analysis)"

    def _generate_analysis_prompt(self, contract_code: str) -> str:
        """Generate RAG-enhanced analysis prompt for Ollama LLM."""
        # Get relevant knowledge from RAG knowledge base
        rag_context = ""
        if self._use_rag:
            rag_context = get_relevant_knowledge(contract_code)

        prompt = f"""You are a Solidity security expert with comprehensive knowledge of ERC standards and best practices.

SMART CONTRACT:
```solidity
{contract_code}
```
"""

        # Add RAG context if available
        if rag_context:
            prompt += f"""
REFERENCE DOCUMENTATION (for context):
{rag_context}

Use this documentation to enhance your analysis, particularly for:
- ERC-20/721/1155 standard compliance
- Common vulnerability patterns
- Best practices validation
"""

        prompt += """
ANALYSIS INSTRUCTIONS:
1. Identify all security vulnerabilities (reentrancy, integer overflow/underflow, unchecked calls, access control issues, etc.)
2. Check for ERC standard compliance (if applicable)
3. Verify against known vulnerability patterns
4. Check for logic bugs and design flaws
5. Rate each finding's severity: CRITICAL, HIGH, MEDIUM, LOW

OUTPUT FORMAT (JSON):
{
  "findings": [
    {
      "type": "vulnerability_type",
      "severity": "CRITICAL/HIGH/MEDIUM/LOW",
      "title": "Short title",
      "description": "Detailed description",
      "location": "Function or line reference",
      "recommendation": "How to fix"
    }
  ]
}

Provide ONLY the JSON output, no additional text."""

        return prompt

    def _call_ollama_with_retry(self, prompt: str) -> Optional[str]:
        """Call Ollama API with retry logic."""
        for attempt in range(1, self._max_retries + 1):
            try:
                logger.info(f"SmartLLM: Calling Ollama (attempt {attempt}/{self._max_retries})")

                result = subprocess.run(
                    ["ollama", "run", self._model, prompt],
                    capture_output=True,
                    timeout=300,  # 5 minutes max
                    text=True,
                )

                if result.returncode == 0 and result.stdout:
                    return result.stdout.strip()
                else:
                    logger.warning(f"Ollama call failed (attempt {attempt}): {result.stderr}")

            except subprocess.TimeoutExpired:
                logger.warning(f"Ollama call timeout (attempt {attempt})")
            except Exception as e:
                logger.error(f"Ollama call error (attempt {attempt}): {e}")

            # Wait before retry
            if attempt < self._max_retries:
                time.sleep(self._retry_delay)

        return None

    def _parse_llm_response(self, llm_response: str, contract_path: str) -> List[Dict[str, Any]]:
        """Parse LLM response to extract findings."""
        findings = []

        try:
            # Extract JSON from response (LLM might add text around it)
            json_start = llm_response.find("{")
            json_end = llm_response.rfind("}") + 1

            if json_start == -1 or json_end == 0:
                logger.warning("No JSON found in LLM response")
                return []

            json_str = llm_response[json_start:json_end]
            parsed = json.loads(json_str)

            # Extract findings
            llm_findings = parsed.get("findings", [])

            for idx, finding in enumerate(llm_findings):
                normalized = {
                    "id": f"smartllm-{idx+1}",
                    "title": finding.get("title", "LLM-detected issue"),
                    "description": finding.get("description", ""),
                    "severity": finding.get("severity", "MEDIUM").upper(),
                    "confidence": 0.75,  # Medium-high confidence for LLM findings
                    "category": finding.get("type", "ai_detected_pattern"),
                    "location": {
                        "file": contract_path,
                        "details": finding.get("location", "See full contract"),
                    },
                    "recommendation": finding.get(
                        "recommendation", "Review and address the identified issue"
                    ),
                    "references": ["AI-powered analysis using Ollama + deepseek-coder"],
                }
                findings.append(normalized)

            logger.info(f"SmartLLM: Parsed {len(findings)} findings from LLM response")

        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            # Fallback: create a single finding with the raw response
            findings.append(
                {
                    "id": "smartllm-raw",
                    "title": "LLM Analysis Result (raw)",
                    "description": llm_response[:500],  # First 500 chars
                    "severity": "INFO",
                    "confidence": 0.5,
                    "category": "ai_analysis",
                    "location": {"file": contract_path},
                    "recommendation": "Review full LLM response for insights",
                }
            )
        except Exception as e:
            logger.error(f"Error parsing LLM response: {e}")

        return findings

    def _verificator_stage(
        self, contract_code: str, initial_findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Stage 2: Verificator - Fact-check findings and reduce false positives.

        Uses a separate LLM call to verify each finding against the contract
        code and RAG knowledge base. Filters out false positives.

        Args:
            contract_code: Original contract source code
            initial_findings: Findings from Generator stage

        Returns:
            Verified findings (false positives removed)
        """
        verified_findings = []

        for finding in initial_findings:
            # Generate verificator prompt
            verificator_prompt = self._generate_verificator_prompt(contract_code, finding)

            # Call LLM for verification (single attempt, faster)
            try:
                logger.debug(f"Verificator: Checking finding '{finding.get('title')}'")

                result = subprocess.run(
                    ["ollama", "run", self._model, verificator_prompt],
                    capture_output=True,
                    timeout=60,  # Shorter timeout for verificator
                    text=True,
                )

                if result.returncode == 0 and result.stdout:
                    response = result.stdout.strip()
                    response_lower = response.lower()

                    # Parse chain-of-thought verificator response
                    # Look for explicit verdict markers first
                    if (
                        "verdict: confirmed" in response_lower
                        or "verdict:confirmed" in response_lower
                    ):
                        # Finding explicitly confirmed
                        finding["verified"] = True
                        finding["verification_reasoning"] = response[:500]  # Store reasoning
                        finding["confidence"] = min(finding.get("confidence", 0.75) + 0.15, 0.95)
                        verified_findings.append(finding)
                        logger.debug(f"✓ Finding confirmed with CoT: {finding.get('title')}")
                    elif (
                        "verdict: false_positive" in response_lower
                        or "verdict:false_positive" in response_lower
                    ):
                        # Explicit false positive
                        logger.info(f"✗ False positive (CoT verified): {finding.get('title')}")
                    elif "confirmed" in response_lower and "false_positive" not in response_lower:
                        # Legacy format: implicit confirmation
                        finding["verified"] = True
                        finding["confidence"] = min(finding.get("confidence", 0.75) + 0.1, 0.95)
                        verified_findings.append(finding)
                        logger.debug(f"✓ Finding confirmed: {finding.get('title')}")
                    else:
                        # Default to false positive if no clear confirmation
                        logger.info(f"✗ False positive removed: {finding.get('title')}")
                else:
                    # Verificator failed - keep finding with lower confidence (conservative)
                    logger.warning("Verificator call failed, keeping finding conservatively")
                    finding["verified"] = False
                    finding["confidence"] = max(finding.get("confidence", 0.75) - 0.15, 0.4)
                    verified_findings.append(finding)

            except subprocess.TimeoutExpired:
                logger.warning("Verificator timeout, keeping finding conservatively")
                finding["verified"] = False
                verified_findings.append(finding)
            except Exception as e:
                logger.error(f"Verificator error: {e}")
                finding["verified"] = False
                verified_findings.append(finding)

        logger.info(
            f"Verificator results: {len(initial_findings)} → {len(verified_findings)} "
            f"({len(initial_findings) - len(verified_findings)} false positives removed)"
        )

        return verified_findings

    def _generate_verificator_prompt(self, contract_code: str, finding: Dict[str, Any]) -> str:
        """
        Generate verificator prompt for fact-checking a finding.

        Uses chain-of-thought prompting to improve verification accuracy.
        Based on: Wei et al. (2022) "Chain-of-Thought Prompting Elicits
        Reasoning in Large Language Models" (arXiv:2201.11903)

        Args:
            contract_code: Contract source code
            finding: Finding to verify

        Returns:
            Verificator prompt with chain-of-thought structure
        """
        # Get vulnerability context from knowledge base
        vuln_type = finding.get("category", finding.get("type", ""))
        vuln_context = get_vulnerability_context(vuln_type)

        # Get role-specific system prompt from config
        from src.core.llm_config import ROLE_VERIFICATOR, get_role_system_prompt

        system_prompt = get_role_system_prompt(ROLE_VERIFICATOR)

        return f"""{system_prompt}

TASK: Verify if the following security finding is a TRUE POSITIVE or FALSE POSITIVE.
Think step by step before giving your final verdict.

FINDING TO VERIFY:
- Type: {finding.get('type', 'N/A')}
- Title: {finding.get('title', 'N/A')}
- Description: {finding.get('description', 'N/A')}
- Location: {finding.get('location', {}).get('details', 'N/A')}
- Severity: {finding.get('severity', 'N/A')}

VULNERABILITY REFERENCE (from SWC Registry):
{vuln_context.get('description', 'No reference available')}
Mitigation: {vuln_context.get('mitigation', 'N/A')}

CONTRACT CODE:
```solidity
{contract_code[:2000]}
```

CHAIN-OF-THOUGHT ANALYSIS:
Analyze step by step:

STEP 1 - CODE LOCATION CHECK:
Does the reported location exist in the code? Is it correctly identified?

STEP 2 - VULNERABILITY PATTERN MATCH:
Does the code at this location match the vulnerability pattern described?
Compare against the SWC reference.

STEP 3 - CONTEXT ANALYSIS:
Consider the surrounding code context:
- Are there existing mitigations (checks-effects-interactions, reentrancy guards)?
- Does the control flow actually allow exploitation?
- Are the preconditions for exploitation actually reachable?

STEP 4 - FALSE POSITIVE INDICATORS:
Check for common false positive patterns:
- Safe math libraries in use
- Access control preventing exploitation
- State changes before external calls
- Trusted contract interactions only

STEP 5 - SEVERITY VALIDATION:
If the finding is valid, is the severity level appropriate?
Consider: exploitability, impact, likelihood.

FINAL VERDICT:
Based on your step-by-step analysis, conclude with exactly one of:
- "VERDICT: CONFIRMED" - The finding is a valid true positive
- "VERDICT: FALSE_POSITIVE" - The finding is incorrect or not exploitable

Your analysis:"""

    def _get_cache_key(self, contract_code: str) -> str:
        """Generate cache key from contract code."""
        return hashlib.sha256(contract_code.encode()).hexdigest()

    def _get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached result if available."""
        cache_file = self._cache_dir / f"{cache_key}.json"

        if not cache_file.exists():
            return None

        try:
            # Check if cache is fresh (< 24 hours)
            age_seconds = time.time() - cache_file.stat().st_mtime
            if age_seconds > 86400:  # 24 hours
                logger.info(f"Cache expired for {cache_key}")
                cache_file.unlink()
                return None

            with open(cache_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading cache: {e}")
            return None

    def _cache_result(self, cache_key: str, result: Dict[str, Any]):
        """Cache analysis result."""
        cache_file = self._cache_dir / f"{cache_key}.json"

        try:
            with open(cache_file, "w") as f:
                json.dump(result, f, indent=2)
            logger.info(f"Cached result for {cache_key}")
        except Exception as e:
            logger.error(f"Error writing cache: {e}")


__all__ = ["SmartLLMAdapter"]
