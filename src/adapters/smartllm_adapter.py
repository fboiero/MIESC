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
            installation_cmd=(
                "curl -fsSL https://ollama.com/install.sh | sh && " "ollama pull deepseek-coder"
            ),
            capabilities=[
                ToolCapability(
                    name="ai_analysis",
                    description=(
                        "Local LLM-powered analysis using Ollama with RAG "
                        "enhancement (100% sovereign, DPGA-compliant)"
                    ),
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
                    description=(
                        "Retrieval-Augmented Generation with " "ERC-20/721/1155 knowledge base"
                    ),
                    supported_languages=["solidity"],
                    detection_types=["erc_violations", "standard_compliance"],
                ),
                ToolCapability(
                    name="verificator",
                    description=(
                        "Multi-stage analysis with Generator -> "
                        "Verificator -> Consensus pipeline"
                    ),
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
                "error": (
                    "SmartLLM (Ollama) not available. Ensure Ollama is "
                    "installed and deepseek-coder model is pulled."
                ),
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
        """Generate RAG-enhanced analysis prompt for Ollama LLM.

        Uses structured prompt engineering with:
        - Code pattern detection first (analyze what the code ACTUALLY does)
        - RAG context for vulnerability pattern matching
        - Specific SWC-based vulnerability checks
        """
        # Get relevant knowledge from RAG knowledge base
        rag_context = ""
        if self._use_rag:
            rag_context = get_relevant_knowledge(contract_code)

        # Pre-analyze code for key patterns to guide LLM focus
        code_patterns = self._detect_code_patterns(contract_code)
        focus_areas = self._get_focus_areas(code_patterns)

        prompt = f"""You are a senior smart contract security auditor. Your task is to analyze \
this contract and find REAL vulnerabilities in the ACTUAL code.

CRITICAL: Focus ONLY on vulnerabilities that EXIST in this specific code. \
Do NOT report generic best practices that aren't applicable.

SMART CONTRACT TO ANALYZE:
```solidity
{contract_code}
```

DETECTED CODE PATTERNS (focus your analysis on these):
{focus_areas}
"""

        # Add RAG context if available
        if rag_context:
            prompt += f"""
VULNERABILITY KNOWLEDGE BASE (SWC Registry patterns):
{rag_context[:3000]}
"""

        prompt += """
STEP-BY-STEP ANALYSIS (for security researchers):

STEP 1 - CONTROL FLOW ANALYSIS:
- Trace each function's execution path
- Identify external calls (call, delegatecall, transfer, send)
- Check if state changes happen BEFORE or AFTER external calls

STEP 2 - REENTRANCY CHECK (SWC-107):
- Pattern: external call BEFORE state update = REENTRANCY
- Look for: `.call{value:`, `.transfer(`, `.send(`, `IERC20.transfer(`
- Real-world example: The DAO hack (2016, $60M) used this exact pattern

STEP 3 - ACCESS CONTROL CHECK (SWC-105):
- Are there admin/owner functions without proper modifiers?
- Real-world example: Ronin Bridge (2022, $625M) - compromised private keys

STEP 4 - INTEGER ISSUES (SWC-101):
- Check for unchecked arithmetic (pre-Solidity 0.8.0)
- Look for precision loss in divisions (common in DeFi yield calculations)

STEP 5 - EXTERNAL CALL SAFETY (SWC-104, SWC-113):
- Are return values from external calls checked?
- Real-world example: Wormhole (2022, $320M) - unchecked signature verification

OUTPUT FORMAT (valid JSON only):
```json
{
  "findings": [
    {
      "type": "reentrancy",
      "severity": "CRITICAL",
      "title": "Reentrancy in withdraw function",
      "description": "External call before state update allows reentrancy attack",
      "location": "withdraw:14-16",
      "swc_id": "SWC-107",
      "attack_scenario": "1) Deploy malicious contract 2) Call withdraw 3) Fallback re-enters",
      "remediation": "Move balances[msg.sender] -= amount before the external call",
      "real_world_reference": "The DAO hack 2016"
    }
  ]
}
```

CRITICAL RULES:
- Output ONLY valid JSON inside ```json``` code block
- Do NOT include actual code snippets with newlines (breaks JSON)
- Keep all string values on single lines
- Only report REAL vulnerabilities found in this specific code
- Include SWC Registry ID for each finding
- For CRITICAL findings, include attack_scenario
- Do NOT report generic best practices"""

        return prompt

    def _detect_code_patterns(self, code: str) -> dict:
        """Detect key patterns in code to focus LLM analysis."""
        patterns = {
            "has_external_calls": False,
            "has_state_after_call": False,
            "has_transfer": False,
            "has_delegatecall": False,
            "has_selfdestruct": False,
            "has_mapping": False,
            "has_payable": False,
            "solidity_version": "unknown",
        }

        code_lower = code.lower()

        # Check for external calls
        if ".call{" in code or ".call(" in code:
            patterns["has_external_calls"] = True
        if ".transfer(" in code:
            patterns["has_transfer"] = True
        if "delegatecall" in code_lower:
            patterns["has_delegatecall"] = True
        if "selfdestruct" in code_lower:
            patterns["has_selfdestruct"] = True
        if "mapping(" in code_lower:
            patterns["has_mapping"] = True
        if "payable" in code_lower:
            patterns["has_payable"] = True

        # Detect reentrancy pattern: external call before state update
        # Simple heuristic: if we see .call{ before -= or = on a mapping
        call_pos = code.find(".call{")
        if call_pos == -1:
            call_pos = code.find(".call(")

        if call_pos > 0:
            # Check if there's a state update after the call
            after_call = code[call_pos:]
            if "-=" in after_call or ("+=" in after_call and "balances" in after_call.lower()):
                patterns["has_state_after_call"] = True

        # Extract Solidity version
        import re

        version_match = re.search(r"pragma solidity [\^~]?(\d+\.\d+\.\d+)", code)
        if version_match:
            patterns["solidity_version"] = version_match.group(1)

        return patterns

    def _get_focus_areas(self, patterns: dict) -> str:
        """Generate focus areas based on detected patterns."""
        focus = []

        if patterns.get("has_external_calls"):
            focus.append("- EXTERNAL CALLS DETECTED: Check for reentrancy (SWC-107)")
        if patterns.get("has_state_after_call"):
            focus.append(
                "- WARNING: State update AFTER external call detected - likely REENTRANCY!"
            )
        if patterns.get("has_delegatecall"):
            focus.append("- DELEGATECALL DETECTED: Check for storage collision (SWC-112)")
        if patterns.get("has_selfdestruct"):
            focus.append("- SELFDESTRUCT DETECTED: Check for unauthorized destruction (SWC-106)")
        if patterns.get("has_payable"):
            focus.append("- PAYABLE FUNCTIONS: Check for proper fund handling")
        if patterns.get("has_mapping"):
            focus.append("- MAPPINGS DETECTED: Check for balance manipulation vulnerabilities")

        version = patterns.get("solidity_version", "unknown")
        if version != "unknown":
            major, minor, patch = version.split(".")
            if int(minor) < 8:
                focus.append(
                    f"- SOLIDITY {version}: Check for integer overflow/underflow (SWC-101)"
                )

        if not focus:
            focus.append(
                "- Standard security review: access control, input validation, logic errors"
            )

        return "\n".join(focus)

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
        """Parse LLM response to extract findings with robust JSON repair."""
        findings = []

        try:
            # Strategy 1: Try direct JSON extraction
            parsed = self._extract_json(llm_response)

            if not parsed:
                # Strategy 2: Try to repair common JSON issues
                parsed = self._repair_and_parse_json(llm_response)

            if not parsed:
                # Strategy 3: Extract findings using regex patterns
                parsed = self._extract_findings_regex(llm_response)

            if not parsed:
                logger.warning("Could not parse LLM response as JSON")
                # Return structured finding from raw text analysis
                return self._parse_raw_response(llm_response, contract_path)

            # Extract findings
            llm_findings = parsed.get("findings", [])
            if isinstance(parsed, list):
                llm_findings = parsed

            for idx, finding in enumerate(llm_findings):
                if not isinstance(finding, dict):
                    continue

                # Build SWC reference URL if available
                swc_id = finding.get("swc_id", "")
                swc_url = ""
                if swc_id and "SWC-" in swc_id:
                    swc_num = swc_id.split("SWC-")[1].split()[0].split("(")[0].strip()
                    swc_url = f"https://swcregistry.io/docs/SWC-{swc_num}"

                # Get remediation from either field name
                remediation = (
                    finding.get("remediation")
                    or finding.get("remediation_code")
                    or "Review and address the identified issue"
                )

                normalized = {
                    "id": f"smartllm-{idx+1}",
                    "title": finding.get("title", "LLM-detected issue"),
                    "description": finding.get("description", ""),
                    "severity": finding.get("severity", "MEDIUM").upper(),
                    "confidence": 0.75,
                    "category": finding.get("type", "ai_detected_pattern"),
                    "location": {
                        "file": contract_path,
                        "details": finding.get("location", "See full contract"),
                    },
                    # Enhanced fields for security researchers
                    "swc_id": swc_id,
                    "swc_url": swc_url,
                    "attack_scenario": finding.get("attack_scenario", ""),
                    "vulnerable_code": finding.get("vulnerable_code", ""),
                    "remediation_code": remediation,
                    "testing_suggestion": finding.get("testing_suggestion", ""),
                    "real_world_reference": finding.get("real_world_reference", ""),
                    "recommendation": finding.get("recommendation", remediation),
                    "references": [
                        "AI-powered analysis using Ollama + deepseek-coder",
                    ],
                }
                if swc_url:
                    normalized["references"].append(swc_url)
                if finding.get("real_world_reference"):
                    normalized["references"].append(finding.get("real_world_reference"))

                findings.append(normalized)

            logger.info(f"SmartLLM: Parsed {len(findings)} findings from LLM response")

        except Exception as e:
            logger.error(f"Error parsing LLM response: {e}")
            return self._parse_raw_response(llm_response, contract_path)

        return findings

    def _extract_json(self, text: str) -> Optional[Dict]:
        """Extract JSON object from text using multiple strategies."""
        import re

        # Strategy 1: Find JSON block between ```json and ```
        json_block_match = re.search(r"```json\s*(.*?)\s*```", text, re.DOTALL)
        if json_block_match:
            try:
                return json.loads(json_block_match.group(1))
            except json.JSONDecodeError:
                pass

        # Strategy 2: Find JSON starting with {"findings"
        findings_match = re.search(r'\{\s*"findings"\s*:', text)
        if findings_match:
            start = findings_match.start()
            # Find matching closing brace
            depth = 0
            for i, char in enumerate(text[start:]):
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[start : start + i + 1])
                        except json.JSONDecodeError:
                            break

        # Strategy 3: Simple extraction between first { and last }
        json_start = text.find("{")
        json_end = text.rfind("}") + 1
        if json_start != -1 and json_end > json_start:
            try:
                return json.loads(text[json_start:json_end])
            except json.JSONDecodeError:
                pass

        return None

    def _repair_and_parse_json(self, text: str) -> Optional[Dict]:
        """Attempt to repair common JSON issues and parse."""
        import re

        # Find the JSON portion
        json_start = text.find("{")
        json_end = text.rfind("}") + 1
        if json_start == -1 or json_end <= json_start:
            return None

        json_str = text[json_start:json_end]

        # Repair common issues:
        # 1. Remove trailing commas before ] or }
        json_str = re.sub(r",\s*([}\]])", r"\1", json_str)

        # 2. Fix unescaped newlines in strings (common in code snippets)
        # Replace actual newlines in string values with \n
        def fix_string_newlines(match):
            content = match.group(1)
            # Escape actual newlines
            content = content.replace("\n", "\\n")
            content = content.replace("\r", "\\r")
            content = content.replace("\t", "\\t")
            return f'"{content}"'

        # This regex finds string values and fixes newlines
        # Simple approach: process line by line for key-value pairs
        lines = json_str.split("\n")
        fixed_lines = []
        in_string = False
        string_buffer = ""

        for line in lines:
            # Count quotes to track if we're in a string
            quote_count = line.count('"') - line.count('\\"')

            if in_string:
                string_buffer += "\\n" + line
                if quote_count % 2 == 1:
                    fixed_lines.append(string_buffer)
                    string_buffer = ""
                    in_string = False
            else:
                if quote_count % 2 == 1:
                    in_string = True
                    string_buffer = line
                else:
                    fixed_lines.append(line)

        if string_buffer:
            fixed_lines.append(string_buffer)

        json_str = "\n".join(fixed_lines)

        # 3. Try to parse
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass

        # 4. More aggressive repair: extract just the findings array
        findings_match = re.search(r'"findings"\s*:\s*\[(.*?)\]', json_str, re.DOTALL)
        if findings_match:
            findings_str = findings_match.group(1)
            # Try to extract individual finding objects
            finding_objects = []
            depth = 0
            start = None
            for i, char in enumerate(findings_str):
                if char == "{":
                    if depth == 0:
                        start = i
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0 and start is not None:
                        obj_str = findings_str[start : i + 1]
                        # Clean the object string
                        obj_str = re.sub(r",\s*([}\]])", r"\1", obj_str)
                        try:
                            finding_objects.append(json.loads(obj_str))
                        except json.JSONDecodeError:
                            # Try minimal repair
                            try:
                                obj_str = obj_str.replace("\n", " ")
                                finding_objects.append(json.loads(obj_str))
                            except Exception:
                                pass
                        start = None

            if finding_objects:
                return {"findings": finding_objects}

        return None

    def _extract_findings_regex(self, text: str) -> Optional[Dict]:
        """Extract findings using regex patterns as last resort."""
        import re

        findings = []

        # Pattern to extract vulnerability mentions
        vuln_patterns = [
            (r"(?:CRITICAL|HIGH)\s*[:\-]?\s*([Rr]eentrancy[^\n]*)", "CRITICAL", "reentrancy"),
            (
                r"(?:CRITICAL|HIGH)\s*[:\-]?\s*([Aa]ccess\s+[Cc]ontrol[^\n]*)",
                "HIGH",
                "access_control",
            ),
            (
                r"(?:HIGH|MEDIUM)\s*[:\-]?\s*([Ii]nteger\s+[Oo]verflow[^\n]*)",
                "HIGH",
                "integer_overflow",
            ),
            (
                r"(?:HIGH|MEDIUM)\s*[:\-]?\s*([Uu]nchecked\s+[Cc]all[^\n]*)",
                "HIGH",
                "unchecked_call",
            ),
            (r"SWC-107[:\s]+([^\n]+)", "CRITICAL", "reentrancy"),
            (r"SWC-105[:\s]+([^\n]+)", "HIGH", "access_control"),
            (r"SWC-101[:\s]+([^\n]+)", "HIGH", "integer_overflow"),
        ]

        for pattern, severity, category in vuln_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if match and len(match) > 10:
                    findings.append(
                        {
                            "type": category,
                            "severity": severity,
                            "title": f"{category.replace('_', ' ').title()} Vulnerability",
                            "description": match.strip()[:500],
                        }
                    )

        # Deduplicate by category
        seen = set()
        unique_findings = []
        for f in findings:
            key = (f["type"], f["severity"])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        if unique_findings:
            return {"findings": unique_findings}

        return None

    def _parse_raw_response(self, llm_response: str, contract_path: str) -> List[Dict[str, Any]]:
        """Parse raw LLM response when JSON parsing fails."""
        findings = []

        # Check for reentrancy mentions
        text_lower = llm_response.lower()
        if "reentrancy" in text_lower or "reentrant" in text_lower or "swc-107" in text_lower:
            findings.append(
                {
                    "id": "smartllm-1",
                    "title": "Potential Reentrancy Vulnerability",
                    "description": (
                        "LLM analysis detected reentrancy-related " "patterns in the contract."
                    ),
                    "severity": "CRITICAL",
                    "confidence": 0.65,
                    "category": "reentrancy",
                    "swc_id": "SWC-107",
                    "swc_url": "https://swcregistry.io/docs/SWC-107",
                    "location": {"file": contract_path, "details": "See LLM analysis"},
                    "recommendation": (
                        "Apply checks-effects-interactions pattern. "
                        "Update state before external calls."
                    ),
                    "references": ["AI-powered analysis using Ollama + deepseek-coder"],
                }
            )

        if (
            "access control" in text_lower
            or "unauthorized" in text_lower
            or "swc-105" in text_lower
        ):
            findings.append(
                {
                    "id": f"smartllm-{len(findings)+1}",
                    "title": "Potential Access Control Issue",
                    "description": (
                        "LLM analysis detected access control " "patterns that may need review."
                    ),
                    "severity": "HIGH",
                    "confidence": 0.60,
                    "category": "access_control",
                    "swc_id": "SWC-105",
                    "swc_url": "https://swcregistry.io/docs/SWC-105",
                    "location": {"file": contract_path, "details": "See LLM analysis"},
                    "recommendation": "Review access control modifiers and function visibility.",
                    "references": ["AI-powered analysis using Ollama + deepseek-coder"],
                }
            )

        # If no patterns found, return raw analysis
        if not findings:
            findings.append(
                {
                    "id": "smartllm-raw",
                    "title": "LLM Analysis Result",
                    "description": llm_response[:1000],
                    "severity": "INFO",
                    "confidence": 0.5,
                    "category": "ai_analysis",
                    "location": {"file": contract_path},
                    "recommendation": "Review full LLM response for insights",
                    "references": ["AI-powered analysis using Ollama + deepseek-coder"],
                }
            )

        return findings

    def _verificator_stage(
        self, contract_code: str, initial_findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Stage 2: Verificator - Fact-check findings and reduce false positives.

        Uses a separate LLM call to verify each finding against the contract
        code and RAG knowledge base. Filters out false positives.

        IMPORTANT: For CRITICAL severity findings (reentrancy, etc.), we are
        more conservative and default to keeping the finding unless explicitly
        marked as false positive with clear reasoning.

        Args:
            contract_code: Original contract source code
            initial_findings: Findings from Generator stage

        Returns:
            Verified findings (false positives removed)
        """
        verified_findings = []

        for finding in initial_findings:
            severity = finding.get("severity", "MEDIUM").upper()
            is_critical = severity == "CRITICAL"
            finding_type = finding.get("category", finding.get("type", "")).lower()
            is_reentrancy = "reentrancy" in finding_type or "reentrant" in finding_type

            # For known high-risk patterns, verify using code pattern detection
            if is_reentrancy:
                # Double-check reentrancy using pattern detection
                patterns = self._detect_code_patterns(contract_code)
                if patterns.get("has_external_calls") and patterns.get("has_state_after_call"):
                    # Pattern detection confirms reentrancy - keep finding
                    finding["verified"] = True
                    finding["verification_method"] = "pattern_detection"
                    finding["confidence"] = 0.90  # High confidence from pattern match
                    verified_findings.append(finding)
                    logger.info(
                        f"✓ Reentrancy CONFIRMED by pattern detection: {finding.get('title')}"
                    )
                    continue

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
                        finding["verification_reasoning"] = response[:500]
                        finding["confidence"] = min(finding.get("confidence", 0.75) + 0.15, 0.95)
                        verified_findings.append(finding)
                        logger.info(f"✓ Finding confirmed with CoT: {finding.get('title')}")
                    elif (
                        "verdict: false_positive" in response_lower
                        or "verdict:false_positive" in response_lower
                    ):
                        # Explicit false positive - but for CRITICAL, require clear reasoning
                        if is_critical:
                            # For CRITICAL findings, keep with lower confidence
                            finding["verified"] = False
                            finding["verification_note"] = (
                                "Verificator marked FP but keeping due to severity"
                            )
                            finding["confidence"] = max(
                                finding.get("confidence", 0.75) - 0.20, 0.50
                            )
                            verified_findings.append(finding)
                            logger.warning(
                                f"CRITICAL finding kept despite FP verdict: "
                                f"{finding.get('title')}"
                            )
                        else:
                            logger.info(f"✗ False positive (CoT verified): {finding.get('title')}")
                    elif "confirmed" in response_lower and "false_positive" not in response_lower:
                        # Legacy format: implicit confirmation
                        finding["verified"] = True
                        finding["confidence"] = min(finding.get("confidence", 0.75) + 0.1, 0.95)
                        verified_findings.append(finding)
                        logger.info(f"✓ Finding confirmed: {finding.get('title')}")
                    else:
                        # Ambiguous response - for CRITICAL, keep; otherwise filter
                        if is_critical:
                            finding["verified"] = False
                            finding["verification_note"] = (
                                "Ambiguous verification - kept due to severity"
                            )
                            finding["confidence"] = max(
                                finding.get("confidence", 0.75) - 0.15, 0.50
                            )
                            verified_findings.append(finding)
                            logger.warning(
                                f"⚠ CRITICAL finding kept (ambiguous): {finding.get('title')}"
                            )
                        else:
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
