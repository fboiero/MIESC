"""
Local LLM adapter using Ollama for AI-assisted finding analysis.

Uses deepseek-coder model for vulnerability pattern detection.
Runs entirely locally (no API keys, DPGA-compliant).

Ollama: https://ollama.com
Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

from src.core.tool_protocol import (
    ToolAdapter,
    ToolMetadata,
    ToolStatus,
    ToolCategory,
    ToolCapability
)
from typing import Dict, Any, List, Optional
import logging
import subprocess
import json
import hashlib
import time
from pathlib import Path

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
        self._model = "deepseek-coder"
        self._max_tokens = 8000  # 8K context window
        self._max_retries = 3
        self._retry_delay = 2  # seconds

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="smartllm",
            version="2.0.0",
            category=ToolCategory.AI_ANALYSIS,
            author="Fernando Boiero (DPGA-compliant sovereign LLM adapter)",
            license="AGPL-3.0",
            homepage="https://ollama.com",
            repository="https://github.com/ollama/ollama",
            documentation="https://github.com/ollama/ollama/blob/main/README.md",
            installation_cmd="curl -fsSL https://ollama.com/install.sh | sh && ollama pull deepseek-coder",
            capabilities=[
                ToolCapability(
                    name="ai_analysis",
                    description="Local LLM-powered analysis using Ollama (100% sovereign, DPGA-compliant)",
                    supported_languages=["solidity"],
                    detection_types=[
                        "logic_bugs",
                        "design_issues",
                        "security_patterns",
                        "access_control",
                        "reentrancy",
                        "integer_overflow",
                        "unchecked_calls",
                        "best_practices"
                    ]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True
        )

    def is_available(self) -> ToolStatus:
        """Check if Ollama is installed and deepseek-coder model is available."""
        try:
            # Check if ollama command exists
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                timeout=5,
                text=True
            )

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
                "version": "2.0.0",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": "SmartLLM (Ollama) not available. Ensure Ollama is installed and deepseek-coder model is pulled."
            }

        try:
            # Read contract
            contract_code = self._read_contract(contract_path)
            if not contract_code:
                return {
                    "tool": "smartllm",
                    "version": "2.0.0",
                    "status": "error",
                    "findings": [],
                    "execution_time": time.time() - start_time,
                    "error": f"Could not read contract file: {contract_path}"
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

            # Generate prompt
            prompt = self._generate_analysis_prompt(contract_code)

            # Call Ollama with retry logic
            llm_response = self._call_ollama_with_retry(prompt)

            if not llm_response:
                return {
                    "tool": "smartllm",
                    "version": "2.0.0",
                    "status": "error",
                    "findings": [],
                    "execution_time": time.time() - start_time,
                    "error": "Failed to get response from Ollama LLM"
                }

            # Parse LLM response to extract findings
            findings = self._parse_llm_response(llm_response, contract_path)

            # Build result
            result = {
                "tool": "smartllm",
                "version": "2.0.0",
                "status": "success",
                "findings": findings,
                "metadata": {
                    "model": self._model,
                    "prompt_tokens": len(prompt.split()),  # Approximate
                    "sovereign": True,
                    "dpga_compliant": True
                },
                "execution_time": time.time() - start_time,
                "from_cache": False
            }

            # Cache result
            self._cache_result(cache_key, result)

            return result

        except Exception as e:
            logger.error(f"SmartLLM analysis error: {e}", exc_info=True)
            return {
                "tool": "smartllm",
                "version": "2.0.0",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": str(e)
            }

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """Normalize findings - already normalized in analyze()."""
        return raw_output.get("findings", []) if isinstance(raw_output, dict) else []

    def can_analyze(self, contract_path: str) -> bool:
        """Check if this adapter can analyze the given contract."""
        return Path(contract_path).suffix == '.sol'

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "timeout": 600,
            "model": "deepseek-coder",
            "max_tokens": 8000,
            "temperature": 0.1,  # Low temperature for precise analysis
            "max_retries": 3,
            "retry_delay": 2
        }

    # ============================================================================
    # PRIVATE HELPER METHODS
    # ============================================================================

    def _read_contract(self, contract_path: str) -> Optional[str]:
        """Read contract file content."""
        try:
            with open(contract_path, 'r', encoding='utf-8') as f:
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
        """Generate analysis prompt for Ollama LLM."""
        return f"""You are a Solidity security expert. Analyze the following smart contract for vulnerabilities and issues.

SMART CONTRACT:
```solidity
{contract_code}
```

ANALYSIS INSTRUCTIONS:
1. Identify all security vulnerabilities (reentrancy, integer overflow/underflow, unchecked calls, access control issues, etc.)
2. Check for logic bugs and design flaws
3. Verify best practices compliance
4. Rate each finding's severity: CRITICAL, HIGH, MEDIUM, LOW

OUTPUT FORMAT (JSON):
{{
  "findings": [
    {{
      "type": "vulnerability_type",
      "severity": "CRITICAL/HIGH/MEDIUM/LOW",
      "title": "Short title",
      "description": "Detailed description",
      "location": "Function or line reference",
      "recommendation": "How to fix"
    }}
  ]
}}

Provide ONLY the JSON output, no additional text."""

    def _call_ollama_with_retry(self, prompt: str) -> Optional[str]:
        """Call Ollama API with retry logic."""
        for attempt in range(1, self._max_retries + 1):
            try:
                logger.info(f"SmartLLM: Calling Ollama (attempt {attempt}/{self._max_retries})")

                result = subprocess.run(
                    [
                        "ollama",
                        "run",
                        self._model,
                        prompt
                    ],
                    capture_output=True,
                    timeout=300,  # 5 minutes max
                    text=True
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
            json_start = llm_response.find('{')
            json_end = llm_response.rfind('}') + 1

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
                        "details": finding.get("location", "See full contract")
                    },
                    "recommendation": finding.get("recommendation", "Review and address the identified issue"),
                    "references": [
                        "AI-powered analysis using Ollama + deepseek-coder"
                    ]
                }
                findings.append(normalized)

            logger.info(f"SmartLLM: Parsed {len(findings)} findings from LLM response")

        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            # Fallback: create a single finding with the raw response
            findings.append({
                "id": "smartllm-raw",
                "title": "LLM Analysis Result (raw)",
                "description": llm_response[:500],  # First 500 chars
                "severity": "INFO",
                "confidence": 0.5,
                "category": "ai_analysis",
                "location": {
                    "file": contract_path
                },
                "recommendation": "Review full LLM response for insights"
            })
        except Exception as e:
            logger.error(f"Error parsing LLM response: {e}")

        return findings

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

            with open(cache_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading cache: {e}")
            return None

    def _cache_result(self, cache_key: str, result: Dict[str, Any]):
        """Cache analysis result."""
        cache_file = self._cache_dir / f"{cache_key}.json"

        try:
            with open(cache_file, 'w') as f:
                json.dump(result, f, indent=2)
            logger.info(f"Cached result for {cache_key}")
        except Exception as e:
            logger.error(f"Error writing cache: {e}")


__all__ = ["SmartLLMAdapter"]
