"""
LLM-SmartAudit AI Auditor Adapter - MIESC Phase 5 (Ollama Backend)
===================================================================

LLM-based semantic analysis framework for smart contract auditing.
Uses Ollama for local AI-powered vulnerability detection.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: November 2025
Version: 3.0.0 (Ollama Backend)
"""

from src.core.tool_protocol import (
    ToolAdapter, ToolMetadata, ToolStatus, ToolCategory, ToolCapability
)
from typing import Dict, Any, List, Optional
import subprocess
import logging
import json
import time
import hashlib
from pathlib import Path

logger = logging.getLogger(__name__)


class LLMSmartAuditAdapter(ToolAdapter):
    """
    LLM-SmartAudit AI Auditor using Ollama backend.

    Key Features:
    - LLM-powered semantic analysis using local models
    - Best practice compliance checking
    - Code smell detection
    - Result caching for efficiency
    - No API key required
    """

    # Audit-focused prompt for code quality and best practices
    AUDIT_PROMPT = """You are a smart contract security auditor. Analyze the following Solidity code for:

1. Code quality issues and code smells
2. Best practice violations (naming, structure, patterns)
3. Design pattern problems
4. Gas optimization opportunities
5. Maintainability concerns
6. Documentation gaps

Respond in JSON format:
{
    "issues": [
        {
            "title": "Issue title",
            "severity": "HIGH|MEDIUM|LOW",
            "confidence": 0.8,
            "category": "code_smell|best_practice|design_pattern|gas_optimization|maintainability",
            "line": 10,
            "function": "functionName",
            "description": "What's wrong",
            "recommendation": "How to fix"
        }
    ]
}

CONTRACT:
```solidity
%CONTRACT_CODE%
```

Respond ONLY with valid JSON."""

    def __init__(self):
        super().__init__()
        self._default_timeout = 120
        self._cache_dir = Path.home() / ".miesc" / "llmsmartaudit_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="llmsmartaudit",
            version="3.0.0",
            category=ToolCategory.AI_ANALYSIS,
            author="Ollama Backend by Fernando Boiero",
            license="MIT",
            homepage="https://github.com/Smart-Audit/LLM-SmartAudit",
            repository="https://github.com/Smart-Audit/LLM-SmartAudit",
            documentation="https://github.com/Smart-Audit/LLM-SmartAudit#readme",
            installation_cmd="ollama pull codellama:7b",
            capabilities=[
                ToolCapability(
                    name="llm_auditing",
                    description="LLM-based smart contract auditing using Ollama",
                    supported_languages=["solidity"],
                    detection_types=[
                        "semantic_issues",
                        "best_practice_violations",
                        "design_patterns",
                        "code_smells",
                        "maintainability_issues",
                        "gas_optimization"
                    ]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True
        )

    def is_available(self) -> ToolStatus:
        """Check if Ollama is running with a suitable model."""
        try:
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                timeout=10,
                text=True
            )

            if result.returncode != 0:
                logger.warning("Ollama not running")
                return ToolStatus.CONFIGURATION_ERROR

            # Check for any LLM model
            models = result.stdout.lower()
            if any(m in models for m in ["codellama", "llama3", "deepseek", "qwen"]):
                return ToolStatus.AVAILABLE

            logger.warning("No suitable LLM model found for LLMSmartAudit")
            return ToolStatus.CONFIGURATION_ERROR

        except FileNotFoundError:
            logger.info("Ollama not installed")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            logger.warning("Ollama check timeout")
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking Ollama: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze contract using Ollama for LLM-SmartAudit style analysis.

        Args:
            contract_path: Path to Solidity contract
            **kwargs: Optional configuration (timeout, model)

        Returns:
            Analysis results with findings
        """
        start_time = time.time()

        # Check availability
        if self.is_available() != ToolStatus.AVAILABLE:
            return {
                "tool": "llmsmartaudit",
                "version": "3.0.0",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": "Ollama not available. Install from https://ollama.ai"
            }

        try:
            # Read contract
            contract_code = self._read_contract(contract_path)
            if not contract_code:
                return {
                    "tool": "llmsmartaudit",
                    "version": "3.0.0",
                    "status": "error",
                    "findings": [],
                    "execution_time": time.time() - start_time,
                    "error": f"Could not read contract file: {contract_path}"
                }

            # Check cache
            cache_key = self._get_cache_key(contract_code)
            cached_result = self._get_cached_result(cache_key)
            if cached_result:
                logger.info(f"LLM-SmartAudit: Using cached result for {contract_path}")
                cached_result["from_cache"] = True
                cached_result["execution_time"] = time.time() - start_time
                return cached_result

            # Get configuration
            timeout = kwargs.get("timeout", self._default_timeout)
            model = kwargs.get("model", self._detect_best_model())

            # Run Ollama analysis
            raw_output = self._run_ollama_audit(
                contract_code,
                model=model,
                timeout=timeout
            )

            # Parse findings
            findings = self._parse_llmsmartaudit_output(raw_output, contract_path)

            result = {
                "tool": "llmsmartaudit",
                "version": "3.0.0",
                "status": "success",
                "findings": findings,
                "metadata": {
                    "model": model,
                    "backend": "ollama"
                },
                "execution_time": time.time() - start_time,
                "from_cache": False
            }

            # Cache result
            self._cache_result(cache_key, result)

            return result

        except subprocess.TimeoutExpired:
            return {
                "tool": "llmsmartaudit",
                "version": "3.0.0",
                "status": "timeout",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": f"Analysis exceeded {timeout}s timeout"
            }
        except Exception as e:
            logger.error(f"LLM-SmartAudit analysis error: {e}", exc_info=True)
            return {
                "tool": "llmsmartaudit",
                "version": "3.0.0",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": str(e)
            }

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """Normalize findings - already normalized in analyze()."""
        return raw_output.get("findings", []) if isinstance(raw_output, dict) else []

    def can_analyze(self, contract_path: str) -> bool:
        """Check if adapter can analyze the contract."""
        return Path(contract_path).suffix == '.sol'

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "timeout": 300,
            "model": "default",
            "max_findings": 50
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

    def _detect_best_model(self) -> str:
        """Detect the best available Ollama model."""
        try:
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                timeout=5,
                text=True
            )
            models = result.stdout.lower()

            # Priority order
            model_priority = [
                ("qwen2.5-coder", "qwen2.5-coder:7b"),
                ("codellama", "codellama:7b"),
                ("llama3", "llama3:8b"),
            ]

            for keyword, full_name in model_priority:
                if keyword in models:
                    return full_name

            return "codellama:7b"
        except Exception:
            return "codellama:7b"

    def _run_ollama_audit(
        self,
        contract_code: str,
        model: str = "codellama:7b",
        timeout: int = 120
    ) -> str:
        """Execute audit using Ollama."""

        prompt = self.AUDIT_PROMPT.replace("%CONTRACT_CODE%", contract_code)

        logger.info(f"LLM-SmartAudit: Running Ollama audit with {model}")

        result = subprocess.run(
            ["ollama", "run", model, prompt],
            capture_output=True,
            timeout=timeout,
            text=True
        )

        if result.returncode != 0:
            logger.warning(f"Ollama completed with code {result.returncode}")

        return result.stdout

    def _parse_llmsmartaudit_output(
        self,
        output: str,
        contract_path: str
    ) -> List[Dict[str, Any]]:
        """Parse LLM-SmartAudit output and extract findings."""
        findings = []

        try:
            # Try to parse JSON output
            json_start = output.find('{')
            json_end = output.rfind('}') + 1

            if json_start != -1 and json_end > json_start:
                json_str = output[json_start:json_end]
                parsed = json.loads(json_str)

                # Extract findings from parsed JSON
                issues = parsed.get("issues", []) or parsed.get("findings", [])

                for idx, issue in enumerate(issues):
                    finding = {
                        "id": f"llmsmartaudit-{idx+1}",
                        "title": issue.get("title", "LLM-detected issue"),
                        "description": issue.get("description", issue.get("message", "")),
                        "severity": issue.get("severity", "MEDIUM").upper(),
                        "confidence": issue.get("confidence", 0.70),
                        "category": issue.get("category", "semantic_issue"),
                        "location": {
                            "file": contract_path,
                            "line": issue.get("line", 0),
                            "function": issue.get("function", "")
                        },
                        "recommendation": issue.get("recommendation", "Review and address the LLM-detected issue"),
                        "references": [
                            "https://github.com/Smart-Audit/LLM-SmartAudit",
                            issue.get("reference", "")
                        ]
                    }
                    findings.append(finding)

            else:
                # Fallback: parse text output
                logger.warning("LLM-SmartAudit: No JSON found, using text parsing fallback")
                findings = self._parse_text_output(output, contract_path)

        except json.JSONDecodeError as e:
            logger.error(f"LLM-SmartAudit: JSON parse error - {e}")
            findings = self._parse_text_output(output, contract_path)
        except Exception as e:
            logger.error(f"LLM-SmartAudit: Parse error - {e}")

        logger.info(f"LLM-SmartAudit: Extracted {len(findings)} findings")
        return findings

    def _parse_text_output(self, output: str, contract_path: str) -> List[Dict[str, Any]]:
        """Fallback text parsing for non-JSON output."""
        findings = []

        # Look for common patterns in text output
        patterns = {
            "best practice": ("MEDIUM", "best_practice_violation"),
            "code smell": ("LOW", "code_smell"),
            "semantic issue": ("HIGH", "semantic_issue"),
            "maintainability": ("LOW", "maintainability_issue"),
            "readability": ("LOW", "readability_issue"),
            "design pattern": ("MEDIUM", "design_pattern_issue")
        }

        lines = output.split('\n')
        for i, line in enumerate(lines):
            for pattern, (severity, category) in patterns.items():
                if pattern.lower() in line.lower():
                    findings.append({
                        "id": f"llmsmartaudit-text-{len(findings)+1}",
                        "title": f"LLM-detected: {pattern.title()}",
                        "description": line.strip(),
                        "severity": severity,
                        "confidence": 0.65,  # Lower confidence for text parsing
                        "category": category,
                        "location": {"file": contract_path},
                        "recommendation": f"Review potential {pattern} detected by LLM",
                        "references": ["https://github.com/Smart-Audit/LLM-SmartAudit"]
                    })

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


__all__ = ["LLMSmartAuditAdapter"]
