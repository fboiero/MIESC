"""
LLM-SmartAudit AI Auditor Adapter - MIESC Phase 5 (Matured Implementation)
============================================================================

LLM-based semantic analysis framework for smart contract auditing.
Provides AI-powered vulnerability detection using language models.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: November 11, 2025
Version: 2.0.0 (Matured)
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
    LLM-SmartAudit AI Auditor Adapter for MIESC Layer 5.

    Key Features:
    - LLM-powered semantic analysis
    - Pattern recognition using language models
    - Best practice compliance checking
    - Context-aware vulnerability detection
    - Result caching for efficiency
    """

    def __init__(self):
        super().__init__()
        self._default_timeout = 300  # 5 minutes
        self._cache_dir = Path.home() / ".miesc" / "llmsmartaudit_cache"
        self._cache_dir.mkdir(parents=True, exist_ok=True)

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="llmsmartaudit",
            version="2.0.0",
            category=ToolCategory.AI_ANALYSIS,
            author="LLM-SmartAudit Community (Adapter by Fernando Boiero)",
            license="MIT",
            homepage="https://github.com/Smart-Audit/LLM-SmartAudit",
            repository="https://github.com/Smart-Audit/LLM-SmartAudit",
            documentation="https://github.com/Smart-Audit/LLM-SmartAudit#readme",
            installation_cmd="pip install llm-smartaudit",
            capabilities=[
                ToolCapability(
                    name="llm_auditing",
                    description="LLM-based smart contract auditing with semantic analysis",
                    supported_languages=["solidity"],
                    detection_types=[
                        "semantic_issues",
                        "best_practice_violations",
                        "design_patterns",
                        "code_smells",
                        "maintainability_issues",
                        "readability_issues"
                    ]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True
        )

    def is_available(self) -> ToolStatus:
        """Check if LLM-SmartAudit is installed and functional."""
        try:
            result = subprocess.run(
                ["llm-smartaudit", "--version"],
                capture_output=True,
                timeout=5,
                text=True
            )

            if result.returncode == 0:
                return ToolStatus.AVAILABLE
            else:
                logger.warning(f"LLM-SmartAudit version check failed: {result.stderr}")
                return ToolStatus.CONFIGURATION_ERROR

        except FileNotFoundError:
            logger.info("LLM-SmartAudit not installed. Install: pip install llm-smartaudit")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            logger.warning("LLM-SmartAudit version check timeout")
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking LLM-SmartAudit: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze contract using LLM-SmartAudit.

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
                "version": "2.0.0",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": "LLM-SmartAudit not available. Install: pip install llm-smartaudit"
            }

        try:
            # Read contract
            contract_code = self._read_contract(contract_path)
            if not contract_code:
                return {
                    "tool": "llmsmartaudit",
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
                logger.info(f"LLM-SmartAudit: Using cached result for {contract_path}")
                cached_result["from_cache"] = True
                cached_result["execution_time"] = time.time() - start_time
                return cached_result

            # Get configuration
            timeout = kwargs.get("timeout", self._default_timeout)
            model = kwargs.get("model", "default")

            # Run LLM-SmartAudit analysis
            raw_output = self._run_llmsmartaudit(
                contract_path,
                timeout=timeout,
                model=model
            )

            # Parse findings
            findings = self._parse_llmsmartaudit_output(raw_output, contract_path)

            result = {
                "tool": "llmsmartaudit",
                "version": "2.0.0",
                "status": "success",
                "findings": findings,
                "metadata": {
                    "timeout": timeout,
                    "model": model
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
                "version": "2.0.0",
                "status": "timeout",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": f"LLM-SmartAudit analysis exceeded {timeout}s timeout"
            }
        except Exception as e:
            logger.error(f"LLM-SmartAudit analysis error: {e}", exc_info=True)
            return {
                "tool": "llmsmartaudit",
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

    def _run_llmsmartaudit(
        self,
        contract_path: str,
        timeout: int = 300,
        model: str = "default"
    ) -> str:
        """Execute LLM-SmartAudit analysis."""

        cmd = [
            "llm-smartaudit",
            "analyze",
            contract_path,
            "--format", "json",
            "--model", model
        ]

        logger.info(f"LLM-SmartAudit: Running AI audit (timeout={timeout}s, model={model})")

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            text=True,
            cwd=Path(contract_path).parent
        )

        if result.returncode != 0:
            logger.warning(f"LLM-SmartAudit completed with code {result.returncode}")

        return result.stdout + "\n" + result.stderr

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
