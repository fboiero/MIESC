"""
GPTScan adapter for LLM-powered vulnerability scanning.

Uses Ollama for local AI analysis. Based on GPTScan (ICSE 2024) methodology.
Performs semantic analysis and pattern detection using local LLMs.

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
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)


class GPTScanAdapter(ToolAdapter):
    """
    GPTScan-style LLM integration using Ollama.

    Uses local Ollama models (codellama, llama3, etc.) for security analysis.
    No API key required - runs entirely locally.
    """

    # Vulnerability detection prompts based on GPTScan paper (ICSE 2024)
    SECURITY_PROMPT = """Analyze this Solidity smart contract for security vulnerabilities.

Focus on detecting:
1. Reentrancy vulnerabilities (calls before state updates)
2. Integer overflow/underflow
3. Access control issues (missing modifiers, tx.origin usage)
4. Unchecked external calls
5. Logic errors in business logic
6. Flash loan attack vectors
7. Price manipulation risks

For each vulnerability found, respond in this JSON format:
{
    "vulnerabilities": [
        {
            "title": "Vulnerability Name",
            "severity": "CRITICAL|HIGH|MEDIUM|LOW",
            "confidence": 0.9,
            "line": 42,
            "function": "withdraw",
            "description": "Detailed description",
            "recommendation": "How to fix"
        }
    ]
}

CONTRACT CODE:
```solidity
%CONTRACT_CODE%
```

Respond ONLY with valid JSON. No explanations outside JSON."""

    def __init__(self):
        super().__init__()
        self._default_timeout = 120
        self._ollama_model = "codellama:7b"  # Default model
        self._ollama_url = "http://localhost:11434"

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="gptscan",
            version="3.0.0",
            category=ToolCategory.AI_ANALYSIS,
            author="Based on GPTScan (ICSE 2024), Ollama Backend by Fernando Boiero",
            license="MIT",
            homepage="https://github.com/GPTScan/GPTScan",
            repository="https://github.com/GPTScan/GPTScan",
            documentation="https://github.com/GPTScan/GPTScan#readme",
            installation_cmd="ollama pull codellama:7b",
            capabilities=[
                ToolCapability(
                    name="ai_scanning",
                    description="LLM-powered vulnerability scanning using Ollama",
                    supported_languages=["solidity"],
                    detection_types=[
                        "complex_vulnerabilities",
                        "logic_errors",
                        "ai_detected_patterns",
                        "semantic_issues",
                        "access_control_flaws",
                        "business_logic_bugs"
                    ]
                )
            ],
            cost=0.0,  # Free - local execution
            requires_api_key=False,
            is_optional=True
        )

    def is_available(self) -> ToolStatus:
        """Check if Ollama is running and model is available."""
        try:
            # Check if ollama is running
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                timeout=10,
                text=True
            )

            if result.returncode != 0:
                logger.warning("Ollama not running or not responding")
                return ToolStatus.CONFIGURATION_ERROR

            # Check if we have a suitable model
            models = result.stdout.lower()
            suitable_models = ["codellama", "llama3", "deepseek-coder", "qwen2.5-coder"]

            for model in suitable_models:
                if model in models:
                    logger.info(f"GPTScan: Found Ollama model with {model}")
                    return ToolStatus.AVAILABLE

            # No model found, but ollama is running
            logger.warning("GPTScan: No suitable LLM model found. Run: ollama pull codellama:7b")
            return ToolStatus.CONFIGURATION_ERROR

        except FileNotFoundError:
            logger.info("Ollama not installed. Install from https://ollama.ai")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            logger.warning("Ollama check timeout")
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking Ollama: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze contract using Ollama LLM for GPTScan-style analysis.

        Args:
            contract_path: Path to Solidity contract
            **kwargs: Optional configuration (timeout, model)

        Returns:
            Analysis results with AI-detected findings
        """
        start_time = time.time()

        # Check availability
        if self.is_available() != ToolStatus.AVAILABLE:
            return {
                "tool": "gptscan",
                "version": "3.0.0",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": "Ollama not available. Install from https://ollama.ai and run: ollama pull codellama:7b"
            }

        try:
            # Read contract code
            contract_code = self._read_contract(contract_path)
            if not contract_code:
                return {
                    "tool": "gptscan",
                    "version": "3.0.0",
                    "status": "error",
                    "findings": [],
                    "execution_time": time.time() - start_time,
                    "error": f"Could not read contract: {contract_path}"
                }

            # Get configuration
            timeout = kwargs.get("timeout", self._default_timeout)
            model = kwargs.get("model", self._detect_best_model())

            # Run Ollama analysis
            raw_output = self._run_ollama_analysis(
                contract_code,
                model=model,
                timeout=timeout
            )

            # Parse findings
            findings = self._parse_gptscan_output(raw_output, contract_path)

            return {
                "tool": "gptscan",
                "version": "3.0.0",
                "status": "success",
                "findings": findings,
                "metadata": {
                    "model": model,
                    "backend": "ollama",
                    "cost_usd": 0.0
                },
                "execution_time": time.time() - start_time
            }

        except subprocess.TimeoutExpired:
            return {
                "tool": "gptscan",
                "version": "3.0.0",
                "status": "timeout",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": f"GPTScan analysis exceeded {timeout}s timeout"
            }
        except Exception as e:
            logger.error(f"GPTScan analysis error: {e}", exc_info=True)
            return {
                "tool": "gptscan",
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
            "timeout": 600,
            "model": "gpt-4",
            "temperature": 0.1,
            "max_retries": 3
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
        """Detect the best available Ollama model for security analysis."""
        try:
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                timeout=5,
                text=True
            )
            models = result.stdout.lower()

            # Priority order for security analysis
            model_priority = [
                ("qwen2.5-coder", "qwen2.5-coder:7b"),
                ("deepseek-coder", "deepseek-coder:6.7b"),
                ("codellama", "codellama:7b"),
                ("llama3", "llama3:8b"),
            ]

            for keyword, full_name in model_priority:
                if keyword in models:
                    return full_name

            return "codellama:7b"  # Default fallback
        except Exception:
            return "codellama:7b"

    def _run_ollama_analysis(
        self,
        contract_code: str,
        model: str = "codellama:7b",
        timeout: int = 120
    ) -> str:
        """Execute security analysis using Ollama."""

        # Build prompt with contract code
        prompt = self.SECURITY_PROMPT.replace("%CONTRACT_CODE%", contract_code)

        logger.info(f"GPTScan: Running Ollama analysis with {model}")

        # Use ollama run command
        result = subprocess.run(
            ["ollama", "run", model, prompt],
            capture_output=True,
            timeout=timeout,
            text=True
        )

        if result.returncode != 0:
            logger.warning(f"Ollama completed with code {result.returncode}: {result.stderr}")

        return result.stdout

    def _parse_gptscan_output(
        self,
        output: str,
        contract_path: str
    ) -> List[Dict[str, Any]]:
        """Parse GPTScan output and extract findings."""
        findings = []

        try:
            # Try to parse JSON output
            json_start = output.find('{')
            json_end = output.rfind('}') + 1

            if json_start != -1 and json_end > json_start:
                json_str = output[json_start:json_end]
                parsed = json.loads(json_str)

                # Extract findings from parsed JSON
                vulnerabilities = parsed.get("vulnerabilities", [])

                for idx, vuln in enumerate(vulnerabilities):
                    finding = {
                        "id": f"gptscan-{idx+1}",
                        "title": vuln.get("title", "AI-detected vulnerability"),
                        "description": vuln.get("description", ""),
                        "severity": vuln.get("severity", "MEDIUM").upper(),
                        "confidence": vuln.get("confidence", 0.75),
                        "category": vuln.get("type", "ai_detected_pattern"),
                        "location": {
                            "file": contract_path,
                            "line": vuln.get("line", 0),
                            "function": vuln.get("function", "")
                        },
                        "recommendation": vuln.get("recommendation", "Review and address the AI-detected issue"),
                        "references": [
                            "GPT-4 AI Analysis",
                            vuln.get("reference", "")
                        ]
                    }
                    findings.append(finding)

            else:
                # Fallback: parse text output
                logger.warning("GPTScan: No JSON found, using text parsing fallback")
                findings = self._parse_text_output(output, contract_path)

        except json.JSONDecodeError as e:
            logger.error(f"GPTScan: JSON parse error - {e}")
            findings = self._parse_text_output(output, contract_path)
        except Exception as e:
            logger.error(f"GPTScan: Parse error - {e}")

        logger.info(f"GPTScan: Extracted {len(findings)} findings")
        return findings

    def _parse_text_output(self, output: str, contract_path: str) -> List[Dict[str, Any]]:
        """Fallback text parsing for non-JSON output."""
        findings = []

        # Look for common vulnerability keywords
        keywords = {
            "reentrancy": ("CRITICAL", "reentrancy"),
            "overflow": ("HIGH", "arithmetic_overflow"),
            "underflow": ("HIGH", "arithmetic_underflow"),
            "access control": ("HIGH", "access_control"),
            "unchecked": ("MEDIUM", "unchecked_calls"),
            "logic error": ("HIGH", "logic_error")
        }

        lines = output.split('\n')
        for i, line in enumerate(lines):
            for keyword, (severity, category) in keywords.items():
                if keyword.lower() in line.lower():
                    findings.append({
                        "id": f"gptscan-text-{len(findings)+1}",
                        "title": f"AI-detected: {keyword.title()}",
                        "description": line.strip(),
                        "severity": severity,
                        "confidence": 0.70,  # Lower confidence for text parsing
                        "category": category,
                        "location": {"file": contract_path},
                        "recommendation": f"Review potential {keyword} issue detected by AI",
                        "references": ["GPT-4 AI Analysis"]
                    })

        return findings


__all__ = ["GPTScanAdapter"]
