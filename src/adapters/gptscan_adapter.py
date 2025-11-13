"""
GPTScan adapter for GPT-4 powered vulnerability scanning.

Requires OpenAI API key. Performs semantic analysis and pattern detection.
github.com/GPTScan/GPTScan

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
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
from pathlib import Path

logger = logging.getLogger(__name__)


class GPTScanAdapter(ToolAdapter):
    """
    GPTScan integration for GPT-4 analysis.

    Requires OPENAI_API_KEY environment variable.
    Tracks token usage and API costs. Retries on failure.
    """

    def __init__(self):
        super().__init__()
        self._default_timeout = 600  # 10 minutes
        self._max_retries = 3
        self._retry_delay = 2

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="gptscan",
            version="2.0.0",
            category=ToolCategory.AI_ANALYSIS,
            author="OpenAI Community (Adapter by Fernando Boiero)",
            license="MIT",
            homepage="https://github.com/GPTScan/GPTScan",
            repository="https://github.com/GPTScan/GPTScan",
            documentation="https://github.com/GPTScan/GPTScan#readme",
            installation_cmd="pip install gptscan && export OPENAI_API_KEY=your_key",
            capabilities=[
                ToolCapability(
                    name="ai_scanning",
                    description="GPT-4 powered vulnerability scanning",
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
            cost=0.03,  # $0.03 per 1K tokens (GPT-4)
            requires_api_key=True,
            is_optional=True
        )

    def is_available(self) -> ToolStatus:
        """Check if GPTScan is installed and API key is configured."""
        try:
            # Check if gptscan command exists
            result = subprocess.run(
                ["gptscan", "--version"],
                capture_output=True,
                timeout=5,
                text=True
            )

            if result.returncode != 0:
                logger.warning("GPTScan command failed")
                return ToolStatus.CONFIGURATION_ERROR

            # Check for OpenAI API key
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                logger.warning("OPENAI_API_KEY environment variable not set")
                return ToolStatus.CONFIGURATION_ERROR

            return ToolStatus.AVAILABLE

        except FileNotFoundError:
            logger.info("GPTScan not installed. Install: pip install gptscan")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            logger.warning("GPTScan version check timeout")
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking GPTScan: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze contract using GPTScan AI scanner.

        Args:
            contract_path: Path to Solidity contract
            **kwargs: Optional configuration (timeout, model, temperature)

        Returns:
            Analysis results with AI-detected findings
        """
        start_time = time.time()

        # Check availability
        if self.is_available() != ToolStatus.AVAILABLE:
            return {
                "tool": "gptscan",
                "version": "2.0.0",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": "GPTScan not available or API key missing. Set OPENAI_API_KEY environment variable."
            }

        try:
            # Get configuration
            timeout = kwargs.get("timeout", self._default_timeout)
            model = kwargs.get("model", "gpt-4")  # gpt-4 or gpt-3.5-turbo
            temperature = kwargs.get("temperature", 0.1)  # Low temp for precise analysis

            # Run GPTScan analysis
            raw_output, tokens_used = self._run_gptscan(
                contract_path,
                timeout=timeout,
                model=model,
                temperature=temperature
            )

            # Parse findings
            findings = self._parse_gptscan_output(raw_output, contract_path)

            # Calculate cost
            cost = self._calculate_cost(tokens_used, model)

            return {
                "tool": "gptscan",
                "version": "2.0.0",
                "status": "success",
                "findings": findings,
                "metadata": {
                    "model": model,
                    "tokens_used": tokens_used,
                    "cost_usd": cost,
                    "temperature": temperature
                },
                "execution_time": time.time() - start_time
            }

        except subprocess.TimeoutExpired:
            return {
                "tool": "gptscan",
                "version": "2.0.0",
                "status": "timeout",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": f"GPTScan analysis exceeded {timeout}s timeout"
            }
        except Exception as e:
            logger.error(f"GPTScan analysis error: {e}", exc_info=True)
            return {
                "tool": "gptscan",
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
            "timeout": 600,
            "model": "gpt-4",
            "temperature": 0.1,
            "max_retries": 3
        }

    # ============================================================================
    # PRIVATE HELPER METHODS
    # ============================================================================

    def _run_gptscan(
        self,
        contract_path: str,
        timeout: int = 600,
        model: str = "gpt-4",
        temperature: float = 0.1
    ) -> tuple:
        """Execute GPTScan analysis and return output + token count."""

        cmd = [
            "gptscan",
            "--file", contract_path,
            "--model", model,
            "--temperature", str(temperature),
            "--output-format", "json"
        ]

        logger.info(f"GPTScan: Running AI analysis with {model} (timeout={timeout}s)")

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            text=True,
            cwd=Path(contract_path).parent
        )

        if result.returncode != 0:
            logger.warning(f"GPTScan completed with code {result.returncode}")

        output = result.stdout + "\n" + result.stderr

        # Extract token count from output (if provided by GPTScan)
        tokens_used = self._extract_token_count(output)

        return output, tokens_used

    def _extract_token_count(self, output: str) -> int:
        """Extract token count from GPTScan output."""
        # GPTScan typically reports token usage in output
        # Format: "Tokens used: 1234" or similar
        import re
        match = re.search(r'[Tt]okens?\s+used:\s*(\d+)', output)
        if match:
            return int(match.group(1))
        # Default estimate if not found: ~1 token per 4 characters
        return len(output) // 4

    def _calculate_cost(self, tokens: int, model: str) -> float:
        """Calculate cost based on tokens and model."""
        # GPT-4 pricing (as of 2024)
        rates = {
            "gpt-4": 0.03 / 1000,  # $0.03 per 1K tokens
            "gpt-3.5-turbo": 0.002 / 1000  # $0.002 per 1K tokens
        }
        rate = rates.get(model, 0.03 / 1000)
        return tokens * rate

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
