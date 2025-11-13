"""
SMTChecker Formal Verification Adapter - MIESC Phase 4 (Matured Implementation)
================================================================================

Built-in formal verification tool in the Solidity compiler using SMT (Satisfiability Modulo Theories) solving.
Uses CHC (Constrained Horn Clauses) and BMC (Bounded Model Checking) engines.

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
import re
from pathlib import Path

# OpenLLaMA integration for intelligent post-processing
from src.llm import enhance_findings_with_llm

logger = logging.getLogger(__name__)


class SMTCheckerAdapter(ToolAdapter):
    """
    SMTChecker Formal Verification Adapter for MIESC Layer 4.

    Key Features:
    - Built-in to Solidity compiler (zero external dependencies)
    - CHC (Constrained Horn Clauses) engine for complex properties
    - BMC (Bounded Model Checking) for bounded verification
    - Detects arithmetic overflow, division by zero, assertions
    - No installation required (if solc >= 0.5.0 present)
    """

    def __init__(self):
        super().__init__()
        self._default_timeout = 300  # 5 minutes
        self._solc_min_version = "0.5.0"

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="smtchecker",
            version="2.0.0",
            category=ToolCategory.FORMAL_VERIFICATION,
            author="Ethereum Foundation (Adapter by Fernando Boiero)",
            license="GPL-3.0",
            homepage="https://docs.soliditylang.org/en/latest/smtchecker.html",
            repository="https://github.com/ethereum/solidity",
            documentation="https://docs.soliditylang.org/en/latest/smtchecker.html",
            installation_cmd="Built-in to Solidity compiler (solc >= 0.5.0)",
            capabilities=[
                ToolCapability(
                    name="formal_verification",
                    description="SMT-based formal verification built into Solidity compiler",
                    supported_languages=["solidity"],
                    detection_types=[
                        "arithmetic_overflow",
                        "arithmetic_underflow",
                        "division_by_zero",
                        "trivial_conditions",
                        "unreachable_code",
                        "assertion_violations",
                        "out_of_bounds",
                        "insufficient_funds"
                    ]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True
        )

    def is_available(self) -> ToolStatus:
        """Check if solc is installed and supports SMTChecker."""
        try:
            result = subprocess.run(
                ["solc", "--version"],
                capture_output=True,
                timeout=5,
                text=True
            )

            if result.returncode == 0:
                # Extract version number
                version_match = re.search(r'Version:\s*(\d+\.\d+\.\d+)', result.stdout)
                if version_match:
                    version = version_match.group(1)
                    logger.info(f"SMTChecker: Found solc version {version}")
                return ToolStatus.AVAILABLE
            else:
                logger.warning(f"SMTChecker: solc version check failed")
                return ToolStatus.CONFIGURATION_ERROR

        except FileNotFoundError:
            logger.info("SMTChecker: solc not installed")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            logger.warning("SMTChecker: solc version check timeout")
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking SMTChecker: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze contract using SMTChecker formal verification.

        Args:
            contract_path: Path to Solidity contract
            **kwargs: Optional configuration (timeout, targets, engine)

        Returns:
            Analysis results with findings
        """
        start_time = time.time()

        # Check availability
        if self.is_available() != ToolStatus.AVAILABLE:
            return {
                "tool": "smtchecker",
                "version": "2.0.0",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": "SMTChecker not available (requires solc >= 0.5.0)"
            }

        try:
            # Get configuration
            timeout = kwargs.get("timeout", self._default_timeout)
            engine = kwargs.get("engine", "all")  # chc, bmc, or all
            targets = kwargs.get("targets", "all")  # which verification targets

            # Run SMTChecker analysis
            raw_output = self._run_smtchecker(
                contract_path,
                timeout=timeout,
                engine=engine,
                targets=targets
            )

            # Parse findings
            findings = self._parse_smtchecker_output(raw_output, contract_path)

            # Read contract code for LLM context
            try:
                with open(contract_path, 'r', encoding='utf-8') as f:
                    contract_code = f.read()
            except Exception as e:
                logger.warning(f"Could not read contract for LLM enhancement: {e}")
                contract_code = ""

            # Enhance findings with OpenLLaMA insights (if available)
            if contract_code and findings:
                try:
                    findings = enhance_findings_with_llm(
                        findings=findings,
                        contract_code=contract_code,
                        adapter_name="smtchecker"
                    )
                    logger.info(f"OpenLLaMA: Enhanced SMTChecker findings with AI insights")
                except Exception as e:
                    logger.debug(f"OpenLLaMA enhancement skipped: {e}")

            return {
                "tool": "smtchecker",
                "version": "2.0.0",
                "status": "success",
                "findings": findings,
                "metadata": {
                    "timeout": timeout,
                    "engine": engine,
                    "targets": targets
                },
                "execution_time": time.time() - start_time
            }

        except subprocess.TimeoutExpired:
            return {
                "tool": "smtchecker",
                "version": "2.0.0",
                "status": "timeout",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": f"SMTChecker analysis exceeded {timeout}s timeout"
            }
        except Exception as e:
            logger.error(f"SMTChecker analysis error: {e}", exc_info=True)
            return {
                "tool": "smtchecker",
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
            "engine": "all",  # chc, bmc, or all
            "targets": "all",  # verification targets
            "solver_timeout": 100000  # ms
        }

    # ============================================================================
    # PRIVATE HELPER METHODS
    # ============================================================================

    def _run_smtchecker(
        self,
        contract_path: str,
        timeout: int = 300,
        engine: str = "all",
        targets: str = "all"
    ) -> str:
        """Execute SMTChecker via solc compiler."""

        cmd = [
            "solc",
            "--model-checker-engine", engine,
            "--model-checker-targets", targets,
            contract_path
        ]

        logger.info(f"SMTChecker: Running formal verification (timeout={timeout}s, engine={engine})")

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            text=True,
            cwd=Path(contract_path).parent
        )

        # SMTChecker warnings appear in stderr
        output = result.stdout + "\n" + result.stderr

        if result.returncode != 0 and "Warning" not in output:
            logger.warning(f"SMTChecker completed with code {result.returncode}")

        return output

    def _parse_smtchecker_output(
        self,
        output: str,
        contract_path: str
    ) -> List[Dict[str, Any]]:
        """Parse SMTChecker output and extract findings."""
        findings = []

        lines = output.split('\n')

        for i, line in enumerate(lines):
            # SMTChecker warnings format: Warning: <description>
            if "Warning:" in line or "Error:" in line:
                # Determine severity
                is_error = "Error:" in line
                severity = "HIGH" if is_error else "MEDIUM"

                # Extract location if present (format: filename:line:col:)
                location_match = re.search(r'(\S+\.sol):(\d+):(\d+):', line)
                location = {}
                if location_match:
                    file_path, line_num, col_num = location_match.groups()
                    location = {
                        "file": file_path,
                        "line": int(line_num),
                        "column": int(col_num)
                    }
                else:
                    location = {"file": contract_path}

                # Extract warning message
                message = line.split("Warning:")[-1].split("Error:")[-1].strip()

                # Categorize finding
                category = self._categorize_warning(message)
                confidence = self._estimate_confidence(category, message)

                # Build finding
                finding = {
                    "id": f"smtchecker-{len(findings)+1}",
                    "title": f"SMTChecker: {category.replace('_', ' ').title()}",
                    "description": message,
                    "severity": severity,
                    "confidence": confidence,
                    "category": category,
                    "location": location,
                    "recommendation": self._get_recommendation(category),
                    "references": [
                        "https://docs.soliditylang.org/en/latest/smtchecker.html"
                    ]
                }

                findings.append(finding)

        # Check for successful verification
        if "Warning" not in output and "Error" not in output:
            findings.append({
                "id": "smtchecker-verified",
                "title": "SMTChecker: Contract Formally Verified",
                "description": f"SMTChecker successfully verified {Path(contract_path).name} with no issues found",
                "severity": "INFO",
                "confidence": 1.0,
                "category": "formal_verification_success",
                "location": {"file": contract_path},
                "recommendation": "Contract passed formal verification - continue with other analysis layers",
                "references": ["https://docs.soliditylang.org/en/latest/smtchecker.html"]
            })

        logger.info(f"SMTChecker: Extracted {len(findings)} findings")
        return findings

    def _categorize_warning(self, message: str) -> str:
        """Categorize SMTChecker warning by content."""
        message_lower = message.lower()

        if "overflow" in message_lower:
            return "arithmetic_overflow"
        elif "underflow" in message_lower:
            return "arithmetic_underflow"
        elif "division by zero" in message_lower or "div by zero" in message_lower:
            return "division_by_zero"
        elif "assertion" in message_lower:
            return "assertion_violation"
        elif "out of bounds" in message_lower:
            return "out_of_bounds"
        elif "insufficient funds" in message_lower or "balance" in message_lower:
            return "insufficient_funds"
        elif "unreachable" in message_lower or "dead code" in message_lower:
            return "unreachable_code"
        elif "trivial" in message_lower or "tautology" in message_lower:
            return "trivial_condition"
        else:
            return "smt_checker_warning"

    def _estimate_confidence(self, category: str, message: str) -> float:
        """Estimate confidence based on category and message content."""
        # Formal verification provides high confidence
        if "proved" in message.lower() or "verified" in message.lower():
            return 0.95
        elif category in ["arithmetic_overflow", "division_by_zero", "assertion_violation"]:
            return 0.90  # High confidence for critical issues
        elif category in ["out_of_bounds", "insufficient_funds"]:
            return 0.85
        elif category in ["unreachable_code", "trivial_condition"]:
            return 0.75  # Lower confidence for code quality issues
        else:
            return 0.80  # Default

    def _get_recommendation(self, category: str) -> str:
        """Get recommendation based on finding category."""
        recommendations = {
            "arithmetic_overflow": "Use SafeMath library or Solidity 0.8+ with built-in overflow protection",
            "arithmetic_underflow": "Use SafeMath library or Solidity 0.8+ with built-in underflow protection",
            "division_by_zero": "Add explicit check to prevent division by zero before performing division",
            "assertion_violation": "Review assertion conditions - they should be invariants that must always hold",
            "out_of_bounds": "Add bounds checking before array/buffer access",
            "insufficient_funds": "Add balance check before transfer operations",
            "unreachable_code": "Remove unreachable code or fix logic to make it reachable if intended",
            "trivial_condition": "Simplify or remove trivial conditions that are always true/false"
        }

        return recommendations.get(
            category,
            "Review the SMTChecker warning and address the formal verification issue"
        )


__all__ = ["SMTCheckerAdapter"]
