"""
Manticore Symbolic Execution Adapter - MIESC Phase 3 (Matured Implementation)
===============================================================================

Trail of Bits' symbolic execution tool for EVM bytecode analysis.
Explores multiple execution paths and detects critical vulnerabilities.

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
import tempfile
import shutil
from pathlib import Path

# OpenLLaMA integration for intelligent post-processing
from src.llm import enhance_findings_with_llm

logger = logging.getLogger(__name__)


class ManticoreAdapter(ToolAdapter):
    """
    Manticore Symbolic Execution Adapter for MIESC Layer 3.

    Key Features:
    - Symbolic execution of EVM bytecode
    - Path exploration and state analysis
    - Assertion failure detection
    - Concrete transaction generation
    - Timeout handling for complex contracts
    """

    def __init__(self):
        super().__init__()
        self._default_timeout = 600  # 10 minutes
        self._max_depth = 100  # Maximum symbolic execution depth

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="manticore",
            version="2.0.0",
            category=ToolCategory.SYMBOLIC_EXECUTION,
            author="Trail of Bits (Adapter by Fernando Boiero)",
            license="AGPL-3.0",
            homepage="https://github.com/trailofbits/manticore",
            repository="https://github.com/trailofbits/manticore",
            documentation="https://github.com/trailofbits/manticore/wiki",
            installation_cmd="pip install manticore",
            capabilities=[
                ToolCapability(
                    name="symbolic_execution",
                    description="Symbolic execution engine for smart contracts (Trail of Bits)",
                    supported_languages=["solidity"],
                    detection_types=[
                        "assertion_failures",
                        "integer_overflow",
                        "reentrancy",
                        "uninitialized_storage",
                        "invalid_state_transitions",
                        "reachability_issues"
                    ]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True
        )

    def is_available(self) -> ToolStatus:
        """Check if Manticore is installed and functional."""
        try:
            result = subprocess.run(
                ["manticore", "--version"],
                capture_output=True,
                timeout=5,
                text=True
            )

            if result.returncode == 0:
                return ToolStatus.AVAILABLE
            else:
                logger.warning(f"Manticore version check failed: {result.stderr}")
                return ToolStatus.CONFIGURATION_ERROR

        except FileNotFoundError:
            logger.info("Manticore not installed. Install: pip install manticore")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            logger.warning("Manticore version check timeout")
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking Manticore: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze contract using Manticore symbolic execution.

        Args:
            contract_path: Path to Solidity contract
            **kwargs: Optional configuration (timeout, max_depth)

        Returns:
            Analysis results with findings
        """
        start_time = time.time()

        # Check availability
        if self.is_available() != ToolStatus.AVAILABLE:
            return {
                "tool": "manticore",
                "version": "2.0.0",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": "Manticore not available. Install: pip install manticore"
            }

        try:
            # Get configuration
            timeout = kwargs.get("timeout", self._default_timeout)
            max_depth = kwargs.get("max_depth", self._max_depth)

            # Create temporary workspace
            temp_dir = tempfile.mkdtemp(prefix="manticore_")

            try:
                # Run Manticore analysis
                raw_output = self._run_manticore(
                    contract_path,
                    temp_dir,
                    timeout=timeout,
                    max_depth=max_depth
                )

                # Parse findings
                findings = self._parse_manticore_output(raw_output, contract_path, temp_dir)

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
                            adapter_name="manticore"
                        )
                        logger.info(f"OpenLLaMA: Enhanced Manticore findings with AI insights")
                    except Exception as e:
                        logger.debug(f"OpenLLaMA enhancement skipped: {e}")

                return {
                    "tool": "manticore",
                    "version": "2.0.0",
                    "status": "success",
                    "findings": findings,
                    "metadata": {
                        "timeout": timeout,
                        "max_depth": max_depth,
                        "workspace": temp_dir
                    },
                    "execution_time": time.time() - start_time
                }

            finally:
                # Cleanup temporary directory
                try:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                except Exception as e:
                    logger.warning(f"Failed to cleanup temp dir: {e}")

        except subprocess.TimeoutExpired:
            return {
                "tool": "manticore",
                "version": "2.0.0",
                "status": "timeout",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": f"Manticore analysis exceeded {timeout}s timeout"
            }
        except Exception as e:
            logger.error(f"Manticore analysis error: {e}", exc_info=True)
            return {
                "tool": "manticore",
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
            "max_depth": 100,
            "max_transactions": 3
        }

    # ============================================================================
    # PRIVATE HELPER METHODS
    # ============================================================================

    def _run_manticore(
        self,
        contract_path: str,
        workspace: str,
        timeout: int = 600,
        max_depth: int = 100
    ) -> str:
        """Execute Manticore analysis."""

        cmd = [
            "manticore",
            contract_path,
            "--workspace", workspace,
            "--maxdepth", str(max_depth),
            "--quick-mode"  # Faster analysis
        ]

        logger.info(f"Manticore: Running analysis (timeout={timeout}s)")

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            text=True,
            cwd=Path(contract_path).parent
        )

        if result.returncode != 0:
            logger.warning(f"Manticore completed with code {result.returncode}")

        return result.stdout + result.stderr

    def _parse_manticore_output(
        self,
        output: str,
        contract_path: str,
        workspace: str
    ) -> List[Dict[str, Any]]:
        """Parse Manticore output and extract findings."""
        findings = []

        # Parse textual output for key indicators
        lines = output.split('\n')

        for i, line in enumerate(lines):
            # Detect assertion failures
            if "REVERT" in line or "INVALID" in line or "ASSERTION" in line:
                findings.append({
                    "id": f"manticore-{len(findings)+1}",
                    "title": "Assertion Failure or Revert Detected",
                    "description": line.strip(),
                    "severity": "HIGH",
                    "confidence": 0.85,
                    "category": "assertion_failure",
                    "location": {
                        "file": contract_path,
                        "details": f"Detected during symbolic execution"
                    },
                    "recommendation": "Review the revert condition and ensure it's intentional",
                    "references": [
                        "https://github.com/trailofbits/manticore/wiki"
                    ]
                })

            # Detect integer overflow
            if "overflow" in line.lower() or "underflow" in line.lower():
                findings.append({
                    "id": f"manticore-{len(findings)+1}",
                    "title": "Potential Integer Overflow/Underflow",
                    "description": line.strip(),
                    "severity": "HIGH",
                    "confidence": 0.80,
                    "category": "integer_overflow",
                    "location": {
                        "file": contract_path,
                        "details": "Detected during symbolic execution"
                    },
                    "recommendation": "Use SafeMath or Solidity 0.8+ built-in overflow protection",
                    "references": ["https://consensys.github.io/smart-contract-best-practices/"]
                })

            # Detect reentrancy
            if "reentrancy" in line.lower() or "external call" in line.lower():
                findings.append({
                    "id": f"manticore-{len(findings)+1}",
                    "title": "Potential Reentrancy Vulnerability",
                    "description": line.strip(),
                    "severity": "CRITICAL",
                    "confidence": 0.75,
                    "category": "reentrancy",
                    "location": {
                        "file": contract_path,
                        "details": "Detected during symbolic execution"
                    },
                    "recommendation": "Use checks-effects-interactions pattern or reentrancy guard",
                    "references": ["https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/"]
                })

        # Check workspace for generated test cases
        workspace_path = Path(workspace)
        if workspace_path.exists():
            test_cases = list(workspace_path.glob("*.tx"))
            if test_cases:
                findings.append({
                    "id": f"manticore-testcases",
                    "title": f"Generated {len(test_cases)} Concrete Test Cases",
                    "description": f"Manticore explored {len(test_cases)} execution paths",
                    "severity": "INFO",
                    "confidence": 1.0,
                    "category": "path_exploration",
                    "location": {
                        "file": contract_path,
                        "details": f"Workspace: {workspace}"
                    },
                    "recommendation": "Review generated test cases for edge cases",
                    "references": [f"Workspace: {workspace}"]
                })

        logger.info(f"Manticore: Extracted {len(findings)} findings")
        return findings


__all__ = ["ManticoreAdapter"]
