"""
Halmos Symbolic Testing Adapter - MIESC Phase 3 (Matured Implementation)
==========================================================================

a16z's symbolic testing framework for Foundry-based smart contracts.
Halmos performs symbolic execution on Foundry test files to verify properties.

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


class HalmosAdapter(ToolAdapter):
    """
    Halmos Symbolic Testing Adapter for MIESC Layer 3.

    Key Features:
    - Symbolic execution of Foundry tests
    - Property violation detection
    - Counterexample generation
    - Integration with Foundry test infrastructure
    - Support for `.t.sol` test files
    """

    def __init__(self):
        super().__init__()
        self._default_timeout = 300  # 5 minutes
        self._default_depth = 64  # Symbolic execution depth

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="halmos",
            version="2.0.0",
            category=ToolCategory.SYMBOLIC_EXECUTION,
            author="a16z (Adapter by Fernando Boiero)",
            license="MIT",
            homepage="https://github.com/a16z/halmos",
            repository="https://github.com/a16z/halmos",
            documentation="https://github.com/a16z/halmos/blob/main/README.md",
            installation_cmd="pip install halmos",
            capabilities=[
                ToolCapability(
                    name="symbolic_testing",
                    description="Symbolic testing for Foundry tests (a16z)",
                    supported_languages=["solidity"],
                    detection_types=[
                        "property_violations",
                        "invariant_failures",
                        "assertion_violations",
                        "revert_conditions",
                        "counterexamples"
                    ]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True
        )

    def is_available(self) -> ToolStatus:
        """Check if Halmos is installed and functional."""
        try:
            result = subprocess.run(
                ["halmos", "--version"],
                capture_output=True,
                timeout=5,
                text=True
            )

            if result.returncode == 0:
                return ToolStatus.AVAILABLE
            else:
                logger.warning(f"Halmos version check failed: {result.stderr}")
                return ToolStatus.CONFIGURATION_ERROR

        except FileNotFoundError:
            logger.info("Halmos not installed. Install: pip install halmos")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            logger.warning("Halmos version check timeout")
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking Halmos: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze contract using Halmos symbolic testing.

        Args:
            contract_path: Path to Solidity contract or test file
            **kwargs: Optional configuration (timeout, depth, test_file)

        Returns:
            Analysis results with findings
        """
        start_time = time.time()

        # Check availability
        if self.is_available() != ToolStatus.AVAILABLE:
            return {
                "tool": "halmos",
                "version": "2.0.0",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": "Halmos not available. Install: pip install halmos"
            }

        try:
            # Get configuration
            timeout = kwargs.get("timeout", self._default_timeout)
            depth = kwargs.get("depth", self._default_depth)
            test_file = kwargs.get("test_file", None)

            # Determine test file path
            if test_file:
                target_path = test_file
            else:
                # If contract_path is a test file, use it directly
                if contract_path.endswith('.t.sol'):
                    target_path = contract_path
                else:
                    # Look for corresponding test file
                    target_path = self._find_test_file(contract_path)
                    if not target_path:
                        logger.warning(f"No test file found for {contract_path}")
                        return {
                            "tool": "halmos",
                            "version": "2.0.0",
                            "status": "success",
                            "findings": [],
                            "execution_time": time.time() - start_time,
                            "metadata": {"note": "No test file found - skipping Halmos"}
                        }

            # Run Halmos analysis
            raw_output = self._run_halmos(target_path, timeout=timeout, depth=depth)

            # Parse findings
            findings = self._parse_halmos_output(raw_output, contract_path, target_path)

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
                        adapter_name="halmos"
                    )
                    logger.info(f"OpenLLaMA: Enhanced Halmos findings with AI insights")
                except Exception as e:
                    logger.debug(f"OpenLLaMA enhancement skipped: {e}")

            return {
                "tool": "halmos",
                "version": "2.0.0",
                "status": "success",
                "findings": findings,
                "metadata": {
                    "timeout": timeout,
                    "depth": depth,
                    "test_file": target_path
                },
                "execution_time": time.time() - start_time
            }

        except subprocess.TimeoutExpired:
            return {
                "tool": "halmos",
                "version": "2.0.0",
                "status": "timeout",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": f"Halmos analysis exceeded {timeout}s timeout"
            }
        except Exception as e:
            logger.error(f"Halmos analysis error: {e}", exc_info=True)
            return {
                "tool": "halmos",
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
            "depth": 64,
            "solver_timeout": 100
        }

    # ============================================================================
    # PRIVATE HELPER METHODS
    # ============================================================================

    def _find_test_file(self, contract_path: str) -> Optional[str]:
        """Find corresponding Foundry test file for contract."""
        contract_path_obj = Path(contract_path)
        contract_dir = contract_path_obj.parent
        contract_name = contract_path_obj.stem

        # Common test file patterns
        test_patterns = [
            f"{contract_name}.t.sol",
            f"Test{contract_name}.sol",
            f"{contract_name}Test.sol"
        ]

        # Search in common test directories
        test_dirs = [
            contract_dir / "test",
            contract_dir.parent / "test",
            contract_dir.parent / "tests",
            contract_dir
        ]

        for test_dir in test_dirs:
            if not test_dir.exists():
                continue

            for pattern in test_patterns:
                test_file = test_dir / pattern
                if test_file.exists():
                    return str(test_file)

        return None

    def _run_halmos(self, test_path: str, timeout: int = 300, depth: int = 64) -> str:
        """Execute Halmos symbolic testing."""

        cmd = [
            "halmos",
            "--root", str(Path(test_path).parent),
            "--contract", Path(test_path).stem,
            "--depth", str(depth),
            "--verbose"
        ]

        logger.info(f"Halmos: Running symbolic test analysis (timeout={timeout}s)")

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            text=True,
            cwd=Path(test_path).parent
        )

        if result.returncode not in [0, 1]:  # 0=pass, 1=fail (expected)
            logger.warning(f"Halmos completed with code {result.returncode}")

        return result.stdout + "\n" + result.stderr

    def _parse_halmos_output(
        self,
        output: str,
        contract_path: str,
        test_path: str
    ) -> List[Dict[str, Any]]:
        """Parse Halmos output and extract findings."""
        findings = []

        lines = output.split('\n')

        # Track test results
        for i, line in enumerate(lines):
            # Detect property violations (test failures)
            if "FAIL" in line or "Counterexample" in line:
                # Extract test name
                test_name_match = re.search(r'test\w+', line)
                test_name = test_name_match.group(0) if test_name_match else "unknown_test"

                # Look for counterexample details in following lines
                counterexample = ""
                for j in range(i+1, min(i+10, len(lines))):
                    if lines[j].strip() and not lines[j].startswith("["):
                        counterexample += lines[j].strip() + " "

                findings.append({
                    "id": f"halmos-{len(findings)+1}",
                    "title": f"Property Violation: {test_name}",
                    "description": f"Symbolic test {test_name} failed. {counterexample.strip()}",
                    "severity": "HIGH",
                    "confidence": 0.90,  # High confidence - symbolic proof
                    "category": "property_violation",
                    "location": {
                        "file": contract_path,
                        "test_file": test_path,
                        "details": f"Test: {test_name}"
                    },
                    "recommendation": f"Review test {test_name} and fix the property violation. Counterexample: {counterexample.strip()[:200]}",
                    "references": [
                        "https://github.com/a16z/halmos",
                        f"Test file: {test_path}"
                    ]
                })

            # Detect assertion violations
            if "assert" in line.lower() and ("false" in line.lower() or "fail" in line.lower()):
                findings.append({
                    "id": f"halmos-{len(findings)+1}",
                    "title": "Assertion Violation Detected",
                    "description": line.strip(),
                    "severity": "HIGH",
                    "confidence": 0.88,
                    "category": "assertion_violation",
                    "location": {
                        "file": contract_path,
                        "test_file": test_path,
                        "details": "Detected during symbolic execution"
                    },
                    "recommendation": "Review assertion conditions and ensure they hold for all possible inputs",
                    "references": ["https://github.com/a16z/halmos/wiki/Assertions"]
                })

            # Detect revert conditions
            if "revert" in line.lower() and "unexpected" in line.lower():
                findings.append({
                    "id": f"halmos-{len(findings)+1}",
                    "title": "Unexpected Revert Condition",
                    "description": line.strip(),
                    "severity": "MEDIUM",
                    "confidence": 0.75,
                    "category": "revert_condition",
                    "location": {
                        "file": contract_path,
                        "test_file": test_path
                    },
                    "recommendation": "Verify that revert conditions are intentional and properly documented",
                    "references": ["https://github.com/a16z/halmos"]
                })

        # Check for successful execution
        if "PASS" in output and not findings:
            findings.append({
                "id": "halmos-pass",
                "title": "All Symbolic Tests Passed",
                "description": f"Halmos successfully verified all properties in {Path(test_path).name}",
                "severity": "INFO",
                "confidence": 1.0,
                "category": "verification_success",
                "location": {
                    "file": contract_path,
                    "test_file": test_path
                },
                "recommendation": "Properties verified symbolically - good test coverage",
                "references": [f"Test file: {test_path}"]
            })

        logger.info(f"Halmos: Extracted {len(findings)} findings")
        return findings


__all__ = ["HalmosAdapter"]
