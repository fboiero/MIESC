"""
Wake Testing Framework Adapter - MIESC Phase 4 (Matured Implementation)
=========================================================================

Ackee Blockchain's Python-based testing framework for Solidity contracts.
Wake provides pytest-style testing infrastructure with advanced features.

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

logger = logging.getLogger(__name__)


class WakeAdapter(ToolAdapter):
    """
    Wake Testing Framework Adapter for MIESC Layer 4.

    Key Features:
    - Python-based testing with pytest integration
    - Advanced test discovery and execution
    - Coverage analysis for Solidity contracts
    - Property testing support
    - Detailed test result reporting
    """

    def __init__(self):
        super().__init__()
        self._default_timeout = 300  # 5 minutes

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="wake",
            version="2.0.0",
            category=ToolCategory.FORMAL_VERIFICATION,
            author="Ackee Blockchain (Adapter by Fernando Boiero)",
            license="ISC",
            homepage="https://getwake.io",
            repository="https://github.com/Ackee-Blockchain/wake",
            documentation="https://ackee.xyz/wake/docs/latest/",
            installation_cmd="pip install eth-wake",
            capabilities=[
                ToolCapability(
                    name="python_testing",
                    description="Python-based testing framework for Solidity (Ackee Blockchain)",
                    supported_languages=["solidity"],
                    detection_types=[
                        "test_failures",
                        "assertion_violations",
                        "property_violations",
                        "coverage_gaps",
                        "invariant_breaks"
                    ]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True
        )

    def is_available(self) -> ToolStatus:
        """Check if Wake is installed and functional."""
        try:
            result = subprocess.run(
                ["wake", "--version"],
                capture_output=True,
                timeout=5,
                text=True
            )

            if result.returncode == 0:
                return ToolStatus.AVAILABLE
            else:
                logger.warning(f"Wake version check failed: {result.stderr}")
                return ToolStatus.CONFIGURATION_ERROR

        except FileNotFoundError:
            logger.info("Wake not installed. Install: pip install eth-wake")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            logger.warning("Wake version check timeout")
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking Wake: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze contract using Wake testing framework.

        Args:
            contract_path: Path to Solidity contract
            **kwargs: Optional configuration (timeout, test_path)

        Returns:
            Analysis results with findings
        """
        start_time = time.time()

        # Check availability
        if self.is_available() != ToolStatus.AVAILABLE:
            return {
                "tool": "wake",
                "version": "2.0.0",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": "Wake not available. Install: pip install eth-wake"
            }

        try:
            # Get configuration
            timeout = kwargs.get("timeout", self._default_timeout)
            test_path = kwargs.get("test_path", None)

            # Find test directory
            if not test_path:
                test_path = self._find_test_directory(contract_path)
                if not test_path:
                    logger.warning(f"No test directory found for {contract_path}")
                    return {
                        "tool": "wake",
                        "version": "2.0.0",
                        "status": "success",
                        "findings": [],
                        "execution_time": time.time() - start_time,
                        "metadata": {"note": "No test directory found - skipping Wake"}
                    }

            # Run Wake tests
            raw_output = self._run_wake_tests(test_path, timeout=timeout)

            # Parse findings
            findings = self._parse_wake_output(raw_output, contract_path, test_path)

            return {
                "tool": "wake",
                "version": "2.0.0",
                "status": "success",
                "findings": findings,
                "metadata": {
                    "timeout": timeout,
                    "test_path": test_path
                },
                "execution_time": time.time() - start_time
            }

        except subprocess.TimeoutExpired:
            return {
                "tool": "wake",
                "version": "2.0.0",
                "status": "timeout",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": f"Wake testing exceeded {timeout}s timeout"
            }
        except Exception as e:
            logger.error(f"Wake testing error: {e}", exc_info=True)
            return {
                "tool": "wake",
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
            "coverage": True,
            "verbose": True
        }

    # ============================================================================
    # PRIVATE HELPER METHODS
    # ============================================================================

    def _find_test_directory(self, contract_path: str) -> Optional[str]:
        """Find test directory for contract."""
        contract_path_obj = Path(contract_path)

        # Common test directory patterns
        test_dirs = [
            contract_path_obj.parent / "tests",
            contract_path_obj.parent / "test",
            contract_path_obj.parent.parent / "tests",
            contract_path_obj.parent.parent / "test",
        ]

        for test_dir in test_dirs:
            if test_dir.exists() and test_dir.is_dir():
                # Check if contains Python test files
                py_files = list(test_dir.glob("test_*.py")) + list(test_dir.glob("*_test.py"))
                if py_files:
                    return str(test_dir)

        return None

    def _run_wake_tests(self, test_path: str, timeout: int = 300) -> str:
        """Execute Wake tests."""

        cmd = [
            "wake",
            "test",
            test_path,
            "--verbose",
            "--tb=short"
        ]

        logger.info(f"Wake: Running tests (timeout={timeout}s)")

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            text=True,
            cwd=Path(test_path).parent
        )

        # Wake uses pytest-style return codes: 0=pass, 1=fail (expected)
        if result.returncode not in [0, 1, 5]:  # 5=no tests collected
            logger.warning(f"Wake completed with code {result.returncode}")

        return result.stdout + "\n" + result.stderr

    def _parse_wake_output(
        self,
        output: str,
        contract_path: str,
        test_path: str
    ) -> List[Dict[str, Any]]:
        """Parse Wake output and extract findings."""
        findings = []

        lines = output.split('\n')

        # Track test results (pytest-style output)
        for i, line in enumerate(lines):
            # Detect test failures
            if "FAILED" in line or "ERROR" in line:
                # Extract test name
                test_name_match = re.search(r'test_\w+', line)
                test_name = test_name_match.group(0) if test_name_match else "unknown_test"

                # Look for failure details in following lines
                failure_details = ""
                for j in range(i+1, min(i+15, len(lines))):
                    if lines[j].strip() and not lines[j].startswith("="):
                        failure_details += lines[j].strip() + " "
                    if "AssertionError" in lines[j] or "assert" in lines[j]:
                        break

                severity = "HIGH" if "ERROR" in line else "MEDIUM"

                findings.append({
                    "id": f"wake-{len(findings)+1}",
                    "title": f"Test Failure: {test_name}",
                    "description": f"Wake test {test_name} failed. {failure_details[:300]}",
                    "severity": severity,
                    "confidence": 0.90,  # High confidence - concrete test failure
                    "category": "test_failure",
                    "location": {
                        "file": contract_path,
                        "test_file": test_path,
                        "test_name": test_name
                    },
                    "recommendation": f"Fix test {test_name} failure. Review assertion conditions.",
                    "references": [
                        "https://ackee.xyz/wake/docs/latest/",
                        f"Test file: {test_path}"
                    ]
                })

            # Detect assertion violations
            if "AssertionError" in line:
                findings.append({
                    "id": f"wake-{len(findings)+1}",
                    "title": "Assertion Violation",
                    "description": line.strip(),
                    "severity": "HIGH",
                    "confidence": 0.92,
                    "category": "assertion_violation",
                    "location": {
                        "file": contract_path,
                        "test_file": test_path
                    },
                    "recommendation": "Review assertion condition - it failed during testing",
                    "references": ["https://ackee.xyz/wake/docs/latest/testing/"]
                })

            # Detect coverage issues
            if "coverage" in line.lower() and any(x in line for x in ["%", "percent", "0"]):
                coverage_match = re.search(r'(\d+)%', line)
                if coverage_match:
                    coverage = int(coverage_match.group(1))
                    if coverage < 80:
                        findings.append({
                            "id": f"wake-coverage",
                            "title": f"Low Test Coverage: {coverage}%",
                            "description": f"Test coverage is {coverage}%, below recommended 80%",
                            "severity": "LOW",
                            "confidence": 0.85,
                            "category": "coverage_gap",
                            "location": {
                                "file": contract_path,
                                "test_file": test_path
                            },
                            "recommendation": "Add more test cases to improve coverage",
                            "references": ["https://ackee.xyz/wake/docs/latest/testing/coverage/"]
                        })

        # Check for successful test run
        if "passed" in output.lower() and not findings:
            # Extract test count
            test_count_match = re.search(r'(\d+)\s+passed', output)
            test_count = int(test_count_match.group(1)) if test_count_match else 0

            findings.append({
                "id": "wake-pass",
                "title": f"All Wake Tests Passed ({test_count} tests)",
                "description": f"Wake successfully ran {test_count} tests with no failures",
                "severity": "INFO",
                "confidence": 1.0,
                "category": "test_success",
                "location": {
                    "file": contract_path,
                    "test_file": test_path
                },
                "recommendation": "All tests passing - continue with other analysis layers",
                "references": [f"Test file: {test_path}"]
            })

        logger.info(f"Wake: Extracted {len(findings)} findings")
        return findings


__all__ = ["WakeAdapter"]
