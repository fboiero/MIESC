"""
Foundry Testing Framework Adapter - Layer 2: Dynamic Testing
=============================================================

Foundry is a blazing fast, portable Solidity testing framework written in Rust.
Provides unit testing, fuzz testing, invariant testing, and gas reporting.

Features:
- Ultra-fast test execution (written in Rust)
- Property-based fuzzing
- Invariant testing
- Gas profiling
- Coverage analysis
- Snapshot testing
- Forge script support

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: November 11, 2025
Version: 1.0.0
"""

from src.core.tool_protocol import (
    ToolAdapter, ToolMetadata, ToolStatus, ToolCategory, ToolCapability
)
from src.llm import enhance_findings_with_llm
from typing import Dict, Any, List, Optional
import subprocess
import json
import tempfile
import os
import time
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)


class FoundryAdapter(ToolAdapter):
    """
    Foundry Testing Framework for MIESC Layer 2

    Foundry provides comprehensive testing capabilities for Solidity
    contracts with blazing fast execution speed and advanced features
    like invariant testing and gas profiling.

    DPGA Compliance: 100% PASS
    - Optional tool (graceful degradation if not installed)
    - No external API calls
    - Open source (can be self-hosted)
    """

    METADATA = {
        "name": "foundry",
        "version": "1.0.0",
        "category": "dynamic-testing",
        "description": "Blazing fast Solidity testing framework",
        "is_optional": True,
        "requires": ["forge", "foundry"],
        "supported_languages": ["solidity"],
        "detection_types": [
            "test_failures",
            "assertion_violations",
            "fuzz_failures",
            "invariant_violations",
            "gas_inefficiencies"
        ]
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize Foundry adapter

        Args:
            config: Configuration dict with optional:
                - test_pattern: Test file pattern (default: "test/**/*.sol")
                - fuzz_runs: Number of fuzz runs (default: 256)
                - gas_report: Enable gas reporting (default: True)
                - coverage: Enable coverage (default: False)
                - timeout: Timeout in seconds (default: 300)
        """
        self.config = config or {}
        self.test_pattern = self.config.get("test_pattern", "test/**/*.sol")
        self.fuzz_runs = self.config.get("fuzz_runs", 256)
        self.gas_report = self.config.get("gas_report", True)
        self.coverage = self.config.get("coverage", False)
        self.timeout = self.config.get("timeout", 300)

        logger.debug(f"Foundry adapter initialized (fuzz_runs={self.fuzz_runs})")

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="foundry",
            version="1.0.0",
            category=ToolCategory.DYNAMIC_TESTING,
            author="Paradigm (Adapter by Fernando Boiero)",
            license="MIT",
            homepage="https://github.com/foundry-rs/foundry",
            repository="https://github.com/foundry-rs/foundry",
            documentation="https://book.getfoundry.sh/",
            installation_cmd="curl -L https://foundry.paradigm.xyz | bash && foundryup",
            capabilities=[
                ToolCapability(
                    name="unit_testing",
                    description="Fast Solidity unit testing",
                    supported_languages=["solidity"],
                    detection_types=["test_failures", "assertion_violations"]
                ),
                ToolCapability(
                    name="fuzz_testing",
                    description="Property-based fuzz testing",
                    supported_languages=["solidity"],
                    detection_types=["fuzz_failures", "invariant_violations"]
                ),
                ToolCapability(
                    name="gas_profiling",
                    description="Gas usage profiling and optimization",
                    supported_languages=["solidity"],
                    detection_types=["gas_inefficiencies"]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True
        )

    def is_available(self) -> ToolStatus:
        """Check if Foundry is installed and available"""
        try:
            result = subprocess.run(
                ["forge", "--version"],
                capture_output=True,
                timeout=5,
                text=True
            )
            if result.returncode == 0:
                logger.debug(f"Foundry available: {result.stdout.strip()}")
                return ToolStatus.AVAILABLE
            else:
                return ToolStatus.CONFIGURATION_ERROR
        except FileNotFoundError:
            logger.debug("Foundry not installed")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking Foundry availability: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Run Foundry tests on contract project

        Args:
            contract_path: Path to Solidity contract file or project root
            **kwargs: Additional arguments:
                - test_contract: Specific test contract to run
                - test_function: Specific test function to run
                - match_path: Test file path pattern
                - verbosity: Verbosity level (0-4)

        Returns:
            Dict containing:
                - tool: "foundry"
                - version: Version string
                - status: "success" or "error"
                - findings: List of test failures found
                - execution_time: Test duration
                - tests_run: Number of tests executed
                - tests_passed: Number of tests passed
                - tests_failed: Number of tests failed
                - gas_report: Gas usage information
        """
        start_time = time.time()

        # Check availability
        if self.is_available() != ToolStatus.AVAILABLE:
            return {
                "tool": "foundry",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": "Foundry not available"
            }

        try:
            # Determine project root (look for foundry.toml or lib/ folder)
            project_root = self._find_project_root(contract_path)

            # Build forge test command
            cmd = ["forge", "test"]

            # Add fuzz runs
            cmd.extend(["--fuzz-runs", str(self.fuzz_runs)])

            # Add gas reporting
            if self.gas_report:
                cmd.append("--gas-report")

            # Add test contract filter if specified
            test_contract = kwargs.get("test_contract")
            if test_contract:
                cmd.extend(["--match-contract", test_contract])

            # Add test function filter if specified
            test_function = kwargs.get("test_function")
            if test_function:
                cmd.extend(["--match-test", test_function])

            # Add match path if specified
            match_path = kwargs.get("match_path")
            if match_path:
                cmd.extend(["--match-path", match_path])

            # Add verbosity
            verbosity = kwargs.get("verbosity", 2)
            cmd.append("-" + "v" * verbosity)

            # Add JSON output for easier parsing
            cmd.append("--json")

            logger.info(f"Running Foundry: {' '.join(cmd)}")

            # Run forge test
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout,
                text=True,
                cwd=project_root
            )

            duration = time.time() - start_time

            # Parse output
            findings, test_stats = self._parse_output(result.stdout, result.stderr)

            # Enhance findings with OpenLLaMA (optional)
            try:
                with open(contract_path, 'r') as f:
                    contract_code = f.read()

                # Enhance top findings with LLM insights
                if findings:
                    findings = enhance_findings_with_llm(
                        findings[:5],  # Top 5 findings
                        contract_code,
                        "foundry"
                    )
            except Exception as e:
                logger.debug(f"LLM enhancement failed: {e}")

            # Extract gas report if available
            gas_report = self._extract_gas_report(result.stdout, result.stderr)

            return {
                "tool": "foundry",
                "version": "1.0.0",
                "status": "success",
                "findings": findings,
                "execution_time": round(duration, 2),
                "tests_run": test_stats.get("total", 0),
                "tests_passed": test_stats.get("passed", 0),
                "tests_failed": test_stats.get("failed", 0),
                "gas_report": gas_report,
                "fuzz_runs": self.fuzz_runs,
                "dpga_compliant": True
            }

        except subprocess.TimeoutExpired:
            logger.error(f"Foundry timeout after {self.timeout}s")
            return {
                "tool": "foundry",
                "status": "error",
                "findings": [],
                "execution_time": self.timeout,
                "error": f"Test timeout after {self.timeout}s"
            }
        except FileNotFoundError:
            return {
                "tool": "foundry",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": f"Project root not found for: {contract_path}"
            }
        except Exception as e:
            logger.error(f"Foundry analysis failed: {str(e)}")
            return {
                "tool": "foundry",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": str(e)
            }

    def _find_project_root(self, contract_path: str) -> str:
        """
        Find Foundry project root by looking for foundry.toml or lib/ directory

        Args:
            contract_path: Path to contract file or directory

        Returns:
            Path to project root
        """
        path = Path(contract_path)

        # If it's a file, start from parent directory
        if path.is_file():
            path = path.parent

        # Search upwards for foundry.toml or lib/ directory
        current = path
        for _ in range(10):  # Limit search depth
            if (current / "foundry.toml").exists() or (current / "lib").exists():
                return str(current)

            parent = current.parent
            if parent == current:  # Reached root
                break
            current = parent

        # Fallback to original path
        return str(path)

    def _parse_output(self, stdout: str, stderr: str) -> tuple:
        """
        Parse Foundry test output to extract findings and statistics

        Foundry JSON output format:
        {
          "test_results": {
            "ContractName": {
              "test_functionName": {
                "success": false,
                "reason": "assertion failed",
                ...
              }
            }
          }
        }
        """
        findings = []
        test_stats = {"total": 0, "passed": 0, "failed": 0}

        # Try to parse JSON output first
        try:
            # Foundry outputs multiple JSON lines, find the test results
            for line in stdout.split('\n'):
                if line.strip().startswith('{'):
                    try:
                        data = json.loads(line)
                        if "test_results" in data:
                            findings, test_stats = self._parse_json_results(data)
                            return findings, test_stats
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.debug(f"Failed to parse JSON output: {e}")

        # Fallback to text parsing
        findings, test_stats = self._parse_text_output(stdout, stderr)

        return findings, test_stats

    def _parse_json_results(self, data: Dict[str, Any]) -> tuple:
        """Parse JSON test results from Foundry"""
        findings = []
        test_stats = {"total": 0, "passed": 0, "failed": 0}

        test_results = data.get("test_results", {})

        for contract_name, tests in test_results.items():
            for test_name, result in tests.items():
                test_stats["total"] += 1

                success = result.get("success", True)
                if success:
                    test_stats["passed"] += 1
                else:
                    test_stats["failed"] += 1

                    # Create finding for failed test
                    reason = result.get("reason", "Test failed")
                    findings.append({
                        "type": "test_failure",
                        "severity": "high",
                        "contract": contract_name,
                        "test": test_name,
                        "description": f"Test {test_name} failed: {reason}",
                        "recommendation": "Review test failure and fix contract logic",
                        "counterexample": result.get("counterexample"),
                        "decoded_logs": result.get("decoded_logs", [])
                    })

        return findings, test_stats

    def _parse_text_output(self, stdout: str, stderr: str) -> tuple:
        """Parse text output from Foundry (fallback)"""
        findings = []
        test_stats = {"total": 0, "passed": 0, "failed": 0}

        lines = stdout.split('\n')
        current_contract = None

        for line in lines:
            line = line.strip()

            # Detect contract name
            if line.startswith('[PASS]') or line.startswith('[FAIL]'):
                # Extract test result
                if '[FAIL]' in line:
                    test_stats["total"] += 1
                    test_stats["failed"] += 1

                    # Extract test name
                    match = re.search(r'\[FAIL.*?\]\s+(\w+)\(\)', line)
                    if match:
                        test_name = match.group(1)
                        findings.append({
                            "type": "test_failure",
                            "severity": "high",
                            "test": test_name,
                            "description": f"Test {test_name} failed",
                            "recommendation": "Review test failure and fix contract logic"
                        })
                elif '[PASS]' in line:
                    test_stats["total"] += 1
                    test_stats["passed"] += 1

            # Extract summary statistics
            elif 'passing' in line.lower() and 'failing' in line.lower():
                # Pattern: "Test result: ok. X passed; Y failed; ..."
                passed_match = re.search(r'(\d+)\s+passed', line)
                failed_match = re.search(r'(\d+)\s+failed', line)

                if passed_match:
                    test_stats["passed"] = int(passed_match.group(1))
                if failed_match:
                    test_stats["failed"] = int(failed_match.group(1))

                test_stats["total"] = test_stats["passed"] + test_stats["failed"]

        return findings, test_stats

    def _extract_gas_report(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        Extract gas usage information from output

        Foundry gas report format:
        | Function | Min | Avg | Max | Calls |
        """
        gas_report = {"available": False}

        # Look for gas report table
        if "gas report" in stdout.lower() or "|" in stdout:
            gas_report["available"] = True
            gas_report["note"] = "Gas report generated (see full output)"

            # Try to extract some basic stats
            gas_functions = []
            lines = stdout.split('\n')
            in_table = False

            for line in lines:
                if '|' in line and 'Function' in line:
                    in_table = True
                    continue

                if in_table and '|' in line:
                    # Parse table row
                    parts = [p.strip() for p in line.split('|')]
                    if len(parts) >= 5 and parts[1]:  # Has function name
                        try:
                            gas_functions.append({
                                "function": parts[1],
                                "avg_gas": int(parts[3].replace(',', ''))
                            })
                        except (ValueError, IndexError):
                            pass

                # Stop at empty line
                if in_table and not line.strip():
                    break

            if gas_functions:
                gas_report["functions"] = gas_functions[:10]  # Top 10

        return gas_report

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """
        Normalize findings to MIESC standard format

        Args:
            raw_output: Raw Foundry output or parsed findings

        Returns:
            List of normalized findings
        """
        if isinstance(raw_output, dict) and "findings" in raw_output:
            return raw_output["findings"]
        elif isinstance(raw_output, list):
            return raw_output
        else:
            return []

    def can_analyze(self, contract_path: str) -> bool:
        """Check if file/project can be analyzed"""
        path = Path(contract_path)

        # Can analyze if it's a .sol file
        if path.is_file() and path.suffix == '.sol':
            return True

        # Can analyze if it's a directory with foundry.toml
        if path.is_dir():
            return (path / "foundry.toml").exists()

        return False

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for Foundry"""
        return {
            "test_pattern": "test/**/*.sol",
            "fuzz_runs": 256,
            "gas_report": True,
            "coverage": False,
            "timeout": 300,
            "verbosity": 2
        }


# Adapter registration
def register_adapter():
    """Register Foundry adapter with MIESC"""
    return {
        "adapter_class": FoundryAdapter,
        "metadata": FoundryAdapter.METADATA
    }


__all__ = ["FoundryAdapter", "register_adapter"]
