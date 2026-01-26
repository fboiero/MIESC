"""
Foundry Runner - PoC Execution and Validation
==============================================

Handles execution of Foundry tests for PoC validation.

Features:
- Forge test execution
- Gas reporting
- Trace analysis
- Result parsing
- Continuous validation

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
Version: 1.0.0
"""

import logging
import subprocess
import re
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from enum import Enum

logger = logging.getLogger(__name__)


class TestStatus(Enum):
    """Test execution status."""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class TestResult:
    """Result of a single test."""
    name: str
    status: TestStatus
    gas_used: Optional[int] = None
    duration_ms: float = 0
    error_message: Optional[str] = None
    traces: Optional[str] = None
    logs: List[str] = field(default_factory=list)


@dataclass
class FoundryResult:
    """Result of running Foundry tests."""
    success: bool
    tests: List[TestResult]
    total_tests: int
    passed: int
    failed: int
    skipped: int
    total_gas: int
    execution_time_ms: float
    raw_output: str
    forge_version: Optional[str] = None
    error: Optional[str] = None


class FoundryRunner:
    """
    Runs and validates Foundry PoC tests.

    Provides execution, gas analysis, and result parsing
    for generated PoC templates.
    """

    def __init__(
        self,
        project_dir: Union[str, Path],
        fork_url: Optional[str] = None,
        fork_block: Optional[int] = None,
        verbosity: int = 3,
        gas_report: bool = True,
    ):
        """
        Initialize Foundry runner.

        Args:
            project_dir: Foundry project directory
            fork_url: RPC URL for forking (optional)
            fork_block: Block number for forking (optional)
            verbosity: Test verbosity level (1-5)
            gas_report: Enable gas reporting
        """
        self.project_dir = Path(project_dir)
        self.fork_url = fork_url
        self.fork_block = fork_block
        self.verbosity = verbosity
        self.gas_report = gas_report

        self._check_foundry_installation()

    def _check_foundry_installation(self) -> None:
        """Verify Foundry is installed."""
        try:
            result = subprocess.run(
                ["forge", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                logger.debug(f"Foundry version: {result.stdout.strip()}")
            else:
                logger.warning("Foundry may not be properly installed")
        except FileNotFoundError:
            raise RuntimeError(
                "Foundry not installed. Install with: curl -L https://foundry.paradigm.xyz | bash"
            )
        except subprocess.TimeoutExpired:
            logger.warning("Foundry version check timed out")

    def run_test(
        self,
        test_path: Union[str, Path],
        match_test: Optional[str] = None,
        match_contract: Optional[str] = None,
        timeout: int = 300,
    ) -> FoundryResult:
        """
        Run a specific test file.

        Args:
            test_path: Path to test file
            match_test: Test name pattern to match
            match_contract: Contract name pattern to match
            timeout: Execution timeout in seconds

        Returns:
            FoundryResult with test results
        """
        start_time = time.time()

        # Build command
        cmd = ["forge", "test"]

        # Add test path
        cmd.extend(["--match-path", str(test_path)])

        # Add matchers
        if match_test:
            cmd.extend(["--match-test", match_test])
        if match_contract:
            cmd.extend(["--match-contract", match_contract])

        # Verbosity
        cmd.append(f"-{'v' * self.verbosity}")

        # Gas report
        if self.gas_report:
            cmd.append("--gas-report")

        # Fork configuration
        if self.fork_url:
            cmd.extend(["--fork-url", self.fork_url])
            if self.fork_block:
                cmd.extend(["--fork-block-number", str(self.fork_block)])

        # JSON output for parsing
        cmd.append("--json")

        logger.info(f"Running: {' '.join(cmd[:5])}...")

        try:
            result = subprocess.run(
                cmd,
                cwd=self.project_dir,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            execution_time = (time.time() - start_time) * 1000

            return self._parse_forge_output(
                result.stdout,
                result.stderr,
                result.returncode,
                execution_time,
            )

        except subprocess.TimeoutExpired:
            return FoundryResult(
                success=False,
                tests=[],
                total_tests=0,
                passed=0,
                failed=0,
                skipped=0,
                total_gas=0,
                execution_time_ms=(time.time() - start_time) * 1000,
                raw_output="",
                error=f"Test execution timed out after {timeout}s",
            )
        except Exception as e:
            return FoundryResult(
                success=False,
                tests=[],
                total_tests=0,
                passed=0,
                failed=0,
                skipped=0,
                total_gas=0,
                execution_time_ms=(time.time() - start_time) * 1000,
                raw_output="",
                error=str(e),
            )

    def run_all_tests(
        self,
        test_dir: Optional[Union[str, Path]] = None,
        timeout: int = 600,
    ) -> FoundryResult:
        """
        Run all tests in directory.

        Args:
            test_dir: Test directory (default: test/)
            timeout: Total execution timeout

        Returns:
            FoundryResult with all test results
        """
        start_time = time.time()

        cmd = ["forge", "test"]

        if test_dir:
            cmd.extend(["--match-path", f"{test_dir}/*"])

        cmd.append(f"-{'v' * self.verbosity}")

        if self.gas_report:
            cmd.append("--gas-report")

        if self.fork_url:
            cmd.extend(["--fork-url", self.fork_url])
            if self.fork_block:
                cmd.extend(["--fork-block-number", str(self.fork_block)])

        cmd.append("--json")

        try:
            result = subprocess.run(
                cmd,
                cwd=self.project_dir,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            return self._parse_forge_output(
                result.stdout,
                result.stderr,
                result.returncode,
                (time.time() - start_time) * 1000,
            )

        except subprocess.TimeoutExpired:
            return FoundryResult(
                success=False,
                tests=[],
                total_tests=0,
                passed=0,
                failed=0,
                skipped=0,
                total_gas=0,
                execution_time_ms=(time.time() - start_time) * 1000,
                raw_output="",
                error=f"Tests timed out after {timeout}s",
            )

    def compile(self) -> bool:
        """
        Compile the project.

        Returns:
            True if compilation successful
        """
        try:
            result = subprocess.run(
                ["forge", "build"],
                cwd=self.project_dir,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode == 0:
                logger.info("Compilation successful")
                return True
            else:
                logger.error(f"Compilation failed: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Compilation error: {e}")
            return False

    def validate_poc(
        self,
        poc_path: Union[str, Path],
        expected_profit: bool = True,
    ) -> Dict[str, Any]:
        """
        Validate a PoC by running it and checking results.

        Args:
            poc_path: Path to PoC test file
            expected_profit: Whether PoC should show profit

        Returns:
            Validation result dict
        """
        result = self.run_test(poc_path)

        validation = {
            "path": str(poc_path),
            "valid": result.success,
            "tests_passed": result.passed,
            "tests_failed": result.failed,
            "total_gas": result.total_gas,
            "execution_time_ms": result.execution_time_ms,
            "errors": [],
            "warnings": [],
        }

        # Check for exploit success indicators in output
        if result.success and expected_profit:
            if "PROFIT" in result.raw_output:
                validation["exploit_demonstrated"] = True
            elif "FAILED" in result.raw_output:
                validation["exploit_demonstrated"] = False
                validation["warnings"].append("Exploit may not have succeeded")
            else:
                validation["exploit_demonstrated"] = None
                validation["warnings"].append("Could not determine exploit success")

        # Check for common issues
        if result.error:
            validation["errors"].append(result.error)

        if result.total_gas > 10_000_000:
            validation["warnings"].append(
                f"High gas usage ({result.total_gas:,}) may indicate inefficient exploit"
            )

        return validation

    def _parse_forge_output(
        self,
        stdout: str,
        stderr: str,
        returncode: int,
        execution_time: float,
    ) -> FoundryResult:
        """Parse forge test output."""
        tests = []
        total_gas = 0

        # Try to parse JSON output
        try:
            # Forge JSON output can be multiple JSON objects
            for line in stdout.split('\n'):
                line = line.strip()
                if line.startswith('{'):
                    try:
                        data = json.loads(line)
                        tests.extend(self._parse_test_results(data))
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.debug(f"JSON parsing failed: {e}")

        # Fallback to regex parsing
        if not tests:
            tests = self._parse_text_output(stdout + stderr)

        # Calculate totals
        passed = sum(1 for t in tests if t.status == TestStatus.PASSED)
        failed = sum(1 for t in tests if t.status == TestStatus.FAILED)
        skipped = sum(1 for t in tests if t.status == TestStatus.SKIPPED)
        total_gas = sum(t.gas_used or 0 for t in tests)

        # Get forge version
        version_match = re.search(r'forge (\d+\.\d+\.\d+)', stdout + stderr)
        forge_version = version_match.group(1) if version_match else None

        return FoundryResult(
            success=returncode == 0,
            tests=tests,
            total_tests=len(tests),
            passed=passed,
            failed=failed,
            skipped=skipped,
            total_gas=total_gas,
            execution_time_ms=execution_time,
            raw_output=stdout + stderr,
            forge_version=forge_version,
            error=stderr if returncode != 0 else None,
        )

    def _parse_test_results(self, data: Dict[str, Any]) -> List[TestResult]:
        """Parse test results from JSON data."""
        tests = []

        # Handle different JSON formats from forge
        if "test_results" in data:
            for contract, results in data["test_results"].items():
                for test_name, result in results.items():
                    status = TestStatus.PASSED if result.get("success") else TestStatus.FAILED
                    tests.append(TestResult(
                        name=f"{contract}::{test_name}",
                        status=status,
                        gas_used=result.get("gas"),
                        logs=result.get("logs", []),
                    ))

        return tests

    def _parse_text_output(self, output: str) -> List[TestResult]:
        """Parse test results from text output."""
        tests = []

        # Pattern for test results: [PASS] testName() (gas: 12345)
        pattern = r'\[(PASS|FAIL|SKIP)\]\s+(\w+)\(\)\s*(?:\(gas:\s*(\d+)\))?'

        for match in re.finditer(pattern, output):
            status_str, name, gas = match.groups()

            if status_str == "PASS":
                status = TestStatus.PASSED
            elif status_str == "FAIL":
                status = TestStatus.FAILED
            else:
                status = TestStatus.SKIPPED

            tests.append(TestResult(
                name=name,
                status=status,
                gas_used=int(gas) if gas else None,
            ))

        return tests

    def get_gas_report(self) -> Dict[str, Any]:
        """
        Get detailed gas report.

        Returns:
            Gas report with per-function breakdown
        """
        try:
            result = subprocess.run(
                ["forge", "test", "--gas-report", "--json"],
                cwd=self.project_dir,
                capture_output=True,
                text=True,
                timeout=300,
            )

            # Parse gas report
            report = {
                "contracts": {},
                "total_deployment_gas": 0,
                "total_runtime_gas": 0,
            }

            # Extract gas data from output
            for line in result.stdout.split('\n'):
                if line.strip().startswith('{'):
                    try:
                        data = json.loads(line)
                        if "gas_report" in data:
                            report["contracts"] = data["gas_report"]
                    except json.JSONDecodeError:
                        continue

            return report

        except Exception as e:
            logger.error(f"Gas report failed: {e}")
            return {"error": str(e)}


# Export
__all__ = ["FoundryRunner", "FoundryResult", "TestResult", "TestStatus"]
