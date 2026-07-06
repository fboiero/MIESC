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

import json
import logging
import math
import re
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

FOUNDRY_RUNTIME_ERRORS = (OSError, RuntimeError, subprocess.SubprocessError)
FOUNDRY_PARSE_ERRORS = (AttributeError, TypeError, ValueError)
MAX_RAW_OUTPUT_CHARS = 200_000
MAX_JSON_OUTPUT_LINE_CHARS = 50_000


def _safe_match_filter(value: Any) -> str:
    """Return forge match filters only when they are plain text."""
    if not isinstance(value, str):
        return ""
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        return ""
    text = value.strip()
    if not text:
        return ""
    return text


def _is_gas_report_header_row(cells: List[str]) -> bool:
    """Return True only for normalized gas-report header rows."""
    if len(cells) != 6:
        return False
    normalized = [cell.strip().lower() for cell in cells]
    return normalized == ["contract", "method", "min", "max", "avg", "calls"]


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
        if not isinstance(project_dir, (str, Path)):
            raise ValueError("Malformed Foundry project directory")
        if isinstance(project_dir, str) and not project_dir.strip():
            raise ValueError("Malformed Foundry project directory")
        self.project_dir = Path(project_dir)
        self.fork_url = fork_url.strip() if isinstance(fork_url, str) and fork_url.strip() else None
        self.fork_block = (
            fork_block
            if not isinstance(fork_block, bool) and isinstance(fork_block, int) and fork_block > 0
            else None
        )
        self.verbosity = (
            verbosity
            if not isinstance(verbosity, bool) and isinstance(verbosity, int) and 1 <= verbosity <= 5
            else 3
        )
        self.gas_report = gas_report if isinstance(gas_report, bool) else True

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
        except FileNotFoundError as e:
            raise RuntimeError(
                "Foundry not installed. Install with: curl -L https://foundry.paradigm.xyz | bash"
            ) from e
        except subprocess.TimeoutExpired:
            logger.warning("Foundry version check timed out")

    def _apply_common_test_options(self, cmd: List[str]) -> List[str]:
        """Append options shared by all forge test invocations."""
        cmd.append(f"-{'v' * self.verbosity}")

        if self.gas_report:
            cmd.append("--gas-report")

        if isinstance(self.fork_url, str) and self.fork_url:
            cmd.extend(["--fork-url", self.fork_url])
            if (
                isinstance(self.fork_block, int)
                and not isinstance(self.fork_block, bool)
                and self.fork_block > 0
            ):
                cmd.extend(["--fork-block-number", str(self.fork_block)])

        cmd.append("--json")
        return cmd

    def _build_run_test_command(
        self,
        test_path: Union[str, Path],
        match_test: Optional[str] = None,
        match_contract: Optional[str] = None,
    ) -> List[str]:
        """Build the forge command for a specific test file."""
        test_path_text = str(test_path).strip() if isinstance(test_path, (str, Path)) else ""
        if not test_path_text or any(ord(ch) < 32 for ch in test_path_text):
            raise ValueError("Malformed Foundry test path")
        cmd = ["forge", "test", "--match-path", test_path_text]

        match_test_text = _safe_match_filter(match_test)
        if match_test_text:
            cmd.extend(["--match-test", match_test_text])
        match_contract_text = _safe_match_filter(match_contract)
        if match_contract_text:
            cmd.extend(["--match-contract", match_contract_text])

        return self._apply_common_test_options(cmd)

    def _build_run_all_tests_command(
        self,
        test_dir: Optional[Union[str, Path]] = None,
    ) -> List[str]:
        """Build the forge command for an all-tests run."""
        cmd = ["forge", "test"]

        if test_dir:
            cmd.extend(["--match-path", f"{test_dir}/*"])

        return self._apply_common_test_options(cmd)

    @staticmethod
    def _normalize_timeout_seconds(value: Any, default: int) -> int:
        """Return a positive finite subprocess timeout."""
        if isinstance(value, bool):
            return default
        if isinstance(value, int):
            return value if value > 0 else default
        if isinstance(value, float) and math.isfinite(value):
            return int(value) if value > 0 else default
        return default

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
        timeout = self._normalize_timeout_seconds(timeout, 300)

        cmd = self._build_run_test_command(test_path, match_test, match_contract)

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
        except FOUNDRY_RUNTIME_ERRORS as e:
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
        timeout = self._normalize_timeout_seconds(timeout, 600)

        cmd = self._build_run_all_tests_command(test_dir)

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
        except FOUNDRY_RUNTIME_ERRORS as e:
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

            returncode = result.returncode
            if not isinstance(returncode, int) or isinstance(returncode, bool):
                logger.error("Compilation failed: malformed forge return code")
                return False
            if returncode == 0:
                logger.info("Compilation successful")
                return True
            else:
                error_text = self._normalize_output_text(getattr(result, "stderr", ""))
                logger.error("Compilation failed: %s", error_text)
                return False

        except FOUNDRY_RUNTIME_ERRORS as e:
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
        raw_output = self._normalize_output_text(result.raw_output)
        error = self._normalize_output_text(result.error)

        validation: Dict[str, Any] = {
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
            if "PROFIT" in raw_output:
                validation["exploit_demonstrated"] = True
            elif "FAILED" in raw_output:
                validation["exploit_demonstrated"] = False
                validation["warnings"].append("Exploit may not have succeeded")
            else:
                validation["exploit_demonstrated"] = None
                validation["warnings"].append("Could not determine exploit success")

        # Check for common issues
        if error:
            validation["errors"].append(error)

        total_gas = (
            result.total_gas
            if isinstance(result.total_gas, int) and not isinstance(result.total_gas, bool)
            else 0
        )
        if total_gas > 10_000_000:
            validation["warnings"].append(
                f"High gas usage ({total_gas:,}) may indicate inefficient exploit"
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
        stdout = self._normalize_output_text(stdout)
        stderr = self._normalize_output_text(stderr)

        # Try to parse JSON output
        try:
            # Forge JSON output can be multiple JSON objects
            for line in stdout.split("\n"):
                line = line.strip()
                if len(line) > MAX_JSON_OUTPUT_LINE_CHARS:
                    continue
                if line.startswith("{"):
                    try:
                        data = json.loads(line)
                        tests.extend(self._parse_test_results(data))
                    except json.JSONDecodeError:
                        continue
        except FOUNDRY_PARSE_ERRORS as e:
            logger.debug(f"JSON parsing failed: {e}")

        # Fallback to regex parsing
        if not tests:
            tests = self._parse_text_output(stdout + stderr)

        # Calculate totals
        passed = sum(1 for t in tests if t.status == TestStatus.PASSED)
        failed = sum(1 for t in tests if t.status == TestStatus.FAILED)
        skipped = sum(1 for t in tests if t.status == TestStatus.SKIPPED)
        total_gas = sum(t.gas_used or 0 for t in tests)

        forge_version = self._extract_forge_version(stdout, stderr)

        normalized_returncode = (
            returncode if isinstance(returncode, int) and not isinstance(returncode, bool) else 1
        )

        return FoundryResult(
            success=normalized_returncode == 0,
            tests=tests,
            total_tests=len(tests),
            passed=passed,
            failed=failed,
            skipped=skipped,
            total_gas=total_gas,
            execution_time_ms=self._normalize_execution_time(execution_time),
            raw_output=self._bounded_raw_output(stdout, stderr),
            forge_version=forge_version,
            error=stderr if normalized_returncode != 0 else None,
        )

    @staticmethod
    def _normalize_output_text(value: Any) -> str:
        """Normalize subprocess output to text before parsing."""
        if isinstance(value, str):
            if any(ord(ch) < 32 and ch not in "\n\r\t" or ord(ch) == 127 for ch in value):
                return ""
            return value
        if isinstance(value, bytes):
            text = value.decode("utf-8", errors="replace")
            if any(ord(ch) < 32 and ch not in "\n\r\t" or ord(ch) == 127 for ch in text):
                return ""
            return text
        return ""

    def _bounded_raw_output(self, stdout: str, stderr: str) -> str:
        """Return raw output capped to a bounded result size."""
        return (stdout + stderr)[:MAX_RAW_OUTPUT_CHARS]

    def _extract_forge_version(self, *outputs: Any) -> Optional[str]:
        """Extract forge semantic version from normalized subprocess streams."""
        combined_output = "".join(self._normalize_output_text(output) for output in outputs)
        version_match = re.search(r"\bforge (\d+\.\d+\.\d+)\b", combined_output)
        return version_match.group(1) if version_match else None

    @staticmethod
    def _normalize_execution_time(value: Any) -> float:
        """Normalize execution timings without trusting malformed subprocess metadata."""
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return 0.0
        execution_time = float(value)
        return execution_time if math.isfinite(execution_time) and execution_time >= 0 else 0.0

    def _parse_test_results(self, data: Dict[str, Any]) -> List[TestResult]:
        """Parse test results from JSON data."""
        tests = []

        # Handle different JSON formats from forge
        test_results = data.get("test_results")
        if isinstance(test_results, dict):
            for contract, results in test_results.items():
                contract_name = self._normalize_test_name(contract)
                if contract_name is None:
                    continue
                if not isinstance(results, dict):
                    continue
                for test_name, result in results.items():
                    if not isinstance(result, dict):
                        continue
                    test_name = self._normalize_test_name(test_name)
                    status = self._normalize_success_status(result.get("success"))
                    if test_name is None or status is None:
                        continue
                    logs = self._normalize_logs(result.get("logs"))
                    tests.append(
                        TestResult(
                            name=f"{contract_name}::{test_name}",
                            status=status,
                            gas_used=self._normalize_gas_value(result.get("gas")),
                            logs=logs,
                        )
                    )
        elif "success" in data and (data.get("test_name") or data.get("name")):
            name = self._normalize_test_name(data.get("test_name") or data.get("name"))
            status = self._normalize_success_status(data.get("success"))
            if name is None or status is None:
                return tests
            logs = self._normalize_logs(data.get("logs"))
            tests.append(
                TestResult(
                    name=name,
                    status=status,
                    gas_used=self._normalize_gas_value(data.get("gas")),
                    logs=logs,
                )
            )

        return tests

    @staticmethod
    def _normalize_test_name(value: Any) -> Optional[str]:
        """Normalize Forge JSON test names without accepting malformed shapes."""
        if isinstance(value, str):
            name = value.strip()
            if (
                name
                and len(name) <= 120
                and not any(ord(ch) < 32 or ord(ch) == 127 for ch in value)
            ):
                return name
        return None

    @staticmethod
    def _normalize_success_status(value: Any) -> Optional[TestStatus]:
        """Normalize Forge JSON success flags to test statuses."""
        if value is True:
            return TestStatus.PASSED
        if value is False:
            return TestStatus.FAILED
        if isinstance(value, str):
            status = value.strip().lower()
            if status in {"pass", "passed", "success"}:
                return TestStatus.PASSED
            if status in {"fail", "failed", "failure"}:
                return TestStatus.FAILED
            if status in {"skip", "skipped"}:
                return TestStatus.SKIPPED
        return None

    @staticmethod
    def _normalize_logs(value: Any) -> List[str]:
        """Normalize Forge JSON logs to string entries only."""
        if not isinstance(value, list):
            return []
        logs = []
        for log in value:
            if not isinstance(log, str):
                continue
            text = log.strip()
            if not text or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
                continue
            logs.append(text)
        return logs

    @staticmethod
    def _normalize_gas_value(value: Any) -> Optional[int]:
        """Normalize Forge JSON gas values without trusting malformed shapes."""
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            normalized = value.replace(",", "").strip()
            if normalized.isdigit() and len(normalized) <= 12:
                return int(normalized)
        return None

    @staticmethod
    def _normalize_gas_report(value: Any) -> Dict[str, Any]:
        """Normalize Forge JSON gas_report payloads to contract mappings only."""
        if not isinstance(value, dict):
            return {}

        normalized = {}
        for contract, report in value.items():
            if not isinstance(contract, str) or not isinstance(report, dict):
                continue
            try:
                contract_name = contract.strip()
            except (AttributeError, TypeError, ValueError):
                continue
            if not contract_name or any(ord(ch) < 32 for ch in contract_name):
                continue

            contract_report = dict(report)
            methods = contract_report.get("methods")
            if "methods" in contract_report:
                contract_report["methods"] = (
                    {
                        method: metrics
                        for method, metrics in methods.items()
                        if isinstance(method, str)
                        and isinstance(metrics, dict)
                        and method.strip()
                        and not any(ord(ch) < 32 for ch in method.strip())
                    }
                    if isinstance(methods, dict)
                    else {}
                )
            normalized[contract_name] = contract_report

        return normalized

    def _parse_text_output(self, output: str) -> List[TestResult]:
        """Parse test results from text output."""
        tests = []

        # Pattern for test results:
        # [PASS] testName() (gas: 12345)
        # [PASS] testFuzz(uint256) (runs: 256)
        pattern = (
            r"\[(PASS|FAIL|SKIP)\]\s+([A-Za-z_]\w*)\([^)]*\)\s*"
            r"(?:\([^)]*gas:\s*([\d,]+)[^)]*\))?"
        )

        for match in re.finditer(pattern, output):
            status_str, name, gas = match.groups()

            if status_str == "PASS":
                status = TestStatus.PASSED
            elif status_str == "FAIL":
                status = TestStatus.FAILED
            else:
                status = TestStatus.SKIPPED

            tests.append(
                TestResult(
                    name=name,
                    status=status,
                    gas_used=int(gas.replace(",", "")) if gas else None,
                )
            )

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
            report: Dict[str, Any] = {
                "contracts": {},
                "total_deployment_gas": 0,
                "total_runtime_gas": 0,
            }

            # Extract gas data from output
            stdout = self._normalize_output_text(getattr(result, "stdout", ""))[
                :MAX_RAW_OUTPUT_CHARS
            ]
            for line in stdout.split("\n"):
                if line.strip().startswith("{"):
                    try:
                        data = json.loads(line)
                        if not isinstance(data, dict):
                            continue
                        gas_report = data.get("gas_report")
                        normalized_report = self._normalize_gas_report(gas_report)
                        if normalized_report:
                            report["contracts"] = normalized_report
                    except json.JSONDecodeError:
                        continue
                elif line.strip().startswith("|") and "----" not in line:
                    cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
                    if len(cells) != 6 or _is_gas_report_header_row(cells):
                        continue

                    contract, method, min_gas, max_gas, avg_gas, calls = cells
                    if not _safe_match_filter(contract) or not _safe_match_filter(method):
                        continue
                    try:
                        method_report: Dict[str, Any] = {
                            "min": int(min_gas.replace(",", "")),
                            "max": int(max_gas.replace(",", "")),
                            "avg": int(avg_gas.replace(",", "")),
                            "calls": int(calls.replace(",", "")),
                        }
                    except ValueError:
                        continue

                    contract_report = report["contracts"].setdefault(contract, {"methods": {}})
                    contract_report["methods"][method] = method_report
                    report["total_runtime_gas"] += method_report["avg"] * method_report["calls"]

            return report

        except FOUNDRY_RUNTIME_ERRORS as e:
            logger.error(f"Gas report failed: {e}")
            return {"error": str(e)}


# Export
__all__ = ["FoundryRunner", "FoundryResult", "TestResult", "TestStatus"]
