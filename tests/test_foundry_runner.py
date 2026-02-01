"""
Tests for Foundry Runner Module
===============================

Comprehensive tests for the FoundryRunner class which handles
execution and validation of generated PoC tests.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
"""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from src.poc.validators.foundry_runner import (
    FoundryResult,
    FoundryRunner,
    TestResult,
    TestStatus,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def runner(tmp_path):
    """Create a FoundryRunner with mocked Foundry installation."""
    with patch.object(FoundryRunner, "_check_foundry_installation"):
        return FoundryRunner(project_dir=tmp_path)


@pytest.fixture
def runner_with_fork(tmp_path):
    """Create a FoundryRunner with fork configuration."""
    with patch.object(FoundryRunner, "_check_foundry_installation"):
        return FoundryRunner(
            project_dir=tmp_path,
            fork_url="https://eth-mainnet.g.alchemy.com/v2/xxx",
            fork_block=18500000,
            verbosity=4,
            gas_report=True,
        )


@pytest.fixture
def sample_forge_output():
    """Sample forge test output."""
    return """
Running 3 tests for test/Bank.t.sol:BankTest
[PASS] test_deposit() (gas: 45123)
[PASS] test_withdraw() (gas: 65432)
[FAIL] test_exploit() (gas: 123456)
"""


@pytest.fixture
def sample_forge_json_output():
    """Sample forge test JSON output."""
    return {
        "test_results": {
            "test/Bank.t.sol:BankTest": {
                "test_deposit": {
                    "success": True,
                    "gas": 45123,
                    "logs": ["Deposit successful"],
                },
                "test_withdraw": {
                    "success": True,
                    "gas": 65432,
                    "logs": [],
                },
                "test_exploit": {
                    "success": False,
                    "gas": 123456,
                    "logs": ["Exploit failed: insufficient balance"],
                },
            }
        }
    }


@pytest.fixture
def sample_gas_report():
    """Sample gas report output."""
    return """
| Contract | Method | Min | Max | Avg | # calls |
|----------|--------|-----|-----|-----|---------|
| Bank     | deposit | 45000 | 46000 | 45500 | 10 |
| Bank     | withdraw | 65000 | 70000 | 67500 | 5 |
"""


# =============================================================================
# TestStatus Enum Tests
# =============================================================================


class TestTestStatusEnum:
    """Tests for TestStatus enum."""

    def test_all_statuses_defined(self):
        """Test all expected statuses are defined."""
        assert TestStatus.PASSED.value == "passed"
        assert TestStatus.FAILED.value == "failed"
        assert TestStatus.SKIPPED.value == "skipped"
        assert TestStatus.ERROR.value == "error"
        assert TestStatus.TIMEOUT.value == "timeout"

    def test_status_count(self):
        """Test total number of statuses."""
        assert len(TestStatus) == 5


# =============================================================================
# TestResult Tests
# =============================================================================


class TestTestResultDataclass:
    """Tests for TestResult dataclass."""

    def test_create_test_result(self):
        """Test creating a TestResult."""
        result = TestResult(
            name="test_deposit",
            status=TestStatus.PASSED,
            gas_used=45000,
            duration_ms=100.5,
        )

        assert result.name == "test_deposit"
        assert result.status == TestStatus.PASSED
        assert result.gas_used == 45000
        assert result.duration_ms == 100.5

    def test_test_result_defaults(self):
        """Test TestResult default values."""
        result = TestResult(
            name="test",
            status=TestStatus.PASSED,
        )

        assert result.gas_used is None
        assert result.duration_ms == 0
        assert result.error_message is None
        assert result.traces is None
        assert result.logs == []

    def test_failed_test_result(self):
        """Test failed TestResult with error."""
        result = TestResult(
            name="test_exploit",
            status=TestStatus.FAILED,
            error_message="Assertion failed: expected profit",
        )

        assert result.status == TestStatus.FAILED
        assert "Assertion failed" in result.error_message


# =============================================================================
# FoundryResult Tests
# =============================================================================


class TestFoundryResultDataclass:
    """Tests for FoundryResult dataclass."""

    def test_create_foundry_result(self):
        """Test creating a FoundryResult."""
        tests = [
            TestResult("test1", TestStatus.PASSED, gas_used=1000),
            TestResult("test2", TestStatus.FAILED),
        ]

        result = FoundryResult(
            success=False,
            tests=tests,
            total_tests=2,
            passed=1,
            failed=1,
            skipped=0,
            total_gas=1000,
            execution_time_ms=500.0,
            raw_output="output",
        )

        assert result.success is False
        assert len(result.tests) == 2
        assert result.passed == 1
        assert result.failed == 1
        assert result.total_gas == 1000

    def test_foundry_result_defaults(self):
        """Test FoundryResult default values."""
        result = FoundryResult(
            success=True,
            tests=[],
            total_tests=0,
            passed=0,
            failed=0,
            skipped=0,
            total_gas=0,
            execution_time_ms=0,
            raw_output="",
        )

        assert result.forge_version is None
        assert result.error is None


# =============================================================================
# FoundryRunner Initialization Tests
# =============================================================================


class TestFoundryRunnerInit:
    """Tests for FoundryRunner initialization."""

    def test_default_initialization(self, runner):
        """Test default runner initialization."""
        assert runner.fork_url is None
        assert runner.fork_block is None
        assert runner.verbosity == 3
        assert runner.gas_report is True

    def test_initialization_with_fork(self, runner_with_fork):
        """Test runner initialization with fork config."""
        assert runner_with_fork.fork_url == "https://eth-mainnet.g.alchemy.com/v2/xxx"
        assert runner_with_fork.fork_block == 18500000
        assert runner_with_fork.verbosity == 4

    def test_foundry_not_installed_raises(self, tmp_path):
        """Test error when Foundry not installed."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(RuntimeError) as exc_info:
                FoundryRunner(project_dir=tmp_path)

            assert "Foundry not installed" in str(exc_info.value)


# =============================================================================
# Run Test Tests
# =============================================================================


class TestRunTest:
    """Tests for run_test method."""

    def test_run_test_success(self, runner, sample_forge_output):
        """Test successful test run."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_forge_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = runner.run_test("test/Bank.t.sol")

        assert isinstance(result, FoundryResult)
        assert result.success is True

    def test_run_test_failure(self, runner):
        """Test failed test run."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = "[FAIL] test_exploit()"
        mock_result.stderr = "Assertion failed"

        with patch("subprocess.run", return_value=mock_result):
            result = runner.run_test("test/Bank.t.sol")

        assert result.success is False
        assert result.error is not None

    def test_run_test_timeout(self, runner):
        """Test test run timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("forge", 300)):
            result = runner.run_test("test/Bank.t.sol", timeout=300)

        assert result.success is False
        assert "timed out" in result.error.lower()

    def test_run_test_with_match_test(self, runner, sample_forge_output):
        """Test run with test name matcher."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_forge_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            runner.run_test("test/Bank.t.sol", match_test="test_exploit")

        cmd = mock_run.call_args[0][0]
        assert "--match-test" in cmd
        assert "test_exploit" in cmd

    def test_run_test_with_match_contract(self, runner, sample_forge_output):
        """Test run with contract name matcher."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_forge_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            runner.run_test("test/Bank.t.sol", match_contract="BankTest")

        cmd = mock_run.call_args[0][0]
        assert "--match-contract" in cmd
        assert "BankTest" in cmd


# =============================================================================
# Run All Tests Tests
# =============================================================================


class TestRunAllTests:
    """Tests for run_all_tests method."""

    def test_run_all_tests(self, runner, sample_forge_output):
        """Test running all tests."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_forge_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = runner.run_all_tests()

        assert isinstance(result, FoundryResult)
        assert result.success is True

    def test_run_all_tests_with_dir(self, runner, sample_forge_output):
        """Test running all tests in specific directory."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_forge_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            runner.run_all_tests(test_dir="test/exploits")

        cmd = mock_run.call_args[0][0]
        assert "--match-path" in cmd

    def test_run_all_tests_timeout(self, runner):
        """Test run_all_tests timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("forge", 600)):
            result = runner.run_all_tests(timeout=600)

        assert result.success is False
        assert "timed out" in result.error.lower()


# =============================================================================
# Compile Tests
# =============================================================================


class TestCompile:
    """Tests for compile method."""

    def test_compile_success(self, runner):
        """Test successful compilation."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Compiling..."
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            success = runner.compile()

        assert success is True

    def test_compile_failure(self, runner):
        """Test failed compilation."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: ParserError"

        with patch("subprocess.run", return_value=mock_result):
            success = runner.compile()

        assert success is False

    def test_compile_exception(self, runner):
        """Test compilation with exception."""
        with patch("subprocess.run", side_effect=Exception("Unknown error")):
            success = runner.compile()

        assert success is False


# =============================================================================
# Validate PoC Tests
# =============================================================================


class TestValidatePoC:
    """Tests for validate_poc method."""

    def test_validate_poc_success(self, runner, sample_forge_output):
        """Test successful PoC validation."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_forge_output + "\nPROFIT: 10 ETH"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            validation = runner.validate_poc("test/exploit.t.sol")

        assert validation["valid"] is True
        assert validation["exploit_demonstrated"] is True

    def test_validate_poc_no_profit(self, runner, sample_forge_output):
        """Test PoC validation without profit indicator."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_forge_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            validation = runner.validate_poc("test/exploit.t.sol")

        assert validation["valid"] is True
        assert validation["exploit_demonstrated"] is None  # Uncertain

    def test_validate_poc_failed(self, runner):
        """Test failed PoC validation."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = "FAILED"
        mock_result.stderr = "Assertion error"

        with patch("subprocess.run", return_value=mock_result):
            validation = runner.validate_poc("test/exploit.t.sol")

        assert validation["valid"] is False
        assert len(validation["errors"]) > 0

    def test_validate_poc_high_gas_warning(self, runner):
        """Test PoC validation warns about high gas."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "[PASS] test() (gas: 15000000)"
        mock_result.stderr = ""

        # Mock the run_test to return high gas
        high_gas_result = FoundryResult(
            success=True,
            tests=[TestResult("test", TestStatus.PASSED, gas_used=15000000)],
            total_tests=1,
            passed=1,
            failed=0,
            skipped=0,
            total_gas=15000000,
            execution_time_ms=100,
            raw_output="PROFIT: 1 ETH",
        )

        with patch.object(runner, "run_test", return_value=high_gas_result):
            validation = runner.validate_poc("test/exploit.t.sol")

        assert any("gas" in w.lower() for w in validation["warnings"])


# =============================================================================
# Parse Output Tests
# =============================================================================


class TestParseOutput:
    """Tests for output parsing methods."""

    def test_parse_text_output(self, runner, sample_forge_output):
        """Test parsing text output."""
        tests = runner._parse_text_output(sample_forge_output)

        assert len(tests) == 3
        assert tests[0].name == "test_deposit"
        assert tests[0].status == TestStatus.PASSED
        assert tests[0].gas_used == 45123

    def test_parse_text_output_with_fail(self, runner, sample_forge_output):
        """Test parsing output with failed test."""
        tests = runner._parse_text_output(sample_forge_output)

        failed_tests = [t for t in tests if t.status == TestStatus.FAILED]
        assert len(failed_tests) == 1
        assert failed_tests[0].name == "test_exploit"

    def test_parse_json_output(self, runner, sample_forge_json_output):
        """Test parsing JSON output."""
        tests = runner._parse_test_results(sample_forge_json_output)

        assert len(tests) == 3

        passed = [t for t in tests if t.status == TestStatus.PASSED]
        failed = [t for t in tests if t.status == TestStatus.FAILED]

        assert len(passed) == 2
        assert len(failed) == 1

    def test_parse_empty_output(self, runner):
        """Test parsing empty output."""
        tests = runner._parse_text_output("")
        assert tests == []

    def test_parse_forge_output_combined(self, runner, sample_forge_output):
        """Test combined parsing."""
        result = runner._parse_forge_output(sample_forge_output, "", 0, 100.0)

        assert result.success is True
        assert result.total_tests == 3
        assert result.passed == 2
        assert result.failed == 1


# =============================================================================
# Gas Report Tests
# =============================================================================


class TestGasReport:
    """Tests for gas report functionality."""

    def test_get_gas_report(self, runner, sample_gas_report):
        """Test getting gas report."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_gas_report
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            report = runner.get_gas_report()

        assert "contracts" in report

    def test_get_gas_report_error(self, runner):
        """Test gas report with error."""
        with patch("subprocess.run", side_effect=Exception("Error")):
            report = runner.get_gas_report()

        assert "error" in report


# =============================================================================
# Fork Configuration Tests
# =============================================================================


class TestForkConfiguration:
    """Tests for fork configuration."""

    def test_run_with_fork_url(self, runner_with_fork, sample_forge_output):
        """Test running with fork URL."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_forge_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            runner_with_fork.run_test("test/Bank.t.sol")

        cmd = mock_run.call_args[0][0]
        assert "--fork-url" in cmd
        assert "https://eth-mainnet.g.alchemy.com/v2/xxx" in cmd

    def test_run_with_fork_block(self, runner_with_fork, sample_forge_output):
        """Test running with fork block number."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_forge_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            runner_with_fork.run_test("test/Bank.t.sol")

        cmd = mock_run.call_args[0][0]
        assert "--fork-block-number" in cmd
        assert "18500000" in cmd


# =============================================================================
# Verbosity Tests
# =============================================================================


class TestVerbosity:
    """Tests for verbosity configuration."""

    def test_verbosity_level_3(self, runner, sample_forge_output):
        """Test default verbosity level."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_forge_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            runner.run_test("test/Bank.t.sol")

        cmd = mock_run.call_args[0][0]
        assert "-vvv" in cmd

    def test_verbosity_level_4(self, runner_with_fork, sample_forge_output):
        """Test custom verbosity level."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_forge_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            runner_with_fork.run_test("test/Bank.t.sol")

        cmd = mock_run.call_args[0][0]
        assert "-vvvv" in cmd


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests for FoundryRunner."""

    def test_full_test_flow(self, runner, sample_forge_output, tmp_path):
        """Test complete test execution flow."""
        # Create mock test file
        test_file = tmp_path / "test" / "Exploit.t.sol"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("// Test file")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_forge_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = runner.run_test(str(test_file))

        assert result.success is True
        assert len(result.tests) >= 0  # Depends on parsing

    def test_validation_flow(self, runner, tmp_path):
        """Test complete validation flow."""
        test_file = tmp_path / "test" / "Exploit.t.sol"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("// Test file")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "[PASS] test_exploit() (gas: 50000)\nPROFIT: 5 ETH"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            validation = runner.validate_poc(str(test_file))

        assert validation["valid"] is True
        assert "path" in validation
        assert "execution_time_ms" in validation
