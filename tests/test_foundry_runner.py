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

    def test_initialization_normalizes_fork_options(self, tmp_path):
        """Fork options are normalized before command construction."""
        with patch.object(FoundryRunner, "_check_foundry_installation"):
            runner = FoundryRunner(
                project_dir=tmp_path,
                fork_url=" https://rpc.example ",
                fork_block=True,
            )

        assert runner.fork_url == "https://rpc.example"
        assert runner.fork_block is None

    def test_initialization_defaults_malformed_verbosity_and_gas_report(self, tmp_path):
        """Malformed runner options fall back to safe command defaults."""
        with patch.object(FoundryRunner, "_check_foundry_installation"):
            runner = FoundryRunner(
                project_dir=tmp_path,
                verbosity=["vvv"],
                gas_report="yes",
            )

        assert runner.verbosity == 3
        assert runner.gas_report is True

    @pytest.mark.parametrize("project_dir", [None, {"path": "."}, "  "])
    def test_initialization_rejects_malformed_project_dir(self, project_dir):
        """Malformed project dirs are rejected before Path coercion or forge checks."""
        with patch.object(FoundryRunner, "_check_foundry_installation") as check_foundry:
            with pytest.raises(ValueError, match="Malformed Foundry project directory"):
                FoundryRunner(project_dir=project_dir)

        check_foundry.assert_not_called()

    def test_foundry_not_installed_raises(self, tmp_path):
        """Test error when Foundry not installed."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(RuntimeError) as exc_info:
                FoundryRunner(project_dir=tmp_path)

            assert "Foundry not installed" in str(exc_info.value)


class TestFoundryCommandBuilders:
    """Tests for forge command construction helpers."""

    def test_build_run_test_command_with_matchers(self, runner):
        """Specific test commands include path, matchers, verbosity, gas and JSON output."""
        cmd = runner._build_run_test_command(
            "test/Bank.t.sol",
            match_test="test_exploit",
            match_contract="BankTest",
        )

        assert cmd == [
            "forge",
            "test",
            "--match-path",
            "test/Bank.t.sol",
            "--match-test",
            "test_exploit",
            "--match-contract",
            "BankTest",
            "-vvv",
            "--gas-report",
            "--json",
        ]

    def test_build_run_test_command_with_fork(self, runner_with_fork):
        """Fork configuration is appended consistently."""
        cmd = runner_with_fork._build_run_test_command("test/Bank.t.sol")

        assert "--fork-url" in cmd
        assert "https://eth-mainnet.g.alchemy.com/v2/xxx" in cmd
        assert "--fork-block-number" in cmd
        assert "18500000" in cmd
        assert cmd[-1] == "--json"

    @pytest.mark.parametrize("test_path", [None, {"path": "test/Bank.t.sol"}, "  "])
    def test_build_run_test_command_rejects_malformed_test_path(self, runner, test_path):
        """Malformed test paths are rejected before command construction."""
        with pytest.raises(ValueError, match="Malformed Foundry test path"):
            runner._build_run_test_command(test_path)

    def test_build_run_test_command_ignores_malformed_match_options(self, runner):
        """Malformed match filters should not reach forge arguments."""
        cmd = runner._build_run_test_command(
            "test/Bank.t.sol",
            match_test=["testExploit"],
            match_contract="  ",
        )

        assert "--match-test" not in cmd
        assert "--match-contract" not in cmd

    def test_build_run_test_command_ignores_malformed_fork_options(self, tmp_path):
        """Malformed fork options are ignored before command construction."""
        with patch.object(FoundryRunner, "_check_foundry_installation"):
            runner = FoundryRunner(
                project_dir=tmp_path,
                fork_url={"url": "bad"},
                fork_block=["18500000"],
            )

        cmd = runner._build_run_test_command("test/Bank.t.sol")

        assert "--fork-url" not in cmd
        assert "--fork-block-number" not in cmd
        assert cmd[-1] == "--json"

    def test_build_run_all_tests_command_without_dir_omits_match_path(self, runner):
        """All-test commands do not restrict path unless a directory is provided."""
        cmd = runner._build_run_all_tests_command()

        assert "--match-path" not in cmd
        assert cmd == ["forge", "test", "-vvv", "--gas-report", "--json"]

    def test_build_run_all_tests_command_with_dir(self, runner):
        """All-test commands can be restricted to a directory glob."""
        cmd = runner._build_run_all_tests_command(test_dir="test/exploits")

        assert cmd == [
            "forge",
            "test",
            "--match-path",
            "test/exploits/*",
            "-vvv",
            "--gas-report",
            "--json",
        ]


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

    @pytest.mark.parametrize("timeout", [True, 0, -1, float("inf"), ["300"]])
    def test_run_test_defaults_malformed_timeout(self, runner, sample_forge_output, timeout):
        """Malformed runtime timeouts fall back before subprocess execution."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_forge_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            runner.run_test("test/Bank.t.sol", timeout=timeout)

        assert mock_run.call_args.kwargs["timeout"] == 300

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


class TestRunAllTestsBasic:
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

    @pytest.mark.parametrize("timeout", [True, 0, -1, float("inf"), ["600"]])
    def test_run_all_tests_defaults_malformed_timeout(self, runner, sample_forge_output, timeout):
        """Malformed all-test runtime timeouts fall back before subprocess execution."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_forge_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            runner.run_all_tests(timeout=timeout)

        assert mock_run.call_args.kwargs["timeout"] == 600

    def test_run_all_tests_runtime_error_returns_result(self, runner):
        """Test run_all_tests returns structured result for runtime errors."""
        with patch("subprocess.run", side_effect=RuntimeError("forge unavailable")):
            result = runner.run_all_tests()

        assert result.success is False
        assert result.tests == []
        assert result.total_tests == 0
        assert result.passed == 0
        assert result.failed == 0
        assert result.skipped == 0
        assert result.total_gas == 0
        assert result.raw_output == ""
        assert result.execution_time_ms >= 0
        assert result.error == "forge unavailable"


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

    def test_compile_failure_normalizes_malformed_stderr(self, runner, caplog):
        """Malformed compile stderr should not leak container reprs into logs."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = ["Error: ParserError"]

        with caplog.at_level("ERROR", logger="src.poc.validators.foundry_runner"):
            with patch("subprocess.run", return_value=mock_result):
                success = runner.compile()

        assert success is False
        assert "Compilation failed:" in caplog.text
        assert "['Error: ParserError']" not in caplog.text

    @pytest.mark.parametrize("returncode", [False, "0", None])
    def test_compile_rejects_malformed_returncode(self, runner, caplog, returncode):
        """Malformed compile return codes should not be treated as success."""
        mock_result = MagicMock()
        mock_result.returncode = returncode
        mock_result.stdout = "Compiling..."
        mock_result.stderr = ""

        with caplog.at_level("ERROR", logger="src.poc.validators.foundry_runner"):
            with patch("subprocess.run", return_value=mock_result):
                success = runner.compile()

        assert success is False
        assert "malformed forge return code" in caplog.text

    def test_compile_exception(self, runner):
        """Test compilation with exception."""
        with patch("subprocess.run", side_effect=OSError("Unknown error")):
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

    def test_validate_poc_ignores_malformed_raw_output_and_error_shapes(self, runner):
        """Test validation does not trust non-text output or error containers."""
        malformed_result = FoundryResult(
            success=True,
            tests=[],
            total_tests=0,
            passed=0,
            failed=0,
            skipped=0,
            total_gas=0,
            execution_time_ms=100,
            raw_output=["PROFIT: fake"],
            error={"message": "not a string"},
        )

        with patch.object(runner, "run_test", return_value=malformed_result):
            validation = runner.validate_poc("test/exploit.t.sol")

        assert validation["exploit_demonstrated"] is None
        assert validation["errors"] == []
        assert any("Could not determine" in w for w in validation["warnings"])

    def test_validate_poc_ignores_malformed_total_gas_shape(self, runner):
        """Malformed total gas should not break validation warning checks."""
        malformed_result = FoundryResult(
            success=True,
            tests=[],
            total_tests=0,
            passed=0,
            failed=0,
            skipped=0,
            total_gas=["100000000"],
            execution_time_ms=100,
            raw_output="PROFIT",
            error=None,
        )

        with patch.object(runner, "run_test", return_value=malformed_result):
            validation = runner.validate_poc("test/exploit.t.sol")

        assert validation["exploit_demonstrated"] is True
        assert not any("High gas usage" in warning for warning in validation["warnings"])

    def test_validate_poc_decodes_bytes_raw_output_and_error(self, runner):
        """Test validation still accepts subprocess-like byte output fields."""
        bytes_result = FoundryResult(
            success=True,
            tests=[],
            total_tests=0,
            passed=0,
            failed=0,
            skipped=0,
            total_gas=0,
            execution_time_ms=100,
            raw_output=b"PROFIT: 1 ETH",
            error=b"Assertion failed",
        )

        with patch.object(runner, "run_test", return_value=bytes_result):
            validation = runner.validate_poc("test/exploit.t.sol")

        assert validation["valid"] is True
        assert validation["exploit_demonstrated"] is True
        assert validation["errors"] == ["Assertion failed"]


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

    def test_parse_text_output_with_fuzz_signature(self, runner):
        """Test parsing forge output for fuzz tests with typed arguments."""
        output = """
[PASS] testFuzz_withdraw(uint256,address) (runs: 256, mean: 12345)
[SKIP] test_skipWhenPaused(bool)
[PASS] test_largeGas() (gas: 1,234,567)
"""

        tests = runner._parse_text_output(output)

        assert [t.name for t in tests] == [
            "testFuzz_withdraw",
            "test_skipWhenPaused",
            "test_largeGas",
        ]
        assert tests[0].status == TestStatus.PASSED
        assert tests[0].gas_used is None
        assert tests[1].status == TestStatus.SKIPPED
        assert tests[2].gas_used == 1234567

    def test_parse_json_output(self, runner, sample_forge_json_output):
        """Test parsing JSON output."""
        tests = runner._parse_test_results(sample_forge_json_output)

        assert len(tests) == 3

        passed = [t for t in tests if t.status == TestStatus.PASSED]
        failed = [t for t in tests if t.status == TestStatus.FAILED]

        assert len(passed) == 2
        assert len(failed) == 1

    def test_parse_flat_json_test_result(self, runner):
        """Test parsing a single flat JSON test result."""
        tests = runner._parse_test_results(
            {
                "test_name": "test_foo",
                "success": True,
                "gas": 12345,
                "logs": ["ok"],
            }
        )

        assert len(tests) == 1
        assert tests[0].name == "test_foo"
        assert tests[0].status == TestStatus.PASSED
        assert tests[0].gas_used == 12345
        assert tests[0].logs == ["ok"]

    def test_parse_json_test_results_ignores_malformed_shapes(self, runner):
        """Test malformed JSON test result shapes are ignored."""
        tests = runner._parse_test_results(
            {
                "test_results": {
                    "test/Bad.t.sol:BadTest": ["not", "a", "mapping"],
                    "test/Mixed.t.sol:MixedTest": {
                        "bad_entry": "not a result mapping",
                        "test_ok": {"success": True, "gas": 123, "logs": "not a list"},
                    },
                }
            }
        )

        assert len(tests) == 1
        assert tests[0].name == "test/Mixed.t.sol:MixedTest::test_ok"
        assert tests[0].status == TestStatus.PASSED
        assert tests[0].logs == []

    def test_parse_json_test_results_normalizes_gas_values(self, runner):
        """Test JSON gas values are numeric before aggregate totals use them."""
        tests = runner._parse_test_results(
            {
                "test_results": {
                    "test/Mixed.t.sol:MixedTest": {
                        "test_int": {"success": True, "gas": 123},
                        "test_string": {"success": True, "gas": "1,234"},
                        "test_bad": {"success": True, "gas": ["not numeric"]},
                        "test_bool": {"success": True, "gas": True},
                    },
                }
            }
        )

        assert [test.gas_used for test in tests] == [123, 1234, None, None]

    def test_parse_json_test_results_ignores_malformed_name_and_status(self, runner):
        """Test nested JSON results require string names and boolean success values."""
        tests = runner._parse_test_results(
            {
                "test_results": {
                    "test/Mixed.t.sol:MixedTest": {
                        "test_ok": {"success": True},
                        "test_bad_status": {"success": "true"},
                        123: {"success": True},
                    },
                }
            }
        )

        assert len(tests) == 1
        assert tests[0].name == "test/Mixed.t.sol:MixedTest::test_ok"
        assert tests[0].status == TestStatus.PASSED

    def test_parse_flat_json_test_result_ignores_malformed_name_and_status(self, runner):
        """Test flat JSON results require a string name and boolean success value."""
        assert (
            runner._parse_test_results(
                {
                    "test_name": ["test_bad"],
                    "success": True,
                }
            )
            == []
        )
        assert (
            runner._parse_test_results(
                {
                    "test_name": "test_bad_status",
                    "success": "false",
                }
            )
            == []
        )

    def test_parse_json_test_results_accepts_known_string_statuses(self, runner):
        """Test explicit Forge status strings normalize without accepting arbitrary text."""
        tests = runner._parse_test_results(
            {
                "test_results": {
                    "test/Mixed.t.sol:MixedTest": {
                        "test_pass": {"success": " passed "},
                        "test_fail": {"success": "FAILED"},
                        "test_skip": {"success": "skipped"},
                        "test_bad": {"success": "maybe"},
                    },
                }
            }
        )

        assert [test.name for test in tests] == [
            "test/Mixed.t.sol:MixedTest::test_pass",
            "test/Mixed.t.sol:MixedTest::test_fail",
            "test/Mixed.t.sol:MixedTest::test_skip",
        ]
        assert [test.status for test in tests] == [
            TestStatus.PASSED,
            TestStatus.FAILED,
            TestStatus.SKIPPED,
        ]

    def test_parse_forge_output_ignores_malformed_json_gas(self, runner):
        """Test malformed JSON gas values do not break total gas aggregation."""
        output = (
            '{"test_results": {"test/Bad.t.sol:BadTest": {'
            '"test_bad": {"success": true, "gas": ["not numeric"]},'
            '"test_ok": {"success": true, "gas": "1,000"}'
            "}}}\n"
        )

        result = runner._parse_forge_output(output, "", 0, 10)

        assert result.total_tests == 2
        assert result.total_gas == 1000

    def test_parse_flat_json_test_result_normalizes_logs(self, runner):
        """Test flat JSON test result ignores non-list logs."""
        tests = runner._parse_test_results(
            {
                "test_name": "test_foo",
                "success": True,
                "logs": "not a list",
            }
        )

        assert len(tests) == 1
        assert tests[0].logs == []

    def test_parse_json_test_results_filters_non_string_log_entries(self, runner):
        """Test nested JSON log lists do not propagate non-string entries."""
        tests = runner._parse_test_results(
            {
                "test_results": {
                    "test/Mixed.t.sol:MixedTest": {
                        "test_logs": {
                            "success": True,
                            "logs": ["first", {"event": "bad"}, 123, ["nested"], "last"],
                        },
                    },
                }
            }
        )

        assert len(tests) == 1
        assert tests[0].logs == ["first", "last"]

    def test_parse_flat_json_test_result_filters_non_string_log_entries(self, runner):
        """Test flat JSON log lists do not propagate non-string entries."""
        tests = runner._parse_test_results(
            {
                "test_name": "test_foo",
                "success": True,
                "logs": ["ok", {"decoded": False}, 0],
            }
        )

        assert len(tests) == 1
        assert tests[0].logs == ["ok"]

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
        assert report["contracts"]["Bank"]["methods"]["deposit"]["avg"] == 45500
        assert report["contracts"]["Bank"]["methods"]["withdraw"]["calls"] == 5
        assert report["total_runtime_gas"] == 45500 * 10 + 67500 * 5

    def test_get_gas_report_text_table_with_commas(self, runner):
        """Test parsing textual gas report rows with comma-separated numbers."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """
| Contract | Method | Min | Max | Avg | # calls |
|----------|--------|-----|-----|-----|---------|
| Vault    | deposit | 1,000 | 2,000 | 1,500 | 3 |
| invalid  | row     | N/A   | 2,000 | 1,500 | 3 |
"""
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            report = runner.get_gas_report()

        assert report["contracts"]["Vault"]["methods"]["deposit"] == {
            "min": 1000,
            "max": 2000,
            "avg": 1500,
            "calls": 3,
        }
        assert "invalid" not in report["contracts"]
        assert report["total_runtime_gas"] == 4500

    def test_get_gas_report_json_line(self, runner):
        """Test parsing a JSON gas_report line from forge output."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '{"gas_report": {"Vault": {"methods": {}}}}\n'
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            report = runner.get_gas_report()

        assert report["contracts"] == {"Vault": {"methods": {}}}

    def test_get_gas_report_ignores_non_object_json_report(self, runner):
        """Test non-object JSON gas_report values are ignored."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '{"gas_report": ["not", "a", "mapping"]}\n'
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            report = runner.get_gas_report()

        assert report["contracts"] == {}

    def test_get_gas_report_filters_malformed_json_contract_reports(self, runner):
        """Test JSON gas_report contract entries must be object payloads."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = (
            '{"gas_report": {'
            '"Vault": {"methods": {"deposit": {"avg": 100}}},'
            '"Broken": ["not", "a", "contract report"],'
            '"Scalar": 123'
            "}}\n"
        )
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            report = runner.get_gas_report()

        assert report["contracts"] == {
            "Vault": {"methods": {"deposit": {"avg": 100}}},
        }

    def test_get_gas_report_filters_malformed_json_method_reports(self, runner):
        """Test JSON gas_report method entries must be object payloads."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = (
            '{"gas_report": {'
            '"Vault": {"methods": {'
            '"deposit": {"avg": 100},'
            '"broken": ["not", "a", "method report"],'
            '"scalar": 123'
            "}}"
            "}}\n"
        )
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            report = runner.get_gas_report()

        assert report["contracts"] == {
            "Vault": {"methods": {"deposit": {"avg": 100}}},
        }

    def test_get_gas_report_ignores_malformed_json_methods_shape(self, runner):
        """Test JSON gas_report methods payloads must be object mappings."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '{"gas_report": {"Vault": {"methods": ["bad"]}}}\n'
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            report = runner.get_gas_report()

        assert report["contracts"] == {"Vault": {"methods": {}}}

    def test_get_gas_report_ignores_malformed_stdout_shape(self, runner):
        """Malformed gas report stdout should normalize to an empty report."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ["not text"]
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            report = runner.get_gas_report()

        assert report["contracts"] == {}
        assert report["total_runtime_gas"] == 0

    def test_get_gas_report_ignores_malformed_json_line(self, runner):
        """Test malformed JSON lines do not abort gas report parsing."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """
{"gas_report":
| Contract | Method | Min | Max | Avg | # calls |
|----------|--------|-----|-----|-----|---------|
| Vault    | withdraw | 10 | 20 | 15 | 2 |
"""
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            report = runner.get_gas_report()

        assert report["contracts"]["Vault"]["methods"]["withdraw"]["avg"] == 15
        assert report["total_runtime_gas"] == 30

    def test_get_gas_report_normalizes_malformed_stream_shapes(self, runner):
        """Test malformed stdout shapes do not abort gas report parsing."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = (
            b'["not", "a", "gas report object"]\n'
            b"| Contract | Method | Min | Max | Avg | # calls |\n"
            b"|----------|--------|-----|-----|-----|---------|\n"
            b"| Vault    | deposit | 10 | 20 | 15 | 2 |\n"
        )
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            report = runner.get_gas_report()

        assert report["contracts"]["Vault"]["methods"]["deposit"]["avg"] == 15
        assert report["total_runtime_gas"] == 30

    def test_get_gas_report_treats_missing_stdout_as_empty(self, runner):
        """Test missing stdout is handled as an empty gas report."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = None
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            report = runner.get_gas_report()

        assert report == {
            "contracts": {},
            "total_deployment_gas": 0,
            "total_runtime_gas": 0,
        }

    def test_get_gas_report_error(self, runner):
        """Test gas report with error."""
        with patch("subprocess.run", side_effect=OSError("Error")):
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
        test_file.write_text("// Test file", encoding="utf-8")

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
        test_file.write_text("// Test file", encoding="utf-8")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "[PASS] test_exploit() (gas: 50000)\nPROFIT: 5 ETH"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            validation = runner.validate_poc(str(test_file))

        assert validation["valid"] is True
        assert "path" in validation
        assert "execution_time_ms" in validation


# =============================================================================
# Additional Coverage Tests (Lines 118, 123-124, 208-209, 346-347, 380-386, etc.)
# =============================================================================


class TestFoundryInstallationCheck:
    """Tests for _check_foundry_installation edge cases (lines 118, 123-124)."""

    def test_foundry_not_properly_installed_warning(self, tmp_path, caplog):
        """Test warning when Foundry may not be properly installed (line 118)."""
        import logging

        mock_result = MagicMock()
        mock_result.returncode = 1  # Non-zero indicates issue
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            with caplog.at_level(logging.WARNING):
                FoundryRunner(project_dir=tmp_path)

        assert any("may not be properly installed" in r.message for r in caplog.records)

    def test_foundry_version_logged_when_available(self, tmp_path, caplog):
        """Test debug logging when forge reports a version."""
        import logging

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "forge 0.2.0"

        with patch("subprocess.run", return_value=mock_result):
            with caplog.at_level(logging.DEBUG):
                FoundryRunner(project_dir=tmp_path)

        assert any("Foundry version: forge 0.2.0" in r.message for r in caplog.records)

    def test_foundry_version_check_timeout(self, tmp_path, caplog):
        """Test timeout during version check (lines 123-124)."""
        import logging

        # First call times out, second succeeds (for subsequent operations)
        call_count = [0]

        def side_effect_func(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise subprocess.TimeoutExpired("forge", 10)
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "forge 0.2.0"
            return mock_result

        with patch("subprocess.run", side_effect=side_effect_func):
            with caplog.at_level(logging.WARNING):
                try:
                    FoundryRunner(project_dir=tmp_path)
                except RuntimeError:
                    pass  # May raise if all calls fail

        assert any("timed out" in r.message.lower() for r in caplog.records)


class TestRunTestExceptionHandling:
    """Tests for run_test exception handling (lines 208-209)."""

    def test_run_test_generic_exception(self, runner):
        """Test run_test with generic exception (lines 208-209)."""
        with patch("subprocess.run", side_effect=OSError("Permission denied")):
            result = runner.run_test("test/Test.t.sol")

        assert result.success is False
        assert "Permission denied" in result.error


class TestValidatePoCEdgeCases:
    """Tests for validate_poc edge cases (lines 346-347)."""

    def test_validate_poc_exploit_failed(self, runner, tmp_path):
        """Test validate_poc when exploit fails (lines 346-347)."""
        test_file = tmp_path / "test" / "Exploit.t.sol"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("// Test file", encoding="utf-8")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "FAILED: Exploit did not succeed"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            validation = runner.validate_poc(str(test_file), expected_profit=True)

        assert validation["exploit_demonstrated"] is False
        assert any("may not have succeeded" in w for w in validation["warnings"])

    def test_validate_poc_profit_indicator(self, runner, tmp_path):
        """Test validate_poc with PROFIT indicator."""
        test_file = tmp_path / "test" / "Exploit.t.sol"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("// Test file", encoding="utf-8")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "PROFIT: 5 ETH"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            validation = runner.validate_poc(str(test_file), expected_profit=True)

        assert validation["exploit_demonstrated"] is True

    def test_validate_poc_no_exploit_indicator(self, runner, tmp_path):
        """Test validate_poc without exploit indicators."""
        test_file = tmp_path / "test" / "Exploit.t.sol"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("// Test file", encoding="utf-8")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "[PASS] test_something()"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            validation = runner.validate_poc(str(test_file), expected_profit=True)

        assert validation["exploit_demonstrated"] is None
        assert any("Could not determine" in w for w in validation["warnings"])


class TestParseForgeOutputEdgeCases:
    """Tests for _parse_forge_output edge cases (lines 380-386)."""

    def test_parse_forge_output_json_decode_error(self, runner):
        """Test parsing when JSON is malformed (lines 380-386)."""
        stdout = '{"incomplete: json\n{"also": "broken"}'
        stderr = ""

        result = runner._parse_forge_output(stdout, stderr, 0, 100.0)

        # Should fallback to text parsing
        assert isinstance(result, FoundryResult)

    def test_parse_forge_output_mixed_json_text(self, runner):
        """Test parsing with mixed JSON and text output."""
        stdout = """Some text before
{"test_name": "test_foo", "success": true}
More text
[PASS] test_bar() (gas: 123)
"""
        stderr = ""

        result = runner._parse_forge_output(stdout, stderr, 0, 100.0)

        assert isinstance(result, FoundryResult)
        assert [test.name for test in result.tests] == ["test_foo"]
        assert result.passed == 1

    def test_parse_forge_output_empty(self, runner):
        """Test parsing empty output."""
        result = runner._parse_forge_output("", "", 0, 100.0)

        assert isinstance(result, FoundryResult)
        assert result.total_tests == 0

    def test_parse_forge_output_exception_during_parsing(self, runner, caplog):
        """Test exception handling during JSON parsing (lines 385-386)."""
        import logging

        # Invalid structure that could cause issues
        stdout = '{"key": [invalid]}\n'
        stderr = ""

        with caplog.at_level(logging.DEBUG):
            result = runner._parse_forge_output(stdout, stderr, 0, 100.0)

        # Should handle gracefully
        assert isinstance(result, FoundryResult)

    def test_parse_forge_output_bad_test_results_shape_falls_back_to_text(self, runner, caplog):
        """Test malformed test_results shape does not block text fallback."""
        import logging

        stdout = '{"test_results": null}\n[PASS] test_fromText() (gas: 123)'

        with caplog.at_level(logging.DEBUG):
            result = runner._parse_forge_output(stdout, "", 0, 100.0)

        assert [test.name for test in result.tests] == ["test_fromText"]
        assert not any("JSON parsing failed" in r.message for r in caplog.records)

    def test_parse_forge_output_normalizes_malformed_stream_shapes(self, runner):
        """Test bytes stdout and missing stderr do not break output parsing."""
        stdout = b'{"test_name": "test_bytes", "success": true, "gas": "2,100"}\n'

        result = runner._parse_forge_output(stdout, None, 1, 100.0)

        assert [test.name for test in result.tests] == ["test_bytes"]
        assert result.total_gas == 2100
        assert result.raw_output == stdout.decode()
        assert result.error == ""

    def test_parse_forge_output_bounds_raw_output_size(self, runner):
        """Test raw output is capped while parsing still succeeds."""
        output = "[PASS] test_text() (gas: 123)\n" + ("x" * 210_000)

        result = runner._parse_forge_output(output, "", 0, 100.0)

        assert [test.name for test in result.tests] == ["test_text"]
        assert len(result.raw_output) == 200_000

    def test_parse_forge_output_treats_malformed_returncode_as_failure(self, runner):
        """Test malformed returncode shapes are not treated as successful runs."""
        result = runner._parse_forge_output(
            "[PASS] test_text() (gas: 123)",
            b"raw-error",
            "0",
            100.0,
        )

        assert result.success is False
        assert result.error == "raw-error"
        assert [test.name for test in result.tests] == ["test_text"]

    @pytest.mark.parametrize("execution_time", [None, True, -1.0, float("nan"), float("inf")])
    def test_parse_forge_output_defaults_malformed_execution_time(self, runner, execution_time):
        """Test malformed execution timing metadata does not leak to results."""
        result = runner._parse_forge_output("[PASS] test_text() (gas: 123)", "", 0, execution_time)

        assert result.execution_time_ms == 0.0

    def test_parse_forge_output_extracts_version_from_normalized_streams(self, runner):
        """Test forge version extraction ignores malformed stream shapes."""
        result = runner._parse_forge_output(
            ["forge 9.9.9"],
            b"forge 0.2.0\n[PASS] test_text() (gas: 123)",
            False,
            100.0,
        )

        assert result.forge_version == "0.2.0"
        assert result.success is False
        assert [test.name for test in result.tests] == ["test_text"]


class TestHighGasUsageWarning:
    """Tests for high gas usage warning in validate_poc."""

    def test_high_gas_usage_warning(self, runner, tmp_path):
        """Test warning for high gas usage (lines 356-359)."""
        test_file = tmp_path / "test" / "Exploit.t.sol"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("// Test file", encoding="utf-8")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "[PASS] test() (gas: 15000000)"  # High gas
        mock_result.stderr = ""

        # Mock _parse_forge_output to return high gas
        mock_foundry_result = FoundryResult(
            success=True,
            tests=[TestResult("test", TestStatus.PASSED, gas_used=15000000)],
            total_tests=1,
            passed=1,
            failed=0,
            skipped=0,
            total_gas=15000000,
            execution_time_ms=100.0,
            raw_output="",
        )

        with patch("subprocess.run", return_value=mock_result):
            with patch.object(runner, "_parse_forge_output", return_value=mock_foundry_result):
                validation = runner.validate_poc(str(test_file))

        assert any("High gas usage" in w for w in validation["warnings"])


class TestRunAllTestsAdditional:
    """Tests for run_all_tests method."""

    def test_run_all_tests_success(self, runner, sample_forge_output):
        """Test running all tests successfully."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_forge_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = runner.run_all_tests()

        assert isinstance(result, FoundryResult)

    def test_run_all_tests_without_dir_omits_match_path(self, runner, sample_forge_output):
        """Test default all-test run does not add a path matcher."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_forge_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            runner.run_all_tests()

        cmd = mock_run.call_args[0][0]
        assert "--match-path" not in cmd

    def test_run_all_tests_with_dir_adds_match_path(self, runner, sample_forge_output):
        """Test all-test run can be restricted to a test directory."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_forge_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            runner.run_all_tests(test_dir="test/exploits")

        cmd = mock_run.call_args[0][0]
        assert "--match-path" in cmd
        assert "test/exploits/*" in cmd

    def test_run_all_tests_with_options(self, runner_with_fork, sample_forge_output):
        """Test run_all_tests with fork configuration."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = sample_forge_output
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            runner_with_fork.run_all_tests()

        # Verify fork options are included
        cmd = mock_run.call_args[0][0]
        assert "--fork-url" in cmd

    def test_run_all_tests_timeout(self, runner):
        """Test run_all_tests timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("forge", 600)):
            result = runner.run_all_tests(timeout=600)

        assert result.success is False
        assert "timed out" in result.error.lower()


class TestFoundryRunnerRepr:
    """Tests for FoundryRunner __repr__."""

    def test_repr(self, runner):
        """Test string representation."""
        r = repr(runner)
        assert "FoundryRunner" in r

    def test_repr_with_fork(self, runner_with_fork):
        """Test string representation with fork config."""
        r = repr(runner_with_fork)
        assert "FoundryRunner" in r
